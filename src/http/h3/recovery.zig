//! RFC 9002 recovery bookkeeping: received-packet ACK ranges and RTT/PTO
//! estimation. Pure state machines over caller-supplied nanosecond clocks;
//! nothing here reads a clock, allocates, or blocks.
//!
//! Receive-side ACK ranges are kept as a small sorted array rather than a
//! tree: RFC 9000 caps the useful range count in practice, and a fixed 32
//! ranges per space makes the hot path `onReceived` branch-and-shift with a
//! statically bounded cost. Ranges are never adjacent — adjacency is merged
//! on insertion, which is what makes "is this packet already covered" a
//! single comparison.
//!
//! RTT estimation follows RFC 9002 §5.3 with one shared `smoothed_rtt` /
//! `rttvar` / `min_rtt` across spaces, because those describe the path, not
//! the packet number space. Only the PTO backoff counter is per space, as
//! the spaces arm and fire their own timers independently.
//!
//! Choices the RFC leaves to the implementation are documented next to the
//! constants they affect:

const std = @import("std");

const assert = std.debug.assert;

/// Packet number spaces. The enum values are used directly as array
/// indices, so the declaration order is part of this module's storage
/// layout — reordering is a format change, not a rename.
pub const Space = enum(u2) { initial, handshake, application };

const space_count: usize = 3;

comptime {
    assert(@backingInt(Space.application) + 1 == space_count);
}

fn spaceIndex(space: Space) usize {
    const index = @backingInt(space);
    assert(index < space_count);
    return index;
}

/// RFC 9000 §12.3: packet numbers are 62-bit.
pub const packet_number_max: u64 = (1 << 62) - 1;

/// RFC 9002 §6.2.1 `kInitialRtt`.
pub const initial_rtt_ns: u64 = 333 * std.time.ns_per_ms;
/// Half the initial RTT, matching RFC 9002's first-sample treatment.
pub const initial_rttvar_ns: u64 = initial_rtt_ns / 2;
/// RFC 9002 §6.2.1 `kGranularity`.
pub const timer_granularity_ns: u64 = std.time.ns_per_ms;
/// RFC 9000 §18.2 default `max_ack_delay`. Initial and Handshake spaces
/// use zero: their delay exponent is zero and peers must not delay ACKs.
pub const max_ack_delay_ns: u64 = 25 * std.time.ns_per_ms;
/// Ranges retained per space. Old ranges are dropped rather than merged
/// into a lie: an ACK range that claims unreceived packets is worse than
/// missing an old range.
pub const ack_ranges_max: usize = 32;
/// Sent packets retained per space for RTT sampling. Losing the oldest is
/// safe: its ACK becomes an unknown-packet ACK and is ignored.
pub const sent_max: usize = 64;
/// Backoff is capped at 2^16; with the 60 s ceiling below the shift value
/// stops mattering long before this.
pub const pto_count_max: u8 = 16;
/// Implementation ceiling on a single PTO (RFC 9002 leaves this open).
/// Without it a decaying link backs off into an unbounded timer.
pub const pto_max_ns: u64 = 60 * std.time.ns_per_s;
/// Samples above this are treated as this value. A wildly stale sent time
/// would otherwise overflow the 3x/7x arithmetic in the EWMA.
pub const max_rtt_sample_ns: u64 = 60 * std.time.ns_per_s;

/// One inclusive run of received packet numbers.
pub const AckRange = struct {
    smallest: u64,
    largest: u64,
};

/// Received-packet ranges for the three spaces, plus the "an ACK is owed"
/// flag per space.
pub const AckTracker = struct {
    /// Per space, sorted ascending by `largest` (and therefore by
    /// `smallest`, since ranges never overlap or touch).
    ranges: [space_count][ack_ranges_max]AckRange =
        @splat(@as([ack_ranges_max]AckRange, @splat(.{ .smallest = 0, .largest = 0 }))),
    counts: [space_count]u8 = @splat(0),
    pending: [space_count]bool = @splat(false),

    /// Overwrite `self` with the empty state. Caller-owned storage — the
    /// tracker never allocates.
    pub fn initInPlace(self: *AckTracker) void {
        self.* = .{};
    }

    /// Value-returning form for callers that can hold the tracker on the
    /// stack at the use site.
    pub fn init() AckTracker {
        return .{};
    }

    /// Record an ack-eliciting packet number. A duplicate (already covered
    /// by a retained range) changes nothing and does not re-arm the ACK:
    /// it carries no new information the peer does not already have.
    pub fn onReceived(self: *AckTracker, space: Space, pn: u64) void {
        assert(pn <= packet_number_max);
        const space_index = spaceIndex(space);
        const set = &self.ranges[space_index];
        const count: usize = self.counts[space_index];

        var pos: usize = 0;
        while (pos < count) : (pos += 1) {
            if (set[pos].largest >= pn) break;
        }

        if (pos < count) {
            if (set[pos].smallest <= pn) return;

            if (pn + 1 == set[pos].smallest) {
                set[pos].smallest = pn;
                self.mergeIntoPrevious(space_index, pos);
                self.pending[space_index] = true;
                return;
            }

            // The range immediately below may already end at `pn - 1`;
            // extending it is the same operation seen from the other side.
            if (pos > 0) {
                if (set[pos - 1].largest + 1 == pn) {
                    set[pos - 1].largest = pn;
                    self.pending[space_index] = true;
                    return;
                }
            }

            if (self.insertAt(space_index, pos, .{ .smallest = pn, .largest = pn })) {
                self.pending[space_index] = true;
            }
            return;
        }

        // Above every retained range.
        if (count > 0) {
            if (set[count - 1].largest + 1 == pn) {
                set[count - 1].largest = pn;
                self.pending[space_index] = true;
                return;
            }
        }
        if (self.insertAt(space_index, count, .{ .smallest = pn, .largest = pn })) {
            self.pending[space_index] = true;
        }
    }

    /// Newest-first ACK ranges for the wire. `out` may be shorter than the
    /// retained set; the returned slice is always a prefix of `out`.
    pub fn ackRanges(self: *const AckTracker, space: Space, out: []AckRange) []AckRange {
        const space_index = spaceIndex(space);
        const count: usize = self.counts[space_index];
        const n = @min(out.len, count);
        var i: usize = 0;
        while (i < n) : (i += 1) {
            out[i] = self.ranges[space_index][count - 1 - i];
        }
        return out[0..n];
    }

    pub fn needsAck(self: *const AckTracker, space: Space) bool {
        return self.pending[spaceIndex(space)];
    }

    pub fn onAckSent(self: *AckTracker, space: Space) void {
        self.pending[spaceIndex(space)] = false;
    }

    pub fn reset(self: *AckTracker, space: Space) void {
        const space_index = spaceIndex(space);
        self.counts[space_index] = 0;
        self.pending[space_index] = false;
    }

    /// Merge `set[pos]` upward into `set[pos - 1]` when extending the lower
    /// range made them adjacent.
    fn mergeIntoPrevious(self: *AckTracker, space_index: usize, pos: usize) void {
        assert(pos < self.counts[space_index]);
        if (pos == 0) return;
        const set = &self.ranges[space_index];
        if (set[pos - 1].largest + 1 != set[pos].smallest) return;

        set[pos - 1].largest = set[pos].largest;
        var i: usize = pos;
        const count: usize = self.counts[space_index];
        while (i + 1 < count) : (i += 1) {
            set[i] = set[i + 1];
        }
        self.counts[space_index] -= 1;
    }

    /// Insert a fresh one-packet range at `pos`, preserving sort order.
    /// A full set drops its oldest range; a packet older than the oldest
    /// retained range is refused instead, so dropping never discards newer
    /// information to remember something staler.
    fn insertAt(
        self: *AckTracker,
        space_index: usize,
        pos: usize,
        range: AckRange,
    ) bool {
        const set = &self.ranges[space_index];
        var count: usize = self.counts[space_index];
        var at = pos;
        assert(at <= count);

        if (count == ack_ranges_max) {
            if (at == 0) return false;
            var i: usize = 1;
            while (i < count) : (i += 1) {
                set[i - 1] = set[i];
            }
            count -= 1;
            at -= 1;
        }

        var i: usize = count;
        while (i > at) : (i -= 1) {
            set[i] = set[i - 1];
        }
        set[at] = range;
        self.counts[space_index] = @intCast(count + 1);
        return true;
    }
};

const SentPacket = struct {
    pn: u64 = 0,
    sent_ns: u64 = 0,
};

const SentList = struct {
    packets: [sent_max]SentPacket = @splat(.{}),
    count: u8 = 0,
};

/// RFC 9002 §5 RTT estimator and §6.2 PTO calculation.
pub const Rtt = struct {
    /// EWMA of adjusted samples (RFC 9002 §5.3).
    smoothed_ns: u64 = initial_rtt_ns,
    /// EWMA of sample deviation (RFC 9002 §5.3).
    rttvar_ns: u64 = initial_rttvar_ns,
    /// Minimum observed raw RTT; zero until the first sample.
    min_ns: u64 = 0,
    have_sample: bool = false,
    /// Per space, because each space arms its own PTO timer.
    pto_count: [space_count]u8 = @splat(0),
    sent: [space_count]SentList = @splat(.{}),

    pub fn initInPlace(self: *Rtt) void {
        self.* = .{};
    }

    pub fn init() Rtt {
        return .{};
    }

    /// Remember when an ack-eliciting packet was sent. Re-sending the same
    /// packet number is a caller bug; the first timestamp is kept so a
    /// duplicate cannot shorten the sample.
    pub fn onSent(self: *Rtt, space: Space, pn: u64, now_ns: u64) void {
        assert(pn <= packet_number_max);
        const list = &self.sent[spaceIndex(space)];

        var i: usize = 0;
        while (i < list.count) : (i += 1) {
            if (list.packets[i].pn == pn) return;
        }

        if (list.count == sent_max) {
            var j: usize = 1;
            while (j < sent_max) : (j += 1) {
                list.packets[j - 1] = list.packets[j];
            }
            list.count -= 1;
        }

        list.packets[list.count] = .{ .pn = pn, .sent_ns = now_ns };
        list.count += 1;
    }

    /// Process an ACK whose largest acknowledged number is `largest_acked`.
    /// An ACK naming a packet no longer in the bounded history (unknown or
    /// already acknowledged) is ignored entirely — RFC 9002's sampling
    /// rules cannot be satisfied without the send timestamp, and guessing
    /// would corrupt the EWMA. `now_ns` must be monotonic: it is compared
    /// against the timestamp recorded by `onSent`.
    pub fn onAck(
        self: *Rtt,
        space: Space,
        largest_acked: u64,
        now_ns: u64,
        ack_delay_ns: u64,
    ) void {
        assert(largest_acked <= packet_number_max);
        const space_index = spaceIndex(space);
        const list = &self.sent[space_index];

        var found: ?usize = null;
        var i: usize = 0;
        while (i < list.count) : (i += 1) {
            if (list.packets[i].pn == largest_acked) {
                found = i;
                break;
            }
        }
        const at = found orelse return;

        const sent_ns = list.packets[at].sent_ns;
        assert(now_ns >= sent_ns);
        const latest_ns = @min(now_ns - sent_ns, max_rtt_sample_ns);

        // Initial and Handshake peers must not delay ACKs, so only the
        // Application space can legitimately report a delay.
        const delay_limit_ns: u64 = if (space == .application) max_ack_delay_ns else 0;
        self.updateRtt(latest_ns, @min(ack_delay_ns, delay_limit_ns));

        // A newly acknowledged packet is proof the path still works; the
        // RFC resets the backoff (and any pending loss timer) here.
        self.pto_count[space_index] = 0;
        self.prune(space_index, largest_acked);
    }

    /// Forget a packet declared lost. Its late ACK then becomes an
    /// unknown-packet ACK rather than a sample taken long after the send,
    /// which would inflate the RTT. Loss itself does not advance the PTO
    /// backoff — `onPtoFired` owns that.
    pub fn onPacketLost(self: *Rtt, space: Space, pn: u64) void {
        assert(pn <= packet_number_max);
        const list = &self.sent[spaceIndex(space)];

        var i: usize = 0;
        while (i < list.count) : (i += 1) {
            if (list.packets[i].pn != pn) continue;
            var j = i;
            while (j + 1 < list.count) : (j += 1) {
                list.packets[j] = list.packets[j + 1];
            }
            list.count -= 1;
            return;
        }
    }

    /// A PTO timer expiry. The next `pto` for this space doubles, up to
    /// `pto_count_max`, which with `pto_max_ns` bounds the wait.
    pub fn onPtoFired(self: *Rtt, space: Space) void {
        const space_index = spaceIndex(space);
        if (self.pto_count[space_index] < pto_count_max) {
            self.pto_count[space_index] += 1;
        }
    }

    /// Current PTO for `space`, or null when nothing is in flight and the
    /// caller must not arm a timer. The Application space adds
    /// `max_ack_delay`; Initial and Handshake do not.
    pub fn pto(self: *const Rtt, space: Space) ?u64 {
        const space_index = spaceIndex(space);
        if (self.sent[space_index].count == 0) return null;

        const variance_ns = @max(4 * self.rttvar_ns, timer_granularity_ns);
        var base_ns = self.smoothed_ns + variance_ns;
        if (space == .application) {
            base_ns += max_ack_delay_ns;
        }
        assert(base_ns <= max_rtt_sample_ns * 5);

        const shift: u6 = @intCast(@min(self.pto_count[space_index], pto_count_max));
        const backed_off_ns = base_ns * (@as(u64, 1) << shift);
        return @min(backed_off_ns, pto_max_ns);
    }

    pub fn smoothedRtt(self: *const Rtt) u64 {
        return self.smoothed_ns;
    }

    /// Zero until the first RTT sample.
    pub fn minRtt(self: *const Rtt) u64 {
        return self.min_ns;
    }

    /// RFC 9002 §5.3. The first sample seeds both EWMAs instead of being
    /// folded into the initial 333 ms guess.
    fn updateRtt(self: *Rtt, latest_ns: u64, ack_delay_ns: u64) void {
        assert(latest_ns <= max_rtt_sample_ns);
        assert(ack_delay_ns <= max_ack_delay_ns);

        if (!self.have_sample) {
            self.have_sample = true;
            self.min_ns = latest_ns;
            self.smoothed_ns = latest_ns;
            self.rttvar_ns = latest_ns / 2;
            return;
        }

        self.min_ns = @min(self.min_ns, latest_ns);

        // Never subtract more delay than the sample exceeds the minimum:
        // the adjusted RTT is bounded below by min_rtt.
        var adjusted_ns = latest_ns;
        if (latest_ns >= self.min_ns + ack_delay_ns) {
            adjusted_ns = latest_ns - ack_delay_ns;
        }

        const deviation_ns = if (self.smoothed_ns > adjusted_ns)
            self.smoothed_ns - adjusted_ns
        else
            adjusted_ns - self.smoothed_ns;

        self.rttvar_ns = (3 * self.rttvar_ns + deviation_ns) / 4;
        self.smoothed_ns = (7 * self.smoothed_ns + adjusted_ns) / 8;
    }

    /// Every number up to `largest_acked` is acknowledged or already lost,
    /// so it can no longer produce a valid sample.
    fn prune(self: *Rtt, space_index: usize, largest_acked: u64) void {
        const list = &self.sent[space_index];
        const count: usize = list.count;
        var read: usize = 0;
        var write: usize = 0;
        while (read < count) : (read += 1) {
            if (list.packets[read].pn > largest_acked) {
                list.packets[write] = list.packets[read];
                write += 1;
            }
        }
        list.count = @intCast(write);
    }
};

fn expectRange(expected: AckRange, actual: AckRange) !void {
    try std.testing.expectEqual(expected.smallest, actual.smallest);
    try std.testing.expectEqual(expected.largest, actual.largest);
}

test "adjacent packet numbers coalesce into one range" {
    var tracker: AckTracker = undefined;
    tracker.initInPlace();

    tracker.onReceived(.initial, 1);
    tracker.onReceived(.initial, 2);
    tracker.onReceived(.initial, 3);

    var out: [ack_ranges_max]AckRange = undefined;
    const ranges = tracker.ackRanges(.initial, &out);
    try std.testing.expectEqual(@as(usize, 1), ranges.len);
    try expectRange(.{ .smallest = 1, .largest = 3 }, ranges[0]);
    try std.testing.expect(tracker.needsAck(.initial));
}

test "duplicate packet number changes nothing and does not re-arm ACK" {
    var tracker: AckTracker = undefined;
    tracker.initInPlace();

    tracker.onReceived(.handshake, 7);
    tracker.onAckSent(.handshake);
    tracker.onReceived(.handshake, 7);

    var out: [ack_ranges_max]AckRange = undefined;
    const ranges = tracker.ackRanges(.handshake, &out);
    try std.testing.expectEqual(@as(usize, 1), ranges.len);
    try expectRange(.{ .smallest = 7, .largest = 7 }, ranges[0]);
    try std.testing.expect(!tracker.needsAck(.handshake));
}

test "a gap keeps two separate ranges" {
    var tracker: AckTracker = undefined;
    tracker.initInPlace();

    tracker.onReceived(.application, 10);
    tracker.onReceived(.application, 12);

    var out: [ack_ranges_max]AckRange = undefined;
    const ranges = tracker.ackRanges(.application, &out);
    try std.testing.expectEqual(@as(usize, 2), ranges.len);
    try expectRange(.{ .smallest = 12, .largest = 12 }, ranges[0]);
    try expectRange(.{ .smallest = 10, .largest = 10 }, ranges[1]);
}

test "out-of-order arrivals coalesce and fill gaps" {
    var tracker: AckTracker = undefined;
    tracker.initInPlace();

    tracker.onReceived(.application, 5);
    tracker.onReceived(.application, 3);
    tracker.onReceived(.application, 4);
    tracker.onReceived(.application, 10);
    tracker.onReceived(.application, 12);
    tracker.onReceived(.application, 11);

    var out: [ack_ranges_max]AckRange = undefined;
    const ranges = tracker.ackRanges(.application, &out);
    try std.testing.expectEqual(@as(usize, 2), ranges.len);
    try expectRange(.{ .smallest = 10, .largest = 12 }, ranges[0]);
    try expectRange(.{ .smallest = 3, .largest = 5 }, ranges[1]);
}

test "ackRanges returns newest first and respects the output bound" {
    var tracker: AckTracker = undefined;
    tracker.initInPlace();

    tracker.onReceived(.initial, 1);
    tracker.onReceived(.initial, 5);
    tracker.onReceived(.initial, 10);

    var out: [ack_ranges_max]AckRange = undefined;
    const ranges = tracker.ackRanges(.initial, &out);
    try std.testing.expectEqual(@as(usize, 3), ranges.len);
    try expectRange(.{ .smallest = 10, .largest = 10 }, ranges[0]);
    try expectRange(.{ .smallest = 5, .largest = 5 }, ranges[1]);
    try expectRange(.{ .smallest = 1, .largest = 1 }, ranges[2]);

    var small: [2]AckRange = undefined;
    const truncated = tracker.ackRanges(.initial, &small);
    try std.testing.expectEqual(@as(usize, 2), truncated.len);
    try expectRange(.{ .smallest = 10, .largest = 10 }, truncated[0]);
    try expectRange(.{ .smallest = 5, .largest = 5 }, truncated[1]);
}

test "a full range set drops the oldest and refuses older packets" {
    var tracker: AckTracker = undefined;
    tracker.initInPlace();

    var pn: u64 = 0;
    while (pn < 2 * ack_ranges_max) : (pn += 2) {
        tracker.onReceived(.application, pn);
    }

    var out: [ack_ranges_max]AckRange = undefined;
    var ranges = tracker.ackRanges(.application, &out);
    try std.testing.expectEqual(ack_ranges_max, ranges.len);
    try expectRange(.{ .smallest = 0, .largest = 0 }, ranges[ack_ranges_max - 1]);

    // One newer range: the oldest ({0,0}) is evicted, count stays capped.
    tracker.onReceived(.application, 2 * ack_ranges_max);
    ranges = tracker.ackRanges(.application, &out);
    try std.testing.expectEqual(ack_ranges_max, ranges.len);
    try expectRange(.{ .smallest = 2, .largest = 2 }, ranges[ack_ranges_max - 1]);
    try expectRange(.{ .smallest = 2 * ack_ranges_max, .largest = 2 * ack_ranges_max }, ranges[0]);

    // A packet older than everything retained is ignored, not remembered
    // at the cost of a newer range.
    tracker.onAckSent(.application);
    tracker.onReceived(.application, 0);
    ranges = tracker.ackRanges(.application, &out);
    try std.testing.expectEqual(ack_ranges_max, ranges.len);
    try expectRange(.{ .smallest = 2, .largest = 2 }, ranges[ack_ranges_max - 1]);
    try std.testing.expect(!tracker.needsAck(.application));
}

test "needsAck is armed by receipt and cleared by onAckSent" {
    var tracker = AckTracker.init();
    try std.testing.expect(!tracker.needsAck(.initial));

    tracker.onReceived(.initial, 1);
    try std.testing.expect(tracker.needsAck(.initial));
    tracker.onAckSent(.initial);
    try std.testing.expect(!tracker.needsAck(.initial));

    tracker.onReceived(.initial, 2);
    try std.testing.expect(tracker.needsAck(.initial));
}

test "reset clears one space only" {
    var tracker = AckTracker.init();
    tracker.onReceived(.initial, 1);
    tracker.onReceived(.application, 9);

    tracker.reset(.initial);

    var out: [ack_ranges_max]AckRange = undefined;
    try std.testing.expectEqual(@as(usize, 0), tracker.ackRanges(.initial, &out).len);
    try std.testing.expect(!tracker.needsAck(.initial));
    try std.testing.expectEqual(@as(usize, 1), tracker.ackRanges(.application, &out).len);
    try std.testing.expect(tracker.needsAck(.application));
}

test "first PTO uses the RFC initial RTT and per-space ack delay" {
    var rtt = Rtt.init();
    try std.testing.expectEqual(@as(?u64, null), rtt.pto(.initial));

    rtt.onSent(.initial, 0, 0);
    // 333 ms smoothed + max(4 * 166.5 ms, 1 ms).
    try std.testing.expectEqual(@as(?u64, 999_000_000), rtt.pto(.initial));

    rtt.onSent(.handshake, 0, 0);
    try std.testing.expectEqual(@as(?u64, 999_000_000), rtt.pto(.handshake));

    rtt.onSent(.application, 0, 0);
    // Application space adds the 25 ms max_ack_delay.
    try std.testing.expectEqual(@as(?u64, 1_024_000_000), rtt.pto(.application));
}

test "PTO backs off exponentially and stops at the cap" {
    var rtt = Rtt.init();
    rtt.onSent(.initial, 0, 0);

    rtt.onPtoFired(.initial);
    try std.testing.expectEqual(@as(?u64, 1_998_000_000), rtt.pto(.initial));

    rtt.onPtoFired(.initial);
    try std.testing.expectEqual(@as(?u64, 3_996_000_000), rtt.pto(.initial));

    // Other spaces have their own counter.
    try std.testing.expectEqual(@as(?u64, null), rtt.pto(.application));

    var i: u8 = 0;
    while (i < pto_count_max) : (i += 1) rtt.onPtoFired(.initial);
    try std.testing.expectEqual(@as(?u64, pto_max_ns), rtt.pto(.initial));

    // An acknowledged packet resets the backoff; the 10 ms sample also
    // replaces the initial estimate (10 + max(4 * 5, 1) = 30 ms). The ACK
    // pruned the only sent packet, so re-arm the timer with a new one.
    rtt.onAck(.initial, 0, 10 * std.time.ns_per_ms, 0);
    try std.testing.expectEqual(@as(?u64, null), rtt.pto(.initial));
    rtt.onSent(.initial, 1, 10 * std.time.ns_per_ms);
    try std.testing.expectEqual(@as(?u64, 30_000_000), rtt.pto(.initial));
}

test "first RTT sample seeds the estimator and never subtracts delay below min_rtt" {
    var rtt = Rtt.init();

    rtt.onSent(.application, 0, 0);
    rtt.onAck(.application, 0, 100_000_000, 30_000_000);

    // min_rtt == latest, so the delay cannot be removed from the sample.
    try std.testing.expectEqual(@as(u64, 100_000_000), rtt.smoothedRtt());
    try std.testing.expectEqual(@as(u64, 100_000_000), rtt.minRtt());
    // rttvar starts at half the sample.
    try std.testing.expectEqual(@as(u64, 50_000_000), rtt.rttvar_ns);
}

test "RTT update folds in an adjusted sample and clamps ack delay" {
    var rtt = Rtt.init();

    rtt.onSent(.application, 0, 0);
    rtt.onAck(.application, 0, 100_000_000, 0);
    try std.testing.expectEqual(@as(u64, 100_000_000), rtt.smoothedRtt());

    rtt.onSent(.application, 1, 100_000_000);
    // 300 ms raw, 100 ms of claimed delay clamps to the 25 ms maximum.
    rtt.onAck(.application, 1, 400_000_000, 100_000_000);

    // adjusted = 300 ms - 25 ms = 275 ms.
    // smoothed = (7 * 100 + 275) / 8 = 121.875 ms.
    // rttvar = (3 * 50 + 175) / 4 = 81.25 ms.
    try std.testing.expectEqual(@as(u64, 121_875_000), rtt.smoothedRtt());
    try std.testing.expectEqual(@as(u64, 81_250_000), rtt.rttvar_ns);
    try std.testing.expectEqual(@as(u64, 100_000_000), rtt.minRtt());

    rtt.onSent(.application, 2, 400_000_000);
    // 121.875 + max(4 * 81.25, 1) + 25 = 471.875 ms.
    try std.testing.expectEqual(@as(?u64, 471_875_000), rtt.pto(.application));
}

test "ACK of an unknown or pruned packet leaves the estimator untouched" {
    var rtt = Rtt.init();
    rtt.onSent(.application, 3, 0);

    // Unknown packet number.
    rtt.onAck(.application, 99, 10_000_000, 0);
    try std.testing.expectEqual(initial_rtt_ns, rtt.smoothedRtt());
    try std.testing.expectEqual(@as(u64, 0), rtt.minRtt());

    rtt.onSent(.application, 4, 10_000_000);
    rtt.onAck(.application, 4, 50_000_000, 0);
    try std.testing.expectEqual(@as(u64, 40_000_000), rtt.smoothedRtt());

    // 3 is pruned by the ACK of 4; acking it again is a no-op.
    rtt.onAck(.application, 3, 90_000_000, 0);
    try std.testing.expectEqual(@as(u64, 40_000_000), rtt.smoothedRtt());
    try std.testing.expectEqual(@as(u64, 40_000_000), rtt.minRtt());
}

test "sent-packet history is bounded and a lost packet cannot be sampled" {
    var rtt = Rtt.init();
    const space_index = spaceIndex(.application);

    var pn: u64 = 0;
    while (pn < sent_max + 8) : (pn += 1) {
        rtt.onSent(.application, pn, 0);
    }
    try std.testing.expectEqual(@as(u8, sent_max), rtt.sent[space_index].count);

    // pn 0 fell out of the bounded history; its ACK is ignored.
    rtt.onAck(.application, 0, 5_000_000, 0);
    try std.testing.expectEqual(initial_rtt_ns, rtt.smoothedRtt());

    // A packet declared lost is removed, so its late ACK cannot sample.
    rtt.onSent(.application, 100, 0);
    rtt.onPacketLost(.application, 100);
    rtt.onAck(.application, 100, 5_000_000, 0);
    try std.testing.expectEqual(initial_rtt_ns, rtt.smoothedRtt());
}
