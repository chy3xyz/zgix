//! Listener-level, per-client token bucket (§7, §5): the first policy in
//! this proxy whose state is keyed by *who* is asking rather than by what
//! was asked.
//!
//! The table is fixed-size open addressing over an arena slice allocated
//! once at startup. Nothing here allocates, scans unboundedly, or blocks:
//! `admit` reads and writes at most `probe_max` entries, so the serving
//! path's §5 zero-allocation promise survives the feature.
//!
//! Identity is the same rule every other client-keyed feature uses: an
//! IPv4 client is its /32, an IPv6 client its /64. RFC 8981 rotates the
//! interface half on a timer, so a narrower IPv6 key would name a client
//! that stops existing in an hour; `filter.Cidr` and `hash.key:
//! source_ip` already made that argument, and a rate limiter that
//! disagreed would let one host out of a limit the other two enforce.
//!
//! A table that cannot take a new client fails **open**: the request is
//! allowed and the caller counts `l7_rate_limit_full`. Refusing a client
//! the table never saw would turn a memory bound into an outage, and the
//! counter is what makes the bound visible instead of silent.

const std = @import("std");

const assert = std.debug.assert;

/// The bucket's shape, resolved from a listener's `rate_limit` block.
/// Durations stay in milliseconds here because that is what the operator
/// wrote and what the schema bounds; `admit` converts once per call.
pub const Policy = struct {
    /// Tokens added per `window_ms`.
    requests: u32,
    /// Window over which `requests` tokens accrue.
    window_ms: u32,
    /// Bucket capacity. May exceed `requests` (an idle client accumulates
    /// up to this many) but never falls below it: a capacity smaller than
    /// the refill window would smooth a limit the operator stated as a
    /// per-window allowance.
    burst: u32,
};

/// One client identity. IPv4 stores its four bytes, IPv6 the high 64
/// bits of its /64 — the same projections `filter.Cidr` and the balancer
/// compare.
pub const Key = struct {
    bits: u64,
    family: Family,

    pub const Family = enum(u1) { ipv4, ipv6 };

    /// The identity comparison every client-keyed table uses. Public so a
    /// second policy (the connection cap) cannot grow a subtly different
    /// equality.
    pub fn eql(a: Key, b: Key) bool {
        return a.family == b.family and a.bits == b.bits;
    }
};

/// One bucket. `last_refill_ns` is the instant the current `tokens_milli`
/// balance corresponds to; a refill credits elapsed time from there and
/// advances it by exactly the time those tokens consumed, so sub-token
/// remainders are not thrown away.
pub const Entry = struct {
    key: Key,
    last_refill_ns: u64,
    tokens_milli: u32,
    occupied: bool,
};

/// Milli-tokens per request. Integer math throughout, and one thousandth
/// of a token is finer than any clock this proxy reads.
const token_milli: u32 = 1000;

/// How many slots one lookup may touch. Eight is enough that a table
/// loaded past half full still places most clients on the first or
/// second probe, and small enough that a full table costs eight compares
/// rather than a scan. Past it, fail open.
const probe_max: usize = 8;

/// What one admission decided. `table_full` is an *allow*: the name
/// exists so the caller can count the fail-open rather than mistake it
/// for an ordinary allowance.
pub const Verdict = enum(u2) {
    allowed,
    limited,
    table_full,
};

pub const Table = struct {
    entries: []Entry = &.{},

    /// Reserve `count` buckets from the startup arena. Count zero is the
    /// feature being off and reserves nothing, exactly like every other
    /// optional pool.
    pub fn init(arena: std.mem.Allocator, count: u32) error{OutOfMemory}!Table {
        if (count == 0) return .{};
        const entries = try arena.alloc(Entry, count);
        return fromStorage(entries);
    }

    /// Adopt caller-owned storage — the shape the tests use with a
    /// stack array, and `init` uses with the arena slice. Clearing is
    /// what makes every slot start empty; an entry's other fields are
    /// only read once `occupied` says a key was installed.
    pub fn fromStorage(entries: []Entry) Table {
        const empty: Entry = .{
            .key = .{ .bits = 0, .family = .ipv4 },
            .last_refill_ns = 0,
            .tokens_milli = 0,
            .occupied = false,
        };
        @memset(entries, empty);
        return .{ .entries = entries };
    }

    /// One admission. True means the request may proceed; `table_full`
    /// also allows, and is separated so the caller can witness it.
    pub fn admit(
        table: *Table,
        client: *const std.Io.net.IpAddress,
        now_ns: u64,
        policy: Policy,
    ) Verdict {
        assert(policy.requests >= 1);
        assert(policy.window_ms >= 1);
        assert(policy.burst >= policy.requests);
        assert(policy.burst <= std.math.maxInt(u32) / token_milli);
        // A table that was never reserved cannot track anyone. Failing
        // open is still the answer: refusing traffic because an operator
        // under-provisioned a table would be the outage this avoids.
        if (table.entries.len == 0) return .table_full;
        const key = keyOf(client);
        const start = hashKey(key) % table.entries.len;
        // A short table probes its own width rather than repeating slots.
        const probes = @min(probe_max, table.entries.len);
        var probe: usize = 0;
        while (probe < probes) : (probe += 1) {
            const entry = &table.entries[(start + probe) % table.entries.len];
            if (!entry.occupied) {
                // Linear probing means an existing key cannot sit past
                // the first empty slot: insertion always took the first
                // one it found.
                install(entry, key, now_ns, policy);
                return .allowed;
            }
            if (!key.eql(entry.key)) continue;
            refill(entry, now_ns, policy);
            if (entry.tokens_milli < token_milli) return .limited;
            entry.tokens_milli -= token_milli;
            return .allowed;
        }
        // Bounded probing ran out with no free slot in reach. Allow, and
        // let the caller count that the table's width no longer covers
        // the distinct clients arriving.
        return .table_full;
    }
};

/// The identity a client address contributes. Family-strict: an IPv4
/// address never shares a bucket with an IPv6 one whose low bits happen
/// to match.
pub fn keyOf(client: *const std.Io.net.IpAddress) Key {
    return switch (client.*) {
        .ip4 => |v4| .{
            .bits = std.mem.readInt(u32, &v4.bytes, .big),
            .family = .ipv4,
        },
        .ip6 => |v6| .{
            .bits = std.mem.readInt(u64, v6.bytes[0..8], .big),
            .family = .ipv6,
        },
    };
}

/// SplitMix64's finalizer. Any well-mixed hash works; this one is cheap,
/// pinned by the algorithm rather than a library, and already the shape
/// the balancer uses for the same reason.
fn hashKey(key: Key) usize {
    var z: u64 = key.bits ^ (@as(u64, @backingInt(key.family)) *% 0x9E3779B97F4A7C15);
    z ^= z >> 30;
    z *%= 0xBF58476D1CE4E5B9;
    z ^= z >> 27;
    z *%= 0x94D049BB133111EB;
    z ^= z >> 31;
    return @intCast(z);
}

fn capacityMilli(policy: Policy) u32 {
    assert(policy.burst >= 1);
    assert(policy.burst <= std.math.maxInt(u32) / token_milli);
    return policy.burst * token_milli;
}

/// A newly seen client starts with one request already spent, and the
/// timestamp that spend corresponds to.
fn install(entry: *Entry, key: Key, now_ns: u64, policy: Policy) void {
    assert(!entry.occupied);
    entry.* = .{
        .key = key,
        .last_refill_ns = now_ns,
        .tokens_milli = capacityMilli(policy) - token_milli,
        .occupied = true,
    };
}

/// Credit elapsed monotonic time, capped at capacity. The u128 product
/// keeps a table entry idle for years from wrapping; the division stays
/// in milli-tokens, and the timestamp advances by exactly the time the
/// credited tokens consumed so the truncation remainder is not lost.
fn refill(entry: *Entry, now_ns: u64, policy: Policy) void {
    assert(entry.occupied);
    const capacity = capacityMilli(policy);
    if (now_ns <= entry.last_refill_ns) {
        // A clock that did not advance (or jumped backwards) credits
        // nothing. Monotonicity is the seam's contract; this is the
        // cheap defensive answer rather than a subtraction underflow.
        return;
    }
    if (entry.tokens_milli >= capacity) {
        // Full buckets need no elapsed history; moving the stamp now
        // keeps a later refill from crediting the same idle period twice.
        entry.last_refill_ns = now_ns;
        return;
    }
    const elapsed = now_ns - entry.last_refill_ns;
    const window_ns: u128 = @as(u128, policy.window_ms) * std.time.ns_per_ms;
    const rate_milli: u128 = @as(u128, policy.requests) * token_milli;
    const added_full = @as(u128, elapsed) * rate_milli / window_ns;
    if (added_full == 0) {
        // Less than a milli-token accrued. Leave the stamp where it is
        // so the next call sees the accumulated elapsed time.
        return;
    }
    const room = capacity - entry.tokens_milli;
    if (added_full >= room) {
        entry.tokens_milli = capacity;
        entry.last_refill_ns = now_ns;
        return;
    }
    const added: u32 = @intCast(added_full);
    entry.tokens_milli += added;
    // The instant the credited tokens represent. `added_full` is a floor,
    // so this can never pass `now_ns`; the assert is what proves the
    // arithmetic rather than trusting the derivation.
    const used_ns: u128 = added_full * window_ns / rate_milli;
    entry.last_refill_ns += @intCast(used_ns);
    assert(entry.last_refill_ns <= now_ns);
}

const testing = std.testing;

fn testAddress(comptime literal: []const u8) std.Io.net.IpAddress {
    return std.Io.net.IpAddress.parseLiteral(literal) catch unreachable;
}

fn testPolicy(requests: u32, window_ms: u32, burst: u32) Policy {
    return .{ .requests = requests, .window_ms = window_ms, .burst = burst };
}

test "rate_limit: a full burst is allowed and the next request is not" {
    var storage: [8]Entry = undefined;
    var table = Table.fromStorage(&storage);
    const policy = testPolicy(2, 1000, 3);
    const client = testAddress("127.0.0.1:40000");

    for (0..3) |_| {
        try testing.expectEqual(Verdict.allowed, table.admit(&client, 0, policy));
    }
    // No time passed, so no tokens were refilled.
    try testing.expectEqual(Verdict.limited, table.admit(&client, 0, policy));
    try testing.expectEqual(Verdict.limited, table.admit(&client, 0, policy));
}

test "rate_limit: elapsed time refills at the configured rate" {
    var storage: [8]Entry = undefined;
    var table = Table.fromStorage(&storage);
    const policy = testPolicy(2, 1000, 2);
    const client = testAddress("127.0.0.1:40000");

    try testing.expectEqual(Verdict.allowed, table.admit(&client, 0, policy));
    try testing.expectEqual(Verdict.allowed, table.admit(&client, 0, policy));
    try testing.expectEqual(Verdict.limited, table.admit(&client, 0, policy));

    // Half a window earns one of the two tokens (the refill is
    // continuous, not windowed): allow it, then the next is limited.
    const half_window_ns = @as(u64, 500) * std.time.ns_per_ms;
    try testing.expectEqual(Verdict.allowed, table.admit(&client, half_window_ns, policy));
    try testing.expectEqual(Verdict.limited, table.admit(&client, half_window_ns, policy));

    // A full window after that spend refills the whole burst, no more.
    const next_window_ns = @as(u64, 1500) * std.time.ns_per_ms;
    try testing.expectEqual(Verdict.allowed, table.admit(&client, next_window_ns, policy));
    try testing.expectEqual(Verdict.allowed, table.admit(&client, next_window_ns, policy));
    try testing.expectEqual(Verdict.limited, table.admit(&client, next_window_ns, policy));
}

test "rate_limit: clients have independent buckets" {
    var storage: [8]Entry = undefined;
    var table = Table.fromStorage(&storage);
    const policy = testPolicy(1, 1000, 1);
    const first = testAddress("127.0.0.1:40000");
    const second = testAddress("127.0.0.1:40001");

    // Ports are not identity: same address, same bucket.
    try testing.expectEqual(Verdict.allowed, table.admit(&first, 0, policy));
    try testing.expectEqual(Verdict.limited, table.admit(&second, 0, policy));

    // A different host is a different client.
    const other = testAddress("127.0.0.2:40000");
    try testing.expectEqual(Verdict.allowed, table.admit(&other, 0, policy));
    try testing.expectEqual(Verdict.limited, table.admit(&other, 0, policy));
}

test "rate_limit: IPv4 and IPv6 identities are separate even at equal bits" {
    var storage: [8]Entry = undefined;
    var table = Table.fromStorage(&storage);
    const policy = testPolicy(1, 1000, 1);
    // 0.0.0.0 and :: both project to zero bits; only the family differs.
    const v4 = testAddress("0.0.0.0:0");
    const v6 = testAddress("[::]:0");

    try testing.expectEqual(Verdict.allowed, table.admit(&v4, 0, policy));
    try testing.expectEqual(Verdict.allowed, table.admit(&v6, 0, policy));
    try testing.expectEqual(Verdict.limited, table.admit(&v4, 0, policy));
    try testing.expectEqual(Verdict.limited, table.admit(&v6, 0, policy));
}

test "rate_limit: a full table allows new clients and reports it" {
    var storage: [1]Entry = undefined;
    var table = Table.fromStorage(&storage);
    const policy = testPolicy(1, 1000, 1);
    const first = testAddress("127.0.0.1:40000");
    const second = testAddress("127.0.0.2:40000");

    try testing.expectEqual(Verdict.allowed, table.admit(&first, 0, policy));
    // No slot within the probe window: fail open, named as such so the
    // caller can count the overflow.
    try testing.expectEqual(Verdict.table_full, table.admit(&second, 0, policy));
    // The already-tracked client is still limited, not lost to the
    // full-table case: its entry is still findable.
    try testing.expectEqual(Verdict.limited, table.admit(&first, 0, policy));
}
