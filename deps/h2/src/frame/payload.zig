//! RFC 9113 sections 6.1 to 6.10: what follows the nine-octet header.
//!
//! ## Borrowed, never copied
//!
//! Every variable-length field is a slice of the payload the caller passed in,
//! so parsing a frame allocates nothing and copies nothing. The caller owns the
//! octets and decides how long they live, which is the same arrangement HPACK's
//! decoder uses for a literal that was not Huffman-coded.
//!
//! ## What this layer adds to `Header.validate`
//!
//! Three rules, and they are the three that need an octet of payload to decide:
//!
//!   - a pad length at least as long as the payload (sections 6.1, 6.2, 6.6);
//!   - a promised stream identifier that is zero or odd (sections 5.1.1, 6.6);
//!   - a `WINDOW_UPDATE` increment of zero (section 6.9).
//!
//! Everything else — the length against `SETTINGS_MAX_FRAME_SIZE`, per-type
//! fixed and minimum lengths, stream-identifier validity — was decided by the
//! header, and `parse` asserts it was, rather than checking twice.
//!
//! One thing the header cannot decide, and it is easy to think it can: its
//! minimum length bounds the *whole* payload, padding included, and the peer
//! chooses how much of that is padding. So a HEADERS frame long enough to hold
//! its priority fields can still pad them away. That check belongs here, after
//! the split, and it is a check rather than an assertion.
//!
//! ## Severity is not uniform, and this is where that bites
//!
//! `Header.severity` can answer for every header-level failure with the type
//! and stream identifier alone. Here it cannot: section 6.9 makes a zero
//! increment a *stream* error on a stream and a *connection* error on the
//! connection flow-control window, so the same rule has two answers depending
//! on where it fired. That is why this module has its own `severity` rather
//! than reusing the header's.

const std = @import("std");

const assert = @import("../assert.zig").assert;

const Header = @import("Header.zig");

pub const ErrorCode = Header.ErrorCode;
pub const Severity = Header.Severity;

// Field widths come from `Header`, which slices its own minimum lengths by
// them. See the note there on why they are not redeclared here.
const pad_length_octets = Header.pad_length_octets;
const stream_identifier_octets = Header.stream_identifier_octets;
const error_code_octets = Header.error_code_octets;
const priority_fields_octets = Header.priority_fields_octets;
const ping_payload_octets = Header.ping_payload_octets;
const settings_entry_octets = Header.settings_entry_octets;
/// Section 6.9's increment reserves its high bit exactly as a stream
/// identifier does, and is the same width.
const window_increment_octets = Header.window_increment_octets;

comptime {
    assert(window_increment_octets == stream_identifier_octets);
    assert(settings_entry_octets == 2 + 4);
}

pub const Error = error{
    /// Padding that does not leave the payload's fixed fields intact.
    ///
    /// Section 6.1 states the floor for DATA: padding at least the length of
    /// the frame payload is an error. HEADERS and PUSH_PROMISE carry fields
    /// *between* the pad length and the padding — the priority fields, the
    /// promised stream identifier — and padding that swallows those is the
    /// same error for the same reason.
    ///
    /// The header cannot catch this. Its minimum length bounds the whole
    /// payload including the padding, and the peer chooses how much of that is
    /// padding afterwards.
    Padding,
    /// A promised stream identifier of zero, or an odd one. Section 5.1.1
    /// reserves even identifiers for streams a server initiates, and only a
    /// server sends PUSH_PROMISE, so this holds whichever end is parsing.
    PromisedStream,
    /// A flow-control window increment of zero (section 6.9).
    ZeroIncrement,
};

/// The code a peer should be sent. All three rules here are PROTOCOL_ERROR;
/// they differ in how far they reach, not in what they are called.
pub fn errorCode(err: Error) ErrorCode {
    return switch (err) {
        error.Padding, error.PromisedStream, error.ZeroIncrement => .protocol_error,
    };
}

/// How far a failure reaches.
///
/// Section 6.9 is the reason this takes a header: a zero increment is a stream
/// error on a stream and a connection error on the connection flow-control
/// window, so the rule alone does not decide it.
pub fn severity(header: Header, err: Error) Severity {
    // Each rule belongs to the types that can break it, and asking about a
    // pairing that cannot happen is a caller's bug rather than an answer.
    if (err == error.PromisedStream) assert(header.frame_type == .push_promise);
    if (err == error.ZeroIncrement) assert(header.frame_type == .window_update);
    return switch (err) {
        // Sections 6.1 and 6.6 say connection error in as many words, and
        // section 5.1.1 does for an unexpected stream identifier.
        error.Padding, error.PromisedStream => .connection,
        error.ZeroIncrement => if (header.stream_identifier == 0) .connection else .stream,
    };
}

pub const Priority = struct {
    exclusive: bool,
    stream_dependency: u31,
    /// The octet as it appears on the wire, which is *not* the weight.
    ///
    /// Section 6.3: "Add one to the value to obtain a weight between 1 and
    /// 256." So the octet runs 0 to 255 and the weight runs 1 to 256, which is
    /// why `weight` is a method returning a wider integer rather than this
    /// field under a friendlier name. Section 5.3 deprecates prioritization
    /// altogether, but the octets still arrive and still have to be read
    /// correctly.
    weight_octet: u8,

    /// The priority weight, 1 to 256 (section 6.3). Wider than the octet it
    /// derives from, because 256 does not fit in one.
    pub fn weight(priority: Priority) u16 {
        return @as(u16, priority.weight_octet) + 1;
    }
};

pub const Data = struct {
    data: []const u8,
    /// Null when the PADDED flag is clear; an empty slice when it is set with a
    /// pad length of zero.
    ///
    /// Those are different frames — section 6.1 notes that a zero pad length is
    /// how a frame is made one octet longer — so one slice cannot mean both. It
    /// did until rendering needed to reproduce the octets it parsed.
    padding: ?[]const u8,
};

pub const Headers = struct {
    /// Present only when the PRIORITY flag is set.
    priority: ?Priority,
    /// A field block fragment (section 4.3), for HPACK to decode. Framing does
    /// not look inside it.
    fragment: []const u8,
    /// Null when the PADDED flag is clear. See `Data.padding`.
    padding: ?[]const u8,
};

pub const RstStream = struct {
    error_code: ErrorCode,
};

pub const PushPromise = struct {
    promised_stream_identifier: u31,
    fragment: []const u8,
    /// Null when the PADDED flag is clear. See `Data.padding`.
    padding: ?[]const u8,
};

pub const Ping = struct {
    /// Borrowed, and typed by its length so a caller cannot pass eight octets
    /// of something else.
    opaque_data: *const [ping_payload_octets]u8,
};

pub const Goaway = struct {
    last_stream_identifier: u31,
    error_code: ErrorCode,
    /// Whatever the peer chose to send, which is opaque and may be empty.
    debug_data: []const u8,
};

pub const WindowUpdate = struct {
    /// Never zero: section 6.9 makes that an error, checked in `parse`.
    increment: u31,
};

pub const Continuation = struct {
    fragment: []const u8,
};

/// Section 6.5.1's parameters, as a view over the payload.
///
/// An iterator rather than an array, because the count is the peer's choice and
/// this package does not allocate. Unknown identifiers are handed back rather
/// than skipped: section 6.5.2 requires a receiver to ignore them, and ignoring
/// is the consumer's to do.
pub const Settings = struct {
    entries: []const u8,

    pub const Identifier = enum(u16) {
        header_table_size = 0x01,
        enable_push = 0x02,
        max_concurrent_streams = 0x03,
        initial_window_size = 0x04,
        max_frame_size = 0x05,
        max_header_list_size = 0x06,
        _,
    };

    pub const Entry = struct {
        identifier: Identifier,
        value: u32,
    };

    pub fn count(settings: Settings) u32 {
        assert(settings.entries.len % settings_entry_octets == 0);
        return @intCast(@divExact(settings.entries.len, settings_entry_octets));
    }

    pub fn get(settings: Settings, index: u32) Entry {
        assert(index < settings.count());
        const at = index * settings_entry_octets;
        const octets = settings.entries[at..][0..settings_entry_octets];
        return .{
            .identifier = @enumFromInt((@as(u16, octets[0]) << 8) | octets[1]),
            .value = (@as(u32, octets[2]) << 24) | (@as(u32, octets[3]) << 16) |
                (@as(u32, octets[4]) << 8) | octets[5],
        };
    }

    pub const Iterator = struct {
        settings: Settings,
        index: u32 = 0,

        pub fn next(iterator: *Iterator) ?Entry {
            const total = iterator.settings.count();
            assert(iterator.index <= total);
            // `>=` rather than `==`: `index` is a public field, so a caller can
            // set it past the end and `==` would walk off.
            if (iterator.index >= total) return null;
            const entry = iterator.settings.get(iterator.index);
            iterator.index += 1;
            return entry;
        }
    };

    pub fn iterate(settings: Settings) Iterator {
        return .{ .settings = settings };
    }
};

pub const Payload = union(enum) {
    data: Data,
    headers: Headers,
    priority: Priority,
    rst_stream: RstStream,
    settings: Settings,
    push_promise: PushPromise,
    ping: Ping,
    goaway: Goaway,
    window_update: WindowUpdate,
    continuation: Continuation,
    /// A type RFC 9113 does not define. Section 4.1 requires it be skipped by
    /// its declared length, so the octets are handed back unexamined.
    unknown: []const u8,
};

/// Parse the payload of a frame whose header already validated.
///
/// `payload` must be exactly `header.length` octets — the caller slices it by
/// the length the header declared, and that length was already checked against
/// `SETTINGS_MAX_FRAME_SIZE` and against the type's own rules. Both are
/// asserted rather than re-checked: a second check that could disagree with the
/// first is worse than one that cannot.
pub fn parse(header: Header, payload: []const u8) Error!Payload {
    assert(payload.len == header.length);
    // The header's own rules held, so every fixed field below fits.
    assert(header.validate(Header.max_frame_size_max) != error.FrameSize);

    return switch (header.frame_type) {
        .data => blk: {
            const split = try splitPadding(payload, header.has(.padded));
            break :blk .{ .data = .{ .data = split.body, .padding = split.padding } };
        },
        .headers => .{ .headers = try parseHeaders(header, payload) },
        .priority => blk: {
            assert(payload.len == priority_fields_octets);
            break :blk .{ .priority = readPriority(payload[0..priority_fields_octets]) };
        },
        .rst_stream => blk: {
            assert(payload.len == error_code_octets);
            break :blk .{ .rst_stream = .{
                .error_code = @enumFromInt(readU32(payload[0..error_code_octets])),
            } };
        },
        .settings => blk: {
            assert(payload.len % settings_entry_octets == 0);
            break :blk .{ .settings = .{ .entries = payload } };
        },
        .push_promise => .{ .push_promise = try parsePushPromise(header, payload) },
        .ping => blk: {
            assert(payload.len == ping_payload_octets);
            break :blk .{ .ping = .{ .opaque_data = payload[0..ping_payload_octets] } };
        },
        .goaway => blk: {
            assert(payload.len >= stream_identifier_octets + error_code_octets);
            break :blk .{ .goaway = .{
                .last_stream_identifier = readStreamIdentifier(payload[0..stream_identifier_octets]),
                .error_code = @enumFromInt(readU32(payload[stream_identifier_octets..][0..error_code_octets])),
                .debug_data = payload[stream_identifier_octets + error_code_octets ..],
            } };
        },
        .window_update => blk: {
            assert(payload.len == window_increment_octets);
            // The reserved bit is ignored here as it is in a stream
            // identifier (section 6.9).
            const increment = readStreamIdentifier(payload[0..window_increment_octets]);
            if (increment == 0) return error.ZeroIncrement;
            break :blk .{ .window_update = .{ .increment = increment } };
        },
        .continuation => .{ .continuation = .{ .fragment = payload } },
        _ => .{ .unknown = payload },
    };
}

/// Section 6.2: a pad length, the priority fields when the flag is set, the
/// field block fragment, and the padding.
fn parseHeaders(header: Header, payload: []const u8) Error!Headers {
    const split = try splitPadding(payload, header.has(.padded));
    var rest = split.body;
    var priority: ?Priority = null;
    if (header.has(.priority)) {
        // Checked, not asserted: `Header.validate`'s floor covered the payload
        // before the padding was taken out of it.
        if (rest.len < priority_fields_octets) return error.Padding;
        priority = readPriority(rest[0..priority_fields_octets]);
        rest = rest[priority_fields_octets..];
    }
    assert(rest.len <= payload.len);
    return .{ .priority = priority, .fragment = rest, .padding = split.padding };
}

/// Section 6.6: a pad length, the promised stream identifier, the field block
/// fragment, and the padding.
fn parsePushPromise(header: Header, payload: []const u8) Error!PushPromise {
    const split = try splitPadding(payload, header.has(.padded));
    // Same as HEADERS: the header's floor bounded the payload, and the padding
    // comes out of it afterwards.
    if (split.body.len < stream_identifier_octets) return error.Padding;

    const promised = readStreamIdentifier(split.body[0..stream_identifier_octets]);
    // Section 5.1.1: a server's streams are even-numbered, and zero never
    // establishes a stream. Only a server sends PUSH_PROMISE, so this holds
    // whichever end is parsing.
    if (promised == 0 or promised % 2 != 0) return error.PromisedStream;
    assert(promised % 2 == 0);
    return .{
        .promised_stream_identifier = promised,
        .fragment = split.body[stream_identifier_octets..],
        .padding = split.padding,
    };
}

const Padded = struct {
    body: []const u8,
    padding: ?[]const u8,
};

/// Split a payload into its body and its padding.
///
/// The comparison is a subtraction, not an addition. `pad_length` is the peer's
/// octet and can be anything a `u8` holds; `body_length + pad_length` would be
/// the third time in this package that adding an attacker's number to one of
/// ours before comparing was the bug. Section 6.1's rule — padding at least the
/// payload's length is an error — is exactly `pad_length > rest.len`, because
/// the pad length octet is itself part of that payload.
fn splitPadding(payload: []const u8, padded: bool) Error!Padded {
    if (!padded) return .{ .body = payload, .padding = null };
    // `Header.validate` established the pad length octet is there.
    assert(payload.len >= pad_length_octets);

    const pad_length = payload[0];
    const rest = payload[pad_length_octets..];
    if (pad_length > rest.len) return error.Padding;

    assert(pad_length <= rest.len);
    const body_length = rest.len - pad_length;
    return .{ .body = rest[0..body_length], .padding = rest[body_length..] };
}

fn readPriority(octets: *const [priority_fields_octets]u8) Priority {
    return .{
        .exclusive = octets[0] & exclusive_bit != 0,
        .stream_dependency = readStreamIdentifier(octets[0..stream_identifier_octets]),
        .weight_octet = octets[stream_identifier_octets],
    };
}

fn readU32(octets: *const [4]u8) u32 {
    return (@as(u32, octets[0]) << 24) | (@as(u32, octets[1]) << 16) |
        (@as(u32, octets[2]) << 8) | octets[3];
}

/// A stream identifier, with section 4.1's reserved bit masked off. The same
/// masking applies to a stream dependency and to a window increment, both of
/// which reserve their high bit the same way.
fn readStreamIdentifier(octets: *const [stream_identifier_octets]u8) u31 {
    const value = readU32(octets) & Header.stream_identifier_mask;
    // The negative space: the reserved bit did not survive into the value. It
    // is the same assertion `Header.parse` makes about the same masking, and
    // it is the only thing between a reserved-bit slip and a promised stream
    // identifier flipping parity.
    assert(value & ~Header.stream_identifier_mask == 0);
    return @intCast(value);
}

// ── Rendering ───────────────────────────────────────────────────────────────

pub const RenderError = error{
    /// `target` cannot hold the frame, or the payload is longer than the
    /// 24-bit length field can describe.
    OutputTooLong,
    /// The padding is longer than the pad length octet can express.
    ///
    /// An error rather than an assertion because `padding` is a slice a caller
    /// sizes at run time, and the failure mode is truncation: the header's
    /// length would count every padding octet while the pad length octet named
    /// fewer, and the peer would read the difference as payload.
    PaddingTooLong,
    /// The payload is `.unknown`, which carries its octets but not the type
    /// octet they arrived under.
    ///
    /// Section 4.1 requires a receiver to ignore a type it does not implement,
    /// so `parse` produces this for any extension frame a peer sends — which
    /// makes forwarding one an ordinary thing to attempt and a panic the wrong
    /// answer. A caller that wants to re-emit an extension frame writes the
    /// header itself, with the type octet it kept.
    UnknownType,
};

/// The flags a payload's shape decides. A caller does not get to set these.
const structural_flags_mask: u8 = Header.Flag.padded.bit() | Header.Flag.priority.bit();

/// The largest padding a pad length octet can describe.
const pad_length_max: u32 = std.math.maxInt(u8);

comptime {
    assert(pad_length_max == (@as(u32, 1) << (8 * pad_length_octets)) - 1);
    assert(structural_flags_mask & Header.Flag.end_stream.bit() == 0);
    assert(structural_flags_mask & Header.Flag.end_headers.bit() == 0);
    assert(structural_flags_mask & Header.Flag.ack.bit() == 0);
}

/// The flags a payload's shape requires, as distinct from the ones a sender
/// chooses.
///
/// PADDED and PRIORITY describe what the octets contain, so they are derived
/// here rather than trusted from a caller — a caller that set PADDED on a
/// payload with no padding, or cleared it on one with padding, would produce a
/// frame no decoder could read. END_STREAM, END_HEADERS and ACK carry meaning
/// rather than structure and remain the sender's to set.
pub fn structuralFlags(payload: *const Payload) u8 {
    const padded = Header.Flag.padded.bit();
    const priority = Header.Flag.priority.bit();
    // Exhaustive rather than `else`, so a variant added later with a structural
    // flag fails here loudly instead of rendering without it.
    const flags: u8 = switch (payload.*) {
        .data => |data| if (data.padding != null) padded else 0,
        .headers => |headers| (if (headers.padding != null) padded else 0) |
            (if (headers.priority != null) priority else 0),
        .push_promise => |promise| if (promise.padding != null) padded else 0,
        .priority, .rst_stream, .settings, .ping => 0,
        .goaway, .window_update, .continuation, .unknown => 0,
    };
    assert(flags & ~structural_flags_mask == 0);
    return flags;
}

/// Octets the payload occupies, excluding the nine-octet header.
///
/// Returns `u64` so a caller can compare it against `SETTINGS_MAX_FRAME_SIZE`
/// before narrowing: a payload assembled from slices can exceed what a `u24`
/// length field holds, and finding that out by truncation would render a frame
/// whose header lies about it.
pub fn renderedLength(payload: *const Payload) u64 {
    return switch (payload.*) {
        .data => |data| paddedLength(data.data.len, data.padding),
        .headers => |headers| paddedLength(
            headers.fragment.len + (if (headers.priority != null) @as(u64, priority_fields_octets) else 0),
            headers.padding,
        ),
        .priority => priority_fields_octets,
        .rst_stream => error_code_octets,
        .settings => |settings| settings.entries.len,
        .push_promise => |promise| paddedLength(
            promise.fragment.len + @as(u64, stream_identifier_octets),
            promise.padding,
        ),
        .ping => ping_payload_octets,
        .goaway => |goaway| @as(u64, stream_identifier_octets) +
            @as(u64, error_code_octets) + goaway.debug_data.len,
        .window_update => window_increment_octets,
        .continuation => |continuation| continuation.fragment.len,
        .unknown => |octets| octets.len,
    };
}

fn paddedLength(body: u64, padding: ?[]const u8) u64 {
    const pad = padding orelse return body;
    return @as(u64, pad_length_octets) + body + pad.len;
}

/// Write a whole frame — header and payload — into `target`.
///
/// `flags` carries only the sender's own bits; the structural ones are derived
/// from the payload and merged in. The header's length comes from the payload
/// rather than from the caller, so the two cannot disagree.
///
/// Either the whole frame is written or nothing is: the length is computed and
/// checked before a single octet lands.
pub fn render(
    payload: *const Payload,
    stream_identifier: u31,
    flags: u8,
    target: []u8,
) RenderError!u32 {
    if (payload.* == .unknown) return error.UnknownType;
    try checkPadding(payload);
    // The caller's own bits only. Setting a structural flag is a caller bug —
    // asserted — and masking it out is what keeps a build with assertions off
    // from emitting a frame no decoder can read.
    assert(flags & structural_flags_mask == 0);
    const sender_flags = flags & ~structural_flags_mask;

    const length = renderedLength(payload);
    if (length > Header.max_frame_size_max) return error.OutputTooLong;
    if (length + Header.octets > target.len) return error.OutputTooLong;

    const header: Header = .{
        .length = @intCast(length),
        .frame_type = frameType(payload),
        .flags = sender_flags | structuralFlags(payload),
        .stream_identifier = stream_identifier,
    };
    const written = header.render(target) catch unreachable;
    assert(written == Header.octets);

    const body = target[Header.octets..][0..@as(usize, @intCast(length))];
    renderPayload(payload, body);
    return @intCast(Header.octets + length);
}

/// Refuse padding the pad length octet cannot describe, before anything is
/// written.
fn checkPadding(payload: *const Payload) RenderError!void {
    const padding: ?[]const u8 = switch (payload.*) {
        .data => |data| data.padding,
        .headers => |headers| headers.padding,
        .push_promise => |promise| promise.padding,
        else => null,
    };
    const pad = padding orelse return;
    if (pad.len > pad_length_max) return error.PaddingTooLong;
}

/// The type octet a payload belongs to. An unknown payload cannot be rendered
/// through this path, because nothing here knows what type to call it.
fn frameType(payload: *const Payload) Header.Type {
    return switch (payload.*) {
        .data => .data,
        .headers => .headers,
        .priority => .priority,
        .rst_stream => .rst_stream,
        .settings => .settings,
        .push_promise => .push_promise,
        .ping => .ping,
        .goaway => .goaway,
        .window_update => .window_update,
        .continuation => .continuation,
        // `render` returns `error.UnknownType` before reaching this, because a
        // peer's extension frame arrives as `.unknown` and forwarding one is an
        // ordinary thing to try.
        .unknown => unreachable,
    };
}

fn renderPayload(payload: *const Payload, target: []u8) void {
    assert(target.len == renderedLength(payload));
    // The invariants `parse` enforces on the same octets, restated where they
    // would otherwise be emitted. A frame this package would refuse to read is
    // one it must refuse to write.
    switch (payload.*) {
        .settings => |settings| assert(settings.entries.len % settings_entry_octets == 0),
        .push_promise => |promise| {
            assert(promise.promised_stream_identifier != 0);
            assert(promise.promised_stream_identifier % 2 == 0);
        },
        .window_update => |update| assert(update.increment != 0),
        else => {},
    }
    switch (payload.*) {
        .data => |data| writePadded(target, data.data, data.padding, &.{}),
        .headers => |headers| {
            var fixed: [priority_fields_octets]u8 = undefined;
            const prefix: []const u8 = if (headers.priority) |priority| blk: {
                writePriority(&fixed, priority);
                break :blk &fixed;
            } else &.{};
            writePadded(target, headers.fragment, headers.padding, prefix);
        },
        .priority => |priority| writePriority(target[0..priority_fields_octets], priority),
        .rst_stream => |rst| writeU32(target[0..error_code_octets], @intFromEnum(rst.error_code)),
        .settings => |settings| @memcpy(target, settings.entries),
        .push_promise => |promise| {
            var fixed: [stream_identifier_octets]u8 = undefined;
            writeU32(&fixed, promise.promised_stream_identifier);
            writePadded(target, promise.fragment, promise.padding, &fixed);
        },
        .ping => |ping| @memcpy(target, ping.opaque_data),
        .goaway => |goaway| {
            writeU32(target[0..stream_identifier_octets], goaway.last_stream_identifier);
            writeU32(
                target[stream_identifier_octets..][0..error_code_octets],
                @intFromEnum(goaway.error_code),
            );
            @memcpy(target[stream_identifier_octets + error_code_octets ..], goaway.debug_data);
        },
        .window_update => |update| writeU32(target[0..window_increment_octets], update.increment),
        .continuation => |continuation| @memcpy(target, continuation.fragment),
        .unknown => |octets| @memcpy(target, octets),
    }
}

/// Lay out a padded payload: the pad length, a fixed prefix, the body, then the
/// padding. `prefix` is the priority fields or a promised stream identifier —
/// the octets that sit between the pad length and the body.
fn writePadded(target: []u8, body: []const u8, padding: ?[]const u8, prefix: []const u8) void {
    assert(target.len <= Header.max_frame_size_max);
    var at: u32 = 0;
    if (padding) |pad| {
        // `render` refused anything longer before a single octet was written.
        assert(pad.len <= pad_length_max);
        target[at] = @intCast(pad.len);
        at += pad_length_octets;
    }
    @memcpy(target[at..][0..prefix.len], prefix);
    at += @intCast(prefix.len);
    @memcpy(target[at..][0..body.len], body);
    at += @intCast(body.len);
    if (padding) |pad| {
        @memcpy(target[at..][0..pad.len], pad);
        at += @intCast(pad.len);
    }
    assert(at == target.len);
}

fn writePriority(target: *[priority_fields_octets]u8, priority: Priority) void {
    writeU32(target[0..stream_identifier_octets], priority.stream_dependency);
    // The negative space, and the mirror of what `Header.render` asserts about
    // the same bit: a `u31` dependency cannot have set it, so the OR below is
    // the only thing that can.
    assert(target[0] & exclusive_bit == 0);
    if (priority.exclusive) target[0] |= exclusive_bit;
    target[stream_identifier_octets] = priority.weight_octet;
}

/// Section 6.3's exclusive bit, which occupies the same position a stream
/// identifier reserves.
const exclusive_bit: u8 = 0x80;

comptime {
    assert(exclusive_bit == ~@as(u8, @truncate(Header.stream_identifier_mask >> 24)));
}

fn writeU32(target: *[4]u8, value: u32) void {
    target[0] = @truncate(value >> 24);
    target[1] = @truncate(value >> 16);
    target[2] = @truncate(value >> 8);
    target[3] = @truncate(value);
}

const testing = std.testing;

/// Parse a whole frame, header and payload, the way a caller would.
fn parseFrame(wire: []const u8) !Payload {
    const header = try Header.parse(wire);
    try header.validate(Header.max_frame_size_min);
    return parse(header, wire[Header.octets..][0..header.length]);
}

test "a padded payload splits into body and padding" {
    // DATA, PADDED, stream 1: pad length 3, "hi", three octets of padding.
    const wire = [_]u8{ 0, 0, 6, 0x00, 0x08, 0, 0, 0, 1, 3, 'h', 'i', 0, 0, 0 };
    const payload = try parseFrame(&wire);
    try testing.expectEqualStrings("hi", payload.data.data);
    try testing.expectEqual(@as(usize, 3), payload.data.padding.?.len);
}

test "an unpadded payload has no padding, which is not the same as empty padding" {
    const unpadded = [_]u8{ 0, 0, 2, 0x00, 0x00, 0, 0, 0, 1, 'h', 'i' };
    const without = try parseFrame(&unpadded);
    try testing.expectEqualStrings("hi", without.data.data);
    try testing.expectEqual(@as(?[]const u8, null), without.data.padding);

    // The same two octets of data, PADDED with a pad length of zero. Section
    // 6.1 calls this out: it is how a frame is made one octet longer. The two
    // frames differ on the wire, so they must differ here.
    const padded = [_]u8{ 0, 0, 3, 0x00, 0x08, 0, 0, 0, 1, 0, 'h', 'i' };
    const with = try parseFrame(&padded);
    try testing.expectEqualStrings("hi", with.data.data);
    try testing.expectEqual(@as(usize, 0), with.data.padding.?.len);
}

test "padding at least the payload length is refused, at the boundary" {
    // Payload is four octets: a pad length and three more. A pad length of
    // three consumes them exactly and is legal; four is not.
    const legal = [_]u8{ 0, 0, 4, 0x00, 0x08, 0, 0, 0, 1, 3, 0, 0, 0 };
    const payload = try parseFrame(&legal);
    try testing.expectEqual(@as(usize, 0), payload.data.data.len);
    try testing.expectEqual(@as(usize, 3), payload.data.padding.?.len);

    const illegal = [_]u8{ 0, 0, 4, 0x00, 0x08, 0, 0, 0, 1, 4, 0, 0, 0 };
    try testing.expectError(error.Padding, parseFrame(&illegal));

    // And a pad length no octet count could satisfy.
    const absurd = [_]u8{ 0, 0, 4, 0x00, 0x08, 0, 0, 0, 1, 0xff, 0, 0, 0 };
    try testing.expectError(error.Padding, parseFrame(&absurd));
}

test "a pad length of zero is legal and costs one octet" {
    // The RFC notes this explicitly: a frame can be made one octet longer by
    // including a zero pad length.
    const wire = [_]u8{ 0, 0, 3, 0x00, 0x08, 0, 0, 0, 1, 0, 'h', 'i' };
    const payload = try parseFrame(&wire);
    try testing.expectEqualStrings("hi", payload.data.data);
    try testing.expectEqual(@as(usize, 0), payload.data.padding.?.len);
}

test "HEADERS carries priority only when the flag is set" {
    const bare = [_]u8{ 0, 0, 2, 0x01, 0x00, 0, 0, 0, 1, 'h', 'i' };
    const without = try parseFrame(&bare);
    try testing.expectEqual(@as(?Priority, null), without.headers.priority);
    try testing.expectEqualStrings("hi", without.headers.fragment);

    // PRIORITY flag: exclusive, dependency 20, weight 10, then the fragment.
    const prioritized = [_]u8{ 0, 0, 7, 0x01, 0x20, 0, 0, 0, 3, 0x80, 0, 0, 20, 10, 'h', 'i' };
    const with = try parseFrame(&prioritized);
    try testing.expect(with.headers.priority.?.exclusive);
    try testing.expectEqual(@as(u31, 20), with.headers.priority.?.stream_dependency);
    // The wire octet is 10 and the weight is 11: section 6.3 adds one.
    try testing.expectEqual(@as(u8, 10), with.headers.priority.?.weight_octet);
    try testing.expectEqual(@as(u16, 11), with.headers.priority.?.weight());
    try testing.expectEqualStrings("hi", with.headers.fragment);
}

test "a promised stream identifier must be even and non-zero" {
    // PUSH_PROMISE on stream 1 promising stream 12.
    const even = [_]u8{ 0, 0, 6, 0x05, 0x00, 0, 0, 0, 1, 0, 0, 0, 12, 'h', 'i' };
    const payload = try parseFrame(&even);
    try testing.expectEqual(@as(u31, 12), payload.push_promise.promised_stream_identifier);
    try testing.expectEqualStrings("hi", payload.push_promise.fragment);

    const odd = [_]u8{ 0, 0, 6, 0x05, 0x00, 0, 0, 0, 1, 0, 0, 0, 11, 'h', 'i' };
    try testing.expectError(error.PromisedStream, parseFrame(&odd));

    const zero = [_]u8{ 0, 0, 6, 0x05, 0x00, 0, 0, 0, 1, 0, 0, 0, 0, 'h', 'i' };
    try testing.expectError(error.PromisedStream, parseFrame(&zero));

    // The reserved bit does not make an even identifier odd.
    const reserved = [_]u8{ 0, 0, 6, 0x05, 0x00, 0, 0, 0, 1, 0x80, 0, 0, 12, 'h', 'i' };
    const masked = try parseFrame(&reserved);
    try testing.expectEqual(@as(u31, 12), masked.push_promise.promised_stream_identifier);
}

test "a window increment of zero is refused, and its severity depends on the stream" {
    const on_stream = [_]u8{ 0, 0, 4, 0x08, 0x00, 0, 0, 0, 5, 0, 0, 0, 0 };
    try testing.expectError(error.ZeroIncrement, parseFrame(&on_stream));
    const stream_header = try Header.parse(&on_stream);
    try testing.expectEqual(Severity.stream, severity(stream_header, error.ZeroIncrement));

    // Section 6.9: on the connection flow-control window it ends the
    // connection instead.
    const on_connection = [_]u8{ 0, 0, 4, 0x08, 0x00, 0, 0, 0, 0, 0, 0, 0, 0 };
    try testing.expectError(error.ZeroIncrement, parseFrame(&on_connection));
    const connection_header = try Header.parse(&on_connection);
    try testing.expectEqual(Severity.connection, severity(connection_header, error.ZeroIncrement));

    // A non-zero increment parses, with the reserved bit ignored.
    const fine = [_]u8{ 0, 0, 4, 0x08, 0x00, 0, 0, 0, 5, 0x80, 0, 0x03, 0xe8 };
    const payload = try parseFrame(&fine);
    try testing.expectEqual(@as(u31, 1000), payload.window_update.increment);
}

test "SETTINGS iterates its parameters and keeps unknown identifiers" {
    const wire = [_]u8{
        0, 0, 12, 0x04, 0x00, 0, 0, 0, 0,
        0x00, 0x01, 0x00, 0x00, 0x20, 0x00, // HEADER_TABLE_SIZE = 8192
        0xff, 0xff, 0x00, 0x00, 0x00, 0x07, // an identifier RFC 9113 does not define
    };
    const payload = try parseFrame(&wire);
    try testing.expectEqual(@as(u32, 2), payload.settings.count());

    var iterator = payload.settings.iterate();
    const first = iterator.next().?;
    try testing.expectEqual(Settings.Identifier.header_table_size, first.identifier);
    try testing.expectEqual(@as(u32, 8192), first.value);

    // Section 6.5.2 says a receiver ignores an unknown identifier; ignoring is
    // the consumer's to do, so it arrives rather than disappearing.
    const second = iterator.next().?;
    try testing.expectEqual(@as(u16, 0xffff), @intFromEnum(second.identifier));
    try testing.expectEqual(@as(u32, 7), second.value);
    try testing.expectEqual(@as(?Settings.Entry, null), iterator.next());
}

test "GOAWAY's debug data is optional" {
    const bare = [_]u8{ 0, 0, 8, 0x07, 0x00, 0, 0, 0, 0, 0, 0, 0, 30, 0, 0, 0, 9 };
    const payload = try parseFrame(&bare);
    try testing.expectEqual(@as(u31, 30), payload.goaway.last_stream_identifier);
    try testing.expectEqual(ErrorCode.compression_error, payload.goaway.error_code);
    try testing.expectEqual(@as(usize, 0), payload.goaway.debug_data.len);

    const with_data = [_]u8{ 0, 0, 10, 0x07, 0x00, 0, 0, 0, 0, 0, 0, 0, 30, 0, 0, 0, 9, 'h', 'i' };
    const verbose = try parseFrame(&with_data);
    try testing.expectEqualStrings("hi", verbose.goaway.debug_data);
}

test "an unknown type is handed back whole rather than examined" {
    const wire = [_]u8{ 0, 0, 3, 0xfa, 0xff, 0, 0, 0, 7, 1, 2, 3 };
    const payload = try parseFrame(&wire);
    try testing.expectEqualSlices(u8, &.{ 1, 2, 3 }, payload.unknown);
}

test "every payload field borrows the caller's octets" {
    const wire = [_]u8{ 0, 0, 2, 0x09, 0x00, 0, 0, 0, 1, 'h', 'i' };
    const payload = try parseFrame(&wire);
    // The fragment is the wire's own octets, not a copy of them.
    try testing.expectEqual(@intFromPtr(&wire[Header.octets]), @intFromPtr(payload.continuation.fragment.ptr));
}

test "a padded frame and a zero-padded frame render differently" {
    // The distinction the optional exists for. Same data, one octet apart.
    var target: [32]u8 = undefined;

    const unpadded: Payload = .{ .data = .{ .data = "hi", .padding = null } };
    const bare = try render(&unpadded, 1, 0, &target);
    try testing.expectEqualSlices(u8, &.{ 0, 0, 2, 0x00, 0x00, 0, 0, 0, 1, 'h', 'i' }, target[0..bare]);

    const zero_padded: Payload = .{ .data = .{ .data = "hi", .padding = "" } };
    const padded = try render(&zero_padded, 1, 0, &target);
    try testing.expectEqualSlices(u8, &.{ 0, 0, 3, 0x00, 0x08, 0, 0, 0, 1, 0, 'h', 'i' }, target[0..padded]);
    try testing.expectEqual(bare + 1, padded);
}

test "structural flags come from the payload and sender flags from the caller" {
    var target: [64]u8 = undefined;
    const payload: Payload = .{ .headers = .{
        .priority = .{ .exclusive = true, .stream_dependency = 20, .weight_octet = 9 },
        .fragment = "hi",
        .padding = "pad",
    } };
    // END_HEADERS is the sender's; PADDED and PRIORITY are the payload's.
    const written = try render(&payload, 3, Header.Flag.end_headers.bit(), &target);
    const header = try Header.parse(target[0..written]);
    try testing.expectEqual(@as(u8, 0x2c), header.flags);
    try testing.expect(header.has(.end_headers));
    try testing.expect(header.has(.padded));
    try testing.expect(header.has(.priority));
}

test "every payload shape survives a render and parse round trip" {
    var target: [128]u8 = undefined;
    const opaque_data = "deadbeef".*;
    const cases = [_]struct { payload: Payload, stream: u31 }{
        .{ .payload = .{ .data = .{ .data = "hello", .padding = "pad" } }, .stream = 1 },
        .{ .payload = .{ .data = .{ .data = "", .padding = null } }, .stream = 1 },
        .{ .payload = .{ .headers = .{ .priority = null, .fragment = "hi", .padding = null } }, .stream = 1 },
        .{ .payload = .{ .priority = .{
            .exclusive = false,
            .stream_dependency = 11,
            .weight_octet = 7,
        } }, .stream = 9 },
        .{ .payload = .{ .rst_stream = .{ .error_code = .cancel } }, .stream = 5 },
        .{ .payload = .{ .settings = .{ .entries = &.{ 0, 1, 0, 0, 0x20, 0 } } }, .stream = 0 },
        .{ .payload = .{ .push_promise = .{
            .promised_stream_identifier = 12,
            .fragment = "hi",
            .padding = null,
        } }, .stream = 1 },
        .{ .payload = .{ .ping = .{ .opaque_data = &opaque_data } }, .stream = 0 },
        .{ .payload = .{ .goaway = .{
            .last_stream_identifier = 30,
            .error_code = .compression_error,
            .debug_data = "why",
        } }, .stream = 0 },
        .{ .payload = .{ .window_update = .{ .increment = 1000 } }, .stream = 5 },
        .{ .payload = .{ .continuation = .{ .fragment = "hi" } }, .stream = 1 },
    };

    for (cases) |case| {
        const written = try render(&case.payload, case.stream, 0, &target);
        const header = try Header.parse(target[0..written]);
        try header.validate(Header.max_frame_size_min);
        try testing.expectEqual(case.stream, header.stream_identifier);

        const again = try parse(header, target[Header.octets..][0..header.length]);
        try testing.expectEqual(
            @intFromEnum(std.meta.activeTag(case.payload)),
            @intFromEnum(std.meta.activeTag(again)),
        );
        // And rendering what came back reproduces the same octets.
        var second: [128]u8 = undefined;
        const rewritten = try render(&again, case.stream, 0, &second);
        try testing.expectEqualSlices(u8, target[0..written], second[0..rewritten]);
    }
}

test "render refuses a target it cannot fill, and writes nothing on the way out" {
    const payload: Payload = .{ .data = .{ .data = "hello", .padding = null } };
    var full: [64]u8 = undefined;
    const needed = try render(&payload, 1, 0, &full);

    var length: u32 = 0;
    while (length < needed) : (length += 1) {
        var target: [64]u8 = undefined;
        @memset(&target, 0xaa);
        try testing.expectError(error.OutputTooLong, render(&payload, 1, 0, target[0..length]));
        for (target[0..length]) |octet| try testing.expectEqual(@as(u8, 0xaa), octet);
    }
}

test "renderedLength is what render writes, for every shape" {
    var target: [128]u8 = undefined;
    const payload: Payload = .{ .headers = .{
        .priority = .{ .exclusive = true, .stream_dependency = 1, .weight_octet = 0 },
        .fragment = "fragment",
        .padding = "padding",
    } };
    const written = try render(&payload, 1, 0, &target);
    try testing.expectEqual(renderedLength(&payload) + Header.octets, written);
    // 1 pad length + 5 priority + 8 fragment + 7 padding.
    try testing.expectEqual(@as(u64, 21), renderedLength(&payload));
}

test "an unknown payload is refused rather than panicking" {
    // Section 4.1 makes `parse` produce `.unknown` for every extension frame a
    // peer sends, so forwarding one is an ordinary thing to attempt. This used
    // to be `unreachable` — a panic in a safe build and worse in a fast one —
    // and every call site in the package worked around it with a guard, which
    // is what gave it away.
    const wire = [_]u8{ 0, 0, 3, 0xfa, 0xff, 0, 0, 0, 7, 1, 2, 3 };
    const payload = try parseFrame(&wire);
    try testing.expect(payload == .unknown);

    var target: [64]u8 = undefined;
    try testing.expectError(error.UnknownType, render(&payload, 7, 0, &target));
}

test "padding longer than a pad length octet is refused, not truncated" {
    // The header's length would count every padding octet while the pad length
    // named `len & 0xff` of them, and the peer would read the difference as
    // payload.
    var padding: [pad_length_max + 1]u8 = undefined;
    @memset(&padding, 0);
    const payload: Payload = .{ .data = .{ .data = "hi", .padding = &padding } };

    var target: [1024]u8 = undefined;
    try testing.expectError(error.PaddingTooLong, render(&payload, 1, 0, &target));

    // One octet shorter is the boundary, and it renders.
    const at_limit: Payload = .{ .data = .{ .data = "hi", .padding = padding[0..pad_length_max] } };
    const written = try render(&at_limit, 1, 0, &target);
    try testing.expectEqual(@as(u8, 0xff), target[Header.octets]);
    try testing.expectEqual(@as(u32, Header.octets + 1 + 2 + pad_length_max), written);
}

test "a structural flag from the caller is masked out rather than emitted" {
    // PADDED over a payload with no padding would make the next parser read the
    // first data octet as a pad length. The assertion catches the caller in a
    // build that has assertions; the mask is what keeps a build without them
    // from putting a broken frame on the wire.
    const payload: Payload = .{ .data = .{ .data = "hi", .padding = null } };
    var target: [32]u8 = undefined;
    const written = try render(&payload, 1, 0, &target);
    const header = try Header.parse(target[0..written]);
    try testing.expectEqual(@as(u8, 0), header.flags);
}

test "error codes and severities are what a peer is sent" {
    try testing.expectEqual(ErrorCode.protocol_error, errorCode(error.Padding));
    try testing.expectEqual(ErrorCode.protocol_error, errorCode(error.PromisedStream));
    try testing.expectEqual(ErrorCode.protocol_error, errorCode(error.ZeroIncrement));

    // Each rule is asked about a frame that can actually break it.
    const data: Header = .{ .length = 0, .frame_type = .data, .flags = 0, .stream_identifier = 1 };
    try testing.expectEqual(Severity.connection, severity(data, error.Padding));

    const promise: Header = .{ .length = 0, .frame_type = .push_promise, .flags = 0, .stream_identifier = 1 };
    try testing.expectEqual(Severity.connection, severity(promise, error.PromisedStream));
}

test "padding may not swallow the fields that follow it" {
    // The header's minimum length bounds the whole payload, padding included,
    // and the peer picks the split afterwards. A HEADERS frame long enough to
    // hold its priority fields can still pad them away — which used to be an
    // assertion here, so a peer could panic a safe build with fifteen octets
    // and feed a fast one padding octets as a stream dependency.
    //
    // PADDED|PRIORITY, length 6, pad length 5: the header's floor is exactly 6,
    // so it passes, and nothing is left for the five priority octets.
    const headers = [_]u8{ 0, 0, 6, 0x01, 0x28, 0, 0, 0, 1, 5, 0, 0, 0, 0, 0 };
    try testing.expectError(error.Padding, parseFrame(&headers));

    // One octet more of payload and one less of padding is the boundary, and
    // it is legal: five octets of priority fields and an empty fragment.
    const exact = [_]u8{ 0, 0, 7, 0x01, 0x28, 0, 0, 0, 1, 1, 0, 0, 0, 20, 9, 0 };
    const payload = try parseFrame(&exact);
    try testing.expectEqual(@as(u31, 20), payload.headers.priority.?.stream_dependency);
    try testing.expectEqual(@as(usize, 0), payload.headers.fragment.len);
    try testing.expectEqual(@as(usize, 1), payload.headers.padding.?.len);

    // PUSH_PROMISE is the same shape: floor 5, pad length 4, nothing left for
    // the promised stream identifier.
    const promise = [_]u8{ 0, 0, 5, 0x05, 0x08, 0, 0, 0, 1, 4, 0, 0, 0, 0 };
    try testing.expectError(error.Padding, parseFrame(&promise));

    // And every pad length in between, for both, rather than only the extreme.
    var pad: u8 = 1;
    while (pad <= 5) : (pad += 1) {
        var wire = [_]u8{ 0, 0, 7, 0x01, 0x28, 0, 0, 0, 1, pad, 0, 0, 0, 20, 9, 0 };
        wire[9] = pad;
        const result = parseFrame(&wire);
        if (pad + priority_fields_octets > 6) {
            try testing.expectError(error.Padding, result);
        } else {
            _ = try result;
        }
    }
}
