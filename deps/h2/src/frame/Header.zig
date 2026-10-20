//! RFC 9113 section 4.1: the nine octets every frame begins with.
//!
//!     +-----------------------------------------------+
//!     |                 Length (24)                   |
//!     +---------------+---------------+---------------+
//!     |   Type (8)    |   Flags (8)   |
//!     +-+-------------+---------------+-------------------------------+
//!     |R|                 Stream Identifier (31)                      |
//!     +=+=============================================================+
//!
//! ## What a header can decide on its own
//!
//! More than it looks. Whether a frame's length is legal for its type, and
//! whether its stream identifier is, are both answerable from these nine octets
//! — no payload needed — and between them they are most of what RFC 9113 calls
//! a connection error. `validate` answers both.
//!
//! What it cannot answer is anything inside the payload: whether a pad length
//! fits, whether a `WINDOW_UPDATE` increment is non-zero, whether a promised
//! stream identifier is even. Those belong to the payload codec.
//!
//! ## Unknown types are a rule, not a gap
//!
//! Section 4.1 requires an unimplemented frame type to be *ignored* — skipped by
//! its declared length — rather than rejected. `Type` is therefore a
//! non-exhaustive enum, so a consumer's `switch` has to say what it does with
//! one, and `validate` imposes no length or stream rule on a type it does not
//! know. An extension frame arriving mid-connection is ordinary traffic.
//!
//! ## Flags are per-type
//!
//! The same bit means different things to different types: `0x01` is END_STREAM
//! on DATA and ACK on SETTINGS. Reading a flag therefore goes through `has`,
//! which asserts the flag is one the type defines, so asking a DATA frame
//! whether it is an ACK is a programming error rather than a wrong answer.
//! Undefined flags are ignored on receipt, as section 4.1 requires.

const std = @import("std");

const Header = @This();

const assert = @import("../assert.zig").assert;

/// Octets in the header itself.
pub const octets: u32 = 9;

/// The stream identifier's 31 bits, below RFC 9113 section 4.1's reserved bit.
/// Exported so a caller reasoning about that bit does not have to spell the
/// mask again and get it a bit wrong.
pub const stream_identifier_mask: u32 = 0x7fff_ffff;

/// The fields the wire format is built out of, named so the per-type lengths
/// below are sums of them rather than numbers that happen to be right.
///
/// Public because `payload.zig` slices by exactly these widths. Two modules
/// each holding their own idea of how long a promised stream identifier is
/// would be a frame this one admits and that one reads wrong, so there is one
/// idea and both read it.
pub const length_octets: u32 = 3;
pub const type_octets: u32 = 1;
pub const flags_octets: u32 = 1;
/// A stream identifier, and the reserved bit above it.
pub const stream_identifier_octets: u32 = 4;
/// An error code, wherever one appears in a payload (RFC 9113 section 7).
pub const error_code_octets: u32 = 4;
/// RFC 9113 section 6.3's priority fields: the exclusive bit and stream
/// dependency together, then the weight.
pub const priority_fields_octets: u32 = stream_identifier_octets + 1;
/// The pad length that leads a PADDED payload (sections 6.1, 6.2, 6.6).
pub const pad_length_octets: u32 = 1;
/// Section 6.7's opaque payload.
pub const ping_payload_octets: u32 = 8;
/// Section 6.9's window size increment.
pub const window_increment_octets: u32 = 4;

comptime {
    assert(octets == length_octets + type_octets + flags_octets + stream_identifier_octets);
    // The priority fields are the same five octets whether they arrive in a
    // PRIORITY frame or in a HEADERS frame that sets the flag, which is why
    // both read this rather than each writing 5.
    assert(priority_fields_octets == 5);
    assert(window_increment_octets == stream_identifier_octets);
}

/// The smallest `SETTINGS_MAX_FRAME_SIZE` a peer may advertise, and the value
/// in force before any SETTINGS frame is exchanged (RFC 9113 section 6.5.2).
pub const max_frame_size_min: u32 = 16_384;

/// The largest it may advertise: the length field is 24 bits.
pub const max_frame_size_max: u32 = (1 << 24) - 1;

comptime {
    assert(max_frame_size_min <= max_frame_size_max);
    // The length field is what bounds a frame, so the ceiling above is that
    // field's own range rather than a number chosen here.
    assert(max_frame_size_max == std.math.maxInt(u24));
}

/// RFC 9113 section 11.2's frame type registry.
///
/// Non-exhaustive on purpose: section 4.1 requires an unknown type to be
/// ignored rather than rejected, so a consumer must handle one and this type
/// makes that visible at every `switch`.
pub const Type = enum(u8) {
    data = 0x00,
    headers = 0x01,
    priority = 0x02,
    rst_stream = 0x03,
    settings = 0x04,
    push_promise = 0x05,
    ping = 0x06,
    goaway = 0x07,
    window_update = 0x08,
    continuation = 0x09,
    _,

    /// True when this is a type RFC 9113 defines. An unknown type is skipped
    /// by its length, not refused.
    pub fn known(frame_type: Type) bool {
        return switch (frame_type) {
            .data, .headers, .priority, .rst_stream, .settings => true,
            .push_promise, .ping, .goaway, .window_update, .continuation => true,
            _ => false,
        };
    }
};

/// RFC 9113 section 7's error codes, as a peer would receive them in GOAWAY or
/// RST_STREAM. Non-exhaustive because section 7 says unknown codes must be
/// treated as INTERNAL_ERROR rather than rejected.
pub const ErrorCode = enum(u32) {
    no_error = 0x00,
    protocol_error = 0x01,
    internal_error = 0x02,
    flow_control_error = 0x03,
    settings_timeout = 0x04,
    stream_closed = 0x05,
    frame_size_error = 0x06,
    refused_stream = 0x07,
    cancel = 0x08,
    compression_error = 0x09,
    connect_error = 0x0a,
    enhance_your_calm = 0x0b,
    inadequate_security = 0x0c,
    http_1_1_required = 0x0d,
    _,
};

/// The flags RFC 9113 defines, by the bit each occupies.
///
/// `end_stream` and `ack` share `0x01` and `padded` is `0x08` on three types
/// and undefined on the rest, which is why `has` takes the type into account
/// instead of exposing the octet.
pub const Flag = enum {
    end_stream,
    ack,
    end_headers,
    padded,
    priority,

    /// The bit this flag occupies. END_STREAM and ACK share `0x01` — which is
    /// why this is a mapping rather than the enum's own value, and why `has`
    /// takes the frame's type into account before reading it.
    pub fn bit(flag: Flag) u8 {
        return switch (flag) {
            .end_stream, .ack => 0x01,
            .end_headers => 0x04,
            .padded => 0x08,
            .priority => 0x20,
        };
    }
};

/// Flags each type defines. Everything else is ignored on receipt (section
/// 4.1), which is a rule rather than leniency: it is how extensions add flags
/// without breaking existing peers.
fn definedFlags(frame_type: Type) u8 {
    const end_stream = Flag.end_stream.bit();
    const end_headers = Flag.end_headers.bit();
    const padded = Flag.padded.bit();
    const priority = Flag.priority.bit();
    const ack = Flag.ack.bit();
    return switch (frame_type) {
        .data => end_stream | padded,
        .headers => end_stream | end_headers | padded | priority,
        .push_promise => end_headers | padded,
        .continuation => end_headers,
        .settings, .ping => ack,
        .priority, .rst_stream, .goaway, .window_update => 0,
        _ => 0,
    };
}

length: u24,
frame_type: Type,
/// The raw octet. Read it through `has` rather than by masking, so the type's
/// own meaning for a bit is applied.
flags: u8,
stream_identifier: u31,

pub const ParseError = error{
    /// Fewer than nine octets are available. The caller may have more later;
    /// whether that is malformed is its decision, not this one's.
    Incomplete,
};

/// Read a header from the first nine octets of `source`.
///
/// The reserved bit is masked off and discarded. Section 4.1 says it "MUST be
/// ignored when receiving", so ignoring it is the specified behaviour rather
/// than an omission — but it is masked here, explicitly, rather than left to a
/// `u32` that happens to be compared somewhere later.
pub fn parse(source: []const u8) ParseError!Header {
    if (source.len < octets) return error.Incomplete;
    assert(source.len >= octets);
    const raw_stream: u32 = (@as(u32, source[5]) << 24) | (@as(u32, source[6]) << 16) |
        (@as(u32, source[7]) << 8) | source[8];
    const header: Header = .{
        .length = (@as(u24, source[0]) << 16) | (@as(u24, source[1]) << 8) | source[2],
        .frame_type = @enumFromInt(source[3]),
        .flags = source[4],
        .stream_identifier = @intCast(raw_stream & stream_identifier_mask),
    };
    // The negative space, and the only thing worth asserting here: the
    // reserved bit did not reach the field. Asserting the field fits `u31`
    // would only restate its own type.
    assert(@as(u32, header.stream_identifier) == raw_stream & stream_identifier_mask);
    assert(header.stream_identifier != raw_stream or raw_stream & ~stream_identifier_mask == 0);
    return header;
}

pub const RenderError = error{
    /// `target` is shorter than a header.
    OutputTooLong,
};

/// Write this header into the first nine octets of `target`.
pub fn render(header: Header, target: []u8) RenderError!u32 {
    if (target.len < octets) return error.OutputTooLong;
    target[0] = @truncate(header.length >> 16);
    target[1] = @truncate(header.length >> 8);
    target[2] = @truncate(header.length);
    target[3] = @intFromEnum(header.frame_type);
    target[4] = header.flags;
    // The reserved bit goes out as zero, which section 4.1 requires of a
    // sender even though a receiver must not care.
    target[5] = @truncate(@as(u32, header.stream_identifier) >> 24);
    target[6] = @truncate(@as(u32, header.stream_identifier) >> 16);
    target[7] = @truncate(@as(u32, header.stream_identifier) >> 8);
    target[8] = @truncate(@as(u32, header.stream_identifier));
    assert(target[5] & 0x80 == 0);
    return octets;
}

/// True when `flag` is set.
///
/// Asserts the flag is one this frame's type defines, so asking a DATA frame
/// whether it carries END_HEADERS is caught rather than silently answered
/// about a bit DATA does not define.
///
/// The check is there in any optimize mode unless a consumer passed
/// `-Dassertions=false`; see `src/assert.zig`. It was not, for the first four
/// slices of this package: `std.debug.assert` is elided in `ReleaseFast`, and
/// this comment used to say so and leave the pairing to the caller.
///
/// Note what it cannot catch. END_STREAM and ACK are the same bit, so asking a
/// DATA frame whether it is an ACK passes — the assertion is on the bit the
/// type defines, and DATA defines that one. That is why `Flag.bit` is a mapping
/// rather than the enum's value, and why the type is consulted first.
pub fn has(header: Header, flag: Flag) bool {
    assert(definedFlags(header.frame_type) & flag.bit() != 0);
    return header.flags & flag.bit() != 0;
}

pub const ValidateError = error{
    /// RFC 9113 section 7's PROTOCOL_ERROR.
    Protocol,
    /// FRAME_SIZE_ERROR.
    FrameSize,
};

/// The error code a peer should be sent for a validation failure.
pub fn errorCode(err: ValidateError) ErrorCode {
    return switch (err) {
        error.Protocol => .protocol_error,
        error.FrameSize => .frame_size_error,
    };
}

/// Whether a failure ends the connection or only the stream.
pub const Severity = enum {
    /// RFC 9113 section 5.4.1: GOAWAY, and the connection is over.
    connection,
    /// Section 5.4.2: RST_STREAM, and the connection carries on.
    stream,
};

/// How far a validation failure reaches.
///
/// The code alone is not enough to answer a peer with, and the difference is
/// not cosmetic: a consumer that sends GOAWAY where RST_STREAM was required
/// tears down a connection over one malformed frame. Section 6.3 makes a
/// wrong-length PRIORITY frame a *stream* error, and it is the only length rule
/// in RFC 9113 that is — sections 6.4, 6.5, 6.7 and 6.9 name connection errors
/// outright, and section 4.2 adds every frame carrying a field block and every
/// frame on stream zero.
///
/// This lives here rather than in the caller because it is decidable from the
/// same nine octets everything else here is decided from, which is this
/// module's whole criterion for what it owns.
pub fn severity(header: Header, err: ValidateError) Severity {
    switch (err) {
        // A stream identifier that is wrong for its type cannot be answered
        // with a stream error: there is no stream to reset, which is why every
        // one of these is a connection error in RFC 9113.
        error.Protocol => return .connection,
        error.FrameSize => {},
    }

    // Section 4.2: anything that "could alter the state of the entire
    // connection", which begins with everything on stream zero.
    if (header.stream_identifier == 0) return .connection;
    return switch (header.frame_type) {
        // Section 6.3, the lone exception.
        .priority => .stream,
        // Named connection errors in their own sections.
        .rst_stream, .settings, .ping, .window_update => .connection,
        // Section 4.2's field-block frames.
        .headers, .push_promise, .continuation => .connection,
        // Section 4.2's general rule for everything else, including a type we
        // do not know.
        else => .stream,
    };
}

/// Check everything the nine octets can decide.
///
/// `max_frame_size` is `SETTINGS_MAX_FRAME_SIZE` as *we* advertised it, not as
/// the peer did: it bounds what we are willing to receive. It is checked first,
/// because it is the bound that makes every downstream buffer sizeable, and a
/// per-type rule that passed on a frame too large to hold would be answering
/// the wrong question. It applies to unknown types too — section 4.2 bounds
/// every frame, and a type we will skip still has to be a length we can skip.
///
/// The stream rule is last, so a header breaking both a length rule and a
/// stream rule reports FRAME_SIZE_ERROR. RFC 9113 sets no precedence and both
/// are connection errors for every such pair, so a peer cannot tell the
/// difference; the order is fixed here only so that it is one thing rather
/// than an accident of source layout.
pub fn validate(header: Header, max_frame_size: u32) ValidateError!void {
    assert(max_frame_size >= max_frame_size_min);
    assert(max_frame_size <= max_frame_size_max);
    if (header.length > max_frame_size) return error.FrameSize;

    if (fixedLength(header.frame_type)) |required| {
        if (header.length != required) return error.FrameSize;
    }
    // A variable-length payload can still have a floor: the fields RFC 9113
    // defines before the variable part have to fit. Which fields those are
    // depends on the flags, and the flags are in the header, so this is
    // decidable here rather than in the payload codec.
    if (header.length < header.minimumLength()) return error.FrameSize;
    if (header.frame_type == .settings) {
        // Section 6.5: a multiple of six, and empty when it is an
        // acknowledgement.
        if (header.length % settings_entry_octets != 0) return error.FrameSize;
        if (header.has(.ack) and header.length != 0) return error.FrameSize;
    }

    switch (streamRule(header.frame_type)) {
        .connection => if (header.stream_identifier != 0) return error.Protocol,
        .stream => if (header.stream_identifier == 0) return error.Protocol,
        .either => {},
    }

    // The postcondition every caller relies on, stated where it holds for all
    // of them rather than only in the fuzz target.
    assert(header.length <= max_frame_size);
}

/// One SETTINGS parameter: a 16-bit identifier and a 32-bit value (section
/// 6.5.1). It is what makes a SETTINGS payload's length a multiple of six.
pub const settings_entry_octets: u32 = 6;

comptime {
    assert(settings_entry_octets == 2 + 4);
    // Every floor this file imposes has to be reachable under the smallest
    // frame size a peer may advertise, or a conforming frame would be
    // unrepresentable.
    assert(goaway_minimum_octets <= max_frame_size_min);
    assert(priority_fields_octets + pad_length_octets <= max_frame_size_min);
}

/// Section 6.8: a last stream identifier and an error code, before any
/// optional debug data.
const goaway_minimum_octets: u32 = stream_identifier_octets + error_code_octets;

/// The shortest payload this frame's type and flags can legally have.
///
/// Zero for a type whose payload may be empty. Distinct from `fixedLength`,
/// which is for types whose payload is exactly one size — this is the floor
/// under a variable one, and it moves with the flags because a PADDED frame
/// carries a pad-length octet before anything else.
fn minimumLength(header: Header) u24 {
    const padding: u24 = if (header.frame_type == .data or
        header.frame_type == .headers or
        header.frame_type == .push_promise)
        (if (header.has(.padded)) @as(u24, pad_length_octets) else 0)
    else
        0;

    const minimum: u24 = switch (header.frame_type) {
        // Section 6.1: nothing but the pad length.
        .data => padding,
        // Section 6.2: the priority fields too, when the flag is set.
        .headers => padding +
            (if (header.has(.priority)) @as(u24, priority_fields_octets) else 0),
        // Section 6.6: the promised stream identifier is not optional.
        .push_promise => padding + @as(u24, stream_identifier_octets),
        // Section 6.8: debug data after these is.
        .goaway => @intCast(goaway_minimum_octets),
        // Section 6.10 puts no floor under a field block fragment, and the
        // fixed-length types are handled by `fixedLength`.
        else => 0,
    };
    assert(minimum <= max_frame_size_min);
    // A type with a fixed length has no separate floor; two rules constraining
    // one type would be two places to change it.
    if (fixedLength(header.frame_type) != null) assert(minimum == 0);
    return minimum;
}

/// Payload length RFC 9113 fixes for a type, or null when it varies.
fn fixedLength(frame_type: Type) ?u24 {
    const fixed: ?u24 = switch (frame_type) {
        .priority => @intCast(priority_fields_octets),
        .rst_stream => @intCast(error_code_octets),
        .ping => @intCast(ping_payload_octets),
        .window_update => @intCast(window_increment_octets),
        else => null,
    };
    if (fixed) |length| assert(length > 0);
    return fixed;
}

const StreamRule = enum {
    /// Must be stream zero: the frame is about the connection.
    connection,
    /// Must not be stream zero: the frame is about one stream.
    stream,
    /// Either is meaningful.
    either,
};

fn streamRule(frame_type: Type) StreamRule {
    return switch (frame_type) {
        // Sections 6.5, 6.7, 6.8: connection-level.
        .settings, .ping, .goaway => .connection,
        // Sections 6.1 to 6.4, 6.6, 6.10: about one stream.
        .data, .headers, .priority, .rst_stream, .push_promise, .continuation => .stream,
        // Section 6.9: connection-level with stream zero, stream-level
        // otherwise, and both are ordinary.
        .window_update => .either,
        // An unknown type has no rule to enforce; section 4.1 says ignore it.
        _ => .either,
    };
}

const testing = std.testing;

test "the header round trips through every field" {
    const header: Header = .{
        .length = 0x123456,
        .frame_type = .headers,
        .flags = 0x2c,
        .stream_identifier = 0x7fffffff,
    };
    var wire: [octets]u8 = undefined;
    try testing.expectEqual(octets, try header.render(&wire));

    const parsed = try parse(&wire);
    try testing.expectEqual(header.length, parsed.length);
    try testing.expectEqual(header.frame_type, parsed.frame_type);
    try testing.expectEqual(header.flags, parsed.flags);
    try testing.expectEqual(header.stream_identifier, parsed.stream_identifier);
}

test "the reserved bit is ignored on receipt and zero on send" {
    // Section 4.1. The same stream identifier with the reserved bit set must
    // parse identically.
    const clear = [_]u8{ 0, 0, 0, 0x04, 0, 0x00, 0x00, 0x00, 0x00 };
    const set = [_]u8{ 0, 0, 0, 0x04, 0, 0x80, 0x00, 0x00, 0x00 };
    try testing.expectEqual((try parse(&clear)).stream_identifier, (try parse(&set)).stream_identifier);

    const high = [_]u8{ 0, 0, 0, 0x00, 0, 0xff, 0xff, 0xff, 0xff };
    try testing.expectEqual(@as(u31, 0x7fffffff), (try parse(&high)).stream_identifier);

    var wire: [octets]u8 = undefined;
    const header: Header = .{ .length = 0, .frame_type = .data, .flags = 0, .stream_identifier = 0x7fffffff };
    _ = try header.render(&wire);
    try testing.expectEqual(@as(u8, 0x7f), wire[5]);
}

test "fewer than nine octets is Incomplete, not a guess" {
    const wire = [_]u8{ 0, 0, 0, 0x04, 0, 0, 0, 0, 0 };
    var length: u32 = 0;
    while (length < octets) : (length += 1) {
        try testing.expectError(error.Incomplete, parse(wire[0..length]));
    }
    _ = try parse(&wire);
}

test "an unknown type carries no length or stream rule" {
    // Section 4.1: ignored, which means no rule can fail on it.
    const header: Header = .{
        .length = 1234,
        .frame_type = @enumFromInt(0xfa),
        .flags = 0xff,
        .stream_identifier = 0,
    };
    try testing.expect(!header.frame_type.known());
    try header.validate(max_frame_size_min);

    const on_a_stream: Header = .{
        .length = 1234,
        .frame_type = @enumFromInt(0xfa),
        .flags = 0xff,
        .stream_identifier = 7,
    };
    try on_a_stream.validate(max_frame_size_min);
}

test "every defined type is known and every undefined one is not" {
    const defined = [_]Type{
        .data,         .headers, .priority, .rst_stream,    .settings,
        .push_promise, .ping,    .goaway,   .window_update, .continuation,
    };
    for (defined) |frame_type| try testing.expect(frame_type.known());

    var raw: u16 = 0x0a;
    while (raw <= 0xff) : (raw += 1) {
        try testing.expect(!@as(Type, @enumFromInt(@as(u8, @intCast(raw)))).known());
    }
}

test "a frame larger than what we advertised is a size error" {
    const header: Header = .{ .length = max_frame_size_min + 1, .frame_type = .data, .flags = 0, .stream_identifier = 1 };
    try testing.expectError(error.FrameSize, header.validate(max_frame_size_min));
    try header.validate(max_frame_size_min * 2);
}

test "fixed-length types accept exactly their length" {
    const cases = [_]struct { frame_type: Type, length: u24 }{
        .{ .frame_type = .priority, .length = 5 },
        .{ .frame_type = .rst_stream, .length = 4 },
        .{ .frame_type = .ping, .length = 8 },
        .{ .frame_type = .window_update, .length = 4 },
    };
    for (cases) |case| {
        const stream: u31 = if (case.frame_type == .ping) 0 else 1;
        const exact: Header = .{ .length = case.length, .frame_type = case.frame_type, .flags = 0, .stream_identifier = stream };
        try exact.validate(max_frame_size_min);

        const short: Header = .{ .length = case.length - 1, .frame_type = case.frame_type, .flags = 0, .stream_identifier = stream };
        try testing.expectError(error.FrameSize, short.validate(max_frame_size_min));

        const long: Header = .{ .length = case.length + 1, .frame_type = case.frame_type, .flags = 0, .stream_identifier = stream };
        try testing.expectError(error.FrameSize, long.validate(max_frame_size_min));
    }
}

test "SETTINGS is a multiple of six, and empty when it acknowledges" {
    const empty: Header = .{ .length = 0, .frame_type = .settings, .flags = 0, .stream_identifier = 0 };
    try empty.validate(max_frame_size_min);

    const two: Header = .{ .length = 12, .frame_type = .settings, .flags = 0, .stream_identifier = 0 };
    try two.validate(max_frame_size_min);

    const ragged: Header = .{ .length = 13, .frame_type = .settings, .flags = 0, .stream_identifier = 0 };
    try testing.expectError(error.FrameSize, ragged.validate(max_frame_size_min));

    const ack_empty: Header = .{ .length = 0, .frame_type = .settings, .flags = Flag.ack.bit(), .stream_identifier = 0 };
    try ack_empty.validate(max_frame_size_min);

    const ack_full: Header = .{ .length = 6, .frame_type = .settings, .flags = Flag.ack.bit(), .stream_identifier = 0 };
    try testing.expectError(error.FrameSize, ack_full.validate(max_frame_size_min));
}

test "stream identifiers are checked per type, both directions" {
    const connection_level = [_]Type{ .settings, .ping, .goaway };
    for (connection_level) |frame_type| {
        // Each type's own shortest legal payload, so the stream rule is what
        // this test is measuring rather than the length rule.
        const length: u24 = switch (frame_type) {
            .ping => 8,
            .goaway => 8,
            else => 0,
        };
        const ok: Header = .{ .length = length, .frame_type = frame_type, .flags = 0, .stream_identifier = 0 };
        try ok.validate(max_frame_size_min);
        const bad: Header = .{ .length = length, .frame_type = frame_type, .flags = 0, .stream_identifier = 1 };
        try testing.expectError(error.Protocol, bad.validate(max_frame_size_min));
    }

    const stream_level = [_]Type{ .data, .headers, .priority, .rst_stream, .push_promise, .continuation };
    for (stream_level) |frame_type| {
        const length: u24 = switch (frame_type) {
            .priority => 5,
            .rst_stream => 4,
            .push_promise => 4,
            else => 0,
        };
        const ok: Header = .{ .length = length, .frame_type = frame_type, .flags = 0, .stream_identifier = 1 };
        try ok.validate(max_frame_size_min);
        const bad: Header = .{ .length = length, .frame_type = frame_type, .flags = 0, .stream_identifier = 0 };
        try testing.expectError(error.Protocol, bad.validate(max_frame_size_min));
    }

    // WINDOW_UPDATE is meaningful either way (section 6.9).
    const connection: Header = .{ .length = 4, .frame_type = .window_update, .flags = 0, .stream_identifier = 0 };
    try connection.validate(max_frame_size_min);
    const stream: Header = .{ .length = 4, .frame_type = .window_update, .flags = 0, .stream_identifier = 1 };
    try stream.validate(max_frame_size_min);
}

test "a variable-length payload still has a floor, and the flags move it" {
    // GOAWAY carries a last stream identifier and an error code before its
    // optional debug data (section 6.8), so four octets cannot be one — which
    // is what error/goaway-frame-size in the corpus is.
    const short_goaway: Header = .{ .length = 4, .frame_type = .goaway, .flags = 0, .stream_identifier = 0 };
    try testing.expectError(error.FrameSize, short_goaway.validate(max_frame_size_min));
    const exact_goaway: Header = .{ .length = 8, .frame_type = .goaway, .flags = 0, .stream_identifier = 0 };
    try exact_goaway.validate(max_frame_size_min);

    // An unpadded DATA frame may be empty; a padded one needs its pad length.
    const empty_data: Header = .{ .length = 0, .frame_type = .data, .flags = 0, .stream_identifier = 1 };
    try empty_data.validate(max_frame_size_min);
    const padded_data: Header = .{ .length = 0, .frame_type = .data, .flags = Flag.padded.bit(), .stream_identifier = 1 };
    try testing.expectError(error.FrameSize, padded_data.validate(max_frame_size_min));

    // HEADERS gains five octets with PRIORITY and one more with PADDED.
    const bare: Header = .{ .length = 0, .frame_type = .headers, .flags = 0, .stream_identifier = 1 };
    try bare.validate(max_frame_size_min);
    const with_priority: Header = .{ .length = 4, .frame_type = .headers, .flags = Flag.priority.bit(), .stream_identifier = 1 };
    try testing.expectError(error.FrameSize, with_priority.validate(max_frame_size_min));
    const priority_exact: Header = .{ .length = 5, .frame_type = .headers, .flags = Flag.priority.bit(), .stream_identifier = 1 };
    try priority_exact.validate(max_frame_size_min);
    const both: Header = .{
        .length = 5,
        .frame_type = .headers,
        .flags = Flag.priority.bit() | Flag.padded.bit(),
        .stream_identifier = 1,
    };
    try testing.expectError(error.FrameSize, both.validate(max_frame_size_min));

    // PUSH_PROMISE always carries a promised stream identifier.
    const no_promise: Header = .{ .length = 3, .frame_type = .push_promise, .flags = 0, .stream_identifier = 1 };
    try testing.expectError(error.FrameSize, no_promise.validate(max_frame_size_min));
    const promise: Header = .{ .length = 4, .frame_type = .push_promise, .flags = 0, .stream_identifier = 1 };
    try promise.validate(max_frame_size_min);
    // And a pad length octet before it when PADDED, which is
    // error/push_promise-frame-padding in the corpus.
    const padded_promise: Header = .{ .length = 4, .frame_type = .push_promise, .flags = Flag.padded.bit(), .stream_identifier = 1 };
    try testing.expectError(error.FrameSize, padded_promise.validate(max_frame_size_min));
}

test "the size bound is checked before the per-type rules" {
    // A PING of the wrong length that is also too large reports the bound that
    // makes buffers sizeable, not the one that happens to be checked first in
    // source order.
    const header: Header = .{ .length = max_frame_size_min + 1, .frame_type = .ping, .flags = 0, .stream_identifier = 0 };
    try testing.expectError(error.FrameSize, header.validate(max_frame_size_min));
}

test "flags are read through the type that defines them" {
    const settings: Header = .{ .length = 0, .frame_type = .settings, .flags = 0x01, .stream_identifier = 0 };
    try testing.expect(settings.has(.ack));

    const data: Header = .{ .length = 0, .frame_type = .data, .flags = 0x01, .stream_identifier = 1 };
    try testing.expect(data.has(.end_stream));

    // Undefined flags are ignored on receipt, so a DATA frame with every bit
    // set is still just END_STREAM and PADDED.
    const noisy: Header = .{ .length = 0, .frame_type = .data, .flags = 0xff, .stream_identifier = 1 };
    try testing.expect(noisy.has(.end_stream));
    try testing.expect(noisy.has(.padded));
}

test "error codes map to what a peer is sent" {
    try testing.expectEqual(ErrorCode.protocol_error, errorCode(error.Protocol));
    try testing.expectEqual(ErrorCode.frame_size_error, errorCode(error.FrameSize));
    try testing.expectEqual(@as(u32, 0x01), @intFromEnum(ErrorCode.protocol_error));
    try testing.expectEqual(@as(u32, 0x06), @intFromEnum(ErrorCode.frame_size_error));
}

test "a wrong-length PRIORITY frame is the one stream error, and the rest are not" {
    // RFC 9113 section 6.3 says stream error in as many words; sections 6.4,
    // 6.5, 6.7 and 6.9 all say connection error. Getting this backwards means a
    // consumer tears down a connection over one malformed frame, or fails to
    // tear one down when it must.
    const priority: Header = .{ .length = 6, .frame_type = .priority, .flags = 0, .stream_identifier = 3 };
    try testing.expectError(error.FrameSize, priority.validate(max_frame_size_min));
    try testing.expectEqual(Severity.stream, priority.severity(error.FrameSize));

    const named_connection = [_]Type{ .rst_stream, .settings, .ping, .window_update };
    for (named_connection) |frame_type| {
        const header: Header = .{ .length = 3, .frame_type = frame_type, .flags = 0, .stream_identifier = 1 };
        try testing.expectEqual(Severity.connection, header.severity(error.FrameSize));
    }

    // Section 4.2: anything carrying a field block.
    const field_blocks = [_]Type{ .headers, .push_promise, .continuation };
    for (field_blocks) |frame_type| {
        const header: Header = .{ .length = 1, .frame_type = frame_type, .flags = 0, .stream_identifier = 1 };
        try testing.expectEqual(Severity.connection, header.severity(error.FrameSize));
    }

    // And a DATA frame on a stream is section 4.2's general case.
    const data: Header = .{ .length = 1, .frame_type = .data, .flags = 0, .stream_identifier = 1 };
    try testing.expectEqual(Severity.stream, data.severity(error.FrameSize));
}

test "anything on stream zero, and every stream-rule failure, ends the connection" {
    // A stream error needs a stream to reset, so a bad stream identifier can
    // only ever be a connection error.
    const on_zero: Header = .{ .length = 6, .frame_type = .priority, .flags = 0, .stream_identifier = 0 };
    try testing.expectEqual(Severity.connection, on_zero.severity(error.FrameSize));
    try testing.expectEqual(Severity.connection, on_zero.severity(error.Protocol));

    const data_on_zero: Header = .{ .length = 1, .frame_type = .data, .flags = 0, .stream_identifier = 0 };
    try testing.expectEqual(Severity.connection, data_on_zero.severity(error.Protocol));

    // An unknown type is section 4.2's general rule, both ways.
    const unknown_stream: Header = .{ .length = 1, .frame_type = @enumFromInt(0xfa), .flags = 0, .stream_identifier = 1 };
    try testing.expectEqual(Severity.stream, unknown_stream.severity(error.FrameSize));
    const unknown_zero: Header = .{ .length = 1, .frame_type = @enumFromInt(0xfa), .flags = 0, .stream_identifier = 0 };
    try testing.expectEqual(Severity.connection, unknown_zero.severity(error.FrameSize));
}
