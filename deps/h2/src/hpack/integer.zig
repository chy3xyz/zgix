//! RFC 7541 section 5.1: integers with an N-bit prefix.
//!
//! A value below the prefix's maximum is that prefix; anything larger sets
//! every prefix bit and continues in 7-bit groups, low group first, with the
//! high bit marking continuation.
//!
//! ## Why this primitive owns a bound
//!
//! Section 5.1 sets no limit on how many continuation octets an encoder may
//! send, and says so explicitly: an implementation "MUST" guard against
//! integers that exceed what it can represent. An unbounded run of octets with
//! the high bit set is therefore legal-looking input that a trusting decoder
//! will follow forever, and every HPACK integer — index, length, table size —
//! flows through here. The bound belongs at the primitive rather than at each
//! of a dozen call sites, because a call site that forgets it is silent.

const std = @import("std");

const assert = @import("../assert.zig").assert;

/// The most continuation octets a value may use.
///
/// Five 7-bit groups carry 35 bits, which covers every `u32` a prefix can
/// reach. A sixth cannot describe a representable value, so accepting one only
/// buys an attacker a longer walk. The decode still range-checks the result:
/// five octets can *encode* more than `u32` holds, and this bound is about
/// terminating rather than about fitting.
///
/// It is worth being explicit that this is stricter than RFC 7541 section 5.1,
/// which sets no limit: a peer may pad an integer with zero-valued groups
/// indefinitely and still be conformant, and such an encoding is rejected here
/// as `TooLarge`. That is the right direction for a decoder facing the open
/// internet, and it is a deliberate deviation rather than an oversight.
pub const continuation_octets_max: u32 = 5;

/// The widest prefix section 5.1 defines. A prefix is the low bits of an octet
/// whose high bits carry a representation's type tag, and the one
/// representation with no tag bits — a dynamic table size update's successor,
/// and string lengths — uses seven.
pub const prefix_bits_max: u4 = 8;

comptime {
    // The shift in `decode` is a `u6`, and it reaches 7 per continuation octet.
    assert(continuation_octets_max * 7 <= std.math.maxInt(u6));
    // And five groups have to cover every `u32`, which is the claim the doc
    // above makes about why five is enough.
    assert(continuation_octets_max * 7 >= 32);
    assert(prefix_bits_max >= 1);
}

pub const DecodeError = error{
    /// The encoding continues past the end of the input. The caller may have
    /// more bytes; within a header block, which arrives whole, it does not,
    /// and this is malformed.
    Incomplete,
    /// More continuation octets than `continuation_octets_max`, or a value too
    /// large for `u32`.
    TooLarge,
};

pub const Decoded = struct {
    value: u32,
    /// Octets consumed, including the prefix octet. Always at least one.
    octets: u32,
};

/// Decode the integer beginning at `source[0]`, whose prefix occupies the low
/// `prefix_bits` bits of that octet. Bits above the prefix are the caller's
/// type tag and are ignored here.
pub fn decode(source: []const u8, prefix_bits: u4) DecodeError!Decoded {
    assert(prefix_bits >= 1);
    assert(prefix_bits <= prefix_bits_max);
    if (source.len == 0) return error.Incomplete;

    const prefix_max: u32 = (@as(u32, 1) << prefix_bits) - 1;
    const prefix: u32 = source[0] & prefix_max;
    if (prefix < prefix_max) {
        return .{ .value = prefix, .octets = 1 };
    }

    // Accumulate in u64 so the overflow check below is a comparison rather
    // than a wrap that has already lost the evidence.
    var value: u64 = prefix_max;
    var shift: u6 = 0;
    var continuation_octets: u32 = 0;
    while (continuation_octets < continuation_octets_max) {
        const index = continuation_octets + 1;
        if (index >= source.len) return error.Incomplete;
        const octet = source[index];
        continuation_octets += 1;

        value += @as(u64, octet & 0x7f) << shift;
        if (octet & 0x80 == 0) {
            if (value > std.math.maxInt(u32)) return error.TooLarge;
            const decoded: Decoded = .{
                .value = @intCast(value),
                .octets = continuation_octets + 1,
            };
            assert(decoded.octets <= continuation_octets_max + 1);
            return decoded;
        }
        shift += 7;
    }
    assert(continuation_octets == continuation_octets_max);
    return error.TooLarge;
}

pub const EncodeError = error{
    /// `target` cannot hold the encoding.
    OutputTooLong,
};

/// Write `value` into `target` with an `prefix_bits`-bit prefix, keeping the
/// tag bits `target[0]` already holds above that prefix.
///
/// The caller sets the tag first — `target[0] = 0x80` for an indexed field, and
/// so on — because the tag is what decides `prefix_bits`, and splitting them
/// across two arguments invites a pair that disagrees.
pub fn encode(target: []u8, value: u32, prefix_bits: u4, tag: u8) EncodeError!u32 {
    assert(prefix_bits >= 1);
    assert(prefix_bits <= prefix_bits_max);
    // The tag must not reach into the prefix, or it would be read back as part
    // of the value. An eight-bit prefix leaves no room for a tag at all, so
    // there is nothing to check there.
    if (prefix_bits < prefix_bits_max) {
        assert((tag & ((@as(u16, 1) << prefix_bits) - 1)) == 0);
    }

    // Checked once, up front, so this function either writes the whole encoding
    // or touches nothing. `huffman.encode` has the same contract, and a caller
    // writing a length followed by a Huffman string composes exactly the two —
    // one of them leaving a half-written prefix behind on failure would be a
    // trap set for whoever writes that caller.
    const length = encodedLength(value, prefix_bits);
    if (length > target.len) return error.OutputTooLong;

    const prefix_max: u32 = (@as(u32, 1) << prefix_bits) - 1;
    if (value < prefix_max) {
        target[0] = tag | @as(u8, @intCast(value));
        assert(length == 1);
        return 1;
    }

    target[0] = tag | @as(u8, @intCast(prefix_max));
    var remaining: u32 = value - prefix_max;
    var index: u32 = 1;
    while (remaining >= 0x80) {
        assert(index < length);
        target[index] = @as(u8, @truncate(remaining)) | 0x80;
        index += 1;
        remaining >>= 7;
    }
    assert(index < length);
    target[index] = @intCast(remaining);
    assert(index + 1 == length);
    return length;
}

/// Octets `encode` would write. Lets a caller check space once for a whole
/// representation instead of unwinding a partial write.
pub fn encodedLength(value: u32, prefix_bits: u4) u32 {
    assert(prefix_bits >= 1);
    assert(prefix_bits <= prefix_bits_max);
    const prefix_max: u32 = (@as(u32, 1) << prefix_bits) - 1;
    if (value < prefix_max) return 1;

    var remaining: u32 = value - prefix_max;
    var octets: u32 = 1;
    while (remaining >= 0x80) {
        octets += 1;
        remaining >>= 7;
        assert(octets <= continuation_octets_max);
    }
    assert(octets <= continuation_octets_max);
    return octets + 1;
}

// RFC 7541 Appendix C.1 gives three worked examples; each is both directions.

test "C.1.1: 10 in a 5-bit prefix" {
    const decoded = try decode(&.{0b0000_1010}, 5);
    try std.testing.expectEqual(@as(u32, 10), decoded.value);
    try std.testing.expectEqual(@as(u32, 1), decoded.octets);

    var target: [8]u8 = undefined;
    target[0] = 0;
    try std.testing.expectEqual(@as(u32, 1), try encode(&target, 10, 5, 0));
    try std.testing.expectEqual(@as(u8, 0b0000_1010), target[0]);
}

test "C.1.2: 1337 in a 5-bit prefix" {
    const decoded = try decode(&.{ 0b0001_1111, 0b1001_1010, 0b0000_1010 }, 5);
    try std.testing.expectEqual(@as(u32, 1337), decoded.value);
    try std.testing.expectEqual(@as(u32, 3), decoded.octets);

    var target: [8]u8 = undefined;
    try std.testing.expectEqual(@as(u32, 3), try encode(&target, 1337, 5, 0));
    try std.testing.expectEqualSlices(u8, &.{ 0b0001_1111, 0b1001_1010, 0b0000_1010 }, target[0..3]);
}

test "C.1.3: 42 starting at an octet boundary" {
    const decoded = try decode(&.{0b0010_1010}, 8);
    try std.testing.expectEqual(@as(u32, 42), decoded.value);
    try std.testing.expectEqual(@as(u32, 1), decoded.octets);

    var target: [8]u8 = undefined;
    try std.testing.expectEqual(@as(u32, 1), try encode(&target, 42, 8, 0));
    try std.testing.expectEqual(@as(u8, 42), target[0]);
}

test "tag bits above the prefix are ignored on decode and kept on encode" {
    // 0b1010_1010 with a 5-bit prefix is the value 10 behind a 0b101 tag.
    const decoded = try decode(&.{0b1010_1010}, 5);
    try std.testing.expectEqual(@as(u32, 10), decoded.value);

    var target: [4]u8 = undefined;
    _ = try encode(&target, 10, 5, 0b1010_0000);
    try std.testing.expectEqual(@as(u8, 0b1010_1010), target[0]);
}

test "a value at the prefix maximum still needs a continuation octet" {
    // 31 in a 5-bit prefix cannot be the prefix itself: all-ones means "more".
    var target: [4]u8 = undefined;
    try std.testing.expectEqual(@as(u32, 2), try encode(&target, 31, 5, 0));
    try std.testing.expectEqualSlices(u8, &.{ 0b0001_1111, 0 }, target[0..2]);

    const decoded = try decode(target[0..2], 5);
    try std.testing.expectEqual(@as(u32, 31), decoded.value);
    try std.testing.expectEqual(@as(u32, 2), decoded.octets);
}

test "round trip across every prefix width and a spread of values" {
    const values = [_]u32{
        0,                    1,                        2,                    30,  31,   32,    126,   127,
        128,                  254,                      255,                  256, 1337, 16383, 16384, std.math.maxInt(u16),
        std.math.maxInt(u24), std.math.maxInt(u32) - 1, std.math.maxInt(u32),
    };
    var target: [16]u8 = undefined;
    for (1..prefix_bits_max + 1) |bits_usize| {
        const bits: u4 = @intCast(bits_usize);
        for (values) |value| {
            const written = try encode(&target, value, bits, 0);
            try std.testing.expectEqual(encodedLength(value, bits), written);
            const decoded = try decode(target[0..written], bits);
            try std.testing.expectEqual(value, decoded.value);
            try std.testing.expectEqual(written, decoded.octets);
        }
    }
}

test "truncated encodings report Incomplete, never a short value" {
    // 1337 needs three octets; every strict prefix of it is incomplete.
    const full = [_]u8{ 0b0001_1111, 0b1001_1010, 0b0000_1010 };
    try std.testing.expectError(error.Incomplete, decode(full[0..0], 5));
    try std.testing.expectError(error.Incomplete, decode(full[0..1], 5));
    try std.testing.expectError(error.Incomplete, decode(full[0..2], 5));
}

test "an unbounded continuation run terminates as TooLarge" {
    // The shape a decoder without this bound follows forever.
    const bomb = @as([64]u8, @splat(0xff));
    try std.testing.expectError(error.TooLarge, decode(&bomb, 5));
    try std.testing.expectError(error.TooLarge, decode(&bomb, 7));
    try std.testing.expectError(error.TooLarge, decode(&bomb, 8));
}

test "a value past u32 is rejected rather than wrapped" {
    // Prefix 255 plus 2^35-ish: representable in five octets, not in u32.
    const source = [_]u8{ 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f };
    try std.testing.expectError(error.TooLarge, decode(&source, 8));
}

test "encode reports OutputTooLong instead of writing past the target" {
    var target: [1]u8 = undefined;
    try std.testing.expectError(error.OutputTooLong, encode(&target, 1337, 5, 0));
    var empty: [0]u8 = undefined;
    try std.testing.expectError(error.OutputTooLong, encode(&empty, 0, 5, 0));
}
