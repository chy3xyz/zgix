//! One header field: a name and a value, both borrowed.
//!
//! This is the type the decoder emits and the encoder consumes, and it is
//! deliberately the smallest thing that can be one: two slices and a bit. The
//! package's whole reason to exist is that its two consumers do not share a
//! runtime, so it cannot name either one's header type — but a consumer can
//! build its own from this by construction rather than by copying, which is
//! what keeps a proxy's phase model intact across the boundary.
//!
//! ## Where the bytes live
//!
//! The slices borrow, and what they borrow from decides how long they are good
//! for. The decoder points them at either the comptime static table (good
//! forever) or the caller's own output buffer (good until the caller reuses
//! it). They are never pointed into the dynamic table: a later field in the
//! same header block can evict the entry a slice came from and overwrite its
//! bytes, so an indexed reference is copied out instead. That is a lifetime
//! rule, not an optimization, and `Decoder` states it again where it is
//! enforced.

const std = @import("std");

const Field = @This();

const assert = @import("../assert.zig").assert;

name: []const u8,
value: []const u8,
/// The field was received as, or must be sent as, a never-indexed literal
/// (RFC 7541 section 6.2.3).
///
/// This survives a decode/encode round trip on purpose. The representation
/// exists so an intermediary cannot quietly downgrade a field its sender
/// judged too sensitive to enter any compression context, and an intermediary
/// that forgets the bit is exactly the failure it guards against.
never_indexed: bool = false,

/// The field's size for the table and header-list accounting of RFC 7541
/// sections 4.1 and 6.5.2: its two lengths plus 32 octets of assumed overhead.
///
/// Returns `u64` because it is summed over a whole header block, and a bound
/// that can overflow before it is compared is not a bound.
pub fn size(field: *const Field) u64 {
    assert(field.name.len <= std.math.maxInt(u32));
    assert(field.value.len <= std.math.maxInt(u32));
    return @as(u64, field.name.len) + @as(u64, field.value.len) + overhead;
}

/// RFC 7541 section 4.1's per-entry allowance, "an estimate for the overhead
/// associated with an entry". It is a constant of the format rather than of
/// any implementation, which is what lets both peers agree on a table's size
/// without agreeing on how either stores it.
///
/// It is also what makes a field count bound derivable instead of configured:
/// no entry can cost less than this, so a byte budget divided by it is the
/// most entries that budget can hold. See `Decoder.fieldsMax`.
pub const overhead: u64 = 32;

pub fn eql(field: *const Field, other: *const Field) bool {
    if (!std.mem.eql(u8, field.name, other.name)) return false;
    return std.mem.eql(u8, field.value, other.value);
}

test "size counts both lengths plus the fixed overhead" {
    const field: Field = .{ .name = "content-type", .value = "text/plain" };
    try std.testing.expectEqual(@as(u64, 12 + 10 + 32), field.size());
}

test "an empty field still costs the overhead" {
    const field: Field = .{ .name = "", .value = "" };
    try std.testing.expectEqual(overhead, field.size());
}
