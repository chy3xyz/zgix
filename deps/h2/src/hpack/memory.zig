//! Span arithmetic shared by the pieces of this package that copy between
//! caller-owned buffers.

const std = @import("std");

/// True when two spans share any octet.
///
/// Containment is not the question and testing only the start pointer gets it
/// wrong: a slice beginning before a buffer and reaching into it overlaps just
/// as badly as one beginning inside. Both `@memcpy` sites in this package —
/// the dynamic table taking a field in, and the decoder copying an entry out —
/// are undefined on overlap, and each asserts against it with this.
pub fn overlaps(left: []const u8, right: []const u8) bool {
    if (left.len == 0 or right.len == 0) return false;
    const left_begin = @intFromPtr(left.ptr);
    const right_begin = @intFromPtr(right.ptr);
    return left_begin < right_begin + right.len and right_begin < left_begin + left.len;
}

test "overlap is symmetric and catches a span reaching in from before" {
    var block: [16]u8 = undefined;
    const whole = block[0..];
    const head = block[0..8];
    const tail = block[8..];

    try std.testing.expect(overlaps(whole, head));
    try std.testing.expect(overlaps(head, whole));
    try std.testing.expect(!overlaps(head, tail));
    try std.testing.expect(!overlaps(tail, head));

    // The case a start-pointer test misses: `head` begins before `middle` and
    // runs into it.
    const middle = block[4..12];
    try std.testing.expect(overlaps(head, middle));
    try std.testing.expect(overlaps(middle, head));

    // A zero-length span borrows nothing, wherever it points.
    try std.testing.expect(!overlaps(block[4..4], whole));
    try std.testing.expect(!overlaps(whole, block[4..4]));
}
