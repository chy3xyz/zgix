//! An `Io.Reader` that serves a canned byte stream in caller-chosen segments.
//!
//! This is the harness behind design rule 4. `stream` never crosses the next
//! boundary, so the same bytes can be handed to the parser under every
//! possible transport segmentation and the results compared. The chunked body
//! that was read as plain text for months (benchmark `19e34a3`) was exactly a
//! segmentation-dependent parse; nothing else finds that class of bug.
//!
//! Test and fuzz infrastructure. It is deliberately not exported from
//! `root.zig`: consumers inject their own transports (rule 5), and a canned
//! one is only useful to code that is testing zurl itself.

const std = @import("std");
const Io = std.Io;
const assert = std.debug.assert;

const SegmentedReader = @This();

data: []const u8,
pos: usize = 0,
/// Serve at most this many bytes per `stream` call.
segment_bytes_max: usize,
/// Additionally never cross this absolute offset — a single "packet
/// boundary". `null` is no boundary at all.
///
/// A real two-segment split is `1 <= boundary <= data.len - 1`: offset 0 has
/// nothing before it and offset `data.len` nothing after, so either one is
/// the whole-input read wearing a different name. This is optional rather
/// than a zero sentinel because those two readings of `0` are not
/// distinguishable by eye — a fuzz harness once spent 95% of its budget
/// running "split at 0" as an accidental synonym for "do not split", and
/// reported a pass throughout. Callers assert the range; `stream` below
/// cannot, because it only ever sees one segment at a time.
boundary: ?usize = null,
interface: Io.Reader,

pub fn init(
    data: []const u8,
    segment_bytes_max: usize,
    boundary: ?usize,
    buffer: []u8,
) SegmentedReader {
    // A zero segment size would serve nothing and turn every parse into a
    // spurious EndOfStream; `buffer` bounds the longest line the parser can
    // see, so a zero there fails every head for the wrong reason.
    assert(segment_bytes_max > 0);
    assert(buffer.len > 0);
    // Asserted here rather than left to callers: this is the only place that
    // holds both the data and the offset, and a boundary outside the range is
    // the "split at 0" no-op the field's doc warns about.
    if (boundary) |b| {
        assert(b >= 1);
        assert(b < data.len);
    }

    return .{
        .data = data,
        .segment_bytes_max = segment_bytes_max,
        .boundary = boundary,
        .interface = .{
            .vtable = &.{ .stream = stream },
            .buffer = buffer,
            .seek = 0,
            .end = 0,
        },
    };
}

/// The logical stream offset the reader of this has consumed: bytes served,
/// less whatever is still sitting unread in the reader's buffer.
///
/// Two segmentations that agree on the body but disagree here have framed the
/// connection differently — the ziglang/zig#25181 shape, where a bodyless
/// reply's non-existent body is eaten out of the next response. The body
/// bytes look identical right up until the next request on that connection.
pub fn consumed(s: *const SegmentedReader) usize {
    assert(s.interface.end >= s.interface.seek);
    const buffered = s.interface.end - s.interface.seek;
    assert(s.pos >= buffered);

    return s.pos - buffered;
}

fn stream(r: *Io.Reader, w: *Io.Writer, limit: Io.Limit) Io.Reader.StreamError!usize {
    const s: *SegmentedReader = @alignCast(@fieldParentPtr("interface", r));
    assert(s.pos <= s.data.len);

    if (s.pos >= s.data.len) return error.EndOfStream;
    var n = limit.minInt(@min(s.segment_bytes_max, s.data.len - s.pos));
    if (s.boundary) |boundary| {
        if (boundary > s.pos and boundary < s.pos + n) n = boundary - s.pos;
    }
    if (n == 0) return error.EndOfStream;

    try w.writeAll(s.data[s.pos..][0..n]);
    s.pos += n;
    assert(s.pos <= s.data.len);
    return n;
}
