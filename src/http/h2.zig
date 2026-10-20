//! HTTP/2 codec seam (§4/§7): the vendored zhttp primitives behind one
//! import, so the rest of zgix states "HTTP/2" once and never names the
//! vendor.
//!
//! Only the pure codec is here — frame framing, HPACK/Huffman, settings,
//! flow control, the stream registry. zhttp's server and client loops are
//! built around `std.Io` readers and a per-request arena; zgix's serving
//! path is sans-I/O over a fixed pool, so the driver is ours to write.
//! The codec is the part worth reusing: RFC-level framing is where the
//! subtle bugs live, and none of it needs an event loop.

const std = @import("std");

const vendor = @import("zhttp-h2");

pub const frame = vendor.frame;
pub const hpack = vendor.hpack;
pub const huffman = vendor.huffman;
pub const Settings = vendor.Settings;
pub const Stream = vendor.Stream;
pub const StreamRegistry = vendor.StreamRegistry;
pub const FlowControl = vendor.FlowControl;
pub const ErrorCode = vendor.ErrorCode;

/// The client connection preface, re-exported so a future listener can
/// compare it without importing the vendor module directly.
pub const connection_preface = vendor.connection_preface;

comptime {
    // zgix speak HTTP/1.1 externally today; this pin is the reminder that
    // the moment a listener offers "h2" in ALPN, the frame cap and the
    // preface are protocol constants, not tunables.
    std.debug.assert(connection_preface.len == 24);
    std.debug.assert(frame.header_size == 9);
}

test "h2 codec: frame headers round-trip" {
    const header: frame.FrameHeader = .{
        .length = 1234,
        .frame_type = .data,
        .flags = .{ .value = 0x1 },
        .stream_id = 7,
    };
    const wire = header.encode();
    const parsed = frame.FrameHeader.parse(&wire);
    try std.testing.expectEqual(header.length, parsed.length);
    try std.testing.expectEqual(header.frame_type, parsed.frame_type);
    try std.testing.expectEqual(header.flags.value, parsed.flags.value);
    try std.testing.expectEqual(header.stream_id, parsed.stream_id);
}

test "h2 codec: HPACK round-trips a header block" {
    var encoder_buffer: [4096]u8 = undefined;
    var encoder_entries: [16]hpack.DynamicTable.Entry = undefined;
    var encoder = hpack.Encoder.init(&encoder_buffer, &encoder_entries);

    var block: [1024]u8 = undefined;
    var used: usize = 0;
    used += try encoder.encodeHeader(block[used..], ":status", "200");
    used += try encoder.encodeHeader(block[used..], "content-type", "text/plain");
    used += try encoder.encodeHeader(block[used..], "x-trace", "abc123");

    var decoder_buffer: [4096]u8 = undefined;
    var decoder_entries: [16]hpack.DynamicTable.Entry = undefined;
    var decoder = hpack.Decoder.init(&decoder_buffer, &decoder_entries);
    var fields: [8]hpack.HeaderField = undefined;
    const count = try decoder.decode(block[0..used], &fields);

    try std.testing.expectEqual(@as(usize, 3), count);
    try std.testing.expectEqualStrings(":status", fields[0].name);
    try std.testing.expectEqualStrings("200", fields[0].value);
    try std.testing.expectEqualStrings("content-type", fields[1].name);
    try std.testing.expectEqualStrings("text/plain", fields[1].value);
    try std.testing.expectEqualStrings("x-trace", fields[2].name);
    try std.testing.expectEqualStrings("abc123", fields[2].value);
}
