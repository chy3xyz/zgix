const ConnectionIO = @This();
const std = @import("std");
const mem = std.mem;
const Io = std.Io;

const frame = @import("frame.zig");
const FrameType = frame.FrameType;
const FrameHeader = frame.FrameHeader;
const Flags = frame.Flags;
const ErrorCode = @import("errors.zig").ErrorCode;

/// Assembled header block ready for HPACK decoding.
pub const HeaderBlock = struct {
    stream_id: u31,
    data: []const u8,
    end_stream: bool,
};

/// Incoming frame after demultiplexing. Either a complete header block
/// (assembled from HEADERS + CONTINUATION) or a non-header frame.
pub const IncomingFrame = union(enum) {
    header_block: HeaderBlock,
    data: struct { stream_id: u31, payload: []const u8, end_stream: bool },
    settings: struct { payload: []const u8, ack: bool },
    window_update: struct { stream_id: u31, payload: []const u8 },
    ping: struct { payload: []const u8, ack: bool },
    rst_stream: struct { stream_id: u31, payload: []const u8 },
    goaway: []const u8,
    priority: u31,
    push_promise: struct { stream_id: u31, payload: []const u8 },
    unknown: void,
};

/// Demultiplexes incoming HTTP/2 frames and assembles CONTINUATION
/// sequences into complete header blocks (RFC 9113 §4.3).
///
/// CONTINUATION rules enforced:
/// - After HEADERS/PUSH_PROMISE without END_HEADERS, only CONTINUATION
///   on the same stream is accepted
/// - Any other frame type during assembly is a connection error
/// - Assembled header block is delivered as a single HeaderBlock
pub const FrameReader = struct {
    /// Buffer for assembling header blocks across CONTINUATION frames.
    header_buf: [16384]u8 = undefined,
    header_len: usize = 0,
    /// Stream ID of the header block being assembled, 0 if idle.
    header_stream_id: u31 = 0,
    /// Whether END_STREAM was set on the initial HEADERS frame.
    header_end_stream: bool = false,

    /// Maximum frame payload size to accept.
    max_frame_size: u24 = frame.default_max_frame_size,

    /// Read the next logical frame from the reader, assembling CONTINUATION
    /// sequences into complete header blocks.
    ///
    /// Returns `error.EndOfStream` when the connection is closed.
    /// Returns `error.ProtocolError` on framing violations.
    pub fn readFrame(self: *FrameReader, reader: *Io.Reader) !IncomingFrame {
        while (true) {
            const hdr_buf = reader.take(frame.header_size) catch |err| switch (err) {
                error.EndOfStream => return error.EndOfStream,
                else => return error.ReadFailed,
            };
            const header = FrameHeader.parse(hdr_buf[0..frame.header_size]);

            if (header.length > self.max_frame_size) {
                return error.FrameSizeError;
            }

            var payload: []const u8 = &.{};
            if (header.length > 0) {
                payload = reader.take(header.length) catch |err| switch (err) {
                    error.EndOfStream => return error.EndOfStream,
                    else => return error.ReadFailed,
                };
            }

            // If we're assembling a header block, only CONTINUATION on
            // the same stream is allowed (RFC 9113 §4.3)
            if (self.header_len > 0) {
                if (header.frame_type != .continuation or header.stream_id != self.header_stream_id) {
                    return error.ProtocolError;
                }

                // Append fragment
                if (self.header_len + payload.len > self.header_buf.len) {
                    return error.InternalError;
                }
                @memcpy(self.header_buf[self.header_len..][0..payload.len], payload);
                self.header_len += payload.len;

                if (header.flags.has(Flags.end_headers)) {
                    // Header block complete
                    const result = IncomingFrame{ .header_block = .{
                        .stream_id = self.header_stream_id,
                        .data = self.header_buf[0..self.header_len],
                        .end_stream = self.header_end_stream,
                    } };
                    self.header_len = 0;
                    self.header_stream_id = 0;
                    return result;
                }
                // Need more CONTINUATION frames
                continue;
            }

            // Normal frame dispatch
            switch (header.frame_type) {
                .headers => {
                    if (header.stream_id == 0) return error.ProtocolError;

                    // Strip padding and priority fields to get the header block fragment
                    var frag = payload;
                    var pad_len: usize = 0;
                    if (header.flags.has(Flags.padded)) {
                        if (frag.len < 1) return error.ProtocolError;
                        pad_len = frag[0];
                        frag = frag[1..];
                    }
                    if (header.flags.has(Flags.priority_flag)) {
                        if (frag.len < 5) return error.ProtocolError;
                        frag = frag[5..]; // skip dependency(4) + weight(1)
                    }
                    if (pad_len > frag.len) return error.ProtocolError;
                    const fragment = frag[0 .. frag.len - pad_len];

                    if (header.flags.has(Flags.end_headers)) {
                        // Complete header block in a single frame
                        return .{ .header_block = .{
                            .stream_id = header.stream_id,
                            .data = fragment,
                            .end_stream = header.flags.has(Flags.end_stream),
                        } };
                    }

                    // Start CONTINUATION assembly
                    if (fragment.len > self.header_buf.len) return error.InternalError;
                    @memcpy(self.header_buf[0..fragment.len], fragment);
                    self.header_len = fragment.len;
                    self.header_stream_id = header.stream_id;
                    self.header_end_stream = header.flags.has(Flags.end_stream);
                    continue; // read next frame (must be CONTINUATION)
                },

                .data => {
                    if (header.stream_id == 0) return error.ProtocolError;
                    return .{ .data = .{
                        .stream_id = header.stream_id,
                        .payload = payload,
                        .end_stream = header.flags.has(Flags.end_stream),
                    } };
                },

                .settings => {
                    if (header.stream_id != 0) return error.ProtocolError;
                    return .{ .settings = .{
                        .payload = payload,
                        .ack = header.flags.has(Flags.ack),
                    } };
                },

                .window_update => {
                    return .{ .window_update = .{
                        .stream_id = header.stream_id,
                        .payload = payload,
                    } };
                },

                .ping => {
                    if (header.stream_id != 0) return error.ProtocolError;
                    if (payload.len != 8) return error.FrameSizeError;
                    return .{ .ping = .{
                        .payload = payload,
                        .ack = header.flags.has(Flags.ack),
                    } };
                },

                .rst_stream => {
                    if (header.stream_id == 0) return error.ProtocolError;
                    return .{ .rst_stream = .{
                        .stream_id = header.stream_id,
                        .payload = payload,
                    } };
                },

                .goaway => {
                    if (header.stream_id != 0) return error.ProtocolError;
                    return .{ .goaway = payload };
                },

                .priority => {
                    if (header.stream_id == 0) return error.ProtocolError;
                    return .{ .priority = header.stream_id };
                },

                .push_promise => {
                    return .{ .push_promise = .{
                        .stream_id = header.stream_id,
                        .payload = payload,
                    } };
                },

                .continuation => {
                    // CONTINUATION outside of header block assembly is a protocol error
                    return error.ProtocolError;
                },

                _ => return .{ .unknown = {} },
            }
        }
    }

    /// Returns true if currently assembling a header block (waiting for CONTINUATION).
    pub fn isAssemblingHeaders(self: *const FrameReader) bool {
        return self.header_len > 0;
    }
};

/// Writes outgoing HTTP/2 frames, splitting large payloads into
/// multiple frames as needed and handling CONTINUATION for headers.
pub const FrameWriter = struct {
    max_frame_size: u24 = frame.default_max_frame_size,

    /// Write a complete HEADERS block, splitting into HEADERS + CONTINUATION
    /// frames if the encoded header block exceeds max_frame_size.
    pub fn writeHeaders(self: *const FrameWriter, writer: *Io.Writer, stream_id: u31, header_block: []const u8, end_stream: bool) !void {
        const max: usize = self.max_frame_size;

        if (header_block.len <= max) {
            const flags: u8 = Flags.end_headers | if (end_stream) Flags.end_stream else 0;
            try frame.writeFrame(writer, .headers, .{ .value = flags }, stream_id, header_block);
        } else {
            // First frame: HEADERS without END_HEADERS
            const first_flags: u8 = if (end_stream) Flags.end_stream else 0;
            try frame.writeFrame(writer, .headers, .{ .value = first_flags }, stream_id, header_block[0..max]);

            var sent: usize = max;
            while (sent < header_block.len) {
                const chunk = @min(header_block.len - sent, max);
                const is_last = sent + chunk >= header_block.len;
                const cont_flags: Flags = if (is_last) .{ .value = Flags.end_headers } else Flags.none;
                try frame.writeFrame(writer, .continuation, cont_flags, stream_id, header_block[sent..][0..chunk]);
                sent += chunk;
            }
        }
    }

    /// Write DATA frames, splitting if payload exceeds max_frame_size.
    pub fn writeData(self: *const FrameWriter, writer: *Io.Writer, stream_id: u31, data: []const u8, end_stream: bool) !void {
        const max: usize = self.max_frame_size;

        if (data.len == 0) {
            if (end_stream) {
                try frame.writeFrame(writer, .data, .{ .value = Flags.end_stream }, stream_id, &.{});
            }
            return;
        }

        var sent: usize = 0;
        while (sent < data.len) {
            const chunk = @min(data.len - sent, max);
            const is_last = sent + chunk >= data.len;
            const flags: Flags = if (is_last and end_stream) .{ .value = Flags.end_stream } else Flags.none;
            try frame.writeFrame(writer, .data, flags, stream_id, data[sent..][0..chunk]);
            sent += chunk;
        }
    }
};

// --- Tests ---

const testing = std.testing;

test "FrameReader: single HEADERS frame with END_HEADERS" {
    // Build a HEADERS frame: stream 1, END_HEADERS | END_STREAM, payload "hello"
    const payload = "hello";
    const hdr = FrameHeader{
        .length = @intCast(payload.len),
        .frame_type = .headers,
        .flags = .{ .value = Flags.end_headers | Flags.end_stream },
        .stream_id = 1,
    };
    const encoded_hdr = hdr.encode();
    const raw = encoded_hdr ++ payload.*;

    var io_reader: Io.Reader = .fixed(&raw);
    var fr: FrameReader = .{};

    const result = try fr.readFrame(&io_reader);
    switch (result) {
        .header_block => |hb| {
            try testing.expectEqual(@as(u31, 1), hb.stream_id);
            try testing.expectEqualStrings("hello", hb.data);
            try testing.expect(hb.end_stream);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "FrameReader: HEADERS + CONTINUATION assembly" {
    // HEADERS without END_HEADERS, then CONTINUATION with END_HEADERS
    const part1 = "hel";
    const part2 = "lo";

    const hdr1 = (FrameHeader{
        .length = @intCast(part1.len),
        .frame_type = .headers,
        .flags = .{ .value = Flags.end_stream }, // no END_HEADERS
        .stream_id = 3,
    }).encode();

    const hdr2 = (FrameHeader{
        .length = @intCast(part2.len),
        .frame_type = .continuation,
        .flags = .{ .value = Flags.end_headers },
        .stream_id = 3,
    }).encode();

    const raw = hdr1 ++ part1.* ++ hdr2 ++ part2.*;

    var io_reader: Io.Reader = .fixed(&raw);
    var fr: FrameReader = .{};

    const result = try fr.readFrame(&io_reader);
    switch (result) {
        .header_block => |hb| {
            try testing.expectEqual(@as(u31, 3), hb.stream_id);
            try testing.expectEqualStrings("hello", hb.data);
            try testing.expect(hb.end_stream);
        },
        else => return error.TestUnexpectedResult,
    }
    try testing.expect(!fr.isAssemblingHeaders());
}

test "FrameReader: wrong frame during CONTINUATION is protocol error" {
    const part1 = "hel";
    const hdr1 = (FrameHeader{
        .length = @intCast(part1.len),
        .frame_type = .headers,
        .flags = Flags.none, // no END_HEADERS
        .stream_id = 1,
    }).encode();

    // Send a PING instead of CONTINUATION
    const ping_payload: [8]u8 = @splat(0);
    const hdr2 = (FrameHeader{
        .length = 8,
        .frame_type = .ping,
        .flags = Flags.none,
        .stream_id = 0,
    }).encode();

    const raw = hdr1 ++ part1.* ++ hdr2 ++ ping_payload;

    var io_reader: Io.Reader = .fixed(&raw);
    var fr: FrameReader = .{};

    try testing.expectError(error.ProtocolError, fr.readFrame(&io_reader));
}

test "FrameReader: DATA frame" {
    const payload = "body";
    const hdr = (FrameHeader{
        .length = @intCast(payload.len),
        .frame_type = .data,
        .flags = .{ .value = Flags.end_stream },
        .stream_id = 1,
    }).encode();

    const raw = hdr ++ payload.*;
    var io_reader: Io.Reader = .fixed(&raw);
    var fr: FrameReader = .{};

    const result = try fr.readFrame(&io_reader);
    switch (result) {
        .data => |d| {
            try testing.expectEqual(@as(u31, 1), d.stream_id);
            try testing.expectEqualStrings("body", d.payload);
            try testing.expect(d.end_stream);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "FrameReader: SETTINGS frame" {
    const hdr = (FrameHeader{
        .length = 0,
        .frame_type = .settings,
        .flags = .{ .value = Flags.ack },
        .stream_id = 0,
    }).encode();

    var io_reader: Io.Reader = .fixed(&hdr);
    var fr: FrameReader = .{};

    const result = try fr.readFrame(&io_reader);
    switch (result) {
        .settings => |s| {
            try testing.expect(s.ack);
            try testing.expectEqual(@as(usize, 0), s.payload.len);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "FrameWriter: small header block fits in one frame" {
    var buf: [256]u8 = undefined;
    var io_writer: Io.Writer = .fixed(&buf);
    const fw: FrameWriter = .{};

    try fw.writeHeaders(&io_writer, 1, "hello", true);

    // Parse the written frame
    var io_reader: Io.Reader = .fixed(io_writer.buffered());
    const hdr_buf = try io_reader.take(frame.header_size);
    const hdr = FrameHeader.parse(hdr_buf[0..frame.header_size]);

    try testing.expectEqual(FrameType.headers, hdr.frame_type);
    try testing.expectEqual(@as(u31, 1), hdr.stream_id);
    try testing.expect(hdr.flags.has(Flags.end_headers));
    try testing.expect(hdr.flags.has(Flags.end_stream));
    try testing.expectEqual(@as(u24, 5), hdr.length);
}

test "FrameWriter: large header block splits into CONTINUATION" {
    var buf: [65536]u8 = undefined;
    var io_writer: Io.Writer = .fixed(&buf);
    const fw: FrameWriter = .{ .max_frame_size = 10 };

    // 25 bytes = 3 frames: 10 + 10 + 5
    const data = "abcdefghijklmnopqrstuvwxy";
    try fw.writeHeaders(&io_writer, 5, data, false);

    // Parse frames
    var io_reader: Io.Reader = .fixed(io_writer.buffered());

    // Frame 1: HEADERS, no END_HEADERS
    const h1_buf = try io_reader.take(frame.header_size);
    const h1 = FrameHeader.parse(h1_buf[0..frame.header_size]);
    try testing.expectEqual(FrameType.headers, h1.frame_type);
    try testing.expect(!h1.flags.has(Flags.end_headers));
    try testing.expectEqual(@as(u24, 10), h1.length);
    _ = try io_reader.take(10);

    // Frame 2: CONTINUATION, no END_HEADERS
    const h2_buf = try io_reader.take(frame.header_size);
    const h2 = FrameHeader.parse(h2_buf[0..frame.header_size]);
    try testing.expectEqual(FrameType.continuation, h2.frame_type);
    try testing.expect(!h2.flags.has(Flags.end_headers));
    try testing.expectEqual(@as(u24, 10), h2.length);
    _ = try io_reader.take(10);

    // Frame 3: CONTINUATION, END_HEADERS
    const h3_buf = try io_reader.take(frame.header_size);
    const h3 = FrameHeader.parse(h3_buf[0..frame.header_size]);
    try testing.expectEqual(FrameType.continuation, h3.frame_type);
    try testing.expect(h3.flags.has(Flags.end_headers));
    try testing.expectEqual(@as(u24, 5), h3.length);
}

test "FrameWriter: DATA splitting" {
    var buf: [256]u8 = undefined;
    var io_writer: Io.Writer = .fixed(&buf);
    const fw: FrameWriter = .{ .max_frame_size = 4 };

    try fw.writeData(&io_writer, 1, "abcdefgh", true);

    var io_reader: Io.Reader = .fixed(io_writer.buffered());

    // Frame 1: 4 bytes, no END_STREAM
    const h1_buf = try io_reader.take(frame.header_size);
    const h1 = FrameHeader.parse(h1_buf[0..frame.header_size]);
    try testing.expectEqual(FrameType.data, h1.frame_type);
    try testing.expect(!h1.flags.has(Flags.end_stream));
    try testing.expectEqual(@as(u24, 4), h1.length);
    _ = try io_reader.take(4);

    // Frame 2: 4 bytes, END_STREAM
    const h2_buf = try io_reader.take(frame.header_size);
    const h2 = FrameHeader.parse(h2_buf[0..frame.header_size]);
    try testing.expectEqual(FrameType.data, h2.frame_type);
    try testing.expect(h2.flags.has(Flags.end_stream));
    try testing.expectEqual(@as(u24, 4), h2.length);
}

test "FrameWriter: empty DATA with END_STREAM" {
    var buf: [64]u8 = undefined;
    var io_writer: Io.Writer = .fixed(&buf);
    const fw: FrameWriter = .{};

    try fw.writeData(&io_writer, 1, "", true);

    var io_reader: Io.Reader = .fixed(io_writer.buffered());
    const h_buf = try io_reader.take(frame.header_size);
    const h = FrameHeader.parse(h_buf[0..frame.header_size]);
    try testing.expectEqual(FrameType.data, h.frame_type);
    try testing.expect(h.flags.has(Flags.end_stream));
    try testing.expectEqual(@as(u24, 0), h.length);
}
