//! Sans-I/O HTTP/2 client for the upstream leg (DESIGN.md §7).
//!
//! zhttp's `h2` codec supplies the RFC-level pieces — frames, HPACK,
//! settings, flow-control arithmetic. This module is the driver zoxy's
//! serving model needs: no `std.Io` readers, no per-request arena, no
//! threads. It encodes one request into the caller's buffer and consumes
//! response bytes one complete frame at a time, so the exchange can keep
//! its recv→send→recv discipline.
//!
//! **One stream at a time.** A connection carries one exchange; the next
//! exchange either reuses it after END_STREAM or dials a fresh one. That
//! is deliberately narrower than RFC 9113 allows and exactly as wide as
//! the current §7 model — multiplexing needs per-stream exchange state,
//! which is a different design, not a bigger buffer.
//!
//! **No HPACK dynamic table in either direction.** The client encodes
//! every field with the never-indexed literal form and advertises
//! `SETTINGS_HEADER_TABLE_SIZE = 0`. A conforming origin therefore sends
//! no dynamic-table references, so the decoder needs no table and a
//! connection can be recycled without carrying encoder state — the same
//! reason a parked h1 connection carries nothing but a socket.
//!
//! **Receive windows are opened once.** The SETTINGS frame advertises the
//! maximum stream window and one WINDOW_UPDATE opens the connection
//! window to the same value. This keeps the response path free of
//! WINDOW_UPDATE bookkeeping for the first 2 GiB of a connection's life;
//! a response larger than that needs a design that can send control
//! frames mid-pump, and is not claimed here.

const std = @import("std");

const h2 = @import("h2.zig");

pub const frame = h2.frame;
pub const hpack = h2.hpack;
pub const ErrorCode = h2.ErrorCode;

const assert = std.debug.assert;

/// What the caller's buffers must hold. The inbound assembly buffer is
/// one maximum frame plus its header; HEADERS/CONTINUATION blocks may be
/// larger, so they get their own buffer.
pub const inbound_bytes_max: usize = frame.header_size + frame.default_max_frame_size;
pub const header_block_bytes_max: usize = 16 * 1024;
pub const header_fields_max: usize = 64;
pub const outbound_request_bytes_max: usize = 32 * 1024;

/// The largest window either side may advertise (RFC 9113 §6.9.1).
pub const window_max: u31 = std.math.maxInt(i31);

/// Why a frame stream could not be driven. Everything here dooms the
/// connection, not one request: HTTP/2 errors are connection-scoped in
/// this one-stream model.
pub const Error = error{
    BufferTooSmall,
    FrameTooLarge,
    HeaderBlockTooLarge,
    HeaderListTooLong,
    ProtocolError,
    HpackDecodingError,
};

/// One client-side HTTP/2 connection's state. Inline buffers; a caller
/// that wants a pool allocates `Client` objects, never bytes.
pub const Client = struct {
    /// Bytes received but not yet parsed, plus the tail of a split frame.
    inbound: [inbound_bytes_max]u8 = undefined,
    inbound_len: usize = 0,
    /// Bytes at the front already returned to the caller. Compacted on
    /// the next `feed`, which is what keeps a DATA payload's slice valid
    /// until the caller has forwarded it.
    consumed: usize = 0,

    /// A HEADERS block being assembled across CONTINUATION frames.
    block: [header_block_bytes_max]u8 = undefined,
    block_len: usize = 0,
    block_stream: u31 = 0,
    block_end_stream: bool = false,
    assembling: bool = false,

    decoder_buffer: [64]u8 = undefined,
    decoder_entries: [1]hpack.DynamicTable.Entry = undefined,
    decoder: hpack.Decoder = undefined,

    /// The stream this connection is carrying, and the next id to open.
    stream_id: u31 = 0,
    next_stream_id: u31 = 1,
    /// Whether response HEADERS have been seen, so a second block on the
    /// same stream is labeled trailers rather than a second response.
    response_started: bool = false,
    /// The connection preface and our SETTINGS have been written.
    preface_sent: bool = false,
    /// A stream is open: from `startRequest` until its END_STREAM.
    active: bool = false,

    /// Peer-advertised limits, applied from its SETTINGS frame.
    peer_max_frame: usize = frame.default_max_frame_size,
    peer_initial_window: i64 = 65535,
    /// Connection-level send credit; starts at 65535 (§6.9.2).
    send_window: i64 = 65535,
    /// Stream-level send credit, mirrored from the peer's SETTINGS.
    stream_send_window: i64 = 65535,
    /// Credit the peer may still spend sending to us. Starts at the
    /// protocol's 65535, then opens to `window_max` with the WINDOW_UPDATE
    /// `startRequest` sends.
    recv_window: i64 = 65535,

    pub fn initInPlace(self: *Client) void {
        self.* = .{};
        self.decoder = hpack.Decoder.init(&self.decoder_buffer, &self.decoder_entries);
        // The one client-side encoder setting that makes a parked
        // connection stateless: a conforming peer cannot index anything.
        self.decoder.dynamic_table.setMaxSize(0);
    }

    /// One regular header as the caller supplies it. Pseudo-headers come
    /// from the request line, never from this list.
    pub const Header = struct {
        name: []const u8,
        value: []const u8,
    };

    pub const Request = struct {
        method: []const u8,
        /// `http` or `https`; the origin's view of this hop.
        scheme: []const u8,
        /// The `:authority` a host header would have named.
        authority: []const u8,
        /// Origin-form path and query.
        path: []const u8,
        headers: []const Header = &.{},
        /// True when the request has no body: END_STREAM rides HEADERS.
        end_stream: bool = true,
    };

    /// Encode this stream's request HEADERS (+CONTINUATION), and on the
    /// first call the connection preface, our SETTINGS and the window
    /// update too. Returns the bytes written. A connection may carry a
    /// new request after the previous stream ended; the preface is
    /// emitted once.
    pub fn startRequest(self: *Client, out: []u8, request: Request) Error!usize {
        assert(!self.active);
        assert(self.stream_id == 0);
        var writer: std.Io.Writer = .fixed(out);
        if (!self.preface_sent) {
            writer.writeAll(h2.connection_preface) catch return error.BufferTooSmall;
            const settings = [_]frame.Setting{
                .{ .id = .enable_push, .value = 0 },
                .{ .id = .max_concurrent_streams, .value = 1 },
                .{ .id = .initial_window_size, .value = window_max },
                .{ .id = .header_table_size, .value = 0 },
            };
            frame.writeSettings(&writer, &settings) catch return error.BufferTooSmall;
            // Open the connection-level receive window once. The stream
            // window already opened via SETTINGS; the local counter must
            // move with the frame we just wrote or a 64 KiB response
            // would look like a flow-control violation.
            var increment: [4]u8 = undefined;
            std.mem.writeInt(u32, &increment, window_max - 65535, .big);
            frame.writeFrame(&writer, .window_update, .none, 0, &increment) catch
                return error.BufferTooSmall;
            self.recv_window = window_max;
            self.preface_sent = true;
        }
        if (self.next_stream_id > std.math.maxInt(i31) - 2) return error.ProtocolError;
        self.stream_id = self.next_stream_id;
        self.next_stream_id += 2;
        // A new stream gets the peer's current initial window; the
        // connection-level window persists across streams.
        self.stream_send_window = self.peer_initial_window;
        self.response_started = false;
        self.active = true;

        const block = try self.encodeHeaders(request);
        writeHeaderBlock(
            &writer,
            block,
            self.stream_id,
            self.peer_max_frame,
            request.end_stream,
        ) catch return error.BufferTooSmall;
        return writer.end;
    }

    /// Frame one request-body chunk. `end_stream` must be true on the
    /// last call, including a bodyless request that did not already end
    /// at HEADERS. Returns how many input bytes fit the peer's flow
    /// control and frame size; `blocked` means zero credit and the caller
    /// must wait for WINDOW_UPDATE.
    pub const EncodedData = struct {
        written: usize = 0,
        blocked: bool = false,
    };

    pub fn encodeData(
        self: *Client,
        out: []u8,
        data: []const u8,
        end_stream: bool,
    ) Error!EncodedData {
        assert(self.stream_id != 0);
        const credit = @min(self.send_window, self.stream_send_window);
        if (credit <= 0) return .{ .blocked = true };
        var writer: std.Io.Writer = .fixed(out);
        if (data.len == 0) {
            if (end_stream) {
                frame.writeFrame(&writer, .data, .{ .value = frame.Flags.end_stream }, self.stream_id, &.{}) catch
                    return error.BufferTooSmall;
            }
            return .{ .written = 0 };
        }
        var taken: usize = 0;
        while (taken < data.len) {
            const remaining_credit: usize = @intCast(credit - @as(i64, @intCast(taken)));
            const room = @min(remaining_credit, self.peer_max_frame);
            if (room == 0) break;
            const chunk = data[taken..][0..@min(room, data.len - taken)];
            const last = taken + chunk.len == data.len;
            const flags: frame.Flags = if (last and end_stream)
                .{ .value = frame.Flags.end_stream }
            else
                .none;
            frame.writeFrame(&writer, .data, flags, self.stream_id, chunk) catch
                return error.BufferTooSmall;
            taken += chunk.len;
        }
        self.send_window -= @intCast(taken);
        self.stream_send_window -= @intCast(taken);
        assert(self.send_window >= 0 and self.stream_send_window >= 0);
        return .{ .written = taken, .blocked = taken == 0 };
    }

    /// A SETTINGS acknowledgement, for the caller that received a
    /// non-ACK SETTINGS event.
    pub fn encodeSettingsAck(out: []u8) Error!usize {
        var writer: std.Io.Writer = .fixed(out);
        frame.writeSettingsAck(&writer) catch return error.BufferTooSmall;
        return writer.end;
    }

    /// A PING acknowledgement carrying the peer's eight opaque bytes.
    pub fn encodePingAck(out: []u8, payload: [8]u8) Error!usize {
        var writer: std.Io.Writer = .fixed(out);
        frame.writeFrame(&writer, .ping, .{ .value = frame.Flags.ack }, 0, &payload) catch
            return error.BufferTooSmall;
        return writer.end;
    }

    /// One inbound event. `data` and `headers` alias this client's
    /// buffers and stay valid until the next `feed`.
    pub const Event = union(enum) {
        headers: struct {
            fields: []const hpack.HeaderField,
            end_stream: bool,
            /// A block after the response head: HTTP trailers.
            trailers: bool,
        },
        data: struct {
            payload: []const u8,
            end_stream: bool,
        },
        settings: struct { ack: bool },
        ping: struct { payload: [8]u8, ack: bool },
        window_update: struct { stream_id: u31, increment: u31 },
        rst_stream: struct { stream_id: u31, error_code: u32 },
        goaway: struct { last_stream_id: u31, error_code: u32 },
        /// A frame this model has no use for (PRIORITY, unknown types).
        ignored: void,
        /// A frame is split across reads: call `feed` again with the
        /// next bytes.
        need_more: void,
    };

    /// Append `bytes` and parse at most one frame. Call again with `&.{}`
    /// to drain frames the previous chunk carried. `fields` receives a
    /// decoded header block and must have room for `header_fields_max`.
    pub fn feed(
        self: *Client,
        bytes: []const u8,
        fields: []hpack.HeaderField,
    ) Error!Event {
        self.compact();
        if (bytes.len > self.inbound.len - self.inbound_len) return error.BufferTooSmall;
        @memcpy(self.inbound[self.inbound_len..][0..bytes.len], bytes);
        self.inbound_len += bytes.len;
        return self.parseOne(fields);
    }

    fn compact(self: *Client) void {
        if (self.consumed == 0) return;
        assert(self.consumed <= self.inbound_len);
        const remaining = self.inbound_len - self.consumed;
        std.mem.copyForwards(u8, self.inbound[0..remaining], self.inbound[self.consumed..self.inbound_len]);
        self.inbound_len = remaining;
        self.consumed = 0;
    }

    fn parseOne(self: *Client, fields: []hpack.HeaderField) Error!Event {
        if (self.inbound_len < frame.header_size) return .need_more;
        const header = frame.FrameHeader.parse(self.inbound[0..frame.header_size]);
        if (header.length > frame.default_max_frame_size) return error.FrameTooLarge;
        const total = frame.header_size + @as(usize, header.length);
        if (self.inbound_len < total) return .need_more;
        const payload = self.inbound[frame.header_size..total];
        self.consumed = total;
        return switch (header.frame_type) {
            .settings => self.onSettings(payload, header.flags),
            .ping => self.onPing(payload, header.flags),
            .window_update => self.onWindowUpdate(payload, header),
            .rst_stream => self.onRst(payload, header),
            .goaway => self.onGoaway(payload),
            .headers => self.onHeaders(payload, header, fields),
            .continuation => self.onContinuation(payload, header, fields),
            .data => self.onData(payload, header),
            .push_promise => error.ProtocolError, // ENABLE_PUSH was 0.
            .priority => .ignored,
            else => .ignored,
        };
    }

    fn onSettings(self: *Client, payload: []const u8, flags: frame.Flags) Error!Event {
        if (flags.has(frame.Flags.ack)) {
            if (payload.len != 0) return error.ProtocolError;
            return .{ .settings = .{ .ack = true } };
        }
        if (payload.len % 6 != 0) return error.ProtocolError;
        var iterator = frame.parseSettings(payload);
        while (iterator.next()) |setting| {
            switch (setting.id) {
                .initial_window_size => {
                    if (setting.value > window_max) return error.ProtocolError;
                    const next: i64 = setting.value;
                    self.stream_send_window += next - self.peer_initial_window;
                    self.peer_initial_window = next;
                },
                .max_frame_size => {
                    if (setting.value < frame.default_max_frame_size or
                        setting.value > 0x00FF_FFFF) return error.ProtocolError;
                    self.peer_max_frame = setting.value;
                },
                // The peer's header-table size governs our encoder, which
                // never indexes. Enable-push and concurrency are its to
                // state and ours to ignore in a one-stream client.
                else => {},
            }
        }
        return .{ .settings = .{ .ack = false } };
    }

    fn onPing(self: *Client, payload: []const u8, flags: frame.Flags) Error!Event {
        _ = self;
        if (payload.len != 8) return error.ProtocolError;
        var copy: [8]u8 = undefined;
        @memcpy(&copy, payload);
        return .{ .ping = .{ .payload = copy, .ack = flags.has(frame.Flags.ack) } };
    }

    fn onWindowUpdate(self: *Client, payload: []const u8, header: frame.FrameHeader) Error!Event {
        if (payload.len != 4) return error.ProtocolError;
        const raw = std.mem.readInt(u32, payload[0..4], .big);
        const increment: u31 = @intCast(raw & 0x7FFF_FFFF);
        if (increment == 0) return error.ProtocolError;
        if (header.stream_id == 0) {
            self.send_window += increment;
        } else if (header.stream_id == self.stream_id) {
            self.stream_send_window += increment;
        }
        return .{ .window_update = .{
            .stream_id = header.stream_id,
            .increment = increment,
        } };
    }

    fn onRst(self: *Client, payload: []const u8, header: frame.FrameHeader) Error!Event {
        _ = self;
        if (payload.len != 4) return error.ProtocolError;
        return .{ .rst_stream = .{
            .stream_id = header.stream_id,
            .error_code = std.mem.readInt(u32, payload[0..4], .big),
        } };
    }

    fn onGoaway(self: *Client, payload: []const u8) Error!Event {
        _ = self;
        if (payload.len < 8) return error.ProtocolError;
        return .{ .goaway = .{
            .last_stream_id = @intCast(std.mem.readInt(u32, payload[0..4], .big) & 0x7FFF_FFFF),
            .error_code = std.mem.readInt(u32, payload[4..8], .big),
        } };
    }

    fn onHeaders(
        self: *Client,
        payload: []const u8,
        header: frame.FrameHeader,
        fields: []hpack.HeaderField,
    ) Error!Event {
        if (self.assembling) return error.ProtocolError;
        if (!self.active or header.stream_id != self.stream_id) return error.ProtocolError;
        if (header.flags.has(frame.Flags.padded)) {
            if (payload.len < 1) return error.ProtocolError;
        }
        var fragment = payload;
        var pad_len: usize = 0;
        if (header.flags.has(frame.Flags.padded)) {
            pad_len = fragment[0];
            fragment = fragment[1..];
        }
        if (header.flags.has(frame.Flags.priority_flag)) {
            if (fragment.len < 5) return error.ProtocolError;
            fragment = fragment[5..];
        }
        if (pad_len > fragment.len) return error.ProtocolError;
        fragment = fragment[0 .. fragment.len - pad_len];
        if (header.flags.has(frame.Flags.end_headers)) {
            return self.decodeBlock(fragment, header.flags.has(frame.Flags.end_stream), fields);
        }
        if (fragment.len > self.block.len) return error.HeaderBlockTooLarge;
        @memcpy(self.block[0..fragment.len], fragment);
        self.block_len = fragment.len;
        self.block_stream = header.stream_id;
        self.block_end_stream = header.flags.has(frame.Flags.end_stream);
        self.assembling = true;
        return .need_more;
    }

    fn onContinuation(
        self: *Client,
        payload: []const u8,
        header: frame.FrameHeader,
        fields: []hpack.HeaderField,
    ) Error!Event {
        if (!self.assembling) return error.ProtocolError;
        if (header.stream_id != self.block_stream) return error.ProtocolError;
        if (self.block_len + payload.len > self.block.len) return error.HeaderBlockTooLarge;
        @memcpy(self.block[self.block_len..][0..payload.len], payload);
        self.block_len += payload.len;
        if (!header.flags.has(frame.Flags.end_headers)) return .need_more;
        self.assembling = false;
        const end_stream = self.block_end_stream;
        const block = self.block[0..self.block_len];
        self.block_len = 0;
        return self.decodeBlock(block, end_stream, fields);
    }

    fn decodeBlock(
        self: *Client,
        block: []const u8,
        end_stream: bool,
        fields: []hpack.HeaderField,
    ) Error!Event {
        const count = self.decoder.decode(block, fields) catch return error.HpackDecodingError;
        if (count > fields.len) return error.HeaderListTooLong;
        const trailers = self.response_started;
        self.response_started = true;
        if (end_stream) {
            self.active = false;
            self.stream_id = 0;
        }
        return .{ .headers = .{
            .fields = fields[0..count],
            .end_stream = end_stream,
            .trailers = trailers,
        } };
    }

    fn onData(
        self: *Client,
        payload: []const u8,
        header: frame.FrameHeader,
    ) Error!Event {
        if (header.stream_id != self.stream_id or !self.active) return error.ProtocolError;
        self.recv_window -= @intCast(payload.len);
        if (self.recv_window < 0) return error.ProtocolError;
        if (header.flags.has(frame.Flags.end_stream)) {
            self.active = false;
            self.stream_id = 0;
        }
        return .{ .data = .{
            .payload = payload,
            .end_stream = header.flags.has(frame.Flags.end_stream),
        } };
    }

    fn encodeHeaders(self: *Client, request: Request) Error![]const u8 {
        var used: usize = 0;
        const block = self.block[0..];
        used += hpack.Encoder.encodeHeaderWithoutIndexing(
            block[used..],
            ":method",
            request.method,
        ) catch return error.HeaderBlockTooLarge;
        used += hpack.Encoder.encodeHeaderWithoutIndexing(
            block[used..],
            ":scheme",
            request.scheme,
        ) catch return error.HeaderBlockTooLarge;
        used += hpack.Encoder.encodeHeaderWithoutIndexing(
            block[used..],
            ":authority",
            request.authority,
        ) catch return error.HeaderBlockTooLarge;
        used += hpack.Encoder.encodeHeaderWithoutIndexing(
            block[used..],
            ":path",
            request.path,
        ) catch return error.HeaderBlockTooLarge;
        for (request.headers) |header| {
            if (header.name.len == 0) continue;
            if (header.name[0] == ':') continue;
            if (!forwardable(header.name)) continue;
            used += hpack.Encoder.encodeHeaderWithoutIndexing(
                block[used..],
                header.name,
                header.value,
            ) catch return error.HeaderBlockTooLarge;
        }
        return block[0..used];
    }
};

/// Connection-specific fields never cross an HTTP/2 hop (RFC 9113
/// §8.2.2). `host` is represented by `:authority` and is dropped.
fn forwardable(name: []const u8) bool {
    const denied = [_][]const u8{
        "connection",
        "keep-alive",
        "proxy-connection",
        "transfer-encoding",
        "upgrade",
        "host",
        "te",
    };
    for (denied) |candidate| {
        if (std.ascii.eqlIgnoreCase(name, candidate)) return false;
    }
    return true;
}

/// Write a header block as HEADERS plus as many CONTINUATION frames as
/// the peer's frame size needs. END_STREAM rides the first frame.
fn writeHeaderBlock(
    writer: *std.Io.Writer,
    block: []const u8,
    stream_id: u31,
    max_frame: usize,
    end_stream: bool,
) !void {
    assert(max_frame >= frame.default_max_frame_size);
    if (block.len <= max_frame) {
        const flags_value: u8 = frame.Flags.end_headers |
            (if (end_stream) frame.Flags.end_stream else 0);
        try frame.writeFrame(writer, .headers, .{ .value = flags_value }, stream_id, block);
        return;
    }
    const first_flags: u8 = if (end_stream) frame.Flags.end_stream else 0;
    try frame.writeFrame(writer, .headers, .{ .value = first_flags }, stream_id, block[0..max_frame]);
    var sent: usize = max_frame;
    while (sent < block.len) {
        const chunk = @min(block.len - sent, max_frame);
        const last = sent + chunk == block.len;
        const flags: frame.Flags = if (last) .{ .value = frame.Flags.end_headers } else .none;
        try frame.writeFrame(writer, .continuation, flags, stream_id, block[sent..][0..chunk]);
        sent += chunk;
    }
}

// --- Tests ---

const testing = std.testing;

fn testClient() Client {
    var client: Client = undefined;
    client.initInPlace();
    return client;
}

/// Read the next frame header from a wire buffer and return its payload.
fn nextFrame(wire: []const u8, offset: *usize) struct {
    header: frame.FrameHeader,
    payload: []const u8,
} {
    const header = frame.FrameHeader.parse(wire[offset.*..][0..frame.header_size]);
    const start = offset.* + frame.header_size;
    const payload = wire[start..][0..header.length];
    offset.* = start + header.length;
    return .{ .header = header, .payload = payload };
}

fn encodeServerHeaders(wire: []u8, offset: *usize, stream_id: u31, end_stream: bool, fields: []const hpack.HeaderField) !void {
    var block: [4096]u8 = undefined;
    var used: usize = 0;
    for (fields) |field| {
        used += try hpack.Encoder.encodeHeaderWithoutIndexing(block[used..], field.name, field.value);
    }
    const flags_value: u8 = frame.Flags.end_headers |
        (if (end_stream) frame.Flags.end_stream else 0);
    var writer: std.Io.Writer = .fixed(wire[offset.*..]);
    try frame.writeFrame(&writer, .headers, .{ .value = flags_value }, stream_id, block[0..used]);
    offset.* += writer.end;
}

test "h2 client: a request encodes preface, settings, window and headers" {
    var client = testClient();
    var out: [outbound_request_bytes_max]u8 = undefined;
    const headers = [_]Client.Header{
        .{ .name = "accept", .value = "*/*" },
        .{ .name = "connection", .value = "keep-alive" },
        .{ .name = "host", .value = "ignored.example" },
    };
    const len = try client.startRequest(&out, .{
        .method = "GET",
        .scheme = "https",
        .authority = "origin.example",
        .path = "/v1/items?page=2",
        .headers = &headers,
    });
    var offset: usize = 0;
    try testing.expectEqualSlices(u8, h2.connection_preface, out[0..h2.connection_preface.len]);
    offset += h2.connection_preface.len;
    const settings = nextFrame(out[0..len], &offset);
    try testing.expectEqual(frame.FrameType.settings, settings.header.frame_type);
    var iterator = frame.parseSettings(settings.payload);
    var saw_window = false;
    var saw_table = false;
    while (iterator.next()) |setting| {
        if (setting.id == .initial_window_size) {
            try testing.expectEqual(window_max, setting.value);
            saw_window = true;
        }
        if (setting.id == .header_table_size) {
            try testing.expectEqual(@as(u32, 0), setting.value);
            saw_table = true;
        }
    }
    try testing.expect(saw_window and saw_table);
    const update = nextFrame(out[0..len], &offset);
    try testing.expectEqual(frame.FrameType.window_update, update.header.frame_type);
    try testing.expectEqual(@as(u32, window_max - 65535), std.mem.readInt(u32, update.payload[0..4], .big));
    const request = nextFrame(out[0..len], &offset);
    try testing.expectEqual(frame.FrameType.headers, request.header.frame_type);
    try testing.expect(request.header.flags.has(frame.Flags.end_headers));
    try testing.expect(request.header.flags.has(frame.Flags.end_stream));

    var decoded_storage: [8]hpack.HeaderField = undefined;
    var decoder_state: hpack.Decoder = hpack.Decoder.init(&client.decoder_buffer, &client.decoder_entries);
    decoder_state.dynamic_table.setMaxSize(0);
    const count = try decoder_state.decode(request.payload, &decoded_storage);
    try testing.expectEqual(@as(usize, 5), count);
    try testing.expectEqualStrings(":method", decoded_storage[0].name);
    try testing.expectEqualStrings("GET", decoded_storage[0].value);
    try testing.expectEqualStrings(":authority", decoded_storage[2].name);
    try testing.expectEqualStrings("origin.example", decoded_storage[2].value);
    try testing.expectEqualStrings(":path", decoded_storage[3].name);
    try testing.expectEqualStrings("/v1/items?page=2", decoded_storage[3].value);
    // Connection-specific fields were dropped; accept survived.
    try testing.expectEqualStrings("accept", decoded_storage[4].name);
    try testing.expectEqual(@as(usize, len), offset);
}

test "h2 client: response settings, headers and data across split reads" {
    var client = testClient();
    var out: [outbound_request_bytes_max]u8 = undefined;
    _ = try client.startRequest(&out, .{
        .method = "GET",
        .scheme = "http",
        .authority = "o",
        .path = "/",
    });

    var wire: [4096]u8 = undefined;
    var used: usize = 0;
    {
        var writer: std.Io.Writer = .fixed(wire[used..]);
        try frame.writeSettings(&writer, &.{
            .{ .id = .initial_window_size, .value = 1 << 20 },
            .{ .id = .max_frame_size, .value = 1 << 15 },
        });
        used += writer.end;
    }
    try encodeServerHeaders(&wire, &used, 1, false, &.{
        .{ .name = ":status", .value = "200" },
        .{ .name = "content-type", .value = "text/plain" },
    });
    {
        var writer: std.Io.Writer = .fixed(wire[used..]);
        try frame.writeFrame(&writer, .data, .none, 1, "hello ");
        used += writer.end;
    }

    var fields: [header_fields_max]hpack.HeaderField = undefined;
    // Split the settings frame mid-payload: the driver must ask for more.
    const first = try client.feed(wire[0..12], &fields);
    try testing.expect(std.meta.activeTag(first) == .need_more);
    const settings_event = try client.feed(wire[12..used], &fields);
    switch (settings_event) {
        .settings => |s| try testing.expect(!s.ack),
        else => return error.TestUnexpectedResult,
    }
    try testing.expectEqual(@as(i64, 1 << 20), client.stream_send_window);
    try testing.expectEqual(@as(usize, 1 << 15), client.peer_max_frame);

    const headers_event = try client.feed(&.{}, &fields);
    switch (headers_event) {
        .headers => |h| {
            try testing.expect(!h.end_stream and !h.trailers);
            try testing.expectEqual(@as(usize, 2), h.fields.len);
            try testing.expectEqualStrings(":status", h.fields[0].name);
            try testing.expectEqualStrings("200", h.fields[0].value);
        },
        else => return error.TestUnexpectedResult,
    }
    const data_event = try client.feed(&.{}, &fields);
    switch (data_event) {
        .data => |d| try testing.expectEqualStrings("hello ", d.payload),
        else => return error.TestUnexpectedResult,
    }
    try testing.expect(std.meta.activeTag(try client.feed(&.{}, &fields)) == .need_more);
}

test "h2 client: a header block split across CONTINUATION frames assembles" {
    var client = testClient();
    var out: [outbound_request_bytes_max]u8 = undefined;
    _ = try client.startRequest(&out, .{
        .method = "GET",
        .scheme = "http",
        .authority = "o",
        .path = "/",
    });

    var block: [256]u8 = undefined;
    var used: usize = 0;
    used += try hpack.Encoder.encodeHeaderWithoutIndexing(block[used..], ":status", "204");
    used += try hpack.Encoder.encodeHeaderWithoutIndexing(block[used..], "x-trailer", "yes");
    const split = used / 2;

    var wire: [4096]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&wire);
    try frame.writeFrame(&writer, .headers, .none, 1, block[0..split]);
    try frame.writeFrame(&writer, .continuation, .{ .value = frame.Flags.end_headers }, 1, block[split..used]);
    const len = writer.end;

    var fields: [header_fields_max]hpack.HeaderField = undefined;
    try testing.expect(std.meta.activeTag(try client.feed(wire[0..len], &fields)) == .need_more);
    switch (try client.feed(&.{}, &fields)) {
        .headers => |h| {
            try testing.expectEqual(@as(usize, 2), h.fields.len);
            try testing.expectEqualStrings(":status", h.fields[0].name);
            try testing.expectEqualStrings("204", h.fields[0].value);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "h2 client: ping and settings acknowledgements round-trip" {
    var client = testClient();
    var out: [64]u8 = undefined;

    var wire: [64]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&wire);
    const ping_payload = [8]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };
    try frame.writeFrame(&writer, .ping, .none, 0, &ping_payload);
    const len = writer.end;
    var fields: [header_fields_max]hpack.HeaderField = undefined;
    const event = try client.feed(wire[0..len], &fields);
    switch (event) {
        .ping => |p| {
            try testing.expect(!p.ack);
            try testing.expectEqualSlices(u8, &ping_payload, &p.payload);
            const ack_len = try Client.encodePingAck(&out, p.payload);
            var offset: usize = 0;
            const ack = nextFrame(out[0..ack_len], &offset);
            try testing.expectEqual(frame.FrameType.ping, ack.header.frame_type);
            try testing.expect(ack.header.flags.has(frame.Flags.ack));
            try testing.expectEqualSlices(u8, &ping_payload, ack.payload);
        },
        else => return error.TestUnexpectedResult,
    }

    var settings_wire: [64]u8 = undefined;
    var settings_writer: std.Io.Writer = .fixed(&settings_wire);
    try frame.writeSettings(&settings_writer, &.{});
    const settings_len = settings_writer.end;
    const settings_event = try client.feed(settings_wire[0..settings_len], &fields);
    switch (settings_event) {
        .settings => |s| try testing.expect(!s.ack),
        else => return error.TestUnexpectedResult,
    }
    const ack_len = try Client.encodeSettingsAck(&out);
    var offset: usize = 0;
    const ack = nextFrame(out[0..ack_len], &offset);
    try testing.expectEqual(frame.FrameType.settings, ack.header.frame_type);
    try testing.expect(ack.header.flags.has(frame.Flags.ack));
}

test "h2 client: window updates credit the right scope" {
    var client = testClient();
    var out: [outbound_request_bytes_max]u8 = undefined;
    _ = try client.startRequest(&out, .{
        .method = "GET",
        .scheme = "http",
        .authority = "o",
        .path = "/",
    });

    const connection_before = client.send_window;
    var wire: [16]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&wire);
    var increment: [4]u8 = undefined;
    std.mem.writeInt(u32, &increment, 1000, .big);
    try frame.writeFrame(&writer, .window_update, .none, 0, &increment);
    var fields: [header_fields_max]hpack.HeaderField = undefined;
    const event = try client.feed(wire[0..writer.end], &fields);
    switch (event) {
        .window_update => |w| {
            try testing.expectEqual(@as(u31, 1000), w.increment);
            try testing.expectEqual(@as(u31, 0), w.stream_id);
        },
        else => return error.TestUnexpectedResult,
    }
    try testing.expectEqual(connection_before + 1000, client.send_window);
}

test "h2 client: data honours peer flow control and frame size" {
    var client = testClient();
    var out: [outbound_request_bytes_max]u8 = undefined;
    _ = try client.startRequest(&out, .{
        .method = "POST",
        .scheme = "http",
        .authority = "o",
        .path = "/upload",
        .end_stream = false,
    });
    // The peer's initial window is the default 65535; shrink it to prove
    // the credit is respected, with a small frame size to force splits.
    client.stream_send_window = 10;
    client.peer_max_frame = 4;
    var data_out: [4096]u8 = undefined;
    const first = try client.encodeData(&data_out, "abcdefghijklmnop", false);
    try testing.expectEqual(@as(usize, 10), first.written);
    try testing.expectEqual(@as(i64, 0), client.stream_send_window);
    const blocked = try client.encodeData(&data_out, "more", true);
    try testing.expect(blocked.blocked);
    // Two frames of four plus one of two.
    var offset: usize = 0;
    const total = 3 * frame.header_size + 10;
    var frames: usize = 0;
    while (offset < total) : (frames += 1) {
        const f = nextFrame(data_out[0..total], &offset);
        try testing.expectEqual(frame.FrameType.data, f.header.frame_type);
        try testing.expect(f.payload.len <= 4);
    }
    try testing.expectEqual(@as(usize, 3), frames);
    try testing.expectEqual(total, offset);
}

test "h2 client: push promise is a connection error and RST/GOAWAY surface" {
    var client = testClient();
    var out: [outbound_request_bytes_max]u8 = undefined;
    _ = try client.startRequest(&out, .{
        .method = "GET",
        .scheme = "http",
        .authority = "o",
        .path = "/",
    });
    var fields: [header_fields_max]hpack.HeaderField = undefined;

    var wire: [64]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&wire);
    try frame.writeFrame(&writer, .push_promise, .none, 1, "x");
    try testing.expectError(error.ProtocolError, client.feed(wire[0..writer.end], &fields));

    var reset: [16]u8 = undefined;
    var reset_writer: std.Io.Writer = .fixed(&reset);
    var code: [4]u8 = undefined;
    std.mem.writeInt(u32, &code, @backingInt(ErrorCode.refused_stream), .big);
    try frame.writeFrame(&reset_writer, .rst_stream, .none, 1, &code);
    switch (try client.feed(reset[0..reset_writer.end], &fields)) {
        .rst_stream => |r| try testing.expectEqual(@as(u32, @backingInt(ErrorCode.refused_stream)), r.error_code),
        else => return error.TestUnexpectedResult,
    }

    var goaway: [32]u8 = undefined;
    var goaway_writer: std.Io.Writer = .fixed(&goaway);
    var last: [4]u8 = undefined;
    std.mem.writeInt(u32, &last, 1, .big);
    const goaway_payload = last ++ code;
    try frame.writeFrame(&goaway_writer, .goaway, .none, 0, &goaway_payload);
    switch (try client.feed(goaway[0..goaway_writer.end], &fields)) {
        .goaway => |g| {
            try testing.expectEqual(@as(u31, 1), g.last_stream_id);
            try testing.expectEqual(@as(u32, @backingInt(ErrorCode.refused_stream)), g.error_code);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "h2 client: a connection carries a second stream without a second preface" {
    var client = testClient();
    var out: [outbound_request_bytes_max]u8 = undefined;
    _ = try client.startRequest(&out, .{
        .method = "GET",
        .scheme = "http",
        .authority = "o",
        .path = "/one",
    });

    var wire: [4096]u8 = undefined;
    var used: usize = 0;
    try encodeServerHeaders(&wire, &used, 1, true, &.{
        .{ .name = ":status", .value = "204" },
    });
    var fields: [header_fields_max]hpack.HeaderField = undefined;
    switch (try client.feed(wire[0..used], &fields)) {
        .headers => |h| try testing.expect(h.end_stream),
        else => return error.TestUnexpectedResult,
    }
    try testing.expect(!client.active);

    const len = try client.startRequest(&out, .{
        .method = "GET",
        .scheme = "http",
        .authority = "o",
        .path = "/two",
    });
    // The preface is not repeated; the first byte is the next HEADERS.
    var offset: usize = 0;
    const request = nextFrame(out[0..len], &offset);
    try testing.expectEqual(frame.FrameType.headers, request.header.frame_type);
    try testing.expectEqual(@as(u31, 3), request.header.stream_id);
    try testing.expectEqual(@as(usize, len), offset);
}
