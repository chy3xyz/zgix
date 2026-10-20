const H2Client = @This();
const std = @import("std");
const mem = std.mem;
const Io = std.Io;

const Request = @import("../Request.zig");
const Response = @import("../Response.zig");
const Headers = @import("../Headers.zig");

const h2 = @import("../h2/root.zig");
const frame = h2.frame;
const hpack = h2.hpack;
const Flags = frame.Flags;
const Settings = h2.Settings;
const FlowControl = h2.FlowControl;
const StreamRegistry = h2.StreamRegistry;
const ConnectionIO = h2.ConnectionIO;
const ErrorCode = h2.ErrorCode;

const Client = @import("Client.zig");

/// HTTP/2 client state for a single connection.
/// Created after TLS negotiation selects "h2" via ALPN,
/// or for cleartext h2c with prior knowledge.
reader: *Io.Reader,
writer: *Io.Writer,

settings_sync: Settings.Sync = .{},
registry: StreamRegistry = .{ .is_server = false },
flow: FlowControl.FlowController = .{},
frame_reader: ConnectionIO.FrameReader = .{},
frame_writer: ConnectionIO.FrameWriter = .{},

// HPACK state
hpack_enc_buf: [4096]u8 = undefined,
hpack_enc_entries: [128]hpack.DynamicTable.Entry = undefined,
encoder: hpack.Encoder = undefined,
hpack_dec_buf: [4096]u8 = undefined,
hpack_dec_entries: [128]hpack.DynamicTable.Entry = undefined,
decoder: hpack.Decoder = undefined,

initialized: bool = false,

pub fn init(reader: *Io.Reader, writer: *Io.Writer) H2Client {
    var self: H2Client = .{
        .reader = reader,
        .writer = writer,
    };
    self.encoder = hpack.Encoder.init(&self.hpack_enc_buf, &self.hpack_enc_entries);
    self.decoder = hpack.Decoder.init(&self.hpack_dec_buf, &self.hpack_dec_entries);
    return self;
}

/// Perform the HTTP/2 connection preface exchange (RFC 9113 §3.4).
/// Must be called once after connection establishment.
pub fn handshake(self: *H2Client) !void {
    // Send client connection preface
    try self.writer.writeAll(frame.connection_preface);

    // Send our SETTINGS
    self.settings_sync.local.enable_push = false; // clients typically disable push
    const settings_list = [_]frame.Setting{
        .{ .id = .enable_push, .value = 0 },
        .{ .id = .max_concurrent_streams, .value = 100 },
    };
    try frame.writeSettings(self.writer, &settings_list);
    try self.writer.flush();

    self.settings_sync.markSent(@intCast(self.encoder.dynamic_table.max_size));

    // Read server's SETTINGS (must be first frame)
    const server_settings = try self.frame_reader.readFrame(self.reader);
    switch (server_settings) {
        .settings => |s| {
            if (s.ack) return error.ProtocolError;
            const result = try self.settings_sync.applyPeerSettings(s.payload);
            self.decoder.dynamic_table.setMaxSize(result.new_decoder_table_size);
            self.frame_writer.max_frame_size = @intCast(self.settings_sync.peer.max_frame_size);
        },
        else => return error.ProtocolError,
    }

    // ACK server's SETTINGS
    try frame.writeSettingsAck(self.writer);
    try self.writer.flush();

    // Read server's ACK of our SETTINGS (may arrive later, but try to consume it now)
    // It might be interleaved with other frames, so we don't strictly require it here.

    self.initialized = true;
}

/// Send a request and receive the response.
pub fn request(
    self: *H2Client,
    allocator: std.mem.Allocator,
    method: Request.Method,
    host: []const u8,
    path: []const u8,
    scheme: []const u8,
    headers: ?Headers,
    body: ?[]const u8,
) !Response {
    if (!self.initialized) return error.ConnectionFailed;

    // Open a new stream
    const stream = try self.registry.open();
    const stream_id = stream.id;

    // Encode request headers via HPACK
    var header_buf: [8192]u8 = undefined;
    var hpos: usize = 0;

    // Pseudo-headers (must come first, RFC 9113 §8.3.1)
    hpos += try self.encoder.encodeHeader(header_buf[hpos..], ":method", method.toBytes());
    hpos += try self.encoder.encodeHeader(header_buf[hpos..], ":scheme", scheme);
    hpos += try self.encoder.encodeHeader(header_buf[hpos..], ":authority", host);
    hpos += try self.encoder.encodeHeader(header_buf[hpos..], ":path", path);

    // Regular headers
    if (headers) |h| {
        for (h.entries[0..h.len]) |entry| {
            // Skip prohibited headers
            if (Headers.eqlIgnoreCase(entry.name, "host")) continue;
            if (Headers.eqlIgnoreCase(entry.name, "connection")) continue;
            if (Headers.eqlIgnoreCase(entry.name, "keep-alive")) continue;
            if (Headers.eqlIgnoreCase(entry.name, "transfer-encoding")) continue;
            if (Headers.eqlIgnoreCase(entry.name, "upgrade")) continue;
            if (hpos + entry.name.len + entry.value.len + 10 > header_buf.len) break;
            hpos += try self.encoder.encodeHeader(header_buf[hpos..], entry.name, entry.value);
        }
    }

    // Send HEADERS (+ optional DATA)
    const has_body = body != null and body.?.len > 0;
    try self.frame_writer.writeHeaders(self.writer, stream_id, header_buf[0..hpos], !has_body);

    if (has_body) {
        try self.frame_writer.writeData(self.writer, stream_id, body.?, true);
    }
    try self.writer.flush();

    // Update stream state
    stream.send(.headers, .{ .value = Flags.end_headers | if (!has_body) Flags.end_stream else 0 }) catch {};
    if (has_body) {
        stream.send(.data, .{ .value = Flags.end_stream }) catch {};
    }

    // Read response frames
    var response: Response = .{};
    var response_headers_received = false;
    var body_parts: [64][]const u8 = undefined;
    var body_part_count: usize = 0;
    var total_body_len: usize = 0;

    while (true) {
        const incoming = self.frame_reader.readFrame(self.reader) catch |err| switch (err) {
            error.EndOfStream => break,
            else => return error.InvalidResponse,
        };

        switch (incoming) {
            .header_block => |hb| {
                if (hb.stream_id != stream_id) continue;

                var decoded_headers: [hpack.max_decoded_headers]hpack.HeaderField = undefined;
                const count = self.decoder.decode(hb.data, &decoded_headers) catch
                    return error.InvalidResponse;

                // Check for informational response (1xx)
                var status_value: ?[]const u8 = null;
                for (decoded_headers[0..count]) |h| {
                    if (mem.eql(u8, h.name, ":status")) {
                        status_value = h.value;
                    }
                }

                if (status_value) |sv| {
                    const status_code = std.fmt.parseInt(u16, sv, 10) catch
                        return error.InvalidStatusCode;

                    if (status_code >= 100 and status_code < 200) {
                        // Informational response — skip and read next
                        continue;
                    }

                    response.status = Client.intToStatusCode(status_code) orelse
                        return error.InvalidStatusCode;
                }

                // Copy regular headers
                for (decoded_headers[0..count]) |h| {
                    if (h.name.len > 0 and h.name[0] == ':') continue;
                    response.headers.append(h.name, h.value) catch break;
                }

                response_headers_received = true;
                if (hb.end_stream) break;
            },

            .data => |d| {
                if (d.stream_id != stream_id) continue;

                // Flow control: send WINDOW_UPDATE
                if (d.payload.len > 0) {
                    const should_update = self.flow.recordRecv(@intCast(d.payload.len)) catch break;
                    if (should_update) {
                        const inc = self.flow.pendingWindowUpdate() catch break;
                        if (inc > 0) {
                            frame.writeWindowUpdate(self.writer, 0, inc) catch break;
                            frame.writeWindowUpdate(self.writer, stream_id, inc) catch break;
                            self.writer.flush() catch break;
                        }
                    }
                }

                if (d.payload.len > 0 and body_part_count < body_parts.len) {
                    body_parts[body_part_count] = d.payload;
                    body_part_count += 1;
                    total_body_len += d.payload.len;
                }

                if (d.end_stream) break;
            },

            .settings => |s| {
                if (s.ack) {
                    if (self.settings_sync.receiveAck()) |new_size| {
                        self.encoder.setMaxTableSize(new_size);
                    }
                } else {
                    const result = self.settings_sync.applyPeerSettings(s.payload) catch continue;
                    self.decoder.dynamic_table.setMaxSize(result.new_decoder_table_size);
                    self.frame_writer.max_frame_size = @intCast(self.settings_sync.peer.max_frame_size);
                    frame.writeSettingsAck(self.writer) catch {};
                    self.writer.flush() catch {};
                }
            },

            .ping => |p| {
                if (!p.ack) {
                    frame.writePing(self.writer, p.payload[0..8], true) catch {};
                    self.writer.flush() catch {};
                }
            },

            .window_update => |wu| {
                if (wu.payload.len == 4) {
                    const increment = frame.parseWindowUpdate(wu.payload) catch continue;
                    if (wu.stream_id == 0) {
                        self.flow.recvWindowUpdate(increment) catch {};
                    }
                }
            },

            .goaway => break,

            .rst_stream => |rs| {
                if (rs.stream_id == stream_id) {
                    return error.InvalidResponse;
                }
            },

            else => {},
        }
    }

    if (!response_headers_received) return error.InvalidResponse;

    // Assemble body from parts
    if (total_body_len > 0) {
        const body_assembled = allocator.alloc(u8, total_body_len) catch
            return error.ResponseTooLarge;
        var offset: usize = 0;
        for (body_parts[0..body_part_count]) |part| {
            @memcpy(body_assembled[offset..][0..part.len], part);
            offset += part.len;
        }
        response.body = body_assembled;
        response._body_allocated = body_assembled;
    }

    return response;
}

/// Send GOAWAY and close.
pub fn close(self: *H2Client) void {
    frame.writeGoaway(self.writer, self.registry.last_local_stream_id, .no_error, &.{}) catch {};
    self.writer.flush() catch {};
    self.initialized = false;
}
