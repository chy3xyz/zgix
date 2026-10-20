//! Allocation-free HTTP/3 request-stream parser and response serializer.
//!
//! One QUIC bidirectional stream carries one request: a HEADERS frame, zero
//! or more DATA frames, and optionally a trailing HEADERS frame. This module
//! parses that shape without an allocator and without importing the QUIC
//! transport, so the stream→exchange mapping stays independent of zquic.
//!
//! **Storage ownership.** A `RequestStream` owns the fixed buffers it is
//! declared with: the request header block, the trailer block and the two
//! decoded `Header` arrays. The `Request` carried by the `headers` event
//! borrows those buffers, and also borrows any slices the injected `Codec`
//! hands back from `decode` (typically pointers into the block bytes this
//! module stores). The request is therefore valid until the stream is
//! dropped; the stream never reuses its buffers. Body bytes are never
//! buffered: each `feed` hands them back as `body` events borrowing the
//! caller's own input slice.
//!
//! **Limits.** Both header blocks have named limits; exceeding one is a
//! named error, not a malformed event, because the caller's answer is
//! policy (431 and stream reset) rather than "the peer is lying". The body
//! has no size limit at this layer: it streams through as events and is
//! bounded by QUIC flow control instead of a fixed buffer.
//! Header-rules violations are reported as `Event.malformed`, which the
//! caller answers by resetting the stream.
//!
//! **Varint minimality.** RFC 9000 §16 says a sender MUST use the minimal
//! encoding and a receiver MAY reject non-minimal forms. This parser accepts
//! them: the decoded value is unambiguous, and a peer's sloppy encoder is not
//! worth killing an otherwise well-formed exchange over. `readVarint` still
//! reports the encoded length so the caller can judge for itself.
//!
//! **Message completion.** Frames carry no FIN bit in HTTP/3; the QUIC
//! stream's FIN is the transport's signal. `feed` reports `headers` as soon
//! as the first HEADERS block validates, then `body` events for DATA frame
//! payload, and `complete` once a trailing HEADERS block (trailers, parsed
//! and dropped) finishes the message. For a request without trailers the
//! caller reports FIN through `finish`, which answers `complete`.
//!
//! `writeData` takes `fin` for call-site clarity, but HTTP/3 frames have no
//! FIN bit: the parameter is not serialized. Ending the QUIC stream after
//! the write is the caller's job.

const std = @import("std");

const assert = std.debug.assert;

/// Largest encoded header block, per HEADERS frame. The initial block and
/// the trailer block each get their own buffer of this size.
pub const header_block_bytes_max: usize = 16 * 1024;

/// Largest number of decoded headers in one block (pseudo-headers included
/// on the way in; `Request.headers` exposes the regular ones).
pub const headers_max: usize = 128;

pub const frame_type_data: u64 = 0x0;
pub const frame_type_headers: u64 = 0x1;

/// Every failure this module or an injected codec can report. A codec that
/// has its own decoding errors maps them onto `CodecFailure`.
pub const Error = error{
    /// More bytes are needed to finish the varint or frame.
    Truncated,
    /// A value did not fit the 62 bits RFC 9000 §16 allows.
    VarintOverflow,
    HeaderBlockTooLarge,
    TooManyHeaders,
    /// The caller's output buffer cannot hold the encoded frame.
    OutputTooSmall,
    /// The stream already completed or failed; a stream is single-use.
    StreamClosed,
    DataBeforeHeaders,
    DataAfterTrailers,
    HeadersAfterTrailers,
    InvalidStatus,
    /// An injected codec rejected the bytes. The codec owns the detail.
    CodecFailure,
    /// The codec needs dynamic-table entries it does not have yet (QPACK
    /// blocked section, RFC 9204 §4.4). Not a stream failure: the caller
    /// parks the section and re-feeds via `retryParked` once the peer's
    /// encoder stream delivers the missing inserts.
    Blocked,
};

pub const Header = struct { name: []const u8, value: []const u8 };

/// Decoded header block codec (QPACK in production, a test parser here).
///
/// `decode` writes at most `out.len` headers and returns how many it wrote;
/// the slices it stores must stay valid for the lifetime of the `Request`
/// built from them. `encode` writes one complete header block to `out` and
/// returns the used prefix.
pub const Codec = struct {
    ctx: *anyopaque,
    decode: *const fn (ctx: *anyopaque, block: []const u8, out: []Header) Error!usize,
    encode: *const fn (ctx: *anyopaque, headers: []const Header, out: []u8) Error![]const u8,
};

pub const Varint = struct { value: u64, len: u8 };

/// Length of the minimal varint encoding of `value`, or 0 when `value` is
/// outside the 62-bit range RFC 9000 §16 permits.
pub fn varintLen(value: u64) u8 {
    if (value < (1 << 6)) return 1;
    if (value < (1 << 14)) return 2;
    if (value < (1 << 30)) return 4;
    if (value < (1 << 62)) return 8;
    return 0;
}

pub fn writeVarint(out: []u8, value: u64) Error!usize {
    const len: usize = varintLen(value);
    if (len == 0) return error.VarintOverflow;
    assert(len == 1 or len == 2 or len == 4 or len == 8);
    if (out.len < len) return error.OutputTooSmall;

    switch (len) {
        1 => {
            out[0] = @intCast(value);
        },
        2 => {
            out[0] = 0x40 | @as(u8, @intCast(value >> 8));
            out[1] = @intCast(value & 0xff);
        },
        4 => {
            out[0] = 0x80 | @as(u8, @intCast(value >> 24));
            out[1] = @intCast((value >> 16) & 0xff);
            out[2] = @intCast((value >> 8) & 0xff);
            out[3] = @intCast(value & 0xff);
        },
        8 => {
            out[0] = 0xc0 | @as(u8, @intCast(value >> 56));
            out[1] = @intCast((value >> 48) & 0xff);
            out[2] = @intCast((value >> 40) & 0xff);
            out[3] = @intCast((value >> 32) & 0xff);
            out[4] = @intCast((value >> 24) & 0xff);
            out[5] = @intCast((value >> 16) & 0xff);
            out[6] = @intCast((value >> 8) & 0xff);
            out[7] = @intCast(value & 0xff);
        },
        else => unreachable,
    }
    return len;
}

pub fn readVarint(bytes: []const u8) Error!Varint {
    if (bytes.len == 0) return error.Truncated;
    const len: u8 = switch (bytes[0] >> 6) {
        0 => 1,
        1 => 2,
        2 => 4,
        3 => 8,
        else => unreachable,
    };
    if (bytes.len < len) return error.Truncated;
    assert(len <= 8);

    var value: u64 = bytes[0] & 0x3f;
    for (bytes[1..len]) |byte| {
        value = (value << 8) | byte;
    }
    return .{ .value = value, .len = len };
}

/// The decoded form of one request's head. All slices borrow the stream's
/// storage (and the codec's), so the value is valid only while the stream
/// is. `body` is always empty: body bytes are delivered incrementally as
/// `Event.body` chunks. `trailers` is always empty: a trailing HEADERS
/// block is parsed and validated, then dropped.
pub const Request = struct {
    stream_id: u64,
    method: []const u8,
    scheme: []const u8,
    authority: ?[]const u8,
    path: []const u8,
    /// Regular headers only; pseudo-headers are lifted into the fields above.
    headers: []Header,
    /// Always empty; trailers are validated and dropped, never retained.
    trailers: []Header,
    /// Always empty; body bytes travel only as `Event.body` chunks.
    body: []const u8,
    /// True when the transport FIN rode in with the HEADERS frame itself:
    /// the request owns no body and none can arrive. The session sets
    /// this; the parser leaves it false. `onBodyChunk` still delivers the
    /// completing `(empty, fin)` marker either way — the flag only lets
    /// the handler commit to a bodyless shape up front.
    fin_on_headers: bool = false,
};

/// One parsing step's outcome. `feed` answers at most one event per call
/// and reports how many input bytes it consumed; the caller keeps feeding
/// the remainder until `need_more`, so events arrive strictly in wire order.
pub const Event = union(enum) {
    /// The bytes so far stop at a frame or varint boundary; nothing new to
    /// report. The caller must supply more bytes, or report FIN.
    need_more,
    /// The first HEADERS block decoded and validated. `body` and `trailers`
    /// on the request are empty; DATA payload follows as `body` events.
    headers: Request,
    /// Payload bytes of the DATA frame currently being consumed, exactly as
    /// they arrived in this `feed` call's input (a frame split across calls
    /// yields one event per call). Borrows the caller's input slice.
    body: []const u8,
    /// The message is complete: a trailing HEADERS block finished inside
    /// `feed`, or `finish` saw the QUIC stream's FIN. No events follow.
    complete,
    /// The peer violated HTTP/3 request-stream rules; reset the stream.
    malformed,
};

/// `feed`'s return: how many bytes of the offered input were consumed, and
/// the event their processing produced. `consumed` is always `<=` the
/// offered length; a caller offering the remainder of a buffer makes
/// progress on every iteration, since only `need_more` can report a
/// consumed count of zero.
pub const Fed = struct {
    consumed: usize,
    event: Event,
};

/// Parse one request stream. Single-use: the caller places it (stack or
/// static pooled slot), feeds it, and drops it after completion or failure.
pub const RequestStream = struct {
    codec: *Codec,
    stream_id: u64,

    phase: Phase = .initial,
    state: State = .frame_header,
    failed: bool = false,
    /// Set when a HEADERS frame's decode answered `error.Blocked`: the
    /// block bytes stay buffered in `header_block`/`trailer_block` and the
    /// parser stops at the frame boundary until the caller retries via
    /// `retryParked`. Feeding more bytes while parked is refused.
    parked: bool = false,

    /// Up to a full frame header (two 8-byte varints) held across feeds.
    frame_header_bytes: [16]u8 = undefined,
    frame_header_len: u8 = 0,
    frame_type: u64 = 0,
    frame_bytes_left: u64 = 0,
    header_target: HeaderTarget = .headers,

    header_block: [header_block_bytes_max]u8 = undefined,
    header_block_len: usize = 0,
    trailer_block: [header_block_bytes_max]u8 = undefined,
    trailer_block_len: usize = 0,

    headers: [headers_max]Header = undefined,
    header_count: usize = 0,
    /// Decode scratch for the trailer block; validated by `validateTrailers`
    /// and then dropped — trailer fields are never retained.
    trailer_headers: [headers_max]Header = undefined,

    method: ?[]const u8 = null,
    scheme: ?[]const u8 = null,
    authority: ?[]const u8 = null,
    path: ?[]const u8 = null,

    const Phase = enum { initial, data, trailers, complete };
    const State = enum { frame_header, frame_payload };
    const HeaderTarget = enum { headers, trailers };

    const ParsedFrameHeader = struct {
        frame_type: u64,
        frame_len: u64,
    };

    const FrameResult = enum { ready, headers, complete, malformed };

    /// Construct in place. The caller supplies the storage by owning the
    /// returned value; no allocation happens here or later.
    pub fn initInPlace(codec: *Codec, stream_id: u64) RequestStream {
        return .{ .codec = codec, .stream_id = stream_id };
    }

    /// Consume transport bytes. The same bytes are never fed twice; whatever
    /// is left of a frame is remembered across calls. Each call answers one
    /// event; when that event is not `need_more`, the caller handles it and
    /// re-feeds the unconsumed remainder (`Fed.consumed` says where it
    /// starts) to collect the next one.
    pub fn feed(self: *RequestStream, bytes: []const u8) Error!Fed {
        if (self.failed) return error.StreamClosed;
        if (self.phase == .complete) return error.StreamClosed;
        if (self.parked) return error.Blocked;

        var input = bytes;
        var passes: u64 = 0;
        while (true) : (passes += 1) {
            assert(passes <= @as(u64, @intCast(bytes.len)) + 2);
            switch (self.state) {
                .frame_header => {
                    const parsed = (try self.takeFrameHeader(&input)) orelse
                        return .{ .consumed = bytes.len - input.len, .event = .need_more };
                    try self.beginFrame(parsed.frame_type, parsed.frame_len);
                    if (self.frame_bytes_left != 0) continue;
                    const result = try self.finishFrame();
                    if (self.feedEvent(result, bytes.len - input.len)) |fed| return fed;
                },
                .frame_payload => {
                    if (self.takePayload(&input)) |chunk| {
                        return .{ .consumed = bytes.len - input.len, .event = .{ .body = chunk } };
                    }
                    if (self.frame_bytes_left > 0)
                        return .{ .consumed = bytes.len - input.len, .event = .need_more };
                    const result = try self.finishFrame();
                    if (self.feedEvent(result, bytes.len - input.len)) |fed| return fed;
                },
            }
            if (input.len == 0)
                return .{ .consumed = bytes.len, .event = .need_more };
        }
    }

    /// Map a finished frame onto the event to answer, or null when the
    /// frame produced none and the loop should continue with the rest of
    /// the input.
    fn feedEvent(self: *RequestStream, result: FrameResult, consumed: usize) ?Fed {
        switch (result) {
            .ready => return null,
            .malformed => {
                self.failed = true;
                return .{ .consumed = consumed, .event = .malformed };
            },
            .headers => return .{ .consumed = consumed, .event = .{ .headers = self.headersRequest() } },
            .complete => {
                self.phase = .complete;
                return .{ .consumed = consumed, .event = .complete };
            },
        }
    }

    /// Report the QUIC stream's FIN. A request without trailers completes
    /// here; a stream that stopped mid-frame is `Truncated`. A parked
    /// stream refuses: the caller retries the decode first, and FIN is
    /// re-offered once the section resolves.
    pub fn finish(self: *RequestStream) Error!Event {
        if (self.failed) return error.StreamClosed;
        if (self.phase == .complete) return error.StreamClosed;
        if (self.parked) return error.Blocked;
        if (self.phase == .initial) {
            self.failed = true;
            return .malformed;
        }
        if (self.state == .frame_payload) {
            // A DATA (or skipped unknown) frame whose final byte arrived in
            // an earlier feed reports its chunk without closing the frame;
            // FIN is the moment to close it out. A still-open frame is a
            // truncated message either way.
            if (self.frame_bytes_left != 0) return error.Truncated;
            const result = try self.finishFrame();
            switch (result) {
                .ready => {},
                .malformed => {
                    self.failed = true;
                    return .malformed;
                },
                // Header frames close inside `feed`; only DATA or skipped
                // frames can still be open here.
                .headers, .complete => unreachable,
            }
        }
        if (self.frame_header_len != 0) return error.Truncated;
        self.phase = .complete;
        return .complete;
    }

    /// Assemble one frame header from buffered plus new bytes, advancing
    /// `input` past every byte copied into the staging buffer. Returns null
    /// only when the input ran out before both varints were complete.
    fn takeFrameHeader(self: *RequestStream, input: *[]const u8) Error!?ParsedFrameHeader {
        var passes: u32 = 0;
        while (true) : (passes += 1) {
            assert(passes <= 18);
            const buffered = self.frame_header_bytes[0..self.frame_header_len];
            if (try readVarintIfComplete(buffered)) |type_varint| {
                assert(type_varint.len <= buffered.len);
                const length_bytes = buffered[type_varint.len..];
                if (try readVarintIfComplete(length_bytes)) |length_varint| {
                    const header_len: usize = @as(usize, type_varint.len) + length_varint.len;
                    assert(header_len == buffered.len);
                    self.frame_header_len = 0;
                    return .{
                        .frame_type = type_varint.value,
                        .frame_len = length_varint.value,
                    };
                }
            }
            if (input.len == 0) return null;
            assert(self.frame_header_len < self.frame_header_bytes.len);
            self.frame_header_bytes[self.frame_header_len] = input.*[0];
            self.frame_header_len += 1;
            input.* = input.*[1..];
        }
    }

    fn beginFrame(self: *RequestStream, frame_type: u64, frame_len: u64) Error!void {
        switch (frame_type) {
            frame_type_data => {
                if (self.phase == .initial) return error.DataBeforeHeaders;
                if (self.phase == .trailers) return error.DataAfterTrailers;
                assert(self.phase == .data);
                // No size check: body bytes stream through to the caller as
                // events, bounded by QUIC flow control instead of a buffer.
            },
            frame_type_headers => {
                if (self.phase == .trailers) return error.HeadersAfterTrailers;
                if (self.phase == .initial) {
                    self.header_target = .headers;
                    if (frame_len > @as(u64, @intCast(header_block_bytes_max - self.header_block_len))) {
                        return error.HeaderBlockTooLarge;
                    }
                } else {
                    assert(self.phase == .data);
                    // RFC 9114 allows zero DATA frames before trailers, so a
                    // second HEADERS section is trailers either way.
                    self.header_target = .trailers;
                    if (frame_len > @as(u64, @intCast(header_block_bytes_max - self.trailer_block_len))) {
                        return error.HeaderBlockTooLarge;
                    }
                }
            },
            else => {},
        }
        self.frame_type = frame_type;
        self.frame_bytes_left = frame_len;
        self.state = .frame_payload;
    }

    /// Consume payload bytes of the frame in progress. DATA bytes are handed
    /// back as a chunk borrowing this call's input; header-block bytes are
    /// copied into the matching block buffer; unknown frame types are
    /// skipped. Returns null when no DATA bytes were taken.
    fn takePayload(self: *RequestStream, input: *[]const u8) ?[]const u8 {
        const available: u64 = @intCast(input.len);
        const take: u64 = @min(available, self.frame_bytes_left);
        const count: usize = @intCast(take);
        const chunk = input.*[0..count];

        var data_chunk: ?[]const u8 = null;
        switch (self.frame_type) {
            frame_type_data => {
                if (count > 0) data_chunk = chunk;
            },
            frame_type_headers => switch (self.header_target) {
                .headers => {
                    assert(self.header_block_len + count <= header_block_bytes_max);
                    @memcpy(self.header_block[self.header_block_len..][0..count], chunk);
                    self.header_block_len += count;
                },
                .trailers => {
                    assert(self.trailer_block_len + count <= header_block_bytes_max);
                    @memcpy(self.trailer_block[self.trailer_block_len..][0..count], chunk);
                    self.trailer_block_len += count;
                },
            },
            else => {},
        }

        self.frame_bytes_left -= take;
        input.* = input.*[count..];
        return data_chunk;
    }

    fn finishFrame(self: *RequestStream) Error!FrameResult {
        assert(self.frame_bytes_left == 0);
        var decoded_headers = false;
        if (self.frame_type == frame_type_headers) {
            const valid = try self.decodeBlock();
            if (!valid) return .malformed;
            decoded_headers = self.header_target == .headers;
        }
        self.state = .frame_header;
        if (self.phase == .trailers) {
            self.phase = .complete;
            return .complete;
        }
        if (decoded_headers) return .headers;
        return .ready;
    }

    fn decodeBlock(self: *RequestStream) Error!bool {
        const is_trailer = self.header_target == .trailers;
        const block: []const u8 = if (is_trailer)
            self.trailer_block[0..self.trailer_block_len]
        else
            self.header_block[0..self.header_block_len];
        const out: []Header = if (is_trailer)
            self.trailer_headers[0..]
        else
            self.headers[0..];

        const count = self.codec.decode(self.codec.ctx, block, out) catch |err| switch (err) {
            // The block stays buffered for `retryParked`; nothing about
            // the stream's state advances.
            error.Blocked => {
                self.parked = true;
                return error.Blocked;
            },
            else => return err,
        };
        if (count > out.len) return error.TooManyHeaders;

        if (is_trailer) {
            if (!validateTrailers(out[0..count])) return false;
            self.phase = .trailers;
        } else {
            if (!self.validateHeaders(out[0..count])) return false;
            self.phase = .data;
        }
        return true;
    }

    /// Retry a field section that parked on `error.Blocked`, after the
    /// codec's dynamic table gained entries. The buffered block is decoded
    /// again; on success the parked flag clears and the answer is the
    /// event the original `feed` would have produced (`.headers`, or
    /// `.complete` for a trailing block). Returns null when the section is
    /// still blocked — the caller's retry loop stops at the first
    /// still-blocked head, in arrival order.
    pub fn retryParked(self: *RequestStream) Error!?Fed {
        assert(self.parked);
        // Parking happens only when a HEADERS frame's payload finished
        // (decode is the last step), so the frame is complete in every
        // respect except its decoded fields.
        assert(self.frame_bytes_left == 0);
        const result = self.finishFrame() catch |err| switch (err) {
            error.Blocked => return null,
            else => return err,
        };
        self.parked = false;
        // A HEADERS frame never finishes `.ready`; `feedEvent` covers the
        // remaining results (and latches `failed` on `.malformed`).
        return self.feedEvent(result, 0) orelse unreachable;
    }

    /// Apply RFC 9114 §4.3's request pseudo-header rules and compact the
    /// regular headers to the front of `headers`.
    fn validateHeaders(self: *RequestStream, headers: []Header) bool {
        var write: usize = 0;
        var regular_seen = false;

        for (headers) |header| {
            if (header.name.len == 0) return false;
            if (header.name[0] == ':') {
                if (regular_seen) return false;
                if (std.mem.eql(u8, header.name, ":method")) {
                    if (self.method != null) return false;
                    self.method = header.value;
                } else if (std.mem.eql(u8, header.name, ":scheme")) {
                    if (self.scheme != null) return false;
                    self.scheme = header.value;
                } else if (std.mem.eql(u8, header.name, ":authority")) {
                    if (self.authority != null) return false;
                    self.authority = header.value;
                } else if (std.mem.eql(u8, header.name, ":path")) {
                    if (self.path != null) return false;
                    self.path = header.value;
                } else {
                    return false;
                }
            } else {
                regular_seen = true;
                headers[write] = header;
                write += 1;
            }
        }

        const method = self.method orelse return false;
        const scheme = self.scheme orelse return false;
        const path = self.path orelse return false;
        if (method.len == 0) return false;
        if (scheme.len == 0) return false;
        if (path.len == 0) return false;
        if (path[0] != '/') return false;

        self.header_count = write;
        return true;
    }

    /// Build the head-only request for the `headers` event. `body` and
    /// `trailers` are empty by construction: body bytes arrive as `body`
    /// events, trailer fields are validated and dropped.
    fn headersRequest(self: *RequestStream) Request {
        assert(self.phase == .data);
        assert(self.method != null);
        assert(self.scheme != null);
        assert(self.path != null);
        return .{
            .stream_id = self.stream_id,
            .method = self.method.?,
            .scheme = self.scheme.?,
            .authority = self.authority,
            .path = self.path.?,
            .headers = self.headers[0..self.header_count],
            .trailers = &.{},
            .body = "",
        };
    }
};

fn validateTrailers(headers: []const Header) bool {
    for (headers) |header| {
        if (header.name.len == 0) return false;
        if (header.name[0] == ':') return false;
    }
    return true;
}

/// `null` means "not enough bytes yet"; every other failure propagates.
fn readVarintIfComplete(bytes: []const u8) Error!?Varint {
    return readVarint(bytes) catch |err| switch (err) {
        error.Truncated => null,
        else => |other| return other,
    };
}

/// Serialize a response HEADERS frame. `codec` encodes `:status` plus
/// `headers`; the frame header is prepended here.
pub fn writeHead(codec: *Codec, status: u16, headers: []const Header, out: []u8) Error![]const u8 {
    return writeHeadFrame(codec, status, headers, out);
}

fn writeHeadFrame(codec: *Codec, status: u16, headers: []const Header, out: []u8) Error![]const u8 {
    if (status < 100) return error.InvalidStatus;
    if (status > 999) return error.InvalidStatus;
    if (headers.len > headers_max) return error.TooManyHeaders;
    assert(headers.len + 1 <= headers_max + 1);

    var status_text: [3]u8 = undefined;
    const status_value = formatStatus(status, &status_text);
    var all: [headers_max + 1]Header = undefined;
    all[0] = .{ .name = ":status", .value = status_value };
    for (headers, 0..) |header, index| {
        all[index + 1] = header;
    }

    var block: [header_block_bytes_max]u8 = undefined;
    const encoded = try codec.encode(codec.ctx, all[0 .. headers.len + 1], &block);
    if (encoded.len > block.len) return error.HeaderBlockTooLarge;
    return writeFrame(frame_type_headers, encoded, out);
}

/// Serialize one DATA frame. `fin` is not encoded: HTTP/3 DATA frames carry
/// no FIN bit, and the caller ends the QUIC stream after writing.
pub fn writeData(data: []const u8, fin: bool, out: []u8) Error![]const u8 {
    return writeDataFrame(data, fin, out);
}

fn writeDataFrame(data: []const u8, fin: bool, out: []u8) Error![]const u8 {
    _ = fin;
    return writeFrame(frame_type_data, data, out);
}

fn writeFrame(frame_type: u64, payload: []const u8, out: []u8) Error![]const u8 {
    const payload_len: u64 = @intCast(payload.len);
    const type_len = varintLen(frame_type);
    const length_len = varintLen(payload_len);
    if (type_len == 0) return error.VarintOverflow;
    if (length_len == 0) return error.VarintOverflow;

    const prefix_len: usize = @as(usize, type_len) + length_len;
    if (out.len < prefix_len) return error.OutputTooSmall;
    if (payload.len > out.len - prefix_len) return error.OutputTooSmall;

    _ = try writeVarint(out[0..type_len], frame_type);
    _ = try writeVarint(out[type_len..prefix_len], payload_len);
    @memcpy(out[prefix_len..][0..payload.len], payload);
    return out[0 .. prefix_len + payload.len];
}

fn formatStatus(status: u16, out: *[3]u8) []const u8 {
    assert(status >= 100);
    assert(status <= 999);
    out[0] = @intCast('0' + status / 100);
    out[1] = @intCast('0' + (status / 10) % 10);
    out[2] = @intCast('0' + status % 10);
    return out[0..3];
}

/// A response frame writer bound to a codec, so call sites do not repeat it.
pub const ResponseWriter = struct {
    codec: *Codec,

    pub fn init(codec: *Codec) ResponseWriter {
        return .{ .codec = codec };
    }

    pub fn writeHead(self: *const ResponseWriter, status: u16, headers: []const Header, out: []u8) Error![]const u8 {
        return writeHeadFrame(self.codec, status, headers, out);
    }

    pub fn writeData(self: *const ResponseWriter, data: []const u8, fin: bool, out: []u8) Error![]const u8 {
        _ = self;
        return writeDataFrame(data, fin, out);
    }
};

// ---------------------------------------------------------------------------
// Tests

const TestCodec = struct {
    fail: bool = false,
    decode_calls: usize = 0,
    encode_calls: usize = 0,

    fn codec(self: *TestCodec) Codec {
        return .{
            .ctx = self,
            .decode = decode,
            .encode = encode,
        };
    }

    fn decode(ctx: *anyopaque, block: []const u8, out: []Header) Error!usize {
        const self: *TestCodec = @ptrCast(@alignCast(ctx));
        self.decode_calls += 1;
        if (self.fail) return error.CodecFailure;

        var count: usize = 0;
        var rest = block;
        while (rest.len > 0) : (count += 1) {
            assert(count <= block.len);
            const newline = std.mem.indexOfScalar(u8, rest, '\n') orelse return error.CodecFailure;
            const line = rest[0..newline];
            const tab = std.mem.indexOfScalar(u8, line, '\t') orelse return error.CodecFailure;
            if (count == out.len) return error.TooManyHeaders;
            out[count] = .{ .name = line[0..tab], .value = line[tab + 1 ..] };
            rest = rest[newline + 1 ..];
        }
        return count;
    }

    fn encode(ctx: *anyopaque, headers: []const Header, out: []u8) Error![]const u8 {
        const self: *TestCodec = @ptrCast(@alignCast(ctx));
        self.encode_calls += 1;
        if (self.fail) return error.CodecFailure;

        var used: usize = 0;
        for (headers) |header| {
            const needed = header.name.len + 1 + header.value.len + 1;
            if (used + needed > out.len) return error.OutputTooSmall;
            @memcpy(out[used..][0..header.name.len], header.name);
            used += header.name.len;
            out[used] = '\t';
            used += 1;
            @memcpy(out[used..][0..header.value.len], header.value);
            used += header.value.len;
            out[used] = '\n';
            used += 1;
        }
        return out[0..used];
    }
};

/// Append `name\tvalue\n` to a test header block.
fn appendHeader(out: []u8, used: *usize, name: []const u8, value: []const u8) void {
    const needed = name.len + 1 + value.len + 1;
    assert(used.* + needed <= out.len);
    @memcpy(out[used.*..][0..name.len], name);
    used.* += name.len;
    out[used.*] = '\t';
    used.* += 1;
    @memcpy(out[used.*..][0..value.len], value);
    used.* += value.len;
    out[used.*] = '\n';
    used.* += 1;
}

fn appendFrame(out: []u8, used: *usize, frame_type: u64, payload: []const u8) void {
    const prefix = writeFrame(frame_type, payload, out[used.*..]) catch unreachable;
    used.* += prefix.len;
}

fn standardBlock() []const u8 {
    const block = struct {
        var buffer: [128]u8 = undefined;
        var len: usize = 0;
    };
    block.len = 0;
    appendHeader(&block.buffer, &block.len, ":method", "GET");
    appendHeader(&block.buffer, &block.len, ":scheme", "https");
    appendHeader(&block.buffer, &block.len, ":authority", "example.test");
    appendHeader(&block.buffer, &block.len, ":path", "/index.html");
    return block.buffer[0..block.len];
}

fn expectMalformed(event: Event) !void {
    switch (event) {
        .malformed => {},
        else => return error.ExpectedMalformed,
    }
}

/// Feed one byte at a time and return the first event that is not
/// `need_more` (or the last event seen when the whole buffer only moved
/// the parser forward).
fn feedAll(stream: *RequestStream, bytes: []const u8) !Event {
    var event: Event = .need_more;
    for (bytes) |byte| {
        const fed = try stream.feed(&.{byte});
        try std.testing.expectEqual(@as(usize, 1), fed.consumed);
        event = fed.event;
        switch (event) {
            .need_more => {},
            else => return event,
        }
    }
    return event;
}

/// Collects the event stream of one request while asserting the ordering
/// rules: one `headers`, then `body` chunks, then `complete`. `malformed`
/// is recorded rather than rejected so failure tests can assert it.
const Drain = struct {
    headers: ?Request = null,
    body: [512]u8 = undefined,
    body_len: usize = 0,
    chunk_count: usize = 0,
    completed: bool = false,
    malformed: bool = false,

    fn accept(self: *Drain, event: Event) !void {
        switch (event) {
            .need_more => {},
            .headers => |request| {
                if (self.headers != null) return error.DuplicateHeaders;
                if (self.completed) return error.HeadersAfterComplete;
                self.headers = request;
            },
            .body => |chunk| {
                if (self.headers == null) return error.BodyBeforeHeaders;
                if (self.completed) return error.BodyAfterComplete;
                if (chunk.len > self.body.len - self.body_len) return error.BodyOverflow;
                @memcpy(self.body[self.body_len..][0..chunk.len], chunk);
                self.body_len += chunk.len;
                self.chunk_count += 1;
            },
            .complete => {
                if (self.headers == null) return error.CompleteBeforeHeaders;
                if (self.completed) return error.DuplicateComplete;
                self.completed = true;
            },
            .malformed => {
                if (self.malformed) return error.DuplicateMalformed;
                self.malformed = true;
            },
        }
    }

    /// Feed a buffer to completion, handling every event it produces.
    fn feed(self: *Drain, stream: *RequestStream, bytes: []const u8) !void {
        var rest = bytes;
        while (rest.len > 0) {
            const fed = try stream.feed(rest);
            if (fed.consumed == 0 and fed.event == .need_more) return error.NoProgress;
            try self.accept(fed.event);
            rest = rest[fed.consumed..];
        }
    }
};

test "varint: minimal lengths at every boundary" {
    const cases = [_]struct { value: u64, len: u8 }{
        .{ .value = 0, .len = 1 },
        .{ .value = 63, .len = 1 },
        .{ .value = 64, .len = 2 },
        .{ .value = 16383, .len = 2 },
        .{ .value = 16384, .len = 4 },
        .{ .value = (1 << 30) - 1, .len = 4 },
        .{ .value = 1 << 30, .len = 8 },
        .{ .value = (1 << 62) - 1, .len = 8 },
    };
    for (cases) |case| {
        try std.testing.expectEqual(case.len, varintLen(case.value));
        var buffer: [8]u8 = undefined;
        const written = try writeVarint(&buffer, case.value);
        try std.testing.expectEqual(@as(usize, case.len), written);
        const decoded = try readVarint(buffer[0..written]);
        try std.testing.expectEqual(case.value, decoded.value);
        try std.testing.expectEqual(case.len, decoded.len);
    }
    try std.testing.expectEqual(@as(u8, 0), varintLen(1 << 62));
}

test "varint: RFC 9000 examples" {
    var buffer: [8]u8 = undefined;
    const examples = [_]struct { value: u64, bytes: []const u8 }{
        .{ .value = 37, .bytes = &.{0x25} },
        .{ .value = 15293, .bytes = &.{ 0x7b, 0xbd } },
        .{ .value = 494878333, .bytes = &.{ 0x9d, 0x7f, 0x3e, 0x7d } },
        .{ .value = 151288809941952652, .bytes = &.{ 0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c } },
    };
    for (examples) |example| {
        const written = try writeVarint(&buffer, example.value);
        try std.testing.expectEqualSlices(u8, example.bytes, buffer[0..written]);
        const decoded = try readVarint(example.bytes);
        try std.testing.expectEqual(example.value, decoded.value);
        try std.testing.expectEqual(@as(u8, @intCast(example.bytes.len)), decoded.len);
    }
}

test "varint: truncation, overflow, non-minimal acceptance" {
    try std.testing.expectError(error.Truncated, readVarint(&.{}));
    try std.testing.expectError(error.Truncated, readVarint(&.{0x40}));
    try std.testing.expectError(error.Truncated, readVarint(&.{ 0x80, 0x00, 0x00 }));
    try std.testing.expectError(error.Truncated, readVarint(&.{0xc0}));

    var small: [1]u8 = undefined;
    try std.testing.expectError(error.VarintOverflow, writeVarint(&small, 1 << 62));
    try std.testing.expectError(error.OutputTooSmall, writeVarint(&small, 64));

    // Non-minimal 2-byte encoding of 1 is accepted; the value is the same.
    const decoded = try readVarint(&.{ 0x40, 0x01 });
    try std.testing.expectEqual(@as(u64, 1), decoded.value);
    try std.testing.expectEqual(@as(u8, 2), decoded.len);
}

test "request: HEADERS split across every byte delivers the head at once" {
    var codec_state = TestCodec{};
    var codec = codec_state.codec();
    var stream = RequestStream.initInPlace(&codec, 1);

    var wire: [256]u8 = undefined;
    var used: usize = 0;
    appendFrame(&wire, &used, frame_type_headers, standardBlock());

    const event = try feedAll(&stream, wire[0..used]);
    const request = switch (event) {
        .headers => |head| head,
        else => return error.ExpectedHeaders,
    };
    try std.testing.expectEqual(@as(u64, 1), request.stream_id);
    try std.testing.expectEqualSlices(u8, "GET", request.method);
    try std.testing.expectEqualSlices(u8, "https", request.scheme);
    try std.testing.expectEqualSlices(u8, "example.test", request.authority.?);
    try std.testing.expectEqualSlices(u8, "/index.html", request.path);
    try std.testing.expectEqual(@as(usize, 0), request.headers.len);
    try std.testing.expectEqual(@as(usize, 0), request.trailers.len);
    try std.testing.expectEqual(@as(usize, 0), request.body.len);

    try std.testing.expect((try stream.finish()) == .complete);
    try std.testing.expectError(error.StreamClosed, stream.feed(&.{}));
}

test "request: DATA crossing feed boundaries arrives as ordered chunks" {
    var codec_state = TestCodec{};
    var codec = codec_state.codec();
    var stream = RequestStream.initInPlace(&codec, 3);

    var wire: [256]u8 = undefined;
    var used: usize = 0;
    appendFrame(&wire, &used, frame_type_headers, standardBlock());
    appendFrame(&wire, &used, frame_type_data, "hello, ");
    appendFrame(&wire, &used, frame_type_data, "world");

    var header_wire: [128]u8 = undefined;
    var header_used: usize = 0;
    appendFrame(&header_wire, &header_used, frame_type_headers, standardBlock());
    const head = try stream.feed(header_wire[0..header_used]);
    try std.testing.expect(head.event == .headers);
    try std.testing.expectEqual(header_used, head.consumed);

    // Each feed surfaces at most one chunk, spanning whatever the current
    // DATA frame contributes: the first feed carries frame one's whole
    // payload, the second finishes frame two. Nothing is buffered between
    // calls, and the final frame ends exactly at a feed boundary, so FIN
    // closes it.
    const expected = [_][]const u8{ "hello, ", "world" };
    var rest = wire[header_used..used];
    var index: usize = 0;
    while (rest.len > 0) {
        const fed = try stream.feed(rest);
        rest = rest[fed.consumed..];
        switch (fed.event) {
            .body => |chunk| {
                try std.testing.expect(index < expected.len);
                try std.testing.expectEqualSlices(u8, expected[index], chunk);
                index += 1;
            },
            .need_more => {},
            else => return error.ExpectedBody,
        }
    }
    try std.testing.expectEqual(expected.len, index);
    try std.testing.expect((try stream.finish()) == .complete);
}

test "request: unknown frame types are skipped" {
    var codec_state = TestCodec{};
    var codec = codec_state.codec();
    var stream = RequestStream.initInPlace(&codec, 5);

    var wire: [256]u8 = undefined;
    var used: usize = 0;
    appendFrame(&wire, &used, 0x21, "grease");
    appendFrame(&wire, &used, frame_type_headers, standardBlock());
    appendFrame(&wire, &used, 0x40, "ignored");
    appendFrame(&wire, &used, frame_type_data, "payload");

    var drain = Drain{};
    try drain.feed(&stream, wire[0..used]);
    const request = drain.headers orelse return error.ExpectedHeaders;
    try std.testing.expectEqual(@as(u64, 5), request.stream_id);
    try std.testing.expectEqualSlices(u8, "payload", drain.body[0..drain.body_len]);
    try drain.accept(try stream.finish());
    try std.testing.expect(drain.completed);
}

test "request: trailers complete the message and are dropped" {
    var codec_state = TestCodec{};
    var codec = codec_state.codec();
    var stream = RequestStream.initInPlace(&codec, 7);

    var trailer_block: [64]u8 = undefined;
    var trailer_len: usize = 0;
    appendHeader(&trailer_block, &trailer_len, "grpc-status", "0");

    var wire: [256]u8 = undefined;
    var used: usize = 0;
    appendFrame(&wire, &used, frame_type_headers, standardBlock());
    appendFrame(&wire, &used, frame_type_data, "body");
    appendFrame(&wire, &used, frame_type_headers, trailer_block[0..trailer_len]);

    var drain = Drain{};
    try drain.feed(&stream, wire[0..used]);
    const request = drain.headers orelse return error.ExpectedHeaders;
    try std.testing.expectEqualSlices(u8, "body", drain.body[0..drain.body_len]);
    try std.testing.expect(drain.completed);
    // The trailer block was decoded and validated (two decode calls), then
    // dropped: the request exposes no trailer fields.
    try std.testing.expectEqual(@as(usize, 2), codec_state.decode_calls);
    try std.testing.expectEqual(@as(usize, 0), request.trailers.len);
}

test "request: duplicate pseudo-header is malformed" {
    var block: [128]u8 = undefined;
    var used: usize = 0;
    appendHeader(&block, &used, ":method", "GET");
    appendHeader(&block, &used, ":method", "POST");
    appendHeader(&block, &used, ":scheme", "https");
    appendHeader(&block, &used, ":path", "/");
    try expectMalformed(try headerOnlyEvent(&used, &block));
}

fn headerOnlyEvent(used: *usize, block: *const [128]u8) !Event {
    var codec_state = TestCodec{};
    var codec = codec_state.codec();
    var stream = RequestStream.initInPlace(&codec, 9);
    var wire: [256]u8 = undefined;
    var wire_used: usize = 0;
    appendFrame(&wire, &wire_used, frame_type_headers, block[0..used.*]);
    return feedAll(&stream, wire[0..wire_used]);
}

test "request: pseudo-header after regular header is malformed" {
    var block: [128]u8 = undefined;
    var used: usize = 0;
    appendHeader(&block, &used, ":method", "GET");
    appendHeader(&block, &used, "accept", "*/*");
    appendHeader(&block, &used, ":scheme", "https");
    appendHeader(&block, &used, ":path", "/");
    try expectMalformed(try headerOnlyEvent(&used, &block));
}

test "request: missing :method is malformed" {
    var block: [128]u8 = undefined;
    var used: usize = 0;
    appendHeader(&block, &used, ":scheme", "https");
    appendHeader(&block, &used, ":path", "/");
    try expectMalformed(try headerOnlyEvent(&used, &block));
}

test "request: :path must start with a slash" {
    var block: [128]u8 = undefined;
    var used: usize = 0;
    appendHeader(&block, &used, ":method", "GET");
    appendHeader(&block, &used, ":scheme", "https");
    appendHeader(&block, &used, ":path", "index.html");
    try expectMalformed(try headerOnlyEvent(&used, &block));
}

test "request: trailer pseudo-header is malformed" {
    var codec_state = TestCodec{};
    var codec = codec_state.codec();
    var stream = RequestStream.initInPlace(&codec, 11);

    var trailer_block: [64]u8 = undefined;
    var trailer_len: usize = 0;
    appendHeader(&trailer_block, &trailer_len, ":status", "200");

    var wire: [256]u8 = undefined;
    var used: usize = 0;
    appendFrame(&wire, &used, frame_type_headers, standardBlock());
    appendFrame(&wire, &used, frame_type_data, "x");
    appendFrame(&wire, &used, frame_type_headers, trailer_block[0..trailer_len]);

    var drain = Drain{};
    try drain.feed(&stream, wire[0..used]);
    try std.testing.expect(drain.malformed);
}

test "request: header block over the limit is a named error" {
    var codec_state = TestCodec{};
    var codec = codec_state.codec();
    var stream = RequestStream.initInPlace(&codec, 13);

    var wire: [32]u8 = undefined;
    var used: usize = 0;
    appendFrame(&wire, &used, frame_type_headers, "");
    used = 0;
    wire[used] = 0x01;
    used += 1;
    const written = try writeVarint(wire[used..], header_block_bytes_max + 1);
    used += written;

    try std.testing.expectError(error.HeaderBlockTooLarge, stream.feed(wire[0..used]));
}

test "request: a body past the old 64 KiB cap streams through" {
    var codec_state = TestCodec{};
    var codec = codec_state.codec();
    var stream = RequestStream.initInPlace(&codec, 15);

    const body_len = 70 * 1024; // larger than the removed 64 KiB buffer cap
    var body: [body_len]u8 = undefined;
    for (&body, 0..) |*byte, index| byte.* = @truncate(index *% 31 + 7);

    var head_wire: [128]u8 = undefined;
    var head_used: usize = 0;
    appendFrame(&head_wire, &head_used, frame_type_headers, standardBlock());
    const head = try stream.feed(head_wire[0..head_used]);
    try std.testing.expect(head.event == .headers);

    var frame_wire: [16]u8 = undefined;
    var frame_used: usize = 0;
    frame_wire[frame_used] = 0x00;
    frame_used += 1;
    frame_used += try writeVarint(frame_wire[frame_used..], body_len);
    var fed = try stream.feed(frame_wire[0..frame_used]);
    try std.testing.expect(fed.event == .need_more);

    // Feed the payload in thirds: each slice surfaces as its own chunk,
    // with nothing buffered between calls.
    var collected: [body_len]u8 = undefined;
    var collected_len: usize = 0;
    var offset: usize = 0;
    while (offset < body.len) {
        const end = @min(offset + body.len / 3 + 1, body.len);
        fed = try stream.feed(body[offset..end]);
        offset = end;
        switch (fed.event) {
            .body => |chunk| {
                @memcpy(collected[collected_len..][0..chunk.len], chunk);
                collected_len += chunk.len;
            },
            .need_more => {},
            else => return error.ExpectedBody,
        }
    }
    try std.testing.expectEqual(body.len, collected_len);
    try std.testing.expectEqualSlices(u8, &body, &collected);
    try std.testing.expect((try stream.finish()) == .complete);
}

test "request: empty stream at FIN is malformed" {
    var codec_state = TestCodec{};
    var codec = codec_state.codec();
    var stream = RequestStream.initInPlace(&codec, 17);
    try expectMalformed(try stream.finish());
}

test "request: a codec error propagates" {
    var codec_state = TestCodec{ .fail = true };
    var codec = codec_state.codec();
    var stream = RequestStream.initInPlace(&codec, 19);

    var wire: [128]u8 = undefined;
    var used: usize = 0;
    appendFrame(&wire, &used, frame_type_headers, standardBlock());
    try std.testing.expectError(error.CodecFailure, feedAll(&stream, wire[0..used]));
}

test "response: HEADERS with :status and regular headers" {
    var codec_state = TestCodec{};
    var codec = codec_state.codec();
    const writer = ResponseWriter.init(&codec);

    const headers = [_]Header{
        .{ .name = "content-type", .value = "text/plain" },
        .{ .name = "content-length", .value = "5" },
    };
    var out: [256]u8 = undefined;
    const encoded = try writer.writeHead(200, &headers, &out);

    const type_varint = try readVarint(encoded);
    try std.testing.expectEqual(frame_type_headers, type_varint.value);
    const length_varint = try readVarint(encoded[type_varint.len..]);
    try std.testing.expectEqual(@as(u64, encoded.len - type_varint.len - length_varint.len), length_varint.value);

    const block = encoded[@as(usize, type_varint.len) + length_varint.len ..];
    var decoded: [headers_max]Header = undefined;
    const count = try TestCodec.decode(&codec_state, block, &decoded);
    try std.testing.expectEqual(@as(usize, 3), count);
    try std.testing.expectEqualSlices(u8, ":status", decoded[0].name);
    try std.testing.expectEqualSlices(u8, "200", decoded[0].value);
    try std.testing.expectEqualSlices(u8, "content-type", decoded[1].name);
    try std.testing.expectEqual(@as(usize, 1), codec_state.encode_calls);
}

test "response: DATA frame ignores fin" {
    var out_with_fin: [64]u8 = undefined;
    var out_without_fin: [64]u8 = undefined;
    const with_fin = try writeData("hello", true, &out_with_fin);
    const without_fin = try writeData("hello", false, &out_without_fin);

    try std.testing.expectEqualSlices(u8, with_fin, without_fin);
    try std.testing.expectEqualSlices(u8, &.{ 0x00, 0x05, 'h', 'e', 'l', 'l', 'o' }, with_fin);
}

test "response: invalid status and short output are named errors" {
    var codec_state = TestCodec{};
    var codec = codec_state.codec();
    var out: [64]u8 = undefined;
    try std.testing.expectError(error.InvalidStatus, writeHead(&codec, 99, &.{}, &out));
    try std.testing.expectError(error.InvalidStatus, writeHead(&codec, 1000, &.{}, &out));

    var tiny: [2]u8 = undefined;
    try std.testing.expectError(
        error.OutputTooSmall,
        writeHead(&codec, 204, &.{.{ .name = "x", .value = "y" }}, &tiny),
    );
}
