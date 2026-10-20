//! HTTP/3 session layer: QUIC stream bytes ↔ one request handler.
//!
//! `H3Session` owns the per-connection QPACK encoder/decoder, the bounded
//! request-stream table, the server control streams and response
//! serialization. A `Sender` supplies the transport, so the layer is
//! testable without a QUIC connection and the real connection only has to
//! hand over one `StreamHandler`.
//!
//! QPACK is dynamic in both directions (RFC 9204). The session advertises a
//! 4096-byte dynamic table and 16 blocked streams; the peer's encoder
//! stream (client uni type 0x02) is applied to `qpack_decoder`, whose
//! Insert Count Increments and Section Acknowledgments go out on the
//! server decoder stream (id 11, type 0x03). The response encoder is the
//! vendor `qpack.Encoder`, configured from the client SETTINGS frame with
//! its capacity capped at the same 4096; its encoder-stream instructions
//! ride server stream 7 (type 0x02) ahead of the HEADERS frame that
//! references them, and the peer's decoder stream (type 0x03) feeds its
//! acknowledgments back. A request field section whose Required Insert
//! Count is not yet satisfied parks (RFC 9204 §4.4) in a bounded FIFO
//! instead of failing the stream: `feedPeerEncoder` retries the queue head
//! whenever new inserts land. Chrome advertises blocked_streams=100 and
//! uses blocked references aggressively; the zero advertisement this file
//! shipped before gave that interop away.
//!
//! Deferred, deliberately:
//!
//! - Client control-stream MAX_PUSH_ID handling; SETTINGS and GOAWAY are
//!   consumed, other frames skipped.
//! - Response trailers. `sendResponse` emits HEADERS and at most one DATA
//!   frame in one transport send; the split `sendResponseHead`/`sendData`
//!   pair streams a body across many DATA frames, one HEADERS frame first,
//!   without that bound.
//!
//! The file also retains the earlier bounded QUIC slot probe
//! (`Slot`/`Session`) that `root.zig` re-exports. That type prices zquic's
//! allocator use; `H3Session` is the protocol layer above it.

const std = @import("std");

const constants = @import("../../constants.zig");
const zquic = @import("zquic");
const qpack = @import("qpack");

const connection = @import("connection.zig");
const request_stream = @import("request_stream.zig");

const Http3 = zquic.Http3;

/// Response bytes are built here before the single transport send. A
/// response (HEADERS plus DATA) past this bound is `ResponseTooLarge`.
const response_bytes_max: usize = 64 * 1024;

/// Dynamic-table capacity this session advertises in its SETTINGS frame and
/// also the cap it places on its own response encoder. 4096 bytes matches
/// the vendor default and comfortably covers a browser's first flight of
/// repetitive request headers; the table's live bytes (name + value + 32
/// per entry, RFC 9204 §3.2.1) can never exceed it, so the per-connection
/// reservation is fixed whether or not the peer uses the table.
pub const qpack_max_table_capacity: usize = 4096;

/// Blocked streams this session advertises: 16, the same bound the
/// session places on its own encoder (`qpack_encoder_blocked_cap`). A
/// conforming peer may park at most this many field sections whose
/// Required Insert Count is not yet satisfied; the decoder parks them in
/// a FIFO bounded by this constant (see `parked`) and retries the head
/// whenever the encoder stream delivers inserts. A 17th blocked section
/// means the peer exceeded its advertised budget — a protocol error for
/// that stream. Chrome's 100 is larger than a single connection's
/// in-flight request table here, so 16 surrenders nothing measurable.
pub const qpack_blocked_streams: usize = 16;

/// Ceiling the session places on its own encoder's blocked-section count
/// when the peer advertises a nonzero limit. The vendor already caps at 16;
/// restating the bound here keeps the session's memory reasoning in one
/// place.
pub const qpack_encoder_blocked_cap: usize = 16;

/// Reassembly buffer for the peer's encoder-stream instructions. Any single
/// legal instruction fits: an insert entry larger than the table capacity
/// is itself a protocol error (RFC 9204 §4.3.2), so an instruction needing
/// more than `qpack_max_table_capacity` of payload can never be applied.
const qpack_instruction_buffer_bytes: usize = qpack_max_table_capacity + 64;

/// Reassembly buffer for the peer's decoder-stream instructions. One
/// instruction is at most `qpack.max_decoder_instruction_len` bytes; a
/// burst is drained greedily, so a handful of slots covers a split write.
const qpack_decoder_instruction_buffer_bytes: usize = 64;

/// Reassembly buffer for control-stream frames (SETTINGS, GOAWAY). Both
/// frames are a handful of bytes in practice; a frame that cannot fit is
/// dropped with the connection, the same verdict an over-long control
/// frame earns elsewhere.
const control_stream_buffer_bytes: usize = 512;

/// Server-initiated unidirectional streams (RFC 9114 §6.2, RFC 9204 §4.2).
/// All are `stream_id & 0x3 == 0x3`.
const control_stream_id: u64 = 3;
const qpack_encoder_stream_id: u64 = 7;
const qpack_decoder_stream_id: u64 = 11;

pub const Sender = struct {
    ctx: *anyopaque,
    send: *const fn (ctx: *anyopaque, stream_id: u64, data: []const u8, fin: bool) anyerror!void,
    /// Optional multi-packet path returning bytes queued (short write =
    /// backpressure). Null (test doubles, and literals that predate the
    /// field) makes `sendData` fall back to one `send`, which then bounds a
    /// chunk to what a single transport send carries.
    send_multi: ?*const fn (ctx: *anyopaque, stream_id: u64, data: []const u8, fin: bool) anyerror!usize = null,
};

pub const RequestHandler = struct {
    ctx: *anyopaque,
    /// The request head is complete and validated; called once per request,
    /// before any `onBodyChunk`. `request.body` is always empty — body
    /// bytes arrive only through `onBodyChunk`. The entry stays active
    /// after this returns: release happens at body completion unless the
    /// handler deferred or started a split response (see `deferRequest`,
    /// `sendResponseHead`), at `sendResponse` once the body has completed,
    /// or at `abort`/`abortStream`.
    onRequest: *const fn (
        ctx: *anyopaque,
        session: *H3Session,
        stream_id: u64,
        request: *const request_stream.Request,
    ) void,
    /// Incremental request body: called in arrival order after the headers
    /// were delivered; `fin=true` marks the last chunk (the completing
    /// event, which carries any remaining bytes — often empty). The body
    /// has no size limit; the stream's QUIC flow control is the backstop.
    onBodyChunk: ?*const fn (
        ctx: *anyopaque,
        session: *H3Session,
        stream_id: u64,
        chunk: []const u8,
        fin: bool,
    ) anyerror!void = null,
    /// The request stream was reset by the peer (upload aborted): the entry
    /// is already released; the handler must drop any in-flight exchange
    /// state it pinned for this stream.
    onAborted: ?*const fn (ctx: *anyopaque, session: *H3Session, stream_id: u64) void = null,
};

/// Named failures the session can report to a caller. `onStreamData` drops
/// them (the stream is reset by dropping its slot); the private `feed`
/// returns them so tests and a future listener can distinguish policy.
const FeedError = error{
    /// The header block or decoded header count exceeded its limit.
    RequestTooLarge,
    CodecFailure,
    /// The peer's bytes (or a body arriving uninvited, see
    /// `deliverChunk`) violated HTTP/3 request-stream rules.
    Malformed,
    /// The handler's `onBodyChunk` rejected a chunk: the exchange it
    /// represents failed mid-body, so the stream was dropped.
    HandlerFailed,
    /// All `streams_max` request slots are in use.
    StreamLimit,
};

pub const H3Session = struct {
    /// Request slots, and so the client-bidi stream ceiling the connection
    /// advertises: one constant (`constants.h3_request_streams_max`) is the
    /// single source for both, aliased here where the table is sized.
    pub const streams_max = constants.h3_request_streams_max;

    allocator: std.mem.Allocator,
    sender: Sender,
    handler: RequestHandler,

    /// Session-level codec for response encoding. Request parsers get
    /// per-entry codecs so the decode callback can find the entry whose
    /// header bytes it must keep alive.
    codec: request_stream.Codec,

    streams: []StreamEntry,
    /// The client's UDP address, set by the listener right after
    /// `initInPlace` (the session itself never sees a datagram's source).
    /// The proxy reads it for the per-request witness facts; undefined
    /// until the listener sets it.
    peer: std.Io.net.IpAddress = undefined,
    /// Back-pointer the listener installs once both halves of the slot
    /// exist: every released request slot hands its stream credit back to
    /// the client through it (`Connection.raiseBidiStreamLimit`). Null in
    /// tests, which drive the session with a `FakeSender` and no connection
    /// underneath.
    conn: ?*connection.Connection = null,
    /// Client-initiated unidirectional streams: control and QPACK types.
    /// Four slots cover the control stream plus the two QPACK streams and
    /// one spare; excess streams are ignored.
    uni: [4]UniEntry = @splat(.{}),
    /// A client GOAWAY was seen on the control stream: no new request
    /// streams should be accepted after this.
    draining: bool = false,
    control_sent: bool,
    /// QPACK decode side: applies the peer's encoder-stream instructions
    /// (client uni type 0x02) and decodes request header blocks. Sized at
    /// `qpack_max_table_capacity`, the value SETTINGS advertises.
    qpack_decoder: qpack.Decoder = undefined,
    /// QPACK encode side: encodes response header blocks once the client
    /// SETTINGS have configured it, bounded by the peer's advertised
    /// capacity capped at `qpack_max_table_capacity`.
    qpack_encoder: qpack.Encoder = undefined,
    /// True once the QPACK state has been poisoned by a protocol error.
    /// The connection underneath (when one exists) is aborted at the same
    /// moment; this flag is the bare-session/test-double equivalent. A
    /// poisoned session refuses any field section that references the
    /// dynamic table but still decodes static-only blocks — they never
    /// touch the desynchronized table.
    qpack_failed: bool = false,
    /// The request stream currently being encoded by `encodeCallback`, set
    /// around `writeHead` in `sendResponse`/`sendResponseHead` the way
    /// `decode_target` brackets the decode path — the encoder tracks
    /// Section Acknowledgments per stream.
    encode_target: ?u64 = null,
    /// Reassembly tail for the three instruction/frame streams above.
    /// Control frames and QPACK instructions may arrive split across
    /// datagrams; parsing consumes complete units and retains the rest.
    control_rx: [control_stream_buffer_bytes]u8 = undefined,
    control_rx_len: usize = 0,
    qpack_rx: [qpack_instruction_buffer_bytes]u8 = undefined,
    qpack_rx_len: usize = 0,
    decoder_rx: [qpack_decoder_instruction_buffer_bytes]u8 = undefined,
    decoder_rx_len: usize = 0,
    /// The entry currently being fed. The codec callback runs synchronously
    /// inside `feed`/`finish` and needs to know where decoded header fields
    /// should be retained.
    decode_target: ?*StreamEntry,
    /// FIFO of request streams whose current field section parked on a
    /// blocked QPACK decode, in arrival order. Only the stream id is
    /// stored: the section's bytes stay in the entry's fixed
    /// `header_block` buffer, so parking rides the per-entry allocation
    /// the session already pays and the total is bounded by
    /// `qpack_blocked_streams` × `request_stream.header_block_bytes_max`.
    parked: [qpack_blocked_streams]u64 = undefined,
    parked_len: u8 = 0,

    pub fn initInPlace(
        self: *H3Session,
        allocator: std.mem.Allocator,
        sender: Sender,
        handler: RequestHandler,
    ) !void {
        self.allocator = allocator;
        self.sender = sender;
        self.handler = handler;
        self.codec = .{ .ctx = self, .decode = decodeCallback, .encode = encodeCallback };
        self.streams = &.{};
        self.peer = undefined;
        self.conn = null;
        self.uni = @splat(.{});
        self.draining = false;
        self.control_sent = false;
        self.decode_target = null;
        self.qpack_decoder = qpack.Decoder.init(allocator, qpack_max_table_capacity);
        self.qpack_encoder = qpack.Encoder.init(allocator);
        self.qpack_failed = false;
        self.encode_target = null;
        self.control_rx_len = 0;
        self.qpack_rx_len = 0;
        self.decoder_rx_len = 0;
        self.parked_len = 0;

        self.streams = allocator.alloc(StreamEntry, streams_max) catch |err| {
            self.qpack_encoder.deinit();
            self.qpack_decoder.deinit();
            return err;
        };
        for (self.streams) |*entry| {
            entry.* = .{};
            entry.codec = .{ .ctx = self, .decode = decodeCallback, .encode = encodeCallback };
        }
    }

    pub fn deinit(self: *H3Session) void {
        // Release the back-pointer before the entries: slot teardown must
        // not credit a dying connection with stream slots it will never
        // advertise.
        self.conn = null;
        self.qpack_decoder.deinit();
        self.qpack_encoder.deinit();
        for (self.streams) |*entry| self.releaseEntry(entry);
        if (self.streams.len > 0) self.allocator.free(self.streams);
        self.streams = &.{};
    }

    /// The callback to install on a `connection.Connection`. `on_reset`
    /// lands with the connection's RESET_STREAM handling (agent C): the
    /// peer abandoned the request's upload, so the entry and any exchange
    /// state the handler pinned for it must go.
    pub fn streamHandler(self: *H3Session) connection.StreamHandler {
        return .{ .ctx = self, .onData = onStreamData, .on_reset = onStreamReset };
    }

    /// Whether the client sent HTTP/3 GOAWAY. The listener can use this to
    /// stop accepting new request streams on the connection.
    pub fn isDraining(self: *const H3Session) bool {
        return self.draining;
    }

    /// Send the server control and QPACK streams once the handshake is
    /// complete. Idempotent after a successful call; a failed send leaves
    /// the flag clear so the caller can retry.
    ///
    /// SETTINGS carries the QPACK terms this session serves: a
    /// 4096-byte dynamic table and 16 blocked streams. Both are
    /// comptime-fixed, so the frame is serialized into the stack buffer
    /// with two one-byte setting ids and no allocation.
    pub fn sendControl(self: *H3Session) !void {
        if (self.control_sent) return;

        var control: [16]u8 = undefined;
        var writer: std.Io.Writer = .fixed(&control);
        const stream_type = [_]u8{0x00}; // control stream
        try writer.writeAll(&stream_type);
        // Two settings: QPACK_MAX_TABLE_CAPACITY = 4096 (a two-byte
        // varint) and QPACK_BLOCKED_STREAMS = 16. 2 + 3 = 5 payload bytes.
        const settings = Http3.FrameHeader{ .frame_type = .settings, .length = 5 };
        try settings.serialize(&writer);
        try writer.writeAll(&.{ 0x01, 0x50, 0x00, 0x07, 0x10 });
        try self.sender.send(self.sender.ctx, control_stream_id, control[0..writer.end], false);

        // RFC 9114 §6.2.3: 0x02 names a QPACK encoder stream, 0x03 a QPACK
        // decoder stream. zgix is the server: stream 7 carries its encoder
        // instructions for response blocks, stream 11 the Insert Count
        // Increments and Section Acknowledgments its decoder emits.
        const encoder_type = [_]u8{0x02};
        try self.sender.send(self.sender.ctx, qpack_encoder_stream_id, &encoder_type, false);

        const decoder_type = [_]u8{0x03};
        try self.sender.send(self.sender.ctx, qpack_decoder_stream_id, &decoder_type, false);

        self.control_sent = true;
    }

    /// Encode and send one response: HEADERS (`:status` plus `headers`) and,
    /// when `body` is non-empty, one DATA frame. Empty bodies put `fin` on
    /// the HEADERS send instead of emitting an empty DATA frame.
    pub fn sendResponse(
        self: *H3Session,
        stream_id: u64,
        status: u16,
        headers: []const request_stream.Header,
        body: []const u8,
        fin: bool,
    ) !void {
        var out: [response_bytes_max]u8 = undefined;
        self.encode_target = stream_id;
        const head = request_stream.writeHead(&self.codec, status, headers, &out) catch |err| {
            self.encode_target = null;
            return switch (err) {
                error.OutputTooSmall => error.ResponseTooLarge,
                else => err,
            };
        };
        self.encode_target = null;

        if (body.len == 0) {
            try self.sender.send(self.sender.ctx, stream_id, head, fin);
            self.responseDone(stream_id);
            return;
        }

        if (body.len > out.len - head.len) return error.ResponseTooLarge;
        const data = request_stream.writeData(body, fin, out[head.len..]) catch |err| {
            return switch (err) {
                error.OutputTooSmall => error.ResponseTooLarge,
                else => err,
            };
        };
        try self.sender.send(self.sender.ctx, stream_id, out[0 .. head.len + data.len], fin);
        self.responseDone(stream_id);
    }

    /// The one-shot response path finished sending: free the slot when the
    /// request body has completed too. An upload still arriving keeps the
    /// entry alive — its parser must consume the remaining bytes, and body
    /// completion frees it through `maybeRelease`; the handler having
    /// answered, `deferRequest`'s pin is spent either way.
    fn responseDone(self: *H3Session, stream_id: u64) void {
        const entry = self.findActive(stream_id) orelse return;
        if (entry.body_done) {
            self.releaseEntry(entry);
        } else {
            entry.keep = false;
        }
    }

    /// Begin a split (streamed) response: encode HEADERS (`:status` plus
    /// `headers`) and send them in one transport send. The request slot is
    /// pinned past the handler return and stays held until a `sendData` fin
    /// chunk is fully queued or `abortStream` runs; the body then travels
    /// as zero or more DATA frames through `sendData`. A bodyless response
    /// still ends with `sendData(stream_id, "", true)` — HEADERS alone
    /// never carries fin here, so an empty DATA frame does.
    pub fn sendResponseHead(
        self: *H3Session,
        stream_id: u64,
        status: u16,
        headers: []const request_stream.Header,
    ) !void {
        var out: [response_bytes_max]u8 = undefined;
        self.encode_target = stream_id;
        const head = request_stream.writeHead(&self.codec, status, headers, &out) catch |err| {
            self.encode_target = null;
            return switch (err) {
                error.OutputTooSmall => error.ResponseTooLarge,
                else => err,
            };
        };
        self.encode_target = null;
        const entry = self.findOrCreate(stream_id) orelse return error.StreamLimit;
        try self.sender.send(self.sender.ctx, stream_id, head, false);
        // The streaming state opens only on a successful send; a failure
        // leaves the entry as it was, and the caller's error path aborts.
        entry.head_sent = true;
        entry.keep = true;
    }

    /// Queue one DATA chunk of a split response, returning the payload bytes
    /// actually queued: `chunk.len` means the whole chunk went out. A short
    /// return is backpressure (full datagram queue or flow-control window),
    /// never an error: fin is not set and the slot stays held, and the
    /// caller keeps the unsent tail and re-invokes with it once the
    /// window-open notify says the path cleared, `fin` unchanged. `fin`
    /// takes effect only when everything it rode in with is queued — only
    /// then is the slot released, so the MAX_STREAMS credit still fires
    /// exactly once per request.
    ///
    /// Framing is stateful across a short write: the chunk that
    /// short-wrote left its DATA frame open, and the offered chunk's
    /// leading bytes continue that frame with no new header (a caller may
    /// offer exactly the unsent tail or split it further). Bytes past the
    /// open frame's remainder — a caller re-slicing from its relay buffer
    /// rather than from the tail — are not an error: they begin a new DATA
    /// frame in the same call. Either way fin lands only when the open
    /// frame and the offered bytes all queued, so a fin on an incomplete
    /// frame simply stays pending while the frame does.
    ///
    /// The stream must have a completed `sendResponseHead`; every other
    /// state — released, fin already sent, never headed — answers
    /// `error.StreamReleased`, the only soft failure: only hard transport
    /// errors (handshake state, stream table, seal) escape as errors from
    /// the send itself. A chunk past `response_bytes_max` is
    /// `error.ChunkTooLarge`.
    pub fn sendData(
        self: *H3Session,
        stream_id: u64,
        chunk: []const u8,
        fin_in: bool,
    ) !usize {
        const entry = self.findActive(stream_id) orelse return error.StreamReleased;
        if (!entry.head_sent) return error.StreamReleased;

        var out: [response_bytes_max]u8 = undefined;
        var total: usize = 0;
        var rest = chunk;
        const fin = fin_in;

        // A short-written chunk left its DATA frame open: the offered
        // chunk's leading bytes continue it, headerless. The fin may ride
        // that continuation only when the continuation is the chunk's
        // whole remainder and completes the frame; the transport drops a
        // fin on a partially queued slice, so an unfinished frame defers
        // it either way. Bytes past the drained frame begin a new DATA
        // frame below, the fin riding them instead.
        if (entry.pending_data > 0) {
            const cont = rest[0..@min(rest.len, entry.pending_data)];
            const cont_fin = fin and cont.len == entry.pending_data and cont.len == rest.len;
            const queued = try self.queueSend(stream_id, cont, cont_fin);
            total += queued;
            entry.pending_data -= queued;
            if (entry.pending_data > 0) return total; // frame still open
            if (cont_fin) {
                // The chunk was exactly the frame's tail and took the fin.
                self.releaseStream(stream_id);
                return total;
            }
            rest = rest[cont.len..];
            if (rest.len == 0) return total; // frame drained, no fin asked
        }

        // What remains starts a fresh DATA frame (on the first call that is
        // the whole chunk). The frame header rides at the front of the
        // first transport chunk, which short-writes only at chunk
        // boundaries, so a partial send always covers the whole header; a
        // hypothetical mid-header cut reports zero payload queued and keeps
        // the frame fully pending rather than underflowing the remainder.
        const framed = request_stream.writeData(rest, fin, &out) catch |err| {
            return switch (err) {
                error.OutputTooSmall => error.ChunkTooLarge,
                else => err,
            };
        };
        const header_len = framed.len - rest.len;
        const queued = try self.queueSend(stream_id, framed, fin);
        const payload_queued: usize = if (queued >= header_len) queued - header_len else 0;
        entry.pending_data = rest.len - payload_queued;
        if (fin and queued == framed.len) self.releaseStream(stream_id);
        return total + payload_queued;
    }

    /// Reap encoder field sections whose peer acknowledgments stayed out
    /// past the vendor timeout, releasing the table entries they pin. The
    /// check is a single counter read while nothing is blocked, so it is
    /// cheap enough to ride every inbound beat. A timeout means the peer's
    /// decoder feedback stalled; the session answers by degrading to
    /// literal encoding (the blocked-stream budget exhausts, then
    /// `mayBlockNewSection` refuses dynamic references) rather than by
    /// tearing the connection down — serving correctness outranks table
    /// hygiene, and the table itself stays bounded by capacity either way.
    fn serviceQpackEncoder(self: *H3Session) void {
        if (self.qpack_encoder.blockedStreamCount() == 0) return;
        _ = self.qpack_encoder.expireBlockedSections((self.qpack_encoder.clock)());
    }

    /// One transport send of an already-framed slice, returning the framed
    /// bytes queued. The multi-packet path reports its short write; the
    /// single-packet fallback (senders without `send_multi`, i.e. test
    /// doubles) either carries the whole slice or names the chunk too
    /// large for one transport send.
    fn queueSend(self: *H3Session, stream_id: u64, framed: []const u8, fin: bool) !usize {
        if (self.sender.send_multi) |send_multi| {
            const queued = try send_multi(self.sender.ctx, stream_id, framed, fin);
            std.debug.assert(queued <= framed.len);
            return queued;
        }
        if (framed.len > connection.max_stream_frame_payload) return error.ChunkTooLarge;
        try self.sender.send(self.sender.ctx, stream_id, framed, fin);
        return framed.len;
    }

    /// Abort a split response whose HEADERS already went out: the QUIC
    /// stream is reset with H3_REQUEST_CANCELLED and the request slot frees,
    /// handing the client one MAX_STREAMS credit — the same release the fin
    /// chunk would have done, so the exactly-once invariant holds either
    /// way. This is the reset counterpart of `abort`, which stays for
    /// responses whose HEADERS never sent, where resetting would accuse the
    /// client of a request it made correctly. A bare session (no connection
    /// underneath, as in unit tests) just frees the slot.
    pub fn abortStream(self: *H3Session, stream_id: u64) void {
        const entry = self.findActive(stream_id) orelse return;
        if (self.conn) |conn| conn.resetStream(stream_id, connection.h3_request_cancelled) catch {};
        self.releaseEntry(entry);
    }

    /// Keep a request entry alive after the handler returns. (The proposed
    /// name `defer` is a Zig keyword, hence `deferRequest`.) The upstream
    /// exchange is asynchronous, so the parser and decoded headers must
    /// survive until the response is sent.
    pub fn deferRequest(self: *H3Session, stream_id: u64) void {
        const entry = self.findActive(stream_id) orelse return;
        entry.keep = true;
    }

    /// Drop a deferred request without a response. Errors on an exchange
    /// call this after `sendResponse` itself failed.
    pub fn abort(self: *H3Session, stream_id: u64) void {
        const entry = self.findActive(stream_id) orelse return;
        self.releaseEntry(entry);
        // Aborted mid-exchange, no response FIN will ever free the
        // connection's stream-table slot, so it would sit there for the
        // connection's life; hand it back explicitly. A null conn (the
        // session driven bare in tests) has no table to release into.
        if (self.conn) |conn| conn.dropStream(stream_id);
    }

    fn releaseStream(self: *H3Session, stream_id: u64) void {
        const entry = self.findActive(stream_id) orelse return;
        self.releaseEntry(entry);
    }

    fn findActive(self: *H3Session, stream_id: u64) ?*StreamEntry {
        for (self.streams) |*entry| {
            if (entry.active and entry.stream_id == stream_id) return entry;
        }
        return null;
    }

    /// `StreamHandler` callback. Parse errors drop the stream, never the
    /// connection: one bad request must not end every exchange on it.
    fn onStreamData(ctx: *anyopaque, stream_id: u64, data: []const u8, fin: bool) void {
        const self: *H3Session = @ptrCast(@alignCast(ctx));
        self.feed(stream_id, data, fin) catch {};
    }

    /// `StreamHandler` reset callback: the peer abandoned its send half
    /// (RFC 9000 §19.4), so the upload stops where it is. Free the entry —
    /// the release carries the MAX_STREAMS credit, exactly once — and only
    /// then tell the handler to drop its in-flight exchange, so whatever it
    /// calls back into the session finds the stream already gone.
    fn onStreamReset(ctx: *anyopaque, stream_id: u64) void {
        const self: *H3Session = @ptrCast(@alignCast(ctx));
        const entry = self.findActive(stream_id) orelse return;
        self.releaseEntry(entry);
        if (self.handler.onAborted) |onAborted| {
            onAborted(self.handler.ctx, self, stream_id);
        }
    }

    fn feed(self: *H3Session, stream_id: u64, data: []const u8, fin: bool) FeedError!void {
        // Stream-id low bits (RFC 9000 §2.1): 0 = client bidi (request),
        // 2 = client uni (HTTP/3 control/QPACK), 1/3 = server-initiated.
        switch (stream_id & 0x3) {
            0 => {},
            2 => return self.feedUni(stream_id, data),
            else => return,
        }
        if (self.draining) return;

        self.serviceQpackEncoder();

        const entry = self.findOrCreate(stream_id) orelse return error.StreamLimit;
        if (entry.parser.parked) {
            // The head section is parked on QPACK entries the encoder has
            // not sent yet. The realistic blocked shape is HEADERS with
            // the encoder-stream instructions a round behind; bytes that
            // arrive after the park are dropped rather than buffered (a
            // body could outrun any fixed buffer), and a FIN is
            // remembered so the exchange completes when the section
            // resolves. An encoder that never catches up stalls the
            // exchange into the connection's existing deadlines — which
            // is exactly the sanctioned way to reap a stuck QPACK peer.
            if (fin) entry.fin_pending = true;
            return;
        }
        self.decode_target = entry;
        defer self.decode_target = null;

        // The parser answers at most one event per call; keep feeding the
        // unconsumed remainder so every event lands in wire order. The
        // handler answers inside the events (a synchronous `sendResponse`,
        // an `abortStream`), and such a call may release the entry: bytes
        // after that belong to a dead stream and are dropped.
        var rest = data;
        while (rest.len > 0) {
            const fed = entry.parser.feed(rest) catch |err| {
                if (err == error.Blocked) {
                    // The codec needs dynamic-table entries the peer's
                    // encoder stream has not delivered. Park instead of
                    // failing: bytes already consumed stay consumed, the
                    // block itself remains buffered in the entry, and a
                    // FIN riding this datagram waits for the retry.
                    if (fin) entry.fin_pending = true;
                    try self.parkBlock(entry);
                    return;
                }
                self.releaseEntry(entry);
                return mapParseError(err);
            };
            const remainder = rest[fed.consumed..];
            // FIN riding right behind the HEADERS frame marks a bodyless
            // request: the handler learns it with the head, while the
            // completing `onBodyChunk` marker still lands afterwards.
            const fin_on_headers = fin and remainder.len == 0;
            rest = remainder;
            try self.handleEvent(entry, fed.event, fin_on_headers);
            if (!entry.active) return;
        }
        // FIN completes a request whose last frame already parsed; a body
        // completed by trailers is a no-op here (`body_done` is set).
        if (fin and entry.active and !entry.body_done) {
            if (entry.parser.parked) {
                entry.fin_pending = true;
            } else {
                try self.finishEntry(entry);
            }
        }
    }

    /// Park a stream whose field section answered `error.Blocked`. The
    /// queue is bounded by the advertised `qpack_blocked_streams`: a
    /// conforming peer never exceeds it, so the 17th blocked section is a
    /// protocol error for that stream — released exactly like a malformed
    /// frame, without poisoning the dynamic tables (the encoder can keep
    /// using them, it merely overcommitted its blocking budget).
    fn parkBlock(self: *H3Session, entry: *StreamEntry) FeedError!void {
        if (self.parked_len >= qpack_blocked_streams) {
            self.releaseEntry(entry);
            return error.Malformed;
        }
        self.parked[self.parked_len] = entry.stream_id;
        self.parked_len += 1;
    }

    /// Drop the queue head (the caller has retried or given up on it).
    /// Bounded by `qpack_blocked_streams`; order preserved by the shift.
    fn shiftParked(self: *H3Session) void {
        std.debug.assert(self.parked_len > 0);
        var index: u8 = 1;
        while (index < self.parked_len) : (index += 1) {
            self.parked[index - 1] = self.parked[index];
        }
        self.parked_len -= 1;
    }

    /// Retry parked sections after the peer's encoder stream applied new
    /// inserts (`feedPeerEncoder` calls this once per delivery). The
    /// queue's insert count is monotone — applying instructions only adds
    /// entries, never removes them — so a section that retries blocked
    /// stays blocked until at least as many inserts exist, and one that
    /// decodes can never block again: retrying in strict arrival order,
    /// stopping at the first still-blocked head, is sound. In the
    /// compliant case the head is also the first to unblock: an encoder
    /// emits its inserts before the sections that reference them, so an
    /// earlier section never waits on entries newer than a later one's.
    /// A still-blocked head only delays later sections (the encoder's
    /// Insert Count Increment flow keeps them consistent), never
    /// corrupts them. Each cleared head runs the ordinary event path —
    /// the same `handleEvent`/`finishEntry` tail `feed` uses — and a
    /// decoded section carries its Section Acknowledgment out on the
    /// decoder stream through the unchanged `decodeCallback`.
    fn retryParkedBlocks(self: *H3Session) void {
        while (self.parked_len > 0) {
            const stream_id = self.parked[0];
            const entry = self.findActive(stream_id) orelse {
                // The stream died (reset, abort) while parked: its slot
                // goes with it.
                self.shiftParked();
                continue;
            };
            self.decode_target = entry;
            const fed = entry.parser.retryParked() catch {
                // Retry-time codec or validation failure is the same
                // malformed verdict the original feed would have drawn;
                // `handleEvent`'s inner paths release on their own errors.
                self.decode_target = null;
                self.shiftParked();
                self.releaseEntry(entry);
                continue;
            };
            self.decode_target = null;
            if (fed == null) break; // head still blocked: later ones wait
            self.shiftParked();
            const fin_on_headers = entry.fin_pending;
            self.handleEvent(entry, fed.?.event, fin_on_headers) catch {};
            if (!entry.active) continue;
            if (entry.fin_pending) {
                entry.fin_pending = false;
                if (!entry.body_done) self.finishEntry(entry) catch {};
            }
        }
    }

    /// Dispatch one parser event to the handler side. Protocol violations
    /// and handler failures release the entry; completion marks the body
    /// done and releases when the exchange needs nothing more of the slot.
    /// `fin_on_headers` is meaningful only on the `.headers` event: whether
    /// the delivery's transport FIN closed right behind the head.
    fn handleEvent(
        self: *H3Session,
        entry: *StreamEntry,
        event: request_stream.Event,
        fin_on_headers: bool,
    ) FeedError!void {
        switch (event) {
            .need_more => {},
            .headers => |request| self.deliver(entry, request, fin_on_headers),
            .body => |chunk| try self.deliverChunk(entry, chunk),
            .complete => try self.completeEntry(entry),
            .malformed => {
                self.releaseEntry(entry);
                return error.Malformed;
            },
        }
    }

    /// The request head borrows the entry's decoded-header storage, so the
    /// handler runs while both are alive. The entry outlives the callback:
    /// body chunks may still be in flight, and the release rules live in
    /// `maybeRelease` / the response paths. The session stamps whether the
    /// stream's FIN rode the HEADERS frame (`fin_on_headers`) so a handler
    /// can commit to a bodyless exchange before the body's completion
    /// marker arrives.
    fn deliver(
        self: *H3Session,
        entry: *StreamEntry,
        request: request_stream.Request,
        fin_on_headers: bool,
    ) void {
        var amended = request;
        amended.fin_on_headers = fin_on_headers;
        self.handler.onRequest(self.handler.ctx, self, entry.stream_id, &amended);
    }

    /// Hand one DATA-frame run to the handler. Without a subscribed
    /// `onBodyChunk` the body cannot be consumed, and a request the handler
    /// cannot consume is a protocol error at this layer — the only honest
    /// verdict is to drop the stream, exactly like a malformed frame.
    fn deliverChunk(self: *H3Session, entry: *StreamEntry, chunk: []const u8) FeedError!void {
        const onBodyChunk = self.handler.onBodyChunk orelse {
            self.releaseEntry(entry);
            return error.Malformed;
        };
        onBodyChunk(self.handler.ctx, self, entry.stream_id, chunk, false) catch {
            self.releaseEntry(entry);
            return error.HandlerFailed;
        };
    }

    /// The request body is complete (FIN or trailers): deliver the fin
    /// marker and free the slot when nothing pins it. The fin chunk is the
    /// last `onBodyChunk` call either way; it is empty unless the trailer
    /// boundary left nothing to pair with the marker.
    fn completeEntry(self: *H3Session, entry: *StreamEntry) FeedError!void {
        if (!entry.active) return;
        entry.body_done = true;
        if (self.handler.onBodyChunk) |onBodyChunk| {
            onBodyChunk(self.handler.ctx, self, entry.stream_id, "", true) catch {
                self.releaseEntry(entry);
                return error.HandlerFailed;
            };
        }
        self.maybeRelease(entry);
    }

    /// Free the slot once the request is fully received and the exchange
    /// needs nothing more of it: a deferred request (`deferRequest`) and a
    /// split response in flight (`sendResponseHead`) keep their pins until
    /// `sendResponse`/`sendData`-fin/`abort` runs; everything else — the
    /// synchronous `sendResponse`, the unanswered fire-and-forget request —
    /// ends here. Releases through this path happen exactly once, guarded
    /// by `entry.active`.
    fn maybeRelease(self: *H3Session, entry: *StreamEntry) void {
        if (!entry.active) return;
        if (!entry.body_done) return;
        if (entry.keep or entry.head_sent) return;
        self.releaseEntry(entry);
    }

    /// Client unidirectional stream: the first varint names the HTTP/3
    /// stream type (RFC 9114 §6.2). 0x00 is the control stream (SETTINGS
    /// and GOAWAY consumed, other frames skipped); 0x02 is the peer's
    /// QPACK encoder stream, whose instructions grow `qpack_decoder`; 0x03
    /// is the peer's QPACK decoder stream, whose acknowledgments advance
    /// `qpack_encoder`. The remaining bytes of each stream are reassembled
    /// in bounded buffers because QUIC splits are not visible to this
    /// layer. A protocol error on either QPACK stream is a connection
    /// error (RFC 9204 §5.3); with no connection underneath it poisons the
    /// session instead, failing every later dynamic reference closed.
    fn feedUni(self: *H3Session, stream_id: u64, data: []const u8) FeedError!void {
        const entry = self.findUni(stream_id) orelse return error.StreamLimit;
        var payload = data;
        if (entry.kind == .unknown) {
            const parsed = request_stream.readVarint(data) catch return error.Malformed;
            entry.kind = switch (parsed.value) {
                0x00 => .control,
                0x02 => .qpack_encoder,
                0x03 => .qpack_decoder,
                else => .other,
            };
            payload = data[parsed.len..];
        }
        switch (entry.kind) {
            .control => self.feedControl(payload) catch return error.Malformed,
            .qpack_encoder => self.feedPeerEncoder(payload),
            .qpack_decoder => self.feedPeerDecoder(payload),
            else => {},
        }
    }

    /// Parse control-stream frames from the reassembly buffer. A partial
    /// frame head or payload keeps the tail and waits for more bytes; the
    /// buffer bound turns an oversized or garbage frame into the same
    /// fatal verdict a malformed SETTINGS earns.
    fn feedControl(self: *H3Session, data: []const u8) !void {
        if (data.len > self.control_rx.len - self.control_rx_len) return error.ControlOverflow;
        @memcpy(self.control_rx[self.control_rx_len..][0..data.len], data);
        self.control_rx_len += data.len;

        var offset: usize = 0;
        while (offset < self.control_rx_len) {
            const rest = self.control_rx[offset..self.control_rx_len];
            const parsed = Http3.FrameHeader.parse(rest) catch break; // wait for more bytes
            const frame_end = parsed.consumed + @as(usize, @intCast(parsed.header.length));
            if (frame_end > rest.len) break; // partial payload
            const payload = rest[parsed.consumed..frame_end];
            offset += frame_end;
            // The frame is consumed before it is applied, so a SETTINGS
            // error does not leave a parsed frame in the buffer to be
            // re-parsed (and re-rejected) on the next datagram.
            self.consumeControlRx(offset);
            switch (parsed.header.frame_type) {
                .settings => try self.applyPeerSettings(payload),
                .goaway => self.draining = true,
                else => {},
            }
        }
    }

    /// Drop the consumed prefix of the control-stream buffer.
    fn consumeControlRx(self: *H3Session, consumed: usize) void {
        const rest = self.control_rx[consumed..self.control_rx_len];
        std.mem.copyForwards(u8, self.control_rx[0..rest.len], rest);
        self.control_rx_len = rest.len;
    }

    /// The peer's SETTINGS frame: pull the two QPACK terms and configure
    /// the response encoder. The capacity the encoder chooses is the
    /// peer's advertised maximum capped at this session's own bound, so
    /// per-connection table memory stays a fixed reservation regardless of
    /// what the client offers. Configuring stages a Set Dynamic Table
    /// Capacity instruction; it is flushed immediately so the peer's
    /// decoder sees the table state before any field section references
    /// it. A second SETTINGS frame is ignored (the encoder configures
    /// once), matching the single-settings rule the session's own
    /// advertisement follows.
    fn applyPeerSettings(self: *H3Session, payload: []const u8) !void {
        var offset: usize = 0;
        var max_table_capacity: u64 = 0;
        var blocked_streams: u64 = 0;
        while (offset < payload.len) {
            const id = request_stream.readVarint(payload[offset..]) catch return error.MalformedSettings;
            offset += id.len;
            const value = request_stream.readVarint(payload[offset..]) catch return error.MalformedSettings;
            offset += value.len;
            switch (id.value) {
                0x01 => max_table_capacity = value.value,
                0x07 => blocked_streams = value.value,
                else => {},
            }
        }
        if (!self.qpack_encoder.configured) {
            const capacity = @min(max_table_capacity, qpack_max_table_capacity);
            try self.qpack_encoder.configure(
                capacity,
                @min(blocked_streams, qpack_encoder_blocked_cap),
            );
            try self.flushEncoderStream();
        }
    }

    /// QPACK is poisoned: refuse every dynamic-table reference from here
    /// on. Two teardowns, by cause. Peer faults — an encoder instruction
    /// outside its advertised budget, a malformed one, or an impossible
    /// decoder instruction — earn a CONNECTION_CLOSE naming the failure
    /// (RFC 9114 §8: `0x0201` decompression / `0x0202` encompression), so
    /// a conforming client learns why instead of timing out; the tables
    /// are desynchronized, so nothing gentler is honest. Local limits —
    /// a reassembly buffer full because the peer sent more than the
    /// table could ever hold, or an allocation failure — stay silent:
    /// the peer may be mid-instruction and blameless, and §10.2.2
    /// forbids a close frame that names a code the peer did not earn.
    fn abortQpack(self: *H3Session) void {
        self.qpackFailedSilent();
        if (self.conn) |conn| conn.abort();
    }

    /// The peer-fault variant: same poisoning, plus the parting frame.
    /// After `closeWithError` the closing state keeps answering inbound
    /// datagrams with close retransmissions until the peer goes quiet,
    /// so a client that keeps talking learns the verdict promptly.
    fn failQpackPeer(self: *H3Session, error_code: u64) void {
        self.qpackFailedSilent();
        if (self.conn) |conn| conn.closeWithError(error_code, "qpack fault");
    }

    fn qpackFailedSilent(self: *H3Session) void {
        self.qpack_failed = true;
    }

    /// Apply the peer's encoder-stream instructions to the decode table.
    /// Complete instructions are consumed one at a time; the tail of a
    /// split instruction stays in `qpack_rx` for the next datagram. Every
    /// applied insert is confirmed with one Insert Count Increment on the
    /// decoder stream, which is what lets the peer start referencing new
    /// entries within its blocked-stream budget.
    fn feedPeerEncoder(self: *H3Session, data: []const u8) void {
        if (self.qpack_failed) return;
        if (data.len > self.qpack_rx.len - self.qpack_rx_len) {
            // Local limit, not a peer fault: the buffer holds any single
            // legal instruction, so arriving full means the peer sent
            // more than the table could ever hold — but it may be a
            // split of one huge insert it believed legal on a bigger
            // table, so no close frame names it (§10.2.2's rule against
            // punishing blameless peers).
            self.abortQpack();
            return;
        }
        @memcpy(self.qpack_rx[self.qpack_rx_len..][0..data.len], data);
        self.qpack_rx_len += data.len;

        const inserts_before = self.qpack_decoder.insertCount();
        var offset: usize = 0;
        while (offset < self.qpack_rx_len) {
            const applied = qpack.applyEncoderInstruction(
                &self.qpack_decoder,
                self.qpack_rx[0..self.qpack_rx_len],
                offset,
            ) catch {
                // Every error the codec can raise here is a peer fault:
                // capacity above the advertised maximum, an entry larger
                // than the table, a bad name-reference index, invalid
                // Huffman, an insert that would evict a referenced entry
                // — the encoder wrote bytes outside the session's own
                // SETTINGS. (The set has no local-limit member; the
                // decoder allocates from the startup arena, and an
                // OutOfMemory there is a build-time misbudget, outside
                // what a peer's bytes may trigger.) RFC 9204 §4.3 makes
                // it a connection error, and the frame says which.
                self.failQpackPeer(connection.h3_qpack_decompression_failed);
                return;
            };
            switch (applied) {
                .applied => |done| offset = done.end,
                .incomplete => break,
                .invalid => {
                    // A truncated or otherwise malformed instruction on
                    // the wire — also the encoder's bytes, also §4.3.
                    self.failQpackPeer(connection.h3_qpack_decompression_failed);
                    return;
                },
            }
        }
        self.consumeQpackRx(offset);
        const applied_inserts = self.qpack_decoder.insertCount() - inserts_before;
        if (applied_inserts > 0) {
            self.sendDecoderInstruction(.{
                .insert_count_increment = applied_inserts,
            });
            // New entries may unblock parked sections; retry before any
            // further input is handled, so a request that waited decodes
            // at the earliest possible moment.
            self.retryParkedBlocks();
        }
    }

    /// Drop the consumed prefix of the peer-encoder reassembly buffer.
    fn consumeQpackRx(self: *H3Session, consumed: usize) void {
        const rest = self.qpack_rx[consumed..self.qpack_rx_len];
        std.mem.copyForwards(u8, self.qpack_rx[0..rest.len], rest);
        self.qpack_rx_len = rest.len;
    }

    /// Feed the peer's decoder-stream instructions (Insert Count
    /// Increment, Section Acknowledgment, Stream Cancellation) to the
    /// response encoder. ls-qpack-class peers send these promptly; a
    /// violation — an increment of zero, an ack with no outstanding
    /// section — is a connection error (RFC 9204 §4.4), and like every
    /// peer fault here it earns the frame that says so.
    fn feedPeerDecoder(self: *H3Session, data: []const u8) void {
        if (self.qpack_failed) return;
        if (data.len > self.decoder_rx.len - self.decoder_rx_len) {
            // Local limit again (the buffer spans any legal burst), so
            // silent, on the same terms as the encoder side.
            self.abortQpack();
            return;
        }
        @memcpy(self.decoder_rx[self.decoder_rx_len..][0..data.len], data);
        self.decoder_rx_len += data.len;

        var offset: usize = 0;
        while (offset < self.decoder_rx_len) {
            switch (qpack.scanDecoderInstruction(self.decoder_rx[0..self.decoder_rx_len], offset)) {
                .complete => |done| {
                    offset = done.end;
                    switch (done.instruction) {
                        .insert_count_increment => self.qpack_encoder.onInsertCountIncrement(done.value) catch {
                            // An ICI of zero, or larger than the inserts
                            // the peer has not acknowledged: its own
                            // accounting is broken (RFC 9204 §4.4.1).
                            self.failQpackPeer(connection.h3_qpack_encompression_failed);
                            return;
                        },
                        .section_acknowledgment => self.qpack_encoder.onSectionAcknowledgment(done.value) catch {
                            // An ack for a stream with no outstanding
                            // dynamic reference (RFC 9204 §4.4.2).
                            self.failQpackPeer(connection.h3_qpack_encompression_failed);
                            return;
                        },
                        .stream_cancellation => self.qpack_encoder.onStreamCancellation(done.value),
                    }
                },
                .incomplete => break,
                .invalid => {
                    // Malformed decoder instruction bytes.
                    self.failQpackPeer(connection.h3_qpack_encompression_failed);
                    return;
                },
            }
        }
        const rest = self.decoder_rx[offset..self.decoder_rx_len];
        std.mem.copyForwards(u8, self.decoder_rx[0..rest.len], rest);
        self.decoder_rx_len = rest.len;
    }

    /// Serialize one decoder-stream instruction onto the server decoder
    /// stream (id 11). Writes are tiny (at most 11 bytes) and ride a
    /// single transport send; a failure here is swallowed because the
    /// session's other writes surface the transport's state first.
    fn sendDecoderInstruction(self: *H3Session, instruction: qpack.DecoderInstructionValue) void {
        var buf: [qpack.max_decoder_instruction_len]u8 = undefined;
        const n = qpack.writeDecoderInstruction(&buf, instruction) catch return;
        self.sender.send(self.sender.ctx, qpack_decoder_stream_id, buf[0..n], false) catch {};
    }

    /// Drain staged encoder-stream instructions onto the server encoder
    /// stream (id 7). The bytes must reach the peer strictly before any
    /// HEADERS block that references them, so the response paths flush
    /// inside the encode callback, ahead of the HEADERS send. A multi-send
    /// sender may short-write; the consumed prefix is dropped so a stalled
    /// flush is resumed, never repeated.
    fn flushEncoderStream(self: *H3Session) !void {
        var rest = self.qpack_encoder.pendingInstructions();
        while (rest.len > 0) {
            if (self.sender.send_multi) |send_multi| {
                const queued = try send_multi(self.sender.ctx, qpack_encoder_stream_id, rest, false);
                if (queued == 0) return error.FlowControlBlocked;
                self.qpack_encoder.consumePendingInstructions(queued);
                rest = self.qpack_encoder.pendingInstructions();
            } else {
                try self.sender.send(self.sender.ctx, qpack_encoder_stream_id, rest, false);
                self.qpack_encoder.clearPendingInstructions();
                rest = self.qpack_encoder.pendingInstructions();
            }
        }
    }

    fn findUni(self: *H3Session, stream_id: u64) ?*UniEntry {
        for (&self.uni) |*entry| {
            if (entry.used and entry.id == stream_id) return entry;
        }
        for (&self.uni) |*entry| {
            if (entry.used) continue;
            entry.* = .{ .used = true, .id = stream_id };
            return entry;
        }
        return null;
    }

    /// The parser saw the QUIC stream's FIN. A request whose last frame
    /// already parsed completes here; anything else is a truncated or empty
    /// message, answered by dropping the stream.
    fn finishEntry(self: *H3Session, entry: *StreamEntry) FeedError!void {
        const event = entry.parser.finish() catch |err| {
            self.releaseEntry(entry);
            return mapParseError(err);
        };
        switch (event) {
            .complete => try self.completeEntry(entry),
            .need_more, .malformed => {
                self.releaseEntry(entry);
                return error.Malformed;
            },
            // `finish` only runs when the input stopped at a frame
            // boundary; head and chunk events fire from `feed`.
            .headers, .body => unreachable,
        }
    }

    fn findOrCreate(self: *H3Session, stream_id: u64) ?*StreamEntry {
        for (self.streams) |*entry| {
            if (entry.active and entry.stream_id == stream_id) return entry;
        }
        for (self.streams) |*entry| {
            if (entry.active) continue;
            entry.active = true;
            entry.stream_id = stream_id;
            entry.decoded_headers = null;
            entry.decoded_trailers = null;
            entry.keep = false;
            entry.head_sent = false;
            entry.pending_data = 0;
            entry.body_done = false;
            entry.fin_pending = false;
            entry.next_section = .headers;
            entry.parser = request_stream.RequestStream.initInPlace(&entry.codec, stream_id);
            return entry;
        }
        return null;
    }

    fn releaseEntry(self: *H3Session, entry: *StreamEntry) void {
        if (!entry.active) return;
        const released_id = entry.stream_id;
        if (entry.decoded_headers) |*list| {
            list.deinit();
            entry.decoded_headers = null;
        }
        if (entry.decoded_trailers) |*list| {
            list.deinit();
            entry.decoded_trailers = null;
        }
        entry.active = false;
        entry.keep = false;
        entry.head_sent = false;
        entry.pending_data = 0;
        entry.body_done = false;
        entry.fin_pending = false;
        entry.next_section = .headers;
        // The entry's parser (and its `parked` flag) resets with the next
        // `findOrCreate`; the queue itself must drop the reference now,
        // not on the next retry, or a recycled slot could momentarily
        // match a stale id. Bounded by `qpack_blocked_streams`.
        var index: u8 = 0;
        while (index < self.parked_len) {
            if (self.parked[index] == released_id) {
                var shift: u8 = index + 1;
                while (shift < self.parked_len) : (shift += 1) {
                    self.parked[shift - 1] = self.parked[shift];
                }
                self.parked_len -= 1;
                break;
            }
            index += 1;
        }
        entry.stream_id = 0;
        // A free request slot is one more stream the client may open. The
        // raise is best-effort: a connection that declines it (handshake
        // state, a full datagram queue) keeps its current ceiling, which
        // is always legal — the client only waits, never breaks.
        if (self.conn) |conn| conn.raiseBidiStreamLimit() catch {};
    }

    /// Retain the decoder's fields on the entry so the `Request`'s header
    /// slices stay valid for the exchange's life (until `sendResponse`/
    /// `abort` releases the slot). Only the first HEADERS block feeds the
    /// handler; a trailer block is validated by the parser and then only
    /// kept alive — never exposed. Blocks are decoded against
    /// `qpack_decoder`, which the peer's encoder stream keeps current; a
    /// block whose Required Insert Count exceeds the applied inserts is not
    /// a failure — the session advertises blocked streams, so the parser
    /// parks the section (`error.Blocked`) and `retryParkedBlocks` re-enters
    /// this callback once the inserts land. A decoded block with a nonzero
    /// Required Insert Count is acknowledged on the decoder stream (RFC
    /// 9204 §4.4.1) — the retry path included, unchanged — which is what
    /// finally releases the encoder-side reference to the entries it used.
    fn decodeCallback(
        ctx: *anyopaque,
        block: []const u8,
        out: []request_stream.Header,
    ) request_stream.Error!usize {
        const self: *H3Session = @ptrCast(@alignCast(ctx));
        const entry = self.decode_target orelse return error.CodecFailure;
        if (self.qpack_failed) {
            // The dynamic table is no longer trusted: refuse any block
            // that references it. Static-only blocks (Required Insert
            // Count 0) never touch the table and still decode.
            const ric = qpack.peekRequiredInsertCount(
                block,
                self.qpack_decoder.insertCount(),
                qpack_max_table_capacity,
            ) catch return error.CodecFailure;
            if (ric != 0) return error.CodecFailure;
        }
        var list = self.qpack_decoder.decodeBlock(block) catch |err| switch (err) {
            error.Blocked => return error.Blocked,
            else => return error.CodecFailure,
        };
        if (list.fields.len > out.len) {
            list.deinit();
            return error.TooManyHeaders;
        }

        switch (entry.next_section) {
            .headers => {
                if (entry.decoded_headers) |*old| old.deinit();
                entry.decoded_headers = list;
                entry.next_section = .trailers;
            },
            .trailers => {
                // Trailer fields never reach the handler (`Request.trailers`
                // is always empty), but the parser validates the decoded
                // slices right after this callback returns, so the list
                // must stay alive until the entry goes.
                if (entry.decoded_trailers) |*old| old.deinit();
                entry.decoded_trailers = list;
            },
        }

        if (list.required_insert_count > 0) {
            self.sendDecoderInstruction(.{ .section_acknowledgment = entry.stream_id });
        }
        for (list.fields, out[0..list.fields.len]) |field, *header| {
            header.* = .{ .name = field.name, .value = field.value };
        }
        return list.fields.len;
    }

    /// The response encoder. With the client SETTINGS seen, `qpack_encoder`
    /// emits dynamic field sections: repeated sizable headers go into the
    /// table, the matching encoder-stream instructions are staged, and the
    /// block references entries the peer has acknowledged (or can afford
    /// to block on). The staged instructions flush onto stream 7 inside
    /// this callback, ahead of the HEADERS send the caller performs with
    /// the returned block. Until SETTINGS arrive the encoder stays
    /// unconfigured and responses use the vendor's static-table encoding —
    /// legal against any peer, and the only correct answer to a peer that
    /// advertised no dynamic capacity.
    fn encodeCallback(
        ctx: *anyopaque,
        headers: []const request_stream.Header,
        out: []u8,
    ) request_stream.Error![]const u8 {
        const self: *H3Session = @ptrCast(@alignCast(ctx));
        if (headers.len > request_stream.headers_max + 1) return error.TooManyHeaders;
        if (self.qpack_failed) return error.CodecFailure;

        // QPACK field names are lowercase (RFC 9204 §4.1); an HTTP/1.1
        // origin and a careless handler both spell them with capitals.
        var name_buf: [8 * 1024]u8 = undefined;
        var name_len: usize = 0;
        var fields: [request_stream.headers_max + 1]qpack.HeaderField = undefined;
        for (headers, 0..) |header, index| {
            var name = header.name;
            var has_upper = false;
            for (name) |ch| {
                if (std.ascii.isUpper(ch)) {
                    has_upper = true;
                    break;
                }
            }
            if (has_upper) {
                if (name.len > name_buf.len - name_len) return error.TooManyHeaders;
                const lower = name_buf[name_len..][0..name.len];
                for (name, 0..) |ch, position| lower[position] = std.ascii.toLower(ch);
                name = lower;
                name_len += name.len;
            }
            fields[index] = .{ .name = name, .value = header.value };
        }

        if (self.qpack_encoder.configured) {
            const stream_id = self.encode_target orelse return error.CodecFailure;
            const encoded = self.qpack_encoder.encodeSection(
                self.allocator,
                stream_id,
                fields[0..headers.len],
            ) catch return error.CodecFailure;
            defer self.allocator.free(encoded);
            self.flushEncoderStream() catch return error.CodecFailure;

            if (encoded.len > out.len) return error.OutputTooSmall;
            @memcpy(out[0..encoded.len], encoded);
            return out[0..encoded.len];
        }

        const encoded = qpack.encode(self.allocator, fields[0..headers.len]) catch
            return error.CodecFailure;
        defer self.allocator.free(encoded);

        if (encoded.len > out.len) return error.OutputTooSmall;
        @memcpy(out[0..encoded.len], encoded);
        return out[0..encoded.len];
    }
};

const UniKind = enum { unknown, control, qpack_encoder, qpack_decoder, other };

const UniEntry = struct {
    used: bool = false,
    id: u64 = 0,
    kind: UniKind = .unknown,
};

const StreamEntry = struct {
    active: bool = false,
    /// Set by `deferRequest`: the handler owns the entry until `sendResponse` or
    /// `abort`, because the upstream exchange outlives the callback.
    keep: bool = false,
    stream_id: u64 = 0,
    /// Set once `sendResponseHead`'s HEADERS send succeeded. `sendData`
    /// refuses streams without it, and the slot stays pinned (like `keep`)
    /// until the fin chunk queues or `abortStream` runs.
    head_sent: bool = false,
    /// Payload bytes still owed to a DATA frame whose send short-wrote. A
    /// retry's leading bytes continue the open frame headerless; bytes
    /// past the remainder drain it and begin a new DATA frame in the same
    /// call.
    pending_data: usize = 0,
    /// Set once the request body is fully received (FIN or trailers). Until
    /// then the entry must stay active to keep parsing the upload, even if
    /// the response already went out.
    body_done: bool = false,
    /// FIN arrived while the head section was QPACK-parked: completing the
    /// exchange waits for `retryParkedBlocks` to resolve the section.
    fin_pending: bool = false,
    parser: request_stream.RequestStream = undefined,
    codec: request_stream.Codec = undefined,
    decoded_headers: ?qpack.HeaderList = null,
    /// Trailer blocks validate through the parser but are never handed to
    /// the handler; the list is retained only so its decoded slices stay
    /// alive for that validation, and dies with the entry.
    decoded_trailers: ?qpack.HeaderList = null,
    next_section: Section = .headers,

    const Section = enum { headers, trailers };
};

fn mapParseError(err: request_stream.Error) FeedError {
    return switch (err) {
        error.HeaderBlockTooLarge,
        error.TooManyHeaders,
        error.VarintOverflow,
        => error.RequestTooLarge,
        error.CodecFailure => error.CodecFailure,
        // `feed` intercepts Blocked for parking before mapping; reaching
        // this arm means the guard slipped.
        error.Blocked => unreachable,
        else => error.Malformed,
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const FakeSender = struct {
    const Send = struct {
        stream_id: u64 = 0,
        len: usize = 0,
        fin: bool = false,
        bytes: [response_bytes_max]u8 = undefined,
    };

    /// One `send_multi` offer: `len` is the framed slice offered, `queued`
    /// the (possibly short) byte count returned to the session.
    const MultiSend = struct {
        stream_id: u64 = 0,
        len: usize = 0,
        fin: bool = false,
        queued: usize = 0,
        bytes: [response_bytes_max]u8 = undefined,
    };

    sends: [16]Send = undefined,
    count: usize = 0,
    multi_sends: [16]MultiSend = undefined,
    multi_count: usize = 0,
    /// When set, `sendMulti` queues at most this many bytes of the offered
    /// slice — a scripted short write. Null queues everything.
    multi_queue_cap: ?usize = null,

    fn interface(self: *FakeSender) Sender {
        return .{ .ctx = self, .send = send };
    }

    fn interfaceMulti(self: *FakeSender) Sender {
        return .{ .ctx = self, .send = send, .send_multi = sendMulti };
    }

    fn send(ctx: *anyopaque, stream_id: u64, data: []const u8, fin: bool) anyerror!void {
        const self: *FakeSender = @ptrCast(@alignCast(ctx));
        if (self.count == self.sends.len) return error.TooManySends;
        if (data.len > response_bytes_max) return error.SendTooLarge;
        self.sends[self.count] = .{ .stream_id = stream_id, .len = data.len, .fin = fin };
        @memcpy(self.sends[self.count].bytes[0..data.len], data);
        self.count += 1;
    }

    fn sendMulti(ctx: *anyopaque, stream_id: u64, data: []const u8, fin: bool) anyerror!usize {
        const self: *FakeSender = @ptrCast(@alignCast(ctx));
        if (self.multi_count == self.multi_sends.len) return error.TooManySends;
        if (data.len > response_bytes_max) return error.SendTooLarge;
        const queued = @min(data.len, self.multi_queue_cap orelse data.len);
        self.multi_sends[self.multi_count] = .{
            .stream_id = stream_id,
            .len = data.len,
            .fin = fin,
            .queued = queued,
        };
        @memcpy(self.multi_sends[self.multi_count].bytes[0..data.len], data);
        self.multi_count += 1;
        return queued;
    }

    fn at(self: *const FakeSender, index: usize) *const Send {
        std.debug.assert(index < self.count);
        return &self.sends[index];
    }

    fn multiAt(self: *const FakeSender, index: usize) *const MultiSend {
        std.debug.assert(index < self.multi_count);
        return &self.multi_sends[index];
    }
};

const FakeHandler = struct {
    calls: usize = 0,
    respond: bool = true,
    body: [128 * 1024]u8 = undefined,
    body_len: usize = 0,
    /// Chunks delivered by `onBodyChunk`, and the fin marker's arrival.
    chunk_count: usize = 0,
    body_fin: bool = false,
    /// The body length `onRequest` itself reported: always zero, pinned by
    /// the streaming contract.
    head_body_len: usize = 1,
    /// The trailer count `onRequest` reported: always zero, trailers are
    /// parsed, validated and dropped.
    head_trailers_len: usize = 1,
    /// `onAborted` invocations: peer resets only.
    aborts: usize = 0,
    method: [16]u8 = undefined,
    method_len: usize = 0,
    path: [64]u8 = undefined,
    path_len: usize = 0,
    /// The last regular header the handler saw, truncated to the buffers.
    header_name: [64]u8 = undefined,
    header_name_len: usize = 0,
    header_value: [128]u8 = undefined,
    header_value_len: usize = 0,
    response_status: u16 = 200,
    response_body: []const u8 = "ok",
    response_fin: bool = true,
    last_error: ?anyerror = null,

    fn interface(self: *FakeHandler) RequestHandler {
        return .{
            .ctx = self,
            .onRequest = onRequest,
            .onBodyChunk = onBodyChunk,
            .onAborted = onAborted,
        };
    }

    fn onRequest(
        ctx: *anyopaque,
        session: *H3Session,
        stream_id: u64,
        request: *const request_stream.Request,
    ) void {
        const self: *FakeHandler = @ptrCast(@alignCast(ctx));
        self.calls += 1;
        self.method_len = @min(request.method.len, self.method.len);
        @memcpy(self.method[0..self.method_len], request.method[0..self.method_len]);
        self.path_len = @min(request.path.len, self.path.len);
        @memcpy(self.path[0..self.path_len], request.path[0..self.path_len]);
        self.head_body_len = request.body.len;
        self.head_trailers_len = request.trailers.len;
        if (request.headers.len > 0) {
            const last = request.headers[request.headers.len - 1];
            self.header_name_len = @min(last.name.len, self.header_name.len);
            @memcpy(self.header_name[0..self.header_name_len], last.name[0..self.header_name_len]);
            self.header_value_len = @min(last.value.len, self.header_value.len);
            @memcpy(self.header_value[0..self.header_value_len], last.value[0..self.header_value_len]);
        }
        if (!self.respond) return;
        session.sendResponse(
            stream_id,
            self.response_status,
            &.{},
            self.response_body,
            self.response_fin,
        ) catch |err| {
            self.last_error = err;
        };
    }

    fn onBodyChunk(
        ctx: *anyopaque,
        session: *H3Session,
        stream_id: u64,
        chunk: []const u8,
        fin: bool,
    ) anyerror!void {
        _ = session;
        _ = stream_id;
        const self: *FakeHandler = @ptrCast(@alignCast(ctx));
        if (chunk.len > self.body.len - self.body_len) return error.BodyOverflow;
        @memcpy(self.body[self.body_len..][0..chunk.len], chunk);
        self.body_len += chunk.len;
        self.chunk_count += 1;
        if (fin) self.body_fin = true;
    }

    fn onAborted(ctx: *anyopaque, session: *H3Session, stream_id: u64) void {
        _ = session;
        _ = stream_id;
        const self: *FakeHandler = @ptrCast(@alignCast(ctx));
        self.aborts += 1;
    }
};

fn appendFrame(out: []u8, used: *usize, frame_type: u64, payload: []const u8) !void {
    used.* += try request_stream.writeVarint(out[used.*..], frame_type);
    used.* += try request_stream.writeVarint(out[used.*..], payload.len);
    if (payload.len > out.len - used.*) return error.OutputTooSmall;
    @memcpy(out[used.*..][0..payload.len], payload);
    used.* += payload.len;
}

/// Build one QPACK HEADERS block carrying the standard request pseudo-headers.
fn requestBlock(out: []u8, allocator: std.mem.Allocator, path: []const u8) ![]const u8 {
    const fields = [_]qpack.HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "spike.zgix.test" },
        .{ .name = ":path", .value = path },
    };
    const block = try qpack.encode(allocator, &fields);
    defer allocator.free(block);
    if (block.len > out.len) return error.OutputTooSmall;
    @memcpy(out[0..block.len], block);
    return out[0..block.len];
}

fn headerBlock(out: []u8, allocator: std.mem.Allocator, name: []const u8, value: []const u8) ![]const u8 {
    const fields = [_]qpack.HeaderField{.{ .name = name, .value = value }};
    const block = try qpack.encode(allocator, &fields);
    defer allocator.free(block);
    if (block.len > out.len) return error.OutputTooSmall;
    @memcpy(out[0..block.len], block);
    return out[0..block.len];
}

fn requestWire(out: []u8, allocator: std.mem.Allocator, path: []const u8, body: []const u8) ![]const u8 {
    var block: [1024]u8 = undefined;
    const encoded = try requestBlock(&block, allocator, path);
    var used: usize = 0;
    try appendFrame(out, &used, request_stream.frame_type_headers, encoded);
    if (body.len > 0) try appendFrame(out, &used, request_stream.frame_type_data, body);
    return out[0..used];
}

fn decodeBlockCounts(block: []const u8, allocator: std.mem.Allocator) !usize {
    var list = try qpack.decode(allocator, block);
    defer list.deinit();
    return list.fields.len;
}

test "h3 session: a complete request produces one labeled response" {
    var sender = FakeSender{};
    var handler = FakeHandler{};
    var session: H3Session = undefined;
    try session.initInPlace(std.testing.allocator, sender.interface(), handler.interface());
    defer session.deinit();

    var wire: [1024]u8 = undefined;
    const request = try requestWire(&wire, std.testing.allocator, "/hello", "request-body");
    const sh = session.streamHandler();
    sh.onData(sh.ctx, 0, request, true);

    try std.testing.expectEqual(@as(usize, 1), handler.calls);
    try std.testing.expectEqualStrings("GET", handler.method[0..handler.method_len]);
    try std.testing.expectEqualStrings("/hello", handler.path[0..handler.path_len]);
    try std.testing.expectEqualStrings("request-body", handler.body[0..handler.body_len]);
    try std.testing.expectEqual(@as(usize, 0), handler.head_body_len);
    try std.testing.expect(handler.body_fin);
    try std.testing.expect(handler.last_error == null);

    // The handler responds synchronously; one transport send carries HEADERS
    // and DATA, and `fin` rides that send.
    try std.testing.expectEqual(@as(usize, 1), sender.count);
    const send = sender.at(0);
    try std.testing.expectEqual(@as(u64, 0), send.stream_id);
    try std.testing.expect(send.fin);

    const type_v = try request_stream.readVarint(send.bytes[0..send.len]);
    try std.testing.expectEqual(request_stream.frame_type_headers, type_v.value);
    const length_v = try request_stream.readVarint(send.bytes[type_v.len..send.len]);
    const block_start: usize = type_v.len + length_v.len;
    const block_end = block_start + @as(usize, @intCast(length_v.value));
    try std.testing.expect(block_end <= send.len);

    const data_type = try request_stream.readVarint(send.bytes[block_end..send.len]);
    try std.testing.expectEqual(request_stream.frame_type_data, data_type.value);
    const data_len = try request_stream.readVarint(send.bytes[block_end + data_type.len .. send.len]);
    const data_start = block_end + data_type.len + data_len.len;
    try std.testing.expectEqualStrings(
        "ok",
        send.bytes[data_start..][0..@intCast(data_len.value)],
    );

    // A fresh decoder sees the response header block the same way a client
    // would: `:status` first, then the regular headers.
    var decoded = try qpack.decode(std.testing.allocator, send.bytes[block_start..block_end]);
    defer decoded.deinit();
    const fields = decoded.fields;
    try std.testing.expect(fields.len >= 1);
    try std.testing.expectEqualStrings(":status", fields[0].name);
    try std.testing.expectEqualStrings("200", fields[0].value);
}

test "h3 session: a request split across two feeds is delivered once" {
    var sender = FakeSender{};
    var handler = FakeHandler{ .respond = false };
    var session: H3Session = undefined;
    try session.initInPlace(std.testing.allocator, sender.interface(), handler.interface());
    defer session.deinit();

    var wire: [1024]u8 = undefined;
    const request = try requestWire(&wire, std.testing.allocator, "/split", "half-and-half");
    const split = request.len / 2;
    const sh = session.streamHandler();
    // The first half lands mid-header-block: nothing is deliverable yet.
    sh.onData(sh.ctx, 4, request[0..split], false);
    sh.onData(sh.ctx, 4, request[split..], true);

    // Exactly one delivery: the head when the HEADERS frame completed, the
    // body as chunks after it, the slot released at FIN.
    try std.testing.expectEqual(@as(usize, 1), handler.calls);
    try std.testing.expectEqualStrings("/split", handler.path[0..handler.path_len]);
    try std.testing.expectEqualStrings("half-and-half", handler.body[0..handler.body_len]);
    try std.testing.expect(handler.body_fin);
    try std.testing.expectEqual(@as(usize, 0), activeEntries(&session));
}

test "h3 session: headers are delivered before the body arrives" {
    var sender = FakeSender{};
    var handler = FakeHandler{ .respond = false };
    var session: H3Session = undefined;
    try session.initInPlace(std.testing.allocator, sender.interface(), handler.interface());
    defer session.deinit();

    var head_wire: [1024]u8 = undefined;
    const head = try requestWire(&head_wire, std.testing.allocator, "/early-head", "");
    const sh = session.streamHandler();
    // Headers only, no FIN: the handler sees the request now, body or not.
    sh.onData(sh.ctx, 0, head, false);
    try std.testing.expectEqual(@as(usize, 1), handler.calls);
    try std.testing.expectEqualStrings("/early-head", handler.path[0..handler.path_len]);
    try std.testing.expectEqual(@as(usize, 0), handler.head_body_len);
    try std.testing.expectEqual(@as(usize, 1), activeEntries(&session));

    // The body frame arrives afterwards, in its own feed.
    var body_wire: [64]u8 = undefined;
    var body_used: usize = 0;
    try appendFrame(&body_wire, &body_used, request_stream.frame_type_data, "later");
    sh.onData(sh.ctx, 0, body_wire[0..body_used], false);
    try std.testing.expectEqualStrings("later", handler.body[0..handler.body_len]);
    try std.testing.expect(!handler.body_fin);

    sh.onData(sh.ctx, 0, &.{}, true);
    try std.testing.expect(handler.body_fin);
    try std.testing.expectEqual(@as(usize, 0), activeEntries(&session));
}

test "h3 session: a synchronous response does not swallow the uploading body" {
    var sender = FakeSender{};
    var handler = FakeHandler{}; // answers inside onRequest
    var session: H3Session = undefined;
    try session.initInPlace(std.testing.allocator, sender.interface(), handler.interface());
    defer session.deinit();

    var wire: [1024]u8 = undefined;
    const request = try requestWire(&wire, std.testing.allocator, "/early", "tail");
    const sh = session.streamHandler();
    sh.onData(sh.ctx, 0, request, true);

    // The response went out at the head, and the body chunks — plus the fin
    // marker — still reached the handler afterwards.
    try std.testing.expectEqual(@as(usize, 1), sender.count);
    try std.testing.expect(sender.at(0).fin);
    try std.testing.expectEqualSlices(u8, "tail", handler.body[0..handler.body_len]);
    try std.testing.expect(handler.body_fin);
    try std.testing.expectEqual(@as(usize, 0), activeEntries(&session));
}

test "h3 session: a body over the old 64 KiB cap delivers whole" {
    var sender = FakeSender{};
    var handler = FakeHandler{ .respond = false };
    var session: H3Session = undefined;
    try session.initInPlace(std.testing.allocator, sender.interface(), handler.interface());
    defer session.deinit();

    // 100 KiB where a 64 KiB buffer used to error: the stream control window
    // is the only bound now.
    const body_len = 100 * 1024;
    var body: [body_len]u8 = undefined;
    for (&body, 0..) |*byte, index| byte.* = @truncate(index *% 13 + 5);

    var wire: [body_len + 1024]u8 = undefined;
    const request = try requestWire(&wire, std.testing.allocator, "/upload", &body);
    const sh = session.streamHandler();
    // Feed the wire in thirds so the body surfaces as multiple chunks.
    var offset: usize = 0;
    while (offset < request.len) {
        const end = @min(offset + request.len / 3 + 1, request.len);
        const fin = end == request.len;
        sh.onData(sh.ctx, 0, request[offset..end], fin);
        offset = end;
    }

    try std.testing.expectEqual(@as(usize, 1), handler.calls);
    try std.testing.expectEqual(body_len, handler.body_len);
    try std.testing.expectEqualSlices(u8, &body, handler.body[0..handler.body_len]);
    try std.testing.expect(handler.body_fin);
    try std.testing.expectEqual(@as(usize, 0), activeEntries(&session));
}

test "h3 session: a peer reset frees the entry and notifies the handler" {
    var sender = FakeSender{};
    var handler = FakeHandler{ .respond = false };
    var session: H3Session = undefined;
    try session.initInPlace(std.testing.allocator, sender.interface(), handler.interface());
    defer session.deinit();

    var wire: [1024]u8 = undefined;
    const request = try requestWire(&wire, std.testing.allocator, "/reset-me", "");
    const sh = session.streamHandler();
    // Headers delivered, upload unfinished: the slot is held.
    sh.onData(sh.ctx, 4, request, false);
    try std.testing.expectEqual(@as(usize, 1), handler.calls);
    try std.testing.expectEqual(@as(usize, 1), activeEntries(&session));

    // The connection's reset hook (agent C's on_reset) fires: the entry is
    // gone and the handler heard about it, exactly once.
    const on_reset = sh.on_reset orelse return error.MissingOnReset;
    on_reset(sh.ctx, 4);
    try std.testing.expectEqual(@as(usize, 0), activeEntries(&session));
    try std.testing.expectEqual(@as(usize, 1), handler.aborts);
    try std.testing.expect(!handler.body_fin);

    // A reset for a stream that never opened is a no-op, and the freed slot
    // serves a fresh exchange end to end.
    on_reset(sh.ctx, 8);
    try std.testing.expectEqual(@as(usize, 1), handler.aborts);
    sh.onData(sh.ctx, 4, request, true);
    try std.testing.expectEqual(@as(usize, 2), handler.calls);
    try std.testing.expect(handler.body_fin);
    try std.testing.expectEqual(@as(usize, 0), activeEntries(&session));
}

const NoBodyHandler = struct {
    calls: usize = 0,

    fn interface(self: *NoBodyHandler) RequestHandler {
        return .{ .ctx = self, .onRequest = onRequest };
    }

    fn onRequest(
        ctx: *anyopaque,
        session: *H3Session,
        stream_id: u64,
        request: *const request_stream.Request,
    ) void {
        _ = session;
        _ = stream_id;
        _ = request;
        const self: *NoBodyHandler = @ptrCast(@alignCast(ctx));
        self.calls += 1;
    }
};

test "h3 session: body bytes without an onBodyChunk subscription drop the stream" {
    var sender = FakeSender{};
    var handler = NoBodyHandler{};
    var session: H3Session = undefined;
    try session.initInPlace(std.testing.allocator, sender.interface(), handler.interface());
    defer session.deinit();

    // The head delivers fine; the body frame that follows is a protocol
    // error for a handler that never subscribed to body bytes.
    var wire: [1024]u8 = undefined;
    const request = try requestWire(&wire, std.testing.allocator, "/no-body-sub", "unexpected");
    try std.testing.expectError(error.Malformed, session.feed(0, request, false));
    try std.testing.expectEqual(@as(usize, 1), handler.calls);
    try std.testing.expectEqual(@as(usize, 0), activeEntries(&session));

    // The dropped slot is reusable, and a bodyless request on it is fine.
    const empty = try requestWire(&wire, std.testing.allocator, "/no-body-sub", "");
    try session.feed(4, empty, true);
    try std.testing.expectEqual(@as(usize, 2), handler.calls);
    try std.testing.expectEqual(@as(usize, 0), activeEntries(&session));
}

test "h3 session: trailers are dropped and the request still completes" {
    var sender = FakeSender{};
    var handler = FakeHandler{ .respond = false };
    var session: H3Session = undefined;
    try session.initInPlace(std.testing.allocator, sender.interface(), handler.interface());
    defer session.deinit();

    var wire: [1024]u8 = undefined;
    const request = try requestWire(&wire, std.testing.allocator, "/trailers", "body");
    var used = request.len;
    var trailer_buf: [128]u8 = undefined;
    const trailer = try headerBlock(&trailer_buf, std.testing.allocator, "x-trailer", "done");
    try appendFrame(&wire, &used, request_stream.frame_type_headers, trailer);

    // No FIN: the trailing HEADERS section is the completion signal.
    const sh = session.streamHandler();
    sh.onData(sh.ctx, 8, wire[0..used], false);
    try std.testing.expectEqual(@as(usize, 1), handler.calls);
    try std.testing.expectEqualStrings("body", handler.body[0..handler.body_len]);
    try std.testing.expectEqual(@as(usize, 0), handler.head_trailers_len);
    try std.testing.expect(handler.body_fin);
    try std.testing.expectEqual(@as(usize, 0), activeEntries(&session));

    // The FIN that follows a trailers-completed message is a no-op, not a
    // second completion.
    sh.onData(sh.ctx, 8, &.{}, true);
    try std.testing.expectEqual(@as(usize, 1), handler.calls);
}

test "h3 session: unknown frames before HEADERS are skipped" {
    var sender = FakeSender{};
    var handler = FakeHandler{ .respond = false };
    var session: H3Session = undefined;
    try session.initInPlace(std.testing.allocator, sender.interface(), handler.interface());
    defer session.deinit();

    var wire: [1024]u8 = undefined;
    var used: usize = 0;
    try appendFrame(&wire, &used, 0x21, "grease");
    var request_buf: [1024]u8 = undefined;
    const request = try requestWire(&request_buf, std.testing.allocator, "/greased", "x");
    @memcpy(wire[used..][0..request.len], request);
    used += request.len;

    const sh = session.streamHandler();
    sh.onData(sh.ctx, 12, wire[0..used], true);
    try std.testing.expectEqual(@as(usize, 1), handler.calls);
    try std.testing.expectEqualStrings("/greased", handler.path[0..handler.path_len]);
    try std.testing.expectEqualStrings("x", handler.body[0..handler.body_len]);
}

test "h3 session: the ninth concurrent request stream is dropped" {
    var sender = FakeSender{};
    var handler = FakeHandler{ .respond = false };
    var session: H3Session = undefined;
    try session.initInPlace(std.testing.allocator, sender.interface(), handler.interface());
    defer session.deinit();

    var wire: [1024]u8 = undefined;
    const request = try requestWire(&wire, std.testing.allocator, "/many", "");
    const sh = session.streamHandler();

    // Nine opens without FIN: the first eight deliver their heads and hold
    // their slots (a request is not complete until its body is); the ninth
    // is past the ceiling and never reaches the handler.
    var index: u64 = 0;
    while (index <= H3Session.streams_max) : (index += 1) {
        sh.onData(sh.ctx, index * 4, request, false);
    }
    try std.testing.expectEqual(H3Session.streams_max, handler.calls);
    try std.testing.expectEqual(H3Session.streams_max, activeEntries(&session));

    // FIN completes each held request; with no deferred exchange the slots
    // free on completion.
    index = 0;
    while (index < H3Session.streams_max) : (index += 1) {
        sh.onData(sh.ctx, index * 4, &.{}, true);
    }
    try std.testing.expectEqual(H3Session.streams_max, handler.calls);
    try std.testing.expectEqual(@as(usize, 0), activeEntries(&session));

    // The freed slots serve fresh streams again.
    sh.onData(sh.ctx, 0, request, true);
    try std.testing.expectEqual(H3Session.streams_max + 1, handler.calls);
}

test "h3 session: control streams are sent once" {
    var sender = FakeSender{};
    var handler = FakeHandler{ .respond = false };
    var session: H3Session = undefined;
    try session.initInPlace(std.testing.allocator, sender.interface(), handler.interface());
    defer session.deinit();

    try session.sendControl();
    try std.testing.expectEqual(@as(usize, 3), sender.count);

    const control = sender.at(0);
    try std.testing.expectEqual(control_stream_id, control.stream_id);
    try std.testing.expect(!control.fin);
    // SETTINGS advertises a 4096-byte QPACK dynamic table (0x01, two-byte
    // varint 0x5000) and 16 blocked streams (0x07, 0x10): 5 payload
    // bytes on a 2-byte frame header after the stream-type byte.
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0x00, 0x04, 0x05, 0x01, 0x50, 0x00, 0x07, 0x10 },
        control.bytes[0..control.len],
    );

    const qpack_encoder = sender.at(1);
    try std.testing.expectEqual(qpack_encoder_stream_id, qpack_encoder.stream_id);
    try std.testing.expect(!qpack_encoder.fin);
    try std.testing.expectEqualSlices(u8, &.{0x02}, qpack_encoder.bytes[0..qpack_encoder.len]);

    const qpack_decoder = sender.at(2);
    try std.testing.expectEqual(qpack_decoder_stream_id, qpack_decoder.stream_id);
    try std.testing.expect(!qpack_decoder.fin);
    // RFC 9114 §6.2.3: the decoder stream is type 0x03.
    try std.testing.expectEqualSlices(u8, &.{0x03}, qpack_decoder.bytes[0..qpack_decoder.len]);

    try session.sendControl();
    try std.testing.expectEqual(@as(usize, 3), sender.count);
}

test "h3 session: client SETTINGS and GOAWAY are consumed, not requests" {
    var sender = FakeSender{};
    var handler = FakeHandler{ .respond = false };
    var session: H3Session = undefined;
    try session.initInPlace(std.testing.allocator, sender.interface(), handler.interface());
    defer session.deinit();
    const sh = session.streamHandler();

    // Stream 2 is client-initiated unidirectional: type 0x00 (control)
    // followed by an empty SETTINGS frame.
    sh.onData(sh.ctx, 2, &.{ 0x00, 0x04, 0x00 }, false);
    try std.testing.expectEqual(@as(usize, 0), handler.calls);
    try std.testing.expect(!session.isDraining());

    // Stream 6: the type byte arrives first, then a GOAWAY frame
    // (type 0x07, length 1, stream id 0).
    sh.onData(sh.ctx, 6, &.{0x00}, false);
    sh.onData(sh.ctx, 6, &.{ 0x07, 0x01, 0x00 }, false);
    try std.testing.expect(session.isDraining());

    // After GOAWAY a new client bidi request is refused without reaching
    // the handler.
    var wire: [1024]u8 = undefined;
    const request = try requestWire(&wire, std.testing.allocator, "/after", "");
    sh.onData(sh.ctx, 0, request, true);
    try std.testing.expectEqual(@as(usize, 0), handler.calls);
}

test "h3 session: an empty body puts fin on the HEADERS send" {
    var sender = FakeSender{};
    var handler = FakeHandler{ .respond = false };
    var session: H3Session = undefined;
    try session.initInPlace(std.testing.allocator, sender.interface(), handler.interface());
    defer session.deinit();

    try session.sendResponse(9, 204, &.{}, &.{}, true);
    try std.testing.expectEqual(@as(usize, 1), sender.count);
    const send = sender.at(0);
    try std.testing.expectEqual(@as(u64, 9), send.stream_id);
    try std.testing.expect(send.fin);

    const type_v = try request_stream.readVarint(send.bytes[0..send.len]);
    try std.testing.expectEqual(request_stream.frame_type_headers, type_v.value);
    const length_v = try request_stream.readVarint(send.bytes[type_v.len..send.len]);
    const block_start: usize = type_v.len + length_v.len;
    const block_end = block_start + @as(usize, @intCast(length_v.value));
    // The HEADERS frame is the whole send: no empty DATA frame follows.
    try std.testing.expectEqual(send.len, block_end);
    // HEADERS carries exactly `:status`; no regular headers were passed.
    try std.testing.expectEqual(@as(usize, 1), try decodeBlockCounts(
        send.bytes[block_start..block_end],
        std.testing.allocator,
    ));
}

test "h3 session: a malformed header block frees the stream" {
    var sender = FakeSender{};
    var handler = FakeHandler{ .respond = false };
    var session: H3Session = undefined;
    try session.initInPlace(std.testing.allocator, sender.interface(), handler.interface());
    defer session.deinit();

    var wire: [16]u8 = undefined;
    var used: usize = 0;
    try appendFrame(&wire, &used, request_stream.frame_type_headers, &.{0xff});
    const sh = session.streamHandler();
    sh.onData(sh.ctx, 0, wire[0..used], true);
    try std.testing.expectEqual(@as(usize, 0), handler.calls);

    // The slot was released: the same stream id can carry a new request.
    var request_buf: [1024]u8 = undefined;
    const request = try requestWire(&request_buf, std.testing.allocator, "/retry", "");
    sh.onData(sh.ctx, 0, request, true);
    try std.testing.expectEqual(@as(usize, 1), handler.calls);
    try std.testing.expectEqualStrings("/retry", handler.path[0..handler.path_len]);
}

test "h3 session: size and codec overflows are named errors" {
    var sender = FakeSender{};
    var handler = FakeHandler{ .respond = false };
    var session: H3Session = undefined;
    try session.initInPlace(std.testing.allocator, sender.interface(), handler.interface());
    defer session.deinit();

    // Declared header block larger than the parser's buffer.
    var header_wire: [16]u8 = undefined;
    var used: usize = 0;
    used += try request_stream.writeVarint(header_wire[used..], request_stream.frame_type_headers);
    used += try request_stream.writeVarint(
        header_wire[used..],
        request_stream.header_block_bytes_max + 1,
    );
    try std.testing.expectError(
        error.RequestTooLarge,
        session.feed(0, header_wire[0..used], false),
    );

    // More decoded headers than the request parser's array can hold. The
    // QPACK decoder itself allows 256, so the overflow is this layer's.
    var many: [request_stream.headers_max + 2]qpack.HeaderField = undefined;
    for (&many) |*field| field.* = .{ .name = "x", .value = "v" };
    const block = try qpack.encode(std.testing.allocator, &many);
    defer std.testing.allocator.free(block);

    var overflow_wire: [2048]u8 = undefined;
    used = 0;
    try appendFrame(&overflow_wire, &used, request_stream.frame_type_headers, block);
    try std.testing.expectError(
        error.RequestTooLarge,
        session.feed(4, overflow_wire[0..used], false),
    );

    // A response body that cannot fit the response buffer.
    const oversized: [response_bytes_max + 1]u8 = @splat(0);
    try std.testing.expectError(
        error.ResponseTooLarge,
        session.sendResponse(3, 200, &.{}, &oversized, true),
    );
}

test "h3 session: a codec failure drops only that stream" {
    var sender = FakeSender{};
    var handler = FakeHandler{ .respond = false };
    var session: H3Session = undefined;
    try session.initInPlace(std.testing.allocator, sender.interface(), handler.interface());
    defer session.deinit();

    var wire: [16]u8 = undefined;
    var used: usize = 0;
    try appendFrame(&wire, &used, request_stream.frame_type_headers, &.{0xff});
    try std.testing.expectError(error.CodecFailure, session.feed(0, wire[0..used], true));

    var request_buf: [1024]u8 = undefined;
    const request = try requestWire(&request_buf, std.testing.allocator, "/alive", "");
    try session.feed(4, request, true);
    try std.testing.expectEqual(@as(usize, 1), handler.calls);
    try std.testing.expectEqualStrings("/alive", handler.path[0..handler.path_len]);
}

const DeferHandler = struct {
    calls: usize = 0,
    body: [1024]u8 = undefined,
    body_len: usize = 0,
    body_fin: bool = false,

    fn interface(self: *DeferHandler) RequestHandler {
        return .{ .ctx = self, .onRequest = onRequest, .onBodyChunk = onBodyChunk };
    }

    fn onRequest(
        ctx: *anyopaque,
        session: *H3Session,
        stream_id: u64,
        request: *const request_stream.Request,
    ) void {
        _ = request;
        const self: *DeferHandler = @ptrCast(@alignCast(ctx));
        self.calls += 1;
        session.deferRequest(stream_id);
    }

    fn onBodyChunk(
        ctx: *anyopaque,
        session: *H3Session,
        stream_id: u64,
        chunk: []const u8,
        fin: bool,
    ) anyerror!void {
        _ = session;
        _ = stream_id;
        const self: *DeferHandler = @ptrCast(@alignCast(ctx));
        if (chunk.len > self.body.len - self.body_len) return error.BodyOverflow;
        @memcpy(self.body[self.body_len..][0..chunk.len], chunk);
        self.body_len += chunk.len;
        if (fin) self.body_fin = true;
    }
};

fn activeEntries(session: *H3Session) usize {
    var count: usize = 0;
    for (session.streams) |entry| {
        if (entry.active) count += 1;
    }
    return count;
}

test "h3 session: a deferred request is released by sendResponse" {
    var sender = FakeSender{};
    var handler = DeferHandler{};
    var session: H3Session = undefined;
    try session.initInPlace(std.testing.allocator, sender.interface(), handler.interface());
    defer session.deinit();

    var wire: [1024]u8 = undefined;
    const request = try requestWire(&wire, std.testing.allocator, "/deferred", "body");
    const sh = session.streamHandler();
    sh.onData(sh.ctx, 0, request, true);
    try std.testing.expectEqual(@as(usize, 1), handler.calls);
    try std.testing.expectEqual(@as(usize, 0), sender.count);
    try std.testing.expectEqual(@as(usize, 1), activeEntries(&session));

    // The asynchronous handler answers later; the slot is held until then.
    try session.sendResponse(0, 200, &.{}, "later", true);
    try std.testing.expectEqual(@as(usize, 1), sender.count);
    try std.testing.expectEqual(@as(usize, 0), activeEntries(&session));

    // The released slot is reusable for another deferred request.
    sh.onData(sh.ctx, 4, request, true);
    try std.testing.expectEqual(@as(usize, 2), handler.calls);
    try std.testing.expectEqual(@as(usize, 1), activeEntries(&session));
    try session.sendResponse(4, 200, &.{}, "later", true);
    try std.testing.expectEqual(@as(usize, 0), activeEntries(&session));
}

test "h3 session: abort releases a deferred request" {
    var sender = FakeSender{};
    var handler = DeferHandler{};
    var session: H3Session = undefined;
    try session.initInPlace(std.testing.allocator, sender.interface(), handler.interface());
    defer session.deinit();

    var wire: [1024]u8 = undefined;
    const request = try requestWire(&wire, std.testing.allocator, "/aborted", "");
    const sh = session.streamHandler();
    sh.onData(sh.ctx, 8, request, true);
    try std.testing.expectEqual(@as(usize, 1), activeEntries(&session));

    session.abort(8);
    try std.testing.expectEqual(@as(usize, 0), activeEntries(&session));
    try std.testing.expectEqual(@as(usize, 0), sender.count);
    // A second abort is a no-op, not a double release.
    session.abort(8);

    sh.onData(sh.ctx, 12, request, true);
    try std.testing.expectEqual(@as(usize, 1), activeEntries(&session));
    session.abort(12);
    try std.testing.expectEqual(@as(usize, 0), activeEntries(&session));
}

test "h3 session: a split response sends HEADERS once then DATA chunks with fin on the last" {
    var sender = FakeSender{};
    var handler = DeferHandler{};
    var session: H3Session = undefined;
    try session.initInPlace(std.testing.allocator, sender.interfaceMulti(), handler.interface());
    defer session.deinit();

    var wire: [1024]u8 = undefined;
    const request = try requestWire(&wire, std.testing.allocator, "/stream", "");
    const sh = session.streamHandler();
    sh.onData(sh.ctx, 0, request, true);
    try std.testing.expectEqual(@as(usize, 1), activeEntries(&session));

    // DATA before HEADERS is a named error, not a send.
    try std.testing.expectError(error.StreamReleased, session.sendData(0, "x", false));

    try session.sendResponseHead(0, 200, &.{.{ .name = "content-type", .value = "text/plain" }});
    try std.testing.expectEqual(@as(usize, 1), sender.count);
    try std.testing.expectEqual(@as(usize, 0), sender.multi_count);
    try std.testing.expectEqual(@as(usize, 1), activeEntries(&session));

    // The head send is a HEADERS frame, no fin, and decodes to :status
    // first — the same bytes a client would parse.
    const head = sender.at(0);
    try std.testing.expectEqual(@as(u64, 0), head.stream_id);
    try std.testing.expect(!head.fin);
    const head_type = try request_stream.readVarint(head.bytes[0..head.len]);
    try std.testing.expectEqual(request_stream.frame_type_headers, head_type.value);
    const head_len = try request_stream.readVarint(head.bytes[head_type.len..head.len]);
    const block_start = head_type.len + head_len.len;
    var decoded = try qpack.decode(
        std.testing.allocator,
        head.bytes[block_start..][0..@intCast(head_len.value)],
    );
    defer decoded.deinit();
    try std.testing.expectEqual(@as(usize, 2), decoded.fields.len);
    try std.testing.expectEqualStrings(":status", decoded.fields[0].name);
    try std.testing.expectEqualStrings("200", decoded.fields[0].value);

    // Three DATA chunks ride as three framed sends; only the last fin
    // releases the slot.
    try std.testing.expectEqual(@as(usize, 2), try session.sendData(0, "aa", false));
    try std.testing.expectEqual(@as(usize, 1), activeEntries(&session));
    try std.testing.expectEqual(@as(usize, 3), try session.sendData(0, "bbb", false));
    try std.testing.expectEqual(@as(usize, 1), activeEntries(&session));
    try std.testing.expectEqual(@as(usize, 1), try session.sendData(0, "c", true));
    try std.testing.expectEqual(@as(usize, 0), activeEntries(&session));

    try std.testing.expectEqual(@as(usize, 3), sender.multi_count);
    const chunks = [_][]const u8{ "aa", "bbb", "c" };
    for (chunks, 0..) |want, index| {
        const send = sender.multiAt(index);
        try std.testing.expectEqual(@as(u64, 0), send.stream_id);
        try std.testing.expectEqual(index == chunks.len - 1, send.fin);
        try std.testing.expectEqual(send.len, send.queued);
        const type_v = try request_stream.readVarint(send.bytes[0..send.len]);
        try std.testing.expectEqual(request_stream.frame_type_data, type_v.value);
        const length_v = try request_stream.readVarint(send.bytes[type_v.len..send.len]);
        try std.testing.expectEqual(want.len, length_v.value);
        const payload_start = type_v.len + length_v.len;
        try std.testing.expectEqualStrings(want, send.bytes[payload_start..][0..want.len]);
    }

    // The fin released the stream: DATA now answers the released error.
    try std.testing.expectError(error.StreamReleased, session.sendData(0, "more", false));
}

test "h3 session: a short-written DATA chunk keeps the slot until the retry completes the frame" {
    var sender = FakeSender{};
    var handler = DeferHandler{};
    var session: H3Session = undefined;
    try session.initInPlace(std.testing.allocator, sender.interfaceMulti(), handler.interface());
    defer session.deinit();

    var wire: [1024]u8 = undefined;
    const request = try requestWire(&wire, std.testing.allocator, "/stalled", "");
    const sh = session.streamHandler();
    sh.onData(sh.ctx, 0, request, true);

    try session.sendResponseHead(0, 200, &.{});
    try std.testing.expectEqual(@as(usize, 1), sender.count);

    // Script the backpressure: of the 13 framed bytes (a 2-byte DATA header
    // plus the 11-byte payload) the transport queues 7 — the fin-less
    // chunk reports 5 payload bytes and holds the slot.
    sender.multi_queue_cap = 7;
    const first = try session.sendData(0, "hello world", false);
    try std.testing.expectEqual(@as(usize, 5), first);
    try std.testing.expectEqual(@as(usize, 1), activeEntries(&session));
    const stalled = sender.multiAt(0);
    try std.testing.expect(!stalled.fin);
    try std.testing.expectEqual(@as(usize, 7), stalled.queued);
    // The frame header and the first five payload bytes are on the wire.
    try std.testing.expectEqualSlices(u8, &.{ 0x00, 0x0b }, stalled.bytes[0..2]);
    try std.testing.expectEqualStrings("hello", stalled.bytes[2..7]);

    // The retry carries the unsent tail with no new frame header: the
    // bytes continue the open DATA frame, and the completing tail takes
    // the fin and releases the slot.
    sender.multi_queue_cap = null;
    const tail = " world";
    const second = try session.sendData(0, tail, true);
    try std.testing.expectEqual(tail.len, second);
    try std.testing.expectEqual(@as(usize, 0), activeEntries(&session));
    const resumed = sender.multiAt(1);
    try std.testing.expect(resumed.fin);
    try std.testing.expectEqual(tail.len, resumed.len);
    try std.testing.expectEqual(tail.len, resumed.queued);
    try std.testing.expectEqualStrings(tail, resumed.bytes[0..tail.len]);
}

test "h3 session: a retry offering more than the open frame's remainder frames the excess anew" {
    var sender = FakeSender{};
    var handler = DeferHandler{};
    var session: H3Session = undefined;
    try session.initInPlace(std.testing.allocator, sender.interfaceMulti(), handler.interface());
    defer session.deinit();

    var wire: [1024]u8 = undefined;
    const request = try requestWire(&wire, std.testing.allocator, "/overshoot", "");
    const sh = session.streamHandler();
    sh.onData(sh.ctx, 0, request, true);

    try session.sendResponseHead(0, 200, &.{});

    // The short write leaves " world" (6 bytes) owed to the open frame.
    sender.multi_queue_cap = 7;
    try std.testing.expectEqual(@as(usize, 5), try session.sendData(0, "hello world", false));
    try std.testing.expectEqual(@as(usize, 1), activeEntries(&session));

    // A caller re-slicing from its relay buffer offers more than the tail:
    // the first six bytes complete the open frame headerless, the excess
    // becomes a fresh DATA frame, and the fin rides it to release.
    sender.multi_queue_cap = null;
    try std.testing.expectEqual(@as(usize, 9), try session.sendData(0, " worldXYZ", true));
    try std.testing.expectEqual(@as(usize, 0), activeEntries(&session));

    try std.testing.expectEqual(@as(usize, 3), sender.multi_count);
    const cont = sender.multiAt(1);
    try std.testing.expect(!cont.fin);
    try std.testing.expectEqualStrings(" world", cont.bytes[0..cont.len]);
    const fresh = sender.multiAt(2);
    try std.testing.expect(fresh.fin);
    const type_v = try request_stream.readVarint(fresh.bytes[0..fresh.len]);
    try std.testing.expectEqual(request_stream.frame_type_data, type_v.value);
    const length_v = try request_stream.readVarint(fresh.bytes[type_v.len..fresh.len]);
    try std.testing.expectEqual(@as(usize, 3), length_v.value);
    const payload_start = type_v.len + length_v.len;
    try std.testing.expectEqualStrings("XYZ", fresh.bytes[payload_start..][0..3]);
}

test "h3 session: sendData falls back to one packet send when the sender has no multi path" {
    var sender = FakeSender{};
    var handler = DeferHandler{};
    var session: H3Session = undefined;
    try session.initInPlace(std.testing.allocator, sender.interface(), handler.interface());
    defer session.deinit();

    var wire: [1024]u8 = undefined;
    const request = try requestWire(&wire, std.testing.allocator, "/fallback", "");
    const sh = session.streamHandler();
    sh.onData(sh.ctx, 0, request, true);

    try session.sendResponseHead(0, 200, &.{});
    try std.testing.expectEqual(@as(usize, 2), try session.sendData(0, "ok", false));
    try std.testing.expectEqual(@as(usize, 1), activeEntries(&session));
    try std.testing.expectEqual(@as(usize, 2), sender.count); // head + data, all via send
    try std.testing.expectEqual(@as(usize, 0), sender.multi_count);
    const data_send = sender.at(1);
    try std.testing.expect(!data_send.fin);
    const type_v = try request_stream.readVarint(data_send.bytes[0..data_send.len]);
    try std.testing.expectEqual(request_stream.frame_type_data, type_v.value);

    // An empty fin chunk is a legal empty DATA frame and releases the slot.
    try std.testing.expectEqual(@as(usize, 0), try session.sendData(0, "", true));
    try std.testing.expectEqual(@as(usize, 0), activeEntries(&session));
    const fin_send = sender.at(2);
    try std.testing.expect(fin_send.fin);

    // On the single-packet path a chunk that cannot fit one transport send
    // is a named error, and the stream stays open for a smaller retry.
    sh.onData(sh.ctx, 4, request, true);
    try session.sendResponseHead(4, 200, &.{});
    var big: [connection.max_stream_frame_payload]u8 = @splat('x');
    try std.testing.expectError(error.ChunkTooLarge, session.sendData(4, &big, false));
    try std.testing.expectEqual(@as(usize, 1), activeEntries(&session));
    try std.testing.expectEqual(@as(usize, 4), try session.sendData(4, "fine", true));
    try std.testing.expectEqual(@as(usize, 0), activeEntries(&session));
}

test "h3 session: abortStream frees the entry, sends nothing on a bare session, and is idempotent" {
    var sender = FakeSender{};
    var handler = DeferHandler{};
    var session: H3Session = undefined;
    try session.initInPlace(std.testing.allocator, sender.interfaceMulti(), handler.interface());
    defer session.deinit();

    var wire: [1024]u8 = undefined;
    const request = try requestWire(&wire, std.testing.allocator, "/reset", "");
    const sh = session.streamHandler();
    sh.onData(sh.ctx, 0, request, true);
    try session.sendResponseHead(0, 200, &.{});
    try std.testing.expectEqual(@as(usize, 7), try session.sendData(0, "partial", false));
    try std.testing.expectEqual(@as(usize, 1), activeEntries(&session));

    // No connection underneath (the unit-test shape): the reset is skipped
    // and only the entry frees.
    session.abortStream(0);
    try std.testing.expectEqual(@as(usize, 0), activeEntries(&session));
    try std.testing.expectEqual(@as(usize, 1), sender.count);
    try std.testing.expectEqual(@as(usize, 1), sender.multi_count);

    // A second abort finds no entry: no double release, no sends.
    session.abortStream(0);
    try std.testing.expectEqual(@as(usize, 1), sender.count);
    try std.testing.expectEqual(@as(usize, 1), sender.multi_count);

    // The freed slot serves a fresh exchange end to end.
    sh.onData(sh.ctx, 4, request, true);
    try session.sendResponseHead(4, 200, &.{});
    try std.testing.expectEqual(@as(usize, 1), activeEntries(&session));
    try std.testing.expectEqual(@as(usize, 0), try session.sendData(4, "", true));
    try std.testing.expectEqual(@as(usize, 0), activeEntries(&session));
}

test "h3 session: uppercase response header names are lowercased" {
    var sender = FakeSender{};
    var handler = FakeHandler{ .respond = false };
    var session: H3Session = undefined;
    try session.initInPlace(std.testing.allocator, sender.interface(), handler.interface());
    defer session.deinit();

    // HTTP/1.1 origins spell them "Content-Type"; QPACK requires lowercase.
    try session.sendResponse(
        0,
        200,
        &.{.{ .name = "Content-Type", .value = "text/plain" }},
        "",
        true,
    );
    try std.testing.expectEqual(@as(usize, 1), sender.count);

    const send = sender.at(0);
    const type_v = try request_stream.readVarint(send.bytes[0..send.len]);
    const length_v = try request_stream.readVarint(send.bytes[type_v.len..send.len]);
    const block_start: usize = type_v.len + length_v.len;
    const block_end = block_start + @as(usize, @intCast(length_v.value));
    var decoded = try qpack.decode(std.testing.allocator, send.bytes[block_start..block_end]);
    defer decoded.deinit();
    try std.testing.expectEqual(@as(usize, 2), decoded.fields.len);
    try std.testing.expectEqualStrings(":status", decoded.fields[0].name);
    try std.testing.expectEqualStrings("content-type", decoded.fields[1].name);
}

// ---------------------------------------------------------------------------
// Dynamic QPACK (RFC 9204). The peer's encoder stream grows the decode
// table; dynamic request blocks resolve against it; the decoder stream
// returns the Insert Count Increments and Section Acknowledgments that keep
// the peer's encoder advancing. The client SETTINGS frame configures the
// response encoder, whose stream-7 instructions precede the HEADERS blocks
// that reference them.
// ---------------------------------------------------------------------------

/// One 64-byte header value: past the vendor encoder's minimum insert
/// length, so a peer-shaped encoder will table it.
const dyn_header_value = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

/// The encoder-stream prefix a browser-shaped peer sends before its first
/// dynamic request: Set Dynamic Table Capacity at this session's maximum,
/// then one literal-name insert, staged by the vendor encoder.
fn peerEncoderBytes(out: []u8, name: []const u8, value: []const u8) ![]const u8 {
    var encoder = qpack.Encoder.init(std.testing.allocator);
    defer encoder.deinit();
    try encoder.configure(qpack_max_table_capacity, qpack_blocked_streams);
    const block = try encoder.encodeSection(
        std.testing.allocator,
        0,
        &.{.{ .name = name, .value = value }},
    );
    defer std.testing.allocator.free(block);
    const staged = encoder.pendingInstructions();
    if (staged.len + 1 > out.len) return error.OutputTooSmall;
    out[0] = 0x02; // client QPACK encoder stream type
    @memcpy(out[1..][0..staged.len], staged);
    return out[0 .. staged.len + 1];
}

/// One request HEADERS block: the static pseudo-headers a real request
/// carries, plus a pre-base dynamic reference to the table's newest entry.
/// Required Insert Count 1 encodes as 0x02 (one entry inside the 256-wide
/// wraparound window a 4096-byte table defines); Delta Base 0 puts Base at
/// 1, so index 0x80 is the most recent insert.
fn dynamicRequestBlock(out: []u8, allocator: std.mem.Allocator, path: []const u8) ![]const u8 {
    const fields = [_]qpack.HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "spike.zgix.test" },
        .{ .name = ":path", .value = path },
    };
    const static_block = try qpack.encode(allocator, &fields);
    defer allocator.free(static_block);
    if (static_block.len < 2) return error.InvalidBlock;
    if (static_block.len + 1 > out.len) return error.OutputTooSmall;
    out[0] = 0x02; // Required Insert Count 1
    out[1] = 0x00; // Delta Base 0: Base == Required Insert Count
    @memcpy(out[2..][0 .. static_block.len - 2], static_block[2..]);
    out[static_block.len] = 0x80; // indexed field line, pre-base index 0
    return out[0 .. static_block.len + 1];
}

/// Send the given bytes as one client-SETTINGS frame on a fresh control
/// stream (stream id 2), the shape Chrome's opening flight has.
fn feedClientSettings(session: *H3Session, capacity: u64, blocked: u64) !void {
    var frame: [40]u8 = undefined;
    var used: usize = 0;
    frame[used] = 0x00; // control stream type
    used += 1;
    var payload: [32]u8 = undefined;
    var plen: usize = 0;
    payload[plen] = 0x01; // QPACK_MAX_TABLE_CAPACITY
    plen += 1;
    plen += try request_stream.writeVarint(payload[plen..], capacity);
    payload[plen] = 0x07; // QPACK_BLOCKED_STREAMS
    plen += 1;
    plen += try request_stream.writeVarint(payload[plen..], blocked);
    used += try request_stream.writeVarint(frame[used..], 0x04);
    used += try request_stream.writeVarint(frame[used..], @as(u64, plen));
    @memcpy(frame[used..][0..plen], payload[0..plen]);
    const sh = session.streamHandler();
    sh.onData(sh.ctx, 2, frame[0 .. used + plen], false);
}

/// Count the recorded sends on one stream.
fn sendsOn(sender: *const FakeSender, stream_id: u64) usize {
    var count: usize = 0;
    for (sender.sends[0..sender.count]) |send| {
        if (send.stream_id == stream_id) count += 1;
    }
    return count;
}

/// Concatenate the recorded payloads on one stream into `out`.
fn collectSends(sender: *const FakeSender, stream_id: u64, out: []u8) ![]const u8 {
    var used: usize = 0;
    for (sender.sends[0..sender.count]) |send| {
        if (send.stream_id != stream_id) continue;
        if (send.len > out.len - used) return error.OutputTooSmall;
        @memcpy(out[used..][0..send.len], send.bytes[0..send.len]);
        used += send.len;
    }
    return out[0..used];
}

test "h3 session: peer encoder instructions feed the decode table and dynamic references resolve" {
    var sender = FakeSender{};
    var handler = FakeHandler{ .respond = false };
    var session: H3Session = undefined;
    try session.initInPlace(std.testing.allocator, sender.interface(), handler.interface());
    defer session.deinit();
    const sh = session.streamHandler();

    // Chrome's opening QPACK flight on the encoder stream: capacity, then
    // one literal insert. The table applies it immediately.
    var enc_wire: [256]u8 = undefined;
    const enc_bytes = try peerEncoderBytes(&enc_wire, "x-dyn-payload", dyn_header_value);
    sh.onData(sh.ctx, 2, enc_bytes, false);
    try std.testing.expectEqual(@as(u64, 1), session.qpack_decoder.insertCount());

    // A field section referencing that entry by relative index decodes to
    // the inserted name and value.
    var block: [256]u8 = undefined;
    const dynamic = try dynamicRequestBlock(&block, std.testing.allocator, "/dyn");
    var wire: [512]u8 = undefined;
    var used: usize = 0;
    try appendFrame(&wire, &used, request_stream.frame_type_headers, dynamic);
    sh.onData(sh.ctx, 0, wire[0..used], true);

    try std.testing.expectEqual(@as(usize, 1), handler.calls);
    try std.testing.expectEqualStrings("/dyn", handler.path[0..handler.path_len]);
    try std.testing.expectEqualStrings("x-dyn-payload", handler.header_name[0..handler.header_name_len]);
    try std.testing.expectEqualStrings(dyn_header_value, handler.header_value[0..handler.header_value_len]);
}

test "h3 session: dynamic decode emits Insert Count Increment then Section Acknowledgment on the decoder stream" {
    var sender = FakeSender{};
    var handler = FakeHandler{ .respond = false };
    var session: H3Session = undefined;
    try session.initInPlace(std.testing.allocator, sender.interface(), handler.interface());
    defer session.deinit();
    const sh = session.streamHandler();

    // Applying the peer's insert produces exactly one decoder-stream write:
    // an Insert Count Increment of 1.
    var enc_wire: [256]u8 = undefined;
    const enc_bytes = try peerEncoderBytes(&enc_wire, "x-dyn-payload", dyn_header_value);
    sh.onData(sh.ctx, 2, enc_bytes, false);
    try std.testing.expectEqual(@as(usize, 1), sendsOn(&sender, qpack_decoder_stream_id));
    const ici = sender.at(sendsOn(&sender, qpack_decoder_stream_id) - 1);
    const ici_scan = qpack.scanDecoderInstruction(ici.bytes[0..ici.len], 0);
    try std.testing.expectEqual(qpack.DecoderInstruction.insert_count_increment, ici_scan.complete.instruction);
    try std.testing.expectEqual(@as(u64, 1), ici_scan.complete.value);

    // Decoding the dynamic section acknowledges it on the same stream.
    var block: [256]u8 = undefined;
    const dynamic = try dynamicRequestBlock(&block, std.testing.allocator, "/acked");
    var wire: [512]u8 = undefined;
    var used: usize = 0;
    try appendFrame(&wire, &used, request_stream.frame_type_headers, dynamic);
    sh.onData(sh.ctx, 0, wire[0..used], true);

    try std.testing.expectEqual(@as(usize, 1), handler.calls);
    try std.testing.expectEqual(@as(usize, 2), sendsOn(&sender, qpack_decoder_stream_id));
    const ack = sender.at(sendsOn(&sender, qpack_decoder_stream_id) - 1);
    const ack_scan = qpack.scanDecoderInstruction(ack.bytes[0..ack.len], 0);
    try std.testing.expectEqual(qpack.DecoderInstruction.section_acknowledgment, ack_scan.complete.instruction);
    try std.testing.expectEqual(@as(u64, 0), ack_scan.complete.value);
}

// ---------------------------------------------------------------------------
// Blocked-section parking (RFC 9204 §4.4). The session advertises 16 blocked
// streams, so a request whose Required Insert Count is not yet satisfied
// parks in a bounded FIFO instead of failing: `feedPeerEncoder` retries the
// head whenever inserts land, and a decoded retry carries its Section
// Acknowledgment out on the decoder stream through the ordinary path.
// ---------------------------------------------------------------------------

/// Hand-crafted peer encoder-stream data: the `0x02` stream-type byte, an
/// optional Set Dynamic Table Capacity (4096, the prefix-integer encoding
/// `3f e1 1f` the vendor emits), and one Insert with Literal Name (`1 T=0`
/// + 6-bit name length, name, `H=0` + 7-bit value length, value).
fn encoderInsertBytes(
    out: []u8,
    stream_type: bool,
    with_capacity: bool,
    name: []const u8,
    value: []const u8,
) ![]const u8 {
    var used: usize = 0;
    if (stream_type) {
        out[used] = 0x02; // client QPACK encoder stream type
        used += 1;
    }
    if (with_capacity) {
        out[used] = 0x3f;
        out[used + 1] = 0xe1;
        out[used + 2] = 0x1f;
        used += 3;
    }
    if (name.len > 30 or value.len > 126) return error.TestInputTooLong;
    out[used] = 0x40 | @as(u8, @intCast(name.len)); // 01 H=0, literal name
    used += 1;
    @memcpy(out[used..][0..name.len], name);
    used += name.len;
    out[used] = @as(u8, @intCast(value.len));
    used += 1;
    @memcpy(out[used..][0..value.len], value);
    used += value.len;
    return out[0..used];
}

/// A field section with Required Insert Count 2: static pseudo-headers plus
/// a pre-base indexed line at relative index 1 (entry #1 once Base is 2).
/// Mirrors `dynamicRequestBlock`'s construction one Required Insert Count
/// step up.
fn dynamicRequestBlockTwo(out: []u8, allocator: std.mem.Allocator, path: []const u8) ![]const u8 {
    const fields = [_]qpack.HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "spike.zgix.test" },
        .{ .name = ":path", .value = path },
    };
    const static_block = try qpack.encode(allocator, &fields);
    defer allocator.free(static_block);
    if (static_block.len < 2) return error.InvalidBlock;
    if (static_block.len + 1 > out.len) return error.OutputTooSmall;
    out[0] = 0x03; // Required Insert Count 2
    out[1] = 0x00; // Delta Base 0: Base == Required Insert Count
    @memcpy(out[2..][0 .. static_block.len - 2], static_block[2..]);
    out[static_block.len] = 0x81; // indexed field line, pre-base index 1
    return out[0 .. static_block.len + 1];
}

test "h3 session: a decodable block never parks" {
    var sender = FakeSender{};
    var handler = FakeHandler{ .respond = false };
    var session: H3Session = undefined;
    try session.initInPlace(std.testing.allocator, sender.interface(), handler.interface());
    defer session.deinit();
    const sh = session.streamHandler();

    // A static-only request head (RIC 0) decodes with an empty table.
    var wire: [512]u8 = undefined;
    var used: usize = 0;
    const fields = [_]qpack.HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "spike.zgix.test" },
        .{ .name = ":path", .value = "/static" },
    };
    const static_block = try qpack.encode(std.testing.allocator, &fields);
    defer std.testing.allocator.free(static_block);
    try appendFrame(&wire, &used, request_stream.frame_type_headers, static_block);
    sh.onData(sh.ctx, 0, wire[0..used], true);

    try std.testing.expectEqual(@as(usize, 1), handler.calls);
    try std.testing.expectEqualStrings("/static", handler.path[0..handler.path_len]);
    // Hot path: nothing touched the parking queue.
    try std.testing.expectEqual(@as(u8, 0), session.parked_len);
    try std.testing.expect(!session.streams[0].parser.parked);
}

test "h3 session: a blocked section parks, and releasing the stream purges the queue" {
    var sender = FakeSender{};
    var handler = FakeHandler{ .respond = false };
    var session: H3Session = undefined;
    try session.initInPlace(std.testing.allocator, sender.interface(), handler.interface());
    defer session.deinit();
    const sh = session.streamHandler();

    // The insert that would satisfy the block has not arrived: the section
    // parks instead of failing the stream.
    var block: [256]u8 = undefined;
    const dynamic = try dynamicRequestBlock(&block, std.testing.allocator, "/parked");
    var wire: [512]u8 = undefined;
    var used: usize = 0;
    try appendFrame(&wire, &used, request_stream.frame_type_headers, dynamic);
    sh.onData(sh.ctx, 0, wire[0..used], true);

    try std.testing.expectEqual(@as(usize, 0), handler.calls);
    try std.testing.expectEqual(@as(u8, 1), session.parked_len);
    try std.testing.expectEqual(@as(u64, 0), session.parked[0]);
    try std.testing.expect(session.streams[0].parser.parked);
    // FIN rode the parked datagram: completion waits for the retry.
    try std.testing.expect(session.streams[0].fin_pending);

    // A peer reset while parked frees the entry and the queue slot together.
    sh.on_reset.?(sh.ctx, 0);
    try std.testing.expectEqual(@as(u8, 0), session.parked_len);
    try std.testing.expect(session.findActive(0) == null);
}

test "h3 session: a parked section decodes when the inserts land, and the retry carries its Section Ack" {
    var sender = FakeSender{};
    var handler = FakeHandler{ .respond = false };
    var session: H3Session = undefined;
    try session.initInPlace(std.testing.allocator, sender.interface(), handler.interface());
    defer session.deinit();
    const sh = session.streamHandler();

    var block: [256]u8 = undefined;
    const dynamic = try dynamicRequestBlock(&block, std.testing.allocator, "/parked");
    var wire: [512]u8 = undefined;
    var used: usize = 0;
    try appendFrame(&wire, &used, request_stream.frame_type_headers, dynamic);
    sh.onData(sh.ctx, 0, wire[0..used], true);
    try std.testing.expectEqual(@as(u8, 1), session.parked_len);
    try std.testing.expectEqual(@as(usize, 0), handler.calls);

    // The encoder stream catches up: capacity, then the missing insert. The
    // retry decodes the parked head before any further input is handled.
    var enc_wire: [256]u8 = undefined;
    const enc_bytes = try encoderInsertBytes(&enc_wire, true, true, "x-dyn-payload", dyn_header_value);
    sh.onData(sh.ctx, 2, enc_bytes, false);

    try std.testing.expectEqual(@as(u64, 1), session.qpack_decoder.insertCount());
    try std.testing.expectEqual(@as(u8, 0), session.parked_len);
    try std.testing.expect(!session.streams[0].parser.parked);
    try std.testing.expectEqual(@as(usize, 1), handler.calls);
    try std.testing.expectEqualStrings("/parked", handler.path[0..handler.path_len]);
    try std.testing.expectEqualStrings("x-dyn-payload", handler.header_name[0..handler.header_name_len]);
    try std.testing.expectEqualStrings(dyn_header_value, handler.header_value[0..handler.header_value_len]);

    // The decoder stream saw the Insert Count Increment and then the
    // retried section's Section Acknowledgment — the ordinary decode path,
    // re-entered by the retry.
    try std.testing.expectEqual(@as(usize, 2), sendsOn(&sender, qpack_decoder_stream_id));
    const ack = sender.at(sendsOn(&sender, qpack_decoder_stream_id) - 1);
    const ack_scan = qpack.scanDecoderInstruction(ack.bytes[0..ack.len], 0);
    try std.testing.expectEqual(qpack.DecoderInstruction.section_acknowledgment, ack_scan.complete.instruction);
    try std.testing.expectEqual(@as(u64, 0), ack_scan.complete.value);
    // FIN was pending on the parked head: the completing body marker landed.
    try std.testing.expect(session.streams[0].body_done or session.findActive(0) == null);
}

test "h3 session: parked sections retry head-first in arrival order" {
    var sender = FakeSender{};
    var handler = FakeHandler{ .respond = false };
    var session: H3Session = undefined;
    try session.initInPlace(std.testing.allocator, sender.interface(), handler.interface());
    defer session.deinit();
    const sh = session.streamHandler();

    // Stream 0 needs one insert; stream 4 declares Required Insert Count 2.
    // Both park, in arrival order.
    var block_one: [256]u8 = undefined;
    const dynamic_one = try dynamicRequestBlock(&block_one, std.testing.allocator, "/one");
    var wire: [512]u8 = undefined;
    var used: usize = 0;
    try appendFrame(&wire, &used, request_stream.frame_type_headers, dynamic_one);
    sh.onData(sh.ctx, 0, wire[0..used], false);

    var block_two: [256]u8 = undefined;
    const dynamic_two = try dynamicRequestBlockTwo(&block_two, std.testing.allocator, "/two");
    used = 0;
    try appendFrame(&wire, &used, request_stream.frame_type_headers, dynamic_two);
    sh.onData(sh.ctx, 4, wire[0..used], false);

    try std.testing.expectEqual(@as(u8, 2), session.parked_len);
    try std.testing.expectEqual(@as(usize, 0), handler.calls);

    // Only the first insert lands: the head (RIC 1) resolves, the second
    // section (RIC 2) must stay parked — the retry loop stops at the first
    // still-blocked head, so a section that could not have decoded did not
    // jump the queue.
    var first_wire: [256]u8 = undefined;
    const first = try encoderInsertBytes(&first_wire, true, true, "x-first", dyn_header_value);
    sh.onData(sh.ctx, 2, first, false);

    try std.testing.expectEqual(@as(u64, 1), session.qpack_decoder.insertCount());
    try std.testing.expectEqual(@as(u8, 1), session.parked_len);
    try std.testing.expectEqual(@as(usize, 1), handler.calls);
    try std.testing.expectEqualStrings("/one", handler.path[0..handler.path_len]);

    // The second insert unblocks the remaining head.
    var second_wire: [256]u8 = undefined;
    const second = try encoderInsertBytes(&second_wire, false, false, "x-second", dyn_header_value);
    sh.onData(sh.ctx, 2, second, false);

    try std.testing.expectEqual(@as(u64, 2), session.qpack_decoder.insertCount());
    try std.testing.expectEqual(@as(u8, 0), session.parked_len);
    try std.testing.expectEqual(@as(usize, 2), handler.calls);
    try std.testing.expectEqualStrings("/two", handler.path[0..handler.path_len]);
}

test "h3 session: a blocked section past the advertised budget is a protocol error for that stream" {
    var sender = FakeSender{};
    var handler = FakeHandler{ .respond = false };
    var session: H3Session = undefined;
    try session.initInPlace(std.testing.allocator, sender.interface(), handler.interface());
    defer session.deinit();
    const sh = session.streamHandler();

    // White-box: the budget is the advertised 16, but the request table
    // holds fewer slots, so fill the queue with inert ids to exercise the
    // 17th-blocked-section path directly.
    for (0..qpack_blocked_streams) |index| {
        session.parked[index] = @intCast(1000 + index);
    }
    session.parked_len = qpack_blocked_streams;

    var block: [256]u8 = undefined;
    const dynamic = try dynamicRequestBlock(&block, std.testing.allocator, "/over");
    var wire: [512]u8 = undefined;
    var used: usize = 0;
    try appendFrame(&wire, &used, request_stream.frame_type_headers, dynamic);
    sh.onData(sh.ctx, 0, wire[0..used], true);

    // The offending stream is released like a malformed frame; the tables
    // and the queue are untouched (the encoder merely overcommitted its
    // blocking budget, it did not desynchronize anything).
    try std.testing.expect(session.findActive(0) == null);
    try std.testing.expectEqual(@as(usize, 0), handler.calls);
    try std.testing.expectEqual(@as(usize, 0), handler.aborts);
    try std.testing.expectEqual(@as(u8, qpack_blocked_streams), session.parked_len);
    try std.testing.expect(!session.qpack_failed);
}

// ---------------------------------------------------------------------------
// QPACK failures choose their teardown by cause. Peer faults — encoder
// instructions outside the session's SETTINGS, impossible decoder-stream
// instructions — poison the tables and earn a CONNECTION_CLOSE naming the
// failure (RFC 9114 §8: decompression 0x0201, encompression 0x0202), so a
// client learns why instead of riding the idle timeout. Local limits stay
// silent: the peer may be blameless, and §10.2.2 forbids naming it.
// The close-vs-silent distinction below reads the connection's flags:
// `closeWithError` latches `closing`, `abort` latches `closed`.
// ---------------------------------------------------------------------------

/// A bare connection under a test session. `closeWithError` records its
/// code and latches `closing` before it ever reaches for packet keys, so
/// the session's framed-vs-silent choice is fully observable without a
/// handshake; the sealing itself is proven in connection.zig's tests.
fn wiredConn() !connection.Connection {
    const fixtures = struct {
        const cert_pem = @embedFile("../../tls/testdata/cert.pem");
        const key_pem = @embedFile("../../tls/testdata/key.pem");
    };
    try connection.Connection.configureServer(fixtures.cert_pem, fixtures.key_pem);
    var conn: connection.Connection = undefined;
    const peer: std.Io.net.IpAddress = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 4433 } };
    try conn.initInPlace(
        std.testing.allocator,
        peer,
        .{ .cert_pem = fixtures.cert_pem, .key_pem = fixtures.key_pem },
    );
    return conn;
}

test "h3 session: a peer encoder-stream violation closes the connection with a frame" {
    var sender = FakeSender{};
    var handler = FakeHandler{ .respond = false };
    var session: H3Session = undefined;
    try session.initInPlace(std.testing.allocator, sender.interface(), handler.interface());
    defer session.deinit();
    var conn = try wiredConn();
    defer conn.deinit();
    session.conn = &conn;
    const sh = session.streamHandler();

    // Set Dynamic Table Capacity 8192 — above the 4096 this session
    // advertised (RFC 9204 §4.3.1 makes the excess an encoder error):
    // the `3f e1 3f` prefix-integer encoding of 8192, after the stream
    // type byte.
    sh.onData(sh.ctx, 2, &.{ 0x02, 0x3f, 0xe1, 0x3f }, false);

    try std.testing.expect(session.qpack_failed);
    try std.testing.expectEqual(
        connection.h3_qpack_decompression_failed,
        conn.close_error_code,
    );
    try std.testing.expect(conn.closing);
    // A dynamic reference after the poison must be refused, not decoded.
    var block: [256]u8 = undefined;
    const dynamic = try dynamicRequestBlock(&block, std.testing.allocator, "/late");
    var wire: [512]u8 = undefined;
    var used: usize = 0;
    try appendFrame(&wire, &used, request_stream.frame_type_headers, dynamic);
    sh.onData(sh.ctx, 0, wire[0..used], true);
    try std.testing.expectEqual(@as(usize, 0), handler.calls);
}

test "h3 session: an impossible decoder instruction closes the connection with a frame" {
    var sender = FakeSender{};
    var handler = FakeHandler{ .respond = false };
    var session: H3Session = undefined;
    try session.initInPlace(std.testing.allocator, sender.interface(), handler.interface());
    defer session.deinit();
    var conn = try wiredConn();
    defer conn.deinit();
    session.conn = &conn;
    const sh = session.streamHandler();

    // Configure the response encoder, then have the peer's decoder
    // stream confirm zero inserts — `00` is always an invalid Insert
    // Count Increment (RFC 9204 §4.4.1).
    try feedClientSettings(&session, 4096, 16);
    sh.onData(sh.ctx, 6, &.{ 0x03, 0x00 }, false);

    try std.testing.expect(session.qpack_failed);
    try std.testing.expectEqual(
        connection.h3_qpack_encompression_failed,
        conn.close_error_code,
    );
    try std.testing.expect(conn.closing);
}

test "h3 session: a local reassembly limit fails silent" {
    var sender = FakeSender{};
    var handler = FakeHandler{ .respond = false };
    var session: H3Session = undefined;
    try session.initInPlace(std.testing.allocator, sender.interface(), handler.interface());
    defer session.deinit();
    var conn = try wiredConn();
    defer conn.deinit();
    session.conn = &conn;
    const sh = session.streamHandler();

    // More encoder bytes than the reassembly buffer spans: local state,
    // no close frame — the peer may be splitting one huge insert it
    // believed legal on a bigger table, and §10.2.2 says blameless
    // traffic earns silence. The session still poisons: nothing after
    // this can trust the table.
    var flood: [qpack_instruction_buffer_bytes + 2]u8 = @splat(0xaa);
    flood[0] = 0x02; // encoder stream type
    sh.onData(sh.ctx, 2, &flood, false);

    try std.testing.expect(session.qpack_failed);
    // Silent: the abort latch (`closed`, and `closing` with it — abort
    // refuses sends from here on) with no close code recorded.
    try std.testing.expect(conn.closed);
    try std.testing.expectEqual(@as(u64, 0), conn.close_error_code);
}

test "h3 session: client SETTINGS configure the response encoder at the session cap" {
    var sender = FakeSender{};
    var handler = FakeHandler{ .respond = false };
    var session: H3Session = undefined;
    try session.initInPlace(std.testing.allocator, sender.interface(), handler.interface());
    defer session.deinit();

    // The client offers an 8 KiB table and 100 blocked streams; the
    // session's own 4 KiB bound wins, and the encoder stream announces the
    // chosen capacity before any field section can reference it.
    try feedClientSettings(&session, 8192, 100);
    try std.testing.expect(session.qpack_encoder.configured);
    try std.testing.expectEqual(@as(usize, qpack_max_table_capacity), session.qpack_encoder.table.capacity);
    try std.testing.expectEqual(@as(usize, qpack_encoder_blocked_cap), session.qpack_encoder.blocked_stream_limit);

    var staged: [64]u8 = undefined;
    const bytes = try collectSends(&sender, qpack_encoder_stream_id, &staged);
    try std.testing.expectEqualSlices(u8, &.{ 0x3f, 0xe1, 0x1f }, bytes); // Set Dynamic Table Capacity 4096
}

test "h3 session: a response with a repeated sizable header round-trips through a peer decoder" {
    var sender = FakeSender{};
    var handler = FakeHandler{ .respond = false };
    var session: H3Session = undefined;
    try session.initInPlace(std.testing.allocator, sender.interface(), handler.interface());
    defer session.deinit();
    const sh = session.streamHandler();
    const allocator = std.testing.allocator;

    try feedClientSettings(&session, 4096, 16);

    // First response: the sizable header is inserted and referenced; the
    // section stays blocked on the peer's acknowledgment. The encoder
    // stream carries the capacity announcement (from the SETTINGS
    // handling) and the insert; both precede the HEADERS frame on the
    // wire.
    try session.sendResponse(0, 200, &.{.{
        .name = "x-large-response-header",
        .value = dyn_header_value,
    }}, "", true);
    try std.testing.expectEqual(@as(usize, 1), session.qpack_encoder.insertCount());
    try std.testing.expectEqual(@as(usize, 1), session.qpack_encoder.blockedStreamCount());
    try std.testing.expectEqual(@as(usize, 1), session.qpack_encoder.outstandingSectionCount(0));
    try std.testing.expectEqual(@as(u64, qpack_encoder_stream_id), sender.at(0).stream_id);

    var peer = qpack.Decoder.init(allocator, qpack_max_table_capacity);
    defer peer.deinit();
    try applyPeerEncoderFrom(&peer, &sender, 0);

    var head_block: [256]u8 = undefined;
    const first_block = try responseBlock(sender.at(2), &head_block);
    try std.testing.expect(first_block[0] != 0); // a nonzero Required Insert Count
    var first_list = try peer.decodeBlock(first_block);
    defer first_list.deinit();
    try std.testing.expectEqualStrings(dyn_header_value, first_list.get("x-large-response-header").?);

    // The peer acknowledges: increment first, then the section.
    var ici: [qpack.max_decoder_instruction_len]u8 = undefined;
    const ici_len = try qpack.writeDecoderInstruction(&ici, .{ .insert_count_increment = 1 });
    sh.onData(sh.ctx, 6, &.{0x03}, false);
    sh.onData(sh.ctx, 6, ici[0..ici_len], false);
    sh.onData(sh.ctx, 6, &.{0x80}, false); // Section Acknowledgment for stream 0
    try std.testing.expectEqual(@as(u64, 1), session.qpack_encoder.knownReceivedCount());
    try std.testing.expectEqual(@as(usize, 0), session.qpack_encoder.blockedStreamCount());
    try std.testing.expectEqual(@as(usize, 0), session.qpack_encoder.outstandingSectionCount(0));

    // Second response with the same header: the entry is already
    // acknowledged, so nothing new is staged; the peer's table resolves
    // the reference without further instructions.
    try session.sendResponse(0, 200, &.{.{
        .name = "x-large-response-header",
        .value = dyn_header_value,
    }}, "", true);
    try std.testing.expectEqual(@as(usize, 2), sendsOn(&sender, qpack_encoder_stream_id));
    var second_block: [256]u8 = undefined;
    var second_list = try peer.decodeBlock(try responseBlock(sender.at(3), &second_block));
    defer second_list.deinit();
    try std.testing.expectEqualStrings(dyn_header_value, second_list.get("x-large-response-header").?);
}

/// Apply the encoder-stream payloads at send indexes >= `start` to a
/// peer-side decoder, in send order.
fn applyPeerEncoderFrom(peer: *qpack.Decoder, sender: *const FakeSender, start: usize) !void {
    var offset: usize = 0;
    var staged: [256]u8 = undefined;
    for (sender.sends[start..sender.count]) |send| {
        if (send.stream_id != qpack_encoder_stream_id) continue;
        if (send.len > staged.len - offset) return error.OutputTooSmall;
        @memcpy(staged[offset..][0..send.len], send.bytes[0..send.len]);
        offset += send.len;
    }
    const bytes = staged[0..offset];
    var cursor: usize = 0;
    while (cursor < bytes.len) {
        switch (qpack.applyEncoderInstruction(peer, bytes, cursor) catch return error.ApplyFailed) {
            .applied => |done| cursor = done.end,
            else => return error.IncompleteInstruction,
        }
    }
}

/// Extract the HEADERS frame's QPACK block from one recorded send.
fn responseBlock(send: *const FakeSender.Send, out: []u8) ![]const u8 {
    const type_v = try request_stream.readVarint(send.bytes[0..send.len]);
    if (type_v.value != request_stream.frame_type_headers) return error.NotHeaders;
    const length_v = try request_stream.readVarint(send.bytes[type_v.len..send.len]);
    const start: usize = type_v.len + length_v.len;
    const end = start + @as(usize, @intCast(length_v.value));
    if (end > send.len) return error.Truncated;
    @memcpy(out[0 .. end - start], send.bytes[start..end]);
    return out[0 .. end - start];
}

test "h3 session: split encoder-stream instructions buffer until complete" {
    var sender = FakeSender{};
    var handler = FakeHandler{ .respond = false };
    var session: H3Session = undefined;
    try session.initInPlace(std.testing.allocator, sender.interface(), handler.interface());
    defer session.deinit();
    const sh = session.streamHandler();

    var enc_wire: [256]u8 = undefined;
    const enc_bytes = try peerEncoderBytes(&enc_wire, "x-dyn-payload", dyn_header_value);
    sh.onData(sh.ctx, 2, enc_bytes[0..1], false); // the stream-type byte
    // Every remaining byte one at a time: nothing applies until an
    // instruction is whole, and no confirmation is sent for none.
    for (enc_bytes[1..]) |byte| {
        sh.onData(sh.ctx, 2, &.{byte}, false);
    }
    try std.testing.expectEqual(@as(u64, 1), session.qpack_decoder.insertCount());
    try std.testing.expectEqual(@as(usize, 1), sendsOn(&sender, qpack_decoder_stream_id));

    var block: [256]u8 = undefined;
    const dynamic = try dynamicRequestBlock(&block, std.testing.allocator, "/split");
    var wire: [512]u8 = undefined;
    var used: usize = 0;
    try appendFrame(&wire, &used, request_stream.frame_type_headers, dynamic);
    sh.onData(sh.ctx, 0, wire[0..used], true);
    try std.testing.expectEqual(@as(usize, 1), handler.calls);
    try std.testing.expectEqualStrings(dyn_header_value, handler.header_value[0..handler.header_value_len]);
}

test "h3 session: random encoder-stream bytes cannot crash the session" {
    var prng = std.Random.DefaultPrng.init(0x5eed);
    const random = prng.random();
    var sender = FakeSender{};
    var handler = FakeHandler{ .respond = false };
    var session: H3Session = undefined;
    try session.initInPlace(std.testing.allocator, sender.interface(), handler.interface());
    defer session.deinit();
    const sh = session.streamHandler();
    sh.onData(sh.ctx, 2, &.{0x02}, false);

    var blob: [97]u8 = undefined;
    var fed: usize = 0;
    while (fed < 200) : (fed += 1) {
        const len = random.uintLessThan(usize, blob.len + 1);
        for (blob[0..len]) |*byte| byte.* = random.int(u8);
        sh.onData(sh.ctx, 2, blob[0..len], false);
        if (session.qpack_failed) break; // a random walk hit a violation: survived it
    }

    // Whatever the fuzz did, a static request still decodes; the session
    // refuses dynamic references only once poisoned.
    var wire: [1024]u8 = undefined;
    const request = try requestWire(&wire, std.testing.allocator, "/after-fuzz", "");
    sh.onData(sh.ctx, 0, request, true);
    try std.testing.expectEqual(@as(usize, 1), handler.calls);
    try std.testing.expectEqualStrings("/after-fuzz", handler.path[0..handler.path_len]);
}

test "h3 session: QPACK protocol violations fail the session closed" {
    // A capacity above the advertised maximum desynchronizes the tables.
    {
        var sender = FakeSender{};
        var handler = FakeHandler{ .respond = false };
        var session: H3Session = undefined;
        try session.initInPlace(std.testing.allocator, sender.interface(), handler.interface());
        defer session.deinit();
        const sh = session.streamHandler();

        sh.onData(sh.ctx, 2, &.{ 0x02, 0x3f, 0xe1, 0x20 }, false); // capacity 4224 > 4096
        try std.testing.expect(session.qpack_failed);
    }

    // An overlong varint is an invalid instruction, never a stall.
    {
        var sender = FakeSender{};
        var handler = FakeHandler{ .respond = false };
        var session: H3Session = undefined;
        try session.initInPlace(std.testing.allocator, sender.interface(), handler.interface());
        defer session.deinit();
        const sh = session.streamHandler();

        sh.onData(sh.ctx, 2, &.{ 0x02, 0x3f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01 }, false);
        try std.testing.expect(session.qpack_failed);
    }

    // A poisoned session refuses dynamic references but still serves
    // static-only blocks until the connection reaper takes it.
    {
        var sender = FakeSender{};
        var handler = FakeHandler{ .respond = false };
        var session: H3Session = undefined;
        try session.initInPlace(std.testing.allocator, sender.interface(), handler.interface());
        defer session.deinit();
        const sh = session.streamHandler();

        sh.onData(sh.ctx, 2, &.{ 0x02, 0x20 }, false); // capacity 0 is legal...
        try std.testing.expect(!session.qpack_failed);
        sh.onData(sh.ctx, 2, &.{ 0x3f, 0xe1, 0x20 }, false); // ...but 4224 is not
        try std.testing.expect(session.qpack_failed);

        var block: [256]u8 = undefined;
        const dynamic = try dynamicRequestBlock(&block, std.testing.allocator, "/refused");
        var wire: [512]u8 = undefined;
        var used: usize = 0;
        try appendFrame(&wire, &used, request_stream.frame_type_headers, dynamic);
        sh.onData(sh.ctx, 0, wire[0..used], true);
        try std.testing.expectEqual(@as(usize, 0), handler.calls);

        var static_wire: [1024]u8 = undefined;
        const request = try requestWire(&static_wire, std.testing.allocator, "/still-static", "");
        sh.onData(sh.ctx, 4, request, true);
        try std.testing.expectEqual(@as(usize, 1), handler.calls);
        try std.testing.expectEqualStrings("/still-static", handler.path[0..handler.path_len]);
    }

    // A decoder-stream violation: Insert Count Increment of zero.
    {
        var sender = FakeSender{};
        var handler = FakeHandler{ .respond = false };
        var session: H3Session = undefined;
        try session.initInPlace(std.testing.allocator, sender.interface(), handler.interface());
        defer session.deinit();
        const sh = session.streamHandler();

        sh.onData(sh.ctx, 6, &.{ 0x03, 0x00 }, false);
        try std.testing.expect(session.qpack_failed);
    }
}

// ---------------------------------------------------------------------------
// Earlier bounded QUIC slot probe, retained because `root.zig` re-exports
// `session.Session`. It prices zquic's allocator use; `H3Session` above is
// the protocol layer.
// ---------------------------------------------------------------------------

const Connection = zquic.Connection.Connection;
const Stream = zquic.Stream.Stream;
const StreamType = zquic.Stream.StreamType;

/// What one h3 connection may hold before the handshake even runs. A probe
/// at zquic 0.9.18 measured the empty connection at 2,984 bytes plus 328
/// bytes per bidirectional stream; the rest is headroom for crypto
/// reassembly, packet queues and stream buffers, which this module bounds
/// by construction even though it does not yet drive them.
pub const default_capacity_bytes: usize = 256 * 1024;

/// Streams one slot may open. A thousand (zquic's own high-level default)
/// is a server's number; a proxy that maps one stream to one §7 exchange
/// wants a number it can price against its own conn slots.
pub const default_streams_max: u16 = 64;

pub const Error = error{
    OutOfMemory,
    StreamLimit,
    /// zquic refused for a reason this layer does not model. The caller's
    /// answer is the same as `OutOfMemory`: close the QUIC connection.
    Internal,
};

/// A slot parameterised by its byte budget, so a test can force exhaustion
/// without allocating a production-sized object.
pub fn Slot(comptime capacity_bytes: usize, comptime streams_max: u16) type {
    comptime {
        if (capacity_bytes < 1024) @compileError("an h3 slot needs at least its state");
        if (streams_max < 1) @compileError("an h3 slot needs room for one stream");
    }
    return struct {
        storage: [capacity_bytes]u8 = undefined,
        fixed: std.heap.FixedBufferAllocator = undefined,
        connection: Connection = undefined,
        streams_created: u16 = 0,
        initialized: bool = false,

        const Self = @This();

        pub const capacity = capacity_bytes;
        pub const stream_limit = streams_max;

        pub fn init(self: *Self) Error!void {
            self.fixed = .init(&self.storage);
            self.connection = Connection.init(self.fixed.allocator(), .server, .{}) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => return error.Internal,
            };
            self.streams_created = 0;
            self.initialized = true;
        }

        pub fn deinit(self: *Self) void {
            if (!self.initialized) return;
            self.connection.deinit();
            self.initialized = false;
        }

        /// Bytes this slot's connection has actually claimed. The difference
        /// from `capacity` is the headroom left for the handshake and for
        /// stream buffers, and it is what a banner term would report.
        pub fn usedBytes(self: *const Self) usize {
            return self.fixed.end_index;
        }

        pub fn createStream(self: *Self, stream_type: StreamType) Error!*Stream {
            if (!self.initialized) return error.Internal;
            if (self.streams_created >= streams_max) return error.StreamLimit;
            // zquic folds every stream-allocation failure into its own
            // InternalError, so the caller cannot tell an exhausted arena
            // from any other refusal; both close the QUIC connection.
            const stream = self.connection.createStream(stream_type) catch return error.Internal;
            self.streams_created += 1;
            return stream;
        }
    };
}

pub const Session = Slot(default_capacity_bytes, default_streams_max);

test "h3 session: the empty slot fits and reports its use" {
    var session: Session = undefined;
    try session.init();
    defer session.deinit();
    try std.testing.expect(session.usedBytes() < Session.capacity);
    // The empty connection allocates nothing at this zquic version; the
    // bound catches a future one that starts reserving server-shaped state.
    try std.testing.expect(session.usedBytes() <= 64 * 1024);
}

test "h3 session: the stream cap refuses before the arena does" {
    var session: Session = undefined;
    try session.init();
    defer session.deinit();
    var created: u16 = 0;
    while (created < Session.stream_limit) : (created += 1) {
        _ = try session.createStream(.server_bidirectional);
    }
    try std.testing.expectEqual(Session.stream_limit, created);
    try std.testing.expectError(error.StreamLimit, session.createStream(.server_bidirectional));
    try std.testing.expect(session.usedBytes() < Session.capacity);
}

test "h3 session: a tiny arena refuses cleanly instead of growing" {
    const Tiny = Slot(1024, 64);
    var session: Tiny = undefined;
    try session.init();
    defer session.deinit();
    var created: u16 = 0;
    while (created < Tiny.stream_limit) : (created += 1) {
        _ = session.createStream(.server_bidirectional) catch |err| {
            try std.testing.expectEqual(error.Internal, err);
            break;
        };
    }
    try std.testing.expect(created < Tiny.stream_limit);
    try std.testing.expect(session.usedBytes() <= Tiny.capacity);
}
