//! Server-side QUIC connection state machine (HTTP/3 listener groundwork).
//!
//! This is the smallest connection that can honestly answer a client: it
//! owns a fixed 256 KiB arena, runs the QUIC-TLS handshake over CRYPTO
//! frames, installs RFC 9001 packet keys at each level as qtls yields the
//! secrets, and moves application bytes over STREAM frames in both
//! directions. A listener can hand it raw datagrams and drain replies
//! without it ever touching the page allocator.
//!
//! Deliberately absent, because the probe/test does not need them:
//!
//! - Full stream state machines and reordering buffers: streams are offset
//!   tables here, bounded in *count* — the listener's request-slot ceiling,
//!   advertised as `initial_max_streams_bidi` and raised by MAX_STREAMS as
//!   slots free; streams past the ceiling are dropped, not answered — and
//!   in *bytes* — MAX_DATA / MAX_STREAM_DATA top-ups on the send side,
//!   advertised windows on the receive side. ACKs and PTO retransmission
//!   are implemented; loss detection is the timer's coarse PTO rather than
//!   a packet-threshold pass.
//! - Multiple CRYPTO chunks per level on the send side. Each flush sends
//!   one frame at offset 0; the handshake in this slice emits one flight
//!   per level, so that is exact rather than approximate.
//!
//! On the receive side CRYPTO is reassembled per level and offsets must
//! arrive in order. Out-of-order or duplicate CRYPTO is a protocol error
//! here instead of being buffered for the recovery pass.

const std = @import("std");

const constants = @import("../../constants.zig");
const qtls = @import("qtls");
const zquic = @import("zquic");

const recovery = @import("recovery.zig");

const assert = std.debug.assert;

const Packet = zquic.core.Packet;
const QuicFrames = zquic.core.QuicFrames;
const PacketCrypto = zquic.PacketCrypto;
const EnhancedTlsContext = zquic.EnhancedCrypto.EnhancedTlsContext;

/// The TLS QUIC levels qtls indexes its buffers by (0 Initial, 2 Handshake,
/// 3 Application). 1 is 0-RTT, which this server does not accept.
const tls_initial = 0;
const tls_handshake = 2;
const tls_application = 3;

/// Packet-number spaces as `Packet.PacketType` maps onto them.
const tls_levels = [3]usize{ tls_initial, tls_handshake, tls_application };

pub const arena_bytes = 256 * 1024;
pub const max_datagram_bytes = 1500;
pub const idle_timeout_ns: u64 = 30 * std.time.ns_per_s;

const datagram_slots = 16;
const stream_slots = 16;
/// Sent packets retained for PTO retransmission, per packet-number space.
/// One slot is enough for a handshake and a few application writes; the
/// oldest is replaced when the ring is full.
const sent_slots = 8;

/// Handshake bytes one level may hold before TLS consumes them. Sized for
/// the fixture certificate plus CertificateVerify and Finished; a real
/// certificate replace would raise it or split CRYPTO frames.
const crypto_buffer_bytes = 8 * 1024;

/// Receive windows advertised to the client. Top-ups are sent once half a
/// window has been consumed, so an upload larger than the window does not
/// stall.
const recv_data_window: u64 = 1 << 20;
const recv_stream_window: u64 = 256 * 1024;

/// Largest STREAM-frame payload one iteration of `sendStreamMulti` seals
/// into a single datagram. Derived from `max_datagram_bytes`: a 1-RTT
/// datagram spends at most 1 + 20 + 4 bytes on the short header (first
/// byte, largest client SCID, largest packet number) plus 16 on the AEAD
/// tag, and a STREAM frame header runs to 1 + 8 + 8 + 8 bytes (type,
/// stream id, offset, length as largest varints). The 128-byte margin
/// covers that worst case plus the small ACK / flow-control prefixes
/// `seal` prepends, so a chunk always seals without
/// `error.DatagramTooLarge` — the same exposure an oversized single
/// `sendStream` already carries.
pub const max_stream_frame_payload: usize = max_datagram_bytes - 128;

// Application error codes carried by RESET_STREAM (RFC 9000 §20.2). The
// transport reserves 0x00-0xff; HTTP/3 (RFC 9114 §8.1) takes the 0x1xx
// range. Only the few a response-abort path needs are named here — the
// full table belongs to the H3 layer above this connection.
pub const h3_no_error: u64 = 0x100;
pub const h3_general_protocol_error: u64 = 0x101;
pub const h3_internal_error: u64 = 0x102;
pub const h3_request_rejected: u64 = 0x10b;
pub const h3_request_cancelled: u64 = 0x10c;
pub const h3_request_incomplete: u64 = 0x10d;
pub const h3_early_response: u64 = 0x10e;

// Connection-level QPACK failures (RFC 9114 §8.1, values from RFC 9204):
// the decode side's dynamic table can no longer track the peer's encoder
// (decompression) or the peer's decoder-stream instructions are
// impossible (encompression). Both poison every later field section, so
// the session fails the connection with the frame that names which.
pub const h3_qpack_decompression_failed: u64 = 0x201;
pub const h3_qpack_encompression_failed: u64 = 0x202;

// QUIC transport error codes (RFC 9000 §20) the connection's fatal-error
// mapping names. Only the ones a server can hit on inbound traffic are
// listed.
pub const transport_frame_encoding_error: u64 = 0x7;
pub const transport_flow_control_error: u64 = 0x3;
pub const transport_protocol_violation: u64 = 0xa;
pub const transport_application_error: u64 = 0xc;
pub const transport_crypto_buffer_exceeded: u64 = 0xd;
pub const transport_aead_limit_reached: u64 = 0x12;

/// Longest CONNECTION_CLOSE reason phrase this connection emits. RFC 9000
/// §19.19 bounds the field by a varint, but a reason is a diagnostic, not
/// a payload: 64 bytes holds a useful phrase and keeps the close frame a
/// rounding error next to a datagram. `closeWithError` asserts the caller
/// stays inside the cap and clips defensively before sealing, so a release
/// build still emits a well-formed frame if a caller slips.
pub const close_reason_max: usize = 64;

/// QUIC varints carry 62 bits (RFC 9000 §16); the vendor serializer ORs
/// the length tag into the top two bits, so a larger code would corrupt
/// the frame. Both CONNECTION_CLOSE types share the bound.
pub const close_error_code_max: u64 = (1 << 62) - 1;

/// The vendor packet crypto frees scratch in an order a bump-only fixed
/// buffer cannot reclaim (`processProtectedRawPacket` frees its raw-packet
/// dupe after allocating the results, so `FixedBufferAllocator.free` —
/// last-allocation-only — silently no-ops; `createProtectedRawPacket`
/// strands its header the same way). On a 1 MiB upload that residue is one
/// packet's bytes per packet processed, linear in the transfer: the
/// 256 KiB arena died ~200 packets in with closeWith OutOfMemory, observed
/// live. `CryptoPool` is the container-side answer (the vendor copy stays
/// untouched): a fixed pool of fixed-size slots whose free list reclaims
/// in ANY order. Two classes cover the layer's live set — key material and
/// headers in the small class, datagram-scale scratch in the large one —
/// and exhaustion asserts instead of corrupting: it means the pool, not
/// the wire, is wrong.
const crypto_pool_small_slot_bytes: usize = 128;
const crypto_pool_small_slots: usize = 32;
const crypto_pool_large_slot_bytes: usize = 1664; // max_datagram + header slop
const crypto_pool_large_slots: usize = 8;

const CryptoPool = struct {
    storage: [
        crypto_pool_small_slot_bytes * crypto_pool_small_slots +
            crypto_pool_large_slot_bytes * crypto_pool_large_slots
    ]u8 align(64) = undefined,
    free_small: [crypto_pool_small_slots]u8 = undefined,
    free_small_len: u8 = 0,
    free_large: [crypto_pool_large_slots]u8 = undefined,
    free_large_len: u8 = 0,

    fn init(self: *CryptoPool) void {
        for (0..crypto_pool_small_slots) |index| {
            self.free_small[index] = @intCast(crypto_pool_small_slots - 1 - index);
        }
        self.free_small_len = crypto_pool_small_slots;
        for (0..crypto_pool_large_slots) |index| {
            self.free_large[index] = @intCast(crypto_pool_large_slots - 1 - index);
        }
        self.free_large_len = crypto_pool_large_slots;
    }

    fn allocator(self: *CryptoPool) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable: std.mem.Allocator.VTable = .{
        .alloc = alloc,
        .resize = resize,
        .remap = remap,
        .free = free,
    };

    fn smallBase(self: *CryptoPool) [*]u8 {
        return @ptrCast(&self.storage);
    }

    fn largeBase(self: *CryptoPool) [*]u8 {
        return self.smallBase() + crypto_pool_small_slot_bytes * crypto_pool_small_slots;
    }

    fn alloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, ret_addr: usize) ?[*]u8 {
        _ = ret_addr;
        const self: *CryptoPool = @ptrCast(@alignCast(ctx));
        assert(alignment.toByteUnits() <= 64); // slots and storage are 64-aligned
        if (len <= crypto_pool_small_slot_bytes) {
            if (self.free_small_len == 0) {
                assert(false); // pool mis-sized: small slots exhausted
                return null;
            }
            self.free_small_len -= 1;
            const index = self.free_small[self.free_small_len];
            return self.smallBase() + @as(usize, index) * crypto_pool_small_slot_bytes;
        }
        if (len <= crypto_pool_large_slot_bytes) {
            if (self.free_large_len == 0) {
                assert(false); // pool mis-sized: large slots exhausted
                return null;
            }
            self.free_large_len -= 1;
            const index = self.free_large[self.free_large_len];
            return self.largeBase() + @as(usize, index) * crypto_pool_large_slot_bytes;
        }
        assert(false); // allocation larger than any slot: pool mis-sized
        return null;
    }

    fn resize(
        ctx: *anyopaque,
        memory: []u8,
        alignment: std.mem.Alignment,
        new_len: usize,
        ret_addr: usize,
    ) bool {
        _ = ctx;
        _ = memory;
        _ = alignment;
        _ = new_len;
        _ = ret_addr;
        return false; // no in-place resize: callers copy
    }

    fn remap(
        ctx: *anyopaque,
        memory: []u8,
        alignment: std.mem.Alignment,
        new_len: usize,
        ret_addr: usize,
    ) ?[*]u8 {
        _ = ctx;
        _ = memory;
        _ = alignment;
        _ = new_len;
        _ = ret_addr;
        return null; // no in-place remap: callers allocate-and-copy
    }

    fn free(ctx: *anyopaque, buf: []u8, alignment: std.mem.Alignment, ret_addr: usize) void {
        _ = alignment;
        _ = ret_addr;
        const self: *CryptoPool = @ptrCast(@alignCast(ctx));
        const base = @intFromPtr(self.smallBase());
        const end = base + self.storage.len;
        const ptr = @intFromPtr(buf.ptr);
        assert(ptr >= base and ptr < end); // not this pool's memory
        if (ptr < base + crypto_pool_small_slot_bytes * crypto_pool_small_slots) {
            const off = ptr - base;
            assert(off % crypto_pool_small_slot_bytes == 0);
            assert(buf.len <= crypto_pool_small_slot_bytes);
            const index: u8 = @intCast(off / crypto_pool_small_slot_bytes);
            for (self.free_small[0..self.free_small_len]) |free_index| {
                assert(free_index != index); // double free
            }
            self.free_small[self.free_small_len] = index;
            self.free_small_len += 1;
            return;
        }
        const off = ptr - base - crypto_pool_small_slot_bytes * crypto_pool_small_slots;
        assert(off % crypto_pool_large_slot_bytes == 0);
        assert(buf.len <= crypto_pool_large_slot_bytes);
        const index: u8 = @intCast(off / crypto_pool_large_slot_bytes);
        for (self.free_large[0..self.free_large_len]) |free_index| {
            assert(free_index != index); // double free
        }
        self.free_large[self.free_large_len] = index;
        self.free_large_len += 1;
    }
};

pub const Config = struct {
    cert_pem: []const u8,
    key_pem: []const u8,
    /// Opaque QUIC transport-parameters block passed through to qtls.
    transport_params: []const u8 = &.{},
};

pub const StreamHandler = struct {
    ctx: *anyopaque,
    /// `data` is transient: it points into the decrypted packet and is only
    /// valid for the duration of the call. Copy what must outlive it.
    onData: *const fn (ctx: *anyopaque, stream_id: u64, data: []const u8, fin: bool) void,
    /// RESET_STREAM received for `stream_id`: the peer aborted its send half
    /// (RFC 9000 §19.4), so the exchange on that stream will never see
    /// another frame from it. Fired after the stream's table slot is
    /// released — a handler re-entering the connection from the callback
    /// sees the freed table, and a second release path is a no-op. Null
    /// keeps the construction sites that predate the hook compiling; the
    /// H3 session subscribes where it wants the notification.
    on_reset: ?*const fn (ctx: *anyopaque, stream_id: u64) void = null,
};

/// Window-open notification: the subscriber re-attempts sends that
/// backpressure stalled, so it fires where the stall can end — after
/// `handleFrames` processed a frame group containing MAX_DATA or
/// MAX_STREAM_DATA, at most once per packet. It never fires from the
/// timer path; the listener's tick calls the subscriber itself as the
/// fallback retry beat. With nothing pending the callback must be a
/// cheap no-op, and a null `window_notify` clears the subscription.
pub const WindowNotify = struct {
    ctx: *anyopaque,
    onOpen: *const fn (ctx: *anyopaque) void,
};

/// Whether a process-wide server certificate is installed. qtls owns the
/// context; this flag only lets `initInPlace` configure it from `Config`
/// when the listener has not already done so.
var server_configured = false;

const SentPacket = struct {
    used: bool = false,
    pn: u64 = 0,
    sent_ns: u64 = 0,
    len: u16 = 0,
    /// The unprotected frame payload, before the ACK prefix. Retransmission
    /// resends the frames, not the acknowledgement that happened to ride
    /// with them.
    frames: [max_datagram_bytes]u8 = undefined,
};

const StreamState = struct {
    id: u64 = 0,
    offset: u64 = 0,
    /// Peer's current send allowance on this stream (MAX_STREAM_DATA may
    /// raise it).
    limit: u64 = 65_536,
    /// Bytes received on this stream, and the receive allowance we have
    /// advertised so far (raised by MAX_STREAM_DATA as it is consumed).
    recv: u64 = 0,
    recv_limit: u64 = recv_stream_window,
    advertised: u64 = recv_stream_window,
    used: bool = false,
    /// FIN sent to the peer on this stream; FIN received from it. Either
    /// alone keeps the slot (a unidirectional control stream sends no FIN,
    /// so it stays for the connection's life); both together mean the
    /// exchange is over and the slot can be reused.
    fin_sent: bool = false,
    fin_recv: bool = false,
};

pub const Connection = struct {
    // `fixed` is backed by `storage`; qtls, PacketCrypto and every packet
    // buffer take their memory from it. There is no second allocator and no
    // fallback to the page allocator.
    storage: [arena_bytes]u8 = undefined,
    fixed: std.heap.FixedBufferAllocator = undefined,

    tls_ctx: EnhancedTlsContext = undefined,
    crypto: PacketCrypto = undefined,
    /// Feeds `crypto`: see `CryptoPool` above. Fixed slots, any-order
    /// reclaim — the vendor crypto's free order would ratchet the main
    /// arena on every packet.
    crypto_pool: CryptoPool = .{},
    tls: ?*qtls.Tls = null,
    initialized: bool = false,

    peer: std.Io.net.IpAddress,
    stream_handler: ?StreamHandler = null,
    /// Subscriber for window-open events, fired by `handleFrames` after a
    /// frame group that carried MAX_DATA / MAX_STREAM_DATA (see
    /// `WindowNotify`). Installed and cleared by the listener layer.
    window_notify: ?WindowNotify = null,

    client_dcid: [20]u8 = undefined,
    client_dcid_len: u8 = 0,
    client_scid: [20]u8 = undefined,
    client_scid_len: u8 = 0,
    server_scid: [8]u8 = undefined,

    started: bool = false,
    closed: bool = false,
    /// Set by `closeWithError` (and latched when a peer CONNECTION_CLOSE
    /// arrives): a close is out or queued, so `sendStream`/`sendStreamMulti`
    /// refuse with error.Closing, while `onDatagram` still processes inbound
    /// packets so the close can be retransmitted until the peer goes silent
    /// — the idle deadline then reaps the slot, as it does for `abort`.
    /// `closed` stays false in this state: latching it would refuse the very
    /// datagrams the retransmission strategy answers.
    closing: bool = false,
    /// Close frame as sealed, for retransmission: the code and the clipped
    /// phrase. Fixed storage — the reason is capped at `close_reason_max`,
    /// so no allocation is needed to re-send.
    close_error_code: u64 = 0,
    close_reason_len: u8 = 0,
    close_reason: [close_reason_max]u8 = undefined,
    established: bool = false,
    handshake_keys_installed: bool = false,
    application_keys_installed: bool = false,
    idle_deadline_ns: ?u64 = null,

    /// Largest packet number seen per packet-number space (Initial,
    /// Handshake, Application), null until the first packet of that space.
    largest_pn: [3]?u64 = .{ null, null, null },
    crypto_len: [qtls.level_count]usize = .{ 0, 0, 0, 0 },
    crypto_rx: [qtls.level_count][crypto_buffer_bytes]u8 = undefined,

    datagrams: [datagram_slots][max_datagram_bytes]u8 = undefined,
    datagram_lens: [datagram_slots]usize = @splat(0),
    queue_head: usize = 0,
    queue_len: usize = 0,

    streams: [stream_slots]StreamState = @splat(StreamState{}),
    /// Received packet numbers awaiting an ACK.
    ack: recovery.AckTracker = .{},
    /// The receive pass's ACK-only supplement is sealed into this side
    /// channel rather than the datagram ring: `takeDatagram` offers it
    /// only when the ring is empty, so it never jumps ahead of data the
    /// application queues right after a receive. One slot: while it is
    /// occupied the newest packet numbers wait for the next seal, which
    /// in practice is one inbound datagram away — the listener drains the
    /// ring (and this) after every receive.
    ack_only_packet: [max_datagram_bytes]u8 = undefined,
    ack_only_packet_len: usize = 0,
    /// Set when a frame group just processed carried an ack-eliciting
    /// frame. `sealAckOnly` consults it so a peer's pure ACK packet is
    /// never answered with an ACK of its own (the tracker over-records —
    /// `consume` logs every packet number, ack-eliciting or not — so the
    /// pending flag alone cannot distinguish the two cases).
    saw_ack_eliciting: bool = false,
    /// RTT/PTO state and the frames of packets still waiting for an ACK.
    rtt: recovery.Rtt = .{},
    sent: [3][sent_slots]SentPacket = @splat(@splat(.{})),
    /// The clock at the last `onDatagram`; `sendStream` has no clock
    /// argument and uses this to timestamp what it seals.
    now_ns: u64 = 0,
    /// Peer transport-parameter limits. Defaults are zquic's, used until
    /// the client's parameters are decoded (and when a test client sends a
    /// placeholder block).
    peer_data_limit: u64 = 1_048_576,
    peer_data_sent: u64 = 0,
    peer_bidi_remote_limit: u64 = 65_536,
    peer_bidi_local_limit: u64 = 65_536,
    peer_uni_limit: u64 = 65_536,
    peer_params_loaded: bool = false,
    /// Connection-level receive accounting. `advertised` starts at the
    /// window and is raised as bytes are consumed.
    recv_data: u64 = 0,
    recv_data_advertised: u64 = recv_data_window,
    recv_data_limit: u64 = recv_data_window,
    recv_stream_limit: u64 = recv_stream_window,
    /// Client-bidi stream ceiling currently advertised to the peer: named
    /// once as `initial_max_streams_bidi` in the transport parameters, then
    /// raised monotonically by MAX_STREAMS frames as request slots free.
    /// A client opens streams in id order, so the count of streams it has
    /// opened is its highest id / 4 + 1 (RFC 9000 §4.5) — the ordinal a new
    /// stream id carries is checked against this before a state slot is
    /// spent on it.
    advertised_bidi_streams: u64 = constants.h3_request_streams_max,
    /// Caller-supplied transport parameters, or empty to let the connection
    /// build the server's own block once the first Initial reveals the CIDs.
    transport_params_override: []const u8 = &.{},

    /// Configure the process-wide server certificate once. Every connection
    /// created afterwards references the context qtls installs here.
    pub fn configureServer(cert_pem: []const u8, key_pem: []const u8) !void {
        try qtls.setServerCert(cert_pem, key_pem);
        server_configured = true;
    }

    /// Initialize in caller-provided storage. `allocator` is part of the
    /// listener's uniform call shape; the fixed arena is the only allocator
    /// this connection uses, so the argument is deliberately ignored.
    pub fn initInPlace(
        self: *Connection,
        allocator: std.mem.Allocator,
        peer: std.Io.net.IpAddress,
        config: Config,
    ) !void {
        _ = allocator;
        self.fixed = .init(&self.storage);
        self.peer = peer;
        self.tls = null;
        self.initialized = false;
        self.stream_handler = null;
        self.window_notify = null;
        self.client_dcid_len = 0;
        self.client_scid_len = 0;
        self.server_scid = @splat(0);
        self.started = false;
        self.closed = false;
        self.closing = false;
        self.close_error_code = 0;
        self.close_reason_len = 0;
        self.established = false;
        self.handshake_keys_installed = false;
        self.application_keys_installed = false;
        self.idle_deadline_ns = null;
        self.largest_pn = .{ null, null, null };
        self.crypto_len = .{ 0, 0, 0, 0 };
        self.queue_head = 0;
        self.queue_len = 0;
        self.streams = @splat(StreamState{});
        self.ack.initInPlace();
        self.saw_ack_eliciting = false;
        self.ack_only_packet_len = 0;
        self.rtt.initInPlace();
        self.sent = @splat(@splat(.{}));
        self.now_ns = 0;
        self.peer_data_limit = 1_048_576;
        self.peer_data_sent = 0;
        self.peer_bidi_remote_limit = 65_536;
        self.peer_bidi_local_limit = 65_536;
        self.peer_uni_limit = 65_536;
        self.peer_params_loaded = false;
        self.recv_data = 0;
        self.recv_data_advertised = recv_data_window;
        self.recv_data_limit = recv_data_window;
        self.recv_stream_limit = recv_stream_window;
        self.advertised_bidi_streams = constants.h3_request_streams_max;
        self.transport_params_override = config.transport_params;

        if (!server_configured) try configureServer(config.cert_pem, config.key_pem);
        self.tls_ctx = try EnhancedTlsContext.init(self.arena(), true, .aes_128_gcm_sha256);
        // The crypto layer allocates per packet and frees scratch in an
        // order a bump-only arena cannot reclaim (see `CryptoPool`); it
        // gets the slot pool, initialized first since its own init
        // allocates key material from it.
        self.crypto_pool.init();
        self.crypto = try PacketCrypto.init(self.crypto_pool.allocator(), &self.tls_ctx, null);
        // The server's transport parameters name the original DCID and the
        // server SCID, both known only from the first Initial; TLS is
        // initialized in `begin`.
        self.tls = null;
        self.initialized = true;
    }

    /// Release OpenSSL objects. The arena itself is caller-owned memory and
    /// needs no freeing; `free` on it only rewinds the most recent allocation.
    pub fn deinit(self: *Connection) void {
        if (!self.initialized) return;
        if (self.tls) |tls| {
            tls.destroy();
            self.tls = null;
        }
        self.crypto.deinit();
        self.tls_ctx.deinit();
        self.initialized = false;
    }

    /// Bytes the connection has claimed from its arena. A banner can price
    /// this; it never exceeds `arena_bytes`.
    pub fn arenaUsedBytes(self: *const Connection) usize {
        return self.fixed.end_index;
    }

    pub fn setStreamHandler(self: *Connection, handler: StreamHandler) void {
        self.stream_handler = handler;
    }

    /// Accept one raw QUIC datagram. Protocol errors close the connection
    /// and are returned; the listener is expected to drop it.
    pub fn onDatagram(self: *Connection, bytes: []const u8, now_ns: u64) !void {
        self.now_ns = now_ns;
        self.idle_deadline_ns = now_ns + idle_timeout_ns;
        if (self.closed) return error.ConnectionClosed;
        if (bytes.len > max_datagram_bytes) {
            self.closeWith(error.DatagramTooLarge);
            return error.DatagramTooLarge;
        }
        if (bytes.len == 0) {
            self.closeWith(error.InvalidPacket);
            return error.InvalidPacket;
        }
        self.saw_ack_eliciting = false;
        // One UDP datagram may carry several long-header packets
        // (Initial + Handshake is the common client coalescing). Walk them
        // in order; a short header always consumes the rest.
        var offset: usize = 0;
        while (offset < bytes.len) {
            const rest = bytes[offset..];
            // Implementations may pad the datagram after the last packet
            // (aioquic does for Initials). Those bytes are not a packet.
            if (rest[0] == 0x00) break;
            if (!self.started) self.begin(rest) catch |err| {
                self.closeWith(err);
                return err;
            };
            const packet_bytes = packetLen(rest) orelse rest.len;
            self.consume(rest[0..packet_bytes]) catch |err| {
                // An established-phase protocol error answers with a
                // CONNECTION_CLOSE (see `closeWith`); the walk then ends
                // normally so the caller drains the queued close before
                // any reap — an error return would forfeit it. Before
                // the handshake the error stays silent and propagates.
                if (self.fatalWalkError(err)) return;
                return err;
            };
            // A coalesced datagram can carry Initial + Handshake + 1-RTT.
            // Drive TLS after each packet so the keys that packet unlocked
            // are installed before the next one is decrypted.
            self.driveTls() catch |err| {
                if (self.fatalWalkError(err)) return;
                return err;
            };
            // A received CONNECTION_CLOSE (or a packet error above) latches
            // `closed`: stop walking coalesced packets — the rest of this
            // datagram is moot and must not resurrect stream slots.
            if (self.closed) return;
            offset += packet_bytes;
        }
        // One outbound answer per inbound datagram, closing first. A
        // closing connection retransmits its CONNECTION_CLOSE — and `seal`
        // prefixes the pending ACK onto that close anyway — so an ACK-only
        // packet must not compete with it for the slot. An open
        // connection that produced nothing owes the peer an ACK-only
        // packet when what it just received was ack-eliciting
        // (`sealAckOnly`): a one-for-one answer is RFC 9002 §7.1's
        // ack-delay restraint, and it is what keeps an upload-heavy
        // peer's congestion window draining.
        if (self.closing) {
            self.retransmitClose();
        } else {
            self.sealAckOnly();
        }
    }

    /// Next outbound raw datagram, or null. The slice points into the
    /// connection and stays valid until the next call. The ring leads; a
    /// sealed ACK-only supplement (`sealAckOnly`) is offered only when the
    /// ring is empty, so pure ACKs never overtake application data.
    pub fn takeDatagram(self: *Connection) ?[]const u8 {
        if (self.queue_len == 0) {
            if (self.ack_only_packet_len == 0) return null;
            const stashed = self.ack_only_packet[0..self.ack_only_packet_len];
            self.ack_only_packet_len = 0;
            return stashed;
        }
        const slot = self.queue_head;
        const len = self.datagram_lens[slot];
        self.queue_head = (self.queue_head + 1) % datagram_slots;
        self.queue_len -= 1;
        return self.datagrams[slot][0..len];
    }

    /// Queue one STREAM frame at the application level. The offset starts at
    /// zero per stream and advances by the bytes previously sent.
    ///
    /// A released slot must not outlive its release anywhere: PTO
    /// retransmission resends the frame copy retained in `sent`, it never
    /// re-enters `sendStream`, and every `streamState`/`findStream` pointer
    /// is transient within one call. A FIN answering a FIN whose twin
    /// already arrived therefore frees the slot right here.
    pub fn sendStream(self: *Connection, stream_id: u64, data: []const u8, fin: bool) !void {
        if (self.closing) return error.Closing;
        if (!self.established) return error.HandshakeIncomplete;
        const stream = try self.streamState(stream_id);
        if (stream.offset + data.len > stream.limit) return error.FlowControlBlocked;
        if (self.peer_data_sent + data.len > self.peer_data_limit) {
            return error.FlowControlBlocked;
        }
        var payload: [max_datagram_bytes]u8 = undefined;
        var writer: std.Io.Writer = .fixed(&payload);
        const frame = QuicFrames.Frame{
            .stream = .init(stream_id, stream.offset, data, fin, stream.offset != 0, true),
        };
        frame.serialize(&writer) catch return error.DatagramTooLarge;
        const packet = try self.seal(tls_application, payload[0..writer.end]);
        defer self.cryptoAllocator().free(packet);
        try self.pushDatagram(packet);
        stream.offset += data.len;
        self.peer_data_sent += data.len;
        if (fin) {
            stream.fin_sent = true;
            // A synchronous request handler answers inside the inbound
            // `onData`, below in `handleFrames`, so the peer's FIN may
            // already be recorded: then both halves are done and the slot
            // frees on this, the response-FIN send.
            if (stream.fin_recv) releaseStreamState(stream);
        }
    }

    /// Queue `data` as STREAM frames across as many datagrams as it takes,
    /// returning the bytes queued. Built for response bodies larger than
    /// one datagram: each iteration seals one chunk of at most
    /// `max_stream_frame_payload` bytes, so the wire limit is per-chunk,
    /// not per-call.
    ///
    /// Backpressure is the return value, not an error: a full datagram
    /// queue, or a flow-control window that cannot hold the next chunk,
    /// stops the loop and reports what was queued. Less than `data.len`
    /// means the caller keeps the remainder and re-invokes with it once
    /// the queue has drained or MAX_DATA / MAX_STREAM_DATA raised the
    /// window. Each chunk is flow-checked whole, with `sendStream`'s
    /// verdict: a chunk that does not fit waits, rather than sending a
    /// clipped piece the peer's reassembly would misread. `fin` rides the
    /// chunk that completes `data` and only that chunk, so a cut-short
    /// caller re-invokes with the tail and `fin` still true. A
    /// `data.len == 0` call with `fin` sends one empty STREAM frame, so a
    /// bodyless response can still close its stream. Errors are the hard
    /// kind: handshake state, a full stream table, or a seal failure.
    pub fn sendStreamMulti(
        self: *Connection,
        stream_id: u64,
        data: []const u8,
        fin: bool,
    ) !usize {
        if (self.closing) return error.Closing;
        if (!self.established) return error.HandshakeIncomplete;
        const stream = try self.streamState(stream_id);
        if (data.len == 0) {
            if (!fin) return 0;
            // An empty FIN still needs a frame on the wire; pad past the
            // header-protection minimum payload `seal` enforces.
            var payload: [max_datagram_bytes]u8 = undefined;
            var writer: std.Io.Writer = .fixed(&payload);
            const frame = QuicFrames.Frame{
                .stream = .init(stream_id, stream.offset, &.{}, true, stream.offset != 0, true),
            };
            frame.serialize(&writer) catch return error.DatagramTooLarge;
            while (writer.end < 8) writer.writeByte(0) catch return error.DatagramTooLarge;
            const packet = try self.seal(tls_application, payload[0..writer.end]);
            defer self.cryptoAllocator().free(packet);
            try self.pushDatagram(packet);
            stream.fin_sent = true;
            if (stream.fin_recv) releaseStreamState(stream);
            return 0;
        }
        var sent: usize = 0;
        while (sent < data.len) {
            const chunk_len = @min(data.len - sent, max_stream_frame_payload);
            // Flow control before queue state: both verdicts are "report
            // the short write", and a window check never burns a packet
            // number or a sealed allocation.
            if (stream.offset + chunk_len > stream.limit) break;
            if (self.peer_data_sent + chunk_len > self.peer_data_limit) break;
            // Seal only when a queue slot is known free: a sealed packet
            // that cannot be queued would spend a packet number for
            // nothing.
            if (self.queue_len >= datagram_slots) break;
            const last = sent + chunk_len == data.len;
            var payload: [max_datagram_bytes]u8 = undefined;
            var writer: std.Io.Writer = .fixed(&payload);
            const frame = QuicFrames.Frame{
                .stream = .init(
                    stream_id,
                    stream.offset,
                    data[sent..][0..chunk_len],
                    fin and last,
                    stream.offset != 0,
                    true,
                ),
            };
            frame.serialize(&writer) catch return error.DatagramTooLarge;
            const packet = try self.seal(tls_application, payload[0..writer.end]);
            defer self.cryptoAllocator().free(packet);
            self.pushDatagram(packet) catch |err| switch (err) {
                error.QueueFull => break, // pre-checked above; defensive
                else => return err,
            };
            stream.offset += chunk_len;
            self.peer_data_sent += chunk_len;
            sent += chunk_len;
        }
        if (fin and sent == data.len) {
            stream.fin_sent = true;
            // Same release pairing as `sendStream`: a handler answering
            // synchronously inside `onData` may already hold the peer's
            // FIN.
            if (stream.fin_recv) releaseStreamState(stream);
        }
        return sent;
    }

    /// Abort `stream_id`'s send half: queue a RESET_STREAM naming
    /// `error_code` and release the table slot. RFC 9000 §19.4 ties the
    /// frame's final size to the send offset — bytes in flight are
    /// abandoned, not retransmitted — so a stream that never opened here
    /// reports a final size of 0. The release mirrors `dropStream`: the
    /// session's slot accounting sees the stream gone immediately, and a
    /// later frame for the id is a fresh open, not a reuse. Receive-side
    /// resets are handled in `handleFrames`.
    pub fn resetStream(self: *Connection, stream_id: u64, error_code: u64) !void {
        if (!self.established) return error.HandshakeIncomplete;
        var final_size: u64 = 0;
        if (self.findStream(stream_id)) |stream| {
            final_size = stream.offset;
            releaseStreamState(stream);
        }
        var payload: [max_datagram_bytes]u8 = undefined;
        var writer: std.Io.Writer = .fixed(&payload);
        const frame = QuicFrames.ResetStreamFrame.init(stream_id, error_code, final_size);
        frame.serialize(&writer) catch return error.DatagramTooLarge;
        // Same header-protection minimum as `raiseBidiStreamLimit`: the
        // frame alone is a handful of varints, so it rides with PADDING.
        while (writer.end < 8) writer.writeByte(0) catch return error.DatagramTooLarge;
        const packet = try self.seal(tls_application, payload[0..writer.end]);
        defer self.cryptoAllocator().free(packet);
        try self.pushDatagram(packet);
    }

    pub fn isEstablished(self: *const Connection) bool {
        return self.established;
    }

    pub fn isClosed(self: *const Connection) bool {
        return self.closed;
    }

    /// The H3 layer detected an unrecoverable protocol error (for example
    /// a QPACK encoder-stream violation, RFC 9204 §5.3) and the connection
    /// cannot honestly continue. This is the *silent* teardown: no
    /// CONNECTION_CLOSE is attempted, the closed flag refuses further
    /// datagrams, and a zero idle deadline makes the next reaper sweep (or
    /// the next inbound packet's redundant check) free the slot instead of
    /// waiting out the idle timeout. The peer, having broken the protocol,
    /// gets no parting bytes. Where the peer should learn why the
    /// connection died — the common case for an H3-layer fatal — prefer
    /// `closeWithError`, which puts a CONNECTION_CLOSE frame on the wire.
    /// Both remain valid: `abort` still suits the graceful idle-reap path
    /// and any pre-1-RTT death where no keys exist to seal with. `abort`
    /// also latches `closing`, so sends after it take the same
    /// error.Closing path as every other dead connection instead of
    /// sealing bytes into a connection that will never drain them.
    pub fn abort(self: *Connection) void {
        if (self.closed) return;
        self.closed = true;
        self.closing = true;
        self.idle_deadline_ns = 0;
    }

    /// Send CONNECTION_CLOSE and enter the closing state. `error_code` is
    /// a QUIC transport error code or one of the `h3_*` application codes
    /// above (parameterized as a plain u64 so both tables reach the wire
    /// unchanged); `reason` is a diagnostic phrase of at most
    /// `close_reason_max` bytes — asserted here, and clipped before
    /// sealing so a release build still emits a well-formed frame if a
    /// caller slips.
    ///
    /// The frame is the transport-level type 0x1c (RFC 9000 §19.19), not
    /// the application-level 0x1d RFC 9114 §8.1 would pair with H3 codes:
    /// this slice has exactly one close path, it lives at the connection
    /// layer, and 0x1c is the variant every peer stack surfaces in
    /// diagnostics. Carrying an `h3_*` code in it is the pragmatic choice
    /// of this experimental slice; 0x1d is a one-line switch in
    /// `sealCloseFrame` once a caller genuinely needs it.
    ///
    /// The close outranks everything queued: the pending datagram ring is
    /// cleared first, so the close goes out ahead of STREAM data and still
    /// fits a full ring. The tradeoff is deliberate — after
    /// CONNECTION_CLOSE the peer discards every stream anyway, so queued
    /// response bytes are dead weight that could otherwise hold the close
    /// hostage.
    ///
    /// Closing refuses new `sendStream`/`sendStreamMulti` with
    /// error.Closing but keeps `onDatagram` live: each inbound datagram
    /// retransmits the close at most once (`retransmitClose`) until the
    /// peer goes silent, and the frame copy retained in the sent ring is
    /// re-sent by PTO ticks independently. The first close is sealed once
    /// — calling `closeWithError` again is an idempotent no-op, not a
    /// second frame. If application keys are not installed (a pre-1-RTT
    /// death) the frame cannot be sealed, and this falls back to `abort`'s
    /// silent teardown.
    pub fn closeWithError(self: *Connection, error_code: u64, reason: []const u8) void {
        assert(error_code <= close_error_code_max);
        assert(reason.len <= close_reason_max);
        if (self.closing or self.closed) return;
        self.closing = true;
        self.close_error_code = error_code;
        const phrase = reason[0..@min(reason.len, close_reason_max)];
        @memcpy(self.close_reason[0..phrase.len], phrase);
        self.close_reason_len = @intCast(phrase.len);
        if (!self.application_keys_installed) {
            self.closed = true;
            self.idle_deadline_ns = 0;
            return;
        }
        // The close outranks everything queued (see the doc above): clear
        // the ring — and a sealed ACK-only supplement waiting in its side
        // channel — so the close leads them all.
        self.queue_head = 0;
        self.queue_len = 0;
        self.ack_only_packet_len = 0;
        self.sealCloseFrame() catch {
            // Sealing or queueing failed (crypto exhaustion): a close the
            // peer never learns about degrades to the silent abort.
            self.closed = true;
            self.idle_deadline_ns = 0;
        };
    }

    /// Seal one CONNECTION_CLOSE frame (type 0x1c, frame_type 0 — no
    /// single frame provoked the kill) from the state `closeWithError`
    /// recorded, and queue it. Shared by the first close and the
    /// per-datagram retransmissions. Like `resetStream`'s frame, the close
    /// is a handful of varints, so it rides with PADDING past the
    /// header-protection minimum payload `seal` enforces. `seal` retains
    /// the payload in the sent ring, which is what lets a PTO tick
    /// re-send the close like any un-acked packet: the ring entry lives
    /// and dies by the ACK/PTO bookkeeping there, not by anything here.
    fn sealCloseFrame(self: *Connection) !void {
        var payload: [max_datagram_bytes]u8 = undefined;
        var writer: std.Io.Writer = .fixed(&payload);
        const frame = QuicFrames.ConnectionCloseFrame.init(
            self.close_error_code,
            0,
            self.close_reason[0..self.close_reason_len],
        );
        try frame.serialize(&writer);
        while (writer.end < 8) try writer.writeByte(0);
        const packet = try self.seal(tls_application, payload[0..writer.end]);
        defer self.cryptoAllocator().free(packet);
        try self.pushDatagram(packet);
    }

    /// Answer one inbound datagram during the closing state with a fresh
    /// close frame (RFC 9000 §10.2.3's "retransmit in response to
    /// anything received", simplified from the RFC's timer-based form to
    /// one re-send per `onDatagram` — bounded by the peer's packet rate,
    /// which is exactly what goes silent when the peer drains). Best
    /// effort: a full ring or a seal failure drops the re-send, since the
    /// original close is already on the wire and PTO retransmits the sent
    /// ring independently.
    fn retransmitClose(self: *Connection) void {
        if (!self.application_keys_installed) return;
        if (self.queue_len >= datagram_slots) return;
        self.sealCloseFrame() catch {};
    }

    /// ACK-only supplement — the receive path's answer to a silent send
    /// path. `seal` prefixes a space's pending ACK onto whatever data it
    /// seals, but an upload-heavy peer can leave us with nothing to send
    /// for seconds; its congestion window then never drains and the
    /// upload stalls (observed live as a freeze past ~27 KiB, the first
    /// flow-control wall the client cannot pass without our ACKs). So
    /// when a receive pass produced no datagram at all and the packets it
    /// processed carried ack-eliciting frames, seal one ACK-only packet:
    /// PADDING carries the payload to the header-protection minimum
    /// (eight bytes, the convention `resetStream` already uses) and `seal`
    /// prepends the ACK frame from the tracker. At most one per inbound
    /// datagram, and only for ack-eliciting input — a one-for-one answer
    /// is exactly RFC 9002 §7.1's ack-delay restraint, and during a large
    /// upload packets arrive every few milliseconds, far inside aioquic's
    /// 25 ms `max_ack_delay`, so no timer is kept for this: a tick-driven
    /// variant would add a `now_ns` comparison to the tracker to cover a
    /// case the per-datagram rule already covers. The sealed packet goes
    /// into the `ack_only_packet` side channel (not the ring) so it never
    /// overtakes data queued behind it; its padding payload still passes
    /// through `seal` unchanged, landing in the sent ring with a normal
    /// lifecycle — the peer never ACKs a non-ack-eliciting packet, so the
    /// entry ages out through the PTO/replacement cycle — and a seal
    /// failure here is deliberate best-effort: the missed ACK costs the
    /// peer one retransmission round, and that re-arms this path.
    fn sealAckOnly(self: *Connection) void {
        if (!self.application_keys_installed) return;
        if (self.queue_len != 0) return;
        if (self.ack_only_packet_len != 0) return;
        if (!self.saw_ack_eliciting) return;
        if (!self.ack.needsAck(.application)) return;
        var payload: [8]u8 = @splat(0);
        const packet = self.seal(tls_application, payload[0..]) catch return;
        defer self.cryptoAllocator().free(packet);
        assert(packet.len <= max_datagram_bytes);
        @memcpy(self.ack_only_packet[0..packet.len], packet);
        self.ack_only_packet_len = packet.len;
    }

    pub fn idleDeadline(self: *const Connection) ?u64 {
        return self.idle_deadline_ns;
    }

    pub fn clientDcid(self: *const Connection) []const u8 {
        return self.client_dcid[0..self.client_dcid_len];
    }

    pub fn serverScid(self: *const Connection) []const u8 {
        return &self.server_scid;
    }

    fn arena(self: *Connection) std.mem.Allocator {
        return self.fixed.allocator();
    }

    /// The allocator behind every slice the packet crypto returns —
    /// sealed packets, processed packets: fixed slots with any-order
    /// reclaim (see `CryptoPool`), never the main arena. Freeing crypto
    /// output through `arena()` would corrupt the arena's bump state.
    fn cryptoAllocator(self: *Connection) std.mem.Allocator {
        return self.crypto_pool.allocator();
    }

    /// Latch a fatal protocol error and hand it back to the caller. An
    /// established connection puts the verdict on the wire:
    /// `closeWithError` seals a CONNECTION_CLOSE naming the closest
    /// transport error code (`transportErrorFor`'s mapping, RFC 9000
    /// §20), and the closing state keeps answering the peer's datagrams
    /// with close retransmissions until it goes quiet — a fuzzing or
    /// misbehaving peer learns the verdict instead of riding the idle
    /// timeout. Before the handshake the death stays silent: there are
    /// no application keys to seal with, and §10.2.3's early-close rules
    /// make the short answer the honest one. Local limits and
    /// packet-protection noise never earn a frame — a byte string that
    /// fails AEAD, or an oversized UDP payload from a random sender, is
    /// not a QUIC peer talking (§10.2.2's rule against punishing the
    /// blameless), and answering it would spend sends on something that
    /// cannot parse a frame.
    fn closeWith(self: *Connection, err: anyerror) void {
        // Already closing: the verdict is on the wire and retransmission
        // continues until the peer goes quiet; a later error — including
        // malformed-packet noise — adds nothing.
        if (self.closing) return;
        if (self.established) {
            if (transportErrorFor(err)) |code| {
                self.closeWithError(code, @errorName(err));
            } else {
                self.closed = true;
                self.closing = true;
            }
        } else {
            self.closed = true;
        }
    }

    /// The receive walk's fatal-error outlet: `closeWith` has already
    /// framed or silenced the death; this reports whether the walk should
    /// swallow the error (established — the queued close must reach the
    /// caller's drain, which an error return would skip) or propagate it
    /// (pre-handshake, where silence and the listener's drop are the
    /// whole story).
    fn fatalWalkError(self: *Connection, err: anyerror) bool {
        self.closeWith(err);
        return self.established;
    }

    /// Map a fatal receive-path condition onto the closest RFC 9000 §20
    /// transport error code, or null when the peer did not earn a frame
    /// (local limits and malformed-packet noise). The mapping is the
    /// whole red-line discipline: every arm must be unreachable by a
    /// conforming peer, or the frame punishes innocence.
    fn transportErrorFor(err: anyerror) ?u64 {
        return switch (err) {
            error.InvalidPacket,
            error.DatagramTooLarge,
            error.InvalidConnectionId,
            error.UnsupportedPacket,
            error.NotInitial,
            error.MissingSourceConnectionId,
            // Packet-protection failures and pre-handshake noise: a byte
            // string that fails AEAD is not a peer talking.
            => null,
            error.OutOfMemory => null, // local budget, never the peer's
            error.InvalidFrame => transport_frame_encoding_error,
            error.FlowControlError => transport_flow_control_error,
            error.CryptoTooLarge => transport_crypto_buffer_exceeded,
            // Everything else that reaches here is a protocol violation:
            // CRYPTO gaps, truncated frame varints, and the like. A gap
            // can in principle follow loss rather than malice, but the
            // connection was ending either way, and the frame at least
            // tells an honest client why.
            else => transport_protocol_violation,
        };
    }

    /// First datagram: requires an Initial and locks the connection ids and
    /// Initial keys to it. A server's first flight must be addressed to the
    /// client's source connection id, so both ids are kept.
    fn begin(self: *Connection, bytes: []const u8) !void {
        const header = try Packet.PacketHeader.parse(bytes, self.arena());
        if (header.packet_type != .initial) return error.NotInitial;
        const scid = header.src_conn_id orelse return error.MissingSourceConnectionId;
        try storeCid(&self.client_dcid, &self.client_dcid_len, header.dest_conn_id.bytes());
        try storeCid(&self.client_scid, &self.client_scid_len, scid.bytes());
        self.deriveServerScid(header.dest_conn_id.bytes());
        try self.crypto.installRfc9001ServerInitialKeys(self.clientDcid());
        try self.startTls();
        self.started = true;
    }

    /// Decrypt one datagram, then feed its frames to TLS or the handler.
    fn consume(self: *Connection, bytes: []const u8) !void {
        const header = try Packet.PacketHeader.parse(bytes, self.arena());
        const slot: usize = switch (header.packet_type) {
            .initial => 0,
            .handshake => 1,
            .one_rtt => 2,
            else => return error.UnsupportedPacket,
        };
        var packet = try self.crypto.processProtectedRawPacket(bytes, self.largest_pn[slot]);
        defer packet.deinit(self.cryptoAllocator());
        self.largest_pn[slot] = if (self.largest_pn[slot]) |largest|
            @max(largest, packet.packet_number)
        else
            packet.packet_number;
        self.ack.onReceived(spaceOfSlot(slot), packet.packet_number);
        try self.handleFrames(tls_levels[slot], packet.payload);
    }

    fn handleFrames(self: *Connection, level: usize, payload: []const u8) !void {
        var reader: std.Io.Reader = .fixed(payload);
        // Set when a frame in this group raised a flow-control ceiling; the
        // notify fires once, after the whole group is processed, so the
        // subscriber's retry pass sees every update the datagram carried.
        var window_opened = false;
        while (reader.seek < reader.end) {
            var frame = try QuicFrames.Frame.parse(&reader, self.arena());
            defer frame.deinit(self.arena());
            if (frame.isAckEliciting()) self.saw_ack_eliciting = true;
            switch (frame) {
                .ack => |ack| try self.onAck(level, ack),
                .max_data => |max_data| {
                    self.peer_data_limit = @max(
                        self.peer_data_limit,
                        max_data.maximum_data,
                    );
                    window_opened = true;
                },
                .max_stream_data => |max_stream_data| {
                    if (self.findStream(max_stream_data.stream_id)) |stream| {
                        stream.limit = @max(stream.limit, max_stream_data.maximum_stream_data);
                    }
                    // The notify fires even when no slot holds the id: the
                    // subscriber's retry pass is keyed by stream, and a miss
                    // there costs what it costs here.
                    window_opened = true;
                },
                .crypto => |crypto| try self.feedCrypto(level, crypto),
                .stream, .stream_fin, .stream_len, .stream_len_fin, .stream_off, .stream_off_fin, .stream_off_len, .stream_off_len_fin => |stream| {
                    // A stream past the advertised ceiling is dropped, not
                    // fatal: RFC 9000 §4.5 counts the streams a peer has
                    // opened as its highest id / 4 + 1 and names
                    // STREAM_LIMIT_ERROR for the violation, but the same
                    // pattern falls out of an honest client that has not
                    // seen our latest MAX_STREAMS yet (loss or reorder),
                    // and killing the connection for it would be
                    // unrecoverable where the drop is not. After a raise
                    // the client may simply
                    // resend; the stream state it would have claimed is
                    // never allocated.
                    if (self.bidiOpenBeyondLimit(stream.stream_id)) continue;
                    const state = try self.streamState(stream.stream_id);
                    const end = stream.offset + stream.data.len;
                    if (end > state.recv_limit) return error.FlowControlError;
                    if (self.recv_data + stream.data.len > self.recv_data_limit) {
                        return error.FlowControlError;
                    }
                    state.recv = @max(state.recv, end);
                    self.recv_data += stream.data.len;
                    // Record the peer's FIN before the handler runs: it may
                    // answer synchronously, and that response FIN is what
                    // frees the slot for a completed request exchange.
                    if (stream.fin) state.fin_recv = true;
                    if (self.stream_handler) |handler| {
                        handler.onData(handler.ctx, stream.stream_id, stream.data, stream.fin);
                    }
                    // The synchronous handler above may already have freed
                    // the slot (a released slot reads `used == false`), in
                    // which case this is a no-op. It fires when our FIN went
                    // out earlier — a response ahead of the request's final
                    // frame — and the peer's FIN only now caught up.
                    if (stream.fin and state.used and state.fin_sent) {
                        releaseStreamState(state);
                    }
                },
                .reset_stream => |reset| {
                    // The peer abandoned its send half (RFC 9000 §19.4).
                    // Free the slot exactly like `dropStream`: state in
                    // the table is discarded, unknown ids are ignored,
                    // and a late frame for the id reopens fresh rather
                    // than reusing stale offsets. The release runs before
                    // the notification so a handler re-entering the
                    // connection from `on_reset` sees the freed table.
                    // Final-size validation against received bytes stays
                    // unenforced, matching this receive path's minimal
                    // accounting.
                    const state = self.findStream(reset.stream_id) orelse continue;
                    releaseStreamState(state);
                    if (self.stream_handler) |handler| {
                        if (handler.on_reset) |on_reset| {
                            on_reset(handler.ctx, reset.stream_id);
                        }
                    }
                },
                // Peer-declared death (RFC 9000 §19.19; §10.2.2/§10.3 for
                // what follows — draining). Both frame flavors latch the
                // same state here: nothing more is worth sending, so
                // refuse new datagrams, release every stream slot
                // (`activeStreamCount` hits zero for the reaper's tests),
                // and zero the idle deadline so the listener's next sweep
                // frees the slot instead of waiting out 30 idle seconds.
                // Upper layers learn of the death through the channel a
                // silent `abort` already used: the listener reaps the slot
                // and tears its exchanges down — `StreamHandler` has no
                // connection-level callback to fire (later work hooks one
                // up), so nothing above the connection is touched here.
                .connection_close, .connection_close_app => {
                    self.closing = true;
                    self.closed = true;
                    self.idle_deadline_ns = 0;
                    for (&self.streams) |*stream| releaseStreamState(stream);
                    return;
                },
                else => {},
            }
        }
        if (window_opened) {
            if (self.window_notify) |notify| notify.onOpen(notify.ctx);
        }
    }

    /// Reassemble one level's CRYPTO stream. This slice refuses gaps rather
    /// than buffering them: without recovery there is nobody to fill a gap.
    fn feedCrypto(self: *Connection, level: usize, crypto: QuicFrames.CryptoFrame) !void {
        if (level >= qtls.level_count) return error.UnsupportedLevel;
        const have = self.crypto_len[level];
        // A retransmitted Initial can repeat bytes already delivered. Feed
        // only the tail that extends the stream; a fully duplicate frame is
        // a no-op. A gap is still refused: without recovery ordering there
        // is nothing to fill it.
        const offset: usize = @intCast(crypto.offset);
        if (offset < have) {
            const overlap = have - offset;
            if (overlap >= crypto.data.len) return;
            const tail = crypto.data[overlap..];
            if (tail.len > self.crypto_rx[level].len - have) return error.CryptoTooLarge;
            const dst = self.crypto_rx[level][have..][0..tail.len];
            @memcpy(dst, tail);
            self.crypto_len[level] = have + tail.len;
            try self.tls.?.pushCrypto(level, dst);
            return;
        }
        if (offset != have) return error.OutOfOrderCrypto;
        if (crypto.data.len > self.crypto_rx[level].len - have) return error.CryptoTooLarge;
        const dst = self.crypto_rx[level][have..][0..crypto.data.len];
        @memcpy(dst, crypto.data);
        self.crypto_len[level] = have + crypto.data.len;
        try self.tls.?.pushCrypto(level, dst);
    }

    /// A peer ACK: sample RTT from the largest acknowledged packet and
    /// retire every retained packet the ranges cover. `Rtt.onAck` prunes
    /// its own list; the frame copy is ours to clear.
    fn onAck(self: *Connection, level: usize, ack: QuicFrames.AckFrame) !void {
        const space = spaceOfLevel(level);
        self.rtt.onAck(space, ack.largest_acknowledged, self.now_ns, ack.ack_delay);
        for (&self.sent[spaceIndex(space)]) |*packet| {
            if (!packet.used) continue;
            if (ackedBy(packet.pn, ack)) packet.used = false;
        }
    }

    /// One PTO tick for this connection. Returns true when a datagram was
    /// queued, so the listener can drain it immediately. At most one packet
    /// per packet-number space is resent per tick; `Rtt` owns the backoff.
    pub fn onTimeout(self: *Connection, now_ns: u64) bool {
        self.now_ns = now_ns;
        var queued = false;
        for ([_]usize{ tls_initial, tls_handshake, tls_application }) |level| {
            const space = spaceOfLevel(level);
            const deadline = self.rtt.pto(space) orelse continue;
            if (deadline > now_ns) continue;
            if (self.retransmitOldest(level, space) catch false) queued = true;
        }
        return queued;
    }

    fn retransmitOldest(
        self: *Connection,
        level: usize,
        space: recovery.Space,
    ) !bool {
        const ring = &self.sent[spaceIndex(space)];
        var chosen: ?usize = null;
        for (ring, 0..) |*packet, index| {
            if (!packet.used) continue;
            if (chosen == null or packet.pn < ring[chosen.?].pn) chosen = index;
        }
        const index = chosen orelse return false;

        var frames: [max_datagram_bytes]u8 = undefined;
        const len = ring[index].len;
        @memcpy(frames[0..len], ring[index].frames[0..len]);
        const old_pn = ring[index].pn;
        ring[index].used = false;
        self.rtt.onPacketLost(space, old_pn);

        // `seal` records the new packet (with a fresh number) and timestamps
        // it; the caller drains it into a datagram.
        const packet = try self.seal(level, frames[0..len]);
        defer self.cryptoAllocator().free(packet);
        try self.pushDatagram(packet);
        self.rtt.onPtoFired(space);
        return true;
    }

    /// Retain an ack-eliciting packet's frames for a possible PTO resend.
    fn rememberSent(self: *Connection, level: usize, pn: u64, payload: []const u8) void {
        assert(payload.len <= max_datagram_bytes);
        const space = spaceOfLevel(level);
        const ring = &self.sent[spaceIndex(space)];
        var slot: usize = 0;
        while (slot < sent_slots) : (slot += 1) {
            if (!ring[slot].used) break;
        }
        if (slot == sent_slots) {
            // Full: replace the oldest packet number. Its ACK would be
            // stale anyway, and the ring is a recovery aid, not history.
            slot = 0;
            var index: usize = 1;
            while (index < sent_slots) : (index += 1) {
                if (ring[index].pn < ring[slot].pn) slot = index;
            }
        }
        ring[slot] = .{
            .used = true,
            .pn = pn,
            .sent_ns = self.now_ns,
            .len = @intCast(payload.len),
        };
        @memcpy(ring[slot].frames[0..payload.len], payload);
        self.rtt.onSent(space, pn, self.now_ns);
    }

    /// Build the server's transport parameters now that the first Initial
    /// named both connection ids, and hand them to OpenSSL. A caller that
    /// supplied its own block keeps it verbatim (tests do this).
    fn startTls(self: *Connection) !void {
        if (self.transport_params_override.len > 0) {
            self.tls = try qtls.Tls.initServer(self.arena(), self.transport_params_override);
            return;
        }
        var params = zquic.core.TransportParameters.TransportParameters{};
        params.max_idle_timeout = idle_timeout_ns / std.time.ns_per_ms;
        params.initial_max_data = self.recv_data_limit;
        params.initial_max_stream_data_bidi_local = self.recv_stream_limit;
        params.initial_max_stream_data_bidi_remote = self.recv_stream_limit;
        params.initial_max_stream_data_uni = self.recv_stream_limit;
        params.initial_max_streams_bidi = constants.h3_request_streams_max;
        params.initial_max_streams_uni = 8;
        params.original_destination_connection_id = self.clientDcid();
        params.initial_source_connection_id = &self.server_scid;

        var buffer: [256]u8 = undefined;
        var writer: std.Io.Writer = .fixed(&buffer);
        zquic.core.TransportParameters.encode(params, &writer) catch return error.TransportParameters;
        // OpenSSL keeps the block for the handshake; the arena owns it.
        const encoded = try self.arena().dupe(u8, buffer[0..writer.end]);
        self.tls = try qtls.Tls.initServer(self.arena(), encoded);
    }

    /// Run TLS, install any newly available keys, then emit the handshake
    /// bytes it produced. Secrecy is installed before packets are sealed, so
    /// the Handshake flight uses Handshake keys rather than Initial ones.
    fn driveTls(self: *Connection) !void {
        const tls = self.tls orelse return error.NotInitialized;
        // OpenSSL may emit ServerHello on one drive and the encrypted flight
        // on the next; a second call is a no-op once it has nothing left.
        try tls.drive();
        try tls.drive();
        self.loadPeerParams(tls);
        try self.installSecrets();
        try self.queueCrypto(tls_initial);
        try self.queueCrypto(tls_handshake);
    }

    /// Decode the client's transport parameters once TLS has seen them.
    /// A malformed or placeholder block keeps the defaults; the handshake
    /// itself already succeeded, so this is a limits question, not a
    /// protocol verdict.
    fn loadPeerParams(self: *Connection, tls: *qtls.Tls) void {
        if (self.peer_params_loaded) return;
        const encoded = tls.peerParams();
        if (encoded.len == 0) return;
        self.peer_params_loaded = true;
        const params = zquic.core.TransportParameters.decode(encoded) catch return;
        self.peer_data_limit = @max(self.peer_data_limit, params.initial_max_data);
        self.peer_bidi_remote_limit = @max(
            self.peer_bidi_remote_limit,
            params.initial_max_stream_data_bidi_remote,
        );
        self.peer_bidi_local_limit = @max(
            self.peer_bidi_local_limit,
            params.initial_max_stream_data_bidi_local,
        );
        self.peer_uni_limit = @max(
            self.peer_uni_limit,
            params.initial_max_stream_data_uni,
        );
    }

    fn installSecrets(self: *Connection) !void {
        const tls = self.tls orelse return error.NotInitialized;
        if (!self.handshake_keys_installed) {
            const secrets = tls.takeSecrets(tls_handshake);
            if (secrets.complete()) {
                try self.installKeys(tls_handshake, secrets);
                self.handshake_keys_installed = true;
            }
        }
        // A server may yield its application write secret before it has
        // authenticated the client's Finished, and taking that half now would
        // discard it (qtls clears both slots on read). Wait for the handshake
        // to finish, when both directions are present.
        if (!self.application_keys_installed and tls.isFinished()) {
            const secrets = tls.takeSecrets(tls_application);
            if (secrets.complete()) {
                try self.installKeys(tls_application, secrets);
                self.application_keys_installed = true;
                self.established = true;
            }
        }
    }

    fn installKeys(self: *Connection, level: usize, secrets: qtls.SecretSet) !void {
        const local = try zquic.Tls13KeySchedule.deriveQuicPacketKeys(&secrets.local.?);
        const remote = try zquic.Tls13KeySchedule.deriveQuicPacketKeys(&secrets.remote.?);
        switch (level) {
            tls_handshake => try self.crypto.installRfc9001HandshakeKeys(&local, &remote),
            tls_application => try self.crypto.installRfc9001ApplicationKeys(&local, &remote),
            else => return error.UnsupportedLevel,
        }
    }

    /// Serialize one level's pending TLS output as one CRYPTO frame and
    /// queue it. The slice is cleared only after the frame has been built.
    fn queueCrypto(self: *Connection, level: usize) !void {
        const tls = self.tls orelse return error.NotInitialized;
        const out = tls.takeOut(level);
        if (out.len == 0) return;
        defer tls.clearOut(level);
        var payload: [max_datagram_bytes]u8 = undefined;
        var writer: std.Io.Writer = .fixed(&payload);
        const frame = QuicFrames.Frame{ .crypto = .init(0, out) };
        frame.serialize(&writer) catch return error.DatagramTooLarge;
        const packet = try self.seal(level, payload[0..writer.end]);
        defer self.cryptoAllocator().free(packet);
        try self.pushDatagram(packet);
    }

    /// Encrypt a frame payload at `level`, prefixing an ACK frame when this
    /// packet number space has unacknowledged input. Initial and Handshake
    /// use long headers to the client's SCID; 1-RTT uses a short header whose
    /// DCID is the client's SCID.
    fn seal(self: *Connection, level: usize, payload: []const u8) ![]u8 {
        const packet_type: Packet.PacketType = switch (level) {
            tls_initial => .initial,
            tls_handshake => .handshake,
            tls_application => .one_rtt,
            else => return error.UnsupportedLevel,
        };
        const space = switch (level) {
            tls_initial => recovery.Space.initial,
            tls_handshake => recovery.Space.handshake,
            tls_application => recovery.Space.application,
            else => return error.UnsupportedLevel,
        };
        var assembled: [max_datagram_bytes]u8 = undefined;
        var writer: std.Io.Writer = .fixed(&assembled);
        if (level == tls_application) self.writeFlowControl(&writer) catch
            return error.DatagramTooLarge;
        if (self.ack.needsAck(space)) {
            var ranges_buf: [recovery.ack_ranges_max]recovery.AckRange = undefined;
            const ranges = self.ack.ackRanges(space, &ranges_buf);
            if (ranges.len > 0) {
                var wire_ranges: [recovery.ack_ranges_max]QuicFrames.AckFrame.AckRange = undefined;
                var count: usize = 0;
                var index: usize = 1;
                while (index < ranges.len) : (index += 1) {
                    // Ranges arrive newest-first and never touch, so the gap
                    // between consecutive ranges is at least one packet.
                    wire_ranges[count] = .{
                        .gap = ranges[index - 1].smallest - ranges[index].largest - 2,
                        .ack_range_length = ranges[index].largest - ranges[index].smallest,
                    };
                    count += 1;
                }
                const ack_frame = QuicFrames.AckFrame{
                    .largest_acknowledged = ranges[0].largest,
                    .ack_delay = 0,
                    .ack_range_count = count,
                    .first_ack_range = ranges[0].largest - ranges[0].smallest,
                    .ack_ranges = wire_ranges[0..count],
                };
                ack_frame.serialize(&writer) catch return error.DatagramTooLarge;
                self.ack.onAckSent(space);
            }
        }
        writer.writeAll(payload) catch return error.DatagramTooLarge;
        const pn = switch (level) {
            tls_initial => self.crypto.nextPacketNumberForLevel(.initial),
            tls_handshake => self.crypto.nextPacketNumberForLevel(.handshake),
            tls_application => self.crypto.nextPacketNumberForLevel(.application),
            else => return error.UnsupportedLevel,
        };
        const packet = try self.crypto.createProtectedRawPacket(
            switch (level) {
                tls_initial => .initial,
                tls_handshake => .handshake,
                tls_application => .application,
                else => return error.UnsupportedLevel,
            },
            packet_type,
            self.clientScid(),
            &self.server_scid,
            assembled[0..writer.end],
        );
        if (payload.len > 0) self.rememberSent(level, pn, payload);
        return packet;
    }

    /// Raise the connection and per-stream receive windows once half of the
    /// current allowance has been consumed. Bounded by the stream table.
    /// The advertisement and the enforcement ceiling move together: the
    /// peer is told it may send `next`, so `handleFrames` must accept at
    /// least `next` — raising `recv_data_advertised` or `advertised`
    /// alone leaves the old ceiling armed, and the moment the peer
    /// believes one of our MAX_DATA / MAX_STREAM_DATA top-ups and sends
    /// past it, the receive path answers an honest client with
    /// error.FlowControlError and kills the connection (observed live as
    /// silence ~256 KiB into a large upload, once the ACK-only path let
    /// the upload reach the first top-up at all).
    fn writeFlowControl(self: *Connection, writer: *std.Io.Writer) !void {
        if (self.recv_data + self.recv_data_limit / 2 > self.recv_data_advertised) {
            const next = self.recv_data + self.recv_data_limit;
            const frame = QuicFrames.MaxDataFrame{ .maximum_data = next };
            try frame.serialize(writer);
            self.recv_data_advertised = next;
            self.recv_data_limit = next;
        }
        for (&self.streams) |*stream| {
            if (!stream.used) continue;
            if (stream.recv + self.recv_stream_limit / 2 <= stream.advertised) continue;
            const next = stream.recv + self.recv_stream_limit;
            const frame = QuicFrames.MaxStreamDataFrame{
                .stream_id = stream.id,
                .maximum_stream_data = next,
            };
            try frame.serialize(writer);
            stream.advertised = next;
            stream.recv_limit = next;
        }
    }

    fn spaceOfLevel(level: usize) recovery.Space {
        return switch (level) {
            tls_initial => .initial,
            tls_handshake => .handshake,
            else => .application,
        };
    }

    fn spaceIndex(space: recovery.Space) usize {
        return switch (space) {
            .initial => 0,
            .handshake => 1,
            .application => 2,
        };
    }

    fn spaceOfSlot(slot: usize) recovery.Space {
        return switch (slot) {
            0 => .initial,
            1 => .handshake,
            else => .application,
        };
    }

    fn pushDatagram(self: *Connection, bytes: []const u8) !void {
        if (bytes.len > max_datagram_bytes) return error.DatagramTooLarge;
        if (self.queue_len >= datagram_slots) return error.QueueFull;
        const tail = (self.queue_head + self.queue_len) % datagram_slots;
        @memcpy(self.datagrams[tail][0..bytes.len], bytes);
        self.datagram_lens[tail] = bytes.len;
        self.queue_len += 1;
    }

    fn clientScid(self: *const Connection) []const u8 {
        return self.client_scid[0..self.client_scid_len];
    }

    fn streamState(self: *Connection, stream_id: u64) !*StreamState {
        for (&self.streams) |*stream| {
            if (stream.used and stream.id == stream_id) return stream;
        }
        for (&self.streams) |*stream| {
            if (!stream.used) {
                stream.* = .{
                    .id = stream_id,
                    .used = true,
                    .limit = self.streamLimitFor(stream_id),
                    .recv_limit = self.recv_stream_limit,
                    .advertised = self.recv_stream_limit,
                };
                return stream;
            }
        }
        return error.TooManyStreams;
    }

    fn findStream(self: *Connection, stream_id: u64) ?*StreamState {
        for (&self.streams) |*stream| {
            if (stream.used and stream.id == stream_id) return stream;
        }
        return null;
    }

    /// Streams currently holding a table slot. The listener's tests assert
    /// release behaviour through it; a caller could price occupancy with it.
    pub fn activeStreamCount(self: *const Connection) usize {
        var count: usize = 0;
        for (&self.streams) |*stream| {
            if (stream.used) count += 1;
        }
        return count;
    }

    /// Drop `stream_id`'s table slot without waiting for the FIN pair. The
    /// session calls this when it aborts a request mid-exchange: no
    /// response FIN will ever free the slot, so it would otherwise sit in
    /// the table for the connection's life. A stream with no slot (never
    /// opened, or already released by its FIN pair) is a no-op — abort can
    /// run after either half fired.
    pub fn dropStream(self: *Connection, stream_id: u64) void {
        const stream = self.findStream(stream_id) orelse return;
        releaseStreamState(stream);
    }

    /// Both directions of `stream` have ended (a sent FIN and a received
    /// FIN, in either order). Return the slot to the free pool by reverting
    /// it to its default state — exactly what `streamState` assigns a fresh
    /// slot. Callers must treat their pointer as dead afterwards; the
    /// release-safety argument lives on `sendStream`.
    fn releaseStreamState(stream: *StreamState) void {
        stream.* = .{};
    }

    /// True when `stream_id` would *open* a client-initiated bidirectional
    /// stream past the advertised ceiling: its ordinal `id / 4 + 1` (RFC
    /// 9000 §4.5) exceeds `advertised_bidi_streams`. Frames for streams
    /// already in the table are data on an open stream, not opens, and
    /// never pass through here.
    fn bidiOpenBeyondLimit(self: *Connection, stream_id: u64) bool {
        if (stream_id & 0x3 != 0) return false;
        if (self.findStream(stream_id) != null) return false;
        return stream_id / 4 + 1 > self.advertised_bidi_streams;
    }

    /// One HTTP/3 request slot came free: the client may open one more
    /// bidirectional stream. Raise the advertised ceiling by one — the
    /// value in a MAX_STREAMS frame must never decrease, and releases are
    /// what increments the count, so a per-release bump is the whole
    /// accounting — and seal a MAX_STREAMS frame immediately. Unlike the
    /// receive windows in `writeFlowControl` this cannot wait for the next
    /// data seal to piggyback on: a client sitting on an exhausted ceiling
    /// sends nothing, so there may never be an ACK or a stream write to
    /// ride with.
    pub fn raiseBidiStreamLimit(self: *Connection) !void {
        if (!self.established) return error.HandshakeIncomplete;
        self.advertised_bidi_streams += 1;
        var payload: [max_datagram_bytes]u8 = undefined;
        var writer: std.Io.Writer = .fixed(&payload);
        const frame = QuicFrames.MaxStreamsFrame{
            .maximum_streams = self.advertised_bidi_streams,
            .bidirectional = true,
        };
        frame.serialize(&writer) catch return error.DatagramTooLarge;
        // Header protection needs a full 16-byte sample starting four bytes
        // into the packet number (RFC 9001 §5.4.2), which the crypto layer
        // enforces as a minimum payload; the frame alone is two varints,
        // so it rides with PADDING.
        while (writer.end < 8) writer.writeByte(0) catch return error.DatagramTooLarge;
        const packet = try self.seal(tls_application, payload[0..writer.end]);
        defer self.cryptoAllocator().free(packet);
        try self.pushDatagram(packet);
    }

    /// Peer allowances differ by stream direction (RFC 9000 §4.6):
    /// client-initiated bidi uses the peer's bidi_remote limit, server
    /// bidi uses bidi_local, and either unidirectional direction uses uni.
    fn streamLimitFor(self: *const Connection, stream_id: u64) u64 {
        return switch (stream_id & 0x3) {
            0 => self.peer_bidi_remote_limit,
            1 => self.peer_bidi_local_limit,
            else => self.peer_uni_limit,
        };
    }

    /// A deterministic server SCID keeps this slice free of a random source;
    /// the listener will replace it with a real CID generator and a demux.
    /// Eight bytes is also the length the vendor's short-header parser assumes
    /// when it reads a 1-RTT destination connection id.
    fn deriveServerScid(self: *Connection, dcid: []const u8) void {
        var hash = std.hash.Wyhash.init(0x6833);
        switch (self.peer) {
            .ip4 => |addr| {
                hash.update(&addr.bytes);
                hash.update(std.mem.asBytes(&addr.port));
            },
            .ip6 => |addr| {
                hash.update(&addr.bytes);
                hash.update(std.mem.asBytes(&addr.port));
            },
        }
        hash.update(dcid);
        std.mem.writeInt(u64, &self.server_scid, hash.final(), .little);
    }
};

fn storeCid(buf: *[20]u8, len: *u8, cid: []const u8) !void {
    if (cid.len == 0 or cid.len > buf.len) return error.InvalidConnectionId;
    @memcpy(buf[0..cid.len], cid);
    len.* = @intCast(cid.len);
}

// ---------------------------------------------------------------------------
// Tests: a minimal in-memory client drives the server over real QUIC packets.
// ---------------------------------------------------------------------------

/// Length of the first QUIC packet in a datagram, or null when the header
/// cannot be walked. A short header always consumes the rest of the
/// datagram; long headers carry an explicit Length field covering packet
/// number, payload and AEAD tag.
fn packetLen(bytes: []const u8) ?usize {
    if (bytes.len == 0) return null;
    const first = bytes[0];
    if ((first & 0x80) == 0) return bytes.len;
    if (bytes.len < 7) return null;
    const version = std.mem.readInt(u32, bytes[1..5], .big);
    if (version == 0) return bytes.len; // version negotiation
    if ((first & 0x30) == 0x30) return bytes.len; // Retry has no Length
    var pos: usize = 5;
    const dcid_len = bytes[pos];
    pos += 1 + dcid_len;
    if (pos >= bytes.len) return null;
    const scid_len = bytes[pos];
    pos += 1 + scid_len;
    if (pos > bytes.len) return null;
    if ((first & 0x30) == 0) { // Initial carries a token
        const token = readVarintRaw(bytes[pos..]) orelse return null;
        pos += token.len;
        if (pos > bytes.len) return null;
    }
    const length = readVarintRaw(bytes[pos..]) orelse return null;
    pos += length.len;
    const end = pos + @as(usize, @intCast(length.value));
    if (end > bytes.len) return null;
    return end;
}

fn readVarintRaw(bytes: []const u8) ?struct { value: u64, len: u8 } {
    if (bytes.len == 0) return null;
    const len: u8 = @as(u8, 1) << @intCast(bytes[0] >> 6);
    if (bytes.len < len) return null;
    var value: u64 = bytes[0] & 0x3f;
    var index: u8 = 1;
    while (index < len) : (index += 1) value = (value << 8) | bytes[index];
    return .{ .value = value, .len = len };
}

/// RFC 9000 §19.3.1: is `pn` covered by this ACK frame's ranges? Bounded by
/// the frame's own range list (the parser caps it at the packet size).
fn ackedBy(pn: u64, ack: QuicFrames.AckFrame) bool {
    var largest = ack.largest_acknowledged;
    const smallest = largest -| ack.first_ack_range;
    if (pn >= smallest and pn <= largest) return true;
    for (ack.ack_ranges) |range| {
        if (largest < range.gap + 2) break;
        const next_largest = largest - range.gap - 2;
        const next_smallest = next_largest -| range.ack_range_length;
        if (pn >= next_smallest and pn <= next_largest) return true;
        largest = next_largest;
    }
    return false;
}

const fixtures = struct {
    const cert_pem = @embedFile("../../tls/testdata/cert.pem");
    const key_pem = @embedFile("../../tls/testdata/key.pem");
};

const test_peer: std.Io.net.IpAddress = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 4433 } };

fn testConfig() Config {
    return .{
        .cert_pem = fixtures.cert_pem,
        .key_pem = fixtures.key_pem,
        .transport_params = &[_]u8{0},
    };
}

fn cryptoFrame(out: []u8, data: []const u8) ![]const u8 {
    var writer: std.Io.Writer = .fixed(out);
    const frame = QuicFrames.Frame{ .crypto = .init(0, data) };
    try frame.serialize(&writer);
    return out[0..writer.end];
}

/// Install packet keys from a traffic-secret pair. The caller's local secret
/// is its write direction; the remote secret authenticates its peer.
fn installPair(
    pc: *PacketCrypto,
    level: usize,
    secrets: qtls.SecretSet,
) !void {
    const local = try zquic.Tls13KeySchedule.deriveQuicPacketKeys(&secrets.local.?);
    const remote = try zquic.Tls13KeySchedule.deriveQuicPacketKeys(&secrets.remote.?);
    switch (level) {
        2 => try pc.installRfc9001HandshakeKeys(&local, &remote),
        3 => try pc.installRfc9001ApplicationKeys(&local, &remote),
        else => return error.UnsupportedLevel,
    }
}

const TestClient = struct {
    allocator: std.mem.Allocator,
    tls_ctx: EnhancedTlsContext,
    crypto: PacketCrypto,
    tls: *qtls.Tls,
    dcid: [8]u8 = @splat(0x11),
    scid: [8]u8 = @splat(0x22),
    largest_pn: [3]?u64 = .{ null, null, null },

    fn init(self: *TestClient, allocator: std.mem.Allocator) !void {
        self.allocator = allocator;
        self.tls_ctx = try EnhancedTlsContext.init(allocator, false, .aes_128_gcm_sha256);
        self.crypto = try PacketCrypto.init(allocator, &self.tls_ctx, null);
        self.tls = try qtls.Tls.initClient(
            allocator,
            "spike.zgix.test",
            &[_]u8{0},
            .{ .insecure_skip_verify = true },
        );
        try self.crypto.installRfc9001ClientInitialKeys(&self.dcid);
    }

    fn deinit(self: *TestClient) void {
        self.tls.destroy();
        self.crypto.deinit();
        self.tls_ctx.deinit();
    }

    fn initial(self: *TestClient) ![]u8 {
        try self.tls.drive();
        var wire: [4096]u8 = undefined;
        const payload = try cryptoFrame(&wire, self.tls.takeOut(0));
        defer self.tls.clearOut(0);
        return self.crypto.createProtectedRawPacket(
            .initial,
            .initial,
            &self.dcid,
            &self.scid,
            payload,
        );
    }

    /// Feed one server datagram to TLS and install whatever secret levels
    /// became complete. Returns true when the client handshake is finished.
    fn accept(self: *TestClient, datagram: []const u8) !bool {
        const header = try Packet.PacketHeader.parse(datagram, self.allocator);
        const slot: usize = switch (header.packet_type) {
            .initial => 0,
            .handshake => 1,
            .one_rtt => 2,
            else => return error.UnexpectedPacket,
        };
        const level = tls_levels[slot];
        var packet = try self.crypto.processProtectedRawPacket(datagram, self.largest_pn[slot]);
        defer packet.deinit(self.allocator);
        self.largest_pn[slot] = packet.packet_number;

        var reader: std.Io.Reader = .fixed(packet.payload);
        while (reader.seek < reader.end) {
            var frame = try QuicFrames.Frame.parse(&reader, self.allocator);
            defer frame.deinit(self.allocator);
            switch (frame) {
                .crypto => |crypto| try self.tls.pushCrypto(level, crypto.data),
                else => {},
            }
        }
        try self.tls.drive();
        try self.tls.drive();
        if (!self.crypto.isLevelPinned(.handshake)) {
            const secrets = self.tls.takeSecrets(2);
            if (secrets.complete()) try installPair(&self.crypto, 2, secrets);
        }
        if (!self.crypto.isLevelPinned(.application)) {
            const secrets = self.tls.takeSecrets(3);
            if (secrets.complete()) try installPair(&self.crypto, 3, secrets);
        }
        return self.tls.isFinished();
    }

    fn finishedDatagram(self: *TestClient, out: []u8, server_scid: []const u8) ![]u8 {
        const payload = try cryptoFrame(out, self.tls.takeOut(2));
        defer self.tls.clearOut(2);
        return self.crypto.createProtectedRawPacket(
            .handshake,
            .handshake,
            server_scid,
            &self.scid,
            payload,
        );
    }

    fn streamDatagram(self: *TestClient, out: []u8, data: []const u8, fin: bool, server_scid: []const u8) ![]u8 {
        return self.streamFrameDatagram(out, 0, data, fin, server_scid);
    }

    /// One 1-RTT STREAM frame opening `stream_id` at offset 0. The caller
    /// owns the returned packet.
    fn streamFrameDatagram(
        self: *TestClient,
        out: []u8,
        stream_id: u64,
        data: []const u8,
        fin: bool,
        server_scid: []const u8,
    ) ![]u8 {
        var writer: std.Io.Writer = .fixed(out);
        const frame = QuicFrames.Frame{ .stream = .init(stream_id, 0, data, fin, false, true) };
        try frame.serialize(&writer);
        return self.crypto.createProtectedRawPacket(
            .application,
            .one_rtt,
            server_scid,
            &self.scid,
            out[0..writer.end],
        );
    }

    /// One 1-RTT RESET_STREAM frame for `stream_id`. The caller owns the
    /// returned packet.
    fn resetDatagram(
        self: *TestClient,
        out: []u8,
        stream_id: u64,
        error_code: u64,
        final_size: u64,
        server_scid: []const u8,
    ) ![]u8 {
        var writer: std.Io.Writer = .fixed(out);
        const frame = QuicFrames.ResetStreamFrame.init(stream_id, error_code, final_size);
        try frame.serialize(&writer);
        return self.crypto.createProtectedRawPacket(
            .application,
            .one_rtt,
            server_scid,
            &self.scid,
            out[0..writer.end],
        );
    }

    /// One 1-RTT CONNECTION_CLOSE frame. `app` selects the application
    /// variant (0x1d) over the transport one (0x1c). The caller owns the
    /// returned packet.
    fn closeDatagram(
        self: *TestClient,
        out: []u8,
        app: bool,
        error_code: u64,
        reason: []const u8,
        server_scid: []const u8,
    ) ![]u8 {
        var writer: std.Io.Writer = .fixed(out);
        if (app) {
            const frame = QuicFrames.ConnectionCloseAppFrame.init(error_code, reason);
            try frame.serialize(&writer);
        } else {
            const frame = QuicFrames.ConnectionCloseFrame.init(error_code, 0, reason);
            try frame.serialize(&writer);
        }
        return self.crypto.createProtectedRawPacket(
            .application,
            .one_rtt,
            server_scid,
            &self.scid,
            out[0..writer.end],
        );
    }

    /// One 1-RTT packet carrying an already-serialized frame payload (the
    /// caller builds MAX_DATA / MAX_STREAM_DATA frames with `serialize`).
    /// The caller owns the returned packet.
    fn frameDatagram(
        self: *TestClient,
        out: []u8,
        frames: []const u8,
        server_scid: []const u8,
    ) ![]u8 {
        var writer: std.Io.Writer = .fixed(out);
        try writer.writeAll(frames);
        return self.crypto.createProtectedRawPacket(
            .application,
            .one_rtt,
            server_scid,
            &self.scid,
            out[0..writer.end],
        );
    }
};

/// Drive the server and the in-memory client through the handshake to an
/// established 1-RTT connection, draining the server's handshake flight.
fn handshakeToEstablished(server: *Connection, client: *TestClient) !void {
    const client_initial = try client.initial();
    defer std.testing.allocator.free(client_initial);
    try server.onDatagram(client_initial, 1);
    while (server.takeDatagram()) |datagram| {
        _ = try client.accept(datagram);
    }
    var fin_buf: [4096]u8 = undefined;
    const client_finished = try client.finishedDatagram(&fin_buf, server.serverScid());
    defer std.testing.allocator.free(client_finished);
    try server.onDatagram(client_finished, 2);
    try std.testing.expect(server.isEstablished());
}

/// Drain the server's next queued datagram, decrypt it on the client, and
/// pull the CONNECTION_CLOSE fields out of it; other frames riding the
/// same packet (an ACK prefix, say) are skipped. Fails when no close frame
/// is present. The reason is copied into `reason_buf` because the parsed
/// frame's slice is freed with the frame.
fn takeCloseFrame(
    server: *Connection,
    client: *TestClient,
    reason_buf: []u8,
) !struct { code: u64, reason: []const u8 } {
    const datagram = server.takeDatagram() orelse return error.MissingDatagram;
    var packet = try client.crypto.processProtectedRawPacket(
        datagram,
        client.largest_pn[2],
    );
    defer packet.deinit(std.testing.allocator);
    client.largest_pn[2] = packet.packet_number;
    var reader: std.Io.Reader = .fixed(packet.payload);
    while (reader.seek < reader.end) {
        var frame = try QuicFrames.Frame.parse(&reader, std.testing.allocator);
        defer frame.deinit(std.testing.allocator);
        switch (frame) {
            .connection_close => |close| {
                if (close.reason_phrase.len > reason_buf.len) return error.ReasonTooLarge;
                @memcpy(reason_buf[0..close.reason_phrase.len], close.reason_phrase);
                return .{
                    .code = close.error_code,
                    .reason = reason_buf[0..close.reason_phrase.len],
                };
            },
            else => {},
        }
    }
    return error.MissingCloseFrame;
}

test "h3 connection: handshake, CRYPTO, and STREAM in both directions" {
    try Connection.configureServer(fixtures.cert_pem, fixtures.key_pem);

    var server: Connection = undefined;
    try server.initInPlace(std.testing.allocator, test_peer, testConfig());
    defer server.deinit();

    var client: TestClient = undefined;
    try client.init(std.testing.allocator);
    defer client.deinit();

    // ClientHello → server Initial keys → server flight.
    const client_initial = try client.initial();
    defer std.testing.allocator.free(client_initial);
    try server.onDatagram(client_initial, 1);
    try std.testing.expectEqual(@as(usize, 8), server.clientDcid().len);
    try std.testing.expectEqual(@as(usize, 8), server.serverScid().len);
    try std.testing.expectEqualSlices(u8, &client.dcid, server.clientDcid());
    try std.testing.expectEqual(@as(?u64, 1 + idle_timeout_ns), server.idleDeadline());

    // Server Initial (ServerHello) then Handshake (certificate flight). The
    // client can only read the second once the first has yielded secrets.
    var saw_server_datagram = false;
    while (server.takeDatagram()) |datagram| {
        saw_server_datagram = true;
        _ = try client.accept(datagram);
    }
    try std.testing.expect(saw_server_datagram);
    try std.testing.expect(client.crypto.isLevelPinned(.handshake));
    try std.testing.expect(client.tls.isFinished());

    // Client Finished → the server authenticates it and holds app secrets.
    var fin_buf: [4096]u8 = undefined;
    const client_finished = try client.finishedDatagram(&fin_buf, server.serverScid());
    defer std.testing.allocator.free(client_finished);
    try server.onDatagram(client_finished, 2);
    try std.testing.expect(server.tls.?.isFinished());
    try std.testing.expect(server.isEstablished());

    // 1-RTT STREAM from the client: the handler must receive the payload and
    // the fin bit synchronously (the frame slice is transient).
    const Recorder = struct {
        len: usize = 0,
        fin: bool = false,
        data: [64]u8 = undefined,
        fn onData(ctx: *anyopaque, _: u64, data: []const u8, fin: bool) void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            @memcpy(self.data[0..data.len], data);
            self.len = data.len;
            self.fin = fin;
        }
    };
    var recorder = Recorder{};
    server.setStreamHandler(.{ .ctx = &recorder, .onData = Recorder.onData });

    // Small windows make the top-up threshold reachable with a 4-byte body:
    // half of 6 is 3, so 4 received bytes advertise the next window.
    server.recv_stream_limit = 6;
    server.recv_data_limit = 6;
    server.recv_data_advertised = 6;

    var ping_buf: [512]u8 = undefined;
    const ping_datagram = try client.streamDatagram(&ping_buf, "ping", true, server.serverScid());
    defer std.testing.allocator.free(ping_datagram);
    try server.onDatagram(ping_datagram, 3);
    try std.testing.expect(recorder.fin);
    try std.testing.expectEqualStrings("ping", recorder.data[0..recorder.len]);

    // The silent receive pass answered with an ACK-only packet
    // (`sealAckOnly`): the acknowledgement of the client's first
    // application packet rides it, and so do the receive-window top-ups
    // `seal` prepends — the same piggyback this test used to assert on
    // the manual pong below, now on the one packet the pass produced.
    const ack_datagram = server.takeDatagram() orelse return error.MissingDatagram;
    var ack_in = try client.crypto.processProtectedRawPacket(ack_datagram, client.largest_pn[2]);
    defer ack_in.deinit(std.testing.allocator);
    client.largest_pn[2] = ack_in.packet_number;
    var ack_reader: std.Io.Reader = .fixed(ack_in.payload);
    var saw_ack = false;
    var saw_max_data = false;
    var saw_max_stream_data = false;
    while (ack_reader.seek < ack_reader.end) {
        var frame = try QuicFrames.Frame.parse(&ack_reader, std.testing.allocator);
        defer frame.deinit(std.testing.allocator);
        switch (frame) {
            .ack => |ack| {
                try std.testing.expectEqual(@as(u64, 0), ack.largest_acknowledged);
                saw_ack = true;
            },
            .max_data => |max_data| {
                try std.testing.expectEqual(@as(u64, 10), max_data.maximum_data);
                saw_max_data = true;
            },
            .max_stream_data => |max_stream| {
                try std.testing.expectEqual(@as(u64, 0), max_stream.stream_id);
                try std.testing.expectEqual(@as(u64, 10), max_stream.maximum_stream_data);
                saw_max_stream_data = true;
            },
            .padding => {},
            else => return error.UnexpectedFrame,
        }
    }
    try std.testing.expect(saw_ack);
    try std.testing.expect(saw_max_data);
    try std.testing.expect(saw_max_stream_data);

    // Connection-level flow control refuses before a datagram is spent.
    const saved_limit = server.peer_data_limit;
    server.peer_data_limit = server.peer_data_sent;
    try std.testing.expectError(
        error.FlowControlBlocked,
        server.sendStream(0, "pong", true),
    );
    server.peer_data_limit = saved_limit;

    // Server → client 1-RTT STREAM. Offset 0 means the frame omits the
    // offset field and carries the length and fin bits. The ACK and the
    // top-ups already went with the ACK-only packet, so the pong is a
    // bare STREAM.
    try server.sendStream(0, "pong", true);
    const pong_datagram = server.takeDatagram() orelse return error.MissingDatagram;
    var pong_in = try client.crypto.processProtectedRawPacket(pong_datagram, client.largest_pn[2]);
    defer pong_in.deinit(std.testing.allocator);
    client.largest_pn[2] = pong_in.packet_number;
    var reader: std.Io.Reader = .fixed(pong_in.payload);
    var saw_pong = false;
    while (reader.seek < reader.end) {
        var frame = try QuicFrames.Frame.parse(&reader, std.testing.allocator);
        defer frame.deinit(std.testing.allocator);
        switch (frame) {
            .stream => |stream| {
                try std.testing.expectEqual(@as(u64, 0), stream.offset);
                try std.testing.expect(stream.fin);
                try std.testing.expectEqualStrings("pong", stream.data);
                saw_pong = true;
            },
            else => {},
        }
    }
    try std.testing.expect(saw_pong);

    // The ping/pong pair completed both directions (each side sent a FIN),
    // so stream 0's slot is back in the free pool.
    try std.testing.expect(server.findStream(0) == null);

    // Stream-level flow control: a retained stream's allowance is its
    // offset, so a further byte is refused until MAX_STREAM_DATA raises it.
    // Stream 4 sends no FIN, so it stays in the table to be pinned.
    try server.sendStream(4, "pong", false);
    const four_datagram = server.takeDatagram() orelse return error.MissingDatagram;
    var four_in = try client.crypto.processProtectedRawPacket(four_datagram, client.largest_pn[2]);
    defer four_in.deinit(std.testing.allocator);
    client.largest_pn[2] = four_in.packet_number;
    var four_reader: std.Io.Reader = .fixed(four_in.payload);
    while (four_reader.seek < four_reader.end) {
        var frame = try QuicFrames.Frame.parse(&four_reader, std.testing.allocator);
        defer frame.deinit(std.testing.allocator);
        switch (frame) {
            .stream => |stream| {
                try std.testing.expectEqual(@as(u64, 4), stream.stream_id);
                try std.testing.expectEqual(@as(u64, 0), stream.offset);
                try std.testing.expect(!stream.fin);
                try std.testing.expectEqualStrings("pong", stream.data);
            },
            else => {},
        }
    }

    var stream_state: ?*StreamState = null;
    for (&server.streams) |*stream| {
        if (stream.used and stream.id == 4) stream_state = stream;
    }
    const pinned = stream_state orelse return error.MissingStream;
    pinned.limit = pinned.offset;
    try std.testing.expectError(
        error.FlowControlBlocked,
        server.sendStream(4, "again", false),
    );
    pinned.limit = 1 << 20;

    // A subsequent write advances the offset and therefore sets the offset
    // field in the frame.
    try server.sendStream(4, "again", false);
    const again_datagram = server.takeDatagram() orelse return error.MissingDatagram;
    var again_in = try client.crypto.processProtectedRawPacket(again_datagram, client.largest_pn[2]);
    defer again_in.deinit(std.testing.allocator);
    client.largest_pn[2] = again_in.packet_number;
    var again_reader: std.Io.Reader = .fixed(again_in.payload);
    while (again_reader.seek < again_reader.end) {
        var frame = try QuicFrames.Frame.parse(&again_reader, std.testing.allocator);
        defer frame.deinit(std.testing.allocator);
        switch (frame) {
            .stream => |stream| {
                try std.testing.expect(stream.has_offset);
                try std.testing.expectEqual(@as(u64, 4), stream.offset);
                try std.testing.expectEqualStrings("again", stream.data);
                try std.testing.expect(!stream.fin);
            },
            else => {},
        }
    }
    try std.testing.expect(server.takeDatagram() == null);

    // No ACK ever reaches the server, so PTO must resend the oldest packet
    // in each space. The application ring's oldest is the ping receive
    // pass's ACK-only supplement — its retained payload is pure PADDING,
    // which is what the probe below flags; a STREAM "pong" would have been
    // the answer before the supplement existed.
    try std.testing.expect(server.onTimeout(3 + 2 * std.time.ns_per_s));
    var saw_retransmit = false;
    while (server.takeDatagram()) |datagram| {
        const header = try Packet.PacketHeader.parse(datagram, std.testing.allocator);
        const slot: usize = switch (header.packet_type) {
            .initial => 0,
            .handshake => 1,
            .one_rtt => 2,
            else => continue,
        };
        var packet = try client.crypto.processProtectedRawPacket(datagram, client.largest_pn[slot]);
        defer packet.deinit(std.testing.allocator);
        client.largest_pn[slot] = packet.packet_number;
        var probe: std.Io.Reader = .fixed(packet.payload);
        while (probe.seek < probe.end) {
            var frame = try QuicFrames.Frame.parse(&probe, std.testing.allocator);
            defer frame.deinit(std.testing.allocator);
            switch (frame) {
                .stream => |stream| {
                    if (std.mem.eql(u8, stream.data, "pong")) saw_retransmit = true;
                },
                .padding => saw_retransmit = true,
                else => {},
            }
        }
    }
    try std.testing.expect(saw_retransmit);

    // Sixteen stream ids fit the fixed table; the seventeenth is refused
    // before it can consume a datagram slot. Stream 0's slot is free again
    // (its FIN pair completed above), so the loop starts at id 0.
    for (0..stream_slots) |id| try server.sendStream(id, "x", false);
    try std.testing.expectError(error.TooManyStreams, server.sendStream(99, "x", false));

    // The handshake state is bounded by the arena.
    try std.testing.expect(server.arenaUsedBytes() < arena_bytes);
}

test "h3 connection: a bad first datagram is refused and closes" {
    try Connection.configureServer(fixtures.cert_pem, fixtures.key_pem);

    var truncated: Connection = undefined;
    try truncated.initInPlace(std.testing.allocator, test_peer, testConfig());
    defer truncated.deinit();
    try std.testing.expect(truncated.takeDatagram() == null);
    try std.testing.expect(truncated.idleDeadline() == null);
    try std.testing.expectError(error.InvalidPacket, truncated.onDatagram(&.{}, 1));
    try std.testing.expect(truncated.isClosed());

    // A syntactically valid long header that is not an Initial is a
    // different protocol error, and equally fatal for this connection.
    var not_initial: Connection = undefined;
    // The default Config leaves transport_params empty; this exercises the
    // pass-through path with a zero-length block as well.
    try not_initial.initInPlace(std.testing.allocator, test_peer, .{
        .cert_pem = fixtures.cert_pem,
        .key_pem = fixtures.key_pem,
    });
    defer not_initial.deinit();
    const dcid: [8]u8 = @splat(0x11);
    const scid: [8]u8 = @splat(0x22);
    const handshake = [_]u8{ 0xe0, 0, 0, 0, 1, 8 } ++ dcid ++ [_]u8{8} ++ scid;
    try std.testing.expectError(error.NotInitial, not_initial.onDatagram(&handshake, 2));
    try std.testing.expect(not_initial.isClosed());
    // The failure path still records the idle deadline for the caller.
    try std.testing.expectEqual(@as(?u64, 2 + idle_timeout_ns), not_initial.idleDeadline());
}

test "h3 connection: abort goes silent and hands the slot to the idle reaper" {
    try Connection.configureServer(fixtures.cert_pem, fixtures.key_pem);

    var server: Connection = undefined;
    try server.initInPlace(std.testing.allocator, test_peer, testConfig());
    defer server.deinit();
    try std.testing.expect(!server.isClosed());

    server.abort();
    try std.testing.expect(server.isClosed());
    // A zero idle deadline is "reap me now" for the listener sweep: the
    // next tick (or the redundant check on the next inbound packet) frees
    // the slot instead of waiting out the idle timeout.
    try std.testing.expectEqual(@as(?u64, 0), server.idleDeadline());

    // Abort is idempotent and later datagrams are refused without a
    // packet number being spent.
    server.abort();
    try std.testing.expectError(error.ConnectionClosed, server.onDatagram(&.{0x40}, 3));
    try std.testing.expect(server.isClosed());
}

test "h3 connection: transport parameters advertise the request-slot ceiling" {
    try Connection.configureServer(fixtures.cert_pem, fixtures.key_pem);

    var server: Connection = undefined;
    // The default Config leaves `transport_params` empty, so the server
    // builds its own block — the path a listener takes. (The shared
    // handshake test passes an override and never exercises this.)
    try server.initInPlace(std.testing.allocator, test_peer, .{
        .cert_pem = fixtures.cert_pem,
        .key_pem = fixtures.key_pem,
    });
    defer server.deinit();

    var client: TestClient = undefined;
    try client.init(std.testing.allocator);
    defer client.deinit();

    const client_initial = try client.initial();
    defer std.testing.allocator.free(client_initial);
    try server.onDatagram(client_initial, 1);
    while (server.takeDatagram()) |datagram| {
        _ = try client.accept(datagram);
    }
    try std.testing.expect(client.tls.isFinished());

    // The client reads the server's block the way `loadPeerParams` reads
    // the client's: whatever the wire carried is what decode must see. The
    // bidi ceiling is the session's request-slot count; the two cannot
    // drift because both name one constant.
    const decoded = zquic.core.TransportParameters.decode(client.tls.peerParams()) catch {
        return error.MissingTransportParameters;
    };
    try std.testing.expectEqual(
        @as(u64, constants.h3_request_streams_max),
        decoded.initial_max_streams_bidi,
    );
    try std.testing.expectEqual(
        @as(u64, constants.h3_request_streams_max),
        decoded.initial_max_streams_uni,
    );
}

test "h3 connection: the stream ceiling drops over-limit opens and raises monotonically" {
    try Connection.configureServer(fixtures.cert_pem, fixtures.key_pem);

    var server: Connection = undefined;
    try server.initInPlace(std.testing.allocator, test_peer, .{
        .cert_pem = fixtures.cert_pem,
        .key_pem = fixtures.key_pem,
    });
    defer server.deinit();
    try std.testing.expectEqual(
        @as(u64, constants.h3_request_streams_max),
        server.advertised_bidi_streams,
    );

    var client: TestClient = undefined;
    try client.init(std.testing.allocator);
    defer client.deinit();

    const client_initial = try client.initial();
    defer std.testing.allocator.free(client_initial);
    try server.onDatagram(client_initial, 1);
    while (server.takeDatagram()) |datagram| {
        _ = try client.accept(datagram);
    }
    var fin_buf: [4096]u8 = undefined;
    const client_finished = try client.finishedDatagram(&fin_buf, server.serverScid());
    defer std.testing.allocator.free(client_finished);
    try server.onDatagram(client_finished, 2);
    try std.testing.expect(server.isEstablished());

    const Recorder = struct {
        calls: usize = 0,
        last_stream_id: u64 = 0,
        data: [64]u8 = undefined,
        len: usize = 0,
        fn onData(ctx: *anyopaque, stream_id: u64, data: []const u8, fin: bool) void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            self.calls += 1;
            self.last_stream_id = stream_id;
            @memcpy(self.data[0..data.len], data);
            self.len = data.len;
            _ = fin;
        }
    };
    var recorder = Recorder{};
    server.setStreamHandler(.{ .ctx = &recorder, .onData = Recorder.onData });

    // The boundary: stream id 28 is the eighth client-bidi stream
    // (28 / 4 + 1 == 8), exactly at the advertised ceiling, and must open.
    var eight_buf: [512]u8 = undefined;
    const eight = try client.streamFrameDatagram(&eight_buf, 28, "eight", true, server.serverScid());
    defer std.testing.allocator.free(eight);
    try server.onDatagram(eight, 3);
    try std.testing.expectEqual(@as(usize, 1), recorder.calls);
    try std.testing.expectEqual(@as(u64, 28), recorder.last_stream_id);
    try std.testing.expectEqualStrings("eight", recorder.data[0..recorder.len]);

    // The ninth open (id 32) is past the ceiling: dropped before it can
    // claim a stream-table slot, the connection stays up, and data on
    // already-open streams keeps flowing.
    var nine_buf: [512]u8 = undefined;
    const nine = try client.streamFrameDatagram(&nine_buf, 32, "nine", true, server.serverScid());
    defer std.testing.allocator.free(nine);
    try server.onDatagram(nine, 4);
    try std.testing.expectEqual(@as(usize, 1), recorder.calls);
    try std.testing.expect(server.findStream(32) == null);
    try std.testing.expect(!server.isClosed());

    var zero_buf: [512]u8 = undefined;
    const zero = try client.streamFrameDatagram(&zero_buf, 0, "zero", true, server.serverScid());
    defer std.testing.allocator.free(zero);
    try server.onDatagram(zero, 5);
    try std.testing.expectEqual(@as(usize, 2), recorder.calls);
    try std.testing.expectEqual(@as(u64, 0), recorder.last_stream_id);

    // The silent receive passes answered each request with an ACK-only
    // packet (`sealAckOnly`); clear them so the takes below read the
    // MAX_STREAMS frames they chase.
    while (server.takeDatagram()) |_| {}

    // Each raise seals a MAX_STREAMS frame whose value grows monotonically
    // (8 → 9 → 10); the client reads both off the wire.
    var seen: [2]u64 = .{ 0, 0 };
    var raise_count: usize = 0;
    while (raise_count < seen.len) : (raise_count += 1) {
        try server.raiseBidiStreamLimit();
        const datagram = server.takeDatagram() orelse return error.MissingDatagram;
        var packet = try client.crypto.processProtectedRawPacket(datagram, client.largest_pn[2]);
        defer packet.deinit(std.testing.allocator);
        client.largest_pn[2] = packet.packet_number;
        var reader: std.Io.Reader = .fixed(packet.payload);
        while (reader.seek < reader.end) {
            var frame = try QuicFrames.Frame.parse(&reader, std.testing.allocator);
            defer frame.deinit(std.testing.allocator);
            switch (frame) {
                .max_streams_bidi => |max| seen[raise_count] = max.maximum_streams,
                else => {},
            }
        }
    }
    try std.testing.expectEqual(@as(u64, 9), seen[0]);
    try std.testing.expectEqual(@as(u64, 10), seen[1]);

    // The raised ceiling now admits the ninth stream: what was dropped is
    // simply resent. The drop is recoverable — which is why it beats
    // closing the connection.
    var retry_buf: [512]u8 = undefined;
    const retry = try client.streamFrameDatagram(&retry_buf, 32, "nine", true, server.serverScid());
    defer std.testing.allocator.free(retry);
    try server.onDatagram(retry, 6);
    try std.testing.expectEqual(@as(usize, 3), recorder.calls);
    try std.testing.expectEqual(@as(u64, 32), recorder.last_stream_id);
    try std.testing.expectEqualStrings("nine", recorder.data[0..recorder.len]);
}

test "h3 connection: fin/fin pairs release slots, so a 17th sequential stream opens" {
    try Connection.configureServer(fixtures.cert_pem, fixtures.key_pem);

    var server: Connection = undefined;
    try server.initInPlace(std.testing.allocator, test_peer, .{
        .cert_pem = fixtures.cert_pem,
        .key_pem = fixtures.key_pem,
    });
    defer server.deinit();
    // The advertised ceiling guards *concurrent* opens; this test prices
    // the table itself, so keep the ordinal check out of the way.
    server.advertised_bidi_streams = 1 << 20;

    var client: TestClient = undefined;
    try client.init(std.testing.allocator);
    defer client.deinit();

    const client_initial = try client.initial();
    defer std.testing.allocator.free(client_initial);
    try server.onDatagram(client_initial, 1);
    while (server.takeDatagram()) |datagram| {
        _ = try client.accept(datagram);
    }
    var fin_buf: [4096]u8 = undefined;
    const client_finished = try client.finishedDatagram(&fin_buf, server.serverScid());
    defer std.testing.allocator.free(client_finished);
    try server.onDatagram(client_finished, 2);
    try std.testing.expect(server.isEstablished());

    const Recorder = struct {
        fins: usize = 0,
        fn onData(ctx: *anyopaque, _: u64, _: []const u8, fin: bool) void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            if (fin) self.fins += 1;
        }
    };
    var recorder = Recorder{};
    server.setStreamHandler(.{ .ctx = &recorder, .onData = Recorder.onData });

    // Seventeen sequential request exchanges on one connection. Each
    // request arrives with FIN, each response leaves with FIN, and the
    // pair frees the slot for the next exchange. The table holds 16
    // slots: without the release, opens accumulate and the 17th dies with
    // error.TooManyStreams — the failure this test pins down.
    var packet_buf: [512]u8 = undefined;
    for (0..17) |ordinal| {
        const stream_id: u64 = ordinal * 4;
        const request = try client.streamFrameDatagram(
            &packet_buf,
            stream_id,
            "req",
            true,
            server.serverScid(),
        );
        defer std.testing.allocator.free(request);
        try server.onDatagram(request, 3);
        try server.sendStream(stream_id, "resp", true);
        // The response FIN completed the pair: the slot is free again.
        try std.testing.expect(server.findStream(stream_id) == null);
        _ = server.takeDatagram() orelse return error.MissingDatagram;
    }
    try std.testing.expectEqual(@as(usize, 17), recorder.fins);
    try std.testing.expectEqual(@as(usize, 0), server.activeStreamCount());
}

test "h3 connection: a one-sided fin keeps the slot until the other end's fin" {
    try Connection.configureServer(fixtures.cert_pem, fixtures.key_pem);

    var server: Connection = undefined;
    try server.initInPlace(std.testing.allocator, test_peer, .{
        .cert_pem = fixtures.cert_pem,
        .key_pem = fixtures.key_pem,
    });
    defer server.deinit();
    server.advertised_bidi_streams = 1 << 20;

    var client: TestClient = undefined;
    try client.init(std.testing.allocator);
    defer client.deinit();

    const client_initial = try client.initial();
    defer std.testing.allocator.free(client_initial);
    try server.onDatagram(client_initial, 1);
    while (server.takeDatagram()) |datagram| {
        _ = try client.accept(datagram);
    }
    var fin_buf: [4096]u8 = undefined;
    const client_finished = try client.finishedDatagram(&fin_buf, server.serverScid());
    defer std.testing.allocator.free(client_finished);
    try server.onDatagram(client_finished, 2);
    try std.testing.expect(server.isEstablished());

    const Recorder = struct {
        fn onData(_: *anyopaque, _: u64, _: []const u8, _: bool) void {}
    };
    var recorder = Recorder{};
    server.setStreamHandler(.{ .ctx = &recorder, .onData = Recorder.onData });

    // Received FIN only: the request is complete but no response has been
    // sent — a premature release would let a fresh stream overwrite the
    // entry while the response still needs it.
    var req_buf: [512]u8 = undefined;
    const request = try client.streamFrameDatagram(&req_buf, 0, "req", true, server.serverScid());
    defer std.testing.allocator.free(request);
    try server.onDatagram(request, 3);
    try std.testing.expect(server.findStream(0) != null);
    try std.testing.expectEqual(@as(usize, 1), server.activeStreamCount());

    // Sent FIN only, the other order: a response closes a stream whose
    // request FIN has not arrived yet — the slot must survive that too.
    try server.sendStream(4, "resp", true);
    try std.testing.expect(server.findStream(4) != null);
    try std.testing.expectEqual(@as(usize, 2), server.activeStreamCount());

    // The outstanding FINs arrive; only now do the slots free.
    var tail_buf: [512]u8 = undefined;
    const tail = try client.streamFrameDatagram(&tail_buf, 4, "req", true, server.serverScid());
    defer std.testing.allocator.free(tail);
    try server.onDatagram(tail, 4);
    try std.testing.expect(server.findStream(4) == null);
    _ = server.takeDatagram() orelse return error.MissingDatagram;

    try server.sendStream(0, "resp", true);
    try std.testing.expect(server.findStream(0) == null);
    _ = server.takeDatagram() orelse return error.MissingDatagram;
    try std.testing.expectEqual(@as(usize, 0), server.activeStreamCount());
}

test "h3 connection: sendStreamMulti shards a large response into contiguous STREAM frames" {
    try Connection.configureServer(fixtures.cert_pem, fixtures.key_pem);

    var server: Connection = undefined;
    try server.initInPlace(std.testing.allocator, test_peer, testConfig());
    defer server.deinit();
    var client: TestClient = undefined;
    try client.init(std.testing.allocator);
    defer client.deinit();
    try handshakeToEstablished(&server, &client);

    // 10 KiB of deterministic bytes: more than any single datagram carries,
    // so the send must shard.
    var body: [10 * 1024]u8 = undefined;
    for (&body, 0..) |*byte, i| byte.* = @truncate(i * 31 + 7);

    const queued = try server.sendStreamMulti(0, &body, true);
    try std.testing.expectEqual(body.len, queued);

    // Every datagram decodes on the client; the STREAM frames arrive in
    // order with contiguous offsets, only the last carries the FIN, and
    // the reassembly matches the body byte for byte.
    var reassembled: [body.len]u8 = undefined;
    var written: usize = 0;
    var packets: usize = 0;
    var expect_offset: u64 = 0;
    while (server.takeDatagram()) |datagram| {
        packets += 1;
        var packet = try client.crypto.processProtectedRawPacket(datagram, client.largest_pn[2]);
        defer packet.deinit(std.testing.allocator);
        client.largest_pn[2] = packet.packet_number;
        var reader: std.Io.Reader = .fixed(packet.payload);
        while (reader.seek < reader.end) {
            var frame = try QuicFrames.Frame.parse(&reader, std.testing.allocator);
            defer frame.deinit(std.testing.allocator);
            switch (frame) {
                .stream => |stream| {
                    try std.testing.expectEqual(expect_offset, stream.offset);
                    const is_last = written + stream.data.len == body.len;
                    try std.testing.expectEqual(is_last, stream.fin);
                    @memcpy(reassembled[written..][0..stream.data.len], stream.data);
                    written += stream.data.len;
                    expect_offset = stream.offset + stream.data.len;
                },
                else => {},
            }
        }
    }
    try std.testing.expect(packets >= 7);
    try std.testing.expectEqual(body.len, written);
    try std.testing.expectEqualSlices(u8, &body, &reassembled);

    // The client's FIN never arrived on stream 0, so the completed send
    // half keeps the slot with fin_sent recorded.
    const state = server.findStream(0) orelse return error.MissingStream;
    try std.testing.expect(state.fin_sent);
    try std.testing.expectEqual(@as(u64, body.len), state.offset);
}

test "h3 connection: sendStreamMulti short-writes at a full queue and resumes after a drain" {
    try Connection.configureServer(fixtures.cert_pem, fixtures.key_pem);

    var server: Connection = undefined;
    try server.initInPlace(std.testing.allocator, test_peer, testConfig());
    defer server.deinit();
    var client: TestClient = undefined;
    try client.init(std.testing.allocator);
    defer client.deinit();
    try handshakeToEstablished(&server, &client);

    // Fill the 16-slot datagram queue with MAX_STREAMS bumps: each seals
    // exactly one datagram and spends no stream state.
    for (0..datagram_slots) |_| try server.raiseBidiStreamLimit();

    // A full queue stops the send before its first chunk; the zero return
    // is the short write. The stream slot exists from the state lookup,
    // ready for the retry.
    var body: [3 * max_stream_frame_payload]u8 = undefined;
    for (&body, 0..) |*byte, i| byte.* = @truncate(i * 17 + 3);
    try std.testing.expectEqual(@as(usize, 0), try server.sendStreamMulti(0, &body, true));
    try std.testing.expect(server.findStream(0) != null);

    // Two free slots fit exactly two chunks of a three-chunk body, and the
    // return value says where the retry resumes.
    _ = server.takeDatagram();
    _ = server.takeDatagram();
    const first = try server.sendStreamMulti(0, &body, true);
    try std.testing.expectEqual(2 * max_stream_frame_payload, first);

    // Drain the rest, retry the tail with fin still set: the completing
    // chunk carries it and records the FIN.
    while (server.takeDatagram()) |_| {}
    const second = try server.sendStreamMulti(0, body[first..], true);
    try std.testing.expectEqual(body.len - first, second);
    const state = server.findStream(0) orelse return error.MissingStream;
    try std.testing.expect(state.fin_sent);
    try std.testing.expectEqual(@as(u64, body.len), state.offset);
}

test "h3 connection: sendStreamMulti reports zero when no window holds a whole chunk" {
    try Connection.configureServer(fixtures.cert_pem, fixtures.key_pem);

    var server: Connection = undefined;
    try server.initInPlace(std.testing.allocator, test_peer, testConfig());
    defer server.deinit();
    var client: TestClient = undefined;
    try client.init(std.testing.allocator);
    defer client.deinit();
    try handshakeToEstablished(&server, &client);

    // Pin stream 0 in the table with one un-finned byte.
    try server.sendStream(0, "hi", false);
    _ = server.takeDatagram() orelse return error.MissingDatagram;
    const state = server.findStream(0) orelse return error.MissingStream;

    var body: [max_stream_frame_payload]u8 = undefined;
    for (&body, 0..) |*byte, i| byte.* = @truncate(i * 5 + 1);

    // Stream window one byte short of a chunk: nothing queues, and no
    // datagram is spent finding out.
    state.limit = state.offset + max_stream_frame_payload - 1;
    try std.testing.expectEqual(@as(usize, 0), try server.sendStreamMulti(0, &body, false));
    try std.testing.expect(server.takeDatagram() == null);

    // The connection-level window gives the same verdict on its own.
    state.limit = 1 << 20;
    server.peer_data_limit = server.peer_data_sent + max_stream_frame_payload - 1;
    try std.testing.expectEqual(@as(usize, 0), try server.sendStreamMulti(0, &body, false));
    try std.testing.expect(server.takeDatagram() == null);

    // One byte more of each window and the chunk fits whole: the verdict
    // flips, which is what unblocking by MAX_DATA / MAX_STREAM_DATA looks
    // like to the caller.
    state.limit = state.offset + max_stream_frame_payload;
    server.peer_data_limit = server.peer_data_sent + max_stream_frame_payload;
    try std.testing.expectEqual(body.len, try server.sendStreamMulti(0, &body, false));
}

test "h3 connection: resetStream frees the slot and the RESET_STREAM decodes on the wire" {
    try Connection.configureServer(fixtures.cert_pem, fixtures.key_pem);

    var server: Connection = undefined;
    try server.initInPlace(std.testing.allocator, test_peer, testConfig());
    defer server.deinit();
    var client: TestClient = undefined;
    try client.init(std.testing.allocator);
    defer client.deinit();
    try handshakeToEstablished(&server, &client);

    // Two bytes on stream 4, then the abort: the slot frees immediately
    // and the wire frame names the send offset as the final size
    // (RFC 9000 §19.4).
    try server.sendStream(4, "hi", false);
    const hi_datagram = server.takeDatagram() orelse return error.MissingDatagram;
    var hi_in = try client.crypto.processProtectedRawPacket(hi_datagram, client.largest_pn[2]);
    defer hi_in.deinit(std.testing.allocator);
    client.largest_pn[2] = hi_in.packet_number;

    try server.resetStream(4, h3_request_cancelled);
    try std.testing.expect(server.findStream(4) == null);

    const reset_datagram = server.takeDatagram() orelse return error.MissingDatagram;
    var reset_in = try client.crypto.processProtectedRawPacket(reset_datagram, client.largest_pn[2]);
    defer reset_in.deinit(std.testing.allocator);
    client.largest_pn[2] = reset_in.packet_number;
    var saw_reset = false;
    var reader: std.Io.Reader = .fixed(reset_in.payload);
    while (reader.seek < reader.end) {
        var frame = try QuicFrames.Frame.parse(&reader, std.testing.allocator);
        defer frame.deinit(std.testing.allocator);
        switch (frame) {
            .reset_stream => |reset| {
                try std.testing.expectEqual(@as(u64, 4), reset.stream_id);
                try std.testing.expectEqual(h3_request_cancelled, reset.application_error_code);
                try std.testing.expectEqual(@as(u64, 2), reset.final_size);
                saw_reset = true;
            },
            else => {},
        }
    }
    try std.testing.expect(saw_reset);
}

test "h3 connection: a received RESET_STREAM frees the slot, notifies on_reset, and late data reopens fresh" {
    try Connection.configureServer(fixtures.cert_pem, fixtures.key_pem);

    var server: Connection = undefined;
    try server.initInPlace(std.testing.allocator, test_peer, testConfig());
    defer server.deinit();
    var client: TestClient = undefined;
    try client.init(std.testing.allocator);
    defer client.deinit();
    try handshakeToEstablished(&server, &client);

    const Recorder = struct {
        calls: usize = 0,
        resets: usize = 0,
        last_reset: u64 = 0,
        last: [16]u8 = undefined,
        len: usize = 0,
        fin: bool = false,
        fn onData(ctx: *anyopaque, _: u64, data: []const u8, fin: bool) void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            self.calls += 1;
            @memcpy(self.last[0..data.len], data);
            self.len = data.len;
            self.fin = fin;
        }
        fn onReset(ctx: *anyopaque, stream_id: u64) void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            self.resets += 1;
            self.last_reset = stream_id;
        }
    };
    var recorder = Recorder{};
    server.setStreamHandler(.{
        .ctx = &recorder,
        .onData = Recorder.onData,
        .on_reset = Recorder.onReset,
    });

    // Open stream 4 with data but no FIN: the slot is live.
    var hello_buf: [512]u8 = undefined;
    const hello = try client.streamFrameDatagram(&hello_buf, 4, "hello", false, server.serverScid());
    defer std.testing.allocator.free(hello);
    try server.onDatagram(hello, 3);
    try std.testing.expectEqual(@as(usize, 1), server.activeStreamCount());
    try std.testing.expectEqualStrings("hello", recorder.last[0..recorder.len]);

    // The peer resets its send half: the slot frees and the subscribed
    // on_reset fires with the id — a session holding a deferred exchange
    // learns the request will never complete.
    var reset_buf: [512]u8 = undefined;
    const reset = try client.resetDatagram(&reset_buf, 4, h3_request_cancelled, 5, server.serverScid());
    defer std.testing.allocator.free(reset);
    try server.onDatagram(reset, 4);
    try std.testing.expectEqual(@as(usize, 0), server.activeStreamCount());
    try std.testing.expectEqual(@as(usize, 1), recorder.calls);
    try std.testing.expectEqual(@as(usize, 1), recorder.resets);
    try std.testing.expectEqual(@as(u64, 4), recorder.last_reset);

    // A reset for a stream never opened is safe to ignore: no slot frees,
    // no notification fires.
    var unknown_buf: [512]u8 = undefined;
    const unknown = try client.resetDatagram(&unknown_buf, 8, h3_no_error, 0, server.serverScid());
    defer std.testing.allocator.free(unknown);
    try server.onDatagram(unknown, 5);
    try std.testing.expectEqual(@as(usize, 0), server.activeStreamCount());
    try std.testing.expectEqual(@as(usize, 1), recorder.resets);

    // Late data for the reset id does not reuse stale state: with the slot
    // released, the frame is a fresh open whose receive offset restarts at
    // zero — the same semantics `dropStream` has always had.
    var late_buf: [512]u8 = undefined;
    const late = try client.streamFrameDatagram(&late_buf, 4, "late", true, server.serverScid());
    defer std.testing.allocator.free(late);
    try server.onDatagram(late, 6);
    try std.testing.expectEqual(@as(usize, 2), recorder.calls);
    try std.testing.expectEqualStrings("late", recorder.last[0..recorder.len]);
    try std.testing.expect(recorder.fin);
    const reopened = server.findStream(4) orelse return error.MissingStream;
    try std.testing.expectEqual(@as(u64, 4), reopened.recv);
    try std.testing.expectEqual(@as(u64, 0), reopened.offset);
}

test "h3 connection: closeWithError seals a decodable close frame and refuses sends" {
    try Connection.configureServer(fixtures.cert_pem, fixtures.key_pem);

    var server: Connection = undefined;
    try server.initInPlace(std.testing.allocator, test_peer, testConfig());
    defer server.deinit();
    var client: TestClient = undefined;
    try client.init(std.testing.allocator);
    defer client.deinit();
    try handshakeToEstablished(&server, &client);

    server.closeWithError(h3_general_protocol_error, "qpack table desync");
    // Closing, not closed: the close is out and retransmission is still
    // armed, so the connection must not read as reaped yet.
    try std.testing.expect(!server.isClosed());
    try std.testing.expectError(error.Closing, server.sendStream(0, "x", false));
    try std.testing.expectError(error.Closing, server.sendStreamMulti(0, "x", true));

    // The sealed frame decodes on the client with the code and the reason
    // intact; the queue holds exactly it (the ring was cleared first).
    var reason_buf: [close_reason_max]u8 = undefined;
    const close = try takeCloseFrame(&server, &client, &reason_buf);
    try std.testing.expectEqual(h3_general_protocol_error, close.code);
    try std.testing.expectEqualStrings("qpack table desync", close.reason);
    try std.testing.expect(server.takeDatagram() == null);

    // Idempotent: a second call seals nothing further, with any code.
    server.closeWithError(h3_internal_error, "other");
    try std.testing.expect(server.takeDatagram() == null);
}

test "h3 connection: closeWithError clears a full datagram queue so the close leads" {
    try Connection.configureServer(fixtures.cert_pem, fixtures.key_pem);

    var server: Connection = undefined;
    try server.initInPlace(std.testing.allocator, test_peer, testConfig());
    defer server.deinit();
    var client: TestClient = undefined;
    try client.init(std.testing.allocator);
    defer client.deinit();
    try handshakeToEstablished(&server, &client);

    // Fill the 16-slot ring with MAX_STREAMS bumps: the close must evict
    // them all, not queue behind them — after CONNECTION_CLOSE every
    // stream they credit is dead weight.
    for (0..datagram_slots) |_| try server.raiseBidiStreamLimit();
    server.closeWithError(h3_general_protocol_error, "fatal");
    var reason_buf: [close_reason_max]u8 = undefined;
    const close = try takeCloseFrame(&server, &client, &reason_buf);
    try std.testing.expectEqual(h3_general_protocol_error, close.code);
    try std.testing.expectEqualStrings("fatal", close.reason);
    try std.testing.expect(server.takeDatagram() == null);
}

test "h3 connection: closing retransmits the close once per inbound datagram and survives PTO" {
    try Connection.configureServer(fixtures.cert_pem, fixtures.key_pem);

    var server: Connection = undefined;
    try server.initInPlace(std.testing.allocator, test_peer, testConfig());
    defer server.deinit();
    var client: TestClient = undefined;
    try client.init(std.testing.allocator);
    defer client.deinit();
    try handshakeToEstablished(&server, &client);

    server.closeWithError(h3_internal_error, "boom");
    var reason_buf: [close_reason_max]u8 = undefined;
    const first = try takeCloseFrame(&server, &client, &reason_buf);
    try std.testing.expectEqualStrings("boom", first.reason);

    // Each inbound datagram earns exactly one retransmitted close: the
    // peer that has not seen the close yet keeps talking, and each thing
    // it says gets one answer (RFC 9000 §10.2.3 intent, simplified).
    var ping_buf: [512]u8 = undefined;
    const ping = try client.streamFrameDatagram(&ping_buf, 0, "again", false, server.serverScid());
    defer std.testing.allocator.free(ping);
    try server.onDatagram(ping, 3);
    const retransmitted = try takeCloseFrame(&server, &client, &reason_buf);
    try std.testing.expectEqual(h3_internal_error, retransmitted.code);
    try std.testing.expect(server.takeDatagram() == null);

    const ping2 = try client.streamFrameDatagram(&ping_buf, 0, "more", false, server.serverScid());
    defer std.testing.allocator.free(ping2);
    try server.onDatagram(ping2, 4);
    const second = try takeCloseFrame(&server, &client, &reason_buf);
    try std.testing.expectEqual(h3_internal_error, second.code);
    try std.testing.expect(server.takeDatagram() == null);

    // A protocol error while closing — an oversized datagram here — must
    // not latch `closed`: the close is already out and inbound packets
    // should keep earning retransmissions, not get refused.
    var junk: [max_datagram_bytes + 1]u8 = @splat(0x40);
    try std.testing.expectError(error.DatagramTooLarge, server.onDatagram(&junk, 5));
    try std.testing.expect(!server.isClosed());
    while (server.takeDatagram()) |_| {}

    // A PTO tick while closing must not crash: the close payloads live in
    // the sent ring and retransmit like any un-acked packet's frames.
    _ = server.onTimeout(6 + 2 * std.time.ns_per_s);
    while (server.takeDatagram()) |datagram| {
        var packet = try client.crypto.processProtectedRawPacket(
            datagram,
            client.largest_pn[2],
        );
        defer packet.deinit(std.testing.allocator);
        client.largest_pn[2] = packet.packet_number;
        var reader: std.Io.Reader = .fixed(packet.payload);
        while (reader.seek < reader.end) {
            var frame = try QuicFrames.Frame.parse(&reader, std.testing.allocator);
            defer frame.deinit(std.testing.allocator);
        }
    }
}

test "h3 connection: a received CONNECTION_CLOSE latches closed, frees every slot, and zeroes the deadline" {
    try Connection.configureServer(fixtures.cert_pem, fixtures.key_pem);

    var server: Connection = undefined;
    try server.initInPlace(std.testing.allocator, test_peer, testConfig());
    defer server.deinit();
    var client: TestClient = undefined;
    try client.init(std.testing.allocator);
    defer client.deinit();
    try handshakeToEstablished(&server, &client);

    // Two open streams hold slots when the peer dies. No stream handler is
    // installed: the close path never consults it, and opens claim slots
    // regardless.
    var one_buf: [512]u8 = undefined;
    const one = try client.streamFrameDatagram(&one_buf, 0, "one", false, server.serverScid());
    defer std.testing.allocator.free(one);
    try server.onDatagram(one, 3);
    var three_buf: [512]u8 = undefined;
    const three = try client.streamFrameDatagram(&three_buf, 4, "three", false, server.serverScid());
    defer std.testing.allocator.free(three);
    try server.onDatagram(three, 4);
    try std.testing.expectEqual(@as(usize, 2), server.activeStreamCount());

    // The two receives queued their ACK-only answers (`sealAckOnly`);
    // clear them so the assertion below — nothing is worth sending once
    // the peer has closed — sees an empty queue.
    while (server.takeDatagram()) |_| {}

    // One transport close frame (0x1c) is enough: the connection latches
    // dead, the table empties, and the reaper's deadline moves to "now".
    var close_buf: [512]u8 = undefined;
    const close = try client.closeDatagram(&close_buf, false, h3_general_protocol_error, "gone", server.serverScid());
    defer std.testing.allocator.free(close);
    try server.onDatagram(close, 5);
    try std.testing.expect(server.isClosed());
    try std.testing.expectEqual(@as(?u64, 0), server.idleDeadline());
    try std.testing.expectEqual(@as(usize, 0), server.activeStreamCount());
    try std.testing.expect(server.findStream(0) == null);
    try std.testing.expect(server.findStream(4) == null);
    try std.testing.expectError(error.Closing, server.sendStream(0, "x", false));
    try std.testing.expectError(error.ConnectionClosed, server.onDatagram(&[_]u8{1}, 6));
    try std.testing.expect(server.takeDatagram() == null);
}

test "h3 connection: a received CONNECTION_CLOSE_APP latches the same state" {
    try Connection.configureServer(fixtures.cert_pem, fixtures.key_pem);

    var server: Connection = undefined;
    try server.initInPlace(std.testing.allocator, test_peer, testConfig());
    defer server.deinit();
    var client: TestClient = undefined;
    try client.init(std.testing.allocator);
    defer client.deinit();
    try handshakeToEstablished(&server, &client);

    // The application variant (0x1d, what RFC 9114 §8 peers send with H3
    // codes) is interchangeable at this layer: dead is dead.
    var close_buf: [512]u8 = undefined;
    const close = try client.closeDatagram(&close_buf, true, h3_no_error, "bye", server.serverScid());
    defer std.testing.allocator.free(close);
    try server.onDatagram(close, 3);
    try std.testing.expect(server.isClosed());
    try std.testing.expectEqual(@as(?u64, 0), server.idleDeadline());
    try std.testing.expectEqual(@as(usize, 0), server.activeStreamCount());
    try std.testing.expectError(error.Closing, server.sendStreamMulti(0, "x", false));
}

test "h3 connection: closeWithError before the handshake falls back to the silent close" {
    try Connection.configureServer(fixtures.cert_pem, fixtures.key_pem);

    var server: Connection = undefined;
    try server.initInPlace(std.testing.allocator, test_peer, testConfig());
    defer server.deinit();

    // No 1-RTT keys exist yet, so nothing can be sealed: the close
    // degrades to `abort`'s teardown — closed, deadline zeroed, no bytes.
    server.closeWithError(h3_general_protocol_error, "too early");
    try std.testing.expect(server.isClosed());
    try std.testing.expectEqual(@as(?u64, 0), server.idleDeadline());
    try std.testing.expect(server.takeDatagram() == null);
    try std.testing.expectError(error.Closing, server.sendStream(0, "x", false));
    try std.testing.expectError(error.ConnectionClosed, server.onDatagram(&[_]u8{1}, 1));
}

test "h3 connection: a silent receive pass seals one ACK-only packet, and pure-ACK input earns no answer" {
    try Connection.configureServer(fixtures.cert_pem, fixtures.key_pem);

    var server: Connection = undefined;
    try server.initInPlace(std.testing.allocator, test_peer, testConfig());
    defer server.deinit();
    var client: TestClient = undefined;
    try client.init(std.testing.allocator);
    defer client.deinit();
    try handshakeToEstablished(&server, &client);
    // Clear anything the handshake left queued so the counts below are
    // exact.
    while (server.takeDatagram()) |_| {}

    // No stream handler is installed: nothing answers the request, the
    // whole receive pass queues no datagram, and the owed ACK is sealed
    // on its own — exactly one packet, an ACK frame plus PADDING past
    // the header-protection minimum.
    var hello_buf: [512]u8 = undefined;
    const hello = try client.streamFrameDatagram(&hello_buf, 0, "hello", false, server.serverScid());
    defer std.testing.allocator.free(hello);
    try server.onDatagram(hello, 3);
    const ack_datagram = server.takeDatagram() orelse return error.MissingAckOnly;
    var packet = try client.crypto.processProtectedRawPacket(ack_datagram, client.largest_pn[2]);
    defer packet.deinit(std.testing.allocator);
    client.largest_pn[2] = packet.packet_number;
    try std.testing.expect(packet.payload.len >= 8);
    var saw_ack = false;
    var reader: std.Io.Reader = .fixed(packet.payload);
    while (reader.seek < reader.end) {
        var frame = try QuicFrames.Frame.parse(&reader, std.testing.allocator);
        defer frame.deinit(std.testing.allocator);
        switch (frame) {
            .ack => |ack| {
                // The client's first application packet is PN 0.
                try std.testing.expectEqual(@as(u64, 0), ack.largest_acknowledged);
                saw_ack = true;
            },
            .padding => {},
            else => return error.UnexpectedFrame,
        }
    }
    try std.testing.expect(saw_ack);
    // One answer per inbound datagram — never two.
    try std.testing.expect(server.takeDatagram() == null);

    // A pure-ACK packet is not ack-eliciting: answering it would
    // ping-pong ACKs forever, so the queue stays empty.
    var frames_buf: [32]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&frames_buf);
    const ack_back = QuicFrames.AckFrame{
        .largest_acknowledged = packet.packet_number,
        .ack_delay = 0,
        .ack_range_count = 0,
        .first_ack_range = 0,
        .ack_ranges = &.{},
    };
    try ack_back.serialize(&writer);
    var pkt_buf: [512]u8 = undefined;
    const ack_only = try client.frameDatagram(&pkt_buf, frames_buf[0..writer.end], server.serverScid());
    defer std.testing.allocator.free(ack_only);
    try server.onDatagram(ack_only, 4);
    try std.testing.expect(server.takeDatagram() == null);
}

test "h3 connection: outbound data already carries the ACK, so no ACK-only is added" {
    try Connection.configureServer(fixtures.cert_pem, fixtures.key_pem);

    var server: Connection = undefined;
    try server.initInPlace(std.testing.allocator, test_peer, testConfig());
    defer server.deinit();
    var client: TestClient = undefined;
    try client.init(std.testing.allocator);
    defer client.deinit();
    try handshakeToEstablished(&server, &client);

    // A synchronous responder: the request's FIN is answered inside the
    // receive pass itself.
    const Responder = struct {
        server: *Connection,
        fn onData(ctx: *anyopaque, stream_id: u64, data: []const u8, fin: bool) void {
            _ = data;
            const self: *@This() = @ptrCast(@alignCast(ctx));
            if (fin) self.server.sendStream(stream_id, "pong", true) catch {};
        }
    };
    var responder = Responder{ .server = &server };
    server.setStreamHandler(.{ .ctx = &responder, .onData = Responder.onData });

    var req_buf: [512]u8 = undefined;
    const request = try client.streamFrameDatagram(&req_buf, 0, "ping", true, server.serverScid());
    defer std.testing.allocator.free(request);
    try server.onDatagram(request, 3);

    // Exactly one datagram was queued: the response, with the owed ACK
    // riding its prefix. A second, ACK-only, packet would be a duplicate
    // answer and must not exist.
    const datagram = server.takeDatagram() orelse return error.MissingDatagram;
    var packet = try client.crypto.processProtectedRawPacket(datagram, client.largest_pn[2]);
    defer packet.deinit(std.testing.allocator);
    client.largest_pn[2] = packet.packet_number;
    var saw_ack = false;
    var saw_pong = false;
    var reader: std.Io.Reader = .fixed(packet.payload);
    while (reader.seek < reader.end) {
        var frame = try QuicFrames.Frame.parse(&reader, std.testing.allocator);
        defer frame.deinit(std.testing.allocator);
        switch (frame) {
            .ack => |ack| {
                try std.testing.expectEqual(@as(u64, 0), ack.largest_acknowledged);
                saw_ack = true;
            },
            .stream => |stream| {
                try std.testing.expect(stream.fin);
                try std.testing.expectEqualStrings("pong", stream.data);
                saw_pong = true;
            },
            else => {},
        }
    }
    try std.testing.expect(saw_ack);
    try std.testing.expect(saw_pong);
    try std.testing.expect(server.takeDatagram() == null);
}

test "h3 connection: an established flow-control violation answers with FLOW_CONTROL_ERROR on the wire" {
    try Connection.configureServer(fixtures.cert_pem, fixtures.key_pem);

    var server: Connection = undefined;
    try server.initInPlace(std.testing.allocator, test_peer, testConfig());
    defer server.deinit();
    var client: TestClient = undefined;
    try client.init(std.testing.allocator);
    defer client.deinit();
    try handshakeToEstablished(&server, &client);

    // Pin the advertised windows at 6 bytes, the existing test idiom: a
    // stream frame one byte past the connection window is a protocol
    // violation no conforming peer commits (the peer's allowance is what
    // we advertised; anything beyond it is its own arithmetic error).
    server.recv_stream_limit = 6;
    server.recv_data_limit = 6;
    server.recv_data_advertised = 6;

    var big_buf: [512]u8 = undefined;
    const big = try client.streamFrameDatagram(&big_buf, 0, "1234567", true, server.serverScid());
    defer std.testing.allocator.free(big);
    // The fatal error no longer surfaces as a return: the walk swallows
    // it so the caller drains the queued close (an error return would
    // forfeit the frame).
    try server.onDatagram(big, 3);

    var reason_buf: [close_reason_max]u8 = undefined;
    const close = try takeCloseFrame(&server, &client, &reason_buf);
    try std.testing.expectEqual(transport_flow_control_error, close.code);
    try std.testing.expectEqualStrings("FlowControlError", close.reason);
    // Closing, not closed: the retransmission strategy keeps answering
    // until the peer goes quiet, and sends take the error.Closing path.
    try std.testing.expect(!server.isClosed());
    try std.testing.expectError(error.Closing, server.sendStream(0, "x", false));
}

test "h3 connection: a malformed frame answers with FRAME_ENCODING_ERROR on the wire" {
    try Connection.configureServer(fixtures.cert_pem, fixtures.key_pem);

    var server: Connection = undefined;
    try server.initInPlace(std.testing.allocator, test_peer, testConfig());
    defer server.deinit();
    var client: TestClient = undefined;
    try client.init(std.testing.allocator);
    defer client.deinit();
    try handshakeToEstablished(&server, &client);

    // 0x1f names no frame type: the vendor parser refuses it, and a
    // frame that does not parse is exactly FRAME_ENCODING_ERROR's
    // meaning. Only a fuzzer or a broken stack emits this — a conforming
    // peer's frames always fit their packet (the parser has no
    // "wait for more bytes" shape at this layer, and none is needed).
    // The 0x1f type byte leads; the padding only carries the packet
    // past the header-protection sample minimum on the sealing side.
    var payload = [_]u8{ 0x1f, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    var pkt_buf: [512]u8 = undefined;
    const datagram = try client.frameDatagram(&pkt_buf, &payload, server.serverScid());
    defer std.testing.allocator.free(datagram);
    try server.onDatagram(datagram, 3);

    var reason_buf: [close_reason_max]u8 = undefined;
    const close = try takeCloseFrame(&server, &client, &reason_buf);
    try std.testing.expectEqual(transport_frame_encoding_error, close.code);
    try std.testing.expectEqualStrings("InvalidFrame", close.reason);
}

test "h3 connection: backpressure never earns a CONNECTION_CLOSE" {
    try Connection.configureServer(fixtures.cert_pem, fixtures.key_pem);

    var server: Connection = undefined;
    try server.initInPlace(std.testing.allocator, test_peer, testConfig());
    defer server.deinit();
    var client: TestClient = undefined;
    try client.init(std.testing.allocator);
    defer client.deinit();
    try handshakeToEstablished(&server, &client);

    // Fill the datagram ring with MAX_STREAMS bumps, then pin the
    // connection flow-control window at exactly what has been sent: both
    // are backpressure shapes with retry semantics, not errors, and a
    // closing flag would turn the next inbound datagram into a refusal.
    for (0..datagram_slots) |_| try server.raiseBidiStreamLimit();
    server.peer_data_limit = server.peer_data_sent;
    try std.testing.expectError(error.FlowControlBlocked, server.sendStream(0, "x", false));
    var body: [2 * max_stream_frame_payload]u8 = undefined;
    for (&body, 0..) |*byte, i| byte.* = @truncate(i * 7 + 1);
    try std.testing.expectEqual(@as(usize, 0), try server.sendStreamMulti(0, &body, true));

    // Every queued datagram must decode with no CONNECTION_CLOSE in it,
    // and the connection must be neither closing nor closed.
    while (server.takeDatagram()) |queued| {
        var packet = try client.crypto.processProtectedRawPacket(queued, client.largest_pn[2]);
        defer packet.deinit(std.testing.allocator);
        client.largest_pn[2] = packet.packet_number;
        var reader: std.Io.Reader = .fixed(packet.payload);
        while (reader.seek < reader.end) {
            var frame = try QuicFrames.Frame.parse(&reader, std.testing.allocator);
            defer frame.deinit(std.testing.allocator);
            switch (frame) {
                .connection_close, .connection_close_app => return error.UnexpectedClose,
                else => {},
            }
        }
    }
    try std.testing.expect(!server.closing);
    try std.testing.expect(!server.isClosed());

    // The retry the backpressure promised: unpin the window (a MAX_DATA
    // top-up is what unblocks a real peer) and the drained ring takes
    // the first chunk at once.
    server.peer_data_limit = 1 << 20;
    const queued = try server.sendStreamMulti(0, &body, true);
    try std.testing.expect(queued > 0);
}

test "h3 connection: while closing, the close retransmission answers instead of an ACK-only packet" {
    try Connection.configureServer(fixtures.cert_pem, fixtures.key_pem);

    var server: Connection = undefined;
    try server.initInPlace(std.testing.allocator, test_peer, testConfig());
    defer server.deinit();
    var client: TestClient = undefined;
    try client.init(std.testing.allocator);
    defer client.deinit();
    try handshakeToEstablished(&server, &client);

    server.closeWithError(h3_general_protocol_error, "bye");
    var reason_buf: [close_reason_max]u8 = undefined;
    _ = try takeCloseFrame(&server, &client, &reason_buf);

    // The peer keeps uploading, unaware of the close. The single answer
    // its datagram earns must be the close retransmission — with the owed
    // ACK riding its `seal` prefix — never a competing ACK-only packet.
    var ping_buf: [512]u8 = undefined;
    const ping = try client.streamFrameDatagram(&ping_buf, 0, "more", false, server.serverScid());
    defer std.testing.allocator.free(ping);
    try server.onDatagram(ping, 3);

    const datagram = server.takeDatagram() orelse return error.MissingDatagram;
    var packet = try client.crypto.processProtectedRawPacket(datagram, client.largest_pn[2]);
    defer packet.deinit(std.testing.allocator);
    client.largest_pn[2] = packet.packet_number;
    var saw_ack = false;
    var saw_close = false;
    var reader: std.Io.Reader = .fixed(packet.payload);
    while (reader.seek < reader.end) {
        var frame = try QuicFrames.Frame.parse(&reader, std.testing.allocator);
        defer frame.deinit(std.testing.allocator);
        switch (frame) {
            .ack => |ack| {
                try std.testing.expectEqual(@as(u64, 0), ack.largest_acknowledged);
                saw_ack = true;
            },
            .connection_close => |close| {
                try std.testing.expectEqual(h3_general_protocol_error, close.error_code);
                try std.testing.expectEqualStrings("bye", close.reason_phrase);
                saw_close = true;
            },
            else => {},
        }
    }
    try std.testing.expect(saw_ack);
    try std.testing.expect(saw_close);
    // One packet answered the datagram — the close, not the close plus an
    // ACK-only behind it.
    try std.testing.expect(server.takeDatagram() == null);
}

test "h3 connection: window notify fires once per window-frame group and never on plain data or the timer" {
    try Connection.configureServer(fixtures.cert_pem, fixtures.key_pem);

    var server: Connection = undefined;
    try server.initInPlace(std.testing.allocator, test_peer, testConfig());
    defer server.deinit();
    var client: TestClient = undefined;
    try client.init(std.testing.allocator);
    defer client.deinit();
    try handshakeToEstablished(&server, &client);

    const Counter = struct {
        calls: usize = 0,
        fn onOpen(ctx: *anyopaque) void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            self.calls += 1;
        }
    };
    var counter = Counter{};
    server.window_notify = .{ .ctx = &counter, .onOpen = Counter.onOpen };

    // A plain STREAM datagram carries no window frame: the notify stays
    // silent, and the stream it opened is in the table for the next step.
    var hello_buf: [512]u8 = undefined;
    const hello = try client.streamFrameDatagram(&hello_buf, 4, "hello", false, server.serverScid());
    defer std.testing.allocator.free(hello);
    try server.onDatagram(hello, 3);
    try std.testing.expectEqual(@as(usize, 0), counter.calls);

    // One MAX_DATA frame in one packet: exactly one notify, and the new
    // ceiling is what the frame carried.
    var frames_buf: [64]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&frames_buf);
    const max_data = QuicFrames.MaxDataFrame{ .maximum_data = 2 * 1024 * 1024 };
    try max_data.serialize(&writer);
    var pkt_buf: [512]u8 = undefined;
    const max_data_dg = try client.frameDatagram(&pkt_buf, frames_buf[0..writer.end], server.serverScid());
    defer std.testing.allocator.free(max_data_dg);
    try server.onDatagram(max_data_dg, 4);
    try std.testing.expectEqual(@as(usize, 1), counter.calls);
    try std.testing.expectEqual(@as(u64, 2 * 1024 * 1024), server.peer_data_limit);

    // MAX_DATA and MAX_STREAM_DATA in the same packet are one frame group:
    // one notify, both ceilings raised (the stream-4 slot exists, so its
    // limit moves; the frame for an unknown id 8 is processed and ignored).
    var group_buf: [96]u8 = undefined;
    var group_writer: std.Io.Writer = .fixed(&group_buf);
    const group_max_data = QuicFrames.MaxDataFrame{ .maximum_data = 4 * 1024 * 1024 };
    try group_max_data.serialize(&group_writer);
    const group_stream_data = QuicFrames.MaxStreamDataFrame{
        .stream_id = 4,
        .maximum_stream_data = 1 << 20,
    };
    try group_stream_data.serialize(&group_writer);
    const unknown_stream_data = QuicFrames.MaxStreamDataFrame{
        .stream_id = 8,
        .maximum_stream_data = 1 << 20,
    };
    try unknown_stream_data.serialize(&group_writer);
    const group_dg = try client.frameDatagram(&pkt_buf, group_buf[0..group_writer.end], server.serverScid());
    defer std.testing.allocator.free(group_dg);
    try server.onDatagram(group_dg, 5);
    try std.testing.expectEqual(@as(usize, 2), counter.calls);
    try std.testing.expectEqual(@as(u64, 4 * 1024 * 1024), server.peer_data_limit);
    const stream4 = server.findStream(4) orelse return error.MissingStream;
    try std.testing.expectEqual(@as(u64, 1 << 20), stream4.limit);

    // The timer path (PTO sweep) must not fire the notify: no window frame
    // arrived, so a tick is not news.
    _ = server.onTimeout(6 + 2 * std.time.ns_per_s);
    try std.testing.expectEqual(@as(usize, 2), counter.calls);
}
