//! UDP listener for the HTTP/3 seam: one socket, bounded connection slots.
//!
//! The listener owns the datagram loop. It parses just enough of each packet
//! to find its connection id, demultiplexes to a `connection.Connection` slot,
//! lets that connection consume the datagram, and submits whatever the
//! connection queued back to the datagram's source address. The fast path
//! allocates nothing: slots, demux storage and send buffers are reserved at
//! init, and this file never touches the page allocator.
//!
//! **Not in this slice:** ACK generation and flow control remain in
//! `connection.zig`'s deferred set. Idle reaping runs on the 100 ms timer
//! (the `onTimer` sweep) and, redundantly, at the head of `onRecv` — the
//! receive-side scan stays because it reaps before dispatch, which the
//! tick alone cannot do for a peer already mid-datagram.
//!
//! Teardown note: `stop` only marks the listener stopping. A close while the
//! receive completion is armed would strand that completion in the backend,
//! so `deinit` closes the socket only when no receive is armed and otherwise
//! leaves the socket to the caller.

const std = @import("std");

const constants = @import("../../constants.zig");
const Io = @import("../../io/io.zig");
const qtls = @import("qtls");
const zquic = @import("zquic");
const qpack = @import("qpack");

const connection = @import("connection.zig");
const proxy = @import("proxy.zig");
const request_stream = @import("request_stream.zig");
const session = @import("session.zig");
const demux = @import("demux.zig");

const Packet = zquic.core.Packet;
const QuicFrames = zquic.core.QuicFrames;
const Http3 = zquic.Http3;

/// TLS QUIC levels indexed by QUIC packet-number space.
const tls_levels = [3]usize{ 0, 2, 3 };

/// One inbound datagram per receive: QUIC's practical MTU is below this, and
/// `connection` emits nothing larger.
const recv_bytes_max = connection.max_datagram_bytes;

/// Outbound submissions that may be in flight at once. Overflow is a drop,
/// not a stall: UDP is lossy and the connection's recovery slice will resend.
const send_slots = 8;

pub fn Listener(comptime IoType: type) type {
    comptime Io.assertUdpInterface(IoType);

    return struct {
        const Self = @This();

        /// A connection slot. The pool's handle indexes this slice; `active`
        /// is the authority because the pool payload is only the index.
        pub const Slot = struct {
            conn: connection.Connection = undefined,
            /// The HTTP/3 layer for this connection. Initialized only when
            /// the listener has a request handler; without one the raw
            /// stream handler (if any) receives bytes instead.
            h3: session.H3Session = undefined,
            h3_ready: bool = false,
            peer: std.Io.net.IpAddress = undefined,
            active: bool = false,
        };

        comptime {
            // The §5 budget prices this slot at
            // `constants.h3_session_slot_bytes`; a slot that outgrows the
            // price fails the build here, the way `h3_exchange_slot_bytes`
            // fails inside the proxy. Evaluated per Io instantiation.
            std.debug.assert(@sizeOf(Slot) <= constants.h3_session_slot_bytes);
        }

        io: *IoType,
        arena: std.mem.Allocator,
        conn_config: connection.Config,
        stream_handler: ?connection.StreamHandler = null,
        request_handler: ?session.RequestHandler = null,
        /// The proxy's deregistration hook: called with the session
        /// pointer right before `h3.deinit`, so every in-flight upstream
        /// exchange naming that session is closed out without answering
        /// it. Installed by the runtime after both listener and proxy
        /// exist; null in seam tests, which drive exchanges directly.
        exchange_teardown: ?proxy.SessionTeardown = null,
        /// The witness hook the session lifecycle reports through — the
        /// request/response half belongs to `proxy`, and one hook covers
        /// the whole `h3_*` counter family. Null in seam tests.
        counters: ?proxy.Counters = null,
        /// The proxy's backpressure-retry hook, fanned out to every active
        /// connection and inherited by slots opened later: a stalled
        /// response retries when a window frame arrives, and the 100 ms
        /// tick re-issues the hook as the fallback beat. Null in seam
        /// tests, where nothing pending ever exists.
        window_notify: ?connection.WindowNotify = null,

        udp: IoType.UdpSocket,
        bound: std.Io.net.IpAddress,

        slots: []Slot,
        in_use: usize,
        demux_storage: []demux.Entry,
        demux_table: demux.Table,

        recv_buffer: [recv_bytes_max]u8 = undefined,
        recv_completion: IoType.UdpCompletion = undefined,
        recv_armed: bool = false,
        /// One coarse PTO tick for every connection. Per-connection timers
        /// would need a cancel path per slot; a 100 ms scan is enough to
        /// drive `onTimeout` at this stage.
        timer_completion: IoType.Completion = .{},
        timer_armed: bool = false,

        send_buffers: [send_slots][connection.max_datagram_bytes]u8 = undefined,
        send_completions: [send_slots]IoType.UdpCompletion = undefined,
        send_ops: [send_slots]SendOp = undefined,
        send_busy: [send_slots]bool = @splat(false),

        started: bool = false,
        stopping: bool = false,

        const SendOp = struct {
            listener: *Self,
            index: usize,
            /// The connection slot this send belongs to, so completing one
            /// send can immediately drain that slot's next queued datagram
            /// instead of waiting for the next inbound packet or tick.
            slot_index: u16,

            fn onDone(self: *SendOp, result: Io.SendError!u32) void {
                _ = result catch 0;
                self.listener.send_busy[self.index] = false;
                self.listener.drainOutbound(self.slot_index);
            }
        };

        /// Reserve slots, demux entries and the socket. The caller owns
        /// `arena`; per-connection arenas are embedded in `Connection` and
        /// are not part of this allocation.
        pub fn initInPlace(
            self: *Self,
            io: *IoType,
            arena: std.mem.Allocator,
            bind: std.Io.net.IpAddress,
            conn_config: connection.Config,
            max_connections: u16,
        ) !void {
            if (max_connections == 0) return error.InvalidArgument;
            self.io = io;
            self.arena = arena;
            self.conn_config = conn_config;
            self.stream_handler = null;
            self.request_handler = null;
            self.exchange_teardown = null;
            self.counters = null;
            self.window_notify = null;
            self.started = false;
            self.stopping = false;
            self.recv_armed = false;
            self.timer_armed = false;
            self.timer_completion = .{};

            self.slots = try arena.alloc(Slot, max_connections);
            for (self.slots) |*slot| slot.* = .{};
            self.in_use = 0;

            // Two identities per connection: the client's original DCID
            // (Initial packets) and this server's SCID (everything after).
            self.demux_storage = try arena.alloc(demux.Entry, max_connections * 2);
            self.demux_table = demux.Table.init(self.demux_storage);

            self.udp = try IoType.udpBind(io, &.{ .ip = bind });
            self.bound = IoType.udpAddress(io, self.udp);
            self.recv_completion = .{};

            for (&self.send_ops, &self.send_completions, 0..) |*op, *completion, index| {
                op.* = .{ .listener = self, .index = index, .slot_index = 0 };
                completion.* = .{};
            }
        }

        /// Release listener state. The socket is closed only when no receive
        /// completion is armed; otherwise the backend still owns it and the
        /// caller must close it after the loop has drained (or cancel first).
        pub fn deinit(self: *Self, io: *IoType) void {
            for (self.slots) |*slot| {
                if (!slot.active) continue;
                // Teardown outside `releaseSlot` (this close defers to the
                // armed receive), but the session still ends here — count
                // it, or opened minus closed would not be the occupancy.
                self.note(.connection_closed);
                if (slot.h3_ready) {
                    // Deregister the session's in-flight exchanges before
                    // the session memory goes away: an exchange completing
                    // after this deinit would answer a dead session.
                    if (self.exchange_teardown) |teardown| {
                        teardown.forget(teardown.ctx, &slot.h3);
                    }
                    slot.h3.deinit();
                    slot.h3_ready = false;
                }
                slot.conn.deinit();
                slot.active = false;
            }
            if (!self.recv_armed) IoType.udpCloseNow(io, self.udp);
            self.started = false;
            self.stopping = true;
        }

        /// Arm the first receive. Idempotent so a caller can start a listener
        /// that was already nudged by a racing path.
        pub fn start(self: *Self) void {
            if (self.started or self.stopping) return;
            self.started = true;
            self.armRecv();
            self.armTimer();
        }

        /// Ask the loop to stop delivering. The armed receive stays armed;
        /// see `deinit`.
        pub fn stop(self: *Self) void {
            self.stopping = true;
        }

        pub fn setStreamHandler(self: *Self, handler: connection.StreamHandler) void {
            self.stream_handler = handler;
            for (self.slots) |*slot| {
                if (slot.active and !slot.h3_ready) slot.conn.setStreamHandler(handler);
            }
        }

        /// Install the HTTP/3 request handler. Applies to connections opened
        /// afterwards; existing raw-mode connections keep their handler.
        pub fn setRequestHandler(self: *Self, handler: session.RequestHandler) void {
            self.request_handler = handler;
        }

        /// Install the exchange-teardown registration the proxy answers
        /// through. Like `setRequestHandler`, applies from installation
        /// onwards; the runtime installs both before `start`.
        pub fn setExchangeTeardown(self: *Self, teardown: proxy.SessionTeardown) void {
            self.exchange_teardown = teardown;
        }

        /// Install the counter witness hook the session lifecycle reports
        /// through. Applies to connections opened afterwards, exactly like
        /// `setRequestHandler`; the runtime installs both before `start`.
        pub fn setCounters(self: *Self, counters: ?proxy.Counters) void {
            self.counters = counters;
        }

        /// Install the window-open notify hook. Every current connection
        /// slot gets it immediately, and `openSlot` wires it into slots
        /// opened afterwards. The hook runs at most once per received
        /// window-frame datagram (in `Connection.handleFrames`) and once
        /// per 100 ms tick (`onTimer`), so with nothing pending it must be
        /// a cheap no-op.
        pub fn setWindowNotify(self: *Self, notify: connection.WindowNotify) void {
            self.window_notify = notify;
            for (self.slots) |*slot| {
                if (slot.active) slot.conn.window_notify = notify;
            }
        }

        pub fn boundAddress(self: *const Self) std.Io.net.IpAddress {
            return self.bound;
        }

        pub fn connectionCount(self: *const Self) usize {
            return self.in_use;
        }

        fn armRecv(self: *Self) void {
            self.recv_armed = true;
            self.recv_completion = .{};
            IoType.udpRecv(
                self.io,
                self.udp,
                self.recv_buffer[0..],
                &self.recv_completion,
                Self,
                self,
                Self.onRecv,
            );
        }

        fn armTimer(self: *Self) void {
            self.timer_armed = true;
            IoType.timerStart(
                self.io,
                &self.timer_completion,
                100 * std.time.ns_per_ms,
                Self,
                self,
                Self.onTimer,
            );
        }

        fn onTimer(self: *Self, result: Io.TimerError!void) void {
            self.timer_armed = false;
            result catch return;
            if (self.stopping) return;
            const now = IoType.nowNs(self.io);
            for (self.slots, 0..) |*slot, index| {
                if (!slot.active) continue;
                if (slot.conn.onTimeout(now)) self.drainOutbound(@intCast(index));
                // The fallback retry beat for backpressured streams: a
                // window frame may never come (the peer's own window is
                // full too), so the tick re-invokes the hook, and anything
                // the retry queues is drained right behind it.
                if (slot.conn.window_notify) |notify| {
                    notify.onOpen(notify.ctx);
                    self.drainOutbound(@intCast(index));
                }
            }
            // The tick is also the idle sweep: a quiet expired connection
            // holds its 256 KiB slot until something notices, and "the
            // next inbound datagram" never comes for a client that simply
            // went away. Bounded by the slot count, so the 100 ms cadence
            // is what it costs whether or not anything expired.
            self.reapIdle(now);
            self.armTimer();
        }

        fn onRecv(self: *Self, result: Io.RecvError!Io.UdpDatagram) void {
            self.recv_armed = false;
            const datagram = result catch {
                self.stopping = true;
                return;
            };
            if (self.stopping) return;
            const len: usize = @min(@as(usize, datagram.len), self.recv_buffer.len);
            const now = IoType.nowNs(self.io);
            // Redundant with the timer sweep but cheap: reap before
            // dispatch so a datagram from a peer whose deadline already
            // passed does not buy the slot another interval.
            self.reapIdle(now);
            self.dispatch(self.recv_buffer[0..len], datagram.source, now);
            if (!self.stopping) self.armRecv();
        }

        /// Route one datagram: existing key, a new Initial, or a drop.
        fn dispatch(
            self: *Self,
            bytes: []const u8,
            peer: std.Io.net.IpAddress,
            now: u64,
        ) void {
            const header = Packet.PacketHeader.parse(bytes, self.arena) catch return;
            const key = makeKey(header.dest_conn_id.bytes(), peer);
            if (self.demux_table.lookup(key)) |index| {
                self.handleDatagram(index, bytes, now);
                return;
            }
            // Only an Initial may create a connection. Anything else with an
            // unknown connection id is a stray or stale packet.
            if (header.packet_type != .initial) return;
            self.openSlot(bytes, peer, now);
        }

        fn openSlot(
            self: *Self,
            bytes: []const u8,
            peer: std.Io.net.IpAddress,
            now: u64,
        ) void {
            const index = self.acquireSlot() orelse return;
            const slot = &self.slots[index];
            slot.peer = peer;
            slot.active = true;
            slot.conn.initInPlace(self.arena, peer, self.conn_config) catch {
                slot.active = false;
                self.in_use -= 1;
                return;
            };
            // The notify could not be installed before the connection
            // existed (`initInPlace` clears it); inherit it now, before the
            // first datagram can stall a send.
            if (self.window_notify) |notify| slot.conn.window_notify = notify;
            if (self.request_handler) |handler| {
                slot.h3.initInPlace(
                    self.arena,
                    .{ .ctx = slot, .send = sendViaSlot },
                    handler,
                ) catch {
                    slot.active = false;
                    self.in_use -= 1;
                    return;
                };
                slot.h3.peer = slot.peer;
                slot.h3_ready = true;
                // The session hands freed request slots back to the client
                // as stream credit through this pointer; both halves of the
                // slot exist by this line.
                slot.h3.conn = &slot.conn;
                slot.conn.setStreamHandler(slot.h3.streamHandler());
            } else if (self.stream_handler) |handler| {
                slot.conn.setStreamHandler(handler);
            }
            // The session is fully installed and about to serve: count it
            // opened here, after the init paths that can still bail, so an
            // opened session always pairs with exactly one closed below.
            self.note(.connection_opened);
            slot.conn.onDatagram(bytes, now) catch {
                self.releaseSlot(index);
                return;
            };
            self.insertKey(slot.conn.clientDcid(), peer, index);
            self.insertKey(slot.conn.serverScid(), peer, index);
            self.maybeStartH3(index);
            self.drainOutbound(index);
        }

        fn handleDatagram(self: *Self, index: u16, bytes: []const u8, now: u64) void {
            const slot = &self.slots[index];
            slot.conn.onDatagram(bytes, now) catch {
                self.releaseSlot(index);
                return;
            };
            self.maybeStartH3(index);
            self.drainOutbound(index);
        }

        /// The server control/QPACK streams may only be sent once the
        /// handshake is complete. `sendControl` is idempotent.
        fn maybeStartH3(self: *Self, index: u16) void {
            const slot = &self.slots[index];
            if (!slot.h3_ready or !slot.conn.isEstablished()) return;
            slot.h3.sendControl() catch {};
        }

        /// Sender context for one connection's H3 session: the slot owns
        /// both the session and the connection it writes through.
        fn sendViaSlot(
            ctx: *anyopaque,
            stream_id: u64,
            data: []const u8,
            fin: bool,
        ) anyerror!void {
            const slot: *Slot = @ptrCast(@alignCast(ctx));
            try slot.conn.sendStream(stream_id, data, fin);
        }

        /// Copy each queued packet into a listener-owned buffer before the
        /// next `takeDatagram` invalidates it, then hand it to the backend.
        /// Only take a datagram when a send buffer is actually free:
        /// `submit` drops silently on exhaustion, and a datagram removed
        /// from the connection queue is gone for good.
        fn drainOutbound(self: *Self, index: u16) void {
            const slot = &self.slots[index];
            while (self.freeSend() != null) {
                const datagram = slot.conn.takeDatagram() orelse break;
                self.submit(index, datagram, slot.peer);
            }
        }

        fn submit(self: *Self, slot_index: u16, bytes: []const u8, peer: std.Io.net.IpAddress) void {
            if (bytes.len == 0 or bytes.len > connection.max_datagram_bytes) return;
            const index = self.freeSend() orelse return;
            @memcpy(self.send_buffers[index][0..bytes.len], bytes);
            self.send_busy[index] = true;
            self.send_completions[index] = .{};
            self.send_ops[index] = .{ .listener = self, .index = index, .slot_index = slot_index };
            IoType.udpSend(
                self.io,
                self.udp,
                peer,
                self.send_buffers[index][0..bytes.len],
                &self.send_completions[index],
                SendOp,
                &self.send_ops[index],
                SendOp.onDone,
            );
        }

        fn freeSend(self: *Self) ?usize {
            for (&self.send_busy, 0..) |*busy, index| {
                if (!busy.*) return index;
            }
            return null;
        }

        fn insertKey(
            self: *Self,
            cid: []const u8,
            peer: std.Io.net.IpAddress,
            index: u16,
        ) void {
            self.demux_table.insert(makeKey(cid, peer), index) catch {};
        }

        /// Drop connections whose idle deadline has passed. Bounded by slot
        /// count; a miss is impossible because `releaseSlot` tombstones both
        /// of the connection's demux keys.
        fn reapIdle(self: *Self, now: u64) void {
            for (self.slots, 0..) |*slot, index| {
                if (!slot.active) continue;
                const deadline = slot.conn.idleDeadline() orelse continue;
                if (deadline > now) continue;
                self.releaseSlot(@intCast(index));
            }
        }

        fn releaseSlot(self: *Self, index: u16) void {
            const slot = &self.slots[index];
            if (!slot.active) return;
            self.note(.connection_closed);
            if (slot.h3_ready) {
                // Deregister the session's in-flight exchanges first: the
                // proxy's exchanges name this session, and an exchange
                // completing after `h3.deinit` would send its answer into
                // freed slot memory.
                if (self.exchange_teardown) |teardown| {
                    teardown.forget(teardown.ctx, &slot.h3);
                }
                slot.h3.deinit();
                slot.h3_ready = false;
            }
            slot.conn.deinit();
            self.demux_table.removeSlot(index);
            slot.active = false;
            self.in_use -= 1;
        }

        /// Report one observable session event to the installed counter
        /// hook, if the runtime installed one. Null in seam tests, where
        /// the lifecycle runs unwitnessed.
        fn note(self: *Self, event: proxy.Counters.Event) void {
            if (self.counters) |counters| counters.note(counters.ctx, event, null);
        }

        /// Lowest free slot, matching the old pool's deterministic choice.
        fn acquireSlot(self: *Self) ?u16 {
            for (self.slots, 0..) |*slot, index| {
                if (slot.active) continue;
                self.in_use += 1;
                return @intCast(index);
            }
            return null;
        }

        fn makeKey(cid: []const u8, peer: std.Io.net.IpAddress) demux.Key {
            var key = demux.Key{ .peer = peer };
            const copy_len = @min(cid.len, key.cid.len);
            @memcpy(key.cid[0..copy_len], cid[0..copy_len]);
            // The demux rejects over-long lengths; the header parser already
            // caps them at 20, so the cast cannot truncate in practice.
            key.cid_len = @intCast(cid.len);
            return key;
        }
    };
}

// ---------------------------------------------------------------------------
// Test: a SimIo client sends one valid Initial through a real socket pair.
// ---------------------------------------------------------------------------

const fixtures = struct {
    const cert_pem = @embedFile("../../tls/testdata/cert.pem");
    const key_pem = @embedFile("../../tls/testdata/key.pem");
};

const TestClient = struct {
    ctx: zquic.EnhancedCrypto.EnhancedTlsContext,
    crypto: zquic.PacketCrypto,
    tls: *qtls.Tls,
    dcid: [8]u8 = @splat(0x11),
    scid: [8]u8 = @splat(0x22),
    largest_pn: [3]?u64 = .{ null, null, null },

    fn initInPlace(self: *TestClient, allocator: std.mem.Allocator) !void {
        // Defaults on a struct type apply only to struct literals; the test
        // declares this client as `undefined` and initializes in place.
        self.dcid = @splat(0x11);
        self.scid = @splat(0x22);
        self.largest_pn = .{ null, null, null };
        self.ctx = try zquic.EnhancedCrypto.EnhancedTlsContext.init(
            allocator,
            false,
            .aes_128_gcm_sha256,
        );
        self.crypto = try zquic.PacketCrypto.init(allocator, &self.ctx, null);
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
        self.ctx.deinit();
    }

    /// ClientHello in one Initial packet. The caller owns the returned bytes.
    fn initial(self: *TestClient, wire: []u8) ![]u8 {
        try self.tls.drive();
        var out: std.Io.Writer = .fixed(wire);
        const frame = zquic.core.QuicFrames.Frame{ .crypto = .init(0, self.tls.takeOut(0)) };
        try frame.serialize(&out);
        defer self.tls.clearOut(0);
        return self.crypto.createProtectedRawPacket(
            .initial,
            .initial,
            &self.dcid,
            &self.scid,
            wire[0..out.end],
        );
    }

    /// Feed one server datagram to TLS and install whatever secret levels
    /// became complete. Returns true when the client handshake is finished.
    fn accept(self: *TestClient, allocator: std.mem.Allocator, datagram: []const u8) !bool {
        const header = try Packet.PacketHeader.parse(datagram, allocator);
        const slot: usize = switch (header.packet_type) {
            .initial => 0,
            .handshake => 1,
            .one_rtt => 2,
            else => return error.UnexpectedPacket,
        };
        const level = tls_levels[slot];
        var packet = try self.crypto.processProtectedRawPacket(datagram, self.largest_pn[slot]);
        defer packet.deinit(allocator);
        self.largest_pn[slot] = packet.packet_number;

        var reader: std.Io.Reader = .fixed(packet.payload);
        while (reader.seek < reader.end) {
            var frame = try QuicFrames.Frame.parse(&reader, allocator);
            defer frame.deinit(allocator);
            switch (frame) {
                .crypto => |crypto| try self.tls.pushCrypto(level, crypto.data),
                else => {},
            }
        }
        try self.tls.drive();
        try self.tls.drive();
        if (!self.crypto.isLevelPinned(.handshake)) {
            const secrets = self.tls.takeSecrets(2);
            if (secrets.complete()) try installClientKeys(&self.crypto, 2, secrets);
        }
        if (!self.crypto.isLevelPinned(.application)) {
            const secrets = self.tls.takeSecrets(3);
            if (secrets.complete()) try installClientKeys(&self.crypto, 3, secrets);
        }
        return self.tls.isFinished();
    }

    fn finishedDatagram(self: *TestClient, out: []u8, server_scid: []const u8) ![]u8 {
        var writer: std.Io.Writer = .fixed(out);
        const frame = QuicFrames.Frame{ .crypto = .init(0, self.tls.takeOut(2)) };
        try frame.serialize(&writer);
        defer self.tls.clearOut(2);
        return self.crypto.createProtectedRawPacket(
            .handshake,
            .handshake,
            server_scid,
            &self.scid,
            out[0..writer.end],
        );
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
};

const ClientProbe = struct {
    sim: *Io.SimIo,
    buffer: []u8,
    expected_dcid: [8]u8,
    received: bool = false,
    long_header: bool = false,
    dcid_ok: bool = false,
    source: std.Io.net.IpAddress = undefined,

    fn onSend(_: *ClientProbe, result: Io.SendError!u32) void {
        _ = result catch 0;
    }

    fn onRecv(self: *ClientProbe, result: Io.RecvError!Io.UdpDatagram) void {
        const datagram = result catch {
            self.sim.stop();
            return;
        };
        self.received = true;
        self.source = datagram.source;
        const len: usize = @min(@as(usize, datagram.len), self.buffer.len);
        const header = Packet.PacketHeader.parse(self.buffer[0..len], std.testing.allocator) catch {
            self.sim.stop();
            return;
        };
        self.long_header = header.packet_type == .initial or header.packet_type == .handshake;
        self.dcid_ok = std.mem.eql(u8, header.dest_conn_id.bytes(), &self.expected_dcid);
        self.sim.stop();
    }
};

test "h3 listener: demuxes an Initial, replies from one slot, drops strays" {
    const SimIo = Io.SimIo;
    const TestListener = Listener(SimIo);

    try connection.Connection.configureServer(fixtures.cert_pem, fixtures.key_pem);

    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var sim_io: SimIo = undefined;
    try sim_io.init(arena, .{ .seed = 17 });

    const loopback = try std.Io.net.IpAddress.parseLiteral("127.0.0.1:0");
    var listener: TestListener = undefined;
    try listener.initInPlace(&sim_io, arena, loopback, .{
        .cert_pem = fixtures.cert_pem,
        .key_pem = fixtures.key_pem,
    }, 2);
    defer listener.deinit(&sim_io);
    listener.start();
    try std.testing.expect(listener.boundAddress().getPort() != 0);
    try std.testing.expectEqual(@as(usize, 0), listener.connectionCount());

    var client: TestClient = undefined;
    try client.initInPlace(std.testing.allocator);
    defer client.deinit();

    const client_socket = try sim_io.udpBind(&.{ .ip = loopback });
    defer sim_io.udpCloseNow(client_socket);

    var recv_buffer: [connection.max_datagram_bytes]u8 = undefined;
    var probe = ClientProbe{
        .sim = &sim_io,
        .buffer = &recv_buffer,
        .expected_dcid = client.scid,
    };
    var recv_completion: SimIo.UdpCompletion = .{};
    sim_io.udpRecv(
        client_socket,
        &recv_buffer,
        &recv_completion,
        ClientProbe,
        &probe,
        ClientProbe.onRecv,
    );

    // A short-header datagram with an unknown DCID is a miss and must be
    // dropped without consuming a connection slot. SimIo may deliver the two
    // sends in either order, so the chosen DCID must miss in both.
    var stray: [24]u8 = @splat(0);
    stray[0] = 0x40;
    // A DCID no connection will ever own: even if the simulator delivers
    // this after the Initial, the lookup must miss and the type must drop it.
    @memset(stray[1..9], 0xaa);
    var stray_send: SimIo.UdpCompletion = .{};
    sim_io.udpSend(
        client_socket,
        listener.boundAddress(),
        &stray,
        &stray_send,
        ClientProbe,
        &probe,
        ClientProbe.onSend,
    );

    var hello_wire: [4096]u8 = undefined;
    const initial = try client.initial(&hello_wire);
    defer std.testing.allocator.free(initial);
    var initial_send: SimIo.UdpCompletion = .{};
    sim_io.udpSend(
        client_socket,
        listener.boundAddress(),
        initial,
        &initial_send,
        ClientProbe,
        &probe,
        ClientProbe.onSend,
    );

    // The client stops the deterministic loop on the first reply.
    try sim_io.run();

    try std.testing.expect(probe.received);
    try std.testing.expect(probe.long_header);
    try std.testing.expect(probe.dcid_ok);
    try std.testing.expectEqual(@as(usize, 1), listener.connectionCount());
    try std.testing.expectEqual(listener.boundAddress().getPort(), probe.source.getPort());
}

// ---------------------------------------------------------------------------
// End-to-end: a SimIo client handshakes, sends an HTTP/3 GET, and reads the
// response. The client is the same packet-level glue as the connection tests,
// but driven by UDP completions instead of synchronous calls.
// ---------------------------------------------------------------------------

fn installClientKeys(
    crypto: *zquic.PacketCrypto,
    level: usize,
    secrets: qtls.SecretSet,
) !void {
    const local = try zquic.Tls13KeySchedule.deriveQuicPacketKeys(&secrets.local.?);
    const remote = try zquic.Tls13KeySchedule.deriveQuicPacketKeys(&secrets.remote.?);
    switch (level) {
        2 => try crypto.installRfc9001HandshakeKeys(&local, &remote),
        3 => try crypto.installRfc9001ApplicationKeys(&local, &remote),
        else => return error.UnsupportedLevel,
    }
}

fn buildE2ERequest(out: []u8, allocator: std.mem.Allocator) ![]const u8 {
    const fields = [_]qpack.HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "spike.zgix.test" },
        .{ .name = ":path", .value = "/e2e" },
        .{ .name = "user-agent", .value = "zgix-e2e" },
    };
    const block = try qpack.encode(allocator, &fields);
    defer allocator.free(block);

    var used: usize = 0;
    used += try request_stream.writeVarint(out[used..], request_stream.frame_type_headers);
    used += try request_stream.writeVarint(out[used..], block.len);
    if (block.len > out.len - used) return error.OutputTooSmall;
    @memcpy(out[used..][0..block.len], block);
    used += block.len;

    used += try request_stream.writeVarint(out[used..], request_stream.frame_type_data);
    used += try request_stream.writeVarint(out[used..], "ping".len);
    if ("ping".len > out.len - used) return error.OutputTooSmall;
    @memcpy(out[used..][0.."ping".len], "ping");
    used += "ping".len;
    return out[0..used];
}

const E2EClient = struct {
    base: TestClient,
    sim: *Io.SimIo,
    allocator: std.mem.Allocator,
    socket: Io.SimIo.UdpSocket,
    server_addr: std.Io.net.IpAddress,

    server_scid: [8]u8 = undefined,
    server_scid_len: u8 = 0,
    largest_pn: [3]?u64 = .{ null, null, null },

    recv_buffer: [connection.max_datagram_bytes]u8 = undefined,
    recv_completion: Io.SimIo.UdpCompletion = undefined,

    send_buffers: [24][connection.max_datagram_bytes]u8 = undefined,
    send_completions: [24]Io.SimIo.UdpCompletion = undefined,
    send_count: usize = 0,

    handshake_keys: bool = false,
    app_keys: bool = false,
    finished_sent: bool = false,
    request_sent: bool = false,
    request_timer: Io.SimIo.Completion = undefined,
    /// The aioquic shape opens three long-lived client uni streams (its
    /// control stream and the QPACK pair) before any request; a test sets
    /// this to have the client do the same.
    send_uni: bool = false,
    uni_sent: bool = false,
    /// Sequential requests: `requests_total` GETs, one per client-bidi
    /// stream, each answered before the next opens. The single-request
    /// tests leave this at one.
    requests_total: usize = 1,
    requests_done: usize = 0,
    /// The client-bidi stream the current request rode in on, and so the
    /// only stream whose bytes count as its response.
    request_stream: u64 = 0,
    /// The success path stops the loop, which most tests want (they assert
    /// straight after `run`). A test that keeps running — the idle-sweep
    /// oracle waits past the session's deadline — turns this off and ends
    /// the run with its own backstop timer instead.
    stop_on_done: bool = true,

    /// A Handshake datagram can overtake the Initial reply in one SimIo
    /// readiness batch. Keep it until the handshake keys exist.
    pending_handshake: [connection.max_datagram_bytes]u8 = undefined,
    pending_handshake_len: usize = 0,
    pending_handshake_valid: bool = false,

    response: [2048]u8 = undefined,
    response_len: usize = 0,
    response_fin: bool = false,
    body: [16]u8 = undefined,
    body_len: usize = 0,
    status_ok: bool = false,
    done: bool = false,
    failed: bool = false,

    fn initInPlace(
        self: *E2EClient,
        sim: *Io.SimIo,
        allocator: std.mem.Allocator,
        socket: Io.SimIo.UdpSocket,
        server_addr: std.Io.net.IpAddress,
    ) !void {
        self.sim = sim;
        self.allocator = allocator;
        self.socket = socket;
        self.server_addr = server_addr;
        self.server_scid_len = 0;
        self.largest_pn = .{ null, null, null };
        self.send_count = 0;
        self.handshake_keys = false;
        self.app_keys = false;
        self.finished_sent = false;
        self.request_sent = false;
        self.send_uni = false;
        self.uni_sent = false;
        self.requests_total = 1;
        self.requests_done = 0;
        self.request_stream = 0;
        self.pending_handshake_len = 0;
        self.pending_handshake_valid = false;
        self.response_len = 0;
        self.response_fin = false;
        self.body_len = 0;
        self.status_ok = false;
        self.done = false;
        self.failed = false;
        self.recv_completion = .{};
        self.request_timer = .{};
        for (&self.send_completions) |*completion| completion.* = .{};
        try self.base.initInPlace(allocator);
    }

    fn deinit(self: *E2EClient) void {
        self.base.deinit();
    }

    fn start(self: *E2EClient) !void {
        self.armRecv();
        var wire: [4096]u8 = undefined;
        const packet = try self.base.initial(&wire);
        defer self.allocator.free(packet);
        try self.sendBytes(packet);
    }

    fn armRecv(self: *E2EClient) void {
        self.recv_completion = .{};
        self.sim.udpRecv(
            self.socket,
            &self.recv_buffer,
            &self.recv_completion,
            E2EClient,
            self,
            E2EClient.onRecv,
        );
    }

    fn sendBytes(self: *E2EClient, bytes: []const u8) !void {
        if (bytes.len > connection.max_datagram_bytes) return error.DatagramTooLarge;
        if (self.send_count == self.send_buffers.len) return error.SendRingFull;
        const index = self.send_count;
        @memcpy(self.send_buffers[index][0..bytes.len], bytes);
        self.send_completions[index] = .{};
        self.sim.udpSend(
            self.socket,
            self.server_addr,
            self.send_buffers[index][0..bytes.len],
            &self.send_completions[index],
            E2EClient,
            self,
            E2EClient.onSend,
        );
        self.send_count += 1;
    }

    fn onSend(_: *E2EClient, result: Io.SendError!u32) void {
        _ = result catch 0;
    }

    fn onRecv(self: *E2EClient, result: Io.RecvError!Io.UdpDatagram) void {
        const datagram = result catch {
            self.fail();
            return;
        };
        const len: usize = @min(@as(usize, datagram.len), self.recv_buffer.len);
        self.handleDatagram(self.recv_buffer[0..len]) catch {
            self.fail();
            return;
        };
        if (!self.done) self.armRecv();
    }

    fn handleDatagram(self: *E2EClient, bytes: []const u8) !void {
        const header = try Packet.PacketHeader.parse(bytes, self.allocator);
        try self.learnServerScid(header);
        if (header.packet_type == .handshake and !self.handshake_keys) {
            return self.stashHandshake(bytes);
        }

        const slot: usize = switch (header.packet_type) {
            .initial => 0,
            .handshake => 1,
            .one_rtt => 2,
            else => return error.UnexpectedPacket,
        };
        var packet = try self.base.crypto.processProtectedRawPacket(bytes, self.largest_pn[slot]);
        defer packet.deinit(self.allocator);
        self.largest_pn[slot] = packet.packet_number;
        try self.feedFrames(tls_levels[slot], packet.payload);
        try self.base.tls.drive();
        try self.base.tls.drive();
        try self.installSecrets();

        if (self.pending_handshake_valid and self.handshake_keys) {
            const len = self.pending_handshake_len;
            self.pending_handshake_valid = false;
            try self.handleDatagram(self.pending_handshake[0..len]);
            return;
        }
        if (self.handshake_keys and !self.finished_sent) try self.sendFinished();
        if (self.response_fin and !self.done) try self.completeResponse();
    }

    fn learnServerScid(self: *E2EClient, header: Packet.PacketHeader) !void {
        if (header.packet_type != .initial and header.packet_type != .handshake) return;
        const scid = header.src_conn_id orelse return;
        const len = @min(scid.bytes().len, self.server_scid.len);
        @memcpy(self.server_scid[0..len], scid.bytes()[0..len]);
        self.server_scid_len = @intCast(len);
    }

    fn stashHandshake(self: *E2EClient, bytes: []const u8) !void {
        if (self.pending_handshake_valid) return error.TooManyPendingHandshakes;
        if (bytes.len > self.pending_handshake.len) return error.DatagramTooLarge;
        @memcpy(self.pending_handshake[0..bytes.len], bytes);
        self.pending_handshake_len = bytes.len;
        self.pending_handshake_valid = true;
    }

    fn feedFrames(self: *E2EClient, level: usize, payload: []const u8) !void {
        var reader: std.Io.Reader = .fixed(payload);
        while (reader.seek < reader.end) {
            var frame = try QuicFrames.Frame.parse(&reader, self.allocator);
            defer frame.deinit(self.allocator);
            switch (frame) {
                .crypto => |crypto| try self.base.tls.pushCrypto(level, crypto.data),
                .stream,
                .stream_fin,
                .stream_len,
                .stream_len_fin,
                .stream_off,
                .stream_off_fin,
                .stream_off_len,
                .stream_off_len_fin,
                => |stream| try self.acceptStream(stream),
                else => {},
            }
        }
    }

    fn acceptStream(self: *E2EClient, stream: QuicFrames.StreamFrame) !void {
        // Server control/QPACK streams (3, 7, 11) are not the response,
        // and neither is a retransmitted frame of an answered request:
        // only the current request stream counts.
        if (stream.stream_id != self.request_stream) return;
        if (stream.data.len > self.response.len - self.response_len) return error.ResponseTooLarge;
        @memcpy(self.response[self.response_len..][0..stream.data.len], stream.data);
        self.response_len += stream.data.len;
        if (stream.fin) self.response_fin = true;
    }

    fn installSecrets(self: *E2EClient) !void {
        if (!self.handshake_keys) {
            const secrets = self.base.tls.takeSecrets(2);
            if (secrets.complete()) {
                try installClientKeys(&self.base.crypto, 2, secrets);
                self.handshake_keys = true;
            }
        }
        // qtls clears both halves on read; wait until the client has both.
        if (!self.app_keys and self.base.tls.isFinished()) {
            const secrets = self.base.tls.takeSecrets(3);
            if (secrets.complete()) {
                try installClientKeys(&self.base.crypto, 3, secrets);
                self.app_keys = true;
            }
        }
    }

    fn sendFinished(self: *E2EClient) !void {
        const out = self.base.tls.takeOut(2);
        if (out.len == 0) return;
        defer self.base.tls.clearOut(2);
        if (self.server_scid_len == 0) return error.MissingServerScid;

        var wire: [512]u8 = undefined;
        var writer: std.Io.Writer = .fixed(&wire);
        const frame = QuicFrames.Frame{ .crypto = .init(0, out) };
        try frame.serialize(&writer);
        const packet = try self.base.crypto.createProtectedRawPacket(
            .handshake,
            .handshake,
            self.serverScid(),
            &self.base.scid,
            wire[0..writer.end],
        );
        defer self.allocator.free(packet);
        try self.sendBytes(packet);
        self.finished_sent = true;

        // SimIo may deliver two sends from one batch in either order, so the
        // request must not race the Finished. Let a timer tick separate them.
        self.request_timer = .{};
        self.sim.timerStart(
            &self.request_timer,
            1 * std.time.ns_per_ms,
            E2EClient,
            self,
            E2EClient.onRequestTimer,
        );
    }

    fn onRequestTimer(self: *E2EClient, result: Io.TimerError!void) void {
        _ = result catch {
            self.fail();
            return;
        };
        if (self.request_sent or !self.app_keys or !self.finished_sent) return;
        if (self.send_uni and !self.uni_sent) {
            self.sendUniStreams() catch {
                self.fail();
                return;
            };
        }
        self.sendRequest() catch self.fail();
    }

    /// The aioquic shape: client control stream (type 0) and the QPACK
    /// decoder/encoder streams (types 1 and 3), none with FIN — they live
    /// for the connection, which is exactly what makes them occupy
    /// stream-table slots on the server for its whole life.
    fn sendUniStreams(self: *E2EClient) !void {
        const types = [_]u8{ 0x00, 0x01, 0x03 };
        for (types, 0..) |stream_type, index| {
            const stream_id: u64 = 2 + index * 4;
            var wire: [64]u8 = undefined;
            var writer: std.Io.Writer = .fixed(&wire);
            const frame = QuicFrames.Frame{
                .stream = .init(stream_id, 0, &[_]u8{stream_type}, false, false, true),
            };
            try frame.serialize(&writer);
            const packet = try self.base.crypto.createProtectedRawPacket(
                .application,
                .one_rtt,
                self.serverScid(),
                &self.base.scid,
                wire[0..writer.end],
            );
            defer self.allocator.free(packet);
            try self.sendBytes(packet);
        }
        self.uni_sent = true;
    }

    fn sendRequest(self: *E2EClient) !void {
        var h3: [512]u8 = undefined;
        const request = try buildE2ERequest(&h3, self.allocator);
        var wire: [640]u8 = undefined;
        var writer: std.Io.Writer = .fixed(&wire);
        const frame = QuicFrames.Frame{
            .stream = .init(self.request_stream, 0, request, true, false, true),
        };
        try frame.serialize(&writer);
        const packet = try self.base.crypto.createProtectedRawPacket(
            .application,
            .one_rtt,
            self.serverScid(),
            &self.base.scid,
            wire[0..writer.end],
        );
        defer self.allocator.free(packet);
        try self.sendBytes(packet);
        self.request_sent = true;
    }

    fn completeResponse(self: *E2EClient) !void {
        var offset: usize = 0;
        var status_seen = false;
        var body_seen = false;
        while (offset < self.response_len) {
            const type_v = try request_stream.readVarint(self.response[offset..self.response_len]);
            offset += type_v.len;
            const length_v = try request_stream.readVarint(self.response[offset..self.response_len]);
            offset += length_v.len;
            const payload_len: usize = @intCast(length_v.value);
            if (payload_len > self.response_len - offset) return error.Truncated;
            const payload = self.response[offset..][0..payload_len];
            offset += payload_len;

            switch (type_v.value) {
                request_stream.frame_type_headers => {
                    var decoded = try qpack.decode(self.allocator, payload);
                    defer decoded.deinit();
                    for (decoded.fields) |field| {
                        if (!std.mem.eql(u8, field.name, ":status")) continue;
                        if (!std.mem.eql(u8, field.value, "200")) return error.BadStatus;
                        status_seen = true;
                    }
                },
                request_stream.frame_type_data => {
                    if (payload.len > self.body.len) return error.BodyTooLarge;
                    @memcpy(self.body[0..payload.len], payload);
                    self.body_len = payload.len;
                    body_seen = true;
                },
                else => {},
            }
        }

        if (!status_seen or !body_seen) return error.IncompleteResponse;
        self.status_ok = status_seen;
        self.requests_done += 1;
        if (self.requests_done < self.requests_total) {
            // The answered stream's slot is long freed (the response FIN
            // completed the fin/fin pair), so the next client-bidi stream
            // opens against a table that never holds more than the
            // long-lived streams plus this one exchange.
            self.request_stream += 4;
            self.response_len = 0;
            self.response_fin = false;
            try self.sendRequest();
            return;
        }
        self.done = true;
        if (self.stop_on_done) self.sim.stop();
    }

    fn serverScid(self: *const E2EClient) []const u8 {
        return self.server_scid[0..self.server_scid_len];
    }

    fn fail(self: *E2EClient) void {
        self.failed = true;
        self.done = true;
        self.sim.stop();
    }
};

test "h3 listener: SimIo end-to-end HTTP/3 GET and response" {
    const SimIo = Io.SimIo;
    const TestListener = Listener(SimIo);

    try connection.Connection.configureServer(fixtures.cert_pem, fixtures.key_pem);

    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var sim_io: SimIo = undefined;
    try sim_io.init(arena, .{ .seed = 23 });

    const loopback = try std.Io.net.IpAddress.parseLiteral("127.0.0.1:0");
    var listener: TestListener = undefined;
    try listener.initInPlace(&sim_io, arena, loopback, .{
        .cert_pem = fixtures.cert_pem,
        .key_pem = fixtures.key_pem,
    }, 2);
    defer listener.deinit(&sim_io);

    const AppHandler = struct {
        method: [8]u8 = undefined,
        method_len: usize = 0,
        path: [16]u8 = undefined,
        path_len: usize = 0,
        body: [16]u8 = undefined,
        body_len: usize = 0,
        calls: usize = 0,

        fn interface(self: *@This()) session.RequestHandler {
            return .{ .ctx = self, .onRequest = onRequest, .onBodyChunk = onBodyChunk };
        }

        /// Body pieces accumulate here: `request.body` is always empty
        /// under the streaming contract, and this handler answers inside
        /// `onRequest`, so the chunks must be collected on the side.
        fn onBodyChunk(
            ctx: *anyopaque,
            _: *session.H3Session,
            _: u64,
            chunk: []const u8,
            _: bool,
        ) anyerror!void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            const take = @min(chunk.len, self.body.len - self.body_len);
            @memcpy(self.body[self.body_len..][0..take], chunk[0..take]);
            self.body_len += take;
        }

        fn onRequest(
            ctx: *anyopaque,
            h3: *session.H3Session,
            stream_id: u64,
            request: *const request_stream.Request,
        ) void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            self.calls += 1;
            self.method_len = @min(request.method.len, self.method.len);
            @memcpy(self.method[0..self.method_len], request.method[0..self.method_len]);
            self.path_len = @min(request.path.len, self.path.len);
            @memcpy(self.path[0..self.path_len], request.path[0..self.path_len]);
            self.body_len = @min(request.body.len, self.body.len);
            @memcpy(self.body[0..self.body_len], request.body[0..self.body_len]);
            h3.sendResponse(
                stream_id,
                200,
                &.{.{ .name = "content-type", .value = "text/plain" }},
                "pong",
                true,
            ) catch {};
        }
    };
    var app = AppHandler{};
    listener.setRequestHandler(app.interface());
    // The teardown registration the runtime installs beside the handler:
    // the idle sweep's reap must call it exactly once for the session,
    // right before the session deinits.
    const TeardownSpy = struct {
        calls: usize = 0,
        fn forget(ctx: *anyopaque, h3: *session.H3Session) void {
            _ = h3;
            const spy: *@This() = @ptrCast(@alignCast(ctx));
            spy.calls += 1;
        }
    };
    var spy = TeardownSpy{};
    listener.setExchangeTeardown(.{ .ctx = &spy, .forget = TeardownSpy.forget });
    listener.start();

    // The listener's receive completion stays armed after the exchange, so
    // without a timer `run` would never find a quiescent state. The client
    // stops the loop on success; this is the failure backstop. 45 s is also
    // the idle-sweep oracle: the session's idle deadline is 30 s from its
    // start and the 100 ms tick must reap it with no further datagrams, so
    // a backstop that fires with the slot still held fails below on
    // `connectionCount()` — the pre-timer behaviour reaped only on inbound
    // packets, and a client that simply went away held its slot forever.
    const StopTimer = struct {
        sim: *SimIo,

        fn onFire(self: *@This(), result: Io.TimerError!void) void {
            _ = result catch {};
            self.sim.stop();
        }
    };
    var stop = StopTimer{ .sim = &sim_io };
    var stop_completion: SimIo.Completion = .{};
    sim_io.timerStart(
        &stop_completion,
        45 * std.time.ns_per_s,
        StopTimer,
        &stop,
        StopTimer.onFire,
    );

    const client_socket = try sim_io.udpBind(&.{ .ip = loopback });
    var client: E2EClient = undefined;
    try client.initInPlace(
        &sim_io,
        std.testing.allocator,
        client_socket,
        listener.boundAddress(),
    );
    defer client.deinit();
    try client.start();
    // The idle-sweep oracle below waits past the session's 30 s deadline,
    // so the client must not stop the loop when its request succeeds —
    // the 45 s backstop is the only thing that ends this run.
    client.stop_on_done = false;

    try sim_io.run();

    try std.testing.expect(!client.failed);
    try std.testing.expect(client.done);
    try std.testing.expectEqual(@as(usize, 1), app.calls);
    try std.testing.expectEqualStrings("GET", app.method[0..app.method_len]);
    try std.testing.expectEqualStrings("/e2e", app.path[0..app.path_len]);
    try std.testing.expectEqualStrings("ping", app.body[0..app.body_len]);
    try std.testing.expect(client.status_ok);
    try std.testing.expectEqualStrings("pong", client.body[0..client.body_len]);
    // The exchange finished long before the backstop, and the idle sweep
    // the tick drives must have reaped the session by now: no inbound
    // packet arrived after the response, so reap-on-recv alone would still
    // hold the slot. The reap is also the teardown wiring's moment: the
    // registration fired exactly once, with the dying session.
    try std.testing.expectEqual(@as(usize, 0), listener.connectionCount());
    try std.testing.expectEqual(@as(usize, 1), spy.calls);
}

// ---------------------------------------------------------------------------
// MAX_STREAMS wiring: the session hands a freed request slot to the
// connection as one more client-bidi stream credit, and the connection
// seals a MAX_STREAMS frame carrying it. The connection and session are
// wired the way `openSlot` wires a slot — the same pointers, installed in
// the same order — but driven synchronously so the wire bytes can be
// asserted directly.
// ---------------------------------------------------------------------------

fn sendViaConn(ctx: *anyopaque, stream_id: u64, data: []const u8, fin: bool) anyerror!void {
    const conn: *connection.Connection = @ptrCast(@alignCast(ctx));
    try conn.sendStream(stream_id, data, fin);
}

test "h3 listener: a finished request raises MAX_STREAMS through the session wiring" {
    try connection.Connection.configureServer(fixtures.cert_pem, fixtures.key_pem);
    const allocator = std.testing.allocator;

    const peer = try std.Io.net.IpAddress.parseLiteral("127.0.0.1:4433");
    var server: connection.Connection = undefined;
    try server.initInPlace(allocator, peer, .{
        .cert_pem = fixtures.cert_pem,
        .key_pem = fixtures.key_pem,
    });
    defer server.deinit();

    const Responder = struct {
        calls: usize = 0,
        fn interface(self: *@This()) session.RequestHandler {
            return .{ .ctx = self, .onRequest = onRequest };
        }
        fn onRequest(
            ctx: *anyopaque,
            h3: *session.H3Session,
            stream_id: u64,
            request: *const request_stream.Request,
        ) void {
            _ = request;
            const self: *@This() = @ptrCast(@alignCast(ctx));
            self.calls += 1;
            h3.sendResponse(stream_id, 200, &.{}, "pong", true) catch {};
        }
    };
    var responder = Responder{};

    var h3: session.H3Session = undefined;
    try h3.initInPlace(
        allocator,
        .{ .ctx = &server, .send = sendViaConn },
        responder.interface(),
    );
    defer h3.deinit();
    // Exactly what `openSlot` installs after both halves of the slot exist.
    h3.conn = &server;
    server.setStreamHandler(h3.streamHandler());

    var client: TestClient = undefined;
    try client.initInPlace(allocator);
    defer client.deinit();

    var hello_wire: [4096]u8 = undefined;
    const initial = try client.initial(&hello_wire);
    defer allocator.free(initial);
    try server.onDatagram(initial, 1);
    while (server.takeDatagram()) |datagram| {
        if (try client.accept(allocator, datagram)) break;
    }
    try std.testing.expect(client.tls.isFinished());

    var fin_wire: [4096]u8 = undefined;
    const finished = try client.finishedDatagram(&fin_wire, server.serverScid());
    defer allocator.free(finished);
    try server.onDatagram(finished, 2);
    try std.testing.expect(server.isEstablished());

    // One request on stream 0. The synchronous responder answers and frees
    // the slot, which must surface as a MAX_STREAMS frame on the wire:
    // the response packet rides first, the credit bump right behind it.
    var h3_wire: [512]u8 = undefined;
    const request = try buildE2ERequest(&h3_wire, allocator);
    var req_pkt: [640]u8 = undefined;
    const req_datagram = try client.streamFrameDatagram(&req_pkt, 0, request, true, server.serverScid());
    defer allocator.free(req_datagram);
    try server.onDatagram(req_datagram, 3);

    try std.testing.expectEqual(@as(usize, 1), responder.calls);
    var saw_response = false;
    var saw_max_streams = false;
    while (server.takeDatagram()) |datagram| {
        var packet = try client.crypto.processProtectedRawPacket(datagram, client.largest_pn[2]);
        defer packet.deinit(allocator);
        client.largest_pn[2] = packet.packet_number;
        var reader: std.Io.Reader = .fixed(packet.payload);
        while (reader.seek < reader.end) {
            var frame = try QuicFrames.Frame.parse(&reader, allocator);
            defer frame.deinit(allocator);
            switch (frame) {
                .stream => |stream| {
                    if (stream.stream_id == 0 and std.mem.indexOf(u8, stream.data, "pong") != null) {
                        saw_response = true;
                    }
                },
                .max_streams_bidi => |max| {
                    // One slot freed, one credit returned: 8 → 9.
                    try std.testing.expectEqual(
                        @as(u64, constants.h3_request_streams_max + 1),
                        max.maximum_streams,
                    );
                    saw_max_streams = true;
                },
                else => {},
            }
        }
    }
    try std.testing.expect(saw_response);
    try std.testing.expect(saw_max_streams);
}

test "h3 listener: abort returns the connection's stream slot" {
    try connection.Connection.configureServer(fixtures.cert_pem, fixtures.key_pem);
    const allocator = std.testing.allocator;

    const peer = try std.Io.net.IpAddress.parseLiteral("127.0.0.1:4433");
    var server: connection.Connection = undefined;
    try server.initInPlace(allocator, peer, .{
        .cert_pem = fixtures.cert_pem,
        .key_pem = fixtures.key_pem,
    });
    defer server.deinit();

    const Deferrer = struct {
        calls: usize = 0,
        fn interface(self: *@This()) session.RequestHandler {
            return .{ .ctx = self, .onRequest = onRequest, .onBodyChunk = onBodyChunk };
        }
        /// The deferred exchange consumes the upload so the stream stays
        /// alive: without an `onBodyChunk` the session answers a body the
        /// handler cannot consume by dropping the stream.
        fn onBodyChunk(
            _: *anyopaque,
            _: *session.H3Session,
            _: u64,
            _: []const u8,
            _: bool,
        ) anyerror!void {}
        fn onRequest(
            ctx: *anyopaque,
            h3: *session.H3Session,
            stream_id: u64,
            request: *const request_stream.Request,
        ) void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            self.calls += 1;
            _ = request;
            // Hold the entry past the callback, the way an outstanding
            // upstream exchange does.
            h3.deferRequest(stream_id);
        }
    };
    var deferrer = Deferrer{};

    var h3: session.H3Session = undefined;
    try h3.initInPlace(
        allocator,
        .{ .ctx = &server, .send = sendViaConn },
        deferrer.interface(),
    );
    defer h3.deinit();
    // Exactly what `openSlot` installs after both halves of the slot exist.
    h3.conn = &server;
    server.setStreamHandler(h3.streamHandler());

    var client: TestClient = undefined;
    try client.initInPlace(allocator);
    defer client.deinit();

    var hello_wire: [4096]u8 = undefined;
    const initial = try client.initial(&hello_wire);
    defer allocator.free(initial);
    try server.onDatagram(initial, 1);
    while (server.takeDatagram()) |datagram| {
        if (try client.accept(allocator, datagram)) break;
    }
    try std.testing.expect(client.tls.isFinished());

    var fin_wire: [4096]u8 = undefined;
    const finished = try client.finishedDatagram(&fin_wire, server.serverScid());
    defer allocator.free(finished);
    try server.onDatagram(finished, 2);
    try std.testing.expect(server.isEstablished());

    // One request on stream 0, deferred by the handler: the session entry
    // and the connection's stream slot are both held.
    var h3_wire: [512]u8 = undefined;
    const request = try buildE2ERequest(&h3_wire, allocator);
    var req_pkt: [640]u8 = undefined;
    const req_datagram = try client.streamFrameDatagram(&req_pkt, 0, request, true, server.serverScid());
    defer allocator.free(req_datagram);
    try server.onDatagram(req_datagram, 3);
    try std.testing.expectEqual(@as(usize, 1), deferrer.calls);
    try std.testing.expectEqual(@as(usize, 1), server.activeStreamCount());

    // No response FIN will ever come, so the abort must free the
    // connection slot itself — without this it would sit in the 16-entry
    // table until the connection died, one slot closer to the
    // error.TooManyStreams wall for every aborted request.
    h3.abort(0);
    try std.testing.expectEqual(@as(usize, 0), server.activeStreamCount());
    while (server.takeDatagram()) |_| {}

    // The freed slot serves the next request end to end: full fin/fin
    // exchange, entry released, stream credit raised.
    var req2_pkt: [640]u8 = undefined;
    const req2 = try client.streamFrameDatagram(&req2_pkt, 4, request, true, server.serverScid());
    defer allocator.free(req2);
    try server.onDatagram(req2, 4);
    try std.testing.expectEqual(@as(usize, 2), deferrer.calls);
    h3.sendResponse(4, 200, &.{}, "pong", true) catch return error.ResponseFailed;
    try std.testing.expectEqual(@as(usize, 0), server.activeStreamCount());
    while (server.takeDatagram()) |_| {}
}

test "h3 listener: abortStream resets a headed stream and releases its slot exactly once" {
    try connection.Connection.configureServer(fixtures.cert_pem, fixtures.key_pem);
    const allocator = std.testing.allocator;

    const peer = try std.Io.net.IpAddress.parseLiteral("127.0.0.1:4433");
    var server: connection.Connection = undefined;
    try server.initInPlace(allocator, peer, .{
        .cert_pem = fixtures.cert_pem,
        .key_pem = fixtures.key_pem,
    });
    defer server.deinit();

    const Deferrer = struct {
        calls: usize = 0,
        fn interface(self: *@This()) session.RequestHandler {
            return .{ .ctx = self, .onRequest = onRequest, .onBodyChunk = onBodyChunk };
        }
        /// Consume the upload so the deferred stream stays alive (see the
        /// twin in the abort-slot test above).
        fn onBodyChunk(
            _: *anyopaque,
            _: *session.H3Session,
            _: u64,
            _: []const u8,
            _: bool,
        ) anyerror!void {}
        fn onRequest(
            ctx: *anyopaque,
            h3: *session.H3Session,
            stream_id: u64,
            request: *const request_stream.Request,
        ) void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            self.calls += 1;
            _ = request;
            // Hold the entry past the callback, the way an outstanding
            // upstream exchange does.
            h3.deferRequest(stream_id);
        }
    };
    var deferrer = Deferrer{};

    var h3: session.H3Session = undefined;
    try h3.initInPlace(
        allocator,
        .{ .ctx = &server, .send = sendViaConn },
        deferrer.interface(),
    );
    defer h3.deinit();
    // Exactly what `openSlot` installs after both halves of the slot exist.
    h3.conn = &server;
    server.setStreamHandler(h3.streamHandler());

    var client: TestClient = undefined;
    try client.initInPlace(allocator);
    defer client.deinit();

    var hello_wire: [4096]u8 = undefined;
    const initial = try client.initial(&hello_wire);
    defer allocator.free(initial);
    try server.onDatagram(initial, 1);
    while (server.takeDatagram()) |datagram| {
        if (try client.accept(allocator, datagram)) break;
    }
    try std.testing.expect(client.tls.isFinished());

    var fin_wire: [4096]u8 = undefined;
    const finished = try client.finishedDatagram(&fin_wire, server.serverScid());
    defer allocator.free(finished);
    try server.onDatagram(finished, 2);
    try std.testing.expect(server.isEstablished());

    // One request on stream 0, deferred; a split response starts — head
    // plus one data chunk — and the exchange stalls mid-body.
    var h3_wire: [512]u8 = undefined;
    const request = try buildE2ERequest(&h3_wire, allocator);
    var req_pkt: [640]u8 = undefined;
    const req_datagram = try client.streamFrameDatagram(&req_pkt, 0, request, true, server.serverScid());
    defer allocator.free(req_datagram);
    try server.onDatagram(req_datagram, 3);
    try std.testing.expectEqual(@as(usize, 1), deferrer.calls);

    h3.sendResponseHead(0, 200, &.{}) catch return error.ResponseFailed;
    _ = h3.sendData(0, "partial", false) catch return error.ResponseFailed;
    // The first queued datagram is the HEADERS send (the ACK and the
    // flow-control top-ups ride in it as their own frames); its STREAM
    // frame payload, plus the 9 framed data bytes, is the stream's send
    // offset — the final size the reset must name.
    const head_dg = server.takeDatagram() orelse return error.MissingHead;
    var head_in = try client.crypto.processProtectedRawPacket(head_dg, client.largest_pn[2]);
    defer head_in.deinit(allocator);
    client.largest_pn[2] = head_in.packet_number;
    var head_len: u64 = 0;
    var head_reader: std.Io.Reader = .fixed(head_in.payload);
    while (head_reader.seek < head_reader.end) {
        var frame = try QuicFrames.Frame.parse(&head_reader, allocator);
        defer frame.deinit(allocator);
        switch (frame) {
            .stream => |stream| head_len += stream.data.len,
            else => {},
        }
    }
    try std.testing.expect(head_len > 0);
    while (server.takeDatagram()) |_| {}
    const send_offset = head_len + 9;
    try std.testing.expect(send_offset > 9);

    // The abort: RESET_STREAM names the send offset as the final size, the
    // connection's stream slot frees immediately, and the session entry
    // frees exactly once — one MAX_STREAMS credit, not two.
    const advertised_before = server.advertised_bidi_streams;
    h3.abortStream(0);
    try std.testing.expectEqual(@as(usize, 0), server.activeStreamCount());
    try std.testing.expectEqual(advertised_before + 1, server.advertised_bidi_streams);
    h3.abortStream(0); // entry gone, slot gone: a true no-op
    try std.testing.expectEqual(advertised_before + 1, server.advertised_bidi_streams);

    // The RESET_STREAM decodes on the wire with H3_REQUEST_CANCELLED and
    // the captured send offset as the final size.
    const reset_dg = server.takeDatagram() orelse return error.MissingReset;
    var reset_in = try client.crypto.processProtectedRawPacket(reset_dg, client.largest_pn[2]);
    defer reset_in.deinit(allocator);
    client.largest_pn[2] = reset_in.packet_number;
    var saw_reset = false;
    var reset_reader: std.Io.Reader = .fixed(reset_in.payload);
    while (reset_reader.seek < reset_reader.end) {
        var frame = try QuicFrames.Frame.parse(&reset_reader, allocator);
        defer frame.deinit(allocator);
        switch (frame) {
            .reset_stream => |reset| {
                try std.testing.expectEqual(@as(u64, 0), reset.stream_id);
                try std.testing.expectEqual(
                    connection.h3_request_cancelled,
                    reset.application_error_code,
                );
                try std.testing.expectEqual(send_offset, reset.final_size);
                saw_reset = true;
            },
            else => {},
        }
    }
    try std.testing.expect(saw_reset);

    // The released entry's stream credit rides the next datagram: exactly
    // one raise, matching the single release.
    const credit_dg = server.takeDatagram() orelse return error.MissingCredit;
    var credit_in = try client.crypto.processProtectedRawPacket(credit_dg, client.largest_pn[2]);
    defer credit_in.deinit(allocator);
    client.largest_pn[2] = credit_in.packet_number;
    var saw_credit = false;
    var credit_reader: std.Io.Reader = .fixed(credit_in.payload);
    while (credit_reader.seek < credit_reader.end) {
        var frame = try QuicFrames.Frame.parse(&credit_reader, allocator);
        defer frame.deinit(allocator);
        switch (frame) {
            .max_streams_bidi => |max| {
                try std.testing.expectEqual(advertised_before + 1, max.maximum_streams);
                saw_credit = true;
            },
            else => {},
        }
    }
    try std.testing.expect(saw_credit);
    try std.testing.expect(server.takeDatagram() == null);

    // The freed slot serves a fresh exchange end to end.
    var req2_pkt: [640]u8 = undefined;
    const req2 = try client.streamFrameDatagram(&req2_pkt, 4, request, true, server.serverScid());
    defer allocator.free(req2);
    try server.onDatagram(req2, 4);
    try std.testing.expectEqual(@as(usize, 2), deferrer.calls);
    h3.sendResponse(4, 200, &.{}, "pong", true) catch return error.ResponseFailed;
    try std.testing.expectEqual(@as(usize, 0), server.activeStreamCount());
    while (server.takeDatagram()) |_| {}
}

test "h3 listener: one connection serves twelve sequential requests" {
    const SimIo = Io.SimIo;
    const TestListener = Listener(SimIo);

    try connection.Connection.configureServer(fixtures.cert_pem, fixtures.key_pem);

    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var sim_io: SimIo = undefined;
    try sim_io.init(arena, .{ .seed = 41 });

    const loopback = try std.Io.net.IpAddress.parseLiteral("127.0.0.1:0");
    var listener: TestListener = undefined;
    try listener.initInPlace(&sim_io, arena, loopback, .{
        .cert_pem = fixtures.cert_pem,
        .key_pem = fixtures.key_pem,
    }, 2);
    defer listener.deinit(&sim_io);

    const AppHandler = struct {
        calls: usize = 0,
        fn interface(self: *@This()) session.RequestHandler {
            return .{ .ctx = self, .onRequest = onRequest };
        }
        fn onRequest(
            ctx: *anyopaque,
            h3: *session.H3Session,
            stream_id: u64,
            request: *const request_stream.Request,
        ) void {
            _ = request;
            const self: *@This() = @ptrCast(@alignCast(ctx));
            self.calls += 1;
            h3.sendResponse(stream_id, 200, &.{}, "pong", true) catch {};
        }
    };
    var app = AppHandler{};
    listener.setRequestHandler(app.interface());
    listener.start();

    // Failure backstop: the exchange runs in milliseconds of simulated
    // time; if a request hangs (the pre-fix behaviour at the eleventh),
    // the backstop ends the run and the assertions below fail.
    const StopTimer = struct {
        sim: *SimIo,

        fn onFire(self: *@This(), result: Io.TimerError!void) void {
            _ = result catch {};
            self.sim.stop();
        }
    };
    var stop = StopTimer{ .sim = &sim_io };
    var stop_completion: SimIo.Completion = .{};
    sim_io.timerStart(
        &stop_completion,
        45 * std.time.ns_per_s,
        StopTimer,
        &stop,
        StopTimer.onFire,
    );

    const client_socket = try sim_io.udpBind(&.{ .ip = loopback });
    var client: E2EClient = undefined;
    try client.initInPlace(
        &sim_io,
        std.testing.allocator,
        client_socket,
        listener.boundAddress(),
    );
    defer client.deinit();
    // The aioquic shape: three long-lived client uni streams (control and
    // the QPACK pair) hold table slots for the connection's life, and
    // their server-side twins (3, 7, 11) hold three more. The table has
    // 16 slots; without fin/fin release the six permanent streams plus
    // the never-freed request slots fill it at the tenth request, and the
    // eleventh dies with error.TooManyStreams. Release keeps the peak at
    // seven, so all twelve requests are served on the one connection.
    client.send_uni = true;
    client.requests_total = 12;
    try client.start();

    try sim_io.run();

    try std.testing.expect(!client.failed);
    try std.testing.expect(client.done);
    try std.testing.expectEqual(@as(usize, 12), app.calls);
    try std.testing.expectEqual(@as(usize, 12), client.requests_done);
    try std.testing.expect(client.status_ok);
    try std.testing.expectEqualStrings("pong", client.body[0..client.body_len]);
}

test "h3 listener: setWindowNotify wires open and future slots and the tick drives it" {
    const SimIo = Io.SimIo;
    const TestListener = Listener(SimIo);

    try connection.Connection.configureServer(fixtures.cert_pem, fixtures.key_pem);

    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var sim_io: SimIo = undefined;
    try sim_io.init(arena, .{ .seed = 59 });

    const loopback = try std.Io.net.IpAddress.parseLiteral("127.0.0.1:0");
    var listener: TestListener = undefined;
    try listener.initInPlace(&sim_io, arena, loopback, .{
        .cert_pem = fixtures.cert_pem,
        .key_pem = fixtures.key_pem,
    }, 2);
    defer listener.deinit(&sim_io);

    const Counter = struct {
        calls: usize = 0,
        fn onOpen(ctx: *anyopaque) void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            self.calls += 1;
        }
    };
    var counter_a = Counter{};
    // Installed before any slot exists: the slot the handshake opens must
    // inherit it through `openSlot`.
    listener.setWindowNotify(.{ .ctx = &counter_a, .onOpen = Counter.onOpen });

    const AppHandler = struct {
        calls: usize = 0,
        fn interface(self: *@This()) session.RequestHandler {
            return .{ .ctx = self, .onRequest = onRequest };
        }
        fn onRequest(
            ctx: *anyopaque,
            h3: *session.H3Session,
            stream_id: u64,
            request: *const request_stream.Request,
        ) void {
            _ = request;
            const self: *@This() = @ptrCast(@alignCast(ctx));
            self.calls += 1;
            h3.sendResponse(stream_id, 200, &.{}, "pong", true) catch {};
        }
    };
    var app = AppHandler{};
    listener.setRequestHandler(app.interface());
    listener.start();

    // Backstop at 450 ms of simulated time: the request answers in
    // milliseconds, and the remaining hundred-millisecond sweeps are what
    // the counter measures.
    const StopTimer = struct {
        sim: *SimIo,

        fn onFire(self: *@This(), result: Io.TimerError!void) void {
            _ = result catch {};
            self.sim.stop();
        }
    };
    var stop = StopTimer{ .sim = &sim_io };
    var stop_completion: SimIo.Completion = .{};
    sim_io.timerStart(
        &stop_completion,
        450 * std.time.ns_per_ms,
        StopTimer,
        &stop,
        StopTimer.onFire,
    );

    const client_socket = try sim_io.udpBind(&.{ .ip = loopback });
    var client: E2EClient = undefined;
    try client.initInPlace(
        &sim_io,
        std.testing.allocator,
        client_socket,
        listener.boundAddress(),
    );
    defer client.deinit();
    // The run ends on the backstop, not the response, so the ticks after
    // the exchange count too.
    client.stop_on_done = false;
    try client.start();

    try sim_io.run();

    try std.testing.expect(!client.failed);
    try std.testing.expect(client.done);
    try std.testing.expectEqual(@as(usize, 1), app.calls);
    // With no window frames inbound, the counter grows only because each
    // 100 ms tick re-issues the hook on the active connection.
    try std.testing.expect(counter_a.calls >= 3);

    // Exactly one slot stayed active (idle reaping is 30 s away), and it
    // carries the notify installed before it opened.
    var active: usize = 0;
    for (listener.slots) |*slot| {
        if (!slot.active) continue;
        active += 1;
        const notify = slot.conn.window_notify orelse return error.MissingNotify;
        try std.testing.expectEqual(@as(*anyopaque, @ptrCast(&counter_a)), notify.ctx);
    }
    try std.testing.expectEqual(@as(usize, 1), active);

    // Re-targeting applies to the open slot immediately — no tick needed.
    var counter_b = Counter{};
    listener.setWindowNotify(.{ .ctx = &counter_b, .onOpen = Counter.onOpen });
    for (listener.slots) |*slot| {
        if (!slot.active) continue;
        const notify = slot.conn.window_notify orelse return error.MissingNotify;
        try std.testing.expectEqual(@as(*anyopaque, @ptrCast(&counter_b)), notify.ctx);
    }
}
