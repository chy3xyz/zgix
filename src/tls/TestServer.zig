//! A minimal TLS origin for the SimIo scenarios that need one: it runs
//! zssl's server handshake, waits for one decrypted request, answers it
//! with a canned 200, and closes. Only the active health-check tests use
//! it (the upstream client lives in `UpstreamTls.zig`), so it is test
//! scaffolding rather than a serving path — the bytes still cross the
//! same `UpstreamTls` client the proxy uses, which is the fact those
//! tests are about.
//!
//! `zssl` is imported here rather than in the test file because the lint
//! boundary confines it to `src/tls/`.

const std = @import("std");

const zssl = @import("zssl");

const Io = @import("../io/io.zig");
const SimIo = @import("../io/SimIo.zig");

const Credentials = @import("Credentials.zig");

const assert = std.debug.assert;

pub const TestServer = @This();

pub const response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";

io: *SimIo = undefined,
listener: SimIo.Listener = undefined,
accept_completion: SimIo.Completion = .{},
listening: bool = false,
credentials: ?Credentials = null,
arena: std.mem.Allocator = undefined,
conns: [8]Conn = @splat(.{}),
accepted_count: u32 = 0,
/// Connections that completed the handshake, decrypted a request, and
/// staged the answer. A probe that stopped after the handshake leaves
/// this below `accepted_count`.
served: u32 = 0,

const Conn = struct {
    server: *TestServer = undefined,
    socket: SimIo.Socket = undefined,
    recv_completion: SimIo.Completion = .{},
    send_completion: SimIo.Completion = .{},
    closed: bool = false,
    /// The handshake and its record buffer, borrowed from this slot.
    tls: Tls = .{},

    const Tls = struct {
        records: zssl.record_buffer.RecordBuffer = undefined,
        wire: [zssl.record.wire_record_bytes_max]u8 = undefined,
        reassembly: [16 * 1024]u8 = undefined,
        flight: [zssl.Credentials.chain_bytes_max + 1024]u8 = undefined,
        out: [zssl.ServerHandshake.out_bytes_min]u8 = undefined,
        outbox: [2 * zssl.record.wire_record_bytes_max]u8 = undefined,
        outbox_len: u32 = 0,
        outbox_sent: u32 = 0,
        hs: zssl.ServerHandshake = undefined,
        replied: bool = false,
        done: bool = false,

        fn drainOutbox(tls: *Tls, bytes: []const u8) void {
            assert(tls.outbox_len + bytes.len <= tls.outbox.len);
            @memcpy(tls.outbox[tls.outbox_len..][0..bytes.len], bytes);
            tls.outbox_len += @intCast(bytes.len);
        }
    };
};

/// Load the fixture identity, listen, and accept. The caller supplies
/// both PEMs so the test file keeps owning its fixtures.
pub fn start(
    server: *TestServer,
    io: *SimIo,
    arena: std.mem.Allocator,
    address: std.Io.net.IpAddress,
    cert_pem: []const u8,
    key_pem: []const u8,
) !void {
    server.io = io;
    server.arena = arena;
    server.credentials = try Credentials.load(arena, cert_pem, key_pem, .{
        // Deterministic signatures keep a seeded run byte-exact.
        .deterministic_nonce = true,
    });
    server.listener = try io.listen(&.{ .ip = address }, null);
    server.listening = true;
    server.armAccept();
}

fn armAccept(server: *TestServer) void {
    server.io.accept(server.listener, &server.accept_completion, TestServer, server, onAccept);
}

fn onAccept(server: *TestServer, result: Io.AcceptError!SimIo.Socket) void {
    const socket = result catch |err| {
        assert(err == error.Canceled);
        return;
    };
    assert(server.accepted_count < server.conns.len);
    const conn = &server.conns[server.accepted_count];
    server.accepted_count += 1;
    conn.server = server;
    conn.socket = socket;
    conn.tls.records = .init(&conn.tls.wire);
    conn.tls.hs = zssl.ServerHandshake.init(&.{
        .credentials = &server.credentials.?.inner,
        // Fixed entropy: replayability is the point of the simulator,
        // and zssl draws none itself.
        .server_random = @splat(0x6d),
        .key_share_private = @as([47]u8, @splat(0x93)) ++ [_]u8{0x0e},
        .reassembly = &conn.tls.reassembly,
        .flight = &conn.tls.flight,
    });
    armRecv(conn);
    server.armAccept();
}

fn recvBuffer(conn: *Conn) []u8 {
    const writable = conn.tls.records.writable();
    assert(writable.len >= 1);
    return writable[0..@min(writable.len, zssl.record.wire_record_bytes_max)];
}

fn armRecv(conn: *Conn) void {
    conn.server.io.recv(
        conn.socket,
        recvBuffer(conn),
        &conn.recv_completion,
        Conn,
        conn,
        onRecv,
    );
}

fn onRecv(conn: *Conn, result: Io.RecvError!u32) void {
    const received = result catch {
        close(conn);
        return;
    };
    conn.tls.records.advance(received);
    // Bounded: each iteration consumes one complete record.
    while (conn.tls.records.next() catch {
        close(conn);
        return;
    }) |wire_record| {
        if (!handleRecord(conn, wire_record)) return;
    }
    afterEvents(conn);
}

fn handleRecord(conn: *Conn, wire_record: []const u8) bool {
    const tls = &conn.tls;
    var event = tls.hs.handleRecord(wire_record, &tls.out) catch {
        close(conn);
        return false;
    };
    while (event) |ready| {
        if (!handleEvent(conn, ready)) return false;
        event = tls.hs.drain(&tls.out) catch {
            close(conn);
            return false;
        };
    }
    return true;
}

fn handleEvent(conn: *Conn, event: zssl.ServerHandshake.Event) bool {
    const tls = &conn.tls;
    switch (event) {
        .send => |bytes| tls.drainOutbox(bytes),
        .connected => {},
        .application_data => {
            if (tls.replied) return true;
            const wire = tls.hs.sendApplicationData(response, &tls.out) catch {
                close(conn);
                return false;
            };
            tls.drainOutbox(wire);
            tls.replied = true;
            conn.server.served += 1;
        },
        .early_data, .closed => {},
    }
    return true;
}

fn afterEvents(conn: *Conn) void {
    const tls = &conn.tls;
    if (tls.outbox_sent < tls.outbox_len) {
        conn.server.io.send(
            conn.socket,
            tls.outbox[tls.outbox_sent..tls.outbox_len],
            &conn.send_completion,
            Conn,
            conn,
            onSend,
        );
        return;
    }
    // An answered probe asked for `Connection: close`; the FIN is the
    // end of the response as far as it is concerned.
    if (tls.replied) {
        close(conn);
        return;
    }
    armRecv(conn);
}

fn onSend(conn: *Conn, result: Io.SendError!u32) void {
    const sent = result catch {
        close(conn);
        return;
    };
    const tls = &conn.tls;
    tls.outbox_sent += sent;
    assert(tls.outbox_sent <= tls.outbox_len);
    if (tls.outbox_sent == tls.outbox_len) {
        tls.outbox_len = 0;
        tls.outbox_sent = 0;
    }
    afterEvents(conn);
}

fn close(conn: *Conn) void {
    conn.server.io.closeNow(conn.socket);
    conn.closed = true;
    if (!conn.tls.done) {
        conn.tls.hs.deinit();
        conn.tls.done = true;
    }
}

/// Close still-open connections so the socket-leak check is exact.
pub fn closeRemaining(server: *TestServer) void {
    for (server.conns[0..server.accepted_count]) |*conn| {
        if (!conn.closed) close(conn);
    }
    if (server.credentials) |*credentials| {
        credentials.deinit();
        server.credentials = null;
    }
}

pub fn stopListening(server: *TestServer) void {
    if (server.listening) {
        server.io.listenClose(server.listener);
        server.listening = false;
    }
}
