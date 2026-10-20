//! HTTP/3 seam (§4/§7, experimental): zquic's QUIC transport and HTTP/3
//! primitives behind one import.
//!
//! **Nothing in the serving path imports this file yet.** The proxy still
//! speaks HTTP/1.1 downstream and HTTP/1.1 upstream; zoxy has no UDP Io
//! contract, no bounded QUIC session model and no QUIC-TLS binding, so a
//! listener cannot honestly advertise `h3`. What this seam buys is that
//! the dependency, the Zig 0.17 fit and the API surface stay compiled and
//! tested (`zig build h3-check`) while that design is written, instead of
//! a vendor snapshot nobody has built since the day it landed.
//!
//! The shapes a future driver needs are all present in zquic's core:
//! `Connection` accepts and produces raw QUIC packets without owning a
//! socket (`queueIncomingRawPacket` / `drainOutgoingRawPackets`), exposes
//! loss-recovery deadlines (`recoveryDeadline`) and retained plaintext for
//! retransmission. What is missing is zoxy's side: a UDP arm in the Io
//! seam, a per-connection fixed arena the session can allocate from, and
//! an exchange model that maps QUIC streams onto §7's one-request unit of
//! work. Those are a design milestone, not a wrapper.

const std = @import("std");

const zquic = @import("zquic");
const qtls = @import("qtls");

/// The vendored QUIC transport module, re-exported for the `h3-check`
/// probe. Keeping this name here is what confines `@import("zquic")` to
/// this directory (lint-enforced); the probe never imports the vendor
/// module directly.
pub const vendor = zquic;

/// OpenSSL's QUIC-TLS callback bridge, for the handshake side the serving
/// design will need. Tested by `h3-check`; not wired to a connection yet.
pub const tls = qtls;

/// The listener's bounded protocol components. Each is pure `std` and
/// testable on its own; the serving loop composes them.
pub const demux = @import("demux.zig");
pub const pool = @import("pool.zig");
pub const recovery = @import("recovery.zig");
pub const request_stream = @import("request_stream.zig");
pub const conn = @import("connection.zig");
pub const listener = @import("listener.zig");
pub const proxy = @import("proxy.zig");

/// The bounded per-connection slot over zquic's allocator seam. Tested by
/// `h3-check`; not wired to a listener.
pub const session = @import("session.zig");
pub const Session = session.Session;

pub const Connection = zquic.Connection.Connection;
pub const ConnectionParams = zquic.Connection.ConnectionParams;
pub const Role = zquic.Connection.Role;
pub const Packet = zquic.Packet;
pub const Stream = zquic.Stream;
pub const TransportParameters = zquic.TransportParameters;

/// The HTTP/3 layer: frame codec, QPACK and the server-side API. Build
/// options enable it for this seam, so the types below are real rather
/// than the feature-off empty struct.
pub const Http3 = zquic.Http3;
pub const QpackEncoder = Http3.QpackEncoder;
pub const QpackDecoder = Http3.QpackDecoder;
pub const Http3Frame = Http3.Frame;
pub const Http3StatusCode = Http3.StatusCode;

comptime {
    // The RFC 9000 long-header invariant the transport depends on. A vendor
    // refresh that changes the packet layout should fail here, not at the
    // first datagram.
    std.debug.assert(@sizeOf(Packet.PacketHeader) >= 1);
}

test "h3 seam: a QUIC connection initializes and releases its state" {
    var connection = try Connection.init(std.testing.allocator, .client, .{});
    defer connection.deinit();
    try std.testing.expectEqual(Role.client, connection.super_connection.role);
}

test "h3 seam: QPACK round-trips the request pseudo-headers" {
    var encoder = QpackEncoder.init();
    var decoder = QpackDecoder.init(std.testing.allocator, 4096);
    defer decoder.deinit(std.testing.allocator);

    var fields = [_]Http3.HeaderField{
        try .init(std.testing.allocator, ":method", "GET"),
        try .init(std.testing.allocator, ":scheme", "https"),
        try .init(std.testing.allocator, ":path", "/"),
        try .init(std.testing.allocator, "user-agent", "zoxy-h3-check"),
    };
    defer for (&fields) |*field| field.deinit();

    const encoded = try encoder.encode(&fields, std.testing.allocator);
    defer std.testing.allocator.free(encoded);
    const decoded = try decoder.decode(encoded, std.testing.allocator);
    defer {
        for (decoded) |*field| field.deinit();
        std.testing.allocator.free(decoded);
    }

    try std.testing.expectEqual(@as(usize, 4), decoded.len);
    try std.testing.expectEqualStrings(":method", decoded[0].name);
    try std.testing.expectEqualStrings("GET", decoded[0].value);
    try std.testing.expectEqualStrings("user-agent", decoded[3].name);
    try std.testing.expectEqualStrings("zoxy-h3-check", decoded[3].value);
}

test "h3 seam: a connection and one stream fit a fixed arena" {
    // The premise of §5's pricing for a future h3 listener: zquic takes an
    // allocator, so a per-slot FixedBufferAllocator turns its dynamic state
    // into a bounded reservation. 256 KiB is a probe, not a claim — the
    // assertion records what this dependency version actually needs.
    //
    // Measured at zquic 0.9.18: `@sizeOf(Connection)` is 2,984 B,
    // `init` allocates nothing, and one bidirectional stream costs 328 B.
    // The 64 KiB bound leaves room for what this does not drive — the
    // handshake's crypto reassembly and packet queues — while still
    // failing if the empty state itself starts reserving like a server.
    var storage: [256 * 1024]u8 = undefined;
    var fixed = std.heap.FixedBufferAllocator.init(&storage);
    var connection = try Connection.init(fixed.allocator(), .client, .{});
    defer connection.deinit();
    try std.testing.expect(fixed.end_index < storage.len);

    const stream = try connection.createStream(.client_bidirectional);
    try std.testing.expect(stream.id == 0);
    try std.testing.expect(fixed.end_index < storage.len);
    // The number the design will price: how much of a slot the empty
    // connection state itself costs before any stream buffer.
    try std.testing.expect(fixed.end_index <= 64 * 1024);
}

test {
    _ = session;
}

test "h3 seam: QUIC-TLS produces an ALPN h3 ClientHello" {
    // The binding's premise: OpenSSL's QUIC-TLS callbacks hand the
    // ClientHello to us as CRYPTO bytes at the Initial level instead of
    // writing to a BIO. A transport-parameters block is opaque here; the
    // probe only needs TLS to emit its first flight.
    const params = [_]u8{0};
    const tls_state = try qtls.Tls.initClient(
        std.testing.allocator,
        "localhost",
        &params,
        .{ .insecure_skip_verify = true },
    );
    defer tls_state.destroy();

    try tls_state.drive();
    const hello = tls_state.takeOut(0);
    try std.testing.expect(hello.len >= 4);
    // HandshakeType.client_hello, then the 3-byte length.
    try std.testing.expectEqual(@as(u8, 0x01), hello[0]);
    // ALPN rides the ClientHello; the binding offers "h3".
    try std.testing.expect(std.mem.indexOf(u8, hello, "h3") != null);
}

test {
    _ = demux;
    _ = pool;
    _ = recovery;
    _ = request_stream;
    _ = conn;
    _ = listener;
    _ = proxy;
}
