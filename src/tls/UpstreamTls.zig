//! Upstream TLS client engine (DESIGN.md §4): zgix's sans-I/O seam over
//! zssl's TLS 1.3 client. The caller owns the socket; this owns the
//! handshake, the record buffer, the plaintext sink, and the trust
//! decision.
//!
//! This is the client-side counterpart to `Engine.zig`, and it drives the
//! same way: ciphertext in through `recvBuffer`/`received` (or `feed`, for
//! bytes a caller already holds), plaintext out through `Sink`
//! (synchronous), ciphertext out through `outbound`/`outboundSent` — an
//! engine-owned outbox the transport drains at its own pace, partial
//! writes included. The asymmetry is deliberate: decrypted bytes are
//! consumed inside the call, while ciphertext has to outlive it, so it is
//! copied out of zssl's scratch buffer before the next call.

const std = @import("std");

const constants = @import("../constants.zig");

const zssl = @import("zssl");

const TrustStore = @import("TrustStore.zig");

const assert = std.debug.assert;

const UpstreamTls = @This();

comptime {
    // The relay and upstream-head widths are sized from the constant;
    // zssl owns the record buffer. They have to be the same number, or a
    // drive step could decrypt more plaintext than its destination holds.
    assert(zssl.record.wire_record_bytes_max == constants.tls_record_wire_bytes_max);
}

/// Pool-owned slot header: `Pool(UpstreamTls)` writes these on acquire
/// and release. `init` and `deinit` must not touch them, or a recycled
/// slot's free-list links and generation would be lost mid-session.
pool_next: u32,
generation: u32,
/// The verifier's context, held inline so the pointer zssl keeps
/// (`&engine.trust_context.?`) refers to this engine rather than to a
/// caller local. `init` copies the caller's context in; null when
/// verification is off.
trust_context: ?TrustStore.Context = null,
hs: zssl.ClientHandshake,
/// Where the next read's ciphertext lands; `records` borrows this storage.
record_storage: [zssl.record.wire_record_bytes_max]u8,
records: zssl.record_buffer.RecordBuffer,
/// Where one `handleRecord` writes a whole flight or a decrypted record.
out: [zssl.ClientHandshake.out_bytes_min]u8,
/// The server's flight, certificate chain included.
reassembly: [16 * 1024]u8,
/// The client's own Certificate/CertificateVerify, mTLS only.
client_auth_flight: [zssl.Credentials.chain_bytes_max + 1024]u8,
/// Ciphertext produced but not yet handed to the transport, and how much
/// of it the transport has already written. Engine-owned so it stays
/// valid across an async send. Three records: a tunnel's transforms can
/// stage two while the read side completes a record that may answer with
/// a control record of its own.
outbox: [3 * zssl.record.wire_record_bytes_max]u8,
outbox_len: u32,
outbox_sent: u32,

pub const Config = struct {
    /// Embedder-supplied entropy; zssl generates none.
    client_random: [32]u8,
    x25519_private: [32]u8,
    /// SNI and the name RFC 9525 matches the leaf against.
    server_name: []const u8,
    /// Null means `.insecure_no_verification`: for tests and pinned
    /// transports only, and named so at the call site.
    trust: ?*const TrustStore.Context = null,
    /// mTLS: presented only if the server sends a CertificateRequest.
    client_credentials: ?*const zssl.Credentials = null,
    alpn_protocols: []const []const u8 = &.{},
};

/// What a drive step hands back synchronously: decrypted application data
/// and the peer's orderly close. Ciphertext does not come through here —
/// see `outbound`.
pub const Sink = struct {
    ctx: *anyopaque,
    /// Decrypted application data from the peer. Valid only for the
    /// duration of the callback.
    appData: *const fn (ctx: *anyopaque, bytes: []const u8) void,
    /// The peer closed the TLS session (close_notify).
    closed: *const fn (ctx: *anyopaque) void,
};

/// In-place init: `hs` borrows `reassembly` and `records` borrows
/// `record_storage`, so this value must not be copied after `init`.
pub fn init(engine: *UpstreamTls, config: *const Config) void {
    assert(config.server_name.len >= 1);
    assert(!std.mem.allEqual(u8, &config.x25519_private, 0));
    // Copy the verifier's context into the slot before zssl can hold a
    // pointer to it: the caller's context may be a stack local, while the
    // handshake outlives `init`.
    engine.trust_context = if (config.trust) |context| context.* else null;
    engine.hs = zssl.ClientHandshake.init(&.{
        .client_random = config.client_random,
        .x25519_private = config.x25519_private,
        .server_name = config.server_name,
        .certificate_policy = if (engine.trust_context != null)
            .leaf_signature
        else
            .insecure_no_verification,
        .chain_verifier = if (engine.trust_context) |*context|
            TrustStore.verifier(context)
        else
            null,
        .client_credentials = config.client_credentials,
        .client_auth_flight = if (config.client_credentials != null)
            &engine.client_auth_flight
        else
            &.{},
        .alpn_protocols = config.alpn_protocols,
        .reassembly = &engine.reassembly,
    });
    engine.records = .init(&engine.record_storage);
    engine.outbox_len = 0;
    engine.outbox_sent = 0;
}

pub fn deinit(engine: *UpstreamTls) void {
    engine.hs.deinit();
}

/// Build the ClientHello, staged in the outbox for the transport.
pub fn start(engine: *UpstreamTls) void {
    const hello = engine.hs.start(&engine.out);
    assert(hello.len > 0);
    engine.stage(hello);
}

/// Where the next read's ciphertext goes, capped to one wire record.
///
/// Never empty: `writable` reclaims what `next` has consumed, so a
/// drained buffer offers all of itself and a partly drained one offers
/// everything past the fragment still arriving.
pub fn recvBuffer(engine: *UpstreamTls) []u8 {
    const writable = engine.records.writable();
    assert(writable.len > 0);
    const take = @min(writable.len, @as(usize, zssl.record.wire_record_bytes_max));
    assert(take > 0);
    return writable[0..take];
}

/// Report `n` bytes landed in the buffer `recvBuffer` handed out, and
/// drive whatever they complete. Any error is the connection's: the
/// caller tears down.
pub fn received(engine: *UpstreamTls, n: usize, sink: *const Sink) !void {
    assert(n > 0);
    assert(n <= zssl.record.wire_record_bytes_max);
    errdefer engine.hs.state = .failed;
    engine.records.advance(n);
    try engine.pump(sink);
}

/// Feed ciphertext the caller already holds — bytes that arrived before
/// the engine existed, or a test's. Consumes all of `wire`: each
/// iteration stages a chunk and drains every complete record, so the
/// record buffer's free space is reclaimed between chunks.
pub fn feed(engine: *UpstreamTls, wire: []const u8, sink: *const Sink) !void {
    var remaining = wire;
    // Bounded: every iteration moves at least one byte out of `remaining`
    // — `recvBuffer` is never empty — so this runs at most `wire.len`
    // times and normally once.
    while (remaining.len > 0) {
        const destination = engine.recvBuffer();
        const take = @min(destination.len, remaining.len);
        assert(take > 0);
        @memcpy(destination[0..take], remaining[0..take]);
        remaining = remaining[take..];
        try engine.received(take, sink);
    }
}

/// Room left to stage. A step may append while an earlier send is still
/// in flight — staged bytes never move — but only while the append fits.
pub fn outboundRoom(engine: *const UpstreamTls) usize {
    assert(engine.outbox_len <= engine.outbox.len);
    return engine.outbox.len - engine.outbox_len;
}

/// Ciphertext waiting for the transport; empty when there is nothing to
/// write. A later step may *append* while this slice is in flight —
/// staged bytes never move, so the in-flight region stays valid; only the
/// remainder grows.
pub fn outbound(engine: *const UpstreamTls) []const u8 {
    assert(engine.outbox_sent <= engine.outbox_len);
    return engine.outbox[engine.outbox_sent..engine.outbox_len];
}

/// Report `n` bytes written, which a short send makes a partial credit.
/// Once everything staged has gone out, the outbox resets to empty.
pub fn outboundSent(engine: *UpstreamTls, n: usize) void {
    assert(n <= engine.outbound().len);
    engine.outbox_sent += @intCast(n);
    assert(engine.outbox_sent <= engine.outbox_len);
    if (engine.outbox_sent == engine.outbox_len) {
        engine.outbox_len = 0;
        engine.outbox_sent = 0;
    }
}

pub fn outboxEmpty(engine: *const UpstreamTls) bool {
    assert(engine.outbox_sent <= engine.outbox_len);
    return engine.outbox_sent == engine.outbox_len;
}

/// Encrypt application data into the outbox. Handshake must be complete.
/// Chunked by the caller: `tls_app_chunk_bytes` is what the outbox is
/// sized against, so a larger plaintext has nowhere to go.
pub fn sendApp(engine: *UpstreamTls, bytes: []const u8) !void {
    assert(engine.isConnected());
    assert(bytes.len > 0);
    assert(bytes.len <= constants.tls_app_chunk_bytes);
    assert(engine.outboundRoom() >= zssl.record.wire_record_bytes_max);
    const wire = try engine.hs.sendApplicationData(bytes, &engine.out);
    assert(wire.len > bytes.len); // Record header + AEAD tag overhead.
    engine.stage(wire);
}

/// Stage an orderly TLS close (close_notify) for the transport.
pub fn sendClose(engine: *UpstreamTls) !void {
    assert(engine.outboundRoom() >= zssl.record.wire_record_bytes_max);
    const wire = try engine.hs.sendClose(&engine.out);
    assert(wire.len > 0);
    engine.stage(wire);
}

pub fn isConnected(engine: *const UpstreamTls) bool {
    return engine.hs.state == .connected;
}

pub fn peerClosed(engine: *const UpstreamTls) bool {
    return engine.hs.state == .close_received or engine.hs.state == .closed;
}

/// Stage ciphertext for the transport. Overflow is impossible by
/// construction — the outbox covers the largest burst one step can
/// produce — so it is an invariant violation, not a condition to shed.
fn stage(engine: *UpstreamTls, wire: []const u8) void {
    assert(wire.len > 0);
    assert(engine.outbox_len + wire.len <= engine.outbox.len);
    @memcpy(engine.outbox[engine.outbox_len..][0..wire.len], wire);
    engine.outbox_len += @intCast(wire.len);
}

/// Drain every complete record the last chunk made available.
fn pump(engine: *UpstreamTls, sink: *const Sink) !void {
    // Bounded: `next()` consumes a record per iteration from a buffer no
    // chunk refills mid-pump, so it runs at most as many times as there
    // are whole records staged.
    while (try engine.records.next()) |wire_record| {
        assert(wire_record.len > 0);
        // One record may carry several post-handshake messages; zssl
        // hands the first back from `handleRecord` and the rest from
        // `drain`, so both are walked before the next record.
        var next_event = try engine.hs.handleRecord(wire_record, &engine.out);
        while (next_event) |event| : (next_event = try engine.hs.drain(&engine.out)) {
            switch (event) {
                .send => |wire| {
                    assert(wire.len > 0);
                    engine.stage(wire);
                },
                // The client flight is ciphertext like any other: zssl
                // has already sealed it, and the handshake is complete the
                // moment it is staged.
                .connected => |wire| {
                    assert(wire.len > 0);
                    engine.stage(wire);
                },
                .application_data => |bytes| {
                    // The one place a peer chooses how many bytes land in
                    // a caller buffer; zssl enforces the same bound.
                    if (bytes.len > zssl.record.plaintext_bytes_max) {
                        return error.RecordTooLarge;
                    }
                    sink.appData(sink.ctx, bytes);
                },
                // Resumption is not wired on this path yet; a ticket is
                // consumed and dropped rather than surfaced.
                .ticket => {},
                .closed => sink.closed(sink.ctx),
            }
        }
    }
}

const fixture_cert_pem = @embedFile("testdata/cert.pem");
const fixture_key_pem = @embedFile("testdata/key.pem");
/// Inside the fixture's 2026-10-20 .. 2036-10-17 validity window.
const fixture_now: i64 = 1_800_000_000;

/// Collects what the sink is handed across a drive step.
const Collector = struct {
    bytes: [64]u8 = undefined,
    len: usize = 0,
    closed: bool = false,

    fn appData(ctx: *anyopaque, bytes: []const u8) void {
        const collector: *Collector = @ptrCast(@alignCast(ctx));
        assert(collector.len + bytes.len <= collector.bytes.len);
        @memcpy(collector.bytes[collector.len..][0..bytes.len], bytes);
        collector.len += bytes.len;
    }

    fn onClosed(ctx: *anyopaque) void {
        const collector: *Collector = @ptrCast(@alignCast(ctx));
        collector.closed = true;
    }

    fn sink(collector: *Collector) UpstreamTls.Sink {
        return .{ .ctx = collector, .appData = appData, .closed = onClosed };
    }

    fn text(collector: *const Collector) []const u8 {
        return collector.bytes[0..collector.len];
    }
};

test "upstream tls: the ClientHello is a handshake record for the configured name" {
    var der_storage: [4096]u8 = undefined;
    const roots = [_][]const u8{try pemToDer(fixture_cert_pem, &der_storage)};
    var trust = TrustStore{ .roots = &roots };
    var context: TrustStore.Context = .{
        .store = &trust,
        .server_name = "spike.zgix.test",
        .now_sec = fixture_now,
    };
    var engine: UpstreamTls = undefined;
    const config: Config = .{
        .client_random = @splat(0x11),
        .x25519_private = @splat(0x22),
        .server_name = "spike.zgix.test",
        .trust = &context,
    };
    engine.init(&config);
    defer engine.deinit();

    engine.start();
    const hello = engine.outbound();
    const header_bytes = @as(usize, zssl.record.header_bytes);
    try std.testing.expect(hello.len > header_bytes);
    const header: *const [zssl.record.header_bytes]u8 = hello[0..header_bytes];
    try std.testing.expectEqual(
        zssl.record.ContentType.handshake,
        (zssl.record.parseHeader(header) catch unreachable).content_type,
    );
}

test "upstream tls: init copies the trust context into the slot" {
    const roots = [_][]const u8{"unused"};
    var trust = TrustStore{ .roots = &roots };
    var context: TrustStore.Context = .{
        .store = &trust,
        .server_name = "spike.zgix.test",
        .now_sec = fixture_now,
    };
    var engine: UpstreamTls = undefined;
    engine.init(&.{
        .client_random = @splat(0x11),
        .x25519_private = @splat(0x22),
        .server_name = "spike.zgix.test",
        .trust = &context,
    });
    defer engine.deinit();

    try std.testing.expect(engine.trust_context != null);
    try std.testing.expectEqualStrings("spike.zgix.test", engine.trust_context.?.server_name);
    try std.testing.expect(engine.trust_context.?.store == &trust);
    // zssl must hold a pointer into the slot, not into `context` above:
    // that frame dies when this function's caller returns.
    const held = if (engine.trust_context) |*slot| slot else unreachable;
    const verifier = engine.hs.config.chain_verifier orelse unreachable;
    try std.testing.expectEqual(@intFromPtr(held), @intFromPtr(verifier.context));
}

test "upstream tls: a full handshake verifies the chain and exchanges data" {
    var der_storage: [4096]u8 = undefined;
    const roots = [_][]const u8{try pemToDer(fixture_cert_pem, &der_storage)};
    var trust = TrustStore{ .roots = &roots };
    var context: TrustStore.Context = .{
        .store = &trust,
        .server_name = "spike.zgix.test",
        .now_sec = fixture_now,
    };

    var chain_storage: [zssl.Credentials.chain_bytes_max]u8 = undefined;
    var server_credentials = try zssl.Credentials.load(
        fixture_cert_pem,
        fixture_key_pem,
        &chain_storage,
        true,
    );
    defer server_credentials.deinit();

    var server_reassembly: [16 * 1024]u8 = undefined;
    var server_flight: [zssl.Credentials.chain_bytes_max + 1024]u8 = undefined;
    var server = zssl.ServerHandshake.init(&.{
        .credentials = &server_credentials,
        .server_random = @splat(0x6d),
        .key_share_private = @as([47]u8, @splat(0x93)) ++ [_]u8{0x0e},
        .reassembly = &server_reassembly,
        .flight = &server_flight,
    });

    var engine: UpstreamTls = undefined;
    const config: Config = .{
        .client_random = @splat(0x1a),
        .x25519_private = @as([31]u8, @splat(0x31)) ++ [_]u8{0x07},
        .server_name = "spike.zgix.test",
        .trust = &context,
    };
    engine.init(&config);
    defer engine.deinit();

    var collector: Collector = .{};
    const sink = collector.sink();
    var server_out: [2 * zssl.record.wire_record_bytes_max]u8 = undefined;
    try runHandshake(&engine, &server, &server_out, &sink);
    try std.testing.expect(engine.isConnected());

    try engine.sendApp("ping");
    const server_event = (try exchange(&engine, &server, &server_out, &sink)).?;
    try std.testing.expectEqualStrings(
        "ping",
        switch (server_event) {
            .application_data => |bytes| bytes,
            else => return error.TestUnexpectedResult,
        },
    );

    const reply = try server.sendApplicationData("pong", &server_out);
    try engine.feed(reply, &sink);
    try std.testing.expectEqualStrings("pong", collector.text());
}

test "upstream tls: mTLS carries the client certificate and the server verifies it" {
    var chain_storage: [zssl.Credentials.chain_bytes_max]u8 = undefined;
    var server_credentials = try zssl.Credentials.load(
        fixture_cert_pem,
        fixture_key_pem,
        &chain_storage,
        true,
    );
    defer server_credentials.deinit();

    var server_reassembly: [16 * 1024]u8 = undefined;
    var server_flight: [zssl.Credentials.chain_bytes_max + 1024]u8 = undefined;
    var server = zssl.ServerHandshake.init(&.{
        .credentials = &server_credentials,
        .server_random = @splat(0x6d),
        .key_share_private = @as([47]u8, @splat(0x93)) ++ [_]u8{0x0e},
        .client_auth = .{ .require = true },
        .reassembly = &server_reassembly,
        .flight = &server_flight,
    });
    defer server.deinit();

    var client_chain_storage: [zssl.Credentials.chain_bytes_max]u8 = undefined;
    var client_credentials = try zssl.Credentials.load(
        fixture_cert_pem,
        fixture_key_pem,
        &client_chain_storage,
        true,
    );
    defer client_credentials.deinit();

    var engine: UpstreamTls = undefined;
    const config: Config = .{
        .client_random = @splat(0x1a),
        .x25519_private = @as([31]u8, @splat(0x31)) ++ [_]u8{0x07},
        .server_name = "spike.zgix.test",
        .client_credentials = &client_credentials,
    };
    engine.init(&config);
    defer engine.deinit();

    var collector: Collector = .{};
    const sink = collector.sink();
    var server_out: [2 * zssl.record.wire_record_bytes_max]u8 = undefined;
    try runHandshake(&engine, &server, &server_out, &sink);

    try std.testing.expect(engine.isConnected());
    try std.testing.expectEqual(zssl.ServerHandshake.State.connected, server.state);
    // The server holds a client key only the client could have signed with.
    try std.testing.expect(server.peer.verified);
    try std.testing.expect(!server.peer.empty);
    try std.testing.expectEqual(@as(u16, 0x0403), @backingInt(server.peer.scheme.?));

    // Client-auth messages are in the transcript both Finisheds MAC, so
    // application keys working proves the two ends agree about them.
    try engine.sendApp("mutual");
    const event = (try exchange(&engine, &server, &server_out, &sink)).?;
    try std.testing.expectEqualStrings("mutual", event.application_data);
}

test "upstream tls: a server requiring mTLS rejects a client with no certificate" {
    var chain_storage: [zssl.Credentials.chain_bytes_max]u8 = undefined;
    var server_credentials = try zssl.Credentials.load(
        fixture_cert_pem,
        fixture_key_pem,
        &chain_storage,
        true,
    );
    defer server_credentials.deinit();

    var server_reassembly: [16 * 1024]u8 = undefined;
    var server_flight: [zssl.Credentials.chain_bytes_max + 1024]u8 = undefined;
    var server = zssl.ServerHandshake.init(&.{
        .credentials = &server_credentials,
        .server_random = @splat(0x6d),
        .key_share_private = @as([47]u8, @splat(0x93)) ++ [_]u8{0x0e},
        .client_auth = .{ .require = true },
        .reassembly = &server_reassembly,
        .flight = &server_flight,
    });
    defer server.deinit();

    var engine: UpstreamTls = undefined;
    const config: Config = .{
        .client_random = @splat(0x1a),
        .x25519_private = @as([31]u8, @splat(0x31)) ++ [_]u8{0x07},
        .server_name = "spike.zgix.test",
    };
    engine.init(&config);
    defer engine.deinit();

    var collector: Collector = .{};
    const sink = collector.sink();
    var server_out: [2 * zssl.record.wire_record_bytes_max]u8 = undefined;
    try std.testing.expectError(
        error.CertificateRequired,
        runHandshake(&engine, &server, &server_out, &sink),
    );
    try std.testing.expectEqual(zssl.ServerHandshake.State.failed, server.state);
    try std.testing.expect(server.peer.empty);
    try std.testing.expect(!server.peer.verified);
}

test "upstream tls: two application records in one received reach the sink in order" {
    var chain_storage: [zssl.Credentials.chain_bytes_max]u8 = undefined;
    var server_credentials = try zssl.Credentials.load(
        fixture_cert_pem,
        fixture_key_pem,
        &chain_storage,
        true,
    );
    defer server_credentials.deinit();

    var server_reassembly: [16 * 1024]u8 = undefined;
    var server_flight: [zssl.Credentials.chain_bytes_max + 1024]u8 = undefined;
    var server = zssl.ServerHandshake.init(&.{
        .credentials = &server_credentials,
        .server_random = @splat(0x6d),
        .key_share_private = @as([47]u8, @splat(0x93)) ++ [_]u8{0x0e},
        .reassembly = &server_reassembly,
        .flight = &server_flight,
    });
    defer server.deinit();

    var engine: UpstreamTls = undefined;
    const config: Config = .{
        .client_random = @splat(0x1a),
        .x25519_private = @as([31]u8, @splat(0x31)) ++ [_]u8{0x07},
        .server_name = "spike.zgix.test",
    };
    engine.init(&config);
    defer engine.deinit();

    var collector: Collector = .{};
    const sink = collector.sink();
    var server_out: [2 * zssl.record.wire_record_bytes_max]u8 = undefined;
    try runHandshake(&engine, &server, &server_out, &sink);
    try std.testing.expect(engine.isConnected());

    var combined: [2 * zssl.record.wire_record_bytes_max]u8 = undefined;
    const first = try server.sendApplicationData("alpha", &server_out);
    @memcpy(combined[0..first.len], first);
    const second = try server.sendApplicationData("beta", &server_out);
    @memcpy(combined[first.len..][0..second.len], second);
    const wire = combined[0 .. first.len + second.len];

    const destination = engine.recvBuffer();
    try std.testing.expect(destination.len >= wire.len);
    @memcpy(destination[0..wire.len], wire);
    try engine.received(wire.len, &sink);

    try std.testing.expectEqualStrings("alphabeta", collector.text());
    try std.testing.expect(engine.outboxEmpty());
}

test "upstream tls: outboundSent credits a partial write without moving bytes" {
    var chain_storage: [zssl.Credentials.chain_bytes_max]u8 = undefined;
    var server_credentials = try zssl.Credentials.load(
        fixture_cert_pem,
        fixture_key_pem,
        &chain_storage,
        true,
    );
    defer server_credentials.deinit();

    var server_reassembly: [16 * 1024]u8 = undefined;
    var server_flight: [zssl.Credentials.chain_bytes_max + 1024]u8 = undefined;
    var server = zssl.ServerHandshake.init(&.{
        .credentials = &server_credentials,
        .server_random = @splat(0x6d),
        .key_share_private = @as([47]u8, @splat(0x93)) ++ [_]u8{0x0e},
        .reassembly = &server_reassembly,
        .flight = &server_flight,
    });
    defer server.deinit();

    var engine: UpstreamTls = undefined;
    const config: Config = .{
        .client_random = @splat(0x1a),
        .x25519_private = @as([31]u8, @splat(0x31)) ++ [_]u8{0x07},
        .server_name = "spike.zgix.test",
    };
    engine.init(&config);
    defer engine.deinit();

    var collector: Collector = .{};
    const sink = collector.sink();
    var server_out: [2 * zssl.record.wire_record_bytes_max]u8 = undefined;
    try runHandshake(&engine, &server, &server_out, &sink);
    try std.testing.expect(engine.outboxEmpty());

    try engine.sendApp("hello");
    const staged = engine.outbound();
    try std.testing.expect(staged.len > 1);

    engine.outboundSent(1);
    try std.testing.expectEqualSlices(u8, staged[1..], engine.outbound());
    try std.testing.expect(!engine.outboxEmpty());

    engine.outboundSent(staged.len - 1);
    try std.testing.expect(engine.outboxEmpty());
    try std.testing.expectEqual(@as(usize, 0), engine.outbound().len);
}

/// Drive the handshake to completion: move the client's staged ciphertext
/// to the server, and every server flight back to the client.
fn runHandshake(
    engine: *UpstreamTls,
    server: *zssl.ServerHandshake,
    server_out: []u8,
    sink: *const Sink,
) !void {
    engine.start();
    // Two exchanges: the ClientHello earns the server flight, and the
    // client flight that completes the handshake follows it out.
    _ = try exchange(engine, server, server_out, sink);
    _ = try exchange(engine, server, server_out, sink);
    try std.testing.expect(engine.outboxEmpty());
    try std.testing.expect(engine.isConnected());
    try std.testing.expectEqual(zssl.ServerHandshake.State.connected, server.state);
}

/// Feed every staged client record to the server, answering the last
/// event, and credit the outbox as sent. Returns the last server event.
fn exchange(
    engine: *UpstreamTls,
    server: *zssl.ServerHandshake,
    server_out: []u8,
    sink: *const Sink,
) !?zssl.ServerHandshake.Event {
    const wire = engine.outbound();
    if (wire.len == 0) return null;
    var last: ?zssl.ServerHandshake.Event = null;
    var index: usize = 0;
    // Bounded: every iteration consumes at least one whole record.
    while (index < wire.len) {
        const record = recordAt(wire, index);
        index += record.len;
        last = try server.handleRecord(record, server_out);
        try answer(engine, last, sink);
    }
    engine.outboundSent(wire.len);
    return last;
}

/// Feed whatever the server produced back into the client. Plaintext is
/// not expected here — the handshake path only carries ciphertext.
fn answer(engine: *UpstreamTls, event: ?zssl.ServerHandshake.Event, sink: *const Sink) !void {
    const ready = event orelse return;
    switch (ready) {
        .send => |wire| try engine.feed(wire, sink),
        .connected, .application_data, .early_data, .closed => {},
    }
}

fn recordAt(bytes: []const u8, index: usize) []const u8 {
    assert(index + 5 <= bytes.len);
    const body = std.mem.readInt(u16, bytes[index + 3 ..][0..2], .big);
    const total = 5 + @as(usize, body);
    assert(index + total <= bytes.len);
    return bytes[index..][0..total];
}

/// One PEM block's DER, decoded into `storage`.
fn pemToDer(pem: []const u8, storage: []u8) ![]const u8 {
    var iterator = zssl.pem.Iterator.init(pem, storage);
    const block = (try iterator.next()) orelse return error.MalformedPem;
    return block.der;
}
