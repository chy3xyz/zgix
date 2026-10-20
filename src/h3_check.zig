//! Root of the experimental `h3-check` gate (DESIGN.md §4/§7).
//!
//! The seam itself lives under `http/h3/`; this wrapper sits one level
//! above it so `@embedFile` can reach the TLS fixtures in
//! `src/tls/testdata/`, which the module-root rule would otherwise put
//! outside the seam's package path. It is the only file the step compiles
//! as a root; nothing in the proxy imports it.

const std = @import("std");

const qtls = @import("qtls");
const h3 = @import("http/h3/root.zig");
const zquic = h3.vendor;

test {
    _ = h3;
}

test "h3 seam: the QUIC-TLS bridge completes a handshake" {
    const fixtures = struct {
        const cert_pem = @embedFile("tls/testdata/cert.pem");
        const key_pem = @embedFile("tls/testdata/key.pem");
    };
    try qtls.setServerCert(fixtures.cert_pem, fixtures.key_pem);
    const params = [_]u8{0};
    const server = try qtls.Tls.initServer(std.testing.allocator, &params);
    defer server.destroy();
    const client = try qtls.Tls.initClient(
        std.testing.allocator,
        "spike.zoxy.test",
        &params,
        .{ .insecure_skip_verify = true },
    );
    defer client.destroy();

    try client.drive();
    var rounds: u8 = 0;
    while (rounds < 8 and (!client.isFinished() or !server.isFinished())) : (rounds += 1) {
        var moved = false;
        for (0..qtls.level_count) |level| {
            const from_client = client.takeOut(level);
            if (from_client.len > 0) {
                try server.pushCrypto(level, from_client);
                client.clearOut(level);
                moved = true;
            }
            const from_server = server.takeOut(level);
            if (from_server.len > 0) {
                try client.pushCrypto(level, from_server);
                server.clearOut(level);
                moved = true;
            }
        }
        if (!moved) break;
        try client.drive();
        try server.drive();
    }
    try std.testing.expect(client.isFinished());
    try std.testing.expect(server.isFinished());

    // Application traffic secrets are the handshake's product; both sides
    // must hold a pair, and the client's write secret is the server's read
    // secret.
    const client_secrets = client.takeSecrets(3);
    try std.testing.expect(client_secrets.complete());
    const server_secrets = server.takeSecrets(3);
    try std.testing.expect(server_secrets.complete());
    try std.testing.expectEqualSlices(u8, &client_secrets.local.?, &server_secrets.remote.?);
    try std.testing.expectEqualSlices(u8, &client_secrets.remote.?, &server_secrets.local.?);
}

/// Serialize one CRYPTO frame carrying `data` at offset zero.
fn cryptoFrameBytes(out: []u8, data: []const u8) ![]const u8 {
    var writer: std.Io.Writer = .fixed(out);
    const frame = zquic.core.QuicFrames.Frame{ .crypto = .init(0, data) };
    try frame.serialize(&writer);
    return out[0..writer.end];
}

/// Copy the first CRYPTO frame's payload out of a decrypted QUIC packet.
/// The parser allocates the frame's data; the copy lets the caller free it
/// before TLS consumes the bytes.
fn extractCrypto(
    allocator: std.mem.Allocator,
    payload: []const u8,
    out: []u8,
) ![]const u8 {
    var reader: std.Io.Reader = .fixed(payload);
    while (reader.seek < reader.end) {
        const frame = try zquic.core.QuicFrames.Frame.parse(&reader, allocator);
        switch (frame) {
            .crypto => |crypto| {
                defer allocator.free(crypto.data);
                if (crypto.data.len > out.len) return error.CryptoTooLarge;
                @memcpy(out[0..crypto.data.len], crypto.data);
                return out[0..crypto.data.len];
            },
            else => {},
        }
    }
    return error.NoCryptoFrame;
}

/// Traffic-secret pair → the two directions' RFC 9001 packet keys.
fn packetKeys(secrets: qtls.SecretSet) !struct {
    local: zquic.Tls13KeySchedule.QuicPacketKeys,
    remote: zquic.Tls13KeySchedule.QuicPacketKeys,
} {
    return .{
        .local = try zquic.Tls13KeySchedule.deriveQuicPacketKeys(&secrets.local.?),
        .remote = try zquic.Tls13KeySchedule.deriveQuicPacketKeys(&secrets.remote.?),
    };
}

test "h3 seam: QUIC Initial, Handshake and 1-RTT complete over raw packets" {
    const allocator = std.testing.allocator;
    const fixtures = struct {
        const cert_pem = @embedFile("tls/testdata/cert.pem");
        const key_pem = @embedFile("tls/testdata/key.pem");
    };
    try qtls.setServerCert(fixtures.cert_pem, fixtures.key_pem);

    var client_tls_ctx = try zquic.EnhancedCrypto.EnhancedTlsContext.init(
        allocator,
        false,
        .aes_128_gcm_sha256,
    );
    defer client_tls_ctx.deinit();
    var server_tls_ctx = try zquic.EnhancedCrypto.EnhancedTlsContext.init(
        allocator,
        true,
        .aes_128_gcm_sha256,
    );
    defer server_tls_ctx.deinit();
    var client_pc = try zquic.PacketCrypto.init(allocator, &client_tls_ctx, null);
    defer client_pc.deinit();
    var server_pc = try zquic.PacketCrypto.init(allocator, &server_tls_ctx, null);
    defer server_pc.deinit();

    const params = [_]u8{0};
    const client_tls = try qtls.Tls.initClient(
        allocator,
        "spike.zoxy.test",
        &params,
        .{ .insecure_skip_verify = true },
    );
    defer client_tls.destroy();
    const server_tls = try qtls.Tls.initServer(allocator, &params);
    defer server_tls.destroy();

    const client_dcid: [8]u8 = @splat(0x11);
    const client_scid: [8]u8 = @splat(0x22);
    const server_scid: [8]u8 = @splat(0x33);
    try client_pc.installRfc9001ClientInitialKeys(&client_dcid);
    try server_pc.installRfc9001ServerInitialKeys(&client_dcid);

    var tx: [8192]u8 = undefined;
    var rx: [8192]u8 = undefined;

    // ClientHello in an Initial packet.
    try client_tls.drive();
    const ch_wire = try cryptoFrameBytes(&tx, client_tls.takeOut(0));
    const client_initial = try client_pc.createProtectedRawPacket(
        .initial,
        .initial,
        &client_dcid,
        &client_scid,
        ch_wire,
    );
    defer allocator.free(client_initial);
    var server_ch_in = try server_pc.processProtectedRawPacket(client_initial, null);
    defer server_ch_in.deinit(allocator);
    try server_tls.pushCrypto(0, try extractCrypto(allocator, server_ch_in.payload, &rx));
    try server_tls.drive();
    // OpenSSL may emit the ServerHello on one drive and the encrypted
    // handshake flight on the next; a second call costs a no-op when the
    // first produced everything.
    try server_tls.drive();

    const server_hs = try packetKeys(server_tls.takeSecrets(2));
    try server_pc.installRfc9001HandshakeKeys(&server_hs.local, &server_hs.remote);

    // ServerHello (Initial) and the encrypted handshake flight (Handshake).
    const sh_wire = try cryptoFrameBytes(&tx, server_tls.takeOut(0));
    const server_initial = try server_pc.createProtectedRawPacket(
        .initial,
        .initial,
        &client_scid,
        &server_scid,
        sh_wire,
    );
    defer allocator.free(server_initial);
    const rest_wire = try cryptoFrameBytes(&tx, server_tls.takeOut(2));
    const server_handshake = try server_pc.createProtectedRawPacket(
        .handshake,
        .handshake,
        &client_scid,
        &server_scid,
        rest_wire,
    );
    defer allocator.free(server_handshake);

    var client_initial_in = try client_pc.processProtectedRawPacket(server_initial, null);
    defer client_initial_in.deinit(allocator);
    try client_tls.pushCrypto(0, try extractCrypto(allocator, client_initial_in.payload, &rx));
    try client_tls.drive();
    const client_hs = try packetKeys(client_tls.takeSecrets(2));
    try client_pc.installRfc9001HandshakeKeys(&client_hs.local, &client_hs.remote);

    var client_handshake_in = try client_pc.processProtectedRawPacket(server_handshake, null);
    defer client_handshake_in.deinit(allocator);
    try client_tls.pushCrypto(2, try extractCrypto(allocator, client_handshake_in.payload, &rx));
    try client_tls.drive();
    const client_app = try packetKeys(client_tls.takeSecrets(3));
    try client_pc.installRfc9001ApplicationKeys(&client_app.local, &client_app.remote);

    // Client Finished, then the server's application keys.
    const fin_wire = try cryptoFrameBytes(&tx, client_tls.takeOut(2));
    const client_finished = try client_pc.createProtectedRawPacket(
        .handshake,
        .handshake,
        &server_scid,
        &client_scid,
        fin_wire,
    );
    defer allocator.free(client_finished);
    var server_fin_in = try server_pc.processProtectedRawPacket(client_finished, null);
    defer server_fin_in.deinit(allocator);
    try server_tls.pushCrypto(2, try extractCrypto(allocator, server_fin_in.payload, &rx));
    try server_tls.drive();
    const server_app = try packetKeys(server_tls.takeSecrets(3));
    try server_pc.installRfc9001ApplicationKeys(&server_app.local, &server_app.remote);

    try std.testing.expect(client_tls.isFinished());
    try std.testing.expect(server_tls.isFinished());
    try std.testing.expectEqualSlices(u8, &client_app.local.key, &server_app.remote.key);

    // A 1-RTT packet is the proof the application keys are installed on
    // both sides: it cannot be decrypted at any lower level.
    // A PING plus PADDING: header protection needs a 16-byte sample, so a
    // one-byte payload cannot be protected (RFC 9001 §5.4.2).
    const ping = [_]u8{ 0x01, 0x00, 0x00, 0x00 };
    const one_rtt = try client_pc.createProtectedRawPacket(
        .application,
        .one_rtt,
        &server_scid,
        &client_scid,
        &ping,
    );
    defer allocator.free(one_rtt);
    var server_one_rtt = try server_pc.processProtectedRawPacket(one_rtt, null);
    defer server_one_rtt.deinit(allocator);
    try std.testing.expectEqualSlices(u8, &ping, server_one_rtt.payload);
    try std.testing.expectEqual(@as(u8, 0x01), server_one_rtt.payload[0]);
}

const H3 = zquic.Http3;

fn freeHeaderFields(fields: []H3.HeaderField) void {
    for (fields) |*field| field.deinit();
}

fn h3RequestFrames(out: []u8, allocator: std.mem.Allocator) ![]const u8 {
    var encoder = H3.QpackEncoder.init();
    var fields = [_]H3.HeaderField{
        try .init(allocator, ":method", "GET"),
        try .init(allocator, ":scheme", "https"),
        try .init(allocator, ":authority", "spike.zoxy.test"),
        try .init(allocator, ":path", "/hello"),
        try .init(allocator, "user-agent", "zoxy-h3-check"),
    };
    defer freeHeaderFields(&fields);
    const block = try encoder.encode(&fields, allocator);
    defer allocator.free(block);

    var writer: std.Io.Writer = .fixed(out);
    const headers = H3.FrameHeader{ .frame_type = .headers, .length = block.len };
    try headers.serialize(&writer);
    try writer.writeAll(block);
    const body = H3.FrameHeader{ .frame_type = .data, .length = "request-body".len };
    try body.serialize(&writer);
    try writer.writeAll("request-body");
    return out[0..writer.end];
}

fn h3ResponseFrames(out: []u8, allocator: std.mem.Allocator) ![]const u8 {
    var encoder = H3.QpackEncoder.init();
    var fields = [_]H3.HeaderField{
        try .init(allocator, ":status", "200"),
        try .init(allocator, "content-type", "text/plain"),
    };
    defer freeHeaderFields(&fields);
    const block = try encoder.encode(&fields, allocator);
    defer allocator.free(block);

    var writer: std.Io.Writer = .fixed(out);
    const headers = H3.FrameHeader{ .frame_type = .headers, .length = block.len };
    try headers.serialize(&writer);
    try writer.writeAll(block);
    const body = H3.FrameHeader{ .frame_type = .data, .length = "ok".len };
    try body.serialize(&writer);
    try writer.writeAll("ok");
    return out[0..writer.end];
}

const ParsedH3 = struct {
    fields: []H3.HeaderField,
    data: []const u8,
};

fn freeDecodedFields(fields: []H3.HeaderField, allocator: std.mem.Allocator) void {
    for (fields) |*field| field.deinit();
    allocator.free(fields);
}

fn parseH3(
    payload: []const u8,
    decoder: *H3.QpackDecoder,
    allocator: std.mem.Allocator,
) !ParsedH3 {
    var offset: usize = 0;
    var headers: []H3.HeaderField = &.{};
    var data: []const u8 = &.{};
    while (offset < payload.len) {
        const parsed = try H3.FrameHeader.parse(payload[offset..]);
        offset += parsed.consumed;
        if (offset + parsed.header.length > payload.len) return error.Truncated;
        const body = payload[offset..][0..parsed.header.length];
        offset += parsed.header.length;
        switch (parsed.header.frame_type) {
            .headers => headers = try decoder.decode(body, allocator),
            .data => data = body,
            else => {},
        }
    }
    return .{ .fields = headers, .data = data };
}

test "h3 seam: an HTTP/3 request and response cross a QUIC stream" {
    const allocator = std.testing.allocator;
    var client_stream = try zquic.Stream.SuperStream.init(allocator, 0, .client_bidirectional);
    defer client_stream.deinit();
    var server_stream = try zquic.Stream.SuperStream.init(allocator, 0, .client_bidirectional);
    defer server_stream.deinit();

    var request_buffer: [4096]u8 = undefined;
    const request = try h3RequestFrames(&request_buffer, allocator);
    _ = try client_stream.write(request, true);
    try server_stream.handleIncomingDataWithFin(client_stream.pendingWriteData(), true);

    var wire: [4096]u8 = undefined;
    const request_len = try server_stream.read(&wire);
    var server_decoder = H3.QpackDecoder.init(allocator, 4096);
    defer server_decoder.deinit(allocator);
    const parsed_request = try parseH3(wire[0..request_len], &server_decoder, allocator);
    defer freeDecodedFields(parsed_request.fields, allocator);
    try std.testing.expectEqualStrings(":method", parsed_request.fields[0].name);
    try std.testing.expectEqualStrings("GET", parsed_request.fields[0].value);
    try std.testing.expectEqualStrings(":path", parsed_request.fields[3].name);
    try std.testing.expectEqualStrings("/hello", parsed_request.fields[3].value);
    try std.testing.expectEqualStrings("request-body", parsed_request.data);

    var response_buffer: [4096]u8 = undefined;
    const response = try h3ResponseFrames(&response_buffer, allocator);
    _ = try server_stream.write(response, true);
    try client_stream.handleIncomingDataWithFin(server_stream.pendingWriteData(), true);

    const response_len = try client_stream.read(&wire);
    var client_decoder = H3.QpackDecoder.init(allocator, 4096);
    defer client_decoder.deinit(allocator);
    const parsed_response = try parseH3(wire[0..response_len], &client_decoder, allocator);
    defer freeDecodedFields(parsed_response.fields, allocator);
    try std.testing.expectEqualStrings(":status", parsed_response.fields[0].name);
    try std.testing.expectEqualStrings("200", parsed_response.fields[0].value);
    try std.testing.expectEqualStrings("ok", parsed_response.data);
}
