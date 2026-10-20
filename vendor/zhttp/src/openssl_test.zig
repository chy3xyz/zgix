const std = @import("std");
const testing = std.testing;
const posix = std.posix;
const openssl = @import("openssl.zig");
const SniContext = openssl.SniContext;
const Connection = openssl.Connection;
const config = openssl.config;
const c = openssl.c;

fn makeSocketPair() ![2]posix.fd_t {
    var fds: [2]posix.fd_t = undefined;
    if (std.c.socketpair(std.os.linux.AF.UNIX, std.os.linux.SOCK.STREAM, 0, &fds) != 0) {
        return error.SocketPairFailed;
    }
    return fds;
}

fn closeFd(fd: posix.fd_t) void {
    _ = std.c.close(fd);
}

// ─── Test Certificates ─────────────────────────────────────────

const test_cert_pem =
    "-----BEGIN CERTIFICATE-----\n" ++
    "MIIBfjCCASOgAwIBAgIUGWJ6UOcFfvMz2WWNBT2KJnCZ6gIwCgYIKoZIzj0EAwIw\n" ++
    "FDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI2MDQzMDE5MDQzOFoXDTI2MDUwMTE5\n" ++
    "MDQzOFowFDESMBAGA1UEAwwJbG9jYWxob3N0MFkwEwYHKoZIzj0CAQYIKoZIzj0D\n" ++
    "AQcDQgAEf6r6DqRFQRcZK3bdQVewsLO30KKi6jmjf/ilQ8Ia86x1qlMXK1W8JljS\n" ++
    "EtIo4XI+XMRiYvJRzmWpyfgb4sF7BKNTMFEwHQYDVR0OBBYEFPcHKQa8VTtVtZMa\n" ++
    "+uni++GsvWClMB8GA1UdIwQYMBaAFPcHKQa8VTtVtZMa+uni++GsvWClMA8GA1Ud\n" ++
    "EwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDSQAwRgIhAM38oCzu+PHKrUCFfdDxzxoO\n" ++
    "UVCzKELsdOGVpiQxJHpJAiEA5vQAM1QqdoXdpNGXwvp46lqyCbgYRdnjhRlQExxa\n" ++
    "32k=\n" ++
    "-----END CERTIFICATE-----\n";

const test_key_pem =
    "-----BEGIN EC PRIVATE KEY-----\n" ++
    "MHcCAQEEIPVAhHt9qqLKmulC2YflDOH6bBozj6fQhGwy6lQKq5D4oAoGCCqGSM49\n" ++
    "AwEHoUQDQgAEf6r6DqRFQRcZK3bdQVewsLO30KKi6jmjf/ilQ8Ia86x1qlMXK1W8\n" ++
    "JljSEtIo4XI+XMRiYvJRzmWpyfgb4sF7BA==\n" ++
    "-----END EC PRIVATE KEY-----\n";

const test_cert2_pem =
    "-----BEGIN CERTIFICATE-----\n" ++
    "MIIBgTCCASegAwIBAgIUUn24q+7zyuF9K+a0998WDy2IxyUwCgYIKoZIzj0EAwIw\n" ++
    "FjEUMBIGA1UEAwwLZXhhbXBsZS5jb20wHhcNMjYwNDMwMTkwNTQzWhcNMjYwNTAx\n" ++
    "MTkwNTQzWjAWMRQwEgYDVQQDDAtleGFtcGxlLmNvbTBZMBMGByqGSM49AgEGCCqG\n" ++
    "SM49AwEHA0IABERBef4GVGAC9NoHc8lz55QK8wwVXP1o7EgwMlU224Qi8rK5KQ6o\n" ++
    "jScnJ5LVOKZste7lIkYDNH/18pUGJC2BtjCjUzBRMB0GA1UdDgQWBBSCQEFtJs7y\n" ++
    "TmDdtChAhfW+tO6V4TAfBgNVHSMEGDAWgBSCQEFtJs7yTmDdtChAhfW+tO6V4TAP\n" ++
    "BgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0gAMEUCIC3QXEa7QY4YfQyrqCFU\n" ++
    "PNR+Z5UgpNiKyzAukRqs/a8WAiEAv8FOqtN2whteWBUmBwTpAgNtYWKErl9X4Qe6\n" ++
    "JU9IsXQ=\n" ++
    "-----END CERTIFICATE-----\n";

const test_key2_pem =
    "-----BEGIN EC PRIVATE KEY-----\n" ++
    "MHcCAQEEIM1t736QzGh2ynl6TO46zfnfOCqGi/cRlZ8gjYSDuzmXoAoGCCqGSM49\n" ++
    "AwEHoUQDQgAEREF5/gZUYAL02gdzyXPnlArzDBVc/WjsSDAyVTbbhCLysrkpDqiN\n" ++
    "JycnktU4pmy17uUiRgM0f/XylQYkLYG2MA==\n" ++
    "-----END EC PRIVATE KEY-----\n";

const test_default_cert = config.CertKeyPair{
    .cert_pem = test_cert_pem,
    .key_pem = test_key_pem,
    .allocator = undefined,
};

// ─── loadCertIntoCtx Tests ─────────────────────────────────────

test "loadCertIntoCtx: loads valid cert and key" {
    const ctx = c.SSL_CTX_new(c.TLS_server_method()) orelse return error.TlsHandshakeFailure;
    defer c.SSL_CTX_free(ctx);
    try openssl.loadCertIntoCtx(ctx, test_cert_pem, test_key_pem);
}

test "loadCertIntoCtx: rejects invalid cert PEM" {
    const ctx = c.SSL_CTX_new(c.TLS_server_method()) orelse return error.TlsHandshakeFailure;
    defer c.SSL_CTX_free(ctx);
    try testing.expectError(error.InvalidCertificate, openssl.loadCertIntoCtx(ctx, "not a cert", test_key_pem));
}

test "loadCertIntoCtx: rejects invalid key PEM" {
    const ctx = c.SSL_CTX_new(c.TLS_server_method()) orelse return error.TlsHandshakeFailure;
    defer c.SSL_CTX_free(ctx);
    try testing.expectError(error.InvalidCertificate, openssl.loadCertIntoCtx(ctx, test_cert_pem, "not a key"));
}

test "loadCertIntoCtx: rejects mismatched cert and key" {
    const ctx = c.SSL_CTX_new(c.TLS_server_method()) orelse return error.TlsHandshakeFailure;
    defer c.SSL_CTX_free(ctx);
    try testing.expectError(error.InvalidCertificate, openssl.loadCertIntoCtx(ctx, test_cert_pem, test_key2_pem));
}

test "loadCertIntoCtx: rejects empty cert" {
    const ctx = c.SSL_CTX_new(c.TLS_server_method()) orelse return error.TlsHandshakeFailure;
    defer c.SSL_CTX_free(ctx);
    try testing.expectError(error.InvalidCertificate, openssl.loadCertIntoCtx(ctx, "", test_key_pem));
}

test "loadCertIntoCtx: rejects empty key" {
    const ctx = c.SSL_CTX_new(c.TLS_server_method()) orelse return error.TlsHandshakeFailure;
    defer c.SSL_CTX_free(ctx);
    try testing.expectError(error.InvalidCertificate, openssl.loadCertIntoCtx(ctx, test_cert_pem, ""));
}

test "loadCertIntoCtx: can load into multiple contexts" {
    const ctx1 = c.SSL_CTX_new(c.TLS_server_method()) orelse return error.TlsHandshakeFailure;
    defer c.SSL_CTX_free(ctx1);
    const ctx2 = c.SSL_CTX_new(c.TLS_server_method()) orelse return error.TlsHandshakeFailure;
    defer c.SSL_CTX_free(ctx2);
    try openssl.loadCertIntoCtx(ctx1, test_cert_pem, test_key_pem);
    try openssl.loadCertIntoCtx(ctx2, test_cert2_pem, test_key2_pem);
}

// ─── SniContext Tests ──────────────────────────────────────────

test "SniContext: init and deinit" {
    var sni = try SniContext.init(testing.allocator, &test_default_cert);
    sni.deinit();
}

test "SniContext: addDomain and deinit cleans up" {
    var sni = try SniContext.init(testing.allocator, &test_default_cert);
    defer sni.deinit();
    try sni.addDomain("example.com", test_cert2_pem, test_key2_pem);
    try testing.expectEqual(@as(u32, 1), sni.domain_contexts.count());
}

test "SniContext: addDomain with invalid cert fails" {
    var sni = try SniContext.init(testing.allocator, &test_default_cert);
    defer sni.deinit();
    try testing.expectError(error.InvalidCertificate, sni.addDomain("bad.com", "bad", "bad"));
    try testing.expectEqual(@as(u32, 0), sni.domain_contexts.count());
}

test "SniContext: addDomain with mismatched cert/key fails" {
    var sni = try SniContext.init(testing.allocator, &test_default_cert);
    defer sni.deinit();
    try testing.expectError(error.InvalidCertificate, sni.addDomain("bad.com", test_cert_pem, test_key2_pem));
    try testing.expectEqual(@as(u32, 0), sni.domain_contexts.count());
}

test "SniContext: add multiple domains" {
    var sni = try SniContext.init(testing.allocator, &test_default_cert);
    defer sni.deinit();
    try sni.addDomain("example.com", test_cert2_pem, test_key2_pem);
    try sni.addDomain("localhost", test_cert_pem, test_key_pem);
    try testing.expectEqual(@as(u32, 2), sni.domain_contexts.count());
}

test "SniContext: replace existing domain" {
    var sni = try SniContext.init(testing.allocator, &test_default_cert);
    defer sni.deinit();
    try sni.addDomain("example.com", test_cert2_pem, test_key2_pem);
    const first_ctx = sni.domain_contexts.get("example.com").?;
    try sni.addDomain("example.com", test_cert2_pem, test_key2_pem);
    const second_ctx = sni.domain_contexts.get("example.com").?;
    try testing.expect(first_ctx != second_ctx);
    try testing.expectEqual(@as(u32, 1), sni.domain_contexts.count());
}

test "SniContext: removeDomain" {
    var sni = try SniContext.init(testing.allocator, &test_default_cert);
    defer sni.deinit();
    try sni.addDomain("example.com", test_cert2_pem, test_key2_pem);
    sni.removeDomain("example.com");
    try testing.expectEqual(@as(u32, 0), sni.domain_contexts.count());
}

test "SniContext: removeDomain nonexistent is no-op" {
    var sni = try SniContext.init(testing.allocator, &test_default_cert);
    defer sni.deinit();
    sni.removeDomain("nonexistent.com");
    try testing.expectEqual(@as(u32, 0), sni.domain_contexts.count());
}

test "SniContext: removeDomain does not affect other domains" {
    var sni = try SniContext.init(testing.allocator, &test_default_cert);
    defer sni.deinit();
    try sni.addDomain("a.com", test_cert2_pem, test_key2_pem);
    try sni.addDomain("b.com", test_cert_pem, test_key_pem);
    sni.removeDomain("a.com");
    try testing.expectEqual(@as(u32, 1), sni.domain_contexts.count());
    try testing.expect(sni.domain_contexts.get("b.com") != null);
    try testing.expect(sni.domain_contexts.get("a.com") == null);
}

test "SniContext: init with invalid default cert fails" {
    const bad_cert = config.CertKeyPair{
        .cert_pem = "bad",
        .key_pem = "bad",
        .allocator = undefined,
    };
    try testing.expectError(error.InvalidCertificate, SniContext.init(testing.allocator, &bad_cert));
}

// ─── SNI callback tests ────────────────────────────────────────

test "sniCallbackFn: selects domain context when hostname matches" {
    var sni = try SniContext.init(testing.allocator, &test_default_cert);
    defer sni.deinit();

    try sni.addDomain("example.com", test_cert2_pem, test_key2_pem);
    const example_ctx = sni.domain_contexts.get("example.com").?;

    const ssl = c.SSL_new(sni.default_ctx) orelse return error.TlsHandshakeFailure;
    defer c.SSL_free(ssl);

    _ = c.SSL_set_tlsext_host_name(ssl, "example.com");
    const result = openssl.sniCallbackFn(ssl, null, @ptrCast(&sni));
    try testing.expectEqual(c.SSL_TLSEXT_ERR_OK, result);
    try testing.expectEqual(example_ctx, c.SSL_get_SSL_CTX(ssl));
}

test "sniCallbackFn: falls back to default when hostname not found" {
    var sni = try SniContext.init(testing.allocator, &test_default_cert);
    defer sni.deinit();

    const ssl = c.SSL_new(sni.default_ctx) orelse return error.TlsHandshakeFailure;
    defer c.SSL_free(ssl);

    _ = c.SSL_set_tlsext_host_name(ssl, "unknown.com");
    const result = openssl.sniCallbackFn(ssl, null, @ptrCast(&sni));
    try testing.expectEqual(c.SSL_TLSEXT_ERR_OK, result);
    try testing.expectEqual(sni.default_ctx, c.SSL_get_SSL_CTX(ssl));
}

test "sniCallbackFn: handles null hostname gracefully" {
    var sni = try SniContext.init(testing.allocator, &test_default_cert);
    defer sni.deinit();

    const ssl = c.SSL_new(sni.default_ctx) orelse return error.TlsHandshakeFailure;
    defer c.SSL_free(ssl);

    const result = openssl.sniCallbackFn(ssl, null, @ptrCast(&sni));
    try testing.expectEqual(c.SSL_TLSEXT_ERR_OK, result);
}

test "sniCallbackFn: handles null arg gracefully" {
    var sni = try SniContext.init(testing.allocator, &test_default_cert);
    defer sni.deinit();

    const ssl = c.SSL_new(sni.default_ctx) orelse return error.TlsHandshakeFailure;
    defer c.SSL_free(ssl);

    const result = openssl.sniCallbackFn(ssl, null, null);
    try testing.expectEqual(c.SSL_TLSEXT_ERR_OK, result);
}

test "sniCallbackFn: switches between multiple domains" {
    var sni = try SniContext.init(testing.allocator, &test_default_cert);
    defer sni.deinit();

    try sni.addDomain("a.com", test_cert2_pem, test_key2_pem);
    try sni.addDomain("b.com", test_cert_pem, test_key_pem);
    const a_ctx = sni.domain_contexts.get("a.com").?;
    const b_ctx = sni.domain_contexts.get("b.com").?;

    {
        const ssl = c.SSL_new(sni.default_ctx) orelse return error.TlsHandshakeFailure;
        defer c.SSL_free(ssl);
        _ = c.SSL_set_tlsext_host_name(ssl, "a.com");
        _ = openssl.sniCallbackFn(ssl, null, @ptrCast(&sni));
        try testing.expectEqual(a_ctx, c.SSL_get_SSL_CTX(ssl));
    }
    {
        const ssl = c.SSL_new(sni.default_ctx) orelse return error.TlsHandshakeFailure;
        defer c.SSL_free(ssl);
        _ = c.SSL_set_tlsext_host_name(ssl, "b.com");
        _ = openssl.sniCallbackFn(ssl, null, @ptrCast(&sni));
        try testing.expectEqual(b_ctx, c.SSL_get_SSL_CTX(ssl));
    }
}

// ─── Connection.deinit owns_ctx Tests ──────────────────────────

test "Connection.deinit: frees ctx when owns_ctx is true" {
    const ctx = c.SSL_CTX_new(c.TLS_server_method()) orelse return error.TlsHandshakeFailure;
    const ssl = c.SSL_new(ctx) orelse {
        c.SSL_CTX_free(ctx);
        return error.TlsHandshakeFailure;
    };
    var conn = Connection{
        .ssl = ssl,
        .ctx = ctx,
        .owns_ctx = true,
    };
    conn.deinit();
}

test "Connection.deinit: does not free ctx when owns_ctx is false" {
    const ctx = c.SSL_CTX_new(c.TLS_server_method()) orelse return error.TlsHandshakeFailure;
    defer c.SSL_CTX_free(ctx);

    const ssl = c.SSL_new(ctx) orelse return error.TlsHandshakeFailure;
    var conn = Connection{
        .ssl = ssl,
        .ctx = ctx,
        .owns_ctx = false,
    };
    conn.deinit();

    // Prove ctx is still valid
    const ssl2 = c.SSL_new(ctx) orelse return error.TlsHandshakeFailure;
    c.SSL_free(ssl2);
}

test "Connection.deinit: SniContext survives after connection deinit" {
    var sni = try SniContext.init(testing.allocator, &test_default_cert);
    defer sni.deinit();

    const ssl = c.SSL_new(sni.default_ctx) orelse return error.TlsHandshakeFailure;
    var conn = Connection{
        .ssl = ssl,
        .ctx = sni.default_ctx,
        .owns_ctx = false,
    };
    conn.deinit();

    // SniContext still functional after connection deinit
    try sni.addDomain("after-deinit.com", test_cert2_pem, test_key2_pem);
    try testing.expectEqual(@as(u32, 1), sni.domain_contexts.count());

    const ssl2 = c.SSL_new(sni.default_ctx) orelse return error.TlsHandshakeFailure;
    c.SSL_free(ssl2);
}

// ─── server() function Tests ───────────────────────────────────
// Close the peer end immediately so SSL_accept gets EOF and fails fast.

test "server: with sni_context fails handshake cleanly" {
    var sni = try SniContext.init(testing.allocator, &test_default_cert);
    defer sni.deinit();

    const fds = try makeSocketPair();
    closeFd(fds[1]);
    defer closeFd(fds[0]);

    const result = openssl.server(fds[0], .{ .sni_context = &sni });
    try testing.expectError(error.TlsHandshakeFailure, result);
}

test "server: without sni_context and with auth fails handshake cleanly" {
    const fds = try makeSocketPair();
    closeFd(fds[1]);
    defer closeFd(fds[0]);

    const auth = config.CertKeyPair{
        .cert_pem = test_cert_pem,
        .key_pem = test_key_pem,
        .allocator = undefined,
    };
    const result = openssl.server(fds[0], .{ .auth = &auth });
    try testing.expectError(error.TlsHandshakeFailure, result);
}

test "server: without auth and without sni fails handshake cleanly" {
    const fds = try makeSocketPair();
    closeFd(fds[1]);
    defer closeFd(fds[0]);

    const result = openssl.server(fds[0], .{});
    try testing.expectError(error.TlsHandshakeFailure, result);
}
