//! Per-cluster upstream TLS runtime (DESIGN.md §4): the trust anchors and
//! optional mTLS identity every connection a cluster dials shares, loaded
//! once at startup from the paths the config named.
//!
//! The config layer stays IO-free and carries paths only (§1); this is
//! where they are read, while a failure can still name the file and stop
//! the process rather than surfacing as a broken connection under traffic.
//! `UpstreamTls.Config` borrows the two pieces by pointer and toggles the
//! verification policy on `trust`, so `verify = false` is represented by a
//! null store rather than a store that happens to trust nothing.

const std = @import("std");

const constants = @import("../constants.zig");
const config = @import("../config.zig");

const Credentials = @import("Credentials.zig");
const TrustStore = @import("TrustStore.zig");

const assert = std.debug.assert;

const ClusterTls = @This();

/// One cluster's loaded state. `server_name` is the config's own arena
/// string; the trust store's roots are arena-owned too, so only the
/// client credentials — whose keys live in libcrypto — need freeing.
pub const Runtime = struct {
    server_name: []const u8,
    /// Present exactly when the config asked for verification.
    trust: ?TrustStore = null,
    /// The mTLS identity, present when the config names a client pair.
    client_credentials: ?Credentials = null,

    pub fn deinit(runtime: *Runtime) void {
        if (runtime.client_credentials) |*credentials| credentials.deinit();
        runtime.* = undefined;
    }
};

/// The caller's file reader, so a test can answer from embedded fixtures
/// without touching the filesystem. `load` supplies the real one.
const Reader = struct {
    context: *const anyopaque,
    read: *const fn (
        context: *const anyopaque,
        allocator: std.mem.Allocator,
        path: []const u8,
    ) anyerror![]const u8,
};

const ReadContext = struct {
    io: std.Io,
};

/// Read the files this cluster's TLS block names and build its runtime.
/// Paths are used exactly as the config wrote them: absolute stays
/// absolute, relative resolves against the working directory.
pub fn load(arena: std.mem.Allocator, io: std.Io, tls: config.Config.Cluster.Tls) !Runtime {
    assert(tls.server_name.len >= 1);
    const context: ReadContext = .{ .io = io };
    return loadWith(arena, tls, .{
        .context = @ptrCast(&context),
        .read = readCwdFile,
    });
}

fn loadWith(
    arena: std.mem.Allocator,
    tls: config.Config.Cluster.Tls,
    reader: Reader,
) !Runtime {
    assert(tls.server_name.len >= 1);
    var runtime: Runtime = .{ .server_name = tls.server_name };
    errdefer runtime.deinit();

    // `verify = false` skips the bundle entirely even when the config
    // carries one: the policy, not the file, is what decides whether an
    // origin identity is checked.
    if (tls.verify) {
        const ca_path = tls.ca_file orelse return error.CaFileMissing;
        const ca_pem = try readPem(arena, reader, ca_path);
        runtime.trust = TrustStore.load(arena, ca_pem) catch |err| {
            std.debug.print(
                "zgix: cannot load upstream CA bundle '{s}': {t}\n",
                .{ ca_path, err },
            );
            return err;
        };
    }

    if (tls.client_cert_path) |cert_path| {
        const key_path = tls.client_key_path orelse return error.ClientKeyMissing;
        const cert_pem = try readPem(arena, reader, cert_path);
        const key_pem = try readPem(arena, reader, key_path);
        // Same loader as a listener's certificates, so the ECDSA-only
        // rule (§4) is enforced in one place for both directions.
        runtime.client_credentials = Credentials.load(arena, cert_pem, key_pem, .{}) catch |err| {
            std.debug.print(
                "zgix: cannot load upstream client certificate '{s}' and key '{s}': {t}\n",
                .{ cert_path, key_path, err },
            );
            return err;
        };
    } else {
        assert(tls.client_key_path == null);
    }
    return runtime;
}

fn readCwdFile(
    context: *const anyopaque,
    allocator: std.mem.Allocator,
    path: []const u8,
) anyerror![]const u8 {
    const cwd: *const ReadContext = @ptrCast(@alignCast(context));
    return std.Io.Dir.cwd().readFileAlloc(
        cwd.io,
        path,
        allocator,
        .limited(constants.tls_pem_bytes_max),
    ) catch |err| {
        // The operator's own text, named here where the read happened —
        // the loader's error says what, not which file.
        std.debug.print("zgix: cannot read upstream TLS file '{s}': {t}\n", .{ path, err });
        return err;
    };
}

fn readPem(arena: std.mem.Allocator, reader: Reader, path: []const u8) ![]const u8 {
    assert(path.len >= 1);
    return reader.read(reader.context, arena, path);
}

// ── tests ──────────────────────────────────────────────────────────────

const fixture_cert_pem = @embedFile("testdata/cert.pem");
const fixture_key_pem = @embedFile("testdata/key.pem");

const Fixture = struct {
    path: []const u8,
    bytes: []const u8,
};

const FixtureTable = struct {
    items: []const Fixture,
};

fn readFixture(
    context: *const anyopaque,
    allocator: std.mem.Allocator,
    path: []const u8,
) anyerror![]const u8 {
    const table: *const FixtureTable = @ptrCast(@alignCast(context));
    for (table.items) |fixture| {
        if (std.mem.eql(u8, fixture.path, path)) return try allocator.dupe(u8, fixture.bytes);
    }
    return error.FileNotFound;
}

fn readerFor(table: *const FixtureTable) Reader {
    return .{ .context = @ptrCast(table), .read = readFixture };
}

test "cluster tls: verify=false reads nothing and trusts nothing" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const table: FixtureTable = .{ .items = &.{} };

    var runtime = try ClusterTls.loadWith(arena_state.allocator(), .{
        .server_name = "origin.example",
        .ca_file = "/unused.pem",
        .verify = false,
    }, readerFor(&table));
    defer runtime.deinit();

    try std.testing.expectEqualStrings("origin.example", runtime.server_name);
    try std.testing.expect(runtime.trust == null);
    try std.testing.expect(runtime.client_credentials == null);
}

test "cluster tls: a CA bundle loads a trust store for the configured name" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const table: FixtureTable = .{ .items = &.{
        .{ .path = "/ca.pem", .bytes = fixture_cert_pem },
    } };

    var runtime = try ClusterTls.loadWith(arena_state.allocator(), .{
        .server_name = "spike.zgix.test",
        .ca_file = "/ca.pem",
        .verify = true,
    }, readerFor(&table));
    defer runtime.deinit();

    try std.testing.expectEqualStrings("spike.zgix.test", runtime.server_name);
    try std.testing.expect(runtime.trust != null);
    try std.testing.expectEqual(@as(usize, 1), runtime.trust.?.roots.len);
    try std.testing.expect(runtime.client_credentials == null);
}

test "cluster tls: a client pair loads an ECDSA identity" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const table: FixtureTable = .{ .items = &.{
        .{ .path = "/client.pem", .bytes = fixture_cert_pem },
        .{ .path = "/client.key", .bytes = fixture_key_pem },
    } };

    var runtime = try ClusterTls.loadWith(arena_state.allocator(), .{
        .server_name = "spike.zgix.test",
        .client_cert_path = "/client.pem",
        .client_key_path = "/client.key",
        .verify = false,
    }, readerFor(&table));
    defer runtime.deinit();

    try std.testing.expect(runtime.trust == null);
    try std.testing.expect(runtime.client_credentials != null);
    try std.testing.expectEqual(
        @import("zssl").backend.SignatureScheme.ecdsa_secp256r1_sha256,
        runtime.client_credentials.?.scheme(),
    );
}

test "cluster tls: a missing CA bundle is refused by path" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const table: FixtureTable = .{ .items = &.{} };

    try std.testing.expectError(
        error.FileNotFound,
        ClusterTls.loadWith(arena_state.allocator(), .{
            .server_name = "origin.example",
            .ca_file = "/missing.pem",
            .verify = true,
        }, readerFor(&table)),
    );
}

test "cluster tls: verify=true without a CA path is refused before any read" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const table: FixtureTable = .{ .items = &.{} };

    try std.testing.expectError(
        error.CaFileMissing,
        ClusterTls.loadWith(arena_state.allocator(), .{
            .server_name = "origin.example",
            .verify = true,
        }, readerFor(&table)),
    );
}

test "cluster tls: a client certificate without its key is refused" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const table: FixtureTable = .{ .items = &.{
        .{ .path = "/client.pem", .bytes = fixture_cert_pem },
    } };

    try std.testing.expectError(
        error.ClientKeyMissing,
        ClusterTls.loadWith(arena_state.allocator(), .{
            .server_name = "origin.example",
            .client_cert_path = "/client.pem",
            .verify = false,
        }, readerFor(&table)),
    );
}
