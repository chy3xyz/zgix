//! Upstream TLS trust anchors (DESIGN.md §4, RFC 9525): a PEM bundle of
//! roots, and the chain/hostname verifier zssl asks the embedder for.
//!
//! zssl proves possession; identity is the embedder's. This is that
//! identity check for an upstream connection: build the presented chain
//! to a configured root, then match the leaf against the server name the
//! cluster configured. Time is passed in rather than read, so a
//! deterministic run can answer the same question twice.
//!
//! The trust anchors are byte-identical roots, not a system store. A
//! deployment that wants the host's bundle reads it into `ca_file`; the
//! absence of ambient trust is deliberate — an upstream identity that
//! depends on whichever CA package the image happened to ship is not a
//! decision this proxy can make for its operator.

const std = @import("std");

const zssl = @import("zssl");

const CertificateList = zssl.certificate_list.CertificateList;

const assert = std.debug.assert;

const TrustStore = @This();

/// DER roots, arena-owned for the process. Never empty once loaded.
roots: []const []const u8,

/// The most certificates a presented chain may carry. RFC 8446 §4.4.2
/// leaves the list unbounded; eight is zssl's own PEM chain bound and
/// enough for leaf + intermediates.
pub const chain_max: usize = 8;

/// Enough for one PEM block's base64 expansion. A certificate chain
/// entry past this is not a chain this build serves.
const pem_block_bytes_max: usize = 16 * 1024;

pub const LoadError = error{
    NoCertificates,
    TooManyCertificates,
    MalformedPem,
    BufferTooSmall,
} || std.mem.Allocator.Error;

/// A bundle past this is not a trust store this build will carry. The
/// count is asserted in the loop rather than left to memory: a PEM file
/// is attacker-adjacent input in a deployment that ships one.
pub const roots_max: usize = 256;

/// Parse every `CERTIFICATE` block in a PEM bundle. Non-certificate
/// blocks are skipped, duplicate roots are dropped, and an empty result
/// is refused: an empty trust store would verify nothing and is far more
/// likely to be the wrong file than an intentional policy.
pub fn load(arena: std.mem.Allocator, pem: []const u8) LoadError!TrustStore {
    var roots: std.ArrayList([]const u8) = .empty;
    defer roots.deinit(arena);
    var rest = pem;
    var blocks: usize = 0;
    while (blocks < roots_max) : (blocks += 1) {
        var storage: [pem_block_bytes_max]u8 = undefined;
        var iterator = zssl.pem.Iterator.init(rest, &storage);
        const block = (iterator.next() catch return error.MalformedPem) orelse break;
        rest = iterator.rest;
        if (!std.mem.eql(u8, block.label, "CERTIFICATE")) continue;
        const der = try arena.dupe(u8, block.der);
        var duplicate = false;
        for (roots.items) |existing| {
            if (std.mem.eql(u8, existing, der)) duplicate = true;
        }
        if (!duplicate) try roots.append(arena, der);
    }
    if (blocks == roots_max) {
        var storage: [pem_block_bytes_max]u8 = undefined;
        var iterator = zssl.pem.Iterator.init(rest, &storage);
        if ((iterator.next() catch return error.MalformedPem) != null) {
            return error.TooManyCertificates;
        }
    }
    if (roots.items.len == 0) return error.NoCertificates;
    return .{ .roots = try arena.dupe([]const u8, roots.items) };
}

/// What a handshake's verifier needs. The store is borrowed, the name is
/// the cluster's `server_name`, and the clock is the caller's.
pub const Context = struct {
    store: *const TrustStore,
    server_name: []const u8,
    now_sec: i64,
};

/// zssl's callback adapter. The context must outlive the handshake that
/// holds it.
pub fn verifier(context: *const Context) zssl.peer_certificate.ChainVerifier {
    return .{
        .context = @ptrCast(@constCast(context)),
        .verify = verifyCallback,
    };
}

fn verifyCallback(context: *anyopaque, chain: CertificateList) bool {
    const ctx: *const Context = @ptrCast(@alignCast(context));
    return ctx.store.verify(chain, ctx.server_name, ctx.now_sec);
}

/// Build the presented chain to a configured root and match the leaf's
/// name. False for any malformed, expired, untrusted, or misnamed chain;
/// the handshake turns that into `error.BadCertificate`.
pub fn verify(
    store: *const TrustStore,
    chain: CertificateList,
    server_name: []const u8,
    now_sec: i64,
) bool {
    assert(store.roots.len >= 1);
    if (server_name.len == 0) return false;

    var presented: [chain_max][]const u8 = undefined;
    var presented_len: usize = 0;
    var iterator = chain.iterator();
    while (iterator.next() catch return false) |entry| {
        if (presented_len == chain_max) return false;
        presented[presented_len] = entry;
        presented_len += 1;
    }
    if (presented_len == 0) return false;

    const leaf = parse(presented[0]) orelse return false;
    leaf.verifyHostName(server_name) catch return false;
    if (!validAt(leaf, now_sec)) return false;

    var current_der = presented[0];
    var depth: usize = 0;
    while (depth < chain_max) : (depth += 1) {
        // A byte-identical root is an anchor: its signature is ours to
        // trust, and `Certificate.verify` against itself proves nothing
        // the bundle did not already state. Its validity still matters.
        const current = parse(current_der) orelse return false;
        for (store.roots) |root| {
            if (std.mem.eql(u8, current_der, root)) return validAt(current, now_sec);
        }

        // Prefer an issuer the peer sent; fall back to the bundle. The
        // order matters only for diagnostics, since either path ends at
        // the same anchor.
        var issuer: ?[]const u8 = null;
        for (presented[0..presented_len]) |candidate| {
            if (std.mem.eql(u8, candidate, current_der)) continue;
            if (issuedBy(current, candidate, now_sec)) {
                issuer = candidate;
                break;
            }
        }
        if (issuer == null) {
            for (store.roots) |candidate| {
                if (std.mem.eql(u8, candidate, current_der)) continue;
                if (issuedBy(current, candidate, now_sec)) {
                    issuer = candidate;
                    break;
                }
            }
        }
        current_der = issuer orelse return false;
    }
    return false;
}

fn parse(der: []const u8) ?std.crypto.Certificate.Parsed {
    const certificate: std.crypto.Certificate = .{ .buffer = der, .index = 0 };
    return certificate.parse() catch null;
}

fn validAt(certificate: std.crypto.Certificate.Parsed, now_sec: i64) bool {
    if (now_sec < 0) return false;
    const now: u64 = @intCast(now_sec);
    return now >= certificate.validity.not_before and
        now <= certificate.validity.not_after;
}

/// Pairwise RFC 5280 check: issuer name, validity and signature. Basic
/// constraints are not checked by `std.crypto.Certificate.verify`; the
/// trust anchor is what bounds this chain, and a deployment that needs
/// path constraints wants a store that enforces them.
fn issuedBy(subject: std.crypto.Certificate.Parsed, issuer_der: []const u8, now_sec: i64) bool {
    const issuer = parse(issuer_der) orelse return false;
    std.crypto.Certificate.verify(subject.certificate, issuer.certificate, now_sec) catch return false;
    return true;
}

// ── tests ──────────────────────────────────────────────────────────────

const fixture_cert_pem = @embedFile("testdata/cert.pem");

/// Inside the fixture's 2026-10-20 .. 2036-10-17 validity window.
const fixture_now: i64 = 1_800_000_000;

test "trust store: a self-signed fixture verifies for its own name" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const store = try TrustStore.load(arena, fixture_cert_pem);
    try std.testing.expectEqual(@as(usize, 1), store.roots.len);

    var der_storage: [4096]u8 = undefined;
    const leaf_der = try pemToDer(fixture_cert_pem, &der_storage);
    var chain_storage: [8192]u8 = undefined;
    const chain = CertificateList.init(try derList(&chain_storage, leaf_der));

    try std.testing.expect(store.verify(chain, "spike.zgix.test", fixture_now));
    try std.testing.expect(store.verify(chain, "SPIKE.ZGIX.TEST", fixture_now));
    try std.testing.expect(!store.verify(chain, "other.example", fixture_now));
    // Outside the fixture's validity window.
    try std.testing.expect(!store.verify(chain, "spike.zgix.test", 0));
}

test "trust store: a certificate outside the bundle is not trusted" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const store = try TrustStore.load(arena, fixture_cert_pem);
    var der_storage: [4096]u8 = undefined;
    const leaf_der = try pemToDer(fixture_cert_pem, &der_storage);
    // Same names and validity, broken signature: the root byte-match is
    // gone and pairwise verification must reject it.
    der_storage[leaf_der.len - 1] ^= 0xff;
    var chain_storage: [8192]u8 = undefined;
    const chain = CertificateList.init(try derList(&chain_storage, leaf_der));

    try std.testing.expect(!store.verify(chain, "spike.zgix.test", fixture_now));
}

test "trust store: an empty bundle is refused" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    try std.testing.expectError(
        error.NoCertificates,
        TrustStore.load(arena_state.allocator(), "not a pem"),
    );
}

/// Test helper: one PEM block's DER, decoded into `storage`.
fn pemToDer(pem: []const u8, storage: []u8) ![]const u8 {
    var iterator = zssl.pem.Iterator.init(pem, storage);
    const block = (try iterator.next()) orelse return error.MalformedPem;
    return block.der;
}

/// Test helper: wrap a single DER entry in the `CertificateList` framing
/// (3-byte length, then the entry, then an empty extensions block).
fn derList(storage: []u8, der: []const u8) ![]const u8 {
    if (der.len > 0xffffff) return error.BufferTooSmall;
    if (storage.len < 3 + der.len + 2) return error.BufferTooSmall;
    storage[0] = @intCast((der.len >> 16) & 0xff);
    storage[1] = @intCast((der.len >> 8) & 0xff);
    storage[2] = @intCast(der.len & 0xff);
    @memcpy(storage[3..][0..der.len], der);
    storage[3 + der.len] = 0;
    storage[4 + der.len] = 0;
    return storage[0 .. 3 + der.len + 2];
}
