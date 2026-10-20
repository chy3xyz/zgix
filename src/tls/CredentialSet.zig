//! A listener's credential set (DESIGN.md §4): one or more certificate
//! chains with the names each serves, selected per handshake by SNI.
//!
//! The set is loaded once at startup and borrowed by every engine on the
//! listener, like the single `Credentials` it replaces. Selection is a
//! bounded scan with no allocation and no parsing: names are either the
//! operator's explicit list or slices of the leaf's own DER, both stable
//! for the process. A name that matches nothing falls back to the first
//! entry, which is also what a client that sent no SNI gets.
//!
//! Matching follows RFC 6125 §6.4: ASCII case-insensitive exact match,
//! or a leftmost `*.` wildcard matching exactly one label. A partial
//! wildcard (`f*.example.com`) is not a wildcard, and neither is one
//! with a dot after the asterisk.

const std = @import("std");
const constants = @import("../constants.zig");

const zssl = @import("zssl");

const Credentials = @import("Credentials.zig");

const assert = std.debug.assert;

const CredentialSet = @This();

entries: []Entry,
/// The entry a client with no SNI, or no match, gets. Always in range:
/// `load` refuses an empty set.
default_index: usize,

pub const Entry = struct {
    credentials: Credentials,
    /// Names this entry serves, as the operator wrote them or as the
    /// leaf's SAN/CN spells them. Slices are stable for the process.
    names: []const []const u8,
};

pub const LoadError = error{
    NoCertificates,
    TooManyCertificates,
    /// An explicit `names` entry was empty.
    EmptyName,
    /// The leaf has no dNSName SAN and no common name to fall back to.
    NoNames,
    /// A leaf could not be parsed for names after `Credentials.load`
    /// accepted it. Should be unreachable: `Credentials.load` already
    /// parses every chain entry.
    MalformedCertificate,
} || Credentials.LoadError || std.mem.Allocator.Error;

/// One configured certificate/key pair, already read from disk.
pub const Source = struct {
    cert_pem: []const u8,
    key_pem: []const u8,
    /// Empty means "derive from the leaf's SAN, then its common name".
    names: []const []const u8 = &.{},
};

/// Parse and load every entry, preserving order. The first entry is the
/// default. `arena` owns the credential set and every name slice for the
/// process; the PEM bytes are only borrowed for the duration of the call.
pub fn load(
    arena: std.mem.Allocator,
    sources: []const Source,
    options: Credentials.Options,
) LoadError!CredentialSet {
    if (sources.len == 0) return error.NoCertificates;
    if (sources.len > constants.tls_certificates_max) {
        return error.TooManyCertificates;
    }

    const entries = try arena.alloc(Entry, sources.len);
    var loaded: usize = 0;
    errdefer for (entries[0..loaded]) |*entry| entry.credentials.deinit();

    for (sources, 0..) |source, index| {
        var credentials = try Credentials.load(
            arena,
            source.cert_pem,
            source.key_pem,
            options,
        );
        errdefer credentials.deinit();

        const names = if (source.names.len > 0)
            try copyNames(arena, source.names)
        else
            try namesFromLeaf(arena, credentials.chain[0]);

        entries[index] = .{ .credentials = credentials, .names = names };
        loaded += 1;
    }

    assert(loaded == sources.len);
    assert(entries.len >= 1);
    return .{ .entries = entries, .default_index = 0 };
}

/// Frees the libcrypto keys. The arena that owns the names and the entry
/// array is the caller's; production lets the process exit instead.
pub fn deinit(set: *CredentialSet) void {
    assert(set.entries.len >= 1);
    for (set.entries) |*entry| entry.credentials.deinit();
    set.* = undefined;
}

/// The credential a client naming `server_name` gets. Null and the empty
/// string are "no SNI"; an unmatched name also falls back, because a
/// listener with one certificate must keep serving.
pub fn select(set: *const CredentialSet, server_name: ?[]const u8) *const Credentials {
    assert(set.entries.len >= 1);
    assert(set.default_index < set.entries.len);
    const raw = server_name orelse return defaultCredentials(set);
    if (raw.len == 0) return defaultCredentials(set);
    const host = trimTrailingDot(raw);
    if (host.len == 0) return defaultCredentials(set);
    for (set.entries) |*entry| {
        for (entry.names) |name| {
            if (nameMatches(name, host)) return &entry.credentials;
        }
    }
    return defaultCredentials(set);
}

pub fn defaultCredentials(set: *const CredentialSet) *const Credentials {
    assert(set.default_index < set.entries.len);
    return &set.entries[set.default_index].credentials;
}

/// zssl's callback adapter. The context is the set itself, which the
/// caller guarantees outlives every engine on the listener.
pub fn selector(set: *const CredentialSet) zssl.ServerHandshake.CredentialSelector {
    return .{
        .context = @ptrCast(@constCast(set)),
        .select = selectCallback,
    };
}

fn selectCallback(context: *anyopaque, server_name: ?[]const u8) ?*const zssl.Credentials {
    const set: *const CredentialSet = @ptrCast(@alignCast(context));
    const credentials: *const Credentials = select(set, server_name);
    return &credentials.inner;
}

/// RFC 6125 §6.4.1/§6.4.3 as `std.crypto.Certificate` implements it:
/// exact, case-insensitive; or `*.suffix` matching exactly one label.
fn nameMatches(pattern: []const u8, host: []const u8) bool {
    assert(pattern.len >= 1);
    assert(host.len >= 1);
    if (std.ascii.eqlIgnoreCase(pattern, host)) return true;
    if (pattern.len < 3 or pattern[0] != '*' or pattern[1] != '.') return false;
    const suffix = pattern[2..];
    // A wildcard is only the leftmost label, and only one.
    if (std.mem.indexOfScalar(u8, suffix, '*') != null) return false;
    const dot = std.mem.indexOfScalar(u8, host, '.') orelse return false;
    if (dot == 0) return false;
    return std.ascii.eqlIgnoreCase(suffix, host[dot + 1 ..]);
}

fn trimTrailingDot(name: []const u8) []const u8 {
    if (name.len > 0 and name[name.len - 1] == '.') return name[0 .. name.len - 1];
    return name;
}

fn copyNames(arena: std.mem.Allocator, names: []const []const u8) ![]const []const u8 {
    assert(names.len >= 1);
    const copy = try arena.alloc([]const u8, names.len);
    for (names, 0..) |name, index| {
        if (name.len == 0) return error.EmptyName;
        copy[index] = try arena.dupe(u8, name);
    }
    return copy;
}

/// The leaf's dNSName SANs, or its common name when the SAN extension has
/// no dNSName. Slices point into the DER, which lives in the arena that
/// owns the credential chain.
fn namesFromLeaf(arena: std.mem.Allocator, leaf_der: []const u8) LoadError![]const []const u8 {
    const certificate: std.crypto.Certificate = .{ .buffer = leaf_der, .index = 0 };
    const parsed = certificate.parse() catch return error.MalformedCertificate;
    var names: std.ArrayList([]const u8) = .empty;
    defer names.deinit(arena);

    const subject_alt_name = parsed.subjectAltName();
    if (subject_alt_name.len == 0) {
        const common_name = parsed.commonName();
        if (common_name.len > 0) try names.append(arena, common_name);
    } else {
        const general_names = std.crypto.Certificate.der.Element.parse(
            subject_alt_name,
            0,
        ) catch return error.MalformedCertificate;
        var index = general_names.slice.start;
        while (index < general_names.slice.end) {
            const general_name = std.crypto.Certificate.der.Element.parse(
                subject_alt_name,
                index,
            ) catch return error.MalformedCertificate;
            index = general_name.slice.end;
            const tag: std.crypto.Certificate.GeneralNameTag =
                @fromBackingInt(@intCast(@backingInt(general_name.identifier.tag)));
            if (tag != .dNSName) continue;
            const dns_name = subject_alt_name[general_name.slice.start..general_name.slice.end];
            if (dns_name.len > 0) try names.append(arena, dns_name);
        }
    }

    if (names.items.len == 0) return error.NoNames;
    return try arena.dupe([]const u8, names.items);
}

const fixture_cert_pem = @embedFile("testdata/cert.pem");
const fixture_key_pem = @embedFile("testdata/key.pem");

test "credential set: the leaf's SAN becomes the name list" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var set = try CredentialSet.load(arena, &.{.{
        .cert_pem = fixture_cert_pem,
        .key_pem = fixture_key_pem,
    }}, .{});
    defer set.deinit();

    try std.testing.expectEqual(@as(usize, 1), set.entries.len);
    try std.testing.expectEqual(@as(usize, 1), set.entries[0].names.len);
    try std.testing.expectEqualStrings("spike.zgix.test", set.entries[0].names[0]);
    try std.testing.expect(select(&set, "spike.zgix.test") == defaultCredentials(&set));
    try std.testing.expect(select(&set, "SPIKE.ZGIX.TEST") == defaultCredentials(&set));
    try std.testing.expect(select(&set, "other.example") == defaultCredentials(&set));
    try std.testing.expect(select(&set, null) == defaultCredentials(&set));
}

test "credential set: explicit names override the certificate" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var set = try CredentialSet.load(arena, &.{
        .{
            .cert_pem = fixture_cert_pem,
            .key_pem = fixture_key_pem,
            .names = &.{"api.example"},
        },
        .{
            .cert_pem = fixture_cert_pem,
            .key_pem = fixture_key_pem,
            .names = &.{ "www.example", "*.wild.example" },
        },
    }, .{});
    defer set.deinit();

    try std.testing.expect(select(&set, "api.example") == &set.entries[0].credentials);
    try std.testing.expect(select(&set, "API.EXAMPLE") == &set.entries[0].credentials);
    try std.testing.expect(select(&set, "www.example") == &set.entries[1].credentials);
    try std.testing.expect(select(&set, "a.wild.example") == &set.entries[1].credentials);
    // One label only, and the apex is not the wildcard.
    try std.testing.expect(select(&set, "a.b.wild.example") == defaultCredentials(&set));
    try std.testing.expect(select(&set, "wild.example") == defaultCredentials(&set));
    // Unknown and absent names take the first entry.
    try std.testing.expect(select(&set, "unknown.example") == defaultCredentials(&set));
    try std.testing.expect(select(&set, null) == defaultCredentials(&set));
    // A trailing dot is the same name.
    try std.testing.expect(select(&set, "api.example.") == &set.entries[0].credentials);
}

test "credential set: partial wildcards are not wildcards" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var set = try CredentialSet.load(arena, &.{
        .{ .cert_pem = fixture_cert_pem, .key_pem = fixture_key_pem, .names = &.{"f*.example"} },
        .{ .cert_pem = fixture_cert_pem, .key_pem = fixture_key_pem, .names = &.{"*.a*.example"} },
    }, .{});
    defer set.deinit();

    try std.testing.expect(select(&set, "foo.example") == defaultCredentials(&set));
    try std.testing.expect(select(&set, "x.a1.example") == defaultCredentials(&set));
}

test "credential set: empty and oversized sets are refused" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    try std.testing.expectError(
        error.NoCertificates,
        CredentialSet.load(arena, &.{}, .{}),
    );

    const too_many = try arena.alloc(CredentialSet.Source, constants.tls_certificates_max + 1);
    for (too_many) |*source| {
        source.* = .{
            .cert_pem = fixture_cert_pem,
            .key_pem = fixture_key_pem,
            .names = &.{"example.test"},
        };
    }
    try std.testing.expectError(
        error.TooManyCertificates,
        CredentialSet.load(arena, too_many, .{}),
    );
}

test "credential set: an empty explicit name is refused" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    try std.testing.expectError(
        error.EmptyName,
        CredentialSet.load(arena, &.{.{
            .cert_pem = fixture_cert_pem,
            .key_pem = fixture_key_pem,
            .names = &.{""},
        }}, .{}),
    );
}
