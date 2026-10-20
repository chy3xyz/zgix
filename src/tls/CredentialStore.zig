//! Certificate rotation storage (DESIGN.md §4): a bounded set of
//! credential generations, preallocated at startup, swapped on SIGHUP.
//!
//! A handshake borrows its listener's `CredentialSet` by pointer for the
//! session's life, so a reload cannot free the set it replaces. Instead
//! every generation is retained: the new one becomes active for new
//! handshakes, the old one serves the handshakes already in flight, and
//! neither is freed until the process exits. `tls_reload_generations_max`
//! bounds that history; past it a reload is refused rather than growing
//! the arena without limit.
//!
//! Everything a generation needs is reserved at startup: a fixed-buffer
//! allocator per generation holds the decoded chains, name arrays and
//! explicit-name copies, and two scratch buffers hold the PEM text while
//! it is parsed. Reading files is the caller's callback, so this module
//! stays IO-free and a test can feed embedded fixtures.

const std = @import("std");
const constants = @import("../constants.zig");

const zssl = @import("zssl");

const Credentials = @import("Credentials.zig");
const CredentialSet = @import("CredentialSet.zig");

const assert = std.debug.assert;

const CredentialStore = @This();

const generations_max = constants.tls_reload_generations_max;
const pem_bytes_max = constants.tls_pem_bytes_max;

/// One listener's certificate paths, in the order the config wrote them.
pub const CertificatePath = struct {
    cert_path: []const u8,
    key_path: []const u8,
    names: []const []const u8,
};

/// A listener's plan: null for plaintext, or the certificate list for a
/// terminating listener.
pub const ListenerPlan = ?[]const CertificatePath;

/// The caller's file reader. `allocator` is a fixed-buffer allocator owned
/// by the store; the returned bytes must point into its memory and need
/// only survive until `CredentialSet.load` returns. `StreamTooLong` is
/// mapped to `FileTooLarge` by the implementation.
pub const Reader = struct {
    context: *anyopaque,
    read: *const fn (
        context: *anyopaque,
        allocator: std.mem.Allocator,
        path: []const u8,
    ) ReadError![]const u8,
};

pub const ReadError = error{
    FileUnreadable,
    FileTooLarge,
    OutOfMemory,
};

pub const LoadError = ReadError || CredentialSet.LoadError || error{
    NoTlsListeners,
    AlreadyInitialized,
    ReloadBudgetExhausted,
};

const Generation = struct {
    /// The fixed-buffer region this generation's credentials live in.
    buffer: []u8,
    fba: std.heap.FixedBufferAllocator,
    /// One slot per listener, in listener order.
    sets: []?CredentialSet,
};

/// Enough for `tls_certificates_max` chains plus their entry/name arrays.
/// The chain storage is zssl's own bound, not zgix's wire bound: that is
/// what `Credentials.load` allocates from the allocator it is handed.
/// 2 KiB of slack per certificate covers the chain slice array, explicit
/// names and SAN slices; the extra 8 KiB covers the entry array itself.
pub const per_listener_bytes: usize =
    @as(usize, constants.tls_certificates_max) *
    (@as(usize, zssl.Credentials.chain_bytes_max) + 2048) + 8192;

/// What one process reserves for rotation, for the banner: every
/// generation times every TLS listener, plus the two PEM scratch halves.
pub fn reservedBytes(tls_listeners: usize) usize {
    assert(tls_listeners >= 1);
    return @as(usize, generations_max) * tls_listeners * per_listener_bytes +
        2 * @as(usize, pem_bytes_max);
}

plans: []const ListenerPlan,
generations: []Generation,
scratch: []u8,
reader: Reader,
options: Credentials.Options,
/// Index into `generations` that new handshakes use, or null before
/// `initial`.
active: ?usize = null,
/// How many generations have been loaded. The next reload uses this.
used: usize = 0,
/// Where the last failed load stopped, for the application's message.
last_listener: usize = 0,
last_certificate: usize = 0,

/// Reserve every generation and the PEM scratch. Does not load anything;
/// `initial` does, so the caller can report a failure before serving.
pub fn init(
    arena: std.mem.Allocator,
    plans: []const ListenerPlan,
    reader: Reader,
    options: Credentials.Options,
) LoadError!CredentialStore {
    assert(plans.len >= 1);
    var tls_listeners: usize = 0;
    for (plans) |plan| {
        if (plan != null) tls_listeners += 1;
    }
    if (tls_listeners == 0) return error.NoTlsListeners;

    const storage = try arena.alloc(
        u8,
        @as(usize, generations_max) * tls_listeners * per_listener_bytes,
    );
    const generations = try arena.alloc(Generation, generations_max);
    const per_generation = tls_listeners * per_listener_bytes;
    for (generations, 0..) |*generation, index| {
        const buffer = storage[index * per_generation ..][0..per_generation];
        const sets = try arena.alloc(?CredentialSet, plans.len);
        @memset(sets, null);
        generation.* = .{
            .buffer = buffer,
            .fba = std.heap.FixedBufferAllocator.init(buffer),
            .sets = sets,
        };
    }
    const scratch = try arena.alloc(u8, 2 * @as(usize, pem_bytes_max));
    return .{
        .plans = plans,
        .generations = generations,
        .scratch = scratch,
        .reader = reader,
        .options = options,
    };
}

/// Load generation zero and make it active.
pub fn initial(store: *CredentialStore) LoadError![]const ?CredentialSet {
    if (store.active != null) return error.AlreadyInitialized;
    try store.loadGeneration(0);
    store.active = 0;
    store.used = 1;
    return store.activeSets();
}

/// Load the next generation and make it active. On error the previous
/// generation stays active and the failed generation's storage is reset.
pub fn reload(store: *CredentialStore) LoadError![]const ?CredentialSet {
    if (store.active == null) return error.AlreadyInitialized;
    if (store.used >= store.generations.len) return error.ReloadBudgetExhausted;
    const next = store.used;
    try store.loadGeneration(next);
    store.active = next;
    store.used += 1;
    return store.activeSets();
}

/// The sets new handshakes should use. Borrowed for the process's life.
pub fn activeSets(store: *const CredentialStore) []const ?CredentialSet {
    const active = store.active orelse return &.{};
    assert(active < store.generations.len);
    return store.generations[active].sets;
}

/// Frees libcrypto keys. The arena owns the buffers; production lets the
/// process exit instead.
pub fn deinit(store: *CredentialStore) void {
    for (store.generations) |*generation| {
        for (generation.sets) |*slot| {
            if (slot.*) |*set| {
                set.deinit();
                slot.* = null;
            }
        }
    }
    store.* = undefined;
}

fn loadGeneration(store: *CredentialStore, index: usize) LoadError!void {
    assert(index < store.generations.len);
    const generation = &store.generations[index];
    generation.fba.reset();
    for (generation.sets) |*slot| slot.* = null;
    var loaded: usize = 0;
    errdefer {
        for (generation.sets[0..loaded]) |*slot| {
            if (slot.*) |*set| set.deinit();
        }
        for (generation.sets) |*slot| slot.* = null;
        generation.fba.reset();
    }
    const allocator = generation.fba.allocator();
    for (store.plans, 0..) |plan, listener_index| {
        const certificates = plan orelse continue;
        store.last_listener = listener_index;
        store.last_certificate = 0;
        const sources = try allocator.alloc(CredentialSet.Source, certificates.len);
        for (certificates, 0..) |certificate, certificate_index| {
            store.last_certificate = certificate_index;
            const cert_pem = try store.readPem(certificate.cert_path, 0);
            const key_pem = try store.readPem(certificate.key_path, 1);
            sources[certificate_index] = .{
                .cert_pem = cert_pem,
                .key_pem = key_pem,
                .names = certificate.names,
            };
        }
        generation.sets[listener_index] = try CredentialSet.load(
            allocator,
            sources,
            store.options,
        );
        loaded += 1;
    }
}

/// One PEM read into half of the scratch. The two halves are read before
/// `CredentialSet.load`, which copies what it keeps, so reusing them for
/// the next certificate is safe.
fn readPem(store: *CredentialStore, path: []const u8, which: u2) LoadError![]const u8 {
    assert(which <= 1);
    assert(path.len >= 1);
    const half = @as(usize, pem_bytes_max);
    const buffer = store.scratch[@as(usize, which) * half ..][0..half];
    var fba = std.heap.FixedBufferAllocator.init(buffer);
    return store.reader.read(store.reader.context, fba.allocator(), path);
}

// ── tests ──────────────────────────────────────────────────────────────

const fixture_cert_pem = @embedFile("testdata/cert.pem");
const fixture_key_pem = @embedFile("testdata/key.pem");

const TestFiles = struct {
    fail: bool = false,

    fn read(
        context: *anyopaque,
        allocator: std.mem.Allocator,
        path: []const u8,
    ) ReadError![]const u8 {
        const files: *TestFiles = @ptrCast(@alignCast(context));
        if (files.fail) return error.FileUnreadable;
        const bytes = if (std.mem.endsWith(u8, path, "key.pem"))
            fixture_key_pem
        else
            fixture_cert_pem;
        return try allocator.dupe(u8, bytes);
    }
};

fn testStore(arena: std.mem.Allocator, names: []const []const u8) !CredentialStore {
    const plans = try arena.alloc(ListenerPlan, 1);
    const paths = try arena.alloc(CertificatePath, 1);
    paths[0] = .{
        .cert_path = "cert.pem",
        .key_path = "key.pem",
        .names = names,
    };
    plans[0] = paths;
    const files = try arena.create(TestFiles);
    files.* = .{};
    const reader: Reader = .{ .context = files, .read = TestFiles.read };
    return CredentialStore.init(arena, plans, reader, .{});
}

test "credential store: initial load and a reload keep both generations" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var store = try testStore(arena, &.{"api.example"});
    defer store.deinit();
    const first = try store.initial();
    try std.testing.expectEqual(@as(usize, 1), first.len);
    try std.testing.expect(first[0] != null);
    try std.testing.expectEqualStrings("api.example", first[0].?.entries[0].names[0]);

    const second = try store.reload();
    try std.testing.expectEqual(@as(usize, 1), second.len);
    try std.testing.expect(second[0] != null);
    // The new generation is a distinct set; the old one is still readable
    // for handshakes that acquired it before the swap.
    try std.testing.expect(second[0].?.entries.ptr != first[0].?.entries.ptr);
    try std.testing.expectEqualStrings("api.example", first[0].?.entries[0].names[0]);
}

test "credential store: the generation budget is finite" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var store = try testStore(arena, &.{"api.example"});
    defer store.deinit();
    _ = try store.initial();
    var reloads: usize = 0;
    while (store.reload()) |_| {
        reloads += 1;
        try std.testing.expect(reloads < generations_max);
    } else |err| switch (err) {
        error.ReloadBudgetExhausted => {},
        else => return err,
    }
    try std.testing.expectEqual(
        @as(usize, generations_max) - 1,
        reloads,
    );
}

test "credential store: a full certificate set fits one generation" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const count = @as(usize, constants.tls_certificates_max);
    const plans = try arena.alloc(ListenerPlan, 1);
    const paths = try arena.alloc(CertificatePath, count);
    for (paths) |*path| {
        path.* = .{
            .cert_path = "cert.pem",
            .key_path = "key.pem",
            .names = &.{"example.test"},
        };
    }
    plans[0] = paths;
    const files = try arena.create(TestFiles);
    files.* = .{};
    const reader: Reader = .{ .context = files, .read = TestFiles.read };

    var store = try CredentialStore.init(arena, plans, reader, .{});
    defer store.deinit();
    const first = try store.initial();
    try std.testing.expectEqual(@as(usize, 1), first.len);
    try std.testing.expectEqual(count, first[0].?.entries.len);
    // The next generation has its own reservation; a full set must fit
    // there too, or the bound advertised at startup is not the bound.
    const second = try store.reload();
    try std.testing.expectEqual(count, second[0].?.entries.len);
}

test "credential store: a failed reload keeps the old generation active" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var files: TestFiles = .{};
    const plans = try arena.alloc(ListenerPlan, 1);
    const paths = try arena.alloc(CertificatePath, 1);
    paths[0] = .{
        .cert_path = "cert.pem",
        .key_path = "key.pem",
        .names = &.{"api.example"},
    };
    plans[0] = paths;
    const reader: Reader = .{ .context = &files, .read = TestFiles.read };

    var store = try CredentialStore.init(arena, plans, reader, .{});
    defer store.deinit();
    const active = try store.initial();

    files.fail = true;
    try std.testing.expectError(error.FileUnreadable, store.reload());
    try std.testing.expect(store.activeSets().ptr == active.ptr);
    try std.testing.expectEqualStrings("api.example", store.activeSets()[0].?.entries[0].names[0]);
}

test "credential store: a store with no TLS listener is refused" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const plans = try arena.alloc(ListenerPlan, 1);
    plans[0] = null;
    var files: TestFiles = .{};
    const reader: Reader = .{ .context = &files, .read = TestFiles.read };
    try std.testing.expectError(
        error.NoTlsListeners,
        CredentialStore.init(arena, plans, reader, .{}),
    );
}
