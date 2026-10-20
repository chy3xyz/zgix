//! Listener-level per-client concurrent-connection cap (§7, §5): nginx's
//! `limit_conn`, with the same bounded-state discipline as the token
//! bucket next door.
//!
//! The table is fixed-size open addressing over an arena slice allocated
//! once at startup. `admit` and `release` touch at most `probe_max`
//! entries, allocate nothing and cannot block.
//!
//! Identity is `rate_limit.keyOf`: an IPv4 client is its /32, an IPv6
//! client its /64. Sharing that function is the point — a connection cap
//! that disagreed with the rate limiter about who a client is would
//! enforce a different policy on the same traffic.
//!
//! A released identity leaves a **tombstone** rather than an empty slot.
//! Linear probing cannot simply clear a slot — a later key may sit past
//! it — so the tombstone keeps the probe chain intact while telling the
//! next insertion that the slot is reusable. A table that cannot place a
//! new client fails **open**: letting a connection through and counting
//! `l7_conn_limit_full` is preferable to an outage caused by a width
//! bound.

const std = @import("std");

const rate_limit = @import("rate_limit.zig");

const assert = std.debug.assert;

/// One identity's slot. `State.empty` terminates a probe; `tombstone` is
/// skipped by a lookup and claims the next insertion.
pub const Entry = struct {
    key: rate_limit.Key = .{ .bits = 0, .family = .ipv4 },
    count: u32 = 0,
    state: State = .empty,

    pub const State = enum(u2) { empty, occupied, tombstone };
};

/// How many slots one lookup or insertion may touch. Same bound and same
/// argument as the rate limiter's: past it, fail open.
const probe_max: usize = 8;

/// What one admission decided. `table_full` is an *allow*: named apart so
/// the caller can count the fail-open instead of mistaking it for an
/// ordinary allowance.
pub const Verdict = enum(u2) {
    allowed,
    limited,
    table_full,
};

pub const Table = struct {
    entries: []Entry = &.{},

    /// Reserve `count` entries from the startup arena. Zero is the
    /// feature being off and reserves nothing, like every other optional
    /// pool.
    pub fn init(arena: std.mem.Allocator, count: u32) error{OutOfMemory}!Table {
        if (count == 0) return .{};
        const entries = try arena.alloc(Entry, count);
        return fromStorage(entries);
    }

    /// Adopt caller-owned storage — the shape the tests use with a stack
    /// array and `init` uses with the arena slice.
    pub fn fromStorage(entries: []Entry) Table {
        @memset(entries, .{});
        return .{ .entries = entries };
    }

    /// One connection's first admitted request. `allowed` increments the
    /// identity's count (at most once per connection — the caller owns
    /// that half of the contract). A table with no slot in reach allows
    /// without counting, so the matching `release` is never called.
    pub fn admit(
        table: *Table,
        client: *const std.Io.net.IpAddress,
        max: u32,
    ) Verdict {
        assert(max >= 1);
        // A table that was never reserved cannot track anyone. Failing
        // open is still the answer: refusing traffic because an operator
        // under-provisioned a table would be the outage this avoids.
        if (table.entries.len == 0) return .table_full;
        const key = rate_limit.keyOf(client);
        const start = hashKey(key) % table.entries.len;
        const probes = @min(probe_max, table.entries.len);
        var first_tombstone: ?usize = null;
        var probe: usize = 0;
        while (probe < probes) : (probe += 1) {
            const index = (start + probe) % table.entries.len;
            const entry = &table.entries[index];
            switch (entry.state) {
                .empty => {
                    install(table, first_tombstone orelse index, key);
                    return .allowed;
                },
                .tombstone => {
                    if (first_tombstone == null) first_tombstone = index;
                },
                .occupied => {
                    if (!key.eql(entry.key)) continue;
                    if (entry.count >= max) return .limited;
                    entry.count += 1;
                    return .allowed;
                },
            }
        }
        if (first_tombstone) |index| {
            install(table, index, key);
            return .allowed;
        }
        return .table_full;
    }

    /// A counted connection closed. Decrement its identity; a count that
    /// reaches zero becomes a tombstone so the slot can be reused without
    /// breaking another key's probe chain. An identity the table never
    /// held (a fail-open admission, or a release raced by nothing) is a
    /// no-op.
    pub fn release(table: *Table, client: *const std.Io.net.IpAddress) void {
        if (table.entries.len == 0) return;
        const key = rate_limit.keyOf(client);
        const start = hashKey(key) % table.entries.len;
        const probes = @min(probe_max, table.entries.len);
        var probe: usize = 0;
        while (probe < probes) : (probe += 1) {
            const entry = &table.entries[(start + probe) % table.entries.len];
            switch (entry.state) {
                .empty => return,
                .tombstone => continue,
                .occupied => {
                    if (!key.eql(entry.key)) continue;
                    assert(entry.count >= 1);
                    entry.count -= 1;
                    if (entry.count == 0) entry.state = .tombstone;
                    return;
                },
            }
        }
    }
};

fn install(table: *Table, index: usize, key: rate_limit.Key) void {
    const entry = &table.entries[index];
    entry.* = .{ .key = key, .count = 1, .state = .occupied };
}

/// FNV-1a over the eight key bytes and the family tag. The family tag is
/// folded in so an IPv4 key cannot land on the same home slot as an IPv6
/// key with the same high bits, which would turn every probe into a
/// family mismatch.
fn hashKey(key: rate_limit.Key) usize {
    var hash: u64 = 0xcbf29ce484222325;
    var bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &bytes, key.bits, .little);
    for (bytes) |byte| {
        hash ^= byte;
        hash *%= 0x100000001b3;
    }
    hash ^= @backingInt(key.family);
    hash *%= 0x100000001b3;
    return @intCast(hash);
}

fn testAddress(comptime literal: []const u8) std.Io.net.IpAddress {
    return std.Io.net.IpAddress.parseLiteral(literal) catch unreachable;
}

test "conn limit: one identity counts up and refuses past max" {
    var storage: [16]Entry = undefined;
    var table = Table.fromStorage(&storage);
    const c = testAddress("10.0.0.1:40000");
    try std.testing.expectEqual(Verdict.allowed, table.admit(&c, 2));
    try std.testing.expectEqual(Verdict.allowed, table.admit(&c, 2));
    try std.testing.expectEqual(Verdict.limited, table.admit(&c, 2));
}

test "conn limit: release hands capacity back and reuse keeps the chain" {
    var storage: [16]Entry = undefined;
    var table = Table.fromStorage(&storage);
    const a = testAddress("10.0.0.1:40000");
    const b = testAddress("10.0.0.2:40000");
    try std.testing.expectEqual(Verdict.allowed, table.admit(&a, 1));
    try std.testing.expectEqual(Verdict.limited, table.admit(&a, 1));
    // B is unaffected by A's bucket.
    try std.testing.expectEqual(Verdict.allowed, table.admit(&b, 1));
    table.release(&a);
    // A's slot is a tombstone now; A admits again, and B still resolves.
    try std.testing.expectEqual(Verdict.allowed, table.admit(&a, 1));
    try std.testing.expectEqual(Verdict.limited, table.admit(&b, 1));
    table.release(&b);
    table.release(&a);
    try std.testing.expectEqual(Verdict.allowed, table.admit(&b, 1));
}

test "conn limit: a one-slot table fails open, then reuses the tombstone" {
    var storage: [1]Entry = undefined;
    var table = Table.fromStorage(&storage);
    const a = testAddress("10.0.0.1:40000");
    const b = testAddress("10.0.0.2:40000");
    try std.testing.expectEqual(Verdict.allowed, table.admit(&a, 4));
    try std.testing.expectEqual(Verdict.table_full, table.admit(&b, 4));
    table.release(&a);
    try std.testing.expectEqual(Verdict.allowed, table.admit(&b, 4));
}

test "conn limit: IPv4 and IPv6 identities are independent" {
    var storage: [16]Entry = undefined;
    var table = Table.fromStorage(&storage);
    const v4 = testAddress("10.0.0.1:40000");
    const v6 = testAddress("[2001:db8::1]:40000");
    try std.testing.expectEqual(Verdict.allowed, table.admit(&v4, 1));
    try std.testing.expectEqual(Verdict.allowed, table.admit(&v6, 1));
    try std.testing.expectEqual(Verdict.limited, table.admit(&v4, 1));
    try std.testing.expectEqual(Verdict.limited, table.admit(&v6, 1));
}

test "conn limit: releasing an unknown identity is a no-op" {
    var storage: [8]Entry = undefined;
    var table = Table.fromStorage(&storage);
    const a = testAddress("10.0.0.1:40000");
    table.release(&a);
    for (table.entries) |entry| {
        try std.testing.expectEqual(Entry.State.empty, entry.state);
    }
    try std.testing.expectEqual(Verdict.allowed, table.admit(&a, 1));
}
