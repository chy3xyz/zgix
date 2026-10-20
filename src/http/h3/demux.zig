//! QUIC connection demux table: maps a connection ID — plus the peer
//! address — to the proxy's connection slot (RFC 9000 §5.1).
//!
//! Storage is caller-owned and adopted at init; `insert`, `lookup`,
//! `remove` and `removeSlot` allocate nothing and touch at most eight
//! entries. The demux runs on the receive path, so a lookup must not walk
//! an arbitrarily long cluster of colliding CIDs: the probe bound is part
//! of the contract. A key with no free slot within that window reports
//! `Full` rather than growing the table or scanning further.
//!
//! A zero-length CID (`cid_len == 0`) matches on the peer address alone.
//! RFC 9000 §5.1 lets an endpoint omit connection IDs when it is willing
//! to be identified by its 4-tuple, so an empty CID is not "no key": the
//! address and port *are* the key. A non-empty CID is compared for exactly
//! `cid_len` bytes and combined with the peer, so the same CID seen from
//! two peers names two connections, and bytes past `cid_len` are padding
//! that must not affect identity.
//!
//! Removal leaves a **tombstone** instead of an empty slot. Linear probing
//! cannot clear a slot outright — a later key may sit past it — so the
//! tombstone keeps the probe chain walkable while telling the next
//! insertion that the slot is reusable.

const std = @import("std");

const assert = std.debug.assert;

/// How many slots one lookup, insertion or removal may touch. Past this
/// the table is treated as full: bounded work beats an unbounded cluster.
const probe_max: usize = 8;

/// Longest CID the table accepts. RFC 9000 caps connection IDs at 20 bytes;
/// the length byte itself must also fit in `u8`.
const cid_max: u8 = 20;

/// One demux identity. `cid[0..cid_len]` is meaningful; the rest is
/// padding. `peer` includes the port, because a zero-length CID needs the
/// full 4-tuple to identify a connection.
pub const Key = struct {
    cid: [cid_max]u8 = @splat(0),
    cid_len: u8 = 0,
    peer: std.Io.net.IpAddress = .{ .ip4 = .{ .bytes = @splat(0), .port = 0 } },

    /// Total order-safe equality for any `cid_len`, including an invalid
    /// one: an over-long key matches nothing rather than panicking while
    /// slicing. `IpAddress.eql` compares address and port; it ignores IPv6
    /// flow and interface, which do not distinguish a peer.
    pub fn eql(a: *const Key, b: *const Key) bool {
        if (a.cid_len > cid_max) return false;
        if (b.cid_len > cid_max) return false;
        if (a.cid_len != b.cid_len) return false;
        if (!std.mem.eql(u8, a.cid[0..a.cid_len], b.cid[0..b.cid_len])) return false;
        return std.Io.net.IpAddress.eql(&a.peer, &b.peer);
    }
};

/// One table slot. `empty` terminates a probe chain; `tombstone` is skipped
/// by a lookup and claims the next insertion.
pub const Entry = struct {
    key: Key = .{},
    slot: u16 = 0,
    state: State = .empty,

    pub const State = enum(u2) { empty, occupied, tombstone };
};

pub const Error = error{
    /// No empty slot or tombstone within the probe window.
    Full,
    /// The same key already maps to a slot.
    Duplicate,
    /// `key.cid_len` exceeds `cid_max`.
    CidTooLong,
};

pub const Table = struct {
    entries: []Entry = &.{},

    /// Adopt caller-owned storage and clear it. No allocation happens here
    /// or later; `fromStorage` is the same contract under the name most
    /// call sites read better.
    pub fn init(entries: []Entry) Table {
        return fromStorage(entries);
    }

    pub fn fromStorage(entries: []Entry) Table {
        @memset(entries, .{});
        return .{ .entries = entries };
    }

    /// Map `key` to `slot`. A duplicate is reported before any slot is
    /// changed, so a failed insert leaves the table untouched.
    pub fn insert(table: *Table, key: Key, slot: u16) Error!void {
        if (key.cid_len > cid_max) return error.CidTooLong;
        if (table.entries.len == 0) return error.Full;
        const start: usize = @intCast(hashKey(&key) % table.entries.len);
        const probes = @min(probe_max, table.entries.len);
        assert(start < table.entries.len);
        assert(probes >= 1);
        var first_tombstone: ?usize = null;
        var probe: usize = 0;
        while (probe < probes) : (probe += 1) {
            const index = (start + probe) % table.entries.len;
            const entry = &table.entries[index];
            switch (entry.state) {
                .empty => {
                    // The whole window was scanned before installing, so a
                    // duplicate behind a tombstone cannot be missed.
                    install(table, first_tombstone orelse index, key, slot);
                    return;
                },
                .tombstone => {
                    if (first_tombstone == null) first_tombstone = index;
                },
                .occupied => {
                    assert(entry.key.cid_len <= cid_max);
                    if (entry.key.eql(&key)) return error.Duplicate;
                },
            }
        }
        if (first_tombstone) |index| {
            install(table, index, key, slot);
            return;
        }
        return error.Full;
    }

    /// Resolve `key` to its slot, or null when absent (or unplaceable by
    /// construction, e.g. an over-long CID).
    pub fn lookup(table: *const Table, key: Key) ?u16 {
        const index = findIndex(table, &key) orelse return null;
        const entry = &table.entries[index];
        assert(entry.state == .occupied);
        assert(entry.key.eql(&key));
        return entry.slot;
    }

    /// Tombstone `key`'s entry. Absent keys are a no-op; the tombstone
    /// keeps every probe chain that passed through the slot intact.
    pub fn remove(table: *Table, key: Key) void {
        const index = findIndex(table, &key) orelse return;
        const entry = &table.entries[index];
        assert(entry.state == .occupied);
        assert(entry.key.eql(&key));
        entry.state = .tombstone;
    }

    /// Tombstone every entry pointing at `slot`. Slots are expected to be
    /// unique; removing all matches keeps a bookkeeping slip from leaving
    /// a stale mapping behind. Unknown slots are a no-op.
    pub fn removeSlot(table: *Table, slot: u16) void {
        var removed: usize = 0;
        for (table.entries) |*entry| {
            if (entry.state != .occupied) continue;
            if (entry.slot != slot) continue;
            entry.state = .tombstone;
            removed += 1;
        }
        assert(removed <= table.entries.len);
    }
};

/// Install a validated key and assert the entry it produced.
fn install(table: *Table, index: usize, key: Key, slot: u16) void {
    assert(index < table.entries.len);
    assert(key.cid_len <= cid_max);
    table.entries[index] = .{ .key = key, .slot = slot, .state = .occupied };
    assert(table.entries[index].state == .occupied);
    assert(table.entries[index].slot == slot);
}

/// Locate `key`'s slot index without mutating. Stops at the first empty
/// slot, which is why a tombstone must never be written as empty.
fn findIndex(table: *const Table, key: *const Key) ?usize {
    if (key.cid_len > cid_max) return null;
    if (table.entries.len == 0) return null;
    const start: usize = @intCast(hashKey(key) % table.entries.len);
    const probes = @min(probe_max, table.entries.len);
    assert(start < table.entries.len);
    assert(probes >= 1);
    var probe: usize = 0;
    while (probe < probes) : (probe += 1) {
        const index = (start + probe) % table.entries.len;
        const entry = &table.entries[index];
        switch (entry.state) {
            .empty => return null,
            .tombstone => continue,
            .occupied => {
                assert(entry.key.cid_len <= cid_max);
                if (entry.key.eql(key)) return index;
            },
        }
    }
    return null;
}

/// FNV-1a over the length byte, the meaningful CID bytes, and the peer's
/// family, address and port. Hashing only `cid[0..cid_len]` is what makes
/// padding bytes irrelevant to placement as well as to equality.
fn hashKey(key: *const Key) usize {
    assert(key.cid_len <= cid_max);
    var hash: u64 = 0xcbf29ce484222325;
    hash = hashByte(hash, key.cid_len);
    for (key.cid[0..key.cid_len]) |byte| hash = hashByte(hash, byte);
    switch (key.peer) {
        .ip4 => |peer| {
            hash = hashByte(hash, 4);
            for (peer.bytes) |byte| hash = hashByte(hash, byte);
            hash = hashPort(hash, peer.port);
        },
        .ip6 => |peer| {
            hash = hashByte(hash, 6);
            for (peer.bytes) |byte| hash = hashByte(hash, byte);
            hash = hashPort(hash, peer.port);
        },
    }
    return @truncate(hash);
}

fn hashByte(hash: u64, byte: u8) u64 {
    return (hash ^ byte) *% 0x100000001b3;
}

fn hashPort(hash: u64, port: u16) u64 {
    var bytes: [2]u8 = undefined;
    std.mem.writeInt(u16, &bytes, port, .little);
    return hashByte(hashByte(hash, bytes[0]), bytes[1]);
}

fn testAddress(literal: []const u8) std.Io.net.IpAddress {
    return std.Io.net.IpAddress.parseLiteral(literal) catch unreachable;
}

fn testKey(byte: u8, cid_len: u8, peer: []const u8) Key {
    var cid: [cid_max]u8 = @splat(0);
    if (cid_len <= cid_max) @memset(cid[0..cid_len], byte);
    return .{ .cid = cid, .cid_len = cid_len, .peer = testAddress(peer) };
}

/// A key distinct from byte zero's key but sharing `home`, so tests can
/// exercise probing without hard-coding the hash.
fn collidingKey(home: usize, len: usize, peer: []const u8) ?Key {
    var byte: u16 = 1;
    while (byte < 256) : (byte += 1) {
        const candidate = testKey(@intCast(byte), 8, peer);
        if (hashKey(&candidate) % len == home) return candidate;
    }
    return null;
}

test "demux: insert then lookup, with CID bytes beyond cid_len ignored" {
    var storage: [16]Entry = undefined;
    var table = Table.init(&storage);
    var cid: [cid_max]u8 = @splat(0);
    cid[0..4].* = .{ 1, 2, 3, 4 };
    const key = Key{ .cid = cid, .cid_len = 4, .peer = testAddress("10.0.0.1:443") };
    const other = testKey(9, 8, "10.0.0.1:443");

    try table.insert(key, 7);
    try std.testing.expectEqual(@as(?u16, 7), table.lookup(key));
    try std.testing.expectEqual(@as(?u16, null), table.lookup(other));

    // Same four meaningful bytes, different padding: the same key.
    cid[4] = 0xff;
    const padded = Key{ .cid = cid, .cid_len = 4, .peer = testAddress("10.0.0.1:443") };
    try std.testing.expectEqual(@as(?u16, 7), table.lookup(padded));
    try std.testing.expectError(error.Duplicate, table.insert(padded, 8));
}

test "demux: colliding keys probe past the home slot" {
    var storage: [8]Entry = undefined;
    var table = Table.init(&storage);
    const peer = "10.0.0.1:443";
    const a = testKey(0, 8, peer);
    const home = hashKey(&a) % storage.len;
    const b = collidingKey(home, storage.len, peer) orelse return error.TestUnexpectedResult;
    try std.testing.expect(hashKey(&b) % storage.len == home);

    try table.insert(a, 1);
    try table.insert(b, 2);
    try std.testing.expectEqual(@as(?u16, 1), table.lookup(a));
    try std.testing.expectEqual(@as(?u16, 2), table.lookup(b));
}

test "demux: the probe bound reports Full while empty slots remain" {
    var storage: [16]Entry = undefined;
    var table = Table.init(&storage);
    const peer = "10.0.0.1:443";
    const a = testKey(0, 8, peer);
    const home = hashKey(&a) % storage.len;

    var keys: [probe_max + 1]Key = undefined;
    var found: usize = 0;
    var byte: u16 = 0;
    while (found < keys.len and byte < 256) : (byte += 1) {
        const candidate = testKey(@intCast(byte), 8, peer);
        if (hashKey(&candidate) % storage.len != home) continue;
        keys[found] = candidate;
        found += 1;
    }
    try std.testing.expectEqual(keys.len, found);

    for (keys[0..probe_max], 0..) |key, index| {
        try table.insert(key, @intCast(index));
    }
    try std.testing.expectError(error.Full, table.insert(keys[probe_max], 100));
    // The eight keys already placed are still reachable.
    for (keys[0..probe_max], 0..) |key, index| {
        try std.testing.expectEqual(@as(?u16, @intCast(index)), table.lookup(key));
    }
}

test "demux: remove leaves a tombstone that does not hide a later key" {
    var storage: [8]Entry = undefined;
    var table = Table.init(&storage);
    const peer = "10.0.0.1:443";
    const a = testKey(0, 8, peer);
    const home = hashKey(&a) % storage.len;
    const b = collidingKey(home, storage.len, peer) orelse return error.TestUnexpectedResult;

    try table.insert(a, 1);
    try table.insert(b, 2);
    table.remove(a);
    try std.testing.expectEqual(@as(?u16, null), table.lookup(a));
    // B sits behind A's tombstone; clearing the slot instead would strand it.
    try std.testing.expectEqual(@as(?u16, 2), table.lookup(b));
    table.remove(b);
}

test "demux: a tombstone slot is reused by the next insert" {
    var storage: [2]Entry = undefined;
    var table = Table.init(&storage);
    const a = testKey(0, 8, "10.0.0.1:443");
    const b = testKey(1, 8, "10.0.0.1:443");
    const c = testKey(2, 8, "10.0.0.1:443");

    try table.insert(a, 1);
    try table.insert(b, 2);
    try std.testing.expectError(error.Full, table.insert(c, 3));
    table.remove(a);
    try table.insert(c, 3);
    try std.testing.expectEqual(@as(?u16, 3), table.lookup(c));
    try std.testing.expectEqual(@as(?u16, 2), table.lookup(b));
}

test "demux: zero-length CID matches by peer 4-tuple only" {
    var storage: [8]Entry = undefined;
    var table = Table.init(&storage);
    const peer_a = "10.0.0.1:5000";
    const peer_b = "10.0.0.2:5000";
    const peer_a_other_port = "10.0.0.1:5001";
    const zero_a = testKey(0xff, 0, peer_a);
    const zero_a_padding = testKey(0x00, 0, peer_a);

    try table.insert(zero_a, 4);
    // Padding bytes carry no identity when cid_len is zero.
    try std.testing.expectEqual(@as(?u16, 4), table.lookup(zero_a_padding));
    try std.testing.expectEqual(@as(?u16, null), table.lookup(testKey(0xff, 0, peer_b)));
    try std.testing.expectEqual(@as(?u16, null), table.lookup(testKey(0xff, 0, peer_a_other_port)));

    // A non-empty CID from the same peer is a different connection.
    const with_cid = testKey(0xaa, 8, peer_a);
    try table.insert(with_cid, 5);
    try std.testing.expectEqual(@as(?u16, 4), table.lookup(zero_a));
    try std.testing.expectEqual(@as(?u16, 5), table.lookup(with_cid));
}

test "demux: same CID with different peers is two connections" {
    var storage: [8]Entry = undefined;
    var table = Table.init(&storage);
    const first = testKey(0x42, 8, "10.0.0.1:443");
    const second = testKey(0x42, 8, "10.0.0.2:443");

    try table.insert(first, 1);
    try table.insert(second, 2);
    try std.testing.expectEqual(@as(?u16, 1), table.lookup(first));
    try std.testing.expectEqual(@as(?u16, 2), table.lookup(second));
}

test "demux: duplicate insert reports and leaves the mapping alone" {
    var storage: [8]Entry = undefined;
    var table = Table.init(&storage);
    const key = testKey(0x33, 8, "10.0.0.1:443");
    try table.insert(key, 1);
    try std.testing.expectError(error.Duplicate, table.insert(key, 9));
    try std.testing.expectEqual(@as(?u16, 1), table.lookup(key));
}

test "demux: full table reports Full, and an empty table holds nothing" {
    var storage: [2]Entry = undefined;
    var table = Table.init(&storage);
    try table.insert(testKey(1, 8, "10.0.0.1:443"), 1);
    try table.insert(testKey(2, 8, "10.0.0.1:443"), 2);
    try std.testing.expectError(
        error.Full,
        table.insert(testKey(3, 8, "10.0.0.1:443"), 3),
    );

    var no_storage: [0]Entry = .{};
    var empty_table = Table.init(&no_storage);
    const key = testKey(4, 8, "10.0.0.1:443");
    try std.testing.expectEqual(@as(?u16, null), empty_table.lookup(key));
    try std.testing.expectError(error.Full, empty_table.insert(key, 4));
    empty_table.remove(key);
    empty_table.removeSlot(4);
}

test "demux: removeSlot clears every mapping to a slot" {
    var storage: [8]Entry = undefined;
    var table = Table.init(&storage);
    const first = testKey(0x10, 8, "10.0.0.1:443");
    const second = testKey(0x20, 8, "10.0.0.1:443");
    const survivor = testKey(0x30, 8, "10.0.0.1:443");

    try table.insert(first, 5);
    try table.insert(second, 5);
    try table.insert(survivor, 6);
    table.removeSlot(5);
    try std.testing.expectEqual(@as(?u16, null), table.lookup(first));
    try std.testing.expectEqual(@as(?u16, null), table.lookup(second));
    try std.testing.expectEqual(@as(?u16, 6), table.lookup(survivor));
    // The freed slots are reusable, and an unknown slot is a no-op.
    try table.insert(first, 7);
    table.removeSlot(99);
    try std.testing.expectEqual(@as(?u16, 7), table.lookup(first));
}

test "demux: a CID longer than 20 bytes is rejected without panicking" {
    var storage: [8]Entry = undefined;
    var table = Table.init(&storage);
    const too_long = testKey(0x55, 21, "10.0.0.1:443");
    try std.testing.expectError(error.CidTooLong, table.insert(too_long, 1));
    try std.testing.expectEqual(@as(?u16, null), table.lookup(too_long));
    table.remove(too_long);
    table.removeSlot(1);
}
