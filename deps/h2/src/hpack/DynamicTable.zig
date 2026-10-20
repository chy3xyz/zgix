//! RFC 7541 section 2.3.2: the dynamic table, as caller-owned storage.
//!
//! ## Why the storage is the caller's
//!
//! A dynamic table is connection-lifetime, per-direction state — 4 KiB each way
//! at the default `SETTINGS_HEADER_TABLE_SIZE`. That is the opposite shape from
//! everything else a proxy pools, which is sized for concurrent *activity*, so
//! where it comes from is a decision only the consumer can make. This type
//! takes two slices and never asks for more.
//!
//! It also makes a table of capacity zero an ordinary configuration rather than
//! a degenerate one: empty slices, no storage, and every insert immediately
//! evicts itself per section 4.4. A decoder advertising
//! `SETTINGS_HEADER_TABLE_SIZE = 0` forbids the peer from indexing at all,
//! which deletes this half of the decoder's work — a lever worth being able to
//! pull without a code path of its own.
//!
//! ## Layout
//!
//! Bytes live in one arena and entries in one ring. Insertion and eviction are
//! both FIFO — newest in at one end, oldest out at the other — so the live
//! bytes are always a single contiguous span, and an entry is never split.
//!
//! When an insert would run past the end of the arena, the live span is
//! compacted back to offset zero and the entry offsets are rebased. The
//! alternative, letting entries wrap, would mean a name arriving in two pieces
//! and every reader having to care; it would also need the arena to be twice
//! the capacity to stay contiguous on read, and the capacity is the number a
//! consumer writes its memory budget in.
//!
//! Compaction is amortized but not free, and the constant is worth stating
//! honestly rather than as "about one". A compaction moves the live span, `L`
//! octets, and leaves the write cursor at `L` — so the next one cannot happen
//! until another `C - L` octets have been inserted, where `C` is the arena.
//! That is `L / (C - L)` octets moved per octet stored, and `L` is a peer's
//! choice: it picks the header sizes.
//!
//! At the 4 KiB default the worst shape a peer can pick is entries of roughly
//! 260 octets, giving 13 live entries, 3380 live octets, and one compaction
//! every two inserts — about 6.5x. At `capacity_max` it is worse: entries of
//! roughly 1600 octets give 40 live and a compaction on *every* insert, moving
//! 64000 octets to store 1600, about 40x.
//!
//! Both are constant factors, so the amortization holds and the work stays
//! O(1) per insert. It is memory bandwidth rather than an unbounded loop. But
//! it is the reason a consumer sizes this table for its traffic instead of
//! handing over `capacity_max` because it can.
//!
//! ## Lifetime
//!
//! `get` returns slices into the arena, valid only until the next insert or
//! capacity change — a later field in the same header block can evict the entry
//! and overwrite its bytes. Callers that outlive one operation copy. `Decoder`
//! does, and says why.

const std = @import("std");

const DynamicTable = @This();

const assert = @import("../assert.zig").assert;

const Field = @import("Field.zig");
const memory = @import("memory.zig");

/// The largest table this type will hold.
///
/// A bound is needed regardless — an unbounded `SETTINGS_HEADER_TABLE_SIZE`
/// from a peer is memory a peer chose for us — and 64 KiB is far past any
/// useful table. Consumers set their real limit lower by handing over a
/// smaller arena.
///
/// It is `maxInt(u16)` and not the 65536 it reads like it wants to be, because
/// the offsets an arena of N octets needs are `0..N` inclusive, not `0..N-1`:
/// `end` is a one-past-the-end cursor that becomes the next entry's
/// `name_offset`, and `get` recomputes a span's end from it. At 65536 both of
/// those reach 65536, which is one past what a `u16` holds. The comptime block
/// below is what makes that a compile error rather than a four-insert bug.
pub const capacity_max: u32 = std.math.maxInt(u16);

comptime {
    // Every offset and cursor this type stores is a `u16`, and the largest of
    // them is the arena's one-past-the-end. This is the relation the constant
    // above exists to satisfy.
    assert(capacity_max <= std.math.maxInt(u16));
    // An entry costs at least the overhead, which is what makes
    // `entriesRequired` exact rather than an estimate.
    assert(Field.overhead > 0);
    assert(capacity_max >= Field.overhead);
}

/// One entry's bookkeeping. The value is stored immediately after the name, so
/// two lengths and one offset locate both. Six octets, which matters: at 4 KiB
/// the ring holds 128 of these per direction per connection, and a proxy holds
/// two per connection across thousands of them.
pub const Entry = struct {
    name_offset: u16,
    name_len: u16,
    value_len: u16,

    /// The entry's charge against the table's budget: its octets plus the
    /// fixed overhead. Named apart from `Field.size` deliberately — that one
    /// returns `u64` because it is summed over a whole header list, this one
    /// `u32` because it is bounded by `capacity_max`, and a reader holding
    /// both at once should not have to work out which is which.
    fn accountedSize(entry: Entry) u32 {
        assert(@as(u32, entry.name_len) + @as(u32, entry.value_len) <= capacity_max);
        return @as(u32, entry.name_len) + @as(u32, entry.value_len) + @as(u32, Field.overhead);
    }
};

/// Entries an arena of `capacity` octets can ever hold at once.
///
/// No entry costs less than `Field.overhead`, so this is exact rather than an
/// estimate, and it is why the ring can be sized once and never checked again.
pub fn entriesRequired(capacity: u32) u32 {
    assert(capacity <= capacity_max);
    return @divFloor(capacity, @as(u32, Field.overhead));
}

/// Storage for a table of `capacity` octets, for callers that know the size at
/// comptime. Callers that do not — a proxy sizing a session pool from config —
/// pass their own slices to `init` instead.
pub fn Storage(comptime capacity: u32) type {
    comptime assert(capacity <= capacity_max);
    return struct {
        bytes: [capacity]u8 = undefined,
        entries: [entriesRequired(capacity)]Entry = undefined,

        pub fn table(storage: *@This()) DynamicTable {
            return DynamicTable.init(&storage.bytes, &storage.entries);
        }
    };
}

arena: []u8,
entries: []Entry,
/// The current maximum, which a dynamic table size update may lower or raise
/// up to `arena.len` (RFC 7541 section 6.3).
capacity: u32,
/// Accounted size of the live entries, which is their octets plus overhead —
/// not the arena bytes they occupy.
size: u32 = 0,
/// Ring position of the newest entry. Normalized to zero when `count` is
/// zero, so an empty table has one representation rather than a stale one.
newest: u32 = 0,
count: u32 = 0,
/// The live span of the arena. `begin` is the oldest entry's first octet,
/// `end` is one past the newest entry's last.
begin: u32 = 0,
end: u32 = 0,

/// `entries` must hold `entriesRequired(arena.len)`; `Storage` gets this right
/// by construction, and a caller sizing its own is asserted here rather than
/// discovering it at the first eviction.
pub fn init(arena: []u8, entries: []Entry) DynamicTable {
    assert(arena.len <= capacity_max);
    assert(entries.len >= entriesRequired(@intCast(arena.len)));
    return .{
        .arena = arena,
        .entries = entries,
        .capacity = @intCast(arena.len),
    };
}

/// The largest capacity this table can be raised to: the arena it was given.
pub fn capacityMax(table: *const DynamicTable) u32 {
    assert(table.arena.len <= capacity_max);
    return @intCast(table.arena.len);
}

pub const CapacityError = error{
    /// The requested capacity is larger than the arena, which for a decoder
    /// means the peer asked for more than we advertised.
    CapacityTooLarge,
};

/// Apply a dynamic table size update (RFC 7541 section 6.3), evicting whatever
/// no longer fits.
pub fn setCapacity(table: *DynamicTable, capacity: u32) CapacityError!void {
    assert(table.size <= table.capacity);
    if (capacity > table.capacityMax()) return error.CapacityTooLarge;
    table.capacity = capacity;
    table.evictTo(capacity);
    assert(table.size <= table.capacity);
    assert(table.begin <= table.end);
    if (table.count == 0) assert(table.begin == table.end);
}

/// The entry `position` places back from the newest, or null past the end.
///
/// Position is zero-based and newest-first, which is the dynamic table's own
/// ordering; converting an on-the-wire index is the caller's job, because the
/// static table's 61 entries sit in front of it and this type does not know
/// about them.
///
/// The returned slices point into the arena. See the lifetime note above.
pub fn get(table: *const DynamicTable, position: u32) ?Field {
    if (position >= table.count) return null;
    const entry = table.entries[table.slotOf(position)];
    // Widened on purpose. The sums are bounded by the arena, but computing
    // them in `u16` makes that bound the *type's* job, and at `capacity_max`
    // the last entry's end is exactly where a `u16` runs out.
    const name_begin: u32 = entry.name_offset;
    const value_begin: u32 = name_begin + entry.name_len;
    const value_end: u32 = value_begin + entry.value_len;
    assert(name_begin <= value_begin);
    assert(value_begin <= value_end);
    assert(value_end <= table.arena.len);
    return .{
        .name = table.arena[name_begin..value_begin],
        .value = table.arena[value_begin..value_end],
    };
}

/// Insert `field` as the newest entry, evicting from the oldest end until it
/// fits.
///
/// An entry larger than the whole capacity empties the table and is not
/// inserted — RFC 7541 section 4.4, and not an error: it is how an encoder
/// legitimately clears a table.
///
/// `field` must not borrow from this table's own arena. The bytes are copied,
/// but an insert may compact first, and compaction moves the live span out
/// from under any slice the caller is still holding — so the copy would read
/// bytes that have already moved. Asserted rather than documented, because the
/// failure is silent and intermittent: it needs the write cursor to have
/// reached the end of the arena, which is rare and input-dependent. A caller
/// that wants to reinsert an existing entry copies it out first.
pub fn insert(table: *DynamicTable, field: Field) void {
    assert(!table.aliasesArena(field.name));
    assert(!table.aliasesArena(field.value));
    const size = field.size();
    assert(size >= Field.overhead);
    if (size > table.capacity) {
        table.clear();
        return;
    }

    // Room for this entry, by the accounting rather than by arena bytes: the
    // 32-octet overhead is fictional storage that only the size budget sees.
    table.evictTo(table.capacity - @as(u32, @intCast(size)));
    assert(table.size + size <= table.capacity);
    assert(table.count < table.entries.len);

    const name_len: u16 = @intCast(field.name.len);
    const value_len: u16 = @intCast(field.value.len);
    const bytes = @as(u32, name_len) + @as(u32, value_len);
    if (table.end + bytes > table.arena.len) table.compact();
    assert(table.end + bytes <= table.arena.len);

    const offset = table.end;
    // `end` is one past the live span, so it reaches `arena.len` — which is
    // why `capacity_max` stops one short of 65536 rather than at it.
    assert(offset <= capacity_max);
    @memcpy(table.arena[offset..][0..name_len], field.name);
    @memcpy(table.arena[offset + name_len ..][0..value_len], field.value);
    table.end += bytes;

    table.newest = if (table.count == 0) 0 else previous(table.newest, @intCast(table.entries.len));
    table.entries[table.newest] = .{
        .name_offset = @intCast(offset),
        .name_len = name_len,
        .value_len = value_len,
    };
    table.count += 1;
    table.size += @intCast(size);
    assert(table.size <= table.capacity);
}

/// Drop every entry, as a size update to zero does (RFC 7541 section 4.3).
pub fn clear(table: *DynamicTable) void {
    table.size = 0;
    table.count = 0;
    // Normalized rather than left stale: `evictTo` asserts the empty table has
    // its cursors at zero, and `newest` is documented as normalized rather than
    // meaningless so that a reader is not left deriving which it is.
    table.newest = 0;
    table.begin = 0;
    table.end = 0;
    assert(table.size == 0);
    assert(table.begin == table.end);
}

/// Evict oldest-first until the accounted size is at most `limit`.
fn evictTo(table: *DynamicTable, limit: u32) void {
    // `count` is in the condition rather than only in an assertion. Every pass
    // drops one entry and every entry charges at least `Field.overhead`, so the
    // size argument alone does terminate — but assertions are a build option
    // here (`-Dassertions`, see src/assert.zig), and with them off a
    // `size`/`count` disagreement would underflow `count - 1` to `maxInt(u32)`
    // and spin. The bound belongs where it cannot be compiled out.
    while (table.count > 0 and table.size > limit) {
        const oldest = table.entries[table.slotOf(table.count - 1)];
        // FIFO means the oldest entry is always at the front of the live span.
        assert(oldest.name_offset == table.begin);
        table.begin += @as(u32, oldest.name_len) + @as(u32, oldest.value_len);
        table.size -= oldest.accountedSize();
        table.count -= 1;
    }
    // Either the limit is met, or there is nothing left to drop.
    assert(table.size <= limit or table.count == 0);
    if (table.count == 0) {
        // Nothing live, so start the arena over rather than leaving the cursors
        // stranded at the far end.
        table.begin = 0;
        table.end = 0;
    }
    assert(table.begin <= table.end);
}

/// Slide the live span back to offset zero and rebase the entries onto it.
fn compact(table: *DynamicTable) void {
    assert(table.begin <= table.end);
    const live = table.end - table.begin;
    assert(live <= table.arena.len);
    if (table.begin == 0) return;

    std.mem.copyForwards(u8, table.arena[0..live], table.arena[table.begin..table.end]);
    const shift = table.begin;
    var position: u32 = 0;
    while (position < table.count) : (position += 1) {
        const entry = &table.entries[table.slotOf(position)];
        assert(entry.name_offset >= shift);
        entry.name_offset -= @intCast(shift);
    }
    table.begin = 0;
    table.end = live;
}

/// Ring index of the entry `position` places back from the newest.
///
/// Public because the encoder keeps arrays parallel to `entries` — one hash per
/// slot — and has to address them the same way this type does. Nothing else
/// should need it.
pub fn slotOf(table: *const DynamicTable, position: u32) u32 {
    assert(position < table.count);
    assert(table.entries.len > 0);
    const entries_count: u32 = @intCast(table.entries.len);
    assert(table.newest < entries_count);
    return (table.newest + position) % entries_count;
}

/// True when `bytes` shares any octet with the arena, which is the aliasing
/// `insert` refuses.
///
/// Overlap rather than containment: testing only the start pointer would miss a
/// slice that begins before the arena and reaches into it, and this assertion
/// is the whole defence for a lifetime rule whose failure is silent.
fn aliasesArena(table: *const DynamicTable, bytes: []const u8) bool {
    return memory.overlaps(bytes, table.arena);
}

/// The ring slot before `index`, wrapping. `entries_count` is a count of slots
/// rather than a byte length, and the caller has it as a `u32` already.
fn previous(index: u32, entries_count: u32) u32 {
    assert(entries_count > 0);
    assert(index < entries_count);
    return (index + entries_count - 1) % entries_count;
}

const testing = std.testing;

test "entriesRequired is exact, because no entry costs less than the overhead" {
    try testing.expectEqual(@as(u32, 0), entriesRequired(0));
    try testing.expectEqual(@as(u32, 0), entriesRequired(31));
    try testing.expectEqual(@as(u32, 1), entriesRequired(32));
    try testing.expectEqual(@as(u32, 128), entriesRequired(4096));
    // 129 minimal entries would need 4128 octets, which 4096 does not have.
    try testing.expect(129 * Field.overhead > 4096);
}

test "insert then read back, newest first" {
    var storage: Storage(4096) = .{};
    var table = storage.table();

    table.insert(.{ .name = "first", .value = "1" });
    table.insert(.{ .name = "second", .value = "2" });

    try testing.expectEqual(@as(u32, 2), table.count);
    try testing.expectEqualStrings("second", table.get(0).?.name);
    try testing.expectEqualStrings("2", table.get(0).?.value);
    try testing.expectEqualStrings("first", table.get(1).?.name);
    try testing.expectEqual(@as(?Field, null), table.get(2));
}

test "C.3.1: the RFC's worked size accounting" {
    var storage: Storage(4096) = .{};
    var table = storage.table();
    table.insert(.{ .name = ":authority", .value = "www.example.com" });
    // The RFC prints "(s = 57)": 10 + 15 + 32.
    try testing.expectEqual(@as(u32, 57), table.size);
}

test "reinserting an entry means copying it out of the arena first" {
    var storage: Storage(4096) = .{};
    var table = storage.table();
    table.insert(.{ .name = "name", .value = "value" });

    // Passing `table.get(0).?` straight back in would alias the arena, which
    // `insert` asserts against: a compaction during the insert would move the
    // bytes out from under those slices.
    const existing = table.get(0).?;
    var name: [16]u8 = undefined;
    var value: [16]u8 = undefined;
    @memcpy(name[0..existing.name.len], existing.name);
    @memcpy(value[0..existing.value.len], existing.value);
    table.insert(.{
        .name = name[0..existing.name.len],
        .value = value[0..existing.value.len],
    });

    try testing.expectEqualStrings("name", table.get(0).?.name);
    try testing.expectEqualStrings("value", table.get(0).?.value);
    try testing.expectEqualStrings("name", table.get(1).?.name);
}

test "aliasing the arena is detected, not silently copied" {
    var storage: Storage(4096) = .{};
    var table = storage.table();
    table.insert(.{ .name = "name", .value = "value" });

    const existing = table.get(0).?;
    try testing.expect(table.aliasesArena(existing.name));
    try testing.expect(table.aliasesArena(existing.value));
    try testing.expect(!table.aliasesArena("elsewhere"));
    // A zero-length slice borrows nothing, whatever it points at.
    try testing.expect(!table.aliasesArena(existing.name[0..0]));
}

test "eviction is oldest-first and frees exactly its accounting" {
    // Room for two 34-octet entries and no more.
    var storage: Storage(68) = .{};
    var table = storage.table();

    table.insert(.{ .name = "a", .value = "1" });
    table.insert(.{ .name = "b", .value = "2" });
    try testing.expectEqual(@as(u32, 2), table.count);
    try testing.expectEqual(@as(u32, 68), table.size);

    table.insert(.{ .name = "c", .value = "3" });
    try testing.expectEqual(@as(u32, 2), table.count);
    try testing.expectEqualStrings("c", table.get(0).?.name);
    try testing.expectEqualStrings("b", table.get(1).?.name);
}

test "an entry larger than the capacity empties the table" {
    var storage: Storage(68) = .{};
    var table = storage.table();
    table.insert(.{ .name = "a", .value = "1" });
    try testing.expectEqual(@as(u32, 1), table.count);

    // RFC 7541 section 4.4: not an error, and the table ends up empty.
    // 3 + 40 + 32 = 75, past the 68 this table holds.
    table.insert(.{ .name = "far", .value = "0123456789012345678901234567890123456789" });
    try testing.expectEqual(@as(u32, 0), table.count);
    try testing.expectEqual(@as(u32, 0), table.size);
}

test "capacity zero holds nothing and needs no storage" {
    var arena: [0]u8 = undefined;
    var entries: [0]Entry = undefined;
    var table = init(&arena, &entries);

    try testing.expectEqual(@as(u32, 0), table.capacity);
    table.insert(.{ .name = "any", .value = "thing" });
    try testing.expectEqual(@as(u32, 0), table.count);
    try testing.expectEqual(@as(?Field, null), table.get(0));
}

test "a size update evicts down to the new capacity" {
    var storage: Storage(4096) = .{};
    var table = storage.table();
    table.insert(.{ .name = "a", .value = "1" }); // 34
    table.insert(.{ .name = "b", .value = "2" }); // 34
    try testing.expectEqual(@as(u32, 68), table.size);

    try table.setCapacity(40);
    try testing.expectEqual(@as(u32, 1), table.count);
    try testing.expectEqualStrings("b", table.get(0).?.name);

    try table.setCapacity(0);
    try testing.expectEqual(@as(u32, 0), table.count);

    // Raising it again is legal up to the arena, and no further.
    try table.setCapacity(4096);
    try testing.expectError(error.CapacityTooLarge, table.setCapacity(4097));
}

test "an arena at capacity_max does not overflow its own offsets" {
    // The shape that broke the u16 entry fields when capacity_max was 65536:
    // four entries of 16 KiB leave the fourth at offset 49152 with 16384
    // octets, and `get` then computes 49152 + 16384 = 65536 — one past what a
    // u16 holds. It read as a bounds check passing, because the wrapped end
    // was zero and zero is less than the arena length.
    var storage: Storage(capacity_max) = .{};
    var table = storage.table();

    const quarter = capacity_max / 4;
    var round: u32 = 0;
    while (round < 12) : (round += 1) {
        var value: [quarter]u8 = undefined;
        @memset(&value, @intCast('a' + round % 26));
        table.insert(.{ .name = "n", .value = value[0 .. quarter - 1] });

        var position: u32 = 0;
        while (position < table.count) : (position += 1) {
            const field = table.get(position).?;
            try testing.expect(field.name.len + field.value.len <= capacity_max);
        }
        try testing.expect(table.end <= capacity_max);
    }
}

test "the write cursor reaches the end of the arena without overflowing an offset" {
    // A single large entry can never do this: its 32 octets of overhead mean
    // its data is at most `capacity - 32`. One-octet entries walk `end` one
    // step at a time, so it lands on every value including `arena.len` itself
    // — the offset a u16 could not hold while capacity_max was 65536.
    var storage: Storage(capacity_max) = .{};
    var table = storage.table();

    var reached_end = false;
    var round: u32 = 0;
    while (round < capacity_max + 64) : (round += 1) {
        table.insert(.{ .name = "n", .value = "" });
        if (table.end == capacity_max) reached_end = true;
        try testing.expect(table.end <= capacity_max);
        try testing.expect(table.size <= table.capacity);
        try testing.expect(table.begin <= table.end);
    }
    try testing.expect(reached_end);

    // And an entry with no octets at all, which is what can then take an
    // offset to exactly `arena.len` rather than one below it.
    table.insert(.{ .name = "", .value = "" });
    try testing.expect(table.end <= capacity_max);
    try testing.expectEqualStrings("", table.get(0).?.name);
}

test "the arena compacts instead of growing, over many rotations" {
    // Sized so the write cursor reaches the end repeatedly: 66 live entries of
    // 30 data octets each, in an arena that only holds about 2 KiB of them.
    var storage: Storage(4096) = .{};
    var table = storage.table();

    var round: u32 = 0;
    while (round < 2000) : (round += 1) {
        var name: [10]u8 = undefined;
        var value: [20]u8 = undefined;
        for (&name, 0..) |*byte, index| byte.* = @intCast('a' + (round + index) % 26);
        for (&value, 0..) |*byte, index| byte.* = @intCast('A' + (round + index) % 26);
        table.insert(.{ .name = &name, .value = &value });

        // Every live entry stays readable and correct after any compaction.
        const newest = table.get(0).?;
        try testing.expectEqualSlices(u8, &name, newest.name);
        try testing.expectEqualSlices(u8, &value, newest.value);
        try testing.expect(table.size <= table.capacity);
        try testing.expect(table.end <= table.arena.len);
        try testing.expect(table.begin <= table.end);
    }

    // And the oldest entry is still intact, not overwritten by a compaction
    // that rebased the wrong slots.
    const oldest = table.get(table.count - 1).?;
    try testing.expectEqual(@as(usize, 10), oldest.name.len);
    try testing.expectEqual(@as(usize, 20), oldest.value.len);
}

test "size accounting reconciles against a recomputed sum after churn" {
    var storage: Storage(512) = .{};
    var table = storage.table();

    var round: u32 = 0;
    while (round < 500) : (round += 1) {
        var value: [40]u8 = undefined;
        const length = round % value.len;
        for (value[0..length], 0..) |*byte, index| byte.* = @intCast('a' + index % 26);
        table.insert(.{ .name = "k", .value = value[0..length] });

        var sum: u32 = 0;
        var position: u32 = 0;
        while (position < table.count) : (position += 1) sum += @intCast(table.get(position).?.size());
        try testing.expectEqual(sum, table.size);
    }
}
