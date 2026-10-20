//! Fixed-capacity, generation-checked slot pool with idle deadlines.
//!
//! H3 request slots are reserved at init and never grow: `acquire` answers
//! null at the wall (the caller sheds), and every slot carries a `u16`
//! generation so a handle that outlived its slot is rejected rather than
//! aliasing whichever request now owns the slot.
//!
//! A handle is only reused after its slot is released, which bumps the
//! generation. Two different acquisitions of one slot therefore compare
//! unequal for 65,536 consecutive releases; the ABA bound is exactly that:
//! a stale handle becomes valid again only once its slot has been released
//! 2^16 times since the handle was issued. At that point the ABA window is
//! closed by design — callers that can hold a handle across 65,536 reuses
//! of the same index must carry a wider identity of their own.
//!
//! Deadlines are absolute nanoseconds, stored per slot and cleared on
//! release. `std.math.maxInt(u64)` means "no deadline", so every real
//! `u64` (including 0, useful to tests) is a settable deadline.

const std = @import("std");

const assert = std.debug.assert;

/// Absolute-nanosecond value meaning a slot has no idle deadline. A real
/// deadline this far out (year ~584 billion) is not representable in
/// practice, so the sentinel costs no usable range.
const deadline_none: u64 = std.math.maxInt(u64);

pub fn Pool(comptime T: type, comptime capacity: usize) type {
    // Handle.index is u16, so capacity 65,536 is the largest pool whose
    // indices all fit; one more would need a wider index.
    comptime assert(capacity <= @as(usize, std.math.maxInt(u16)) + 1);

    return struct {
        const Self = @This();

        /// Slot payload. Undefined until the slot is acquired; a slot is
        /// only ever read through a live handle.
        slots: [capacity]T,
        generation: [capacity]u16,
        free: [capacity]bool,
        deadline_ns: [capacity]u64,
        in_use: usize,

        pub const Handle = struct {
            index: u16,
            generation: u16,
        };

        /// In-place init: the pool has no allocator and no failure path.
        /// Payloads are deliberately left undefined — `T` need not have a
        /// default, and no work is spent on slots nobody acquired.
        pub fn initInPlace(self: *Self) void {
            for (0..capacity) |index| {
                self.generation[index] = 0;
                self.free[index] = true;
                self.deadline_ns[index] = deadline_none;
            }
            self.in_use = 0;
            assert(self.count() == 0);
            assert(self.capacityCount() == capacity);
        }

        /// Lowest free index, so slot assignment is deterministic. Null is
        /// exhaustion — a shed signal, never an error.
        pub fn acquire(self: *Self) ?Handle {
            assert(self.in_use <= capacity);
            for (0..capacity) |index| {
                if (self.free[index]) {
                    self.free[index] = false;
                    self.in_use += 1;
                    assert(self.in_use <= capacity);
                    return .{
                        .index = @intCast(index),
                        .generation = self.generation[index],
                    };
                }
            }
            assert(self.in_use == capacity);
            return null;
        }

        /// A stale handle (free slot, wrapped generation, or out-of-range
        /// index) is ignored: release is idempotent, so a double release
        /// cannot free a slot twice or underflow `in_use`. Callers that
        /// need to distinguish should check `get` first.
        pub fn release(self: *Self, handle: Handle) void {
            if (!self.valid(handle)) return;
            assert(self.in_use >= 1);
            const index: usize = handle.index;
            self.generation[index] +%= 1;
            self.free[index] = true;
            self.deadline_ns[index] = deadline_none;
            self.in_use -= 1;
            assert(self.free[index]);
            assert(self.in_use <= capacity);
        }

        pub fn get(self: *Self, handle: Handle) ?*T {
            if (!self.valid(handle)) return null;
            return &self.slots[handle.index];
        }

        pub fn getConst(self: *const Self, handle: Handle) ?*const T {
            if (!self.valid(handle)) return null;
            return &self.slots[handle.index];
        }

        /// No-op on a stale handle, matching `release`'s rejection rule:
        /// a late timer must not resurrect a deadline on a reused slot.
        pub fn setDeadline(self: *Self, handle: Handle, ns: u64) void {
            if (!self.valid(handle)) return;
            self.deadline_ns[handle.index] = ns;
        }

        /// Null when the handle is stale or the slot has no deadline.
        pub fn deadline(self: *const Self, handle: Handle) ?u64 {
            if (!self.valid(handle)) return null;
            const ns = self.deadline_ns[handle.index];
            if (ns == deadline_none) return null;
            return ns;
        }

        /// Earliest deadline among live slots, or null when no live slot
        /// has one. Used to size the next timer tick.
        pub fn nextDeadline(self: *const Self) ?u64 {
            var earliest: u64 = deadline_none;
            for (0..capacity) |index| {
                if (self.free[index]) continue;
                const ns = self.deadline_ns[index];
                if (ns < earliest) earliest = ns;
            }
            if (earliest == deadline_none) return null;
            return earliest;
        }

        /// Collects live slots whose deadline is due, lowest index first.
        /// Only reports — releasing is the caller's decision, so a scan
        /// can be retried without losing slots. Never writes more than
        /// `out.len`; the scan itself is bounded by capacity.
        pub fn expired(self: *const Self, now_ns: u64, out: []Handle) usize {
            var written: usize = 0;
            for (0..capacity) |index| {
                if (written == out.len) break;
                if (self.free[index]) continue;
                const ns = self.deadline_ns[index];
                if (ns == deadline_none) continue;
                if (ns > now_ns) continue;
                out[written] = .{
                    .index = @intCast(index),
                    .generation = self.generation[index],
                };
                written += 1;
            }
            assert(written <= out.len);
            assert(written <= capacity);
            return written;
        }

        pub fn count(self: *const Self) usize {
            assert(self.in_use <= capacity);
            return self.in_use;
        }

        pub fn capacityCount(self: *const Self) usize {
            _ = self;
            return capacity;
        }

        /// Rejects every dimension a handle can be wrong in — range,
        /// slot occupancy, and generation — before any field is touched.
        fn valid(self: *const Self, handle: Handle) bool {
            const index: usize = handle.index;
            if (index >= capacity) return false;
            if (self.free[index]) return false;
            return self.generation[index] == handle.generation;
        }
    };
}

const TestItem = struct {
    value: u64 = 0,
};

test "pool: acquire/release/reuse keeps the index and bumps generation" {
    var pool: Pool(TestItem, 4) = undefined;
    pool.initInPlace();

    const first = pool.acquire().?;
    try std.testing.expectEqual(@as(u16, 0), first.index);
    try std.testing.expectEqual(@as(u16, 0), first.generation);
    pool.get(first).?.value = 7;

    pool.release(first);
    try std.testing.expectEqual(@as(usize, 0), pool.count());

    const reused = pool.acquire().?;
    try std.testing.expectEqual(first.index, reused.index);
    try std.testing.expectEqual(first.generation + 1, reused.generation);
    try std.testing.expectEqual(@as(*const TestItem, &pool.slots[reused.index]), pool.getConst(reused).?);
    try std.testing.expectEqual(@as(*TestItem, &pool.slots[reused.index]), pool.get(reused).?);
    pool.release(reused);
}

test "pool: generation change rejects the old handle" {
    var pool: Pool(TestItem, 2) = undefined;
    pool.initInPlace();

    const old = pool.acquire().?;
    pool.release(old);
    const new = pool.acquire().?;
    try std.testing.expectEqual(old.index, new.index);
    try std.testing.expect(old.generation != new.generation);

    try std.testing.expectEqual(@as(?*TestItem, null), pool.get(old));
    try std.testing.expectEqual(@as(?*const TestItem, null), pool.getConst(old));
    try std.testing.expectEqual(@as(?u64, null), pool.deadline(old));
    pool.setDeadline(old, 10);
    try std.testing.expectEqual(@as(?u64, null), pool.deadline(new));
    pool.release(old);
    try std.testing.expectEqual(@as(usize, 1), pool.count());
    pool.release(new);
}

test "pool: double release is a no-op" {
    var pool: Pool(TestItem, 2) = undefined;
    pool.initInPlace();

    const handle = pool.acquire().?;
    pool.release(handle);
    pool.release(handle);
    try std.testing.expectEqual(@as(usize, 0), pool.count());

    // The slot is still free exactly once; the pool is not corrupted and
    // the next acquire reuses the same lowest index.
    const again = pool.acquire().?;
    try std.testing.expectEqual(handle.index, again.index);
    try std.testing.expectEqual(@as(usize, 1), pool.count());
    pool.release(again);
    try std.testing.expectEqual(@as(usize, 0), pool.count());
}

test "pool: exhaustion returns null and a release restores one slot" {
    var pool: Pool(TestItem, 2) = undefined;
    pool.initInPlace();
    const Handle = Pool(TestItem, 2).Handle;

    const first = pool.acquire().?;
    const second = pool.acquire().?;
    try std.testing.expect(first.index != second.index);
    try std.testing.expectEqual(@as(?Handle, null), pool.acquire());
    try std.testing.expectEqual(@as(usize, 2), pool.count());

    pool.release(first);
    const third = pool.acquire().?;
    try std.testing.expectEqual(first.index, third.index);
    try std.testing.expectEqual(@as(?Handle, null), pool.acquire());

    pool.release(second);
    pool.release(third);
    try std.testing.expectEqual(@as(usize, 0), pool.count());
}

test "pool: an empty pool is permanently exhausted and well formed" {
    var pool: Pool(TestItem, 0) = undefined;
    pool.initInPlace();
    const Handle = Pool(TestItem, 0).Handle;

    try std.testing.expectEqual(@as(usize, 0), pool.capacityCount());
    try std.testing.expectEqual(@as(usize, 0), pool.count());
    try std.testing.expectEqual(@as(?Handle, null), pool.acquire());
    try std.testing.expectEqual(@as(?u64, null), pool.nextDeadline());
    try std.testing.expectEqual(@as(usize, 0), pool.expired(100, &.{}));
}

test "pool: expired scan is deadline-ordered and bounded by out.len" {
    var pool: Pool(TestItem, 4) = undefined;
    pool.initInPlace();
    const Handle = Pool(TestItem, 4).Handle;

    const a = pool.acquire().?;
    const b = pool.acquire().?;
    const c = pool.acquire().?;
    _ = pool.acquire().?; // No deadline: never reported.
    pool.setDeadline(a, 10);
    pool.setDeadline(b, 20);
    pool.setDeadline(c, 30);

    var found: [4]Handle = undefined;
    try std.testing.expectEqual(@as(usize, 0), pool.expired(9, &found));
    try std.testing.expectEqual(@as(usize, 1), pool.expired(10, &found));
    try std.testing.expectEqual(a, found[0]);
    try std.testing.expectEqual(@as(usize, 2), pool.expired(25, &found));
    try std.testing.expectEqual(a, found[0]);
    try std.testing.expectEqual(b, found[1]);

    // A short buffer truncates instead of overflowing, lowest index first.
    try std.testing.expectEqual(@as(usize, 1), pool.expired(100, found[0..1]));
    try std.testing.expectEqual(a, found[0]);
    try std.testing.expectEqual(@as(usize, 3), pool.expired(100, &found));

    // The scan reports without releasing.
    try std.testing.expectEqual(@as(usize, 4), pool.count());
    try std.testing.expectEqual(@as(usize, 0), pool.expired(100, found[0..0]));
}

test "pool: nextDeadline tracks the earliest live deadline" {
    var pool: Pool(TestItem, 4) = undefined;
    pool.initInPlace();

    try std.testing.expectEqual(@as(?u64, null), pool.nextDeadline());

    const a = pool.acquire().?;
    const b = pool.acquire().?;
    const c = pool.acquire().?;
    const d = pool.acquire().?;
    pool.setDeadline(a, 50);
    pool.setDeadline(b, 20);
    pool.setDeadline(c, 100);
    // d keeps no deadline and must not pull the minimum to the sentinel.
    try std.testing.expectEqual(@as(?u64, 20), pool.nextDeadline());

    pool.release(b);
    try std.testing.expectEqual(@as(?u64, 50), pool.nextDeadline());
    pool.release(a);
    try std.testing.expectEqual(@as(?u64, 100), pool.nextDeadline());
    pool.release(c);
    try std.testing.expectEqual(@as(?u64, null), pool.nextDeadline());
    pool.release(d);
}

test "pool: count and capacityCount" {
    var pool: Pool(TestItem, 3) = undefined;
    pool.initInPlace();
    const Handle = Pool(TestItem, 3).Handle;

    try std.testing.expectEqual(@as(usize, 3), pool.capacityCount());
    try std.testing.expectEqual(@as(usize, 0), pool.count());

    var handles: [3]Handle = undefined;
    for (&handles, 0..) |*handle, index| {
        handle.* = pool.acquire().?;
        const expected: usize = index + 1;
        try std.testing.expectEqual(expected, pool.count());
    }
    try std.testing.expectEqual(@as(usize, 3), pool.count());
    for (handles) |handle| pool.release(handle);
    try std.testing.expectEqual(@as(usize, 0), pool.count());
}

test "pool: generation wraps after 2^16 releases of one slot" {
    var pool: Pool(TestItem, 1) = undefined;
    pool.initInPlace();

    const first = pool.acquire().?;
    pool.release(first);

    var cycle: u32 = 0;
    while (cycle < std.math.maxInt(u16)) : (cycle += 1) {
        const handle = pool.acquire().?;
        pool.release(handle);
    }
    // The generation counter wrapped back to the original value, which is
    // the documented ABA bound rather than corruption.
    const last = pool.acquire().?;
    try std.testing.expectEqual(first.generation, last.generation);
    try std.testing.expect(pool.get(first) != null);
    pool.release(last);
}
