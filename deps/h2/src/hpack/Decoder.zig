//! RFC 7541 section 6: decoding a header block into header fields.
//!
//! ## Shape
//!
//! `iterate` returns an iterator rather than filling an array, because the two
//! consumers want different things from a block: a proxy collects every field
//! before routing, and a load generator counts them and throws them away. An
//! iterator lets the second one cost nothing, and lets either stop early on a
//! field it already knows is fatal.
//!
//! Fields borrow, and from three places:
//!
//!   - the comptime static table, which outlives everything;
//!   - the header block itself, for literals that were not Huffman-coded,
//!     which costs no output buffer at all and no copy;
//!   - the caller's output buffer, for Huffman-coded literals, which have to
//!     be decoded somewhere, and for anything read out of the dynamic table.
//!
//! That last one is a lifetime rule, not an optimization. A later field in the
//! same block can insert an entry, evict the one an earlier field came from,
//! and overwrite its bytes — so a slice into the dynamic table is valid only
//! until the next representation, which is shorter than the caller needs it.
//! Every read of the dynamic table copies out. `DynamicTable.insert` asserts
//! the other half of the same rule, and `iterate` asserts the third: that the
//! output buffer and the table arena are not the same memory.
//!
//! ## What bounds what
//!
//! The output buffer is the structural bound: a compression bomb expands into
//! a buffer the caller sized, and stops there. `list_size_max` is the protocol
//! bound the peer was told about (`SETTINGS_MAX_HEADER_LIST_SIZE`), checked as
//! the block decodes rather than after, because a decoder that finishes the
//! work and then reports the overflow has already done what the attacker
//! wanted.
//!
//! There is deliberately no separate field-count bound. Every field costs at
//! least `Field.overhead` against `list_size_max`, so a count bound follows
//! from the size bound and cannot drift out of step with it. That is what
//! CVE-2026-49975 was: implementations had the size bound, counted cookie
//! crumbs as one field rather than many, and found that a byte of wire could
//! buy thousands of allocations. Accounting for every field, always, makes the
//! second bound unnecessary rather than forgotten. See `fieldsMax`.
//!
//! ## Non-minimal integers are accepted
//!
//! RFC 7541 section 5.1 does not require an integer to spend the fewest
//! continuation octets that can express it, so `{0x1f, 0x80, 0x00}` and
//! `{0x1f, 0x00}` are both the value 31 behind a 5-bit prefix. This decoder
//! accepts both. Rejecting the long spelling would be stricter than the RFC and
//! would break a conforming peer, and unlike the HTTP/1 framing ambiguities
//! that motivate strictness elsewhere, both spellings decode to the *same
//! value* — there is no second interpretation for two peers to disagree about,
//! only wasted octets, and `integer.continuation_octets_max` already bounds how
//! many of those a peer may spend.

const std = @import("std");

const Decoder = @This();

const assert = @import("../assert.zig").assert;

const DynamicTable = @import("DynamicTable.zig");
const Field = @import("Field.zig");
const huffman = @import("huffman.zig");
const integer = @import("integer.zig");
const memory = @import("memory.zig");
const static_table = @import("static_table.zig");

/// Consecutive dynamic table size updates allowed at the start of a block.
///
/// RFC 7541 section 4.2 requires an update to sit at the beginning of a header
/// block; two can legitimately arrive together, because a peer that lowered and
/// then raised its limit between blocks must signal both, and the pair is what
/// proves it went down. A third says nothing a second did not, so it is where
/// an otherwise free way to make a decoder work stops.
pub const size_updates_max: u32 = 2;

/// RFC 7541 section 5.2: a string's length sits below the H bit, so seven.
const prefix_string: u4 = 7;
/// RFC 7541 section 6.1.
const prefix_indexed: u4 = 7;
/// RFC 7541 section 6.3.
const prefix_size_update: u4 = 5;

comptime {
    // At least one, or a leading update could never be consumed; and `advance`
    // allows exactly one pass more than this, which is the pass that produces
    // a field.
    assert(size_updates_max >= 1);
    assert(size_updates_max < std.math.maxInt(u32));
    // Every prefix is one the integer codec can represent.
    assert(prefix_string <= integer.prefix_bits_max);
    assert(prefix_indexed <= integer.prefix_bits_max);
    assert(prefix_size_update <= integer.prefix_bits_max);
}

table: DynamicTable,
/// `SETTINGS_MAX_HEADER_LIST_SIZE` as advertised to the peer, in the units of
/// `Field.size`. A `u32` because that is the SETTINGS parameter's wire type: a
/// wider bound here could not be communicated to the peer it constrains.
list_size_max: u32,

pub fn init(table: DynamicTable, list_size_max: u32) Decoder {
    assert(table.capacity <= table.capacityMax());
    assert(table.size <= table.capacity);
    return .{ .table = table, .list_size_max = list_size_max };
}

/// The most fields a block can carry, derived from `list_size_max` rather than
/// configured beside it. Floored, because it is an upper bound and a partial
/// field is not a field.
pub fn fieldsMax(decoder: *const Decoder) u32 {
    return @divFloor(decoder.list_size_max, @as(u32, Field.overhead));
}

pub const Error = error{
    /// The block ends in the middle of a representation.
    Incomplete,
    /// Index zero, or an index past the end of both tables.
    InvalidIndex,
    /// A Huffman-coded string contains EOS, ends mid-code, or pads wrongly.
    InvalidHuffman,
    /// An integer ran past `integer.continuation_octets_max`, or past `u32`.
    IntegerTooLarge,
    /// The header list exceeded `list_size_max`.
    HeaderListTooLarge,
    /// The decoding did not fit the caller's output buffer.
    OutputTooLong,
    /// A size update asked for more than the arena we advertised.
    CapacityTooLarge,
    /// A size update arrived after the first field of the block.
    UnexpectedSizeUpdate,
    /// More than `size_updates_max` updates at the start of one block.
    TooManySizeUpdates,
};

/// Decode `block` into `buffer`, one field at a time.
///
/// `block` and `buffer` must both outlive every field the iterator yields, and
/// `buffer` must not overlap the dynamic table's arena — the decoder copies out
/// of one into the other.
pub fn iterate(decoder: *Decoder, buffer: []u8, block: []const u8) Iterator {
    // Offsets into both are tracked as u32, which is a precondition rather than
    // an assumption. A block this large is far past any
    // `SETTINGS_MAX_FRAME_SIZE` a peer could negotiate, so this is unreachable
    // rather than restrictive.
    assert(block.len <= std.math.maxInt(u32));
    assert(buffer.len <= std.math.maxInt(u32));
    assert(!memory.overlaps(buffer, decoder.table.arena));
    return .{ .decoder = decoder, .buffer = buffer, .block = block };
}

pub const Iterator = struct {
    decoder: *Decoder,
    buffer: []u8,
    block: []const u8,
    /// Octets of `buffer` spent. Never rewound: earlier fields still borrow.
    used: u32 = 0,
    /// Octets of `block` consumed.
    offset: u32 = 0,
    /// Running `Field.size` total, checked against `list_size_max`. Wider than
    /// the bound it is checked against, so no wrap can happen before the
    /// comparison that would have caught it.
    list_size: u64 = 0,
    field_count: u32 = 0,
    size_updates: u32 = 0,
    /// Cleared by the first representation that is not a size update.
    at_block_start: bool = true,
    /// The first error, latched. See `next`.
    failure: ?Error = null,

    /// The next field, or null at the end of the block.
    ///
    /// An error ends the iteration: it is latched, and every later call returns
    /// the same one. A decode that failed mid-representation leaves the offset
    /// pointing into the middle of something, and resuming from there would
    /// invent fields out of the tail of a length already rejected.
    pub fn next(iterator: *Iterator) Error!?Field {
        if (iterator.failure) |failure| return failure;
        const before = iterator.offset;
        const field = iterator.advance() catch |err| {
            iterator.failure = err;
            return err;
        };
        // Every representation consumes at least one octet. This is what bounds
        // every caller's loop, the fuzz targets' included, so it is asserted
        // rather than assumed.
        if (field != null) assert(iterator.offset > before);
        return field;
    }

    /// Fields yielded so far.
    pub fn fieldCount(iterator: *const Iterator) u32 {
        return iterator.field_count;
    }

    /// The `Field.size` total charged so far. A caller that stopped early reads
    /// this to report what it had already admitted.
    pub fn headerListSize(iterator: *const Iterator) u64 {
        return iterator.list_size;
    }

    fn advance(iterator: *Iterator) Error!?Field {
        // Bounded by `size_updates_max`: every pass either returns, ends the
        // block, or consumes one of a capped number of size updates.
        var passes: u32 = 0;
        while (passes <= size_updates_max) : (passes += 1) {
            assert(iterator.size_updates <= size_updates_max);
            if (iterator.offset == iterator.block.len) return null;
            assert(iterator.offset < iterator.block.len);

            const lead = iterator.block[iterator.offset];
            if (lead & 0b1000_0000 != 0) return try iterator.indexed();
            if (lead & 0b1100_0000 == 0b0100_0000) return try iterator.literal(.incremental);
            if (lead & 0b1110_0000 == 0b0010_0000) {
                try iterator.sizeUpdate();
                continue;
            }
            if (lead & 0b1111_0000 == 0b0001_0000) return try iterator.literal(.never);
            assert(lead & 0b1111_0000 == 0);
            return try iterator.literal(.without);
        }
        return error.TooManySizeUpdates;
    }

    /// The three literal forms of RFC 7541 sections 6.2.1 to 6.2.3.
    ///
    /// Each one's prefix width travels with it, so a call site cannot pair the
    /// width of one with the table behaviour of another. `.without` and
    /// `.never` share a width and differ in everything else, which is exactly
    /// the pair a loose integer argument would let someone swap.
    const Indexing = enum {
        incremental,
        without,
        never,

        fn prefixBits(indexing: Indexing) u4 {
            return switch (indexing) {
                .incremental => 6,
                .without, .never => 4,
            };
        }
    };

    /// RFC 7541 section 6.1.
    fn indexed(iterator: *Iterator) Error!Field {
        const index = try iterator.readInteger(prefix_indexed);
        // Index zero is not a field; the representation has no meaning, and
        // section 6.1 says so outright.
        if (index == 0) return error.InvalidIndex;
        const field = try iterator.lookup(index);
        try iterator.account(field);
        return field;
    }

    /// RFC 7541 sections 6.2.1 to 6.2.3.
    fn literal(iterator: *Iterator, indexing: Indexing) Error!Field {
        const index = try iterator.readInteger(indexing.prefixBits());
        const name = if (index == 0)
            try iterator.readString()
        else
            try iterator.lookupName(index);
        const value = try iterator.readString();

        const field: Field = .{
            .name = name,
            .value = value,
            .never_indexed = indexing == .never,
        };
        if (indexing == .incremental) {
            // Neither slice aliases the arena: a static name is comptime, and
            // everything else is in the block or the output buffer, because the
            // lookups above copy out of the dynamic table. `insert` asserts it
            // too, from its own side.
            iterator.decoder.table.insert(field);
            assert(iterator.decoder.table.size <= iterator.decoder.table.capacity);
        } else {
            assert(iterator.decoder.table.size <= iterator.decoder.table.capacity);
        }
        try iterator.account(field);
        return field;
    }

    /// RFC 7541 section 6.3.
    fn sizeUpdate(iterator: *Iterator) Error!void {
        // Section 4.2: an update belongs at the beginning of a header block.
        // Accepting one later would let a peer resize the table between two
        // fields of the same list, which no encoder needs and every decoder
        // would then have to agree about.
        if (!iterator.at_block_start) return error.UnexpectedSizeUpdate;
        if (iterator.size_updates == size_updates_max) return error.TooManySizeUpdates;
        iterator.size_updates += 1;
        assert(iterator.size_updates <= size_updates_max);

        const capacity = try iterator.readInteger(prefix_size_update);
        iterator.decoder.table.setCapacity(capacity) catch |err| switch (err) {
            error.CapacityTooLarge => return error.CapacityTooLarge,
        };
        assert(iterator.decoder.table.capacity <= iterator.decoder.table.capacityMax());
        assert(iterator.decoder.table.size <= iterator.decoder.table.capacity);
    }

    /// Resolve a wire index to a whole field.
    ///
    /// A dynamic entry is copied into the output buffer. See the lifetime note
    /// at the top of this file: the slices it would otherwise return stay valid
    /// only until the next insert, and the caller holds them for longer.
    fn lookup(iterator: *Iterator, index: u32) Error!Field {
        assert(index > 0);
        if (static_table.get(index)) |field| return field;
        // `static_table.get` returns null only past its own range, which is
        // what makes the subtraction safe. Stated here rather than inferred
        // from another file.
        assert(index >= static_table.dynamic_offset);

        const position = index - static_table.dynamic_offset;
        const entry = iterator.decoder.table.get(position) orelse return error.InvalidIndex;
        return .{
            .name = try iterator.copyOut(entry.name),
            .value = try iterator.copyOut(entry.value),
        };
    }

    /// Resolve a wire index to a name alone, for a literal carrying its own
    /// value.
    ///
    /// Separate from `lookup` because copying the entry's value as well would
    /// spend output buffer on octets that are then discarded — which tightens
    /// the structural bomb bound below what this module documents, and can
    /// refuse a block that would otherwise have fitted.
    fn lookupName(iterator: *Iterator, index: u32) Error![]const u8 {
        assert(index > 0);
        if (static_table.get(index)) |field| return field.name;
        assert(index >= static_table.dynamic_offset);

        const position = index - static_table.dynamic_offset;
        const entry = iterator.decoder.table.get(position) orelse return error.InvalidIndex;
        return try iterator.copyOut(entry.name);
    }

    /// RFC 7541 section 5.2: a length with an H bit above it, then the octets.
    ///
    /// A literal that was not Huffman-coded is returned as a slice of the block
    /// itself — no copy, and no output buffer spent. Only a Huffman-coded one
    /// has to be materialized, because its octets do not exist anywhere yet.
    fn readString(iterator: *Iterator) Error![]const u8 {
        // The H bit has to be read before the length, and a block that ended
        // after the name has neither. Checked rather than asserted: a truncated
        // block is ordinary hostile input, not a programming error.
        if (iterator.offset >= iterator.block.len) return error.Incomplete;
        const coded = iterator.block[iterator.offset] & 0b1000_0000 != 0;
        const length = try iterator.readInteger(prefix_string);

        const begin = iterator.offset;
        assert(begin <= iterator.block.len);
        // Subtract rather than add. `length` is whatever the peer wrote, up to
        // `maxInt(u32)`, so `begin + length` overflows on input a peer can buy
        // with seven octets — a panic in a safe build, and a backwards slice in
        // a fast one.
        const remaining: u32 = @intCast(iterator.block.len - begin);
        if (length > remaining) return error.Incomplete;

        const end = begin + length;
        assert(end <= iterator.block.len);
        assert(end >= begin);
        iterator.offset = end;
        const raw = iterator.block[begin..end];
        if (!coded) return raw;

        const target = iterator.buffer[iterator.used..];
        const written = huffman.decode(target, raw) catch |err| switch (err) {
            error.Invalid => return error.InvalidHuffman,
            error.OutputTooLong => return error.OutputTooLong,
        };
        iterator.used += written;
        assert(iterator.used <= iterator.buffer.len);
        return target[0..written];
    }

    fn readInteger(iterator: *Iterator, prefix_bits: u4) Error!u32 {
        assert(prefix_bits >= 1);
        assert(prefix_bits <= integer.prefix_bits_max);
        const decoded = integer.decode(iterator.block[iterator.offset..], prefix_bits) catch |err| switch (err) {
            error.Incomplete => return error.Incomplete,
            error.TooLarge => return error.IntegerTooLarge,
        };
        assert(decoded.octets >= 1);
        iterator.offset += decoded.octets;
        assert(iterator.offset <= iterator.block.len);
        return decoded.value;
    }

    fn copyOut(iterator: *Iterator, bytes: []const u8) Error![]const u8 {
        assert(iterator.used <= iterator.buffer.len);
        const remaining = iterator.buffer.len - iterator.used;
        if (bytes.len > remaining) return error.OutputTooLong;
        const target = iterator.buffer[iterator.used..][0..bytes.len];
        // `iterate` asserts the buffer and the arena are disjoint, which is what
        // makes this hold for every source this function is called with.
        assert(!memory.overlaps(target, bytes));
        @memcpy(target, bytes);
        iterator.used += @intCast(bytes.len);
        assert(iterator.used <= iterator.buffer.len);
        return target;
    }

    /// Charge a field against `list_size_max`.
    fn account(iterator: *Iterator, field: Field) Error!void {
        assert(field.size() >= Field.overhead);
        iterator.at_block_start = false;
        iterator.list_size += field.size();
        iterator.field_count += 1;
        assert(iterator.list_size >= field.size());
        assert(iterator.field_count >= 1);
        if (iterator.list_size > iterator.decoder.list_size_max) return error.HeaderListTooLarge;
        // The count bound is this one, not a second knob beside it: every field
        // charged at least `Field.overhead`, so surviving the check above means
        // the count is inside `fieldsMax` as well.
        assert(iterator.field_count <= iterator.decoder.fieldsMax());
    }
};

const testing = std.testing;
const examples = @import("rfc7541_examples.zig");

/// Decode one block into a caller-visible list, for tests.
fn collect(
    decoder: *Decoder,
    buffer: []u8,
    block: []const u8,
    fields: *std.ArrayList(Field),
) !void {
    var iterator = decoder.iterate(buffer, block);
    while (try iterator.next()) |field| try fields.append(testing.allocator, field);
}

test "RFC 7541 Appendix C: every story, in order, sharing one context" {
    for (examples.stories) |story| {
        var arena: [DynamicTable.capacity_max]u8 = undefined;
        var entries: [DynamicTable.entriesRequired(DynamicTable.capacity_max)]DynamicTable.Entry = undefined;
        const table = DynamicTable.init(
            arena[0..story.table_size_max],
            entries[0..DynamicTable.entriesRequired(story.table_size_max)],
        );
        var decoder = Decoder.init(table, 64 * 1024);

        for (story.examples) |example| {
            var buffer: [4096]u8 = undefined;
            var fields: std.ArrayList(Field) = .empty;
            defer fields.deinit(testing.allocator);
            try collect(&decoder, &buffer, example.wire, &fields);

            testing.expectEqual(example.fields.len, fields.items.len) catch |err| {
                std.debug.print("{s} / {s}: field count\n", .{ story.name, example.name });
                return err;
            };
            for (example.fields, fields.items) |want, got| {
                testing.expectEqualStrings(want.name, got.name) catch |err| {
                    std.debug.print("{s} / {s}: name\n", .{ story.name, example.name });
                    return err;
                };
                testing.expectEqualStrings(want.value, got.value) catch |err| {
                    std.debug.print("{s} / {s}: value for {s}\n", .{ story.name, example.name, want.name });
                    return err;
                };
            }
            // The RFC prints the table size after each block; matching it is
            // what proves the evictions happened where they should have, and
            // not merely that the fields came out right.
            testing.expectEqual(example.table_size, decoder.table.size) catch |err| {
                std.debug.print("{s} / {s}: table size\n", .{ story.name, example.name });
                return err;
            };
        }
    }
}

test "a string length near u32 max is refused, not added to the offset" {
    // Seven octets of wire. With the bounds check written as `begin + length >
    // block.len` this panicked in a safe build and sliced backwards in a fast
    // one, because `length` reaches `maxInt(u32)` and `begin` is never zero.
    var storage: DynamicTable.Storage(4096) = .{};
    var decoder = Decoder.init(storage.table(), 64 * 1024);
    var buffer: [256]u8 = undefined;

    const raw = [_]u8{ 0x00, 0x7f, 0x80, 0xff, 0xff, 0xff, 0x0f };
    var raw_iterator = decoder.iterate(&buffer, &raw);
    try testing.expectError(error.Incomplete, raw_iterator.next());

    // The same length behind a Huffman bit takes the other branch out.
    const coded = [_]u8{ 0x00, 0xff, 0x80, 0xff, 0xff, 0xff, 0x0f };
    var coded_iterator = decoder.iterate(&buffer, &coded);
    try testing.expectError(error.Incomplete, coded_iterator.next());
}

test "an error ends the iteration rather than resynchronizing" {
    var storage: DynamicTable.Storage(4096) = .{};
    var decoder = Decoder.init(storage.table(), 64 * 1024);
    var buffer: [256]u8 = undefined;

    // A valid field, then an index into an empty dynamic table, then another
    // well-formed field that must not be produced anyway.
    const block = [_]u8{ 0x82, 0x80 | 62, 0x82 };
    var iterator = decoder.iterate(&buffer, &block);
    try testing.expect((try iterator.next()) != null);
    try testing.expectError(error.InvalidIndex, iterator.next());
    try testing.expectError(error.InvalidIndex, iterator.next());
    try testing.expectError(error.InvalidIndex, iterator.next());
    try testing.expectEqual(@as(u32, 1), iterator.fieldCount());
}

test "a literal with an indexed dynamic name copies the name and not the value" {
    var storage: DynamicTable.Storage(4096) = .{};
    var decoder = Decoder.init(storage.table(), 64 * 1024);

    // Seed one entry with a short name and a long value.
    var seed_buffer: [256]u8 = undefined;
    const seed = [_]u8{ 0x40, 0x02, 'a', 'b', 0x14 } ++ @as([20]u8, @splat('v'));
    var seed_iterator = decoder.iterate(&seed_buffer, &seed);
    try testing.expect((try seed_iterator.next()) != null);

    // Then a literal naming it, with its own one-octet raw value. The buffer
    // has room for the two-octet name and nothing else, so copying the seeded
    // twenty-octet value as well would overflow it.
    //
    // Index 62 does not fit the 4-bit prefix a literal-without-indexing uses,
    // so it is spelled as all-ones plus a continuation of 62 - 15.
    var buffer: [2]u8 = undefined;
    const block = [_]u8{ 0x0f, 62 - 15, 0x01, 'x' };
    var iterator = decoder.iterate(&buffer, &block);
    const field = (try iterator.next()).?;
    try testing.expectEqualStrings("ab", field.name);
    try testing.expectEqualStrings("x", field.value);
}

test "a truncated block yields a proper prefix of the fields, or an error" {
    // The oracle a fuzzer would otherwise have to guess at: cutting a block
    // short can never produce a field the whole block did not, and can never
    // produce a *different* field in the same position. Anything else means a
    // representation was accepted on evidence that had not all arrived.
    for (examples.stories) |story| {
        for (story.examples) |example| {
            var whole_storage: DynamicTable.Storage(4096) = .{};
            var whole_decoder = Decoder.init(whole_storage.table(), 64 * 1024);
            var whole_buffer: [4096]u8 = undefined;
            var whole: std.ArrayList(Field) = .empty;
            defer whole.deinit(testing.allocator);
            collect(&whole_decoder, &whole_buffer, example.wire, &whole) catch {};

            var length: u32 = 0;
            while (length < example.wire.len) : (length += 1) {
                var storage: DynamicTable.Storage(4096) = .{};
                var decoder = Decoder.init(storage.table(), 64 * 1024);
                var buffer: [4096]u8 = undefined;
                var cut: std.ArrayList(Field) = .empty;
                defer cut.deinit(testing.allocator);
                collect(&decoder, &buffer, example.wire[0..length], &cut) catch {};

                try testing.expect(cut.items.len <= whole.items.len);
                for (cut.items, whole.items[0..cut.items.len]) |got, want| {
                    try testing.expectEqualStrings(want.name, got.name);
                    try testing.expectEqualStrings(want.value, got.value);
                }
            }
        }
    }
}

test "an index of zero is not a field" {
    var storage: DynamicTable.Storage(4096) = .{};
    var decoder = Decoder.init(storage.table(), 4096);
    var buffer: [256]u8 = undefined;
    var iterator = decoder.iterate(&buffer, &.{0b1000_0000});
    try testing.expectError(error.InvalidIndex, iterator.next());
}

test "an index past both tables is rejected" {
    var storage: DynamicTable.Storage(4096) = .{};
    var decoder = Decoder.init(storage.table(), 4096);
    var buffer: [256]u8 = undefined;
    // 62 is the first dynamic index, and the table is empty.
    var iterator = decoder.iterate(&buffer, &.{0b1000_0000 | 62});
    try testing.expectError(error.InvalidIndex, iterator.next());
}

test "a truncated representation is Incomplete, never a short field" {
    var storage: DynamicTable.Storage(4096) = .{};
    var decoder = Decoder.init(storage.table(), 4096);

    // Literal with incremental indexing, indexed name 1, value length 5, but
    // only three octets of value present.
    const block = [_]u8{ 0x41, 0x05, 'a', 'b', 'c' };
    var buffer: [256]u8 = undefined;
    var iterator = decoder.iterate(&buffer, &block);
    try testing.expectError(error.Incomplete, iterator.next());
}

test "the header list bound is charged as it decodes" {
    var storage: DynamicTable.Storage(4096) = .{};
    // Two static references cost 2 * (name + value + 32); cap below that.
    var decoder = Decoder.init(storage.table(), 60);
    var buffer: [256]u8 = undefined;

    // 0x82 is :method: GET (7 + 3 + 32 = 42), twice is 84.
    var iterator = decoder.iterate(&buffer, &.{ 0x82, 0x82 });
    try testing.expect((try iterator.next()) != null);
    try testing.expectError(error.HeaderListTooLarge, iterator.next());
}

test "an indexed-reference bomb stops at the buffer, not at the wire length" {
    // The CVE-2016-6581 shape: seed one entry, then reference it thousands of
    // times at one octet each.
    var storage: DynamicTable.Storage(4096) = .{};
    var decoder = Decoder.init(storage.table(), std.math.maxInt(u32));

    var block: [4096]u8 = undefined;
    // Literal with incremental indexing, new name, both strings raw.
    var length: u32 = 0;
    block[length] = 0x40;
    length += 1;
    block[length] = 4;
    length += 1;
    @memcpy(block[length..][0..4], "name");
    length += 4;
    block[length] = 5;
    length += 1;
    @memcpy(block[length..][0..5], "value");
    length += 5;
    // Then a one-octet indexed reference to it, over and over.
    while (length < block.len) : (length += 1) block[length] = 0x80 | 62;

    var buffer: [512]u8 = undefined;
    var iterator = decoder.iterate(&buffer, block[0..length]);
    var produced: u32 = 0;
    var failure: ?Error = null;
    // Bounded: no representation is shorter than one octet of wire.
    while (produced <= length) : (produced += 1) {
        assert(produced <= length);
        const field = iterator.next() catch |err| {
            failure = err;
            break;
        };
        if (field == null) break;
    }

    // The expansion is bounded by the buffer the caller sized, not by the
    // 4 KiB of wire that bought it.
    try testing.expectEqual(Error.OutputTooLong, failure.?);
    try testing.expect(produced < 100);
}

test "a size update is refused once the block has begun" {
    var storage: DynamicTable.Storage(4096) = .{};
    var decoder = Decoder.init(storage.table(), 4096);
    var buffer: [256]u8 = undefined;

    // Leading update is fine.
    var leading = decoder.iterate(&buffer, &.{ 0x20, 0x82 });
    try testing.expect((try leading.next()) != null);

    // The same update after a field is not.
    var trailing = decoder.iterate(&buffer, &.{ 0x82, 0x20 });
    try testing.expect((try trailing.next()) != null);
    try testing.expectError(error.UnexpectedSizeUpdate, trailing.next());
}

test "a third consecutive size update is refused" {
    var storage: DynamicTable.Storage(4096) = .{};
    var decoder = Decoder.init(storage.table(), 4096);
    var buffer: [256]u8 = undefined;
    var iterator = decoder.iterate(&buffer, &.{ 0x20, 0x20, 0x20 });
    try testing.expectError(error.TooManySizeUpdates, iterator.next());
}

test "a size update above the advertised arena is refused" {
    var storage: DynamicTable.Storage(64) = .{};
    var decoder = Decoder.init(storage.table(), 4096);
    var buffer: [256]u8 = undefined;
    // 0x3f 0xe1 0x1f is a 5-bit-prefix integer of 4096.
    var iterator = decoder.iterate(&buffer, &.{ 0x3f, 0xe1, 0x1f });
    try testing.expectError(error.CapacityTooLarge, iterator.next());
}

test "an integer continuation run is rejected rather than followed" {
    var storage: DynamicTable.Storage(4096) = .{};
    var decoder = Decoder.init(storage.table(), 4096);
    var buffer: [256]u8 = undefined;
    var block: [64]u8 = undefined;
    block[0] = 0xff; // indexed, prefix all ones
    @memset(block[1..], 0xff);
    var iterator = decoder.iterate(&buffer, &block);
    try testing.expectError(error.IntegerTooLarge, iterator.next());
}

test "never-indexed survives the decode and does not enter the table" {
    var storage: DynamicTable.Storage(4096) = .{};
    var decoder = Decoder.init(storage.table(), 4096);
    var buffer: [256]u8 = undefined;

    // 0x10: never indexed, new name. Both strings raw.
    const block = [_]u8{ 0x10, 0x01, 'a', 0x01, 'b' };
    var iterator = decoder.iterate(&buffer, &block);
    const field = (try iterator.next()).?;
    try testing.expect(field.never_indexed);
    try testing.expectEqual(@as(u32, 0), decoder.table.count);
}

test "a raw literal borrows the block and spends no output buffer" {
    var storage: DynamicTable.Storage(4096) = .{};
    var decoder = Decoder.init(storage.table(), 4096);

    const block = [_]u8{ 0x00, 0x01, 'a', 0x01, 'b' };
    var buffer: [0]u8 = undefined;
    var iterator = decoder.iterate(&buffer, &block);
    const field = (try iterator.next()).?;

    try testing.expectEqualStrings("a", field.name);
    // The slice is the block's own octets, not a copy of them.
    try testing.expectEqual(@intFromPtr(&block[2]), @intFromPtr(field.name.ptr));
}

test "non-minimal integer encodings decode to the same value" {
    var storage: DynamicTable.Storage(4096) = .{};
    var decoder = Decoder.init(storage.table(), 4096);
    var buffer: [256]u8 = undefined;

    // A value below its prefix maximum has only one spelling, so the shortest
    // index that can be written two ways is the prefix maximum itself. With the
    // 4-bit prefix of a literal-without-indexing that is 15 — static entry
    // `accept-charset` — written minimally as {0x0f, 0x00} and here with an
    // extra zero group. RFC 7541 section 5.1 permits both, so accepting this is
    // interoperation rather than laxity; see the note at the top of the file.
    var iterator = decoder.iterate(&buffer, &.{ 0x0f, 0x80, 0x00, 0x01, 'x' });
    const field = (try iterator.next()).?;
    try testing.expectEqualStrings("accept-charset", field.name);
    try testing.expectEqualStrings("x", field.value);

    // And the minimal spelling of the same index reaches the same entry.
    var minimal = decoder.iterate(&buffer, &.{ 0x0f, 0x00, 0x01, 'x' });
    const same = (try minimal.next()).?;
    try testing.expectEqualStrings("accept-charset", same.name);
}

test "fieldsMax floors, so it is an upper bound and not an approximation" {
    var storage: DynamicTable.Storage(4096) = .{};
    const decoder = Decoder.init(storage.table(), 100);
    // Three fields cost at least 96; a fourth cannot fit in 100.
    try testing.expectEqual(@as(u32, 3), decoder.fieldsMax());
}
