//! RFC 7541 section 6: encoding header fields into a header block.
//!
//! ## Two modes, because the consumers want different things
//!
//! A proxy encodes a different response on every stream and wants the dynamic
//! table working for it. A load generator builds one request at startup and
//! sends it forever, and wants a block it can memcpy onto every stream of every
//! connection.
//!
//! That second one is not an optimization of the first: replaying bytes is only
//! *legal* if they never depended on a dynamic table, because the peer's
//! decoder table evolves and the same octets would resolve differently on the
//! second stream. `.static_only` is a guarantee about what the encoder touched,
//! enforced by `insert` asserting its mode rather than by anyone remembering.
//!
//! ## A short block is not an error
//!
//! `encode` fills what it can and reports how many fields it got through. It
//! cannot fail, and that is a correctness property rather than a convenience.
//!
//! An encoder that inserted into its table and then reported failure would have
//! moved state its peer never saw: the block is discarded, the peer's table
//! stays where it was, and the next block references an entry that does not
//! exist there. That is a connection error manufactured by the encoder — and it
//! is invisible locally, because everything the encoder can see is consistent.
//!
//! Stopping instead of failing makes it impossible: every field that entered
//! the table was also written to the target, so whatever the caller sends keeps
//! the two tables in step. The remainder continues in the next buffer, which is
//! what CONTINUATION frames are for (RFC 9113 section 6.10). A caller that
//! needs the whole list in one buffer compares `fields` against what it passed;
//! a `fields` of zero means the first field cannot fit a buffer of this size at
//! all, and no larger number of retries will help.
//!
//! ## Capacity has to match what the peer advertised
//!
//! The table starts at the capacity of the arena it is given, and no size
//! update is emitted for it. The peer's decoder starts at *its*
//! `SETTINGS_HEADER_TABLE_SIZE`, so the two agree only if the consumer makes
//! them agree.
//!
//! An arena **smaller** than the peer's value is safe: this encoder evicts
//! sooner, its live entries stay a prefix of the peer's in the same order, and
//! every index it emits still resolves to the same field. An arena **larger**
//! is corruption, and the quiet kind — it indexes entries the peer has already
//! evicted, and the failure surfaces as a decode error on a later block. This
//! package cannot check it, because only the consumer sees the SETTINGS frame.
//! Size the arena at or below `SETTINGS_HEADER_TABLE_SIZE`, or call
//! `encodeSizeUpdate` to move the peer first.
//!
//! ## Where the time goes
//!
//! Huffman coding is not the cost centre here; lookup is. The static table is a
//! comptime `StaticStringMap` from name to the run of entries sharing it —
//! RFC 7541 keeps same-named entries adjacent, so a name hit gives a short
//! contiguous range to compare values against, and `:status`'s seven is the
//! longest run there is. One probe answers both questions.
//!
//! The dynamic table is searched through two arrays of hashes kept parallel to
//! its entry ring. Whether an explicit `@Vector` scan earns its complexity is
//! still open: at 4 KiB there are at most 128 hashes, 512 octets, and the
//! benchmark workload keeps tables of three or four entries, so it does not
//! exercise a full one. That measurement needs a workload built for it.
//!
//! ## Indexing policy
//!
//! Every field that is not `never_indexed` is inserted, which is what the RFC's
//! own examples do and what makes them an exact-output gate rather than merely
//! a round-trip one. A consumer that wants a different policy — not indexing a
//! request identifier that will never repeat, say — sets `never_indexed`, which
//! is also the representation that keeps it out of an intermediary's table.

const std = @import("std");

const Encoder = @This();

const assert = @import("../assert.zig").assert;

const DynamicTable = @import("DynamicTable.zig");
const Field = @import("Field.zig");
const huffman_codec = @import("huffman.zig");
const integer = @import("integer.zig");
const static_table = @import("static_table.zig");

/// RFC 7541 section 6.1: `1` then a 7-bit index.
const tag_indexed: u8 = 0b1000_0000;
const prefix_indexed: u4 = 7;
/// Section 6.2.1: `01` then a 6-bit name index.
const tag_incremental: u8 = 0b0100_0000;
const prefix_incremental: u4 = 6;
/// Section 6.2.2: `0000` then a 4-bit name index.
const tag_without: u8 = 0b0000_0000;
const prefix_without: u4 = 4;
/// Section 6.2.3: `0001` then a 4-bit name index.
const tag_never: u8 = 0b0001_0000;
const prefix_never: u4 = 4;
/// Section 6.3: `001` then a 5-bit capacity.
const tag_size_update: u8 = 0b0010_0000;
const prefix_size_update: u4 = 5;
/// Section 5.2: `H` then a 7-bit length.
const tag_huffman: u8 = 0b1000_0000;
const prefix_string: u4 = 7;

comptime {
    // Each tag must clear the prefix it sits above, or the length would be read
    // back as part of the tag.
    assert(tag_indexed & ((1 << prefix_indexed) - 1) == 0);
    assert(tag_incremental & ((1 << prefix_incremental) - 1) == 0);
    assert(tag_without & ((1 << prefix_without) - 1) == 0);
    assert(tag_never & ((1 << prefix_never) - 1) == 0);
    assert(tag_size_update & ((1 << prefix_size_update) - 1) == 0);
    assert(tag_huffman & ((1 << prefix_string) - 1) == 0);
    // The three literal forms must be distinguishable from each other and from
    // an indexed field, which is what the decoder's lead-octet ladder rests on.
    assert(tag_without != tag_never);
    assert(tag_incremental & tag_indexed == 0);
    // And every prefix must be one the integer codec can represent.
    assert(prefix_indexed <= integer.prefix_bits_max);
    assert(prefix_incremental <= integer.prefix_bits_max);
    assert(prefix_without <= integer.prefix_bits_max);
    assert(prefix_never <= integer.prefix_bits_max);
    assert(prefix_size_update <= integer.prefix_bits_max);
    assert(prefix_string <= integer.prefix_bits_max);
}

pub const Mode = enum {
    /// Read and write the dynamic table. The output depends on this encoder's
    /// table state, so it is valid exactly once, on the stream it was made for.
    dynamic,
    /// Never touch the dynamic table. The output is a pure function of the
    /// fields, so it may be encoded once and replayed forever.
    static_only,
};

pub const Huffman = enum {
    /// Use Huffman coding only when it produces strictly fewer octets.
    ///
    /// The default, and it differs from the encoder that produced the RFC's
    /// examples on exact ties. `:status: 307` is three octets either way, and
    /// C.6.2 codes it; this does not. Same wire size, and the peer is spared a
    /// Huffman decode, so a tie should go to the raw form.
    if_shorter,
    /// Always, even where it is longer.
    ///
    /// Not a compression setting — it is what the RFC's Huffman examples do
    /// unconditionally, and having it is what lets those examples be an
    /// exact-output gate instead of only a round-trip one.
    always,
    /// Never. Likewise what the RFC's non-Huffman examples need.
    never,
};

table: DynamicTable,
/// One hash per ring slot, parallel to `table.entries`: of the name alone, and
/// of the name and value together. Only slots holding a live entry are read,
/// and a slot is written by the insert that fills it.
name_hashes: []u32,
field_hashes: []u32,
mode: Mode,
huffman: Huffman = .if_shorter,

/// Both hash arrays must be as long as the table's entry ring. `Storage` gets
/// this right by construction; a consumer sizing from configuration is asserted
/// here rather than finding out at the first insert.
pub fn init(
    table: DynamicTable,
    name_hashes: []u32,
    field_hashes: []u32,
    mode: Mode,
) Encoder {
    assert(name_hashes.len >= table.entries.len);
    assert(field_hashes.len >= table.entries.len);
    assert(table.size <= table.capacity);
    return .{
        .table = table,
        .name_hashes = name_hashes,
        .field_hashes = field_hashes,
        .mode = mode,
    };
}

/// Storage for an encoder over a table of `capacity` octets.
pub fn Storage(comptime capacity: u32) type {
    return struct {
        table: DynamicTable.Storage(capacity) = .{},
        name_hashes: [DynamicTable.entriesRequired(capacity)]u32 = undefined,
        field_hashes: [DynamicTable.entriesRequired(capacity)]u32 = undefined,

        pub fn encoder(storage: *@This(), mode: Mode) Encoder {
            return Encoder.init(
                storage.table.table(),
                &storage.name_hashes,
                &storage.field_hashes,
                mode,
            );
        }
    };
}

pub const Encoded = struct {
    /// Octets written to `target`.
    written: u32,
    /// Fields encoded. Fewer than were offered means the target filled up, and
    /// the rest continue in the next buffer. Zero means the first field cannot
    /// fit a buffer this size at all.
    fields: u32,
};

/// Encode as many of `fields` as fit.
///
/// See the module header: this cannot fail, because an encoder that mutated its
/// table and then reported failure would desynchronize the connection.
pub fn encode(encoder: *Encoder, target: []u8, fields: []const Field) Encoded {
    assert(target.len <= std.math.maxInt(u32));
    assert(fields.len <= std.math.maxInt(u32));
    const size_before = encoder.table.size;
    const count_before = encoder.table.count;
    const end_before = encoder.table.end;

    var written: u32 = 0;
    var encoded: u32 = 0;
    for (fields) |field| {
        written += encoder.encodeField(target[written..], field) catch break;
        encoded += 1;
        assert(written <= target.len);
    }

    if (encoder.mode == .static_only) {
        // Checked on three counters, not one. At steady state an insert evicts
        // exactly one entry, so `count` alone is invariant under the very
        // mutation this is meant to catch.
        assert(encoder.table.size == size_before);
        assert(encoder.table.count == count_before);
        assert(encoder.table.end == end_before);
    }
    assert(encoded <= fields.len);
    return .{ .written = written, .fields = encoded };
}

const FieldError = error{
    /// The field's representation does not fit the remaining target.
    OutputTooLong,
};

/// `encodeSizeUpdate`'s errors: `FieldError` plus the one that is about the
/// capacity rather than about the target.
pub const SizeUpdateError = FieldError || DynamicTable.CapacityError;

/// Encode one field, or write nothing at all.
///
/// Atomic by construction: the whole representation's length is computed before
/// any of it is written, and the table is touched only after the write
/// succeeded. That is what lets `encode` stop cleanly at any field.
pub fn encodeField(encoder: *Encoder, target: []u8, field: Field) FieldError!u32 {
    if (field.never_indexed) {
        // Section 6.2.3. The name may still be indexed — what must not happen
        // is the *value* entering any table, here or at an intermediary. The
        // value is not searched for, because finding it would only tempt a
        // representation that indexes it.
        const name_index = encoder.lookupName(field.name);
        return try encoder.writeLiteral(target, field, name_index, tag_never, prefix_never);
    }

    const match = encoder.lookup(field);
    if (match.field_index) |index| {
        // Section 6.1: the whole field in one integer.
        assert(index > 0);
        return integer.encode(target, index, prefix_indexed, tag_indexed) catch
            return error.OutputTooLong;
    }

    if (encoder.mode == .static_only) {
        return try encoder.writeLiteral(target, field, match.name_index, tag_without, prefix_without);
    }

    const written = try encoder.writeLiteral(target, field, match.name_index, tag_incremental, prefix_incremental);
    encoder.insert(field);
    return written;
}

/// Emit a dynamic table size update (RFC 7541 section 6.3) and apply it.
///
/// It belongs at the start of a header block, before any field: the decoder
/// here rejects one anywhere else, and so does every other conforming
/// implementation. At most two may appear together, so a consumer that changes
/// capacity twice between blocks emits both and no more.
///
/// `capacity` is bounded by this encoder's arena, which is not necessarily what
/// the peer will accept — see the module header on matching
/// `SETTINGS_HEADER_TABLE_SIZE`.
///
/// That bound is a *returned error*, not an assertion, and the distinction is
/// the whole reason `src/assert.zig` exists. A consumer will plausibly pass a
/// capacity straight from the peer's `SETTINGS_HEADER_TABLE_SIZE`, so this is
/// peer-controlled input reaching a `pub fn`; guarding it with an assertion
/// left `setCapacity`'s `catch unreachable` genuinely reachable, and under
/// `-Dassertions=false` in ReleaseFast that is undefined behaviour — measured
/// as an unkillable spin, which is a remote livelock on zoxy's threat model.
///
/// Checked before anything is written, so a rejected call leaves `target`
/// untouched — the same atomicity `encodeField` documents.
pub fn encodeSizeUpdate(encoder: *Encoder, target: []u8, capacity: u32) SizeUpdateError!u32 {
    // Still an assertion, and correctly so: a `.static_only` encoder emitting a
    // size update is a caller's programming error, not something a peer can
    // provoke.
    assert(encoder.mode == .dynamic);
    if (capacity > encoder.table.capacityMax()) return error.CapacityTooLarge;

    const written = integer.encode(target, capacity, prefix_size_update, tag_size_update) catch
        return error.OutputTooLong;
    // Now genuinely unreachable: the check above is the same one `setCapacity`
    // makes, and it is in the binary whatever `-Dassertions` says.
    encoder.table.setCapacity(capacity) catch unreachable;
    assert(encoder.table.capacity == capacity);
    assert(encoder.table.size <= capacity);
    return written;
}

// ── Representations ─────────────────────────────────────────────────────────

/// How one string will be written, decided once so the length can be checked
/// before any of it lands.
const StringPlan = struct {
    /// Payload octets on the wire.
    length: u32,
    /// Octets of the length header in front of them.
    header: u32,
    coded: bool,

    fn total(plan: StringPlan) u32 {
        return plan.header + plan.length;
    }
};

fn planString(encoder: *const Encoder, source: []const u8) StringPlan {
    assert(source.len <= std.math.maxInt(u32));
    // `.never` must not pay for a length it will not use, and `.if_shorter`
    // must not compute it twice.
    const coded_length: ?u64 = switch (encoder.huffman) {
        .never => null,
        .always => huffman_codec.encodedLength(source),
        .if_shorter => blk: {
            const length = huffman_codec.encodedLength(source);
            break :blk if (length < source.len) length else null;
        },
    };
    const length: u32 = @intCast(coded_length orelse source.len);
    return .{
        .length = length,
        .header = integer.encodedLength(length, prefix_string),
        .coded = coded_length != null,
    };
}

fn writeString(target: []u8, plan: StringPlan, source: []const u8) u32 {
    assert(target.len >= plan.total());
    const tag: u8 = if (plan.coded) tag_huffman else 0;
    const header = integer.encode(target, plan.length, prefix_string, tag) catch unreachable;
    assert(header == plan.header);

    if (plan.coded) {
        const coded = huffman_codec.encode(target[header..], source) catch unreachable;
        assert(coded == plan.length);
    } else {
        assert(plan.length == source.len);
        @memcpy(target[header..][0..plan.length], source);
    }
    return plan.total();
}

/// A literal representation: a name index or a literal name, then the value.
fn writeLiteral(
    encoder: *const Encoder,
    target: []u8,
    field: Field,
    name_index: ?u32,
    tag: u8,
    prefix_bits: u4,
) FieldError!u32 {
    // Index zero in this slot means "a literal name follows", so a real index
    // of zero would be a corrupt representation rather than a small one.
    if (name_index) |index| assert(index > 0);

    const index_length = integer.encodedLength(name_index orelse 0, prefix_bits);
    const name_plan: ?StringPlan = if (name_index == null) encoder.planString(field.name) else null;
    const value_plan = encoder.planString(field.value);

    var total: u64 = index_length;
    if (name_plan) |plan| total += plan.total();
    total += value_plan.total();
    // Checked once for the whole representation. Checking each part as it goes
    // would leave a name index and a complete name behind when the value did
    // not fit, which is a corrupt block rather than a short one.
    if (total > target.len) return error.OutputTooLong;

    var written = integer.encode(target, name_index orelse 0, prefix_bits, tag) catch unreachable;
    assert(written == index_length);
    if (name_plan) |plan| written += writeString(target[written..], plan, field.name);
    written += writeString(target[written..], value_plan, field.value);
    assert(written == total);
    assert(written >= 1);
    return written;
}

// ── Lookup ──────────────────────────────────────────────────────────────────

const Match = struct {
    /// Lowest wire index sharing the name, or null.
    name_index: ?u32 = null,
    /// Wire index matching both name and value, or null.
    field_index: ?u32 = null,
};

/// Where `field` can be found, preferring the representation that encodes in
/// the fewest octets.
///
/// The order is not arbitrary. A static full match is one octet and a fixed
/// index; a dynamic full match is one or two; a name match saves only the name.
/// Within the dynamic table the newest entry wins, because it has the smallest
/// index and the longest left to live.
///
/// One static probe, whatever the outcome: hashing the name twice per field was
/// most of what made encoding slower than decoding.
fn lookup(encoder: *const Encoder, field: Field) Match {
    const static = static_table.find(field.name, field.value);
    if (static.field_index) |index| {
        assert(index < static_table.dynamic_offset);
        return .{ .name_index = static.name_index, .field_index = index };
    }
    if (encoder.mode == .static_only) return .{ .name_index = static.name_index };

    if (encoder.scan(encoder.field_hashes, hashField(field.name, field.value), field, .name_and_value)) |position| {
        return .{ .name_index = static.name_index, .field_index = encoder.wireIndex(position) };
    }
    if (static.name_index) |index| return .{ .name_index = index };
    if (encoder.scan(encoder.name_hashes, hashName(field.name), field, .name_only)) |position| {
        return .{ .name_index = encoder.wireIndex(position) };
    }
    return .{};
}

/// The name half alone, for a never-indexed field whose value must not be
/// looked for.
fn lookupName(encoder: *const Encoder, name: []const u8) ?u32 {
    if (static_table.findName(name)) |index| {
        assert(index < static_table.dynamic_offset);
        return index;
    }
    if (encoder.mode == .static_only) return null;
    const field: Field = .{ .name = name, .value = "" };
    if (encoder.scan(encoder.name_hashes, hashName(name), field, .name_only)) |position| {
        return encoder.wireIndex(position);
    }
    return null;
}

/// A dynamic table position as the index that names it on the wire.
fn wireIndex(encoder: *const Encoder, position: u32) u32 {
    assert(position < encoder.table.count);
    const index = position + static_table.dynamic_offset;
    assert(index >= static_table.dynamic_offset);
    assert(index < static_table.dynamic_offset + encoder.table.count);
    return index;
}

const Want = enum { name_only, name_and_value };

/// The newest live entry whose hash matches, confirmed by a real comparison.
///
/// Newest first, so the smallest index wins: a nearer entry encodes in fewer
/// octets and has longer left before eviction.
///
/// Walked as one or two contiguous runs of slots rather than position by
/// position. `slotOf` is a modulo, and paying one per candidate to read an
/// array whose live span is already contiguous is work the shape of the data
/// does not require — the ring wraps at most once, so the live slots are
/// `[newest, entries)` followed by `[0, remainder)`. A strided read is also
/// something no compiler will turn into a vector load, and a contiguous one is.
fn scan(
    encoder: *const Encoder,
    hashes: []const u32,
    wanted: u32,
    field: Field,
    want: Want,
) ?u32 {
    const count = encoder.table.count;
    if (count == 0) return null;
    const entries_count: u32 = @intCast(encoder.table.entries.len);
    assert(count <= entries_count);
    assert(hashes.len >= entries_count);

    const newest = encoder.table.newest;
    assert(newest < entries_count);

    // Below one vector there is nothing to vectorize, and splitting the live
    // span into runs to discover that costs more than the walk it replaces.
    // Measured: without this, a table of three or four entries — which is what
    // the RFC's own examples keep, and what a connection has just after its
    // first request — encoded about 2% slower.
    if (count < scan_lanes) return encoder.scanStrided(hashes, wanted, field, want);

    // Position zero is the newest, and the run from it reaches either the end
    // of the live span or the end of the array, whichever comes first.
    const leading_count = @min(count, entries_count - newest);
    assert(leading_count >= 1);
    assert(leading_count <= count);
    if (encoder.scanRun(hashes[newest..][0..leading_count], wanted, field, want, 0)) |position| {
        return position;
    }
    if (leading_count == count) return null;

    // The wrapped remainder, which starts at slot zero by construction. Its
    // first entry's *position* is the leading run's *count*, which holds only
    // because positions are dense from zero — a count standing in for a
    // position is worth saying out loud rather than leaving to arithmetic.
    const trailing_count = count - leading_count;
    assert(trailing_count < entries_count);
    assert(newest + leading_count == entries_count);
    return encoder.scanRun(hashes[0..trailing_count], wanted, field, want, leading_count);
}

/// One contiguous run of slots, whose first entry is `position_begin` places
/// back from the newest.
///
/// Eight hashes per compare. The whole live span of a 4 KiB table is 512 octets
/// — two cache lines — and a hash mismatch is the overwhelmingly common case, so
/// the loop's job is to reject as many as possible per instruction and only
/// then confirm.
fn scanRun(
    encoder: *const Encoder,
    run: []const u32,
    wanted: u32,
    field: Field,
    want: Want,
    position_begin: u32,
) ?u32 {
    assert(run.len <= encoder.table.entries.len);
    // The invariant a wrong run start breaks, stated where every call checks
    // it. `confirm` would catch it too, but only on a hash hit — a bad start
    // that lands on mismatching hashes returns null and says nothing.
    assert(position_begin + run.len <= encoder.table.count);

    const wanted_lanes: @Vector(scan_lanes, u32) = @splat(wanted);
    var offset: usize = 0;
    // Subtraction rather than `offset + scan_lanes <= run.len`: the sum is what
    // would overflow, and a bound that can overflow before it is compared is
    // not a bound.
    while (run.len - offset >= scan_lanes) : (offset += scan_lanes) {
        const chunk: @Vector(scan_lanes, u32) = run[offset..][0..scan_lanes].*;
        const hits = chunk == wanted_lanes;
        if (!@reduce(.Or, hits)) continue;
        // Lanes in order, because the newest match is the one to return and
        // lane order is position order.
        inline for (0..scan_lanes) |lane| {
            if (hits[lane]) {
                if (encoder.confirm(field, want, position_begin + @as(u32, @intCast(offset + lane)))) |position| {
                    return position;
                }
            }
        }
    }

    assert(run.len - offset < scan_lanes);
    while (offset < run.len) : (offset += 1) {
        if (run[offset] != wanted) continue;
        if (encoder.confirm(field, want, position_begin + @as(u32, @intCast(offset)))) |position| {
            return position;
        }
    }
    return null;
}

/// The straight walk: one slot per position, newest first.
///
/// `scan` uses it for a live span too short to fill a vector, and the tests use
/// it as the reference the vector path must agree with.
///
/// `slotOf` is a modulo, and it is not the cost it looks like: the position
/// advances by one, so the compiler strength-reduces it to a compare and a
/// subtract. Replacing it with contiguous-run arithmetic measured *slower* on
/// its own, and is worth having only because it is what lets the run above be
/// a vector load.
fn scanStrided(
    encoder: *const Encoder,
    hashes: []const u32,
    wanted: u32,
    field: Field,
    want: Want,
) ?u32 {
    const count = encoder.table.count;
    // No threshold asserted here on purpose. `scan` decides when to call this
    // rather than the vector path, but the walk itself is correct for any
    // count — which is what lets a test use it as the reference the vector path
    // is checked against, on a table large enough that `scan` would not have
    // chosen it.
    assert(count <= encoder.table.entries.len);
    var position: u32 = 0;
    while (position < count) : (position += 1) {
        const slot = encoder.table.slotOf(position);
        assert(slot < encoder.table.entries.len);
        if (hashes[slot] != wanted) continue;
        if (encoder.confirm(field, want, position)) |found| return found;
    }
    return null;
}

/// Hashes compared per chunk: 32 octets, which is one 256-bit vector where
/// there is one and two 128-bit registers where there is not. On the arm64 this
/// was measured on it lowers to a pair of `ldp`-loaded `q` registers and two
/// `cmeq.4s`, and the per-chunk cost is dominated by the horizontal reduction
/// rather than by the compares — which is why the win is a little under half
/// the scan rather than anything near eightfold.
///
/// Sixteen was tried on that reasoning, since halving the chunks halves the
/// reductions, and measured slower: a realistic table holds forty-odd entries,
/// so sixteen lanes leaves a fifteen-element scalar tail where eight leaves
/// seven. The tail is the thing to keep small at these lengths.
const scan_lanes: u32 = 8;

comptime {
    assert(scan_lanes >= 1);
    // A run is at most the whole entry array, so the largest table this package
    // can hold is the neighbour worth relating to. There is deliberately no
    // lower relation: `entriesRequired(0)` is zero and a table that small is
    // legal, which `scan` handles by taking the strided walk rather than by
    // forming a run at all.
    assert(scan_lanes <= DynamicTable.entriesRequired(DynamicTable.capacity_max));
}

/// A hash hit is a candidate, not an answer.
fn confirm(encoder: *const Encoder, field: Field, want: Want, position: u32) ?u32 {
    assert(position < encoder.table.count);
    const entry = encoder.table.get(position).?;
    if (!std.mem.eql(u8, entry.name, field.name)) return null;
    if (want == .name_and_value and !std.mem.eql(u8, entry.value, field.value)) return null;
    return position;
}

fn insert(encoder: *Encoder, field: Field) void {
    // `.static_only`'s guarantee, enforced where it would be broken rather than
    // checked afterwards.
    assert(encoder.mode == .dynamic);
    encoder.table.insert(field);
    if (encoder.table.count == 0) return; // Did not fit; the table was cleared.

    // A slot is written by the insert that fills it, and read only while that
    // entry is live, so eviction needs no work here: it moves the boundary
    // rather than the contents.
    const slot = encoder.table.slotOf(0);
    assert(slot < encoder.name_hashes.len);
    assert(slot < encoder.field_hashes.len);
    encoder.name_hashes[slot] = hashName(field.name);
    encoder.field_hashes[slot] = hashField(field.name, field.value);
}

fn hashName(name: []const u8) u32 {
    return std.hash.Fnv1a_32.hash(name);
}

fn hashField(name: []const u8, value: []const u8) u32 {
    var hasher = std.hash.Fnv1a_32.init();
    hasher.update(name);
    // A separator, so ("ab", "c") and ("a", "bc") differ by construction rather
    // than by luck.
    hasher.update(&[_]u8{0});
    hasher.update(value);
    return hasher.final();
}

const testing = std.testing;
const Decoder = @import("Decoder.zig");
const examples = @import("rfc7541_examples.zig");

test "RFC 7541 Appendix C: encoding reproduces the RFC's own octets" {
    // The RFC's encoder policy is this one — index everything, prefer an
    // indexed reference — so the examples are an exact-output gate rather than
    // only a round trip. Byte equality against a published encoding pins the
    // representation choices and not just the decoded result.
    for (examples.stories) |story| {
        var storage: Storage(DynamicTable.capacity_max) = .{};
        var encoder = storage.encoder(.dynamic);
        encoder.huffman = if (story.huffman) .always else .never;
        try encoder.table.setCapacity(story.table_size_max);

        for (story.examples) |example| {
            var target: [4096]u8 = undefined;
            const result = encoder.encode(&target, example.fields);
            testing.expectEqual(example.fields.len, result.fields) catch |err| {
                std.debug.print("{s} / {s}: field count\n", .{ story.name, example.name });
                return err;
            };
            testing.expectEqualSlices(u8, example.wire, target[0..result.written]) catch |err| {
                std.debug.print("{s} / {s}\n", .{ story.name, example.name });
                return err;
            };
            testing.expectEqual(example.table_size, encoder.table.size) catch |err| {
                std.debug.print("{s} / {s}: table size\n", .{ story.name, example.name });
                return err;
            };
        }
    }
}

test "a short target stops cleanly and leaves the table where the block ended" {
    // The bug this design exists to make impossible. Encoding into a buffer too
    // small used to insert the fields that fit, report failure, and leave the
    // encoder holding entries the peer had never seen — so the retry emitted an
    // indexed reference to index 62 and the peer answered InvalidIndex.
    var storage: Storage(4096) = .{};
    var encoder = storage.encoder(.dynamic);
    const fields = [_]Field{
        .{ .name = "x-one", .value = "aaaa" },
        .{ .name = "x-two", .value = "bbbb" },
    };

    var small: [12]u8 = undefined;
    const partial = encoder.encode(&small, &fields);
    try testing.expect(partial.fields < fields.len);

    // Whatever entered the table was also written, so a decoder fed exactly
    // those octets agrees about it.
    var decoder_storage: DynamicTable.Storage(4096) = .{};
    var decoder = Decoder.init(decoder_storage.table(), 64 * 1024);
    var buffer: [512]u8 = undefined;
    var iterator = decoder.iterate(&buffer, small[0..partial.written]);
    var seen: u32 = 0;
    while (try iterator.next()) |_| seen += 1;

    try testing.expectEqual(partial.fields, seen);
    try testing.expectEqual(encoder.table.count, decoder.table.count);
    try testing.expectEqual(encoder.table.size, decoder.table.size);

    // And the remainder continues into the next buffer, as a CONTINUATION
    // frame would carry it.
    var rest: [256]u8 = undefined;
    const remainder = encoder.encode(&rest, fields[partial.fields..]);
    try testing.expectEqual(fields.len - partial.fields, remainder.fields);

    var rest_iterator = decoder.iterate(&buffer, rest[0..remainder.written]);
    for (fields[partial.fields..]) |want| {
        const got = (try rest_iterator.next()).?;
        try testing.expectEqualStrings(want.name, got.name);
        try testing.expectEqualStrings(want.value, got.value);
    }
    try testing.expectEqual(encoder.table.size, decoder.table.size);
}

test "a field too large for the target at all reports zero rather than looping" {
    var storage: Storage(4096) = .{};
    var encoder = storage.encoder(.dynamic);
    const fields = [_]Field{.{ .name = "x-name", .value = "a value that will not fit" }};

    var tiny: [4]u8 = undefined;
    const result = encoder.encode(&tiny, &fields);
    try testing.expectEqual(@as(u32, 0), result.fields);
    try testing.expectEqual(@as(u32, 0), result.written);
    // Nothing was written, so nothing was indexed.
    try testing.expectEqual(@as(u32, 0), encoder.table.count);
}

test "a literal never lands half-written" {
    // A name index and a complete literal name followed by no value would be a
    // corrupt representation, not a short one. Every prefix length of a literal
    // must therefore write nothing at all.
    var storage: Storage(4096) = .{};
    const fields = [_]Field{.{ .name = "x-custom-name", .value = "a custom value" }};

    var full_storage: Storage(4096) = .{};
    var full_encoder = full_storage.encoder(.dynamic);
    var full: [256]u8 = undefined;
    const needed = full_encoder.encode(&full, &fields).written;

    var length: u32 = 0;
    while (length < needed) : (length += 1) {
        var encoder = storage.encoder(.dynamic);
        var target: [256]u8 = undefined;
        @memset(target[0..], 0xaa);
        const result = encoder.encode(target[0..length], &fields);
        try testing.expectEqual(@as(u32, 0), result.fields);
        try testing.expectEqual(@as(u32, 0), result.written);
        for (target[0..length]) |octet| try testing.expectEqual(@as(u8, 0xaa), octet);
    }
}

test "a Huffman tie goes to the raw form, which is where the RFC's encoder differs" {
    // `:status: 307` is three octets raw and three Huffman-coded. RFC 7541
    // C.6.2 codes it; the default here does not, because the sizes are equal
    // and the raw form spares the peer a decode. Pinned so the divergence stays
    // a decision rather than becoming a surprise.
    const text = "307";
    try testing.expectEqual(@as(u64, text.len), huffman_codec.encodedLength(text));

    var storage: Storage(4096) = .{};
    var encoder = storage.encoder(.static_only);
    var block: [64]u8 = undefined;

    const raw = encoder.encode(&block, &.{.{ .name = ":status", .value = text }});
    try testing.expectEqual(@as(u8, 0x08), block[0]); // Literal, name index 8.
    try testing.expectEqual(@as(u8, 0x03), block[1]); // H clear, length 3.
    try testing.expectEqualStrings(text, block[2..raw.written]);

    encoder.huffman = .always;
    const coded = encoder.encode(&block, &.{.{ .name = ":status", .value = text }});
    try testing.expectEqual(@as(u8, 0x83), block[1]); // H set, length 3.
    try testing.expectEqual(raw.written, coded.written);
}

test "static-only mode never touches the table, so its output replays" {
    var storage: Storage(4096) = .{};
    var encoder = storage.encoder(.static_only);

    const fields = [_]Field{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/" },
        .{ .name = "user-agent", .value = "zrk" },
    };

    var first: [256]u8 = undefined;
    var second: [256]u8 = undefined;
    const one = encoder.encode(&first, &fields);
    const two = encoder.encode(&second, &fields);

    try testing.expectEqualSlices(u8, first[0..one.written], second[0..two.written]);
    try testing.expectEqual(@as(u32, 0), encoder.table.count);
}

test "a static-only block decodes the same on a stream that never saw the first" {
    // The property replaying actually depends on: a decoder whose table has
    // moved on must still read the same fields out of the same octets.
    var encoder_storage: Storage(4096) = .{};
    var encoder = encoder_storage.encoder(.static_only);

    const fields = [_]Field{
        .{ .name = ":method", .value = "GET" },
        .{ .name = "x-request-id", .value = "abcdef" },
    };
    var block: [256]u8 = undefined;
    const result = encoder.encode(&block, &fields);
    try testing.expectEqual(fields.len, result.fields);

    var decoder_storage: DynamicTable.Storage(4096) = .{};
    var decoder = Decoder.init(decoder_storage.table(), 64 * 1024);
    var buffer: [512]u8 = undefined;

    var round: u32 = 0;
    while (round < 3) : (round += 1) {
        var iterator = decoder.iterate(&buffer, block[0..result.written]);
        for (fields) |want| {
            const got = (try iterator.next()).?;
            try testing.expectEqualStrings(want.name, got.name);
            try testing.expectEqualStrings(want.value, got.value);
        }
        try testing.expectEqual(@as(?Field, null), try iterator.next());
    }
    try testing.expectEqual(@as(u32, 0), decoder.table.count);
}

test "a never-indexed field stays out of both tables and keeps its bit" {
    var storage: Storage(4096) = .{};
    var encoder = storage.encoder(.dynamic);

    const fields = [_]Field{
        .{ .name = "authorization", .value = "secret", .never_indexed = true },
    };
    var block: [256]u8 = undefined;
    const result = encoder.encode(&block, &fields);
    try testing.expectEqual(@as(u32, 0), encoder.table.count);

    var decoder_storage: DynamicTable.Storage(4096) = .{};
    var decoder = Decoder.init(decoder_storage.table(), 64 * 1024);
    var buffer: [512]u8 = undefined;
    var iterator = decoder.iterate(&buffer, block[0..result.written]);
    const got = (try iterator.next()).?;

    try testing.expect(got.never_indexed);
    try testing.expectEqualStrings("secret", got.value);
    try testing.expectEqual(@as(u32, 0), decoder.table.count);
}

test "the dynamic table is searched, newest first" {
    var storage: Storage(4096) = .{};
    var encoder = storage.encoder(.dynamic);
    var block: [256]u8 = undefined;

    const fields = [_]Field{.{ .name = "x-custom", .value = "value" }};
    const first = encoder.encode(&block, &fields);
    try testing.expect(first.written > 10);

    const second = encoder.encode(&block, &fields);
    try testing.expectEqual(@as(u32, 1), second.written);
    try testing.expectEqual(@as(u8, 0x80 | 62), block[0]);

    // A different value under the same name reuses the name index only.
    const other = [_]Field{.{ .name = "x-custom", .value = "other" }};
    const third = encoder.encode(&block, &other);
    try testing.expect(third.written > 1);
    try testing.expect(third.written < first.written);
}

test "a capacity larger than the arena is refused, not asserted" {
    // The guard used to be an assertion, which `-Dassertions=false` removes —
    // and then `setCapacity`'s `catch unreachable` was reachable from a `pub
    // fn` on a value a consumer plausibly takes from the peer's
    // SETTINGS_HEADER_TABLE_SIZE. In ReleaseFast that was an unkillable spin.
    // This test fails against the assertion-guarded version in every build
    // where assertions are off, and panics in every build where they are on.
    var storage: Storage(256) = .{};
    var encoder = storage.encoder(.dynamic);
    var target: [64]u8 = undefined;

    try std.testing.expectError(
        error.CapacityTooLarge,
        encoder.encodeSizeUpdate(&target, 4096),
    );
    // Nothing was written and nothing moved: the check runs before the encode.
    try std.testing.expectEqual(@as(u32, 256), encoder.table.capacity);

    // The boundary itself is accepted.
    const written = try encoder.encodeSizeUpdate(&target, encoder.table.capacityMax());
    try std.testing.expect(written >= 1);
    try std.testing.expectEqual(encoder.table.capacityMax(), encoder.table.capacity);
}

test "a size update moves both tables and is accepted by the decoder" {
    var encoder_storage: Storage(4096) = .{};
    var encoder = encoder_storage.encoder(.dynamic);

    var decoder_storage: DynamicTable.Storage(4096) = .{};
    var decoder = Decoder.init(decoder_storage.table(), 64 * 1024);

    // Seed an entry, then shrink below what it costs.
    var block: [256]u8 = undefined;
    const seeded = encoder.encode(&block, &.{.{ .name = "x-name", .value = "x-value" }});
    try testing.expectEqual(@as(u32, 1), encoder.table.count);

    var buffer: [512]u8 = undefined;
    var seed_iterator = decoder.iterate(&buffer, block[0..seeded.written]);
    while (try seed_iterator.next()) |_| {}
    try testing.expectEqual(encoder.table.size, decoder.table.size);

    // A size update leads the next block, which is the only place the decoder
    // accepts one.
    var update: [16]u8 = undefined;
    const update_written = try encoder.encodeSizeUpdate(&update, 32);
    try testing.expectEqual(@as(u32, 0), encoder.table.count);

    var update_iterator = decoder.iterate(&buffer, update[0..update_written]);
    try testing.expectEqual(@as(?Field, null), try update_iterator.next());
    try testing.expectEqual(@as(u32, 32), decoder.table.capacity);
    try testing.expectEqual(encoder.table.size, decoder.table.size);
    try testing.expectEqual(encoder.table.count, decoder.table.count);
}

test "huffman is used only when it is shorter" {
    var storage: Storage(4096) = .{};
    var encoder = storage.encoder(.static_only);
    var block: [256]u8 = undefined;

    // Lowercase text compresses; a run of high bytes does not.
    const compressible = [_]Field{.{ .name = "x", .value = "aaaaaaaaaaaaaaaa" }};
    _ = encoder.encode(&block, &compressible);
    // Value header is at index 3: 0x00, name length, 'x', then the value.
    try testing.expect(block[3] & 0x80 != 0);

    const incompressible = [_]Field{.{ .name = "x", .value = &@as([16]u8, @splat(0xff)) }};
    _ = encoder.encode(&block, &incompressible);
    try testing.expect(block[3] & 0x80 == 0);
}

test "a full round trip over every Appendix C field list" {
    for (examples.stories) |story| {
        var encoder_storage: Storage(DynamicTable.capacity_max) = .{};
        var encoder = encoder_storage.encoder(.dynamic);
        try encoder.table.setCapacity(story.table_size_max);

        var decoder_storage: DynamicTable.Storage(DynamicTable.capacity_max) = .{};
        const decoder_table = DynamicTable.init(
            decoder_storage.bytes[0..story.table_size_max],
            decoder_storage.entries[0..DynamicTable.entriesRequired(story.table_size_max)],
        );
        var decoder = Decoder.init(decoder_table, 64 * 1024);

        for (story.examples) |example| {
            var block: [4096]u8 = undefined;
            const result = encoder.encode(&block, example.fields);
            try testing.expectEqual(example.fields.len, result.fields);

            var buffer: [4096]u8 = undefined;
            var iterator = decoder.iterate(&buffer, block[0..result.written]);
            for (example.fields) |want| {
                const got = (try iterator.next()).?;
                try testing.expectEqualStrings(want.name, got.name);
                try testing.expectEqualStrings(want.value, got.value);
            }
            try testing.expectEqual(@as(?Field, null), try iterator.next());

            // The two tables agree, which is the invariant that keeps a
            // connection decodable past its first block.
            try testing.expectEqual(encoder.table.size, decoder.table.size);
            try testing.expectEqual(encoder.table.count, decoder.table.count);
        }
    }
}

test "an oversized field clears both tables in step" {
    var encoder_storage: Storage(68) = .{};
    var encoder = encoder_storage.encoder(.dynamic);

    var decoder_storage: DynamicTable.Storage(68) = .{};
    var decoder = Decoder.init(decoder_storage.table(), 64 * 1024);

    const fields = [_]Field{
        .{ .name = "a", .value = "1" },
        .{ .name = "big", .value = "0123456789012345678901234567890123456789" },
    };
    var block: [256]u8 = undefined;
    const result = encoder.encode(&block, &fields);
    try testing.expectEqual(fields.len, result.fields);

    var buffer: [512]u8 = undefined;
    var iterator = decoder.iterate(&buffer, block[0..result.written]);
    while (try iterator.next()) |_| {}

    try testing.expectEqual(@as(u32, 0), encoder.table.count);
    try testing.expectEqual(@as(u32, 0), decoder.table.count);
}

test "the vectorized scan finds the same entry a strided walk would, across the wrap" {
    // The path this test exists for is reached only when at least `scan_lanes`
    // entries are live, and only crosses the ring's wrap when the live span
    // straddles the end of the array. Neither holds for the RFC's examples or
    // the vendored corpus, which keep tables of three or four entries — so
    // before this test, an off-by-one in the trailing run's start passed every
    // gate in the package. Verified by introducing one.
    var storage: Storage(1024) = .{};
    var encoder = storage.encoder(.dynamic);
    var target: [4096]u8 = undefined;

    // Enough distinct fields that `newest` has wrapped past the end of the
    // entry array and come back around.
    var index: u32 = 0;
    while (index < 200) : (index += 1) {
        var name_buffer: [16]u8 = undefined;
        var value_buffer: [24]u8 = undefined;
        const field: Field = .{
            .name = try std.fmt.bufPrint(&name_buffer, "x-probe-{d:0>4}", .{index}),
            .value = try std.fmt.bufPrint(&value_buffer, "value-{d:0>6}-pad", .{index}),
        };
        _ = try encoder.encodeField(&target, field);
    }

    const entries_count: u32 = @intCast(encoder.table.entries.len);
    const count = encoder.table.count;
    // The test is only testing what it claims if both hold.
    try std.testing.expect(count >= scan_lanes);
    try std.testing.expect(encoder.table.newest + count > entries_count);

    // Every live entry must be found at its own position. A run start that is
    // off by one returns a position whose entry is a *different* field, which
    // encodes a reference the peer resolves to the wrong header — a compression
    // bug rather than a crash, and invisible to a round-trip that re-encodes
    // and re-decodes with the same wrong table.
    var position: u32 = 0;
    while (position < count) : (position += 1) {
        const entry = encoder.table.get(position).?;
        // Copied out before `encodeField` sees them. `get` returns slices into
        // the arena, and if the scan regressed, `encodeField` would fall
        // through to a literal and insert them — where the only guard against
        // aliasing is `DynamicTable.insert`'s assertion. Under
        // `-Dassertions=false` that is a `@memcpy` from a region `compact` may
        // just have moved, so this test's failure mode would be undefined
        // behaviour in the one CI leg built to catch it.
        var name_copy: [64]u8 = undefined;
        var value_copy: [64]u8 = undefined;
        @memcpy(name_copy[0..entry.name.len], entry.name);
        @memcpy(value_copy[0..entry.value.len], entry.value);
        const field: Field = .{
            .name = name_copy[0..entry.name.len],
            .value = value_copy[0..entry.value.len],
        };

        const written = try encoder.encodeField(&target, field);
        // A regression would insert rather than index, moving the table under
        // every later iteration. Caught here rather than as a confusing failure
        // three positions later.
        try std.testing.expectEqual(count, encoder.table.count);
        // A full match is one indexed representation and nothing else.
        try std.testing.expect(written >= 1);
        try std.testing.expect(target[0] & 0b1000_0000 != 0);

        const decoded = try integer.decode(target[0..written], prefix_indexed);
        try std.testing.expectEqual(written, decoded.octets);
        try std.testing.expectEqual(encoder.wireIndex(position), decoded.value);

        // And the index really does name this entry, not merely some entry.
        const found = decoded.value - static_table.dynamic_offset;
        const same = encoder.table.get(found).?;
        try std.testing.expectEqualStrings(entry.name, same.name);
        try std.testing.expectEqualStrings(entry.value, same.value);
    }
}

test "the strided and vectorized scans agree on the same table" {
    // The two implementations differ only by a count threshold, so the same
    // table has to give the same answer through either. `scan` picks by
    // `count`; this calls both directly on a table large enough for the vector
    // path, which is the comparison the threshold hides.
    var storage: Storage(1024) = .{};
    var encoder = storage.encoder(.dynamic);
    var target: [4096]u8 = undefined;

    var index: u32 = 0;
    while (index < 200) : (index += 1) {
        var name_buffer: [16]u8 = undefined;
        var value_buffer: [24]u8 = undefined;
        _ = try encoder.encodeField(&target, .{
            .name = try std.fmt.bufPrint(&name_buffer, "x-probe-{d:0>4}", .{index}),
            .value = try std.fmt.bufPrint(&value_buffer, "value-{d:0>6}-pad", .{index}),
        });
    }
    try std.testing.expect(encoder.table.count >= scan_lanes);

    var position: u32 = 0;
    while (position < encoder.table.count) : (position += 1) {
        const entry = encoder.table.get(position).?;
        const field: Field = .{ .name = entry.name, .value = entry.value };
        const wanted = hashField(field.name, field.value);
        const vectorized = encoder.scan(encoder.field_hashes, wanted, field, .name_and_value);
        const strided = encoder.scanStrided(encoder.field_hashes, wanted, field, .name_and_value);
        try std.testing.expectEqual(strided, vectorized);
        try std.testing.expectEqual(position, vectorized.?);
    }

    // And a field in neither, which is the case that walks every live slot.
    const absent: Field = .{ .name = "x-absent", .value = "nothing" };
    const wanted_absent = hashField(absent.name, absent.value);
    try std.testing.expectEqual(
        encoder.scanStrided(encoder.field_hashes, wanted_absent, absent, .name_and_value),
        encoder.scan(encoder.field_hashes, wanted_absent, absent, .name_and_value),
    );
}

test "a name matched by several entries resolves to the newest of them" {
    // `scan` promises "the newest live entry whose hash matches", and for a
    // name that is not a correctness question but a compression one: any entry
    // with the right name encodes correctly, and the newest encodes in the
    // fewest octets. Duplicate *field* hashes cannot arise — a full match is
    // found before an insert — but duplicate *name* hashes arise the moment a
    // header is sent twice with different values, which is `set-cookie` on
    // every response that sets two.
    //
    // The vector path tests eight lanes at once, so this is also what pins lane
    // order: with several matches inside one chunk, reversing the lanes returns
    // an older entry and a larger index. Nothing else in the package notices.
    var storage: Storage(1024) = .{};
    var encoder = storage.encoder(.dynamic);
    var target: [4096]u8 = undefined;

    // Enough distinct fields that the vector path is the one taken.
    var index: u32 = 0;
    while (index < 12) : (index += 1) {
        var name_buffer: [16]u8 = undefined;
        _ = try encoder.encodeField(&target, .{
            .name = try std.fmt.bufPrint(&name_buffer, "x-filler-{d:0>3}", .{index}),
            .value = "filler-value",
        });
    }

    // Then the same name several times over, close enough together to share a
    // chunk with each other.
    var repeat: u32 = 0;
    while (repeat < 4) : (repeat += 1) {
        var value_buffer: [16]u8 = undefined;
        _ = try encoder.encodeField(&target, .{
            .name = "x-repeated",
            .value = try std.fmt.bufPrint(&value_buffer, "value-{d}", .{repeat}),
        });
    }
    try std.testing.expect(encoder.table.count >= scan_lanes);

    // Position zero is the last one inserted, so it is the newest match and the
    // one both scans must name.
    const probe: Field = .{ .name = "x-repeated", .value = "not-in-the-table" };
    const wanted = hashName(probe.name);
    const vectorized = encoder.scan(encoder.name_hashes, wanted, probe, .name_only);
    const strided = encoder.scanStrided(encoder.name_hashes, wanted, probe, .name_only);
    try std.testing.expectEqual(@as(?u32, 0), vectorized);
    try std.testing.expectEqual(strided, vectorized);

    // And there really were several to choose between, or this test proves
    // nothing about ordering.
    var matches: u32 = 0;
    var position: u32 = 0;
    while (position < encoder.table.count) : (position += 1) {
        const entry = encoder.table.get(position).?;
        if (std.mem.eql(u8, entry.name, "x-repeated")) matches += 1;
    }
    try std.testing.expect(matches >= 4);
}
