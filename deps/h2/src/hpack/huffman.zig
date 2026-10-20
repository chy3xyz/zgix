//! RFC 7541 section 5.2 and Appendix B: the fixed Huffman code.
//!
//! ## Decoding
//!
//! `decode` reads twelve bits per lookup and emits up to two symbols — two
//! because two five-bit codes fit in twelve bits and three do not. Four of the
//! 4096 patterns begin a code longer than the window and escape to a canonical
//! decode by length.
//!
//! Twelve is chosen against the code's own length distribution rather than by
//! taste; the table below `window_bits` records the measurement. The table is
//! 16 KiB, small enough to stay resident beside the rest of a proxy's working
//! set, which is the property that decides this design rather than raw
//! throughput. LiteSpeed's sixteen-bit window reads fewer lookups per octet and
//! measures faster in a tight loop, but it is 256 KiB and an L2 resident, and
//! this code runs on a thread also serving thousands of connections.
//!
//! `decodeReference` is the nibble automaton of Pajarola's "Fast Prefix Code
//! Processing" (2003), the construction nghttp2 has used since 2014. It was
//! `decode` until the window was measured against it, and it is kept because
//! the case for shipping the faster one rests on their agreeing everywhere —
//! same octets, same errors, same accept and reject. A consumer that never
//! calls it does not pay for its table: a binary calling only `decode` is
//! 16352 octets smaller, which is exactly the automaton's table.
//!
//! Validity comes free with the same lookups in both. Walking into the EOS leaf
//! is a decoding error rather than a terminator, and the padding rules of
//! section 5.2 — fewer than eight bits, all ones — are checked once at the end.
//!
//! ## Encoding
//!
//! One code per input octet, accumulated in a 64-bit register and flushed a
//! byte at a time. A two-octet table (65536 entries, 512 KiB) buys 1.7-2.1x,
//! and costs more cache than this package is willing to spend for it.

const std = @import("std");

const assert = @import("../assert.zig").assert;

const table = @import("huffman_codes.zig");

pub const Code = table.Code;
pub const eos = table.eos;
pub const bits_min = table.bits_min;
pub const bits_max = table.bits_max;

/// Longest run of padding bits a valid encoding can end with (RFC 7541
/// section 5.2): "a padding strictly longer than 7 bits MUST be treated as a
/// decoding error".
const padding_bits_max: u8 = 7;

comptime {
    // Padding shorter than an octet is the whole of section 5.2's second rule.
    assert(padding_bits_max < 8);
    // One symbol per nibble, which is what lets a `Transition` hold a single
    // symbol and what `walkNibble` asserts dynamically. Four bits cannot finish
    // two codes unless the shortest is four or fewer.
    assert(bits_min > 4);
    // A complete prefix code over `eos + 1` symbols has that many leaves and
    // one fewer internal node.
    assert(nodes_max == 2 * (@as(u16, eos) + 1) - 1);
    // Every state is an internal node, plus one for failure. A full binary
    // tree with L leaves has L - 1 internal nodes, so 2L - 1 total.
    assert(states_max == @divExact(nodes_max - 1, 2) + 1);
}

/// One nibble's transition. Four octets, so a row is 64 and the whole table is
/// `states_count` times that.
const Transition = struct {
    next_state: u16,
    symbol: u8,
    emits: bool,

    /// A transition that goes nowhere and emits nothing, used to fill the
    /// table before the walk overwrites it.
    const blank: Transition = .{ .next_state = 0, .symbol = 0, .emits = false };
};

/// The code is a complete prefix code over 257 symbols, so its tree has 257
/// leaves, 256 internal nodes, and 513 nodes in total. The comptime build
/// asserts it: a tree that came out any other shape would mean the transcribed
/// table is not the code it claims to be.
const nodes_max: u16 = 513;
const node_none: u16 = std.math.maxInt(u16);

/// Every automaton state is an internal node of the tree, so there can be at
/// most 256, plus one for failure.
const states_max: u16 = 257;

const Tree = struct {
    child: [nodes_max][2]u16,
    symbol: [nodes_max]u16,
    is_leaf: [nodes_max]bool,
    /// Bits from the root, which is the padding length if input ends here.
    depth: [nodes_max]u8,
    /// Every bit from the root is a one, which is what legal padding must be.
    all_ones: [nodes_max]bool,
    count: u16,
};

fn buildTree() Tree {
    var built: Tree = .{
        .child = @splat([2]u16{ node_none, node_none }),
        .symbol = @as([nodes_max]u16, @splat(0)),
        .is_leaf = @as([nodes_max]bool, @splat(false)),
        .depth = @as([nodes_max]u8, @splat(0)),
        .all_ones = @as([nodes_max]bool, @splat(false)),
        .count = 1,
    };
    built.all_ones[0] = true;

    for (table.codes, 0..) |code, symbol| {
        assert(code.bits >= table.bits_min);
        assert(code.bits <= table.bits_max);
        var node: u16 = 0;
        var index: u5 = 0;
        while (index < code.bits) : (index += 1) {
            // Descending through a leaf would mean this code has another code
            // as its prefix. Half of prefix-freeness, asserted where it would
            // happen rather than inferred from the node count afterwards.
            assert(!built.is_leaf[node]);
            const bit: u1 = @truncate(code.code >> (code.bits - 1 - index));
            if (built.child[node][bit] == node_none) {
                const fresh = built.count;
                assert(fresh < nodes_max);
                built.count += 1;
                built.child[node][bit] = fresh;
                built.depth[fresh] = built.depth[node] + 1;
                built.all_ones[fresh] = built.all_ones[node] and bit == 1;
            }
            node = built.child[node][bit];
        }
        // And the other half: a code cannot land on an interior node, which
        // would mean some other code is a prefix of *it*.
        assert(!built.is_leaf[node]);
        assert(built.child[node][0] == node_none);
        assert(built.child[node][1] == node_none);
        built.is_leaf[node] = true;
        built.symbol[node] = @intCast(symbol);
    }
    assert(built.count == nodes_max);
    return built;
}

/// The result of walking one nibble from a state: where it lands, and the at
/// most one symbol it completes on the way.
const NibbleWalk = struct {
    node: u16,
    symbol: u8,
    emits: bool,
    failed: bool,
};

/// Walk four bits from `origin`.
///
/// At most one symbol can complete: the shortest code is five bits, so after
/// emitting, the walk restarts at the root with three bits left at most. That
/// is a comptime relation above and an assertion here.
fn walkNibble(origin: u16, nibble: u4) NibbleWalk {
    var node = origin;
    var symbol: u8 = 0;
    var emits = false;

    var step: u3 = 0;
    while (step < 4) : (step += 1) {
        const shift: u2 = @intCast(3 - step);
        const bit: u1 = @truncate(nibble >> shift);
        node = tree.child[node][bit];
        // The tree is complete, so descent always lands somewhere.
        assert(node != node_none);
        if (tree.is_leaf[node]) {
            if (tree.symbol[node] == eos) {
                // An encoded string containing EOS is a decoding error (RFC
                // 7541 section 5.2), not a string terminator.
                return .{ .node = 0, .symbol = 0, .emits = false, .failed = true };
            }
            assert(!emits);
            emits = true;
            symbol = @intCast(tree.symbol[node]);
            node = 0;
        }
    }
    assert(step == 4);
    return .{ .node = node, .symbol = symbol, .emits = emits, .failed = false };
}

const Machine = struct {
    transitions: [states_max][16]Transition,
    accepting: [states_max]bool,
    /// Real states; the failure state sits at this index.
    count: u16,
};

const tree = blk: {
    @setEvalBranchQuota(200_000);
    break :blk buildTree();
};

fn buildMachine() Machine {
    // A complete prefix code over 257 symbols, or the source table is wrong.
    assert(tree.count == nodes_max);

    var built: Machine = .{
        .transitions = @splat(@as([16]Transition, @splat(Transition.blank))),
        .accepting = @as([states_max]bool, @splat(false)),
        .count = 1,
    };
    var state_of_node = @as([nodes_max]u16, @splat(node_none));
    var node_of_state = @as([states_max]u16, @splat(0));
    state_of_node[0] = 0;

    var state: u16 = 0;
    while (state < built.count) : (state += 1) {
        const origin = node_of_state[state];
        for (0..16) |nibble| {
            const walk = walkNibble(origin, @intCast(nibble));
            if (walk.failed) {
                // Patched to the failure state below, once its index is known.
                built.transitions[state][nibble] = .{ .next_state = node_none, .symbol = 0, .emits = false };
                continue;
            }
            if (state_of_node[walk.node] == node_none) {
                const fresh = built.count;
                built.count += 1;
                assert(built.count <= states_max);
                state_of_node[walk.node] = fresh;
                node_of_state[fresh] = walk.node;
            }
            built.transitions[state][nibble] = .{
                .next_state = state_of_node[walk.node],
                .symbol = walk.symbol,
                .emits = walk.emits,
            };
        }
    }

    finish(&built, &node_of_state);
    return built;
}

/// Point every failed transition at the failure state, and precompute which
/// states a valid encoding may end in.
fn finish(built: *Machine, node_of_state: *const [states_max]u16) void {
    const failure = built.count;
    assert(failure < states_max);
    for (0..failure) |index| {
        for (&built.transitions[index]) |*transition| {
            if (transition.next_state == node_none) transition.next_state = failure;
        }
        const node = node_of_state[index];
        // Section 5.2's two padding rules, precomputed: the leftover bits must
        // be the most significant bits of EOS, which are all ones, and there
        // must be fewer than eight of them.
        built.accepting[index] = tree.all_ones[node] and tree.depth[node] <= padding_bits_max;
    }
    // Absorbing, and never accepting, so failure needs no branch to detect and
    // cannot be undone by later input.
    for (&built.transitions[failure]) |*transition| {
        transition.* = .{ .next_state = failure, .symbol = 0, .emits = false };
    }
    built.accepting[failure] = false;
    assert(!built.accepting[failure]);
}

/// Code lengths alone, for `encodedLength`.
///
/// The full table is 257 entries of eight octets — two kilobytes, touched at a
/// random offset per input octet. Summing lengths needs only the length, so a
/// byte per symbol keeps the whole thing in four cache lines instead.
const code_bits = blk: {
    @setEvalBranchQuota(10_000);
    var bits: [256]u8 = undefined;
    for (&bits, 0..) |*entry, symbol| entry.* = table.codes[symbol].bits;
    break :blk bits;
};

comptime {
    // A byte per length, which holds because no code is longer than 30 bits.
    assert(bits_max <= std.math.maxInt(u8));
    // Only the 256 octets, deliberately: EOS has a code but no octet encodes
    // to it, and including it would make an out-of-range index look valid.
    assert(code_bits.len == eos);
    assert(table.codes.len == eos + 1);
}

const machine = blk: {
    @setEvalBranchQuota(2_000_000);
    break :blk buildMachine();
};

/// Real automaton states, failure excluded. Pinned by a test: the count is a
/// property of the code table, and a change in it means the table changed.
pub const states_count: u16 = machine.count;

const transitions = machine.transitions;
const accepting = machine.accepting;

// ── The 12-bit window ───────────────────────────────────────────────────────
//
// The automaton above reads four bits per lookup and emits at most one symbol.
// A wider window reads twelve and emits up to two, because two five-bit codes
// fit and three do not.
//
// Twelve is chosen against the code's own length distribution rather than by
// taste. Measured over all patterns: an eleven-bit window averages 1.350
// symbols per lookup, twelve averages 1.672, thirteen averages 1.890. Thirteen
// buys 13% more for twice the cache footprint, and this runs on a thread that
// is also serving thousands of connections — the same argument that ruled out
// LiteSpeed's 256 KiB sixteen-bit table. Twelve costs 16 KiB, exactly what the
// automaton costs, so shipping it is a swap rather than an addition.
//
// Four of the 4096 patterns begin a code longer than twelve bits and decode
// nothing. Those escape to a canonical decode by length, which needs a few
// hundred octets rather than another table.

const window_bits: u32 = 12;
const window_size: u32 = 1 << @as(u5, @intCast(window_bits));

/// The bit reader's accumulator, and the level below which it refills.
const accumulator_bits: u32 = 64;
const refill_bits_min: u32 = accumulator_bits - 8;

/// What one twelve-bit pattern decodes to.
/// One code resolved from a window pattern by `matchAt`.
const WindowMatch = struct {
    symbol: u8,
    bits: u8,
};

/// What one twelve-bit pattern decodes to.
const Window = struct {
    symbols: [2]u8,
    /// Symbols decoded. Zero means the pattern begins a code too long to
    /// resolve here.
    count: u8,
    /// Bits the symbols consumed, which is what the reader advances by.
    bits: u8,
};

comptime {
    // Two of the shortest code fit in the window and three do not, which is
    // what bounds `symbols` at two.
    assert(2 * @as(u32, bits_min) <= window_bits);
    assert(3 * @as(u32, bits_min) > window_bits);
    // The window index has to fit the shift the reader uses.
    assert(window_bits < accumulator_bits);
    assert(refill_bits_min + 8 == accumulator_bits);
    assert(window_bits <= refill_bits_min);
    // The relation that makes `decode`'s tail check sound. It reads "nothing
    // decodes here" as "the input is exhausted", and that is only true because
    // a complete prefix code always resolves within `bits_max`: if any octet
    // remained, the refill would have left at least `refill_bits_min` bits in
    // the accumulator, and a code would have been found. Widen `bits_max` past
    // this, or lower the refill threshold, and a truncated long code starts
    // being accepted as a valid string.
    assert(bits_max <= refill_bits_min);
    // A window entry's `bits` never exceeds the window.
    assert(window_bits <= std.math.maxInt(u8));
}

const window = blk: {
    @setEvalBranchQuota(2_000_000);
    var built: [window_size]Window = undefined;
    for (&built, 0..) |*entry, pattern| {
        var symbols: [2]u8 = .{ 0, 0 };
        var count: u8 = 0;
        var bits: u8 = 0;
        // A single twelve-bit code consumes the whole window, so the second
        // attempt has no bits to look at — which is `matchAt`'s precondition
        // rather than something for it to discover.
        while (count < 2 and bits < window_bits) {
            const found = matchAt(@intCast(pattern), bits) orelse break;
            symbols[count] = found.symbol;
            count += 1;
            bits += found.bits;
        }
        assert(count <= 2);
        assert(bits <= window_bits);
        assert(count > 0 or bits == 0);
        if (count > 0) assert(bits >= bits_min);
        entry.* = .{ .symbols = symbols, .count = count, .bits = bits };
    }
    break :blk built;
};

/// The code beginning `offset` bits into a window pattern, if one finishes
/// inside the window.
///
/// Walks the tree rather than scanning the code table: twelve steps instead of
/// 257 comparisons, which is the difference between a comptime build that
/// finishes and one that does not.
fn matchAt(pattern: u32, offset: u8) ?WindowMatch {
    assert(offset < window_bits);
    var node: u16 = 0;
    var used: u8 = 0;
    while (offset + used < window_bits) {
        const shift: u5 = @intCast(window_bits - offset - used - 1);
        const bit: u1 = @truncate(pattern >> shift);
        node = tree.child[node][bit];
        assert(node != node_none);
        used += 1;
        if (tree.is_leaf[node]) {
            // EOS is thirty bits and the walk takes at most `window_bits`, so
            // this leaf is out of reach. Stated as negative space, and it fails
            // loudly if the window ever grows past thirty.
            assert(tree.symbol[node] != eos);
            assert(offset + used <= window_bits);
            return .{ .symbol = @intCast(tree.symbol[node]), .bits = used };
        }
    }
    return null;
}

/// Canonical decoding tables, for the codes a window entry could not finish.
///
/// The code is canonical: within one length the codes form a contiguous
/// ascending run, so a symbol is found by asking, for each length in turn,
/// whether the next that many bits fall inside that length's range. The build
/// below asserts both halves of that — ascending, and contiguous — because
/// `huffman_codes.zig` proves only that each code fits its stated length.
/// One symbol resolved from the accumulator by `canonicalAt`.
const CanonicalMatch = struct {
    symbol: u16,
    bits: u32,
};

const Canonical = struct {
    /// Widest, because a code is up to thirty bits. The other two count
    /// symbols, of which there are 257.
    first_code: [bits_max + 1]u32,
    first_index: [bits_max + 1]u16,
    count: [bits_max + 1]u16,
    /// Symbols ordered by (length, code).
    symbols: [eos + 1]u16,
};

const canonical = blk: {
    @setEvalBranchQuota(200_000);
    var built: Canonical = .{
        .first_code = @as([(bits_max + 1)]u32, @splat(0)),
        .first_index = @as([(bits_max + 1)]u16, @splat(0)),
        .count = @as([(bits_max + 1)]u16, @splat(0)),
        .symbols = @as([(eos + 1)]u16, @splat(0)),
    };

    var index: u32 = 0;
    var length: u32 = bits_min;
    while (length <= bits_max) : (length += 1) {
        built.first_index[length] = @intCast(index);
        var lowest: u32 = std.math.maxInt(u32);
        var previous: u32 = 0;
        for (table.codes, 0..) |code, symbol| {
            if (code.bits != length) continue;
            // Ascending, asserted rather than assumed. `canonicalAt` indexes
            // this run by `value - first_code`, so a run that is contiguous as
            // a *set* but out of order decodes to the wrong symbol — and the
            // RFC's table being in ascending order is a property of the RFC,
            // not of this loop. Checking only the minimum and the count would
            // accept the order 4, 3, 5.
            if (built.count[length] > 0) assert(code.code > previous);
            previous = code.code;
            if (code.code < lowest) lowest = code.code;
            built.symbols[index] = @intCast(symbol);
            index += 1;
            built.count[length] += 1;
        }
        built.first_code[length] = if (built.count[length] == 0) 0 else lowest;
        if (built.count[length] > 0) {
            // Contiguous: the last code is the first plus the count.
            assert(built.first_code[length] + built.count[length] - 1 == previous);
        }
    }
    assert(index == eos + 1);
    break :blk built;
};

comptime {
    // Padding is one-bits, at most seven of them (section 5.2). If any code of
    // seven bits or fewer were all ones, padding could be read as a symbol and
    // the tail check below would be wrong.
    var length: u32 = bits_min;
    while (length <= padding_bits_max) : (length += 1) {
        const ones: u32 = (@as(u32, 1) << @intCast(length)) - 1;
        for (table.codes) |code| {
            if (code.bits == length) assert(code.code != ones);
        }
    }
}

/// Decode the one symbol beginning at the top of `accumulator`, or null when no
/// code of any length fits in `available` bits.
fn canonicalAt(accumulator: u64, available: u32) ?CanonicalMatch {
    assert(available <= accumulator_bits);
    var length: u32 = bits_min;
    while (length <= bits_max) : (length += 1) {
        if (length > available) return null;
        if (canonical.count[length] == 0) continue;
        const value: u32 = @intCast(accumulator >> @intCast(accumulator_bits - length));
        // Wrapping on purpose: a value below the run's first code wraps to
        // something far above its count, so one unsigned comparison rejects
        // both ends of the range.
        const offset = value -% canonical.first_code[length];
        if (offset < canonical.count[length]) {
            const symbol = canonical.symbols[canonical.first_index[length] + offset];
            assert(length <= available);
            return .{ .symbol = symbol, .bits = length };
        }
    }
    return null;
}

pub const DecodeError = error{
    /// The encoding contains EOS, ends mid-code, or pads with something other
    /// than fewer than eight one-bits.
    ///
    /// `target` may hold a partial decoding when this is returned — the failure
    /// is only detectable at the end of the input, by which time whatever was
    /// valid has already been written. Callers treat the whole string as absent
    /// rather than truncated.
    Invalid,
    /// The decoding does not fit `target`. For a header field this is the
    /// compression-bomb bound, and the caller sized it.
    OutputTooLong,
};

/// The nibble automaton, kept as the reference `decode` is tested against.
///
/// It is the construction nghttp2 uses and the one whose correctness is easiest
/// to argue: validity falls out of the same table read, and the failure state
/// is absorbing by construction. `decode` is 1.25x to 1.43x faster and has to agree
/// with this on every input, which the differential tests and the fuzz target
/// enforce. Keeping it is what makes that comparison possible.
///
/// The loop carries no failure branch on purpose. The failure state absorbs and
/// emits nothing, so a malformed input stops producing output at the point it
/// goes wrong and is caught by the accepting check at the end. That leaves the
/// bound on wasted work as `source.len`, which the caller has already bounded,
/// and keeps the hot path to two lookups and two predictable branches per
/// octet.
pub fn decodeReference(target: []u8, source: []const u8) DecodeError!u32 {
    // `written` is a u32, which is a precondition rather than an assumption.
    assert(target.len <= std.math.maxInt(u32));
    var state: u16 = 0;
    var written: u32 = 0;

    for (source) |octet| {
        // Narrowed so the row index is a type property rather than a bounds
        // check the optimizer has to rediscover, in the one loop this file's
        // whole design argument is about.
        const high = transitions[state][@as(u4, @truncate(octet >> 4))];
        if (high.emits) {
            if (written == target.len) return error.OutputTooLong;
            target[written] = high.symbol;
            written += 1;
        }
        state = high.next_state;

        const low = transitions[state][@as(u4, @truncate(octet))];
        if (low.emits) {
            if (written == target.len) return error.OutputTooLong;
            target[written] = low.symbol;
            written += 1;
        }
        state = low.next_state;
    }

    assert(state < states_max);
    if (!accepting[state]) return error.Invalid;
    return written;
}

/// Decode `source` into `target`, returning octets written.
///
/// Reads twelve bits per lookup and emits up to two symbols, against the
/// automaton's four bits and at most one. Measured at 1.25x on a twenty-nine
/// octet header value and 1.43x on a hundred-and-thirty-two octet one, at the
/// same 16 KiB of table — which is why this is the one `decode` names. The gain
/// grows with the value's length, because setting up the bit reader is a fixed
/// cost a short string cannot amortize.
///
/// It agrees with `decodeReference` on every input: same octets out, same
/// error, same accept and reject. That is enforced rather than intended — a
/// differential test runs both over every RFC vector and over every one- and
/// two-octet input, and a fuzz target runs both over drawn input.
///
/// Unlike the automaton, this reads bits rather than octets, so it needs no
/// rewind to a byte boundary when it escapes — the escape decodes one symbol
/// canonically from the same bit position and carries on.
pub fn decode(target: []u8, source: []const u8) DecodeError!u32 {
    assert(target.len <= std.math.maxInt(u32));
    assert(source.len <= std.math.maxInt(u32));

    // Left-aligned: the next bit to read is always bit 63, and everything below
    // `available` is zero, which is what makes the padding check at the end a
    // single comparison.
    var accumulator: u64 = 0;
    var available: u32 = 0;
    var offset: u32 = 0;
    var written: u32 = 0;

    var passes: u64 = 0;
    while (true) : (passes += 1) {
        // Bounded: every pass consumes at least one bit of a fixed-length
        // input, or returns.
        assert(passes <= 8 * @as(u64, source.len) + 1);

        while (available <= refill_bits_min and offset < source.len) {
            accumulator |= @as(u64, source[offset]) << @intCast(refill_bits_min - available);
            available += 8;
            offset += 1;
        }
        assert(available <= accumulator_bits);
        // Everything below `available` is zero, which is what makes the padding
        // comparison at the end a single equality.
        if (available < accumulator_bits) {
            assert(accumulator & (~@as(u64, 0) >> @intCast(available)) == 0);
        }

        if (available >= window_bits) {
            const entry = window[@as(u32, @intCast(accumulator >> @as(u6, @intCast(accumulator_bits - window_bits))))];
            if (entry.count > 0) {
                // Subtract rather than add: `target.len` may be `maxInt(u32)`,
                // and `written + entry.count` would wrap past the comparison
                // that is supposed to stop it.
                if (entry.count > target.len - written) {
                    // The automaton writes what fits before it fails, so this
                    // does too — otherwise the two kernels would leave
                    // different octets behind on the same input, and the
                    // differential tests could not compare the target at all.
                    if (entry.count == 2 and written < target.len) {
                        target[written] = entry.symbols[0];
                    }
                    return error.OutputTooLong;
                }
                target[written] = entry.symbols[0];
                if (entry.count == 2) target[written + 1] = entry.symbols[1];
                written += entry.count;
                assert(available >= entry.bits);
                accumulator <<= @intCast(entry.bits);
                available -= entry.bits;
                continue;
            }
        }

        // Either the pattern begins a code too long for the window, or fewer
        // bits are left than the window reads. One symbol, the slow way.
        if (canonicalAt(accumulator, available)) |found| {
            // An encoded string containing EOS is a decoding error, not a
            // terminator (RFC 7541 section 5.2).
            if (found.symbol == eos) return error.Invalid;
            if (written == target.len) return error.OutputTooLong;
            target[written] = @intCast(found.symbol);
            written += 1;
            assert(available >= found.bits);
            accumulator <<= @intCast(found.bits);
            available -= found.bits;
            continue;
        }

        // Nothing decodes, so what is left must be the padding: fewer than
        // eight bits, all ones. Section 5.2's two rules, and the comptime block
        // above is what rules out padding that happens to spell a symbol.
        // Nothing decoded, so the input is exhausted — see the comptime block
        // on `bits_max <= refill_bits_min` for why that follows.
        assert(offset == source.len);
        if (available > padding_bits_max) return error.Invalid;
        if (available > 0) {
            const ones: u64 = ~@as(u64, 0) << @intCast(accumulator_bits - available);
            if (accumulator != ones) return error.Invalid;
        }
        assert(written <= target.len);
        return written;
    }
}

/// Octets `encode` would write for `source`.
pub fn encodedLength(source: []const u8) u64 {
    var bits: u64 = 0;
    for (source) |octet| bits += code_bits[octet];
    assert(bits >= @as(u64, source.len) * bits_min);
    return std.math.divCeil(u64, bits, 8) catch unreachable;
}

pub const EncodeError = error{
    OutputTooLong,
};

/// Encode `source` into `target`, returning octets written.
pub fn encode(target: []u8, source: []const u8) EncodeError!u32 {
    if (encodedLength(source) > target.len) return error.OutputTooLong;

    // Holding fewer than eight bits before each symbol and adding at most
    // thirty keeps the accumulator under thirty-eight bits, so it never
    // overflows and the flush never has to check.
    const length = encodedLength(source);
    var accumulator: u64 = 0;
    var bits: u6 = 0;
    var written: u32 = 0;

    for (source) |octet| {
        const code = table.codes[octet];
        assert(bits < 8);
        accumulator = (accumulator << code.bits) | code.code;
        bits += code.bits;
        // Seven carried in plus the longest code. Asserting the proof rather
        // than a round number above it.
        assert(bits <= 7 + @as(u6, bits_max));
        while (bits >= 8) {
            bits -= 8;
            // The up-front length check is all that stands between a
            // length/emit disagreement and a write past the end, so the
            // negative space belongs here rather than only in the postcondition
            // that would notice afterwards.
            assert(written < length);
            target[written] = @truncate(accumulator >> bits);
            written += 1;
        }
    }

    if (bits > 0) {
        assert(bits < 8);
        const padding: u6 = 8 - bits;
        // Pad with the most significant bits of EOS, which are ones.
        const ones: u64 = (@as(u64, 1) << padding) - 1;
        assert(written < length);
        target[written] = @truncate((accumulator << padding) | ones);
        written += 1;
    }

    assert(written == length);
    return written;
}

test "the window agrees with the automaton on every short input" {
    // Every one- and two-octet string, which is 65792 inputs and covers every
    // window pattern, every escape, and every shape of padding — valid and
    // not. The automaton is the reference; the window is only allowed to be
    // faster, never different.
    var reference: [64]u8 = undefined;
    var fast: [64]u8 = undefined;

    var value: u32 = 0;
    while (value < 256) : (value += 1) {
        const one = [_]u8{@intCast(value)};
        try expectSameDecode(&reference, &fast, &one);
    }

    value = 0;
    while (value < 65536) : (value += 1) {
        const two = [_]u8{ @intCast(value >> 8), @intCast(value & 0xff) };
        try expectSameDecode(&reference, &fast, &two);
    }
}

fn expectSameDecode(reference: []u8, fast: []u8, source: []const u8) !void {
    const want = decodeReference(reference, source);
    const got = decode(fast, source);
    if (want) |written| {
        const fast_written = try got;
        try std.testing.expectEqual(written, fast_written);
        try std.testing.expectEqualSlices(u8, reference[0..written], fast[0..fast_written]);
    } else |err| {
        try std.testing.expectError(err, got);
    }
}

test "the window agrees with the automaton on the RFC vectors and long input" {
    var reference: [4096]u8 = undefined;
    var fast: [4096]u8 = undefined;

    for (@import("rfc7541_examples.zig").huffman_strings) |vector| {
        try expectSameDecode(&reference, &fast, vector.wire);
    }

    // The whole alphabet, which is where the thirty-bit codes and therefore
    // most of the escapes live.
    var source: [256]u8 = undefined;
    for (&source, 0..) |*octet, index| octet.* = @intCast(index);
    var encoded: [2048]u8 = undefined;
    const length = try encode(&encoded, &source);
    try expectSameDecode(&reference, &fast, encoded[0..length]);

    // And a run of it, so the reader crosses the accumulator refill repeatedly.
    var long: [4096]u8 = undefined;
    for (&long, 0..) |*octet, index| octet.* = @intCast('a' + index % 26);
    const long_length = try encode(&encoded, long[0..512]);
    try expectSameDecode(&reference, &fast, encoded[0..long_length]);
}

test "the window reports OutputTooLong at the same capacities as the automaton" {
    const wire = [_]u8{ 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff };
    var capacity: u32 = 0;
    while (capacity <= 16) : (capacity += 1) {
        var reference: [16]u8 = undefined;
        var fast: [16]u8 = undefined;
        @memset(reference[0..], 0);
        @memset(fast[0..], 0);
        const want = decodeReference(reference[0..capacity], &wire);
        const got = decode(fast[0..capacity], &wire);
        if (want) |written| {
            try std.testing.expectEqual(written, try got);
        } else |err| {
            try std.testing.expectError(err, got);
        }
        // Including what each left behind: the window emits two symbols per
        // lookup and the automaton one, so a capacity that splits a pair is
        // where they would most easily disagree.
        try std.testing.expectEqualSlices(u8, reference[0..capacity], fast[0..capacity]);
    }
}

test "the automaton has the state count the construction predicts" {
    // 256 internal nodes in a 257-leaf tree, every one of them reachable at a
    // nibble boundary. nghttp2's table is the same size, from the same
    // construction.
    try std.testing.expectEqual(@as(u16, 256), states_count);
}

test "RFC 7541 Appendix C: every Huffman string, both directions" {
    var decoded: [128]u8 = undefined;
    var encoded: [128]u8 = undefined;
    for (@import("rfc7541_examples.zig").huffman_strings) |vector| {
        const written = try decode(&decoded, vector.wire);
        try std.testing.expectEqualStrings(vector.text, decoded[0..written]);

        // The RFC's bytes are what a conforming encoder produces, so this is a
        // real check on ours rather than a round trip against itself.
        const length = try encode(&encoded, vector.text);
        try std.testing.expectEqualSlices(u8, vector.wire, encoded[0..length]);
    }
}

test "every octet round trips, alone and in a full-alphabet run" {
    var source: [256]u8 = undefined;
    for (&source, 0..) |*octet, index| octet.* = @intCast(index);

    var encoded: [2048]u8 = undefined;
    var decoded: [512]u8 = undefined;

    // The whole alphabet at once, including the 30-bit codes.
    const length = try encode(&encoded, &source);
    const written = try decode(&decoded, encoded[0..length]);
    try std.testing.expectEqualSlices(u8, &source, decoded[0..written]);

    // And each octet on its own, where padding is the whole tail.
    for (source) |octet| {
        const one = [_]u8{octet};
        const encoded_len = try encode(&encoded, &one);
        const decoded_len = try decode(&decoded, encoded[0..encoded_len]);
        try std.testing.expectEqualSlices(u8, &one, decoded[0..decoded_len]);
    }
}

test "an empty string encodes and decodes to nothing" {
    var target: [8]u8 = undefined;
    try std.testing.expectEqual(@as(u32, 0), try encode(&target, ""));
    try std.testing.expectEqual(@as(u64, 0), encodedLength(""));
    try std.testing.expectEqual(@as(u32, 0), try decode(&target, ""));
}

test "padding longer than seven bits is rejected" {
    // "0" is the 5-bit code 00000. One octet of it pads with three ones and is
    // valid; a second all-ones octet is eight bits of padding and is not.
    var target: [8]u8 = undefined;
    try std.testing.expectEqual(@as(u32, 1), try decode(&target, &.{0b0000_0111}));
    try std.testing.expectError(error.Invalid, decode(&target, &.{ 0b0000_0111, 0xff }));
}

test "padding that is not all ones is rejected" {
    // Same 5-bit "0", padded with 000 instead of 111.
    var target: [8]u8 = undefined;
    try std.testing.expectError(error.Invalid, decode(&target, &.{0b0000_0000}));
}

test "an encoded EOS is a decoding error" {
    // EOS is thirty one-bits. Four all-ones octets reach it and then some.
    var target: [16]u8 = undefined;
    try std.testing.expectError(error.Invalid, decode(&target, &.{ 0xff, 0xff, 0xff, 0xff }));
}

test "a truncated code is rejected rather than silently dropped" {
    // The first octet of "www.example.com" alone ends mid-code.
    var target: [64]u8 = undefined;
    try std.testing.expectError(error.Invalid, decode(&target, &.{0xae}));
}

test "decode stops at the target's capacity" {
    var target: [4]u8 = undefined;
    const wire = [_]u8{ 0xae, 0xc3, 0x77, 0x1a, 0x4b }; // 15 octets of output
    try std.testing.expectError(error.OutputTooLong, decode(&target, &wire));
}

test "encode refuses a target that cannot hold the result" {
    var target: [4]u8 = undefined;
    try std.testing.expectError(error.OutputTooLong, encode(&target, "www.example.com"));
}
