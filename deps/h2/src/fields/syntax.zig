//! RFC 9113 section 8.2.1: which octets may appear in a field name and value.
//!
//! This is the h2-to-h1 downgrade guard. A value carrying CR or LF that reaches
//! an HTTP/1.1 upstream is a request-splitting primitive, and section 8.2.1 is
//! written the way it is because of it. The rules are short enough to read in
//! full:
//!
//! * a field name MUST NOT contain 0x00-0x20, 0x41-0x5a, or 0x7f-0xff;
//! * a field name MUST NOT contain a colon, except as the single leading octet
//!   of a pseudo-header field;
//! * a field value MUST NOT contain NUL, LF or CR at any position;
//! * a field value MUST NOT start or end with SP or HTAB.
//!
//! ## Two readings, and why both ship
//!
//! Section 8.2.1 states two levels and means both. It *recommends* validating
//! against RFC 9110 sections 5.1 and 5.5 — `field-name = token`, and a field
//! value of visible characters with interior whitespace — and then *requires*
//! the four bullets above as a floor. The recommended reading rejects sixteen
//! octets the floor admits:
//!
//!     " ( ) , / ; < = > ? @ [ \ ] { }
//!
//! That is RFC 9110 section 5.6.2's delimiter set with the colon removed. The
//! colon is its seventeenth member, and it is not in this list because the
//! floor already refuses it everywhere except a pseudo-header's first octet —
//! so it is not a place the two readings differ.
//!
//! `Rules.strict` is the recommendation and `Rules.minimal` is the floor.
//! Neither is this package's decision to make: a proxy hardening a downgrade
//! wants `strict`, and a load generator replaying a capture wants to know
//! whether a peer would call the capture malformed at all. What this package
//! owns is that the two readings are stated once, from the RFC text, rather
//! than transcribed into each consumer with a different set of typos.
//!
//! `strict` rejects a superset of what `minimal` rejects — asserted at compile
//! time below, over all 256 octets, because a "stricter" mode that accepts
//! something the looser one refuses would be a silent hole rather than a
//! stricter mode.
//!
//! ## One deviation, stated where it happens
//!
//! An empty name is rejected under both. The four bullets are character rules
//! and say nothing about length, so the floor as literally written admits it;
//! but the definition section 8.2.1 points at is `field-name = token = 1*tchar`,
//! which does not, and a nameless field rendered into HTTP/1.1 is a bare
//! `: value` line. It is refused here rather than left to a consumer that would
//! have to remember.
//!
//! ## Why this is where the vectors are
//!
//! Byte classification over a contiguous run is the one shape in this package
//! that vectorizes. Huffman decoding is a bit-serial chain of dependent loads
//! and does not, which is why #1's design comment calls "vectorized HPACK" a
//! category error. Here every octet is independent of every other, so the
//! kernel is a handful of range compares per 16 or 32 octets, and the names
//! and values the decoder hands over are already in cache.

const std = @import("std");

const assert = @import("../assert.zig").assert;

/// How to read section 8.2.1. See the two-readings note above; the choice is
/// the consumer's, so there is no default.
pub const Rules = enum {
    /// Section 8.2.1's four bullets and nothing further: the octets whose
    /// presence RFC 9113 makes a message malformed outright.
    minimal,
    /// RFC 9110 sections 5.1 and 5.5 in full — `field-name = token`, and a
    /// field value of visible octets with interior whitespace only — together
    /// with section 8.2.1's uppercase exclusion. This is what section 8.2.1
    /// recommends, and it is what an intermediary forwarding into HTTP/1.1
    /// should want.
    strict,
};

pub const NameError = error{
    /// No octets, or a pseudo-header whose name is a bare colon. RFC 9110
    /// section 5.1: `field-name = token = 1*tchar`.
    Empty,
    /// An octet the rules forbid. Under either reading this includes every
    /// uppercase letter, every octet at or below SP, and every octet from DEL
    /// up; under `.strict` it also includes RFC 9110's delimiters.
    Character,
    /// A colon somewhere other than as the single leading octet of a
    /// pseudo-header name. Separate from `Character` because it is the one
    /// name octet whose position, not its identity, decides the answer.
    Colon,
};

pub const ValueError = error{
    /// NUL, CR or LF, at any position. Named apart from `Character` because
    /// these three are the delimiters on the HTTP/1.1 side of a downgrade: a
    /// consumer logging this is looking at a request-smuggling attempt, not at
    /// a peer with a sloppy serializer.
    Delimiter,
    /// Another octet RFC 9110 section 5.5 excludes: RFC 5234's CTL — 0x00-0x1f
    /// together with DEL — less the HTAB a value may carry between its ends.
    /// Reachable only under `.strict`; the floor admits every one of them.
    ///
    /// Named `Control` rather than `Character` so that it does not merge with
    /// `NameError.Character` when the two sets are unioned. Zig error sets
    /// combine by name, and a `FieldError.Character` that could have come from
    /// either half would leave a consumer unable to say which half was bad;
    /// every other member of both sets already implies its half.
    Control,
    /// A leading or trailing SP or HTAB. RFC 9110 section 5.5 puts it plainly:
    /// "a field value does not include leading or trailing whitespace".
    Whitespace,
};

/// The single leading octet a pseudo-header name is allowed (section 8.3).
pub const pseudo_prefix: u8 = ':';

/// Check a field name.
///
/// A name beginning with `pseudo_prefix` is checked from its second octet on,
/// which is what makes `:method` legal and `x:y` and `::method` not. Whether a
/// pseudo-header is *allowed here* — the direction it is defined for, whether a
/// trailer section may carry one — is a question about the message and not
/// about these octets, and `MessageValidator` answers it.
pub fn validateName(name: []const u8, rules: Rules) NameError!void {
    if (name.len == 0) return error.Empty;
    const body = if (name[0] == pseudo_prefix) name[1..] else name;
    // Reachable only for a name that is exactly ":", which is a pseudo-header
    // with nothing after the colon.
    if (body.len == 0) return error.Empty;
    assert(body.len >= 1);
    // The sweep runs over `body`, so a colon it finds is one that was not the
    // prefix — which is what lets the classification below be unconditional.
    if (name[0] == pseudo_prefix) assert(body.len == name.len - 1);

    const offset = switch (rules) {
        .minimal => firstRejected(.name_minimal, body),
        .strict => firstRejected(.name_strict, body),
    } orelse return;

    assert(offset < body.len);
    // The colon is the one octet both readings reject for where it is rather
    // than for what it is, so it is reported as such under both.
    if (body[offset] == pseudo_prefix) return error.Colon;
    return error.Character;
}

/// Check a field value.
///
/// The octet scan runs before the whitespace check, so a value that both
/// carries a CR and ends in a space reports `error.Delimiter`. RFC 9113 sets no
/// precedence between the two and a peer cannot tell which was chosen; the
/// order is fixed here so that the more informative answer is the one a
/// consumer logs.
pub fn validateValue(value: []const u8, rules: Rules) ValueError!void {
    const rejected = switch (rules) {
        .minimal => firstRejected(.value_minimal, value),
        .strict => firstRejected(.value_strict, value),
    };
    if (rejected) |offset| {
        assert(offset < value.len);
        return classifyValueOctet(value[offset]);
    }

    if (value.len == 0) return;
    assert(value.len >= 1);
    if (isOptionalWhitespace(value[0])) return error.Whitespace;
    if (isOptionalWhitespace(value[value.len - 1])) return error.Whitespace;
}

/// The error for an octet `firstRejected` has already refused.
///
/// The assertion is the negative space: this is meaningless for an octet no
/// class rejects, and calling it with one would silently return `Control` for
/// something perfectly legal rather than fail.
fn classifyValueOctet(octet: u8) ValueError {
    assert(octet == 0x00 or octet == '\r' or octet == '\n' or octet <= 0x1f or octet == 0x7f);
    return switch (octet) {
        0x00, '\r', '\n' => error.Delimiter,
        else => error.Control,
    };
}

/// RFC 9110 section 5.6.3's OWS: the two octets a value may contain but may not
/// begin or end with.
fn isOptionalWhitespace(octet: u8) bool {
    return octet == ' ' or octet == '\t';
}

/// The four byte classifications, as the kernel and its reference each state
/// them independently.
///
/// A tag rather than a function parameter because the predicate has to be
/// comptime-known for `rejects` to fold to a handful of compares, and Zig has
/// no way to pass a generic function over `@Vector(lane_count, u8)` that does not cost
/// more clarity than the switch does.
pub const Class = enum {
    name_minimal,
    name_strict,
    value_minimal,
    value_strict,
};

/// Octets a kernel sweeps per iteration: 16 on SSE2, 32 under AVX2.
///
/// `orelse 1` is not a fallback that should ever fire on a target this package
/// is built for; it exists so a scalar target compiles, and it degrades the
/// sweep to the tail loop rather than to something wrong.
const lanes: usize = std.simd.suggestVectorLength(u8) orelse 1;

comptime {
    assert(lanes >= 1);
    // The tail loop below runs at most `lanes - 1` times, which is only a
    // bound if the sweep can actually consume every full block before it.
    assert(std.math.isPowerOfTwo(lanes));
}

/// The index of the first octet `class` rejects, or null if it rejects none.
///
/// The tail runs the *same* predicate at one lane wide rather than a scalar
/// transcription of it, which is the point: a tail that could disagree with the
/// body is a bug that only appears for inputs whose length is not a multiple of
/// the vector width, and those are exactly the inputs a hand-written test picks
/// by accident and a fuzzer picks on purpose.
fn firstRejected(comptime class: Class, bytes: []const u8) ?usize {
    var index: usize = 0;
    // Subtraction rather than `index + lanes <= bytes.len`: the sum is what
    // would overflow, and a bound that can overflow before it is compared is
    // not a bound.
    while (bytes.len - index >= lanes) : (index += lanes) {
        const chunk: @Vector(lanes, u8) = bytes[index..][0..lanes].*;
        const bad = rejects(class, lanes, chunk);
        if (@reduce(.Or, bad)) {
            const offset = index + firstSet(bad);
            assert(offset < bytes.len);
            // The postcondition, where a caller can rely on it: the octet
            // named is one this class actually rejects. `validateName` turns
            // this index into one of two errors, so an index that pointed at
            // an accepted octet would be a wrong answer rather than a crash.
            assert(rejects(class, 1, .{bytes[offset]})[0]);
            return offset;
        }
    }

    assert(bytes.len - index < lanes);
    while (index < bytes.len) : (index += 1) {
        const one: @Vector(1, u8) = .{bytes[index]};
        if (rejects(class, 1, one)[0]) return index;
    }
    assert(index == bytes.len);
    return null;
}

/// The lowest lane set in a mask that `@reduce(.Or, …)` has already said is
/// not empty.
///
/// A minimum over lane indices rather than a `@bitCast` to `uN` and `@ctz`: the
/// bit order of a bool vector under a bitcast is the target's lane order, and a
/// wrong answer here would be an off-by-one in a *reported* octet — the
/// difference between `error.Colon` and `error.Character` for a name carrying
/// both. Unset lanes are given `lanes` itself, which is larger than any real
/// index and so loses the reduction.
fn firstSet(mask: @Vector(lanes, bool)) usize {
    const indices: @Vector(lanes, u32) = std.simd.iota(u32, lanes);
    const missing: @Vector(lanes, u32) = @splat(@intCast(lanes));
    const lane = @reduce(.Min, @select(u32, mask, indices, missing));
    // Guaranteed by the caller's `@reduce(.Or, …)`, and stated here because
    // this function is meaningless without it.
    assert(lane < lanes);
    // The property the name claims, in O(1) vector work: no lane below the one
    // returned is set. This is the negative space — a reduction that picked
    // *some* set lane rather than the first would satisfy the assert above and
    // fail this one, and the difference is `error.Colon` against
    // `error.Character` for a name carrying both faults in one chunk.
    const earlier = indices < @as(@Vector(lanes, u32), @splat(lane));
    assert(!@reduce(.Or, mask & earlier));
    return lane;
}

/// Whether each octet is one its class forbids.
///
/// Every test is `(octets -% lo) <= hi - lo`, one wrapping subtract and one
/// unsigned compare per range and needs no signed-compare fixup — the reason
/// the sets below are written as merged ranges rather than as the RFC's prose.
/// `referenceRejects` states the same sets the way the RFCs do, and the
/// comptime block below proves the two agree on all 256 octets, so the merging
/// is checked rather than trusted. Note what that is and is not: for
/// `.name_strict` and `.value_strict` the two are genuinely different
/// formulations — a character list against merged ranges, and a positive
/// grammar against a negative one — so the proof covers a misreading of the
/// RFC. For the two `minimal` classes the RFC itself states ranges, so there is
/// no second formulation to write and the proof covers the merging and the
/// vectorization only.
inline fn rejects(
    comptime class: Class,
    comptime lane_count: usize,
    octets: @Vector(lane_count, u8),
) @Vector(lane_count, bool) {
    return switch (class) {
        // RFC 9113 section 8.2.1's three ranges, plus the colon.
        .name_minimal => within(lane_count, octets, 0x00, 0x20) |
            within(lane_count, octets, 0x41, 0x5a) |
            within(lane_count, octets, 0x7f, 0xff) |
            within(lane_count, octets, pseudo_prefix, pseudo_prefix),
        // The complement of RFC 9110's tchar minus the uppercase letters:
        // `!`, `#$%&'`, `*+`, `-.`, digits, `^_` and backtick joined to the
        // lowercase letters, `|`, `~`.
        .name_strict => ~(within(lane_count, octets, '!', '!') |
            within(lane_count, octets, '#', '\'') |
            within(lane_count, octets, '*', '+') |
            within(lane_count, octets, '-', '.') |
            within(lane_count, octets, '0', '9') |
            within(lane_count, octets, '^', 'z') |
            within(lane_count, octets, '|', '|') |
            within(lane_count, octets, '~', '~')),
        // Section 8.2.1's three named octets.
        .value_minimal => within(lane_count, octets, 0x00, 0x00) |
            within(lane_count, octets, '\n', '\n') |
            within(lane_count, octets, '\r', '\r'),
        // RFC 9110 section 5.5's field-vchar: every control octet except HTAB,
        // and DEL. Note that obs-text, 0x80-0xff, is *permitted* — a recipient
        // is told to treat it as opaque data, not to refuse it.
        .value_strict => within(lane_count, octets, 0x00, 0x08) |
            within(lane_count, octets, 0x0a, 0x1f) |
            within(lane_count, octets, 0x7f, 0x7f),
    };
}

/// `lo <= v <= hi`, per lane, as one wrapping subtract and one compare.
inline fn within(
    comptime lane_count: usize,
    octets: @Vector(lane_count, u8),
    comptime lo: u8,
    comptime hi: u8,
) @Vector(lane_count, bool) {
    comptime assert(lo <= hi);
    const base: @Vector(lane_count, u8) = @splat(lo);
    const span: @Vector(lane_count, u8) = @splat(hi - lo);
    return (octets -% base) <= span;
}

/// The same four classifications, transcribed from the RFCs rather than merged
/// into ranges, and never called at run time by `validateName` or
/// `validateValue`.
///
/// This is the oracle the kernel is proved against, in the same arrangement
/// `huffman.decodeReference` has with `huffman.decode` and for the same reason:
/// two statements of one rule, written from different sources, are worth far
/// more than one statement tested against itself. It is public so the fuzz
/// targets can reach it from their own module.
pub fn referenceRejects(class: Class, octet: u8) bool {
    return switch (class) {
        .name_minimal => octet <= 0x20 or
            (octet >= 0x41 and octet <= 0x5a) or
            octet >= 0x7f or
            octet == pseudo_prefix,
        // RFC 9110 section 5.6.2, copied out: tchar is these fifteen marks,
        // DIGIT and ALPHA; section 8.2.1 then removes uppercase ALPHA.
        .name_strict => std.mem.indexOfScalar(u8, "!#$%&'*+-.^_`|~", octet) == null and
            !(octet >= '0' and octet <= '9') and
            !(octet >= 'a' and octet <= 'z'),
        .value_minimal => octet == 0x00 or octet == '\n' or octet == '\r',
        // field-vchar = VCHAR / obs-text, with SP and HTAB allowed between.
        .value_strict => !(octet == '\t' or
            (octet >= 0x20 and octet <= 0x7e) or
            octet >= 0x80),
    };
}

comptime {
    // Exhaustive equivalence, at compile time, for every class over every
    // octet. This is what lets the kernel be written as merged ranges: the
    // merging cannot drift from the RFC transcription without failing to
    // build. It also makes the fuzz target's job the *slice* logic — tails,
    // lengths, and which index is reported — rather than the classification.
    @setEvalBranchQuota(1_000_000);
    for (std.enums.values(Class)) |class| {
        for (0..256) |value| {
            const octet: u8 = @intCast(value);
            const expected = referenceRejects(class, octet);

            const one: @Vector(1, u8) = .{octet};
            assert(rejects(class, 1, one)[0] == expected);

            // Again at the width that ships. Every operation in `rejects` is
            // lane-wise and so this cannot differ in theory; the one-lane
            // instantiation is the one the tail loop calls and the wide one is
            // the one the sweep calls, and proving only the first would leave
            // the hot path resting on the argument rather than on the check.
            const wide: @Vector(lanes, u8) = @splat(octet);
            const wide_result = rejects(class, lanes, wide);
            assert(@reduce(.Or, wide_result) == expected);
            assert(@reduce(.And, wide_result) == expected);
        }
    }

    // `strict` must reject everything `minimal` rejects. A mode advertised as
    // the stricter reading that admitted an octet the floor refuses would be a
    // hole with a reassuring name, and the two sets are written far enough
    // apart that nothing else would catch it.
    for (0..256) |value| {
        const octet: u8 = @intCast(value);
        if (referenceRejects(.name_minimal, octet)) assert(referenceRejects(.name_strict, octet));
        if (referenceRejects(.value_minimal, octet)) assert(referenceRejects(.value_strict, octet));
    }
}

/// `validateName` written the slow, obvious way, over `referenceRejects`.
///
/// Public for the differential fuzz target, which needs the two whole-slice
/// walks — not just the two classifications — to be indistinguishable. The
/// comptime block above already settles every individual octet; what is left
/// for a fuzzer is whether the vector sweep and its tail report the same
/// *first* offending index that a plain loop does, for every length.
///
/// Every rule below is written out again rather than reaching for the helper
/// the real one calls. That is the point and it is not redundancy: a helper
/// both sides share is a helper the differential is blind to. The value pair
/// shipped that way first — kernel and reference both called one
/// `classifyValueOctet` and one `isOptionalWhitespace` — and a mutation that
/// reported CR as `Control` instead of `Delimiter` passed the differential
/// test untouched.
pub fn validateNameReference(name: []const u8, rules: Rules) NameError!void {
    if (name.len == 0) return error.Empty;
    const body = if (name[0] == pseudo_prefix) name[1..] else name;
    if (body.len == 0) return error.Empty;

    assert(body.len >= 1);
    assert(body.len <= name.len);

    const class: Class = switch (rules) {
        .minimal => .name_minimal,
        .strict => .name_strict,
    };
    for (body) |octet| {
        if (!referenceRejects(class, octet)) continue;
        // RFC 9113 section 8.2.1: "field names MUST NOT include a colon (ASCII
        // COLON, 0x3a)", with the pseudo-header exception already spent above.
        if (octet == 0x3a) return error.Colon;
        return error.Character;
    }
}

/// `validateValue` written the slow, obvious way. See `validateNameReference`,
/// including why nothing here is factored out into a shared helper.
pub fn validateValueReference(value: []const u8, rules: Rules) ValueError!void {
    const class: Class = switch (rules) {
        .minimal => .value_minimal,
        .strict => .value_strict,
    };
    for (value) |octet| {
        if (!referenceRejects(class, octet)) continue;
        // Section 8.2.1: "the zero value (ASCII NUL, 0x00), line feed (ASCII
        // LF, 0x0a), or carriage return (ASCII CR, 0x0d)".
        if (octet == 0x00 or octet == 0x0a or octet == 0x0d) return error.Delimiter;
        return error.Control;
    }

    if (value.len == 0) return;
    assert(value.len >= 1);
    // Section 8.2.1: "MUST NOT start or end with an ASCII whitespace character
    // (ASCII SP or HTAB, 0x20 or 0x09)".
    if (value[0] == 0x20 or value[0] == 0x09) return error.Whitespace;
    const last = value[value.len - 1];
    if (last == 0x20 or last == 0x09) return error.Whitespace;
}

const testing = std.testing;

/// Lengths that straddle the vector width, so every table-driven case below
/// runs against a full sweep, a bare tail, and both boundaries. `lanes` is 16
/// or 32 depending on the machine, which is exactly why these are computed
/// rather than written as numbers.
const straddling_lengths = [_]usize{ 0, 1, lanes - 1, lanes, lanes + 1, 2 * lanes, 2 * lanes + 3 };

test "a lowercase token name is accepted under both readings" {
    for ([_][]const u8{ "a", "content-type", "x-forwarded-for", "accept-encoding", "0", "!#$%&'*+-.^_`|~" }) |name| {
        try validateName(name, .minimal);
        try validateName(name, .strict);
    }
}

test "an uppercase letter is rejected under both readings, wherever it sits" {
    for (straddling_lengths) |length| {
        if (length == 0) continue;
        var name: [2 * lanes + 3]u8 = undefined;
        @memset(name[0..length], 'a');
        for (0..length) |position| {
            name[position] = 'A';
            try testing.expectError(error.Character, validateName(name[0..length], .minimal));
            try testing.expectError(error.Character, validateName(name[0..length], .strict));
            name[position] = 'a';
        }
    }
}

test "an empty name is rejected, and so is a bare colon" {
    try testing.expectError(error.Empty, validateName("", .minimal));
    try testing.expectError(error.Empty, validateName("", .strict));
    try testing.expectError(error.Empty, validateName(":", .minimal));
    try testing.expectError(error.Empty, validateName(":", .strict));
}

test "a colon is legal only as the single leading octet" {
    for ([_][]const u8{ ":method", ":scheme", ":path", ":authority", ":status" }) |name| {
        try validateName(name, .minimal);
        try validateName(name, .strict);
    }
    for ([_][]const u8{ "::method", "x:y", "method:", ":a:b" }) |name| {
        try testing.expectError(error.Colon, validateName(name, .minimal));
        try testing.expectError(error.Colon, validateName(name, .strict));
    }
}

test "the sixteen delimiters separate the two name readings and nothing else does" {
    // The second half of that sentence is the half worth checking, so this
    // walks all 256 octets rather than the sixteen it expects to find. The
    // earlier version iterated only the delimiters and so asserted nothing at
    // all about the other 240.
    const delimiters = "\"(),/;<=>?@[\\]{}";
    for (0..256) |value| {
        const octet: u8 = @intCast(value);
        const name = [_]u8{ 'a', octet, 'b' };
        const under_minimal = errorOf(NameError, validateName(&name, .minimal));
        const under_strict = errorOf(NameError, validateName(&name, .strict));

        const is_delimiter = std.mem.indexOfScalar(u8, delimiters, octet) != null;
        try testing.expectEqual(is_delimiter, under_minimal == null and under_strict != null);
        // And never the other way round: `strict` cannot admit what the floor
        // refuses, which is the subset relation the comptime block asserts on
        // octets, restated here on whole names.
        try testing.expect(!(under_minimal != null and under_strict == null));
    }
}

test "the controls and DEL separate the two value readings and nothing else does" {
    for (0..256) |value| {
        const octet: u8 = @intCast(value);
        const text = [_]u8{ 'a', octet, 'b' };
        const under_minimal = errorOf(ValueError, validateValue(&text, .minimal));
        const under_strict = errorOf(ValueError, validateValue(&text, .strict));

        // RFC 5234's CTL less HTAB, less the three the floor already names.
        const is_extra_control = (octet <= 0x1f or octet == 0x7f) and
            octet != '\t' and octet != 0x00 and octet != '\n' and octet != '\r';
        try testing.expectEqual(is_extra_control, under_minimal == null and under_strict != null);
        try testing.expect(!(under_minimal != null and under_strict == null));
    }
}

test "the octets section 8.2.1 names outright are refused in a name" {
    for ([_]u8{ 0x00, 0x08, '\t', '\n', '\r', 0x1f, ' ', 0x7f, 0x80, 0xff }) |octet| {
        const name = [_]u8{ 'a', octet, 'b' };
        try testing.expectError(error.Character, validateName(&name, .minimal));
        try testing.expectError(error.Character, validateName(&name, .strict));
    }
}

test "a colon reported ahead of a later bad octet, and after an earlier one" {
    // Which error comes back depends on the *first* rejected index. Both of
    // these are shorter than one vector, so they exercise the tail loop only —
    // see the next test for the sweep, which reports its index differently and
    // was not covered by these.
    // Guarded on `lanes` rather than written flat: with `lanes == 1` there is
    // no tail loop for these to reach, the premise is vacuous, and an
    // unguarded `5 < 1` fails the build — which is what it did on
    // riscv64-linux-none, on a file whose `lanes` constant advertises that a
    // scalar target compiles.
    comptime assert(lanes == 1 or "a:b A".len < lanes);
    try testing.expectError(error.Colon, validateName("a:b A", .minimal));
    try testing.expectError(error.Character, validateName("a Ab:c", .minimal));
}

test "the sweep reports the first rejected octet, not merely some rejected octet" {
    // Two faults inside one vector chunk, at every ordered pair of positions.
    // `firstRejected` returns an index and `validateName` turns that index into
    // one of two errors, so a lane reduction that picked the last set lane
    // instead of the first would be visible here and nowhere else: with a
    // single fault the answer is the same either way, and with two faults
    // closer together than the vector width the tail loop settles it before the
    // sweep ever runs.
    // Deliberately not a multiple of the vector width: at exactly `2 * lanes`
    // no case can have one fault inside a full chunk and the other in the tail,
    // which is the pair that catches a tail loop and a sweep disagreeing about
    // which octet came first.
    const length = 2 * lanes + 5;
    var buffer: [2 * lanes + 5]u8 = undefined;
    comptime assert(length % lanes != 0 or lanes == 1);

    for (0..length) |first_at| {
        for (0..length) |second_at| {
            if (first_at == second_at) continue;
            @memset(&buffer, 'a');
            buffer[first_at] = pseudo_prefix;
            buffer[second_at] = 'A';

            // A colon at position zero is the pseudo-header prefix and not a
            // fault at all, so the uppercase letter is the only one left.
            const colon_is_prefix = first_at == 0;
            const expected: NameError = if (!colon_is_prefix and first_at < second_at)
                error.Colon
            else
                error.Character;
            for ([_]Rules{ .minimal, .strict }) |rules| {
                try testing.expectError(expected, validateName(&buffer, rules));
                try testing.expectError(expected, validateNameReference(&buffer, rules));
            }
        }
    }

    // The same observable on the value side, which had no ordering test at all:
    // whichever of these two comes first decides `Delimiter` against `Control`.
    for (0..length) |carriage_at| {
        for (0..length) |control_at| {
            if (carriage_at == control_at) continue;
            @memset(&buffer, 'a');
            buffer[carriage_at] = '\r';
            buffer[control_at] = 0x01;
            const expected: ValueError = if (carriage_at < control_at)
                error.Delimiter
            else
                error.Control;
            try testing.expectError(expected, validateValue(&buffer, .strict));
            try testing.expectError(expected, validateValueReference(&buffer, .strict));
        }
    }
}

test "the whitespace rule survives a value longer than one vector" {
    // Every whitespace case above is five octets or fewer, so the sweep never
    // ran before the check that follows it. These make it run.
    for ([_]usize{ lanes, lanes + 1, 3 * lanes + 7 }) |length| {
        var value: [3 * lanes + 7]u8 = undefined;
        for ([_]u8{ ' ', '\t' }) |space| {
            @memset(value[0..length], 'a');
            value[0] = space;
            try testing.expectError(error.Whitespace, validateValue(value[0..length], .strict));
            try testing.expectError(error.Whitespace, validateValueReference(value[0..length], .strict));

            @memset(value[0..length], 'a');
            value[length - 1] = space;
            try testing.expectError(error.Whitespace, validateValue(value[0..length], .strict));
            try testing.expectError(error.Whitespace, validateValueReference(value[0..length], .strict));

            // Interior whitespace at the same distance in is not a violation,
            // which is what keeps the two checks above from passing for the
            // wrong reason.
            @memset(value[0..length], 'a');
            value[length / 2] = space;
            try validateValue(value[0..length], .strict);
        }
    }
}

test "an ordinary value is accepted, interior whitespace included" {
    for ([_][]const u8{ "", "text/plain", "Mon, 21 Oct 2013 20:13:21 GMT", "a b", "a\tb", "gzip, deflate" }) |value| {
        try validateValue(value, .minimal);
        try validateValue(value, .strict);
    }
}

test "NUL, CR and LF are refused at every position under both readings" {
    for ([_]u8{ 0x00, '\r', '\n' }) |octet| {
        for (straddling_lengths) |length| {
            if (length == 0) continue;
            var value: [2 * lanes + 3]u8 = undefined;
            @memset(value[0..length], 'x');
            for (0..length) |position| {
                value[position] = octet;
                try testing.expectError(error.Delimiter, validateValue(value[0..length], .minimal));
                try testing.expectError(error.Delimiter, validateValue(value[0..length], .strict));
                value[position] = 'x';
            }
        }
    }
}

test "other controls and DEL part the two readings for values" {
    for ([_]u8{ 0x01, 0x08, 0x0b, 0x0c, 0x1f, 0x7f }) |octet| {
        const value = [_]u8{ 'a', octet, 'b' };
        try validateValue(&value, .minimal);
        try testing.expectError(error.Control, validateValue(&value, .strict));
    }
}

test "obs-text is opaque data, not a rejection" {
    for ([_]u8{ 0x80, 0xa0, 0xfe, 0xff }) |octet| {
        const value = [_]u8{ 'a', octet, 'b' };
        try validateValue(&value, .minimal);
        try validateValue(&value, .strict);
    }
}

test "a value may not begin or end with SP or HTAB" {
    for ([_][]const u8{ " a", "a ", "\ta", "a\t", " ", "\t", "  a  " }) |value| {
        try testing.expectError(error.Whitespace, validateValue(value, .minimal));
        try testing.expectError(error.Whitespace, validateValue(value, .strict));
    }
}

test "a delimiter outranks trailing whitespace" {
    try testing.expectError(error.Delimiter, validateValue("a\r\nb ", .minimal));
    try testing.expectError(error.Delimiter, validateValue(" a\r\nb", .minimal));
}

test "the kernel and the reference agree across the vector boundary" {
    // The comptime block settles every octet on its own; this settles the
    // sweep. Each length gets one rejected octet walked across every position,
    // which is the shape that catches a tail loop reading the wrong bytes.
    for ([_]u8{ 0x00, '\t', '\n', '\r', ' ', 'A', ':', '/', 0x7f, 0x80, 0xff }) |octet| {
        for (straddling_lengths) |length| {
            var buffer: [2 * lanes + 3]u8 = undefined;
            @memset(buffer[0..length], 'a');
            for (0..length) |position| {
                buffer[position] = octet;
                const text = buffer[0..length];
                for ([_]Rules{ .minimal, .strict }) |rules| {
                    try testing.expectEqual(
                        errorOf(NameError, validateNameReference(text, rules)),
                        errorOf(NameError, validateName(text, rules)),
                    );
                    try testing.expectEqual(
                        errorOf(ValueError, validateValueReference(text, rules)),
                        errorOf(ValueError, validateValue(text, rules)),
                    );
                }
                buffer[position] = 'a';
            }
        }
    }
}

fn errorOf(comptime Set: type, result: Set!void) ?Set {
    if (result) |_| return null else |err| return err;
}
