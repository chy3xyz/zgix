//! zero allocation, stateless and streaming HTTP parser module.
//! By streaming, it can parse partially received HTTP requests.
//!
//! Line terminators are strictly CRLF: a bare LF is rejected as
//! `error.Invalid`. Accepting both endings is how request smuggling starts
//! — two intermediaries that disagree about where a line ends parse two
//! different messages out of the same bytes (RFC 9112 §2.2 allows the
//! leniency; a proxy-grade parser must not take it).

const std = @import("std");
const builtin = @import("builtin");
const build_options = @import("build_options");
const assert = std.debug.assert;

/// Block size of the CPU.
const block_size = @sizeOf(usize);

// Both tier constants default to the target CPU's own answer; `build_options`
// only overrides them when a build asks (`-Duse-vectors=false`, `-Dvec-size=16`).
// Nothing outside a test should: the detection below is what makes this parser
// fast on the machine it was built for. The overrides exist because
// `std.simd.suggestVectorLength` is non-null on every target hparse builds for,
// so the scalar tier below each `use_vectors` branch is otherwise unreachable —
// and the fuzz harness diffs a forced-scalar build against this one to keep the
// tiers from disagreeing about the same bytes.
//
// There are two tiers now, not three. The SWAR loops that used to sit between
// them are gone: see `matchHeaderValue` for the measurement that removed the
// last one.

// If suggested vector length is null, prefer not to use vectors!
const use_vectors = build_options.use_vectors orelse (std.simd.suggestVectorLength(u8) != null);

/// This is what we use for vector sizes in vectored operations.
/// If `use_vectors` is false, this gives the default block size for the CPU.
///
/// A forced `-Dvec-size` is ignored when vectors are off, rather than recorded and
/// unused: every reader of this sits inside `if (comptime use_vectors)`, so the build
/// would scan byte-at-a-time while `vec_size` advertised the width of a tier it does
/// not contain.
const vec_size = if (!use_vectors) block_size else build_options.vec_size orelse blk: {
    if (std.simd.suggestVectorLength(u8)) |recommended| {
        // In the future, we can look for ways to utilize 512-bit (AVX-512) or even larger registers.
        break :blk if (recommended >= 64) 32 else recommended;
    } else {
        // If vectors are not recommended, we prefer the default block size.
        break :blk block_size;
    }
};

comptime {
    // `VectorInt` is a bit per lane and `@ctz` reads it as the advance, so a width
    // that is not a power of two would silently mis-index the buffer.
    if (!std.math.isPowerOfTwo(vec_size)) @compileError("vec_size must be a power of two");

    // `firstRejected`'s nibble path pairs lanes into `@Vector(vec_size / 2, u16)`,
    // so a width of one has nowhere to put them. Said here, next to the other
    // constraint on this value, because the alternative is a `-Dvec-size=1` build
    // failing on a bitcast size mismatch three frames down with nothing in the
    // message about the width being the problem.
    if (vec_size < 2) @compileError("vec_size must be at least two");
}

/// Which scan tier this build compiled. Exposed so the fuzz harness can prove the
/// two builds it diffs really are different tiers, rather than quietly comparing a
/// build against itself.
pub const uses_vectors = use_vectors;

/// Width in bytes of the scan tier this build compiled.
pub const vector_size: usize = vec_size;

/// `vec_size` as unsigned integer type.
const VectorInt = std.meta.Int(.unsigned, vec_size);

/// How many bytes `matchHeaderValue` scans scalar before it loads a vector chunk.
///
/// The vector loop gates on `hasLength(vec_size)`, which asks how much BUFFER
/// remains, not how long the value is. A one-byte value in the middle of a large
/// head therefore paid a full 32-byte load, five vector ops, a lane mask and a
/// `@ctz` to find a CR one byte away — about fifteen cycles of pure latency, with
/// nothing to overlap it against, because the next header's key cannot be scanned
/// until this value's end is known. Two scalar iterations end that value first.
///
/// Two is small on purpose, and the cost model says why: the prefix is a flat tax
/// of roughly 1.4 cycles per byte on every value longer than it, paid to save
/// ~15 cycles on every value shorter. At 8 it cost `chrome` 19%. At 2 it catches
/// the one- and two-byte values that dominate the win and taxes the rest barely
/// at all.
///
/// `matchPath` deliberately does NOT do this. The same prefix there COSTS 12% on
/// `long-path` and buys nothing back: a target only benefits if it is one or two
/// bytes, and outside `GET /` that does not happen. Values are the opposite — one-
/// and two-byte ones are everywhere — which is the whole reason the two scans get
/// different treatment.
///
/// Measured, `bench/`, Core Ultra 7 258V, 12 interleaved alternations of two
/// builds, comparing minima. Ratios are new/old, so above 1.00 is faster:
///
///   many-tiny      2.12x      chrome-modern  1.03x
///   long-keys      1.71x      long-path      1.01x
///                             minimal        1.00x
///                             long-values    0.97x
///                             chrome         0.97x
///
/// The two realistic requests disagree by design, and that disagreement is the
/// whole argument for the constant. `chrome` is a 2013 capture whose shortest
/// header value is nine bytes, so it sees only the tax; `chrome-modern` carries
/// the `?0`, `?1` and `1` values a current browser sends, and comes out ahead.
/// Worst case anywhere is 3%.
///
/// `long-keys` swung between 1.09x and 1.71x across rebuilds that did not touch
/// the parser, so read it as "clearly positive" and not as a number. Code layout
/// moves the scalar loops by tens of percent and nothing here pins it down.
const scalar_prefix = 2;

/// HTTP methods.
///
/// The nine registered methods below are matched as 4-byte magic integers
/// — the fast path that keeps this parser quick. Any other legal RFC 9110
/// token (PROPFIND, MKCOL, ...) parses as `.extension`; the raw bytes of
/// every method, registered or not, are returned through `parseRequest`'s
/// `method_token`.
pub const Method = enum(u8) {
    /// Never produced by the parser; use it as the caller-side initialization
    /// sentinel (a successful `parseRequest` always overwrites it).
    unknown,
    get,
    post,
    head,
    put,
    delete,
    connect,
    options,
    trace,
    patch,
    /// A token that is none of the nine above; the bytes live in
    /// `method_token`.
    extension,
};

/// HTTP versions
pub const Version = enum(u1) { @"1.0", @"1.1" };

/// Represents a single HTTP header.
pub const Header = struct {
    key: []const u8,
    value: []const u8,
};

// HTTP methods interpreted as integers
const GET_: u32 = @bitCast([4]u8{ 'G', 'E', 'T', ' ' });
const HEAD: u32 = @bitCast([4]u8{ 'H', 'E', 'A', 'D' });
const POST: u32 = @bitCast([4]u8{ 'P', 'O', 'S', 'T' });
const PUT_: u32 = @bitCast([4]u8{ 'P', 'U', 'T', ' ' });
const DELE: u32 = @bitCast([4]u8{ 'D', 'E', 'L', 'E' });
const CONN: u32 = @bitCast([4]u8{ 'C', 'O', 'N', 'N' });
const OPTI: u32 = @bitCast([4]u8{ 'O', 'P', 'T', 'I' });
const TRAC: u32 = @bitCast([4]u8{ 'T', 'R', 'A', 'C' });
const PATC: u32 = @bitCast([4]u8{ 'P', 'A', 'T', 'C' });

// HTTP versions interpreted as integers
const HTTP_1_0: u64 = @bitCast([8]u8{ 'H', 'T', 'T', 'P', '/', '1', '.', '0' });
const HTTP_1_1: u64 = @bitCast([8]u8{ 'H', 'T', 'T', 'P', '/', '1', '.', '1' });

/// Minimum bytes required for an HTTP/1.x request line.
///
/// `GET / HTTP/1.1\r\n`
const min_request_len = 0x10;

/// * `error.Incomplete` — caller should read more bytes into the buffer and retry.
///   `header_count` is left holding the headers parsed so far rather than being
///   untouched; `parseRequestResume`/`parseResponseResume` turn that into a
///   resume point instead of making the caller start over.
/// * `error.Invalid` — the request/response is malformed.
/// * `error.TooManyHeaders` — the provided `headers` slice was too small; caller can
///   retry with a larger slice.
pub const ParseRequestError = error{ Incomplete, Invalid, TooManyHeaders };

/// Whether this build's mask extraction has to work around a missing `pmovmskb`;
/// see `firstRejected`.
///
/// Little-endian only, and `.aarch64_be` is deliberately absent. Both mask forms
/// read the first rejected lane as the lowest set bit, which is a statement about
/// lane-to-byte order that only holds little-endian — so a big-endian build stays
/// on the path it was already taking rather than moving to one nobody has run.
const is_aarch64 = builtin.cpu.arch == .aarch64;

/// Index of the first rejected lane in `bad`, which must have at least one.
///
/// Reached once per scan, not once per chunk. The loops below advance by a
/// constant `vec_size` for as long as every lane is accepted, and only ask for a
/// position on the chunk they stop in — which is what keeps the mask out of the
/// loop-carried dependency chain, since a constant stride is an address the next
/// load does not have to wait for. That is the shape picohttpparser's SSE4.2 loop
/// has for the same reason: `pcmpestri` costs about ten cycles, so it too advances
/// by a constant and reads the returned index only on the way out.
///
/// Being off the chain does not make the lowering free, because header values are
/// short — most scans stop inside their first chunk, so this runs about as often
/// as the loop does. Hence two lowerings, because the two targets disagree about
/// what a lane mask costs. x86 has `pmovmskb`: one instruction for a bit per lane,
/// so bitcasting the compare result straight to an integer is already optimal.
/// AArch64 has no such instruction, and LLVM lowers `@bitCast(@Vector(N, u1))`
/// into `and`/`ext`/`zip1`/`addv` plus a cross-domain `fmov`. `shrn`, narrowing
/// each pair of 16-bit lanes down four bits, leaves one nibble per input byte in a
/// single 64-bit register instead.
///
/// Do not collapse the two branches. The nibble form on x86 costs a `psrlw` and a
/// `pshufb` on top of the `pmovmskb` it cannot avoid, and the bit form on AArch64
/// costs the reduction above. On the `bench/` request, M3 Max, four interleaved
/// runs comparing minima: 91-93 ns/parse with one portable bit-mask form, 79-82
/// with the split — 13%, down from the 20% the same split was worth against the
/// old loop shape (a separate five-run set, 162-168 -> 130-133). Neither pair is
/// reproducible from this tree: both need a build with this branch taken out, and
/// no build option reaches one.
inline fn firstRejected(bad: @Vector(vec_size, bool)) usize {
    // Stated positively at the entry the callers cross, so a future caller that
    // drops the `@reduce` guard fails here rather than inside the mask.
    assert(@reduce(.Or, bad));

    const adv_by = if (comptime is_aarch64) blk: {
        const Vec = @Vector(vec_size, u8);
        const Half = @Vector(vec_size / 2, u16);
        const Narrow = @Vector(vec_size / 2, u8);
        const NibbleMask = @Int(.unsigned, vec_size * 4);

        const bytes: Vec = @select(u8, bad, @as(Vec, @splat(0xff)), @as(Vec, @splat(0)));
        const nibbles: NibbleMask = @bitCast(@as(Narrow, @truncate(@as(Half, @bitCast(bytes)) >> @as(Half, @splat(4)))));

        // Four mask bits per input byte, so the tail count divides by four.
        break :blk @ctz(nibbles) >> 2;
    } else @ctz(@as(VectorInt, @bitCast(@as(@Vector(vec_size, u1), @intFromBool(bad)))));

    // Both lowerings answer "no lane rejected" with the full width, and both
    // callers have already ruled that out with `@reduce(.Or, bad)` — so a result
    // of `vec_size` here means the mask and the reduction disagreed about the same
    // bytes. Worth catching where they meet, because the value goes straight to
    // `Cursor.advance`, which does not check bounds.
    assert(adv_by < vec_size);
    return adv_by;
}

/// Helper for wandering around & parsing things along the way.
const Cursor = struct {
    /// Pointer to current position of cursor.
    idx: [*]const u8,
    /// Pointer to end of the buffer.
    end: [*]const u8,
    /// Pointer to start of the buffer.
    start: [*]const u8,

    /// Returns the current position.
    inline fn current(cursor: *const Cursor) [*]const u8 {
        return cursor.idx;
    }

    /// How far into the buffer the cursor has reached.
    inline fn offsetFromStart(cursor: *const Cursor) usize {
        return @intFromPtr(cursor.idx) - @intFromPtr(cursor.start);
    }

    /// Returns the current character.
    inline fn char(cursor: *const Cursor) u8 {
        return cursor.idx[0];
    }

    /// Advances the position of the cursor by given value.
    /// SAFETY: This function doesn't check if out of bounds reachable.
    inline fn advance(cursor: *Cursor, by: usize) void {
        cursor.idx += by;
    }

    /// Checks if buffer has `len` length of characters.
    /// `(cursor.end - cursor.idx >= len)`
    inline fn hasLength(cursor: *const Cursor, len: usize) bool {
        return cursor.end - cursor.idx >= len;
    }

    /// Loads a `@Vector(len, u8)` from the current position of cursor without advancing.
    /// SAFETY: This function doesn't check if out of bounds reachable.
    inline fn asVector(cursor: *const Cursor, len: comptime_int) @Vector(len, u8) {
        return cursor.idx[0..len].*;
    }

    /// Creates an integer from the current position of the cursor without advancing.
    /// SAFETY: This function doesn't check if out of bounds reachable.
    /// SAFETY: T must be an integer with bit size >= @bitSizeOf(u8).
    inline fn asInteger(cursor: *const Cursor, comptime T: type) T {
        return @bitCast(cursor.idx[0 .. @bitSizeOf(T) / @bitSizeOf(u8)].*);
    }

    /// Peek the current character but don't advance.
    inline fn peek(cursor: *const Cursor, c: u8) bool {
        return cursor.idx[0] == c;
    }

    /// Peek the current and the next but don't advance.
    /// SAFETY: This function doesn't check if out of bounds reachable.
    inline fn peek2(cursor: *const Cursor, c0: u8, c1: u8) bool {
        return cursor.asInteger(u16) == @as(u16, @bitCast([2]u8{ c0, c1 }));
    }

    /// Peek the current and next 2 characters but don't advance.
    /// SAFETY: This function doesn't check if out of bounds reachable.
    inline fn peek3(cursor: *const Cursor, c0: u8, c1: u8, c2: u8) bool {
        return cursor.idx[0] == c0 and cursor.idx[1] == c1 and cursor.idx[2] == c2;
    }

    /// Peek the current and next 3 characters but don't advance.
    /// SAFETY: This function doesn't check if out of bounds reachable.
    inline fn peek4(cursor: *const Cursor, c0: u8, c1: u8, c2: u8, c3: u8) bool {
        return cursor.asInteger(u32) == @as(u32, @bitCast([4]u8{ c0, c1, c2, c3 }));
    }

    /// Moves the cursor until no leading spaces there are.
    inline fn skipSpaces(cursor: *Cursor) void {
        while (cursor.end - cursor.current() > 0 and cursor.char() == ' ') : (cursor.advance(1)) {}
    }

    /// Parses one CRLF line terminator. Bare LF — or anything else — is
    /// `error.Invalid` (see the module doc); a CR at the end of the buffer
    /// is `error.Incomplete` so the caller can read the LF and retry.
    /// Callers guarantee at least one readable byte.
    inline fn parseCrlf(cursor: *Cursor) ParseRequestError!void {
        assert(cursor.end - cursor.current() >= 1);
        if (cursor.char() != '\r') {
            return error.Invalid;
        }
        cursor.advance(1);
        if (cursor.current() == cursor.end) {
            return error.Incomplete;
        }
        if (cursor.char() != '\n') {
            @branchHint(.unlikely);
            return error.Invalid;
        }
        cursor.advance(1);
    }

    /// Parses the method and the trailing space into `method` and
    /// `method_token`. The nine registered methods match as 4-byte magic
    /// integers (the fast path); any other RFC 9110 token (PROPFIND,
    /// MKCOL, ...) takes the fallback scan and comes out as `.extension`.
    /// `method_token` receives the raw token bytes on both paths.
    inline fn parseMethod(
        cursor: *Cursor,
        method: *Method,
        method_token: *?[]const u8,
    ) ParseRequestError!void {
        const token_start = cursor.current();
        if (cursor.matchKnownMethod()) |known| {
            // The cursor sits one past the trailing space; the token is
            // everything before that space.
            const consumed = cursor.current() - token_start;
            assert(consumed >= 4);
            method.* = known;
            method_token.* = token_start[0 .. consumed - 1];
            return;
        }

        // Extension method: scan the token (RFC 9110 §9.1: method = token)
        // up to the delimiting space. Bounded by the buffer end.
        while (cursor.end - cursor.idx > 0 and isValidMethodChar(cursor.char())) {
            cursor.advance(1);
        }
        // Ran out of buffer before any delimiter: read more and retry.
        if (cursor.current() == cursor.end) {
            return error.Incomplete;
        }
        const token_end = cursor.current();
        // An empty token, or a token stopped by anything but the single
        // delimiting space, is malformed.
        if (token_end == token_start) {
            return error.Invalid;
        }
        if (cursor.char() != ' ') {
            return error.Invalid;
        }
        cursor.advance(1);
        method.* = .extension;
        method_token.* = token_start[0 .. token_end - token_start];
    }

    /// Matches the nine registered methods, each with its trailing space,
    /// as 4-byte magic integers. Advances past method and space only on a
    /// match; rewinds to the token start otherwise.
    /// SAFETY: requires 8 readable bytes (`min_request_len` covers it).
    inline fn matchKnownMethod(cursor: *Cursor) ?Method {
        assert(cursor.hasLength(8));
        const token_start = cursor.current();
        // create an u32 out of received bytes to match the method
        const m_u32: u32 = cursor.asInteger(u32);
        // advance 4 since we just consumed 4
        cursor.advance(4);

        const known: ?Method = blk: switch (m_u32) {
            GET_ => break :blk .get,
            POST => {
                // expect space after this
                if (cursor.peek(' ')) {
                    cursor.advance(1);
                    break :blk .post;
                }
                break :blk null;
            },
            HEAD => {
                // expect space after this
                if (cursor.peek(' ')) {
                    cursor.advance(1);
                    break :blk .head;
                }
                break :blk null;
            },
            PUT_ => break :blk .put,
            DELE => {
                // expect `TE ` after this
                if (cursor.peek3('T', 'E', ' ')) {
                    cursor.advance(3);
                    break :blk .delete;
                }
                break :blk null;
            },
            CONN => {
                // expect `ECT ` after this
                if (cursor.peek4('E', 'C', 'T', ' ')) {
                    cursor.advance(4);
                    break :blk .connect;
                }
                break :blk null;
            },
            OPTI => {
                // expect `ONS ` after this
                if (cursor.peek4('O', 'N', 'S', ' ')) {
                    cursor.advance(4);
                    break :blk .options;
                }
                break :blk null;
            },
            TRAC => {
                // expect `E ` after this
                if (cursor.peek2('E', ' ')) {
                    cursor.advance(2);
                    break :blk .trace;
                }
                break :blk null;
            },
            PATC => {
                // expect 'H ' after this
                if (cursor.peek2('H', ' ')) {
                    cursor.advance(2);
                    break :blk .patch;
                }
                break :blk null;
            },
            else => break :blk null,
        };
        if (known == null) {
            // Not a registered method: rewind so the extension-token scan
            // starts from the first byte.
            cursor.idx = token_start;
        }
        return known;
    }

    /// Validates path characters and advances the cursor as much as validated.
    /// Scans a request-target, stopping at the first byte `path_map` refuses.
    ///
    /// Vectorized, unlike `matchHeaderKey`, and the difference is length: a field
    /// name is a handful of bytes so a 16-byte setup never amortizes, while a target
    /// with a query string routinely runs to hundreds. Both regimes were measured,
    /// 10M parses, 11 interleaved runs, minima, against the range compare this
    /// replaces: scalar-only came out 1.03x on an 8-byte target but 1.30x on a
    /// 165-byte one, so SIMD stays. The vector version below then landed at 0.99x
    /// and 0.99x — slightly FASTER than the permissive code it replaces, because
    /// stating the set as a reject mask drops an inversion and an and-not, which
    /// pays for the eight extra equalities.
    ///
    /// The allowed set is 0x21-0x7e minus nine characters, so it is cheaper to test
    /// what is REJECTED: the bound catches controls, space, DEL and all of 0x80-0xff
    /// at once, and a reject mask feeds `@ctz` with no inversion.
    inline fn matchPath(cursor: *Cursor) void {
        if (comptime use_vectors) {
            const Vec = @Vector(vec_size, u8);

            while (cursor.hasLength(vec_size)) {
                const chunk = cursor.asVector(vec_size);

                // Everything outside 0x21-0x7e, in one wrapping subtract and one
                // unsigned compare. A byte below 0x21 wraps to a large value and a
                // byte above 0x7e is already large, so both bounds fall out of the
                // same test — including every byte from 0x80 up, which the old
                // `chunk > ' '` let straight through.
                var bad: @Vector(vec_size, bool) = (chunk -% @as(Vec, @splat(0x21))) > @as(Vec, @splat(0x5d));

                // `{ | }` are contiguous, so one range covers them.
                bad |= (chunk -% @as(Vec, @splat('{'))) <= @as(Vec, @splat(2));

                // The rest are isolated by pchar neighbours — `=` sits between `<`
                // and `>`, `_` between `^` and the backtick — so they cost one
                // compare each rather than folding into ranges.
                inline for ([_]u8{ '"', '<', '>', '\\', '^', '`' }) |c| {
                    bad |= chunk == @as(Vec, @splat(c));
                }

                // The advance is a constant for as long as the chunks are clean, so
                // the next load's address never waits on the lane mask. Only the
                // chunk that stops the scan pays for a position.
                if (@reduce(.Or, bad)) {
                    cursor.advance(firstRejected(bad));
                    return;
                }

                cursor.advance(vec_size);
            }
        }

        // Tail, and the whole scan under `-Duse-vectors=false`. The SWAR tier that
        // used to sit here is gone: it expressed the same range compare in integer
        // arithmetic, and pchar is not a range.
        while (cursor.end - cursor.idx > 0) : (cursor.advance(1)) {
            if (!isValidPathChar(cursor.char())) {
                return;
            }
        }
    }

    /// Parses the path, must be called after `parseMethod`.
    inline fn parsePath(cursor: *Cursor, path: *?[]const u8) ParseRequestError!void {
        // We assume this is called after `parseMethod`.
        const path_start = cursor.current();
        // validate path characters
        cursor.matchPath();
        // after `matchPath` returns, we're at where path ends
        const path_end = cursor.current();

        // If `matchPath` consumed the whole buffer, we reached the end before finding the
        // delimiter. Check this *before* dereferencing so we never read past the end; the
        // caller can read more data and retry.
        if (path_end == cursor.end) {
            return error.Incomplete;
        }

        // Make sure the char caused `matchPath` to return is a space.
        if (cursor.char() == ' ') {
            @branchHint(.likely); // likely go down here

            // An empty request-target is not a request-target (RFC 9112
            // §3.1.1: origin-form is at minimum "/"). Rejecting it here is
            // also what makes `min_request_len` sound: the shortest LEGAL
            // request, "A / HTTP/1.1\r\n\r\n", is exactly 16 bytes, so the
            // fast-path length check can never refuse a complete request.
            //
            // While an empty target was accepted, it could: `x  HTTP/1.1\r\n
            // \r\n` is 15 bytes, so it parsed when a spare byte happened to
            // follow it in the buffer and returned Incomplete when it did
            // not — the same bytes meaning two different things depending on
            // what came after. A caller that had exactly that request and
            // nothing more would wait for bytes that were never coming.
            if (path_end == path_start) {
                @branchHint(.unlikely);
                return error.Invalid;
            }

            // set path
            path.* = path_start[0 .. path_end - path_start];

            // skip the space
            cursor.advance(1);
            // done
            return;
        }

        // Invalid character that's not a space (32) and not the end of the buffer, so a
        // malformed request. Can't go further.
        return error.Invalid;
    }

    /// Parses the HTTP version and the trailing CRLF, must be called after `parsePath`.
    inline fn parseVersion(cursor: *Cursor, version: *Version) ParseRequestError!void {
        // We need at least 9 chars to parse the version and the first byte
        // of its CRLF terminator: `HTTP/1.1\r` => 9. The LF is checked
        // incrementally by `parseCrlf` (`HTTP/1.1\r\n` => 10).
        if (cursor.end - cursor.current() < 9) {
            return error.Incomplete;
        }

        // Create an integer from current index.
        const chunk = cursor.asInteger(u64);
        // advance as much as consumed
        cursor.advance(8);

        // Match the version with magic integers.
        version.* = blk: switch (chunk) {
            HTTP_1_0 => break :blk .@"1.0",
            HTTP_1_1 => break :blk .@"1.1",
            else => return error.Invalid, // Unknown/unsupported HTTP version.
        };

        // Parse the trailing CRLF (strict; bare LF is invalid).
        try cursor.parseCrlf();
    }

    /// Validates header keys, one byte at a time against `key_map`.
    ///
    /// Deliberately NOT vectorized, unlike every other scan in this parser. A
    /// vector path here has to classify tchar exactly, and tchar is not a range —
    /// the old `chunk > ' '` range compare is precisely what let all 144 non-tchar
    /// bytes through. Without a runtime byte shuffle (Zig exposes none portably, and
    /// `@shuffle` needs a comptime mask) an exact classifier costs six wrapping
    /// subtract-and-compare ranges plus three equalities, roughly 32 SSE2
    /// instructions per 16 bytes against the old six.
    ///
    /// That exact vector path was written and measured before being thrown away.
    /// Against the broken range compare it replaced, on the `bench/` request at
    /// `-Diters=10000000`, 11 interleaved runs on an Intel Core Ultra 7 258V,
    /// comparing minima: exact-vector 1.24x SLOWER, this loop 0.85x — faster than
    /// the code it replaces, while also being correct. Header keys are short (the
    /// benchmark's longest is 15 bytes), so a 16-byte-wide setup never pays for
    /// itself. Re-checked with 40-byte keys, where the vector path should win if it
    /// ever does: it still does not.
    ///
    /// Those ratios are not reproducible from this tree — the variant they describe
    /// is deleted, and `bench/` has no target that isolates this function. Treat
    /// them as the reason the code looks like this, not as a measurement you can
    /// re-run. picohttpparser and httparse both scan field names byte-at-a-time for
    /// the same reason. If you reach for SIMD here again, bring your own numbers.
    inline fn matchHeaderKey(cursor: *Cursor) void {
        while (cursor.end - cursor.idx > 0) : (cursor.advance(1)) {
            if (!isValidKeyChar(cursor.char())) {
                return;
            }
        }
    }

    /// Validates header values: a short byte-at-a-time prefix, then a vector tier,
    /// then a byte-at-a-time tail. Nothing else in between — see `scalar_prefix`
    /// for why the prefix is there and why `matchPath` has no equivalent.
    ///
    /// There used to be a SWAR tier here, and deleting it was faster in both builds
    /// — 0.99x with vectors on, and 0.70x with `-Duse-vectors=false`, where it was
    /// doing all of the work. Two reasons it never paid. With vectors on it only
    /// ever saw the 8-to-31-byte window at the very end of the buffer, a couple of
    /// dozen bytes per parse. And it could not express "TAB is legal" in the
    /// arithmetic — a borrow from a genuine sub-0x20 byte perturbs the next byte's
    /// high bit — so it restarted the loop on every TAB, while a table lookup just
    /// says yes. Header values are overwhelmingly valid, so the branch predictor
    /// gets the scalar loop right every time.
    ///
    /// Which leaves 30 lines of bit arithmetic with a documented borrow hazard,
    /// bought nothing, and had its own tier to diverge in. If you reinstate it,
    /// bring numbers for both builds.
    inline fn matchHeaderValue(cursor: *Cursor) void {
        if (comptime use_vectors) {
            // Short values end here, before the vector loop below charges a chunk
            // for them. See `scalar_prefix`.
            // Counter-bounded, not pointer-bounded. At a prefix this short the
            // `end - idx`, `@min`, `idx + n` setup of a pointer bound costs more
            // than the two iterations it exists to bound — measured 0.90x against
            // 0.97x on `chrome`. A longer prefix would want the other form.
            var scanned: usize = 0;
            while (scanned < scalar_prefix and cursor.end - cursor.idx > 0) : (scanned += 1) {
                if (!isValidValueChar(cursor.char())) {
                    return;
                }
                cursor.advance(1);
            }
            // Either the prefix ran out or the buffer did; an invalid byte returns
            // above rather than falling through, so the vector loop below can only
            // ever start on a byte this loop accepted.
            assert(scanned == scalar_prefix or cursor.end - cursor.idx == 0);

            while (cursor.hasLength(vec_size)) {
                // Fill a vector with TAB (\t, 9).
                const tabs: @Vector(vec_size, u8) = @splat(0x9);
                // Fill a vector with DEL (127).
                const deletes: @Vector(vec_size, u8) = @splat(0x7f);
                // Fill a vector with US (31).
                const full_31: @Vector(vec_size, u8) = @splat(0x1f);
                // Load the next chunk from the buffer.
                const chunk = cursor.asVector(vec_size);

                // A byte is a valid value char if it's greater than US (31) OR is a TAB,
                // and isn't DEL (127). TAB is allowed since it's legal inside field values
                // (RFC 7230 field-content permits SP / HTAB between field-vchars).
                //
                // Stated below as its De Morgan negation, so that `firstRejected`
                // sees the same reject-mask convention `matchPath` hands it.
                const bad = ~((chunk > full_31) | (chunk == tabs)) | (chunk == deletes);

                // chunk includes an invalid char or CRLF, we're done. Constant
                // stride on the clean path, position only on the chunk that stops
                // the scan — see `firstRejected` for why that shape matters.
                if (@reduce(.Or, bad)) {
                    cursor.advance(firstRejected(bad));
                    return;
                }

                // advance the cursor
                cursor.advance(vec_size);
            }
        }

        // fallback, scalar search
        while (cursor.end - cursor.idx > 0) : (cursor.advance(1)) {
            if (!isValidValueChar(cursor.char())) {
                return;
            }
        }
    }

    /// Parses a single header.
    inline fn parseHeader(cursor: *Cursor, header: *Header) ParseRequestError!void {
        const key_start = cursor.current();
        cursor.matchHeaderKey();
        const key_end = cursor.current();

        // If `matchHeaderKey` consumed the whole buffer, we reached the end before finding
        // the delimiter. Check before dereferencing so we never read past the end; the
        // caller can read more data and retry.
        if (key_end == cursor.end) {
            return error.Incomplete;
        }

        // Make sure the invalid character is a colon (58).
        switch (cursor.char()) {
            ':' => {
                @branchHint(.likely);

                // This means 0 length header key, which is invalid.
                if (key_end == key_start) {
                    return error.Invalid;
                }

                // move forward
                cursor.advance(1);
            },
            // Any character that's not a colon (58), and not the end of the buffer, so a
            // malformed request. Can't go further.
            else => return error.Invalid,
        }

        // Trim leading optional whitespace (OWS = SP / HTAB) per RFC 7230.
        while (cursor.end - cursor.current() > 0 and (cursor.char() == ' ' or cursor.char() == '\t')) : (cursor.advance(1)) {}

        // Found where header value starts.
        const val_start = cursor.current();
        cursor.matchHeaderValue();
        const val_end = cursor.current();

        // Same as the key above: if the value ran to the end of the buffer we need more
        // bytes to find its terminator. Check before dereferencing.
        if (val_end == cursor.end) {
            return error.Incomplete;
        }

        // Only CRLF ends the value (strict; bare LF is invalid).
        try cursor.parseCrlf();

        // Trim trailing optional whitespace (OWS = SP / HTAB) per RFC 7230
        // (field-value = OWS field-content OWS). The cursor already sits on the terminator;
        // we only shrink the recorded slice.
        var value = val_start[0 .. val_end - val_start];
        while (value.len > 0 and (value[value.len - 1] == ' ' or value[value.len - 1] == '\t')) {
            value.len -= 1;
        }

        // Header is set.
        header.* = .{
            .key = key_start[0 .. key_end - key_start],
            .value = value,
        };
    }

    /// The response line: version, status code, optional status message,
    /// through the CRLF. Extracted so `parseResponse` and
    /// `parseResponseResume` cannot drift apart in what they accept.
    inline fn parseResponseLine(
        cursor: *Cursor,
        version: *Version,
        status_code: *u16,
        status_msg: *?[]const u8,
    ) ParseRequestError!void {
        // The fixed-width reads below — the 8-byte version, the space at 8,
        // the three status digits at 9..11, the byte at 12 — are unguarded, so
        // the precondition travels with the function now that it no longer
        // sits directly under its caller's `min_res_len` check.
        assert(cursor.hasLength(13));

        // Parse HTTP version.
        // Request and response differ in this sense so we can't use `Cursor.parseVersion` here.
        {
            const chunk = cursor.asInteger(u64);
            // advance as much as consumed
            cursor.advance(8);

            // Match the version with magic integers.
            version.* = blk: switch (chunk) {
                HTTP_1_0 => break :blk .@"1.0",
                HTTP_1_1 => break :blk .@"1.1",
                else => return error.Invalid, // Unknown/unsupported HTTP version.
            };

            // Parse the space afterwards.
            if (cursor.char() != ' ') {
                @branchHint(.unlikely);
                return error.Invalid;
            }

            // Consume the space.
            cursor.advance(1);
        }

        // Parse status code.
        {
            // Make sure next 3 bytes are numeric (0-9).
            const all_digits = cursor.idx[0] > 47 and cursor.idx[0] < 58 and
                cursor.idx[1] > 47 and cursor.idx[1] < 58 and
                cursor.idx[2] > 47 and cursor.idx[2] < 58;

            if (!all_digits) {
                @branchHint(.unlikely);
                return error.Invalid;
            }

            // Parse the status code.
            const hundreds: u16 = @as(u16, @intCast(cursor.idx[0] - '0')) * 100;
            const tens: u16 = @as(u16, @intCast(cursor.idx[1] - '0')) * 10;
            const ones: u16 = @as(u16, @intCast(cursor.idx[2] - '0'));

            // Set the status code.
            status_code.* = hundreds + tens + ones;

            // eat bytes
            cursor.advance(3);
        }

        // Parse status message if exists, otherwise, parse CRLF and continue.
        switch (cursor.char()) {
            ' ' => {
                // Skip spaces if there are more.
                cursor.skipSpaces();
                // Get status message after.
                try cursor.parseStatusMessage(status_msg);
            },
            // No status message: the next bytes must be the strict CRLF
            // (anything else, bare LF included, is invalid).
            else => try cursor.parseCrlf(),
        }
    }

    /// Parses HTTP headers into `headers`.
    ///
    /// If the `headers` slice fills up before the terminating CRLF and another header
    /// follows, returns `error.TooManyHeaders` so the caller can retry with a larger slice.
    ///
    /// One-shot: on `error.Incomplete` the caller is expected to come back with
    /// more bytes and start over. `parseHeadersResume` is the version that does
    /// not start over.
    inline fn parseHeaders(cursor: *Cursor, headers: []Header, count: *usize) ParseRequestError!void {
        assert(@intFromPtr(cursor.idx) >= @intFromPtr(cursor.start));
        assert(@intFromPtr(cursor.idx) <= @intFromPtr(cursor.end));

        var i: usize = 0;
        while (i < headers.len) : (i += 1) {
            // We need at least one byte to tell whether the header section has ended or
            // another header follows. Guard before dereferencing so we never read past the
            // end on a truncated request.
            if (cursor.current() == cursor.end) {
                count.* = i;
                return error.Incomplete;
            }

            // Check if the headers part has finished: only the strict CRLF
            // empty line ends it. A bare LF here falls through into
            // `parseHeader`, which rejects it as an invalid key character.
            if (cursor.char() == '\r') {
                try cursor.parseCrlf();
                // end of headers
                count.* = i;
                return;
            }

            try cursor.parseHeader(&headers[i]);
        }

        // Set count to highest.
        count.* = i;

        // The `headers` slice is full; we still need the terminating CRLF. Guard before
        // dereferencing so we never read past the end.
        if (cursor.current() == cursor.end) {
            return error.Incomplete;
        }

        // We have to check for the ending CRLF, same as what we're doing at top.
        if (cursor.char() == '\r') {
            try cursor.parseCrlf();
            return;
        }
        // The `headers` slice is full and the next byte isn't the terminating CRLF.
        // If it's a valid header-key character, another header follows and the caller
        // needs a larger `headers` slice; otherwise the request is malformed.
        if (isValidKeyChar(cursor.char())) {
            return error.TooManyHeaders;
        }
        return error.Invalid;
    }

    /// One header line, resumable at the byte the last attempt reached.
    ///
    /// `parseHeader` above restarts at the line's first byte, which is why a
    /// line-level resume cursor still costs `n * longest_line`. This one keeps
    /// the scan position and which part of the line it was in, so no byte is
    /// ever scanned twice and the total is linear in the head.
    ///
    /// Deliberately NOT shared with `parseHeader`: that one is the hot path
    /// for callers who already have the whole head, and threading phase state
    /// through it would put branches in the middle of the SIMD scans for the
    /// benefit of callers who are not using it. The fuzz harness parses every
    /// input both ways and requires identical results, which is a stronger
    /// guard against drift than sharing the code would be.
    ///
    /// The partial header's key needs no storage here: it is written into the
    /// caller's `headers[i]` the moment it is known, and that array is part of
    /// the documented `Resume` contract.
    inline fn parseHeaderResume(
        cursor: *Cursor,
        header: *Header,
        state: *Resume,
    ) ParseRequestError!void {
        assert(state.scanned >= state.offset);
        assert(@intFromPtr(cursor.start + state.scanned) <= @intFromPtr(cursor.end));

        const line_start = state.offset;

        if (state.phase == .key) {
            cursor.idx = cursor.start + state.scanned;
            cursor.matchHeaderKey();
            if (cursor.current() == cursor.end) {
                state.scanned = cursor.offsetFromStart();
                // The single implication the loop above rests on: a key that
                // stopped short leaves `scanned` STRICTLY past the line start,
                // which is how the next call tells a resumed line from a fresh
                // one. If these were ever equal the line would restart and its
                // key would be truncated to nothing.
                assert(state.scanned > state.offset);
                return error.Incomplete;
            }
            const key_end = cursor.offsetFromStart();
            if (cursor.char() != ':') return error.Invalid;
            // A zero-length header key is invalid.
            if (key_end == line_start) return error.Invalid;

            header.key = (cursor.start + line_start)[0 .. key_end - line_start];
            cursor.advance(1);
            state.phase = .ows;
            state.scanned = cursor.offsetFromStart();
        }

        if (state.phase == .ows) {
            cursor.idx = cursor.start + state.scanned;
            // Trim leading optional whitespace (OWS = SP / HTAB) per RFC 7230.
            while (cursor.end - cursor.current() > 0 and
                (cursor.char() == ' ' or cursor.char() == '\t')) : (cursor.advance(1))
            {}
            if (cursor.current() == cursor.end) {
                // More OWS may follow, so the value has not started yet.
                state.scanned = cursor.offsetFromStart();
                return error.Incomplete;
            }
            state.phase = .value;
            state.value_start = cursor.offsetFromStart();
            state.scanned = state.value_start;
            assert(state.value_start >= state.offset);
        }

        if (state.phase == .value) {
            cursor.idx = cursor.start + state.scanned;
            cursor.matchHeaderValue();
            if (cursor.current() == cursor.end) {
                state.scanned = cursor.offsetFromStart();
                return error.Incomplete;
            }
            state.value_end = cursor.offsetFromStart();
            state.phase = .crlf;
            // `scanned` means "validated up to here", so it follows the value
            // rather than being left behind at its start — otherwise the field
            // is a lie and the linearity bound loosens for chunked arrival.
            state.scanned = state.value_end;
        }

        assert(state.phase == .crlf);
        assert(state.value_end >= state.value_start);
        cursor.idx = cursor.start + state.value_end;
        // Only CRLF ends the value (strict; bare LF is invalid).
        try cursor.parseCrlf();

        // Trim trailing optional whitespace per RFC 7230
        // (field-value = OWS field-content OWS).
        var value = (cursor.start + state.value_start)[0 .. state.value_end - state.value_start];
        while (value.len > 0 and (value[value.len - 1] == ' ' or value[value.len - 1] == '\t')) {
            value.len -= 1;
        }
        header.value = value;

        // Ready for the next line.
        state.phase = .key;
        state.value_start = 0;
        state.value_end = 0;
    }

    /// `parseHeaders`, resumable to the byte. Mirrors the loop above, with the
    /// line-boundary bookkeeping replaced by `state`.
    inline fn parseHeadersResume(
        cursor: *Cursor,
        headers: []Header,
        count: *usize,
        state: *Resume,
    ) ParseRequestError!void {
        assert(state.header_count <= headers.len);
        assert(state.offset <= state.scanned);

        var i: usize = state.header_count;
        while (i < headers.len) : (i += 1) {
            // A FRESH line, as opposed to one being resumed mid-key: nothing
            // of it has been scanned yet. The distinction matters because
            // `offset` is the line's first byte and `parseHeaderResume` takes
            // the key from there — advancing it to the scan position would
            // silently truncate the key to nothing.
            if (state.phase == .key and state.scanned == state.offset) {
                if (cursor.start + state.offset == cursor.end) {
                    count.* = i;
                    return error.Incomplete;
                }
                cursor.idx = cursor.start + state.offset;
                // Only the strict CRLF empty line ends the header section.
                if (cursor.char() == '\r') {
                    cursor.parseCrlf() catch |err| {
                        if (err == error.Incomplete) count.* = i;
                        return err;
                    };
                    count.* = i;
                    return;
                }
            }

            cursor.parseHeaderResume(&headers[i], state) catch |err| {
                if (err == error.Incomplete) {
                    count.* = i;
                    state.header_count = i;
                }
                return err;
            };
            // The line finished; the next one starts here.
            state.offset = cursor.offsetFromStart();
            state.scanned = state.offset;
            state.header_count = i + 1;
        }

        count.* = i;
        // Every line completed, so the two agree and the tail begins here.
        assert(state.offset == state.scanned);

        const tail_start = state.offset;
        if (cursor.start + tail_start == cursor.end) return error.Incomplete;
        cursor.idx = cursor.start + tail_start;
        if (cursor.char() == '\r') {
            try cursor.parseCrlf();
            return;
        }
        if (isValidKeyChar(cursor.char())) {
            return error.TooManyHeaders;
        }
        return error.Invalid;
    }

    /// Matches status message for valid characters.
    inline fn matchStatusMessage(cursor: *Cursor) void {
        while (cursor.end - cursor.idx > 0) : (cursor.advance(1)) {
            if (!isValidStatusMsgChar(cursor.char())) {
                return;
            }
        }
    }

    /// Parses the status message in HTTP responses.
    inline fn parseStatusMessage(cursor: *Cursor, status_msg: *?[]const u8) ParseRequestError!void {
        const msg_start = cursor.current();
        cursor.matchStatusMessage();
        const msg_end = cursor.current();

        // If `matchStatusMessage` consumed the whole buffer, we reached the end before the
        // terminator. Check before dereferencing so we never read past the end.
        if (msg_end == cursor.end) {
            return error.Incomplete;
        }

        // The character that stopped `matchStatusMessage` must start a
        // strict CRLF (bare LF is invalid).
        try cursor.parseCrlf();

        // set the status message
        status_msg.* = msg_start[0 .. msg_end - msg_start];
    }
};

/// Table of valid method characters — token (tchar) from RFC 9110 §5.6.2:
/// letters, digits, and "!#$%&'*+-.^_`|~".
const method_map: [256]u1 = blk: {
    var map = @as([256]u1, @splat(0));
    for ("!#$%&'*+-.^_`|~") |c| map[c] = 1;
    for ('0'..'9' + 1) |c| map[c] = 1;
    for ('A'..'Z' + 1) |c| map[c] = 1;
    for ('a'..'z' + 1) |c| map[c] = 1;
    break :blk map;
};

/// Checks if a given character is a valid method (token) character.
inline fn isValidMethodChar(c: u8) bool {
    return method_map[c] != 0;
}

/// Table of valid request-target characters: RFC 3986 `pchar`, plus the delimiters
/// an origin-form target is actually built out of.
///
/// A positive table, for the reason `key_map` is one. Written as a denylist this
/// accepted nine characters RFC 3986 requires to be percent-encoded — `"<>\^`{|}` —
/// along with every byte from 0x80 to 0xff.
///
/// The one that mattered is `\`. IIS and .NET, and browser URL parsing, normalize a
/// backslash to `/`. A proxy that routes or authorizes on `/public\..\admin` and an
/// origin that resolves it to `/admin` have read two different paths out of one
/// request-target, which is the same failure as disagreeing about a line terminator.
/// The other eight are not normalized into anything by an origin; they are refused
/// because "the request-target is pchar" is a rule worth being able to state, and
/// carve-outs are how the header-key table drifted.
///
/// Rejecting 0x80-0xff is the part with a real cost: raw UTF-8 in a path is common
/// even though RFC 3986 requires it percent-encoded, and those requests now fail.
/// That is a deliberate trade for a parser sitting in front of path-based routing,
/// not an oversight.
///
/// `#`, `[` and `]` are tolerated against the letter of the grammar. A fragment does
/// not belong in a request-target at all, but clients send it and it fails SAFE — an
/// origin that truncates there sees less path than the proxy did, never more.
/// Brackets are reserved for IP-literals rather than paths, and are ubiquitous in
/// query strings.
///
/// IMPORTANT: none of this makes path-based routing safe by itself. The dominant
/// confusions are percent-encoding (`%2e%2e%2f`) and dot-segments, and this parser
/// decodes neither — it hands back an opaque slice. A caller routing on the target
/// must still normalize before it matches. What the table buys is that the proxy and
/// the origin cannot read *different bytes* as different paths.
const path_map: [256]u1 = blk: {
    var map = @as([256]u1, @splat(0));
    // unreserved
    for ('0'..'9' + 1) |c| map[c] = 1;
    for ('A'..'Z' + 1) |c| map[c] = 1;
    for ('a'..'z' + 1) |c| map[c] = 1;
    for ("-._~") |c| map[c] = 1;
    // sub-delims
    for ("!$&'()*+,;=") |c| map[c] = 1;
    // the rest of pchar
    for (":@") |c| map[c] = 1;
    // absolute-path and query structure, and the pct-encoded escape itself
    for ("/?%") |c| map[c] = 1;
    // tolerated; see above
    for ("#[]") |c| map[c] = 1;
    break :blk map;
};

/// Checks if a given character is a valid path character.
inline fn isValidPathChar(c: u8) bool {
    return path_map[c] != 0;
}

/// Table of valid header key characters — the same token (tchar) set as
/// `method_map`, because RFC 9110 §5.6.2 gives field names and methods the same
/// grammar. A field name is `token`, and `token` is `1*tchar`.
///
/// This is a positive table on purpose. Listing what is *invalid* is how this
/// table came to accept 144 bytes it should not have: the separators
/// `"(),/;<=>?@[\]{}` and every byte 0x80-0xff, none of which are tchar. A proxy
/// that hands a backend a field name the backend parses differently is the same
/// smuggling shape as disagreeing about a line terminator, so this is not a
/// cosmetic conformance point.
///
/// This table is now the only thing that decides a key character — `matchHeaderKey`
/// consults it byte by byte and has no vector path to keep in sync. See the comment
/// there for why, and for the measurement behind it.
const key_map: [256]u1 = method_map;

/// Checks if a given character is a valid header key character.
inline fn isValidKeyChar(c: u8) bool {
    return key_map[c] != 0;
}

/// Table of valid header value characters.
///
/// NOTE: TAB (0x09) is intentionally *not* listed as invalid — it's a legal character
/// inside field values (RFC 7230). Leading/trailing TAB is trimmed as OWS in `parseHeader`.
const value_map = createCharMap(.{
    // Invalid characters (control chars except TAB, plus DEL).
    0,  1,  2,  3,  4,  5,  6,  7,  8,  10, 11, 12, 13, 14, 15, 16,
    17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 127,
});

/// Checks if a given character is a valid header value character.
inline fn isValidValueChar(c: u8) bool {
    return value_map[c] != 0;
}

/// Table of valid status message characters.
///
/// RFC 9112 §4 gives `reason-phrase = *( HTAB / SP / VCHAR / obs-text )`, so this is
/// deliberately one character STRICTER than the grammar: HTAB is listed invalid
/// below. Nothing is gained by taking a tab in a phrase clients are told to ignore,
/// and refusing more than the spec requires is the safe direction for a proxy. It is
/// called out because it is a real deviation, and an undocumented table choice is
/// how `key_map` and `path_map` both drifted.
const status_msg_map = createCharMap(.{
    // Invalid characters.
    0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14, 15,  16,
    17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 127,
});

/// Checks if a given character is a valid statuss message character.
inline fn isValidStatusMsgChar(c: u8) bool {
    return status_msg_map[c] != 0;
}

/// Returns a table of 8-bit characters where zeros are invalid and ones are valid,
/// built from the list of characters that are NOT allowed.
///
/// WHEN TO USE THIS, and it is not "never": write the table in the shape the RFC
/// writes the set.
///
/// Two of this parser's tables were denylists and both drifted into accepting bytes
/// they should not have. `key_map` admitted 144 non-tchar bytes and `path_map`
/// admitted `"<>\^`{|}` plus all of 0x80-0xff — in each case because the grammar
/// defines an ALLOWED set (`token` is `1*tchar`, a path segment is `*pchar`) and
/// someone transcribed it inside out. Anything the author did not think to exclude
/// became legal, which is a denylist failing open. Those two are now built as
/// positive tables, next to the grammar they encode.
///
/// The two tables still built here are correct, and for a reason that generalises:
/// their grammars are themselves stated as exclusions. RFC 9110 field-value is
/// `VCHAR / obs-text` plus SP and HTAB — every byte except controls and DEL — and
/// RFC 9112 reason-phrase is the same shape. Listing what they exclude *is* the
/// direct transcription, and inverting them into 200-entry allowlists would be the
/// error-prone direction.
///
/// So: if the RFC says "these are allowed", write an allowlist. If it says
/// "everything but these", use this. Do not pick based on which is shorter to type.
inline fn createCharMap(comptime invalids: anytype) [256]u1 {
    comptime {
        var map: [256]u1 = undefined;
        // Set each index initially.
        @memset(&map, 1);

        // Unset invalid characters.
        for (invalids) |c| map[c] = 0;

        return map;
    }
}

// Public API

/// Parses an HTTP request.
/// * `error.Incomplete` indicates more data is needed to complete the request.
/// * `error.Invalid` indicates request is invalid/malformed.
/// * `error.TooManyHeaders` indicates `headers` was too small; retry with a larger slice.
pub fn parseRequest(
    // Slice we want to parse.
    slice: []const u8,
    /// Parsed method will be stored here. Extension methods (PROPFIND,
    /// MKCOL, ...) come out as `.extension`.
    method: *Method,
    /// The method's raw token bytes ("GET", "PROPFIND", ...) will be
    /// stored here for every successful parse.
    method_token: *?[]const u8,
    /// Parsed path will be stored here.
    path: *?[]const u8,
    /// Parsed HTTP version will be stored here.
    version: *Version,
    /// Parsed headers will be stored here.
    headers: []Header,
    /// Count of parsed headers will be set here.
    header_count: *usize,
) ParseRequestError!usize {
    // The shortest LEGAL request is exactly `min_request_len` bytes:
    // "A / HTTP/1.1\r\n\r\n" is 1+1+1+1+8+2+2 = 16. That is what makes this
    // fast path safe — no complete request can be refused by it — and it holds
    // only because an empty request-target is refused in `parsePath`.
    if (slice.len < min_request_len) {
        return error.Incomplete;
    }

    // Pointer to start of the buffer.
    const slice_start = slice.ptr;
    // Pointer to end of the buffer
    const slice_end = slice.ptr + slice.len;

    // The cursor helps walking through bytes and parsing things.
    // I should better rename it to `Parser` since it's use cases are more similar to it.
    var cursor = Cursor{ .idx = slice_start, .end = slice_end, .start = slice_start };

    // parse the method
    try cursor.parseMethod(method, method_token);
    // parse the path
    try cursor.parsePath(path);
    // parse the HTTP version
    try cursor.parseVersion(version);
    // parse HTTP headers
    try cursor.parseHeaders(headers, header_count);

    // Return the total consumed length to caller.
    return cursor.current() - cursor.start;
}

/// Where an incomplete parse stopped, so the next attempt continues instead of
/// starting over.
///
/// Without this, a streaming caller has no choice but to re-parse the whole
/// head every time more bytes arrive, which makes parsing a head O(N^2) in the
/// number of segments it arrives in — and the segmentation is chosen by
/// whoever is sending. Measured against an 8 KiB head arriving one byte at a
/// time: 8,858 parses, 39 MB scanned, 8.4 ms of CPU for a single head. At
/// 64 KiB it is 2.19 GB and 371 ms.
///
/// Zero-initialise for a new message, then pass the SAME value back alongside
/// a slice that has only GROWN AT THE END. Bytes already consumed must not
/// have moved or changed: the header slices already written point into them.
/// A caller whose buffer can shift — a compaction, a rebase, a ring wrap —
/// must reset this to `.{}` and re-parse from the beginning. An offset past
/// the end is refused; a buffer compacted in place at the same address is not
/// detectable here, and is the caller's to avoid.
///
/// The other out-parameters are equally caller-owned across calls:
///
/// * `headers` must be the SAME array, with `headers[0..header_count]` intact
///   — those slots are not rewritten — AND `headers[header_count]` untouched
///   while a parse is in flight. The key of a half-parsed line is written
///   there as soon as it is known and its value is attached calls later, so
///   clearing or reusing that slot between calls corrupts the header.
/// * `method`, `method_token`, `path` and `version` (or `version`,
///   `status_code`, `status_msg`) are written ONCE, by whichever call finishes
///   the request or status line — `line_done` is what records that. The final
///   successful call does not write them again, so a caller that resets them
///   between calls will see a success return alongside a stale or null value.
/// * On `error.TooManyHeaders` the state still points into the message, so a
///   retry with a bigger array must first copy `headers[0..header_count]` into
///   it. Resetting to `.{}` and re-parsing is the simpler option and costs one
///   pass over a head that was already going to be rejected or grown.
pub const Resume = struct {
    /// Bytes at the front of the slice already parsed.
    offset: usize = 0,
    /// Headers already written into the caller's array.
    header_count: usize = 0,
    /// The request or status line is parsed; only headers remain.
    line_done: bool = false,
    /// Which part of the header line at `offset` the scan stopped in.
    phase: Phase = .key,
    /// How far the scan has already validated. Never less than `offset`, and
    /// the reason no byte is scanned twice: a partial line resumes here rather
    /// than at its first byte.
    scanned: usize = 0,
    /// Bounds of the value of the line being parsed, once they are known.
    value_start: usize = 0,
    value_end: usize = 0,

    /// Where inside one header line a partial parse stopped.
    pub const Phase = enum { key, ows, value, crlf };
};

/// `parseRequest`, resumable. Identical results, linear total work.
///
/// The request line has no interior resume point, so it is re-parsed until it
/// completes — bounded by the length of that one line, never by the head.
pub fn parseRequestResume(
    slice: []const u8,
    state: *Resume,
    method: *Method,
    method_token: *?[]const u8,
    path: *?[]const u8,
    version: *Version,
    headers: []Header,
    header_count: *usize,
) ParseRequestError!usize {
    // `state` is caller-supplied, and `offset` is the one input to this parser
    // that is not a byte in the slice. An out-of-range offset would put the
    // cursor past `end`, and every scan loop here computes `end - idx` as an
    // unsigned pointer difference — which underflows to a huge length and runs
    // off the buffer. So it is an error, not an assertion: assertions are gone
    // in the ReleaseFast build a consumer is free to choose.
    if (state.offset > slice.len) return error.Invalid;
    // `scanned` is caller state too, and the parser relies on it never
    // trailing `offset` (that is what tells a fresh line from a resumed one)
    // and never running past the slice. Both are refused rather than asserted,
    // for the same reason: assertions are gone in ReleaseFast.
    if (state.scanned < state.offset) return error.Invalid;
    if (state.scanned > slice.len) return error.Invalid;
    // `phase`, `value_start` and `value_end` are public fields too, and the
    // `.crlf` path indexes straight through them: `cursor.start + value_end`,
    // and a `value_end` below `value_start` underflows the recorded length to
    // ~0 and walks the trim loop off the buffer. Same reasoning as above —
    // these are errors because assertions are not there in ReleaseFast.
    // Each bound is checked by the phase that actually reads it: `.ows` has
    // not found the value yet, and only `.crlf` indexes through `value_end`.
    if (state.phase == .value or state.phase == .crlf) {
        if (state.value_start < state.offset) return error.Invalid;
        if (state.value_start > slice.len) return error.Invalid;
    }
    if (state.phase == .crlf) {
        if (state.value_end < state.value_start) return error.Invalid;
        if (state.value_end > slice.len) return error.Invalid;
    }
    assert(state.header_count <= headers.len);
    if (!state.line_done) assert(state.header_count == 0);

    const slice_start = slice.ptr;
    var cursor = Cursor{
        .idx = slice_start + state.offset,
        .start = slice_start,
        .end = slice_start + slice.len,
    };

    if (!state.line_done) {
        if (slice.len < min_request_len) return error.Incomplete;
        cursor.idx = slice_start;
        try cursor.parseMethod(method, method_token);
        try cursor.parsePath(path);
        try cursor.parseVersion(version);
        state.line_done = true;
        state.offset = cursor.offsetFromStart();
        // The header scan starts where the line ended; `scanned` never trails
        // `offset`, and the first header line has nothing scanned yet.
        state.scanned = state.offset;
    }

    return resumeHeaders(&cursor, state, slice.len, headers, header_count);
}

/// The header phase of a resumable parse.
///
/// Shared by the request and response entry points on purpose: they differ
/// only in their minimum length and their line parser, and a correctness fix
/// applied to one and missed in the other is exactly the drift that extracting
/// `parseResponseLine` was meant to prevent.
fn resumeHeaders(
    cursor: *Cursor,
    state: *Resume,
    slice_len: usize,
    headers: []Header,
    header_count: *usize,
) ParseRequestError!usize {
    assert(state.line_done);

    const before = state.scanned;
    cursor.parseHeadersResume(headers, header_count, state) catch |err| {
        if (err == error.Incomplete) {
            // The scan never rewinds and never runs past what it was given.
            assert(state.scanned >= before);
            assert(state.scanned <= slice_len);
            assert(state.offset <= state.scanned);
        }
        return err;
    };

    return cursor.offsetFromStart();
}

/// Minimum response len.
///
/// `HTTP/1.1 200\r\n`
/// Status message (OK) is optional.
const min_res_len = 14;

/// Parses an HTTP response.
/// * `error.Incomplete` indicates more data is needed to complete the response.
/// * `error.Invalid` indicates response is invalid/malformed.
/// * `error.TooManyHeaders` indicates `headers` was too small; retry with a larger slice.
pub fn parseResponse(
    // Slice we want to parse.
    slice: []const u8,
    /// Parsed HTTP version will be stored here.
    version: *Version,
    /// Parsed status code will be stored here.
    status_code: *u16,
    /// Parsed status message will be stored here.
    status_msg: *?[]const u8,
    /// Parsed headers will be stored here.
    headers: []Header,
    /// Count of parsed headers will be set here.
    header_count: *usize,
) ParseRequestError!usize {
    // We need at least `min_res_len` bytes to start parsing.
    if (slice.len < min_res_len) {
        return error.Incomplete;
    }

    const slice_start = slice.ptr;
    const slice_end = slice.ptr + slice.len;

    var cursor = Cursor{ .idx = slice_start, .start = slice_start, .end = slice_end };

    try cursor.parseResponseLine(version, status_code, status_msg);

    // Parse headers.
    try cursor.parseHeaders(headers, header_count);

    // Return the total consumed length to caller.
    return cursor.current() - cursor.start;
}

/// `parseResponse`, resumable. See `Resume` for the contract.
pub fn parseResponseResume(
    slice: []const u8,
    state: *Resume,
    version: *Version,
    status_code: *u16,
    status_msg: *?[]const u8,
    headers: []Header,
    header_count: *usize,
) ParseRequestError!usize {
    // `state` is caller-supplied, and `offset` is the one input to this parser
    // that is not a byte in the slice. An out-of-range offset would put the
    // cursor past `end`, and every scan loop here computes `end - idx` as an
    // unsigned pointer difference — which underflows to a huge length and runs
    // off the buffer. So it is an error, not an assertion: assertions are gone
    // in the ReleaseFast build a consumer is free to choose.
    if (state.offset > slice.len) return error.Invalid;
    // `scanned` is caller state too, and the parser relies on it never
    // trailing `offset` (that is what tells a fresh line from a resumed one)
    // and never running past the slice. Both are refused rather than asserted,
    // for the same reason: assertions are gone in ReleaseFast.
    if (state.scanned < state.offset) return error.Invalid;
    if (state.scanned > slice.len) return error.Invalid;
    // `phase`, `value_start` and `value_end` are public fields too, and the
    // `.crlf` path indexes straight through them: `cursor.start + value_end`,
    // and a `value_end` below `value_start` underflows the recorded length to
    // ~0 and walks the trim loop off the buffer. Same reasoning as above —
    // these are errors because assertions are not there in ReleaseFast.
    // Each bound is checked by the phase that actually reads it: `.ows` has
    // not found the value yet, and only `.crlf` indexes through `value_end`.
    if (state.phase == .value or state.phase == .crlf) {
        if (state.value_start < state.offset) return error.Invalid;
        if (state.value_start > slice.len) return error.Invalid;
    }
    if (state.phase == .crlf) {
        if (state.value_end < state.value_start) return error.Invalid;
        if (state.value_end > slice.len) return error.Invalid;
    }
    assert(state.header_count <= headers.len);
    if (!state.line_done) assert(state.header_count == 0);

    const slice_start = slice.ptr;
    var cursor = Cursor{
        .idx = slice_start + state.offset,
        .start = slice_start,
        .end = slice_start + slice.len,
    };

    if (!state.line_done) {
        if (slice.len < min_res_len) return error.Incomplete;
        cursor.idx = slice_start;
        try cursor.parseResponseLine(version, status_code, status_msg);
        state.line_done = true;
        state.offset = cursor.offsetFromStart();
        // The header scan starts where the line ended; `scanned` never trails
        // `offset`, and the first header line has nothing scanned yet.
        state.scanned = state.offset;
    }

    return resumeHeaders(&cursor, state, slice.len, headers, header_count);
}

const testing = std.testing;

/// Testing only.
fn cursorFromBuffer(buf: []const u8) Cursor {
    return .{ .idx = buf.ptr, .start = buf.ptr, .end = buf.ptr + buf.len };
}

test "cursor: parse method/path/version" {
    const check = struct {
        fn func(req: []const u8, expected: Method) !void {
            var cursor = Cursor{ .idx = req.ptr, .start = req.ptr, .end = req.ptr + req.len };

            // test method
            var method = Method.unknown;
            var method_token: ?[]const u8 = null;
            try cursor.parseMethod(&method, &method_token);
            try testing.expectEqual(expected, method);
            try testing.expect(method_token != null);

            // test path
            var path: ?[]const u8 = null;
            try cursor.parsePath(&path);
            try testing.expectEqualStrings("/", path.?);

            // test version
            var version = Version.@"1.0";
            try cursor.parseVersion(&version);
            try testing.expectEqual(.@"1.1", version);
        }
    }.func;

    try check("GET / HTTP/1.1\r\n\r\n", .get);
    try check("POST / HTTP/1.1\r\n\r\n", .post);
    try check("HEAD / HTTP/1.1\r\n\r\n", .head);
    try check("PUT / HTTP/1.1\r\n\r\n", .put);
    try check("DELETE / HTTP/1.1\r\n\r\n", .delete);
    try check("CONNECT / HTTP/1.1\r\n\r\n", .connect);
    try check("OPTIONS / HTTP/1.1\r\n\r\n", .options);
    try check("TRACE / HTTP/1.1\r\n\r\n", .trace);
    try check("PATCH / HTTP/1.1\r\n\r\n", .patch);
}

test "parseRequest: extension methods parse as tokens" {
    const Case = struct { req: []const u8, token: []const u8 };
    const cases = [_]Case{
        .{ .req = "PROPFIND /dav HTTP/1.1\r\nDepth: 1\r\n\r\n", .token = "PROPFIND" },
        .{ .req = "MKCOL /new HTTP/1.1\r\n\r\n", .token = "MKCOL" },
        .{ .req = "M-SEARCH * HTTP/1.1\r\n\r\n", .token = "M-SEARCH" },
        .{ .req = "VERSION-CONTROL /r HTTP/1.1\r\n\r\n", .token = "VERSION-CONTROL" },
        // Registered-method prefixes must fall back to the token scan,
        // not get rejected by the failed magic match.
        .{ .req = "POSTER /x HTTP/1.1\r\n\r\n", .token = "POSTER" },
        .{ .req = "GETX /x HTTP/1.1\r\n\r\n", .token = "GETX" },
        // Tokens are case-sensitive; lowercase is a different (legal) token.
        .{ .req = "get /x HTTP/1.1\r\n\r\n", .token = "get" },
    };

    for (cases) |case| {
        var method: Method = .unknown;
        var method_token: ?[]const u8 = null;
        var path: ?[]const u8 = null;
        var version: Version = .@"1.0";
        var headers: [8]Header = undefined;
        var header_count: usize = 0;

        const len = try parseRequest(
            case.req,
            &method,
            &method_token,
            &path,
            &version,
            &headers,
            &header_count,
        );
        try testing.expectEqual(case.req.len, len);
        try testing.expectEqual(Method.extension, method);
        try testing.expectEqualStrings(case.token, method_token.?);
        try testing.expectEqual(.@"1.1", version);
    }
}

test "parseRequest: known methods also expose their token" {
    const Case = struct { req: []const u8, method: Method, token: []const u8 };
    const cases = [_]Case{
        .{ .req = "GET / HTTP/1.1\r\n\r\n", .method = .get, .token = "GET" },
        .{ .req = "DELETE / HTTP/1.1\r\n\r\n", .method = .delete, .token = "DELETE" },
        .{ .req = "CONNECT host:443 HTTP/1.1\r\n\r\n", .method = .connect, .token = "CONNECT" },
    };

    for (cases) |case| {
        var method: Method = .unknown;
        var method_token: ?[]const u8 = null;
        var path: ?[]const u8 = null;
        var version: Version = .@"1.0";
        var headers: [8]Header = undefined;
        var header_count: usize = 0;

        _ = try parseRequest(
            case.req,
            &method,
            &method_token,
            &path,
            &version,
            &headers,
            &header_count,
        );
        try testing.expectEqual(case.method, method);
        try testing.expectEqualStrings(case.token, method_token.?);
    }
}

test "parseRequest: malformed method tokens are rejected" {
    const requests = [_][]const u8{
        "P@TCH / HTTP/1.1\r\n\r\n", // '@' is not a tchar
        " GET / HTTP/1.1\r\n\r\n", // empty token (leading space)
        "\x01GET / HTTP/1.1\r\n\r\n", // control byte before the token
    };

    for (requests) |req| {
        var method: Method = .unknown;
        var method_token: ?[]const u8 = null;
        var path: ?[]const u8 = null;
        var version: Version = .@"1.0";
        var headers: [8]Header = undefined;
        var header_count: usize = 0;

        try testing.expectError(
            error.Invalid,
            parseRequest(req, &method, &method_token, &path, &version, &headers, &header_count),
        );
    }
}

test "parseRequest: method token without its delimiter stays incomplete" {
    // Sixteen tchar bytes and no space yet: the method may continue in the
    // next read, so the caller must be told to retry, not given Invalid.
    const req = "PROPFINDPROPFIND";
    var method: Method = .unknown;
    var method_token: ?[]const u8 = null;
    var path: ?[]const u8 = null;
    var version: Version = .@"1.0";
    var headers: [8]Header = undefined;
    var header_count: usize = 0;

    try testing.expectError(
        error.Incomplete,
        parseRequest(req, &method, &method_token, &path, &version, &headers, &header_count),
    );
}

test "parseRequest: bare LF line terminators are rejected" {
    // One bare LF at every structural position. Accepting any of these is
    // a smuggling ingredient (see the module doc); all must be Invalid,
    // never a successful parse.
    const requests = [_][]const u8{
        "GET / HTTP/1.1\n\r\n", // request line
        "GET / HTTP/1.1\n\n", // request line and empty line
        "GET / HTTP/1.1\r\nHost: a\n\r\n", // header line
        "GET / HTTP/1.1\r\nHost: a\r\n\n", // final empty line
        "GET / HTTP/1.1\r\n\nHost: a\r\n\r\n", // empty line instead of headers
    };

    for (requests) |req| {
        var method: Method = .unknown;
        var method_token: ?[]const u8 = null;
        var path: ?[]const u8 = null;
        var version: Version = .@"1.0";
        var headers: [8]Header = undefined;
        var header_count: usize = 0;

        try testing.expectError(
            error.Invalid,
            parseRequest(req, &method, &method_token, &path, &version, &headers, &header_count),
        );
    }
}

test "parseResponse: bare LF line terminators are rejected" {
    const responses = [_][]const u8{
        "HTTP/1.1 200 OK\n\r\n", // status line with message
        "HTTP/1.1 200\n\r\n", // status line without message
        "HTTP/1.1 200 OK\r\nHost: a\n\r\n", // header line
        "HTTP/1.1 200 OK\r\nHost: a\r\n\n", // final empty line
    };

    for (responses) |res| {
        var version: Version = .@"1.0";
        var status_code: u16 = 0;
        var status_msg: ?[]const u8 = null;
        var headers: [8]Header = undefined;
        var header_count: usize = 0;

        try testing.expectError(
            error.Invalid,
            parseResponse(res, &version, &status_code, &status_msg, &headers, &header_count),
        );
    }
}

test "cursor: match path" {
    // RFC 3986 pchar, plus the delimiters an origin-form target is built out of and
    // the three characters tolerated against the letter of the grammar. Spelled out
    // here rather than derived from `path_map`, so that the test can disagree with
    // the table — a test written as `path_map[c] != 0` would have happily ratified
    // the denylist this replaced, which admitted `"<>\^`{|}` and all of 0x80-0xff.
    const allowed = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" ++
        "-._~" ++ "!$&'()*+,;=" ++ ":@" ++ "/?%" ++ "#[]";

    for (0..256) |c| {
        var buf: [47]u8 = undefined;
        @memset(&buf, @intCast(c));

        var cursor = cursorFromBuffer(&buf);
        cursor.matchPath();

        if (std.mem.indexOfScalar(u8, allowed, @intCast(c)) != null) {
            // Valid throughout, so the whole buffer is consumed.
            try testing.expectEqual(cursor.end, cursor.current());
            try testing.expect(cursor.end - cursor.current() == 0);
        } else {
            // Invalid at the very first byte, so nothing is consumed.
            try testing.expectEqual(c, cursor.char());
            try testing.expectEqual(cursor.start, cursor.current());
            try testing.expect(cursor.end - cursor.current() == buf.len);
        }
    }
}

test parseRequest {
    const buffer: []const u8 = "OPTIONS /hey-this-is-kinda-long-path HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";

    var method: Method = .unknown;
    var method_token: ?[]const u8 = null;
    var path: ?[]const u8 = null;
    var http_version: Version = .@"1.0";
    var headers: [2]Header = undefined;
    var header_count: usize = 0;

    const len = try parseRequest(buffer[0..], &method, &method_token, &path, &http_version, &headers, &header_count);

    try testing.expect(len == buffer.len);
    try testing.expect(method == .options);
    try testing.expectEqualStrings("OPTIONS", method_token.?);
    try testing.expect(path != null);
    try testing.expectEqualStrings("/hey-this-is-kinda-long-path", path.?);
    try testing.expect(http_version == .@"1.1");
    try testing.expect(header_count == 2);
    try testing.expectEqualStrings("Host", headers[0].key);
    try testing.expectEqualStrings("localhost", headers[0].value);
    try testing.expectEqualStrings("Connection", headers[1].key);
    try testing.expectEqualStrings("close", headers[1].value);
}

test parseResponse {
    const buffer = "HTTP/1.1 418 I'm a teapot\r\nHost: localhost\r\nSome-Number-Sequence: 123291429\r\n\r\n";

    var version: Version = .@"1.0";
    var status_code: u16 = 0;
    var status_msg: ?[]const u8 = null;
    var headers: [2]Header = undefined;
    var header_count: usize = 0;

    const len = try parseResponse(buffer[0..], &version, &status_code, &status_msg, &headers, &header_count);

    try testing.expect(buffer.len == len);
    try testing.expect(version == .@"1.1");
    try testing.expect(status_code == 418);
    try testing.expect(status_msg != null);
    try testing.expectEqualStrings("I'm a teapot", status_msg.?);
    try testing.expect(header_count == 2);
    try testing.expectEqualStrings("Host", headers[0].key);
    try testing.expectEqualStrings("localhost", headers[0].value);
    try testing.expectEqualStrings("Some-Number-Sequence", headers[1].key);
    try testing.expectEqualStrings("123291429", headers[1].value);
}

test "parseRequest: does not read past slice end (OOB regression)" {
    // The backing array is one byte longer than the slice we hand to the parser, and that
    // extra byte is `\n`. Before the end-of-buffer guards, `parseHeaders` would read this
    // byte, treat it as end-of-headers, and report a completed parse that consumed *more*
    // bytes than the slice it was given. It must return `error.Incomplete` instead.
    var backing: [17]u8 = undefined;
    const req = "GET / HTTP/1.1\r\n"; // 16 bytes: well-formed request line, header section truncated
    @memcpy(backing[0..16], req);
    backing[16] = '\n';
    const slice: []const u8 = backing[0..16];

    var method: Method = .unknown;
    var method_token: ?[]const u8 = null;
    var path: ?[]const u8 = null;
    var version: Version = .@"1.0";
    var headers: [8]Header = undefined;
    var header_count: usize = 0;

    try testing.expectError(
        error.Incomplete,
        parseRequest(slice, &method, &method_token, &path, &version, &headers, &header_count),
    );
}

test "parseRequest: truncated inputs return Incomplete" {
    // Each of these ends right where the parser would otherwise dereference one byte past
    // the buffer (path, header key, header value, and between-headers). All must report
    // `error.Incomplete` so the caller can read more and retry.
    const truncations = [_][]const u8{
        "GET / HTTP/1.1\r\n", // header section not started, ends on CRLF
        "GET /aaaaaaaaaaaa", // path with no delimiter yet (>= min_request_len)
        "GET / HTTP/1.1\r\nHost", // header key not terminated by ':'
        "GET / HTTP/1.1\r\nHost: x", // header value not terminated by CRLF
        "GET / HTTP/1.1\r\nHost: x\r\n", // one full header, missing final CRLF
    };

    for (truncations) |req| {
        var method: Method = .unknown;
        var method_token: ?[]const u8 = null;
        var path: ?[]const u8 = null;
        var version: Version = .@"1.0";
        var headers: [8]Header = undefined;
        var header_count: usize = 0;

        try testing.expectError(
            error.Incomplete,
            parseRequest(req, &method, &method_token, &path, &version, &headers, &header_count),
        );
    }
}

test "parseRequest: space in header key is rejected regardless of match path" {
    // Historical: `matchHeaderKey` had a SIMD path chosen by how many bytes remained,
    // and before `key_map` listed space as invalid the scalar path accepted "A B"
    // while the SIMD path rejected it. Both lengths now run the same byte-at-a-time
    // loop, so this no longer probes two tiers — kept because the input is still the
    // one that exposed the split, and because the resolution to that split (making
    // the table agree with the SIMD range compare rather than with RFC 9110) is what
    // later admitted 144 non-tchar bytes. See the tchar test below.
    const reqs = [_][]const u8{
        "GET / HTTP/1.1\r\nA B: v\r\n\r\n", // short tail
        "GET / HTTP/1.1\r\nA B: valuevaluevaluevalue\r\n\r\n", // long tail
    };

    for (reqs) |req| {
        var method: Method = .unknown;
        var method_token: ?[]const u8 = null;
        var path: ?[]const u8 = null;
        var version: Version = .@"1.0";
        var headers: [8]Header = undefined;
        var header_count: usize = 0;

        try testing.expectError(
            error.Invalid,
            parseRequest(req, &method, &method_token, &path, &version, &headers, &header_count),
        );
    }
}

test "parseRequest: a header key is exactly tchar, for every byte" {
    // `key_map` used to be written as a list of what is invalid — controls, space,
    // colon, DEL — which quietly admitted 144 bytes that are not tchar: the RFC 9110
    // separators `"(),/;<=>?@[\]{}` and all of 0x80-0xff. A field name a backend
    // parses differently is the same smuggling shape as disagreeing about a line
    // terminator, so this walks all 256 rather than spot-checking the ones that
    // happened to be found.
    //
    // Both padding lengths matter: `matchHeaderKey` had a vector path chosen by how
    // many bytes remained, and this parser has already shipped one key-scan bug that
    // only one of the two tiers had. The vector path is gone, but the case that
    // exposed the split is worth keeping.
    const tchar = "!#$%&'*+-.^_`|~0123456789" ++
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

    for ([_][]const u8{ "A", &@as([24]u8, @splat('A')) }) |pad| {
        for (0..256) |c| {
            const byte: u8 = @intCast(c);

            var buf: [96]u8 = undefined;
            const req = try std.fmt.bufPrint(&buf, "GET / HTTP/1.1\r\n{s}{c}{s}: v\r\n\r\n", .{ pad, byte, pad });

            var method: Method = .unknown;
            var method_token: ?[]const u8 = null;
            var path: ?[]const u8 = null;
            var version: Version = .@"1.0";
            var headers: [8]Header = undefined;
            var header_count: usize = 0;

            const parsed = if (parseRequest(req, &method, &method_token, &path, &version, &headers, &header_count)) |_| true else |_| false;
            // A colon does not make the parse fail, it ends the key early — so the
            // key surviving whole is what "this byte is legal in a key" means.
            const accepted = parsed and header_count == 1 and headers[0].key.len == pad.len * 2 + 1;

            try testing.expectEqual(std.mem.indexOfScalar(u8, tchar, byte) != null, accepted);
        }
    }
}

test "parseRequest: a request-target is exactly pchar, for every byte" {
    // The `matchPath` counterpart to the tchar test above, and it exists for the
    // same reason: `path_map` was a denylist, so it admitted `"<>\^`{|}` and every
    // byte from 0x80 up, none of which RFC 3986 allows unencoded.
    //
    // The byte is placed at two offsets so it lands inside the vector chunk in one
    // case and in the scalar tail in the other. `matchPath` still has both, so this
    // is the one place a tier split could hide — unlike header keys, where the
    // vector path is gone and the path-differential fuzz oracle has nothing left to
    // compare.
    const allowed = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" ++
        "-._~" ++ "!$&'()*+,;=" ++ ":@" ++ "/?%" ++ "#[]";

    for ([_][]const u8{ "a", &@as([40]u8, @splat('a')) }) |pad| {
        for (0..256) |c| {
            const byte: u8 = @intCast(c);

            var buf: [128]u8 = undefined;
            const req = try std.fmt.bufPrint(&buf, "GET /{s}{c}{s} HTTP/1.1\r\n\r\n", .{ pad, byte, pad });

            var method: Method = .unknown;
            var method_token: ?[]const u8 = null;
            var path: ?[]const u8 = null;
            var version: Version = .@"1.0";
            var headers: [8]Header = undefined;
            var header_count: usize = 0;

            const parsed = if (parseRequest(req, &method, &method_token, &path, &version, &headers, &header_count)) |_| true else |_| false;
            // A rejected byte truncates the target rather than always failing the
            // parse, so the target surviving whole is what acceptance means here.
            const accepted = parsed and path.?.len == pad.len * 2 + 2;

            try testing.expectEqual(std.mem.indexOfScalar(u8, allowed, byte) != null, accepted);
        }
    }
}

test "parseResponse: truncated status/headers return Incomplete" {
    const truncations = [_][]const u8{
        "HTTP/1.1 200\r\n", // status line only, missing final CRLF
        "HTTP/1.1 200 OK", // status message not terminated
        "HTTP/1.1 200 OK\r\nHost: x", // header value not terminated
    };

    for (truncations) |res| {
        var version: Version = .@"1.0";
        var status_code: u16 = 0;
        var status_msg: ?[]const u8 = null;
        var headers: [8]Header = undefined;
        var header_count: usize = 0;

        try testing.expectError(
            error.Incomplete,
            parseResponse(res, &version, &status_code, &status_msg, &headers, &header_count),
        );
    }
}

test "parseRequest: OWS/HTAB handling in header values (RFC 7230)" {
    const Case = struct { req: []const u8, expected: []const u8 };
    const cases = [_]Case{
        // leading HTAB after the colon is trimmed
        .{ .req = "GET / HTTP/1.1\r\nHost:\tlocalhost\r\n\r\n", .expected = "localhost" },
        // trailing SP + HTAB are trimmed
        .{ .req = "GET / HTTP/1.1\r\nHost: localhost \t \r\n\r\n", .expected = "localhost" },
        // internal HTAB is preserved (scalar path, short value)
        .{ .req = "GET / HTTP/1.1\r\nX: a\tb\r\n\r\n", .expected = "a\tb" },
        // internal HTAB is preserved (SIMD path, long value)
        .{ .req = "GET / HTTP/1.1\r\nX: aaaaaaaa\tbbbbbbbbbbbb\r\n\r\n", .expected = "aaaaaaaa\tbbbbbbbbbbbb" },
    };

    for (cases) |c| {
        var method: Method = .unknown;
        var method_token: ?[]const u8 = null;
        var path: ?[]const u8 = null;
        var version: Version = .@"1.0";
        var headers: [8]Header = undefined;
        var header_count: usize = 0;

        _ = try parseRequest(c.req, &method, &method_token, &path, &version, &headers, &header_count);
        try testing.expect(header_count == 1);
        try testing.expectEqualStrings(c.expected, headers[0].value);
    }
}

test "parseRequest: header values at the scalar_prefix boundary" {
    // `matchHeaderValue` hands the first `scalar_prefix` bytes to a byte loop and
    // everything after to the vector loop, so the lengths either side of that seam
    // are where the two tiers could disagree about the same bytes.
    //
    // Every case is padded with a trailing header. Without it the vector loop is
    // unreachable: it gates on `hasLength(vec_size)`, which asks how much BUFFER
    // remains, so a 25-byte request never enters it and the "boundary" would be
    // tested entirely against the scalar tail — the same mistake `scalar_prefix`
    // exists because of.
    const pad = "Pad: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n";
    const Case = struct { value: []const u8, expected: []const u8 };
    const cases = [_]Case{
        // Empty: the seam is crossed before a single byte is accepted.
        .{ .value = "", .expected = "" },
        // Ends inside the prefix.
        .{ .value = "a", .expected = "a" },
        // Exactly `scalar_prefix` bytes: the terminator is the first thing the
        // vector loop is asked about.
        .{ .value = "ab", .expected = "ab" },
        // One past it: the first byte the vector loop actually classifies.
        .{ .value = "abc", .expected = "abc" },
    };

    inline for (cases) |c| {
        const req = "GET / HTTP/1.1\r\nX: " ++ c.value ++ "\r\n" ++ pad ++ "\r\n";
        var method: Method = .unknown;
        var method_token: ?[]const u8 = null;
        var path: ?[]const u8 = null;
        var version: Version = .@"1.0";
        var headers: [8]Header = undefined;
        var header_count: usize = 0;

        _ = try parseRequest(req, &method, &method_token, &path, &version, &headers, &header_count);
        try testing.expect(header_count == 2);
        try testing.expectEqualStrings(c.expected, headers[0].value);
    }
}

test "parseRequest: DEL just past the scalar_prefix seam is still refused" {
    // Padded for the same reason as above, and deliberately at offset 2 — the
    // first byte the vector tier sees. An earlier version of this test put it at
    // offset 0 in a 25-byte request, where the vector tier never runs at all.
    const pad = "Pad: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n";

    inline for (.{ "\x7f", "a\x7f", "ab\x7f", "abc\x7f" }) |value| {
        const req = "GET / HTTP/1.1\r\nX: " ++ value ++ "\r\n" ++ pad ++ "\r\n";
        var method: Method = .unknown;
        var method_token: ?[]const u8 = null;
        var path: ?[]const u8 = null;
        var version: Version = .@"1.0";
        var headers: [8]Header = undefined;
        var header_count: usize = 0;

        try testing.expectError(error.Invalid, parseRequest(req, &method, &method_token, &path, &version, &headers, &header_count));
    }
}

test "parseRequest: buffer truncated inside the scalar_prefix window" {
    // The prefix loop can also run out of buffer rather than out of budget, which
    // is the path that must still report Incomplete rather than a short value.
    const heads = [_][]const u8{
        "GET / HTTP/1.1\r\nX:",
        "GET / HTTP/1.1\r\nX: ",
        "GET / HTTP/1.1\r\nX: a",
        "GET / HTTP/1.1\r\nX: ab",
        "GET / HTTP/1.1\r\nX: abc",
    };

    for (heads) |head| {
        var method: Method = .unknown;
        var method_token: ?[]const u8 = null;
        var path: ?[]const u8 = null;
        var version: Version = .@"1.0";
        var headers: [8]Header = undefined;
        var header_count: usize = 0;

        try testing.expectError(error.Incomplete, parseRequest(head, &method, &method_token, &path, &version, &headers, &header_count));
    }
}

test "parseRequest: full headers slice with more headers returns TooManyHeaders" {
    // Three headers but room for only two: the caller should be told to grow the slice
    // rather than getting an indistinguishable error.Invalid.
    const req = "GET / HTTP/1.1\r\nA: 1\r\nB: 2\r\nC: 3\r\n\r\n";

    var method: Method = .unknown;
    var method_token: ?[]const u8 = null;
    var path: ?[]const u8 = null;
    var version: Version = .@"1.0";
    var headers: [2]Header = undefined;
    var header_count: usize = 0;

    try testing.expectError(
        error.TooManyHeaders,
        parseRequest(req, &method, &method_token, &path, &version, &headers, &header_count),
    );

    // With a large enough slice the same request parses cleanly.
    var big: [8]Header = undefined;
    const len = try parseRequest(req, &method, &method_token, &path, &version, &big, &header_count);
    try testing.expect(len == req.len);
    try testing.expect(header_count == 3);
}

// ---------------------------------------------------------------------------
// resume

/// Feeds `wire` one byte at a time through `parseRequestResume`, and returns
/// the total number of bytes the parser was asked to look at.
///
/// That total is the whole point: without a resume cursor a caller must hand
/// the parser everything it has on every attempt, so the total is quadratic in
/// the head length. With one it is linear, and this counts it so the property
/// is a gate rather than a claim.
fn driveRequestByteAtATime(
    wire: []const u8,
    headers: []Header,
    method: *Method,
    method_token: *?[]const u8,
    path: *?[]const u8,
    version: *Version,
    header_count: *usize,
    consumed: *usize,
) !usize {
    var state: Resume = .{};
    var examined: usize = 0;
    var have: usize = 0;
    while (have < wire.len) {
        have += 1;
        // Bytes this call can possibly look at: everything past the resume
        // point. With no resume cursor this would be `have` every time.
        // What the parser will actually look at: everything past the point the
        // scan already reached. Before intra-line resume this was `state.offset`
        // — the start of the LINE — which is precisely the difference.
        examined += have - state.scanned;
        if (parseRequestResume(
            wire[0..have],
            &state,
            method,
            method_token,
            path,
            version,
            headers,
            header_count,
        )) |n| {
            consumed.* = n;
            return examined;
        } else |err| switch (err) {
            error.Incomplete => continue,
            else => return err,
        }
    }
    return error.Incomplete;
}

test "resume: byte-at-a-time equals one-shot, for requests" {
    const wire = "GET /some/path?q=1 HTTP/1.1\r\n" ++
        "host: example.com\r\nuser-agent: probe/1.0\r\nx-a: 1\r\naccept: */*\r\n\r\n";

    var one_headers: [16]Header = undefined;
    var one_method: Method = .unknown;
    var one_token: ?[]const u8 = null;
    var one_path: ?[]const u8 = null;
    var one_version: Version = .@"1.0";
    var one_count: usize = 0;
    const one_consumed = try parseRequest(
        wire,
        &one_method,
        &one_token,
        &one_path,
        &one_version,
        &one_headers,
        &one_count,
    );

    var inc_headers: [16]Header = undefined;
    var inc_method: Method = .unknown;
    var inc_token: ?[]const u8 = null;
    var inc_path: ?[]const u8 = null;
    var inc_version: Version = .@"1.0";
    var inc_count: usize = 0;
    var inc_consumed: usize = 0;
    const examined = try driveRequestByteAtATime(
        wire,
        &inc_headers,
        &inc_method,
        &inc_token,
        &inc_path,
        &inc_version,
        &inc_count,
        &inc_consumed,
    );

    try testing.expectEqual(one_consumed, inc_consumed);
    try testing.expectEqual(one_method, inc_method);
    try testing.expectEqualStrings(one_token.?, inc_token.?);
    try testing.expectEqualStrings(one_path.?, inc_path.?);
    try testing.expectEqual(one_version, inc_version);
    try testing.expectEqual(one_count, inc_count);
    for (one_headers[0..one_count], inc_headers[0..inc_count]) |a, b| {
        try testing.expectEqualStrings(a.key, b.key);
        try testing.expectEqualStrings(a.value, b.value);
    }

    // The property this API exists for, stated exactly.
    //
    // Re-parsing from byte zero costs n*(n+1)/2. The resume cursor keeps both
    // the line it is on AND how far into that line the scan reached, so no
    // byte is ever scanned twice: the total is LINEAR in the head, with a
    // small constant for the per-call bookkeeping.
    const quadratic = wire.len * (wire.len + 1) / 2;
    try testing.expect(examined < quadratic / 8);
    // The request line has no interior resume point, so it is re-read until it
    // completes: that is line_len^2/2, paid once. Everything after it is read
    // exactly once plus one byte of look-ahead per call.
    const line_len = std.mem.indexOf(u8, wire, "\r\n").? + 2;
    try testing.expect(examined <= line_len * line_len + 2 * wire.len);
}

test "resume: byte-at-a-time equals one-shot, for responses" {
    const wire = "HTTP/1.1 404 Not Found\r\n" ++
        "server: nginx\r\ncontent-length: 153\r\nconnection: close\r\n\r\n";

    var one_headers: [16]Header = undefined;
    var one_version: Version = .@"1.0";
    var one_status: u16 = 0;
    var one_msg: ?[]const u8 = null;
    var one_count: usize = 0;
    const one_consumed = try parseResponse(
        wire,
        &one_version,
        &one_status,
        &one_msg,
        &one_headers,
        &one_count,
    );

    var inc_headers: [16]Header = undefined;
    var inc_version: Version = .@"1.0";
    var inc_status: u16 = 0;
    var inc_msg: ?[]const u8 = null;
    var inc_count: usize = 0;
    var state: Resume = .{};
    var examined: usize = 0;
    var inc_consumed: usize = 0;
    var have: usize = 0;
    while (have < wire.len) {
        have += 1;
        // What the parser will actually look at: everything past the point the
        // scan already reached. Before intra-line resume this was `state.offset`
        // — the start of the LINE — which is precisely the difference.
        examined += have - state.scanned;
        if (parseResponseResume(
            wire[0..have],
            &state,
            &inc_version,
            &inc_status,
            &inc_msg,
            &inc_headers,
            &inc_count,
        )) |n| {
            inc_consumed = n;
            break;
        } else |err| switch (err) {
            error.Incomplete => continue,
            else => return err,
        }
    }

    try testing.expectEqual(one_consumed, inc_consumed);
    try testing.expectEqual(one_version, inc_version);
    try testing.expectEqual(one_status, inc_status);
    try testing.expectEqualStrings(one_msg.?, inc_msg.?);
    try testing.expectEqual(one_count, inc_count);
    for (one_headers[0..one_count], inc_headers[0..inc_count]) |a, b| {
        try testing.expectEqualStrings(a.key, b.key);
        try testing.expectEqualStrings(a.value, b.value);
    }
    const line_len = std.mem.indexOf(u8, wire, "\r\n").? + 2;
    try testing.expect(examined <= line_len * line_len + 2 * wire.len);
}

test "resume: every segmentation reaches the same answer" {
    // Not just byte-at-a-time: the resume point must be right for any split,
    // including ones that land inside a header name, inside a value, and
    // between the CR and the LF of a line terminator.
    // The OWS forms matter: leading SP+HTAB runs are what exercise the `.ows`
    // phase across a buffer boundary, and trailing OWS is trimmed from the
    // recorded value after the scan has already crossed one.
    const wire = "POST /submit HTTP/1.1\r\nhost: h\r\nx-a: \t  vv  \t\r\n" ++
        "content-length: 4\r\nx-b:\r\nx-c:\tw\r\n\r\n";

    var expected_headers: [8]Header = undefined;
    var expected_method: Method = .unknown;
    var expected_token: ?[]const u8 = null;
    var expected_path: ?[]const u8 = null;
    var expected_version: Version = .@"1.0";
    var expected_count: usize = 0;
    const expected_consumed = try parseRequest(
        wire,
        &expected_method,
        &expected_token,
        &expected_path,
        &expected_version,
        &expected_headers,
        &expected_count,
    );

    for (1..wire.len) |step| {
        var headers: [8]Header = undefined;
        var method: Method = .unknown;
        var token: ?[]const u8 = null;
        var path: ?[]const u8 = null;
        var version: Version = .@"1.0";
        var count: usize = 0;
        var state: Resume = .{};
        var have: usize = 0;
        var consumed: usize = 0;

        while (have < wire.len) {
            have = @min(have + step, wire.len);
            if (parseRequestResume(
                wire[0..have],
                &state,
                &method,
                &token,
                &path,
                &version,
                &headers,
                &count,
            )) |n| {
                consumed = n;
                break;
            } else |err| switch (err) {
                error.Incomplete => continue,
                else => return err,
            }
        }

        try testing.expectEqual(expected_consumed, consumed);
        try testing.expectEqual(expected_count, count);
        try testing.expectEqualStrings(expected_path.?, path.?);
        for (expected_headers[0..expected_count], headers[0..count]) |a, b| {
            try testing.expectEqualStrings(a.key, b.key);
            try testing.expectEqualStrings(a.value, b.value);
        }
    }
}

test "parseRequest: an empty request-target is refused" {
    // RFC 9112 §3.1.1 — origin-form is at minimum "/". Found by the fuzzer's
    // consumed-length round-trip oracle, which failed because accepting an
    // empty target let a 15-byte "request" exist at all.
    // At or above `min_request_len` the parser has enough bytes to decide, and
    // the decision is Invalid.
    const cases = [_][]const u8{
        "GET  HTTP/1.1\r\n\r\n",
        "x  HTTP/1.1\r\n\r\n ", // 16 bytes: one past the threshold
        "POST  HTTP/1.1\r\nhost: h\r\n\r\n",
    };
    for (cases) |wire| {
        try testing.expect(wire.len >= min_request_len);
        var method: Method = .unknown;
        var token: ?[]const u8 = null;
        var path: ?[]const u8 = null;
        var version: Version = .@"1.0";
        var headers: [8]Header = undefined;
        var count: usize = 0;
        try testing.expectError(error.Invalid, parseRequest(
            wire,
            &method,
            &token,
            &path,
            &version,
            &headers,
            &count,
        ));
    }

    // Below the threshold the honest answer is "not yet" — the parser cannot
    // see enough to judge, and no COMPLETE legal request is this short, so
    // nothing valid is being deferred.
    {
        const short = "x  HTTP/1.1\r\n\r\n";
        try testing.expect(short.len < min_request_len);
        var method: Method = .unknown;
        var token: ?[]const u8 = null;
        var path: ?[]const u8 = null;
        var version: Version = .@"1.0";
        var headers: [8]Header = undefined;
        var count: usize = 0;
        try testing.expectError(error.Incomplete, parseRequest(
            short,
            &method,
            &token,
            &path,
            &version,
            &headers,
            &count,
        ));
    }
}

test "parseRequest: the shortest legal request parses at exactly its own length" {
    // The property the `min_request_len` fast path silently depended on: no
    // COMPLETE request is shorter than the threshold, so handing the parser
    // exactly one request can never look like "not enough bytes yet".
    //
    // Before empty targets were refused this was false, and the verdict on a
    // complete request depended on how many unrelated bytes followed it.
    const shortest = "A / HTTP/1.1\r\n\r\n";
    try testing.expectEqual(@as(usize, 16), shortest.len);
    try testing.expectEqual(@as(usize, 0x10), min_request_len);

    var method: Method = .unknown;
    var token: ?[]const u8 = null;
    var path: ?[]const u8 = null;
    var version: Version = .@"1.0";
    var headers: [8]Header = undefined;
    var count: usize = 0;
    const n = try parseRequest(
        shortest,
        &method,
        &token,
        &path,
        &version,
        &headers,
        &count,
    );
    try testing.expectEqual(shortest.len, n);
    try testing.expectEqualStrings("/", path.?);
    try testing.expectEqual(@as(usize, 0), count);

    // And the round trip the fuzzer checks: re-parsing exactly what was
    // consumed gives the same answer rather than error.Incomplete.
    var method2: Method = .unknown;
    var token2: ?[]const u8 = null;
    var path2: ?[]const u8 = null;
    var version2: Version = .@"1.0";
    var headers2: [8]Header = undefined;
    var count2: usize = 0;
    const n2 = try parseRequest(
        shortest[0..n],
        &method2,
        &token2,
        &path2,
        &version2,
        &headers2,
        &count2,
    );
    try testing.expectEqual(n, n2);
}

test "parseRequest: every RFC 9112 request-target form is accepted" {
    // Refusing an EMPTY target must not refuse any target that is merely
    // unusual. hparse is used by a proxy, so absolute-form, authority-form
    // (CONNECT) and asterisk-form (OPTIONS) all have to survive.
    const cases = [_]struct { wire: []const u8, target: []const u8 }{
        .{ .wire = "GET /p?q=1 HTTP/1.1\r\nhost: h\r\n\r\n", .target = "/p?q=1" },
        .{ .wire = "GET http://h.example/p HTTP/1.1\r\nhost: h\r\n\r\n", .target = "http://h.example/p" },
        .{ .wire = "CONNECT h.example:443 HTTP/1.1\r\nhost: h\r\n\r\n", .target = "h.example:443" },
        .{ .wire = "OPTIONS * HTTP/1.1\r\nhost: h\r\n\r\n", .target = "*" },
    };
    for (cases) |c| {
        var method: Method = .unknown;
        var token: ?[]const u8 = null;
        var path: ?[]const u8 = null;
        var version: Version = .@"1.0";
        var headers: [8]Header = undefined;
        var count: usize = 0;
        _ = try parseRequest(c.wire, &method, &token, &path, &version, &headers, &count);
        try testing.expectEqualStrings(c.target, path.?);
    }
}

test "resume: an exactly-full header array agrees with one-shot at every split" {
    // The bug this pins: `parseHeaders`' tail block — reached only when the
    // caller's array is exactly full — had an `Incomplete` exit that never
    // reported where it stopped. The resume cursor then pointed at the
    // PREVIOUS line, which read as "the array is full again" and returned
    // TooManyHeaders for a message one-shot parsing accepts. A caller obeying
    // the TooManyHeaders contract would retry with a larger array, resume at
    // the wrong index, and hand back a header slot nothing had written.
    //
    // Every earlier resume test sized the array well above the header count,
    // so none of them could reach that block.
    const wire = "GET / HTTP/1.1\r\nA: b\r\n\r\n";
    const exact = 1; // exactly as many headers as the message has

    var expected_headers: [exact]Header = undefined;
    var expected_method: Method = .unknown;
    var expected_token: ?[]const u8 = null;
    var expected_path: ?[]const u8 = null;
    var expected_version: Version = .@"1.0";
    var expected_count: usize = 0;
    const expected_consumed = try parseRequest(
        wire,
        &expected_method,
        &expected_token,
        &expected_path,
        &expected_version,
        &expected_headers,
        &expected_count,
    );
    try testing.expectEqual(@as(usize, exact), expected_count);

    for (1..wire.len) |step| {
        var headers: [exact]Header = undefined;
        var method: Method = .unknown;
        var token: ?[]const u8 = null;
        var path: ?[]const u8 = null;
        var version: Version = .@"1.0";
        var count: usize = 0;
        var state: Resume = .{};
        var have: usize = 0;
        var consumed: usize = 0;

        while (have < wire.len) {
            have = @min(have + step, wire.len);
            if (parseRequestResume(
                wire[0..have],
                &state,
                &method,
                &token,
                &path,
                &version,
                &headers,
                &count,
            )) |n| {
                consumed = n;
                break;
            } else |err| switch (err) {
                error.Incomplete => continue,
                else => return err,
            }
        }

        try testing.expectEqual(expected_consumed, consumed);
        try testing.expectEqual(expected_count, count);
        try testing.expectEqualStrings(expected_headers[0].key, headers[0].key);
        try testing.expectEqualStrings(expected_headers[0].value, headers[0].value);
    }
}

test "resume: an out-of-range offset is refused rather than trusted" {
    // `state.offset` is the one input to this parser that is not a byte in the
    // slice. Past the end it would put the cursor beyond `end`, and every scan
    // loop computes `end - idx` as an unsigned pointer difference — which
    // underflows and runs off the buffer. An assertion would not survive the
    // ReleaseFast build a consumer may choose, so it is an error.
    const wire = "GET / HTTP/1.1\r\n\r\n";
    var headers: [4]Header = undefined;
    var method: Method = .unknown;
    var token: ?[]const u8 = null;
    var path: ?[]const u8 = null;
    var version: Version = .@"1.0";
    var count: usize = 0;
    var state: Resume = .{ .offset = wire.len + 1, .line_done = true };
    try testing.expectError(error.Invalid, parseRequestResume(
        wire,
        &state,
        &method,
        &token,
        &path,
        &version,
        &headers,
        &count,
    ));

    const response = "HTTP/1.1 200 OK\r\n\r\n";
    var rstate: Resume = .{ .offset = response.len + 1, .line_done = true };
    var rversion: Version = .@"1.0";
    var status: u16 = 0;
    var msg: ?[]const u8 = null;
    try testing.expectError(error.Invalid, parseResponseResume(
        response,
        &rstate,
        &rversion,
        &status,
        &msg,
        &headers,
        &count,
    ));

    // An inconsistent pair is refused too: `scanned` behind `offset` is what
    // distinguishes a fresh line from a resumed one, so a hand-built state
    // that gets it wrong would silently reparse a line from the wrong byte.
    var skewed: Resume = .{ .offset = 4, .scanned = 2, .line_done = true };
    try testing.expectError(error.Invalid, parseResponseResume(
        response,
        &skewed,
        &rversion,
        &status,
        &msg,
        &headers,
        &count,
    ));

    // And the boundary is inclusive: an offset EQUAL to the length is a
    // legitimate "everything so far is consumed, waiting for more".
    var edge: Resume = .{
        .offset = response.len,
        .scanned = response.len,
        .line_done = true,
    };
    try testing.expectError(error.Incomplete, parseResponseResume(
        response,
        &edge,
        &rversion,
        &status,
        &msg,
        &headers,
        &count,
    ));
}
