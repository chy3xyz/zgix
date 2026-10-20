//! Fuzzing the parser, with design rule 4 as the oracle.
//!
//! "It did not crash" is a weak property for a parser: the incident this
//! library exists because of (benchmark `19e34a3`) never crashed. A chunked
//! body was consumed as plain text for months, and which metric series died
//! depended on which byte offset the transport happened to split at. The bug
//! was that the parse was a function of the SEGMENTATION as well as the bytes.
//!
//! So the oracle is that property, stated directly: parse the same bytes three
//! ways — whole, split at one offset, and one byte per read — and require the
//! identical outcome. Rule 4 says "the identical event sequence", so all four
//! channels a caller can observe are compared, because each has its own way to
//! be segmentation-dependent:
//!
//!   * the verdict — status, version, framing, keep-alive, body length;
//!   * the bytes handed to the sink, compared on FAILURE as well as success.
//!     `streamExact64` delivers what it read before hitting EOF, so two
//!     segmentations can both return error.UnexpectedEof having written
//!     different bytes to the sink first — and that is the largest single
//!     bucket in the mutation search, not a corner;
//!   * the header/trailer callback sequence, whose slices point into the
//!     reader's buffer — the one piece of memory a whole-buffer fill and a
//!     byte-at-a-time fill lay out differently;
//!   * where the parse left the stream, because two parses can agree on every
//!     body byte and still leave the connection framed differently. That is
//!     ziglang/zig#25181's shape, and it only shows up on the NEXT response.
//!
//! Run modes:
//!   * `zig build fuzz` — the whole gate: every seed shape at every split
//!     position, plus a deterministic mutation loop over them. 0.15 s, so it
//!     runs on every slice.
//!   * `zig build fuzz --fuzz` — Zig's coverage-guided fuzzer. Does not build
//!     on Zig 0.16.0; see `mutation_iterations`.
//!
//! The oracle uses `std.testing` expectations rather than `assert`, on
//! purpose: assertions vanish in ReleaseFast, and a fuzz run that silently
//! checks nothing is worse than no fuzz run at all. Assertions are still used
//! for the harness's OWN invariants, which are ordinary internal state.

const std = @import("std");
const Io = std.Io;
const assert = std.debug.assert;
const parser = @import("parser.zig");
const SegmentedReader = @import("SegmentedReader.zig");

const t = std.testing;

/// Inputs are capped below the reader buffer on purpose. `error.HeadTooLong`
/// has two sources — a line longer than the reader's buffer, and a head bigger
/// than `max_head_bytes` — and only the second is a property of the bytes. Let
/// a line outrun the buffer and the three parses would legitimately disagree,
/// because a whole-buffer read and a byte-at-a-time read fill that buffer
/// differently. Keeping every input smaller than the buffer leaves the head
/// budget as the only source, and that one all three parses share.
const input_bytes_max = 1024;
const reader_bytes = 2048;
const body_bytes_max = 2048;
/// Room for the recorded header sequence: every header and trailer of a
/// 1 KiB response, length-prefixed, cannot exceed the response plus two bytes
/// per field.
const header_log_bytes = 4096;

comptime {
    // The relationships the paragraphs above depend on, asserted where they
    // are declared rather than trusted.
    assert(input_bytes_max < reader_bytes);
    // A body can never outrun the sink, so error.WriteFailed — which would
    // mean the HARNESS ran out of room, not that the parser rejected
    // anything — is unreachable. `expectSegmentationInvariant` refuses it
    // anyway, because this relationship lives here and the seeds live there.
    assert(input_bytes_max <= body_bytes_max);
    assert(input_bytes_max * 3 <= header_log_bytes);
}

/// The seed corpus: one shape per framing decision the parser owns, so the
/// fuzzer starts from bytes that already reach every branch instead of having
/// to rediscover "HTTP/1.1 " from noise.
///
/// These are also replayed EXACTLY by the corpus test below. As raw fuzzer
/// seeds they are approximate — `Smith` reads structure out of the input, so
/// it will not see these as one whole wire — which is why the exact replay is
/// a separate, ordinary test rather than something inferred from a fuzz run.
const corpus: []const []const u8 = &.{
    // content-length, the ordinary case.
    "HTTP/1.1 200 OK\r\ncontent-length: 5\r\n\r\nhello",
    // chunked, with an extension and a trailer: the shape that broke.
    "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" ++
        "6\r\nmetric\r\nb;ext=1\r\n_total 42.5\r\n0\r\nx-t: 1\r\n\r\n",
    // Bodyless: a body must not be read even though framing offers one.
    "HTTP/1.1 204 No Content\r\ncontent-length: 7\r\n\r\n",
    "HTTP/1.1 304 Not Modified\r\n\r\n",
    // Close-delimited: no framing information at all.
    "HTTP/1.0 200 OK\r\n\r\nrest of the stream",
    // Transfer-Encoding beats Content-Length (RFC 9112 6.3), and disagreeing
    // duplicate lengths are the smuggling primitive.
    "HTTP/1.1 200 OK\r\ncontent-length: 4\r\ntransfer-encoding: chunked\r\n\r\n2\r\nab\r\n0\r\n\r\n",
    "HTTP/1.1 200 OK\r\ncontent-length: 4\r\ncontent-length: 5\r\n\r\n",
    // content-encoding decides whether a body may be delivered at all, so it
    // is a framing shape: refused when a body follows, ignored when the
    // status is bodyless, and `identity` never refused.
    "HTTP/1.1 200 OK\r\ncontent-encoding: gzip\r\ncontent-length: 4\r\n\r\nabcd",
    "HTTP/1.1 200 OK\r\ncontent-encoding: identity\r\ncontent-length: 2\r\n\r\nhi",
    "HTTP/1.1 204 No Content\r\ncontent-encoding: gzip\r\n\r\n",
    // Keep-alive bookkeeping, both directions.
    "HTTP/1.1 301 Moved\r\nconnection: close\r\ncontent-length: 0\r\n\r\n",
    "HTTP/1.0 200 OK\r\nconnection: keep-alive\r\ncontent-length: 2\r\n\r\nhi",
    // Malformed trailers, both shapes: a field with no name and a line with
    // no colon. The head refuses both, so the trailer section must too.
    "HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n2\r\nab\r\n0\r\n: v\r\n\r\n",
    "HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n2\r\nab\r\n0\r\ngarbage\r\n\r\n",
    // Truncated mid-body and mid-head: the EOF paths.
    "HTTP/1.1 200 OK\r\ncontent-length: 99\r\n\r\nshort",
    "HTTP/1.1 200 O",
};

/// The header/trailer callback sequence, recorded.
///
/// The parser's slices point into the reader's buffer and die when the body
/// starts streaming (`parser.HeaderFn` says so), so the bytes are copied — and
/// copying them is exactly the point, because that buffer is filled
/// differently under different segmentation.
const HeaderLog = struct {
    bytes: [header_log_bytes]u8 = undefined,
    len: usize = 0,
    /// Set if the log filled. Compared like everything else: a difference in
    /// where two parses overflowed is still a difference.
    overflowed: bool = false,
    /// Set if the parser ever delivered a field with an empty name. RECORDED
    /// rather than asserted: this is a property of the parser's output, not
    /// of the harness, and it is the exact defect this file found in the
    /// trailer section. An assertion would panic instead of failing through
    /// the oracle with its replay line, and would vanish entirely from the
    /// ReleaseFast build a long mutation run wants.
    saw_empty_name: bool = false,

    fn record(ctx: ?*anyopaque, name: []const u8, value: []const u8) void {
        const self: *HeaderLog = @ptrCast(@alignCast(ctx.?));
        if (name.len == 0) self.saw_empty_name = true;

        self.appendField(name);
        self.appendField(value);
    }

    /// Length-prefixed, never delimited: a fuzzed header value may contain any
    /// byte including whatever delimiter was chosen, and a delimited encoding
    /// would let two different sequences encode identically and compare equal.
    fn appendField(self: *HeaderLog, field: []const u8) void {
        assert(field.len <= input_bytes_max);

        var prefix: [2]u8 = undefined;
        std.mem.writeInt(u16, &prefix, @intCast(field.len), .little);
        self.appendBytes(&prefix);
        self.appendBytes(field);
    }

    fn appendBytes(self: *HeaderLog, bytes: []const u8) void {
        assert(self.len <= self.bytes.len);

        if (self.len + bytes.len > self.bytes.len) {
            self.overflowed = true;
            return;
        }
        @memcpy(self.bytes[self.len..][0..bytes.len], bytes);
        self.len += bytes.len;
    }

    fn recorded(self: *const HeaderLog) []const u8 {
        assert(self.len <= self.bytes.len);
        return self.bytes[0..self.len];
    }
};

/// What one parse produced. `body` points into the `Parse` that produced it.
///
/// The sink's contents sit OUTSIDE the verdict union on purpose: a failed
/// parse has usually already written to the sink, and those bytes are as much
/// a part of what the caller observed as the error value is.
const Outcome = struct {
    body: []const u8,
    verdict: Verdict,

    const Verdict = union(enum) {
        failed: parser.Error,
        parsed: Parsed,
    };

    const Parsed = struct {
        status: u16,
        http11: bool,
        /// What the head said, before a close-delimited body overrode it.
        /// `Head` is public, so this is a channel a caller reads directly —
        /// and it is masked by `keep_alive` in exactly the one framing where
        /// the parser overrides it.
        head_keep_alive: bool,
        /// The exchange's verdict, which is the head's unless the body ran to
        /// connection close.
        keep_alive: bool,
        chunked: bool,
        content_length: ?u64,
        len: u64,
        /// The two wire costs, checked here for the same reason everything
        /// else is: they are what a caller counting bytes off the transport
        /// reports, and a count that depended on how the wire was segmented
        /// would be rule 4's exact prohibition in a number nobody looks at.
        head_len: usize,
        wire_len: u64,
    };
};

/// One parse's buffers and everything it observed, kept together so a caller
/// can hold three of them side by side and compare.
const Parse = struct {
    reader_buf: [reader_bytes]u8 = undefined,
    body_buf: [body_bytes_max]u8 = undefined,
    headers: HeaderLog = .{},
    /// Stream offset reached, set on every exit path including the errors.
    consumed: usize = 0,

    fn run(
        p: *Parse,
        wire: []const u8,
        method: std.http.Method,
        segment_bytes_max: usize,
        boundary: ?usize,
        max_head_bytes: usize,
    ) Outcome {
        // Checked here, where the wire enters, rather than three frames down
        // in HeaderLog: `input_bytes_max` is the bound every buffer in this
        // file is sized against, and it is smaller than either of them.
        assert(wire.len <= input_bytes_max);
        assert(wire.len <= p.body_buf.len);
        assert(wire.len < p.reader_buf.len);

        var reader = SegmentedReader.init(wire, segment_bytes_max, boundary, &p.reader_buf);
        defer p.consumed = reader.consumed();

        var body_writer: Io.Writer = .fixed(&p.body_buf);
        const opts: parser.HeadOptions = .{
            .on_header = HeaderLog.record,
            .ctx = &p.headers,
            .max_head_bytes = max_head_bytes,
        };

        const head = parser.parseHead(&reader.interface, opts) catch |err| {
            return .{ .body = body_writer.buffered(), .verdict = .{ .failed = err } };
        };
        const body = parser.streamBody(&reader.interface, head, method, &body_writer, opts) catch |err| {
            return .{ .body = body_writer.buffered(), .verdict = .{ .failed = err } };
        };
        return .{ .body = body_writer.buffered(), .verdict = .{ .parsed = .{
            .status = head.status,
            .http11 = head.http11,
            .head_keep_alive = head.keep_alive,
            .keep_alive = body.keep_alive,
            .chunked = head.chunked,
            .content_length = head.content_length,
            .len = body.len,
            .head_len = head.head_len,
            .wire_len = body.wire_len,
        } } };
    }
};

/// The oracle. Parses `wire` three ways and requires one answer.
///
/// `split` must be a REAL two-segment split: `1 <= split <= wire.len - 1`.
/// Offset 0 has nothing before it and offset `wire.len` nothing after, so
/// either one runs the whole-input parse a second time rather than testing a
/// split at all. An earlier draft admitted both and spent 95% of its budget
/// comparing the whole-input parse with itself while reporting a pass; the
/// bound is asserted here so that a caller drawing splits from the wrong
/// range fails loudly instead of quietly testing less.
///
/// A wire shorter than two bytes has no split to make, and passes `split = 0`.
fn expectSegmentationInvariant(
    wire: []const u8,
    method: std.http.Method,
    split: usize,
    max_head_bytes: usize,
) !void {
    assert(max_head_bytes > 0);
    if (wire.len >= 2) {
        assert(split >= 1);
        assert(split < wire.len);
    } else {
        // Negative space: a wire this short has no split to make, and every
        // caller is expected to have said so rather than to have passed an
        // offset that would be silently ignored.
        assert(split == 0);
    }

    var whole: Parse = .{};
    var at_split: Parse = .{};
    var byte_at_a_time: Parse = .{};

    const segment_bytes_max = @max(wire.len, 1);
    const boundary: ?usize = if (wire.len >= 2) split else null;

    const a = whole.run(wire, method, segment_bytes_max, null, max_head_bytes);
    const b = at_split.run(wire, method, segment_bytes_max, boundary, max_head_bytes);
    const c = byte_at_a_time.run(wire, method, 1, null, max_head_bytes);

    // error.WriteFailed can only come from the sink, and the sink is this
    // harness's own buffer — so it means the HARNESS ran out of room, not that
    // the parser rejected anything. It is also agreement-preserving: all three
    // parses would report it and the oracle would pass having checked nothing.
    if (a.verdict == .failed) try t.expect(a.verdict.failed != parser.Error.WriteFailed);

    try expectSameOutcome(&a, &b);
    try expectSameOutcome(&a, &c);
    // A field with no name is what `parseHead` refuses outright, so no
    // segmentation of any input may produce one anywhere — head or trailer.
    try t.expect(!whole.headers.saw_empty_name);

    try expectSameHeaders(&whole.headers, &at_split.headers);
    try expectSameHeaders(&whole.headers, &byte_at_a_time.headers);
    try t.expectEqual(whole.consumed, at_split.consumed);
    try t.expectEqual(whole.consumed, byte_at_a_time.consumed);

    try expectCoherent(&a, method);
}

/// Whatever the three agreed on must also be internally coherent. These hold
/// for every input, which is what makes them worth checking here rather than
/// in a test with one known answer.
fn expectCoherent(outcome: *const Outcome, method: std.http.Method) !void {
    switch (outcome.verdict) {
        .failed => {},
        .parsed => |p| {
            try t.expect(p.status >= 100);
            try t.expect(p.status <= 999);
            // The sink got exactly as many bytes as the parse claims it
            // delivered — a chunked decoder that miscounts fails here even
            // when every segmentation miscounts alike.
            try t.expectEqual(p.len, @as(u64, outcome.body.len));
            // A head is at minimum a status line and the blank line that ends
            // it, so a parse that succeeded consumed bytes to do it.
            try t.expect(p.head_len > 0);
            // Chunk framing is the ONLY thing that can sit between the decoded
            // body and the wire, so the gap is exactly as wide as the framing:
            // zero without it, and never negative with it.
            try t.expect(p.wire_len >= p.len);
            if (!p.chunked) try t.expectEqual(p.len, p.wire_len);
            if (p.chunked and p.len > 0) try t.expect(p.wire_len > p.len);
            // keep_alive is the head's verdict unless a close-delimited body
            // overrode it, and that override only ever goes one way.
            if (p.keep_alive) try t.expect(p.head_keep_alive);
            // Bodyless is structural (rule 2): no framing header can put a
            // body on a HEAD reply or a 1xx/204/304.
            if (method == .HEAD) try t.expectEqual(@as(u64, 0), p.len);
            if (p.status == 204 or p.status == 304) try t.expectEqual(@as(u64, 0), p.len);
            if (p.status / 100 == 1) try t.expectEqual(@as(u64, 0), p.len);
        },
    }
}

/// Whether two parses of the same bytes agree in everything a caller can
/// observe. A pure predicate, so the vacuity test can exercise the real
/// comparison without a deliberately-failing expectation printing a diff into
/// an otherwise green test run.
fn sameOutcome(a: *const Outcome, b: *const Outcome) bool {
    // The sink first, and for both variants. On the error paths the parser has
    // usually already delivered bytes — error.UnexpectedEof after a partial
    // content-length body is 7 of every 20 inputs in the mutation census — and
    // an oracle that compared only the error value would call two different
    // deliveries identical.
    if (!std.mem.eql(u8, a.body, b.body)) return false;

    switch (a.verdict) {
        .failed => |err_a| {
            if (b.verdict != .failed) return false;
            return err_a == b.verdict.failed;
        },
        .parsed => |p_a| {
            if (b.verdict != .parsed) return false;
            const p_b = b.verdict.parsed;
            if (p_a.status != p_b.status) return false;
            if (p_a.http11 != p_b.http11) return false;
            if (p_a.head_keep_alive != p_b.head_keep_alive) return false;
            if (p_a.keep_alive != p_b.keep_alive) return false;
            if (p_a.chunked != p_b.chunked) return false;
            if (p_a.content_length != p_b.content_length) return false;
            if (p_a.head_len != p_b.head_len) return false;
            if (p_a.wire_len != p_b.wire_len) return false;
            return p_a.len == p_b.len;
        },
    }
}

fn expectSameOutcome(a: *const Outcome, b: *const Outcome) !void {
    if (sameOutcome(a, b)) return;

    // Both sides in full: a segmentation bug is not debuggable from one of
    // them, and the fuzzer's own report is a byte string, not a parse.
    describeOutcome("whole   ", a);
    describeOutcome("segments", b);
    return error.SegmentationDependentParse;
}

fn sameHeaders(a: *const HeaderLog, b: *const HeaderLog) bool {
    assert(a.len <= a.bytes.len);
    assert(b.len <= b.bytes.len);

    if (a.saw_empty_name != b.saw_empty_name) return false;
    if (a.overflowed != b.overflowed) return false;
    return std.mem.eql(u8, a.recorded(), b.recorded());
}

fn expectSameHeaders(a: *const HeaderLog, b: *const HeaderLog) !void {
    if (sameHeaders(a, b)) return;

    describeHeaders("whole   ", a);
    describeHeaders("segments", b);
    return error.SegmentationDependentHeaders;
}

fn describeHeaders(label: []const u8, log: *const HeaderLog) void {
    std.debug.print(
        "  {s} headers (overflowed={}, empty_name={}):",
        .{ label, log.overflowed, log.saw_empty_name },
    );
    // Hex, for the same reason describeWire uses it: these are fuzzed bytes.
    for (log.recorded()) |byte| std.debug.print(" {x:0>2}", .{byte});
    std.debug.print("\n", .{});
}

fn describeOutcome(label: []const u8, outcome: *const Outcome) void {
    switch (outcome.verdict) {
        .failed => |err| std.debug.print("  {s}: {s}", .{ label, @errorName(err) }),
        .parsed => |p| std.debug.print(
            "  {s}: status={d} http11={} head_keep_alive={} keep_alive={} chunked={} content_length={?d} len={d} head_len={d} wire_len={d}",
            .{ label, p.status, p.http11, p.head_keep_alive, p.keep_alive, p.chunked, p.content_length, p.len, p.head_len, p.wire_len },
        ),
    }
    // Hex, never `{s}`: this is a fuzzed body and the terminal is not asked to
    // interpret arbitrary bytes, control sequences included.
    std.debug.print(" body:", .{});
    for (outcome.body) |byte| std.debug.print(" {x:0>2}", .{byte});
    std.debug.print("\n", .{});
}

// ---------------------------------------------------------------------------
// the mutator

/// Bytes worth mutating toward: the punctuation HTTP framing is built from,
/// plus the hex digits a chunk size is written in. A uniform random byte is a
/// CRLF one time in 32768, so a uniform mutator spends its entire budget
/// failing at the status line and never reaches a body at all.
const interesting_bytes = "\r\n: ;,\t0123456789abcdefxHTTP/.";

/// Iterations of the deterministic mutation loop, and the seed it runs from.
///
/// This loop exists because `zig build fuzz --fuzz` does not build on Zig
/// 0.16.0: the bundled compiler/test_runner.zig fails to compile under -ffuzz
/// with a StackTrace type mismatch at test_runner.zig:566. zoxy hit the
/// identical wall (its src/config.zig records it). Waiting for the toolchain
/// would leave the parser with its hand-written shapes and nothing else, so
/// this does the job a mutator does — derive inputs from the seeds and push
/// each through the same oracle — minus the coverage feedback.
///
/// Deterministic on purpose: a fixed seed means a failure reproduces from the
/// iteration number printed beside it, with no corpus file to lose. Raise the
/// count to search harder; change the seed to search elsewhere.
const mutation_iterations = 20_000;
const mutation_seed = 0x7a75726c_66757a7a; // "zurl" "fuzz"

/// One edit.
const Edit = enum { replace, truncate, insert, delete, splice };

/// Applies one to four edits to a copy of `source`. The returned slice borrows
/// `out` and is valid until the next call with the same buffer.
fn mutate(rand: std.Random, source: []const u8, out: *[input_bytes_max]u8) []u8 {
    assert(source.len <= out.len);

    // Explicitly usize: `out.len` is comptime-known, so inference narrows this
    // to the u11 that holds 1024 and every later index arithmetic fails.
    var len: usize = source.len;
    @memcpy(out[0..len], source);

    var edits = rand.intRangeAtMost(u8, 1, 4);
    while (edits > 0) : (edits -= 1) {
        assert(len <= out.len);
        switch (rand.enumValue(Edit)) {
            .replace => {
                if (len == 0) continue;
                const index = rand.uintLessThan(usize, len);
                out[index] = if (rand.boolean())
                    interesting_bytes[rand.uintLessThan(usize, interesting_bytes.len)]
                else
                    rand.int(u8);
            },
            // Every prefix of a well-formed response must end in an error and
            // never in a hang, so truncation is its own edit rather than a
            // side effect of the others.
            .truncate => len = rand.uintAtMost(usize, len),
            .insert => {
                if (len >= out.len) continue;
                const index = rand.uintAtMost(usize, len);
                std.mem.copyBackwards(u8, out[index + 1 .. len + 1], out[index..len]);
                out[index] = interesting_bytes[rand.uintLessThan(usize, interesting_bytes.len)];
                len += 1;
            },
            .delete => {
                if (len == 0) continue;
                const index = rand.uintLessThan(usize, len);
                std.mem.copyForwards(u8, out[index .. len - 1], out[index + 1 .. len]);
                len -= 1;
            },
            // Splicing is how a chunked head meets a content-length body
            // without the mutator having to spell either from scratch.
            .splice => {
                const other = corpus[rand.uintLessThan(usize, corpus.len)];
                if (other.len == 0 or len == 0) continue;
                const take = rand.intRangeAtMost(usize, 1, @min(other.len, len));
                const from = rand.uintAtMost(usize, other.len - take);
                const at = rand.uintAtMost(usize, len - take);
                assert(at + take <= len);
                assert(from + take <= other.len);
                @memcpy(out[at..][0..take], other[from..][0..take]);
            },
        }
    }

    assert(len <= out.len);
    return out[0..len];
}

fn describeWire(wire: []const u8) void {
    std.debug.print("  wire ({d} bytes):", .{wire.len});
    for (wire) |byte| std.debug.print(" {x:0>2}", .{byte});
    std.debug.print("\n", .{});
}

// ---------------------------------------------------------------------------
// tests

test "fuzz: the parse is a function of the bytes, never of the segmentation" {
    try std.testing.fuzz({}, fuzzOne, .{ .corpus = corpus });
}

fn fuzzOne(context: void, smith: *std.testing.Smith) !void {
    _ = context;

    var wire_buf: [input_bytes_max]u8 = undefined;
    const wire_len = smith.slice(&wire_buf);
    assert(wire_len <= wire_buf.len);
    const wire = wire_buf[0..wire_len];

    // HEAD is half the draw because it is the whole of rule 2's bodyless
    // half, and a uniform method choice would spend most of its budget on GET
    // rediscovering the same paths.
    const method: std.http.Method = if (smith.value(bool)) .HEAD else .GET;
    const split = if (wire.len >= 2) 1 + smith.index(wire.len - 1) else 0;
    const max_head_bytes = smith.valueRangeAtMost(u32, 16, 2048);

    try expectSegmentationInvariant(wire, method, split, max_head_bytes);
}

test "fuzz corpus: every seed holds the invariance at every split position" {
    // The exact replay the fuzzer's own seeding cannot promise, and the gate
    // `zig build fuzz` runs without a fuzzer: every corpus shape, every split
    // point in it, both methods, under two head budgets.
    for (corpus) |wire| {
        try t.expect(wire.len <= input_bytes_max);
        // Every seed is long enough for a real split to exist, or the loop
        // below would run zero times and the seed would go untested.
        try t.expect(wire.len >= 2);
        for ([_]std.http.Method{ .GET, .HEAD }) |method| {
            // One budget no head here can exhaust, and one most of them do
            // (the truncated seed runs out of bytes before it runs out of
            // budget). Both must be segmentation-invariant — "this head was
            // too long" is a verdict on the bytes, not on their arrival.
            for ([_]usize{ 64 * 1024, 24 }) |max_head_bytes| {
                var split: usize = 1;
                while (split < wire.len) : (split += 1) {
                    try expectSegmentationInvariant(wire, method, split, max_head_bytes);
                }
            }
        }
    }
}

test "fuzz: mutated seeds hold the invariance too" {
    var prng: std.Random.DefaultPrng = .init(mutation_seed);
    const rand = prng.random();
    var wire_buf: [input_bytes_max]u8 = undefined;

    for (0..mutation_iterations) |iteration| {
        const seed = corpus[rand.uintLessThan(usize, corpus.len)];
        const wire = mutate(rand, seed, &wire_buf);
        const method: std.http.Method = if (rand.boolean()) .HEAD else .GET;
        // Drawn from 1..len-1, so every draw is a real two-segment split
        // rather than the whole-input parse under another name.
        const split = if (wire.len >= 2) rand.intRangeAtMost(usize, 1, wire.len - 1) else 0;
        // Fuzz the head budget too. A census of an earlier draft that used the
        // 64 KiB default reached error.HeadTooLong zero times in 20,000
        // mutations — with inputs capped at 1 KiB the budget could never run
        // out, so the branch that stops an endless-header server was untested
        // by the very loop meant to test it.
        const max_head_bytes = rand.intRangeAtMost(usize, 16, 2048);

        expectSegmentationInvariant(wire, method, split, max_head_bytes) catch |err| {
            // Everything needed to replay it, on the spot: the loop is
            // deterministic, but reading the bytes back off a seed and an
            // iteration count is not something a person should have to do.
            std.debug.print(
                "\nmutation iteration {d} (seed 0x{x}, method {s}, split {d}, budget {d}) failed:\n",
                .{ iteration, mutation_seed, @tagName(method), split, max_head_bytes },
            );
            describeWire(wire);
            return err;
        };
    }
}

test "fuzz: the oracle is not vacuous" {
    // Proof that the comparison can fail, and specifically that it compares
    // body CONTENT. Two responses identical in status, framing and length,
    // differing only in the bytes delivered, must not compare equal — that is
    // the difference the cAdvisor bug produced, and a comparison that only
    // checked lengths would have shrugged at it. If someone weakens
    // `sameOutcome`, this test stops failing and says so.
    var first: Parse = .{};
    var second: Parse = .{};

    const a = first.run("HTTP/1.1 200 OK\r\ncontent-length: 5\r\n\r\nhello", .GET, 64, null, 4096);
    const b = second.run("HTTP/1.1 200 OK\r\ncontent-length: 5\r\n\r\nworld", .GET, 64, null, 4096);
    try t.expect(a.verdict == .parsed);
    try t.expect(b.verdict == .parsed);
    try t.expectEqual(a.verdict.parsed.len, b.verdict.parsed.len);
    try t.expect(!sameOutcome(&a, &b));

    // A shape difference is caught too: the same head with the body one byte
    // short is an error, not a shorter success.
    var truncated: Parse = .{};
    const c = truncated.run("HTTP/1.1 200 OK\r\ncontent-length: 5\r\n\r\nhell", .GET, 64, null, 4096);
    try t.expectEqual(parser.Error.UnexpectedEof, c.verdict.failed);
    try t.expect(!sameOutcome(&a, &c));

    // And it says yes when it should: a parse compared with itself agrees.
    try t.expect(sameOutcome(&a, &a));
}

test "fuzz: two failures that delivered different bytes are not the same outcome" {
    // The hole this closes. Both parses end in error.UnexpectedEof — the
    // largest bucket in the mutation census — having written five different
    // bytes to the sink on the way. An oracle that compared only the error
    // value would call these identical, and would therefore be blind on the
    // majority of everything it tests.
    var first: Parse = .{};
    var second: Parse = .{};

    const a = first.run("HTTP/1.1 200 OK\r\ncontent-length: 9\r\n\r\nhello", .GET, 64, null, 4096);
    const b = second.run("HTTP/1.1 200 OK\r\ncontent-length: 9\r\n\r\nworld", .GET, 64, null, 4096);

    try t.expectEqual(parser.Error.UnexpectedEof, a.verdict.failed);
    try t.expectEqual(parser.Error.UnexpectedEof, b.verdict.failed);
    // The partial bodies really did reach the sink, and really do differ.
    try t.expectEqualStrings("hello", a.body);
    try t.expectEqualStrings("world", b.body);
    try t.expect(!sameOutcome(&a, &b));
}

test "fuzz: the header sequence is recorded, compared, and can differ" {
    // The header channel needs its own vacuity proof: a log that silently
    // recorded nothing would compare equal forever.
    var with_headers: Parse = .{};
    var without: Parse = .{};

    const wire = "HTTP/1.1 200 OK\r\nx-a: 1\r\ncontent-length: 0\r\n\r\n";
    _ = with_headers.run(wire, .GET, wire.len, null, 4096);
    try t.expect(with_headers.headers.len > 0);
    try t.expect(!with_headers.headers.overflowed);

    const bare = "HTTP/1.1 200 OK\r\n\r\n";
    _ = without.run(bare, .GET, bare.len, null, 4096);
    try t.expectEqual(@as(usize, 0), without.headers.len);
    try t.expect(!sameHeaders(&with_headers.headers, &without.headers));
    try t.expect(sameHeaders(&with_headers.headers, &with_headers.headers));

    // Trailers arrive through the same callback, so a chunked body's trailer
    // must show up in the log too — the branch a whole-response test misses.
    var trailered: Parse = .{};
    const chunked = "HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n2\r\nab\r\n0\r\nx-t: v\r\n\r\n";
    _ = trailered.run(chunked, .GET, chunked.len, null, 4096);
    try t.expect(std.mem.indexOf(u8, trailered.headers.recorded(), "x-t") != null);
}

test "fuzz: the consumed offset is recorded and distinguishes framings" {
    // The 25181 shape: a 204 must leave the next response untouched, and the
    // proof is where the parse stopped, not what the body contained.
    var parse: Parse = .{};
    const wire = "HTTP/1.1 204 No Content\r\ncontent-length: 7\r\n\r\nnextone";
    const outcome = parse.run(wire, .GET, wire.len, null, 4096);

    try t.expect(outcome.verdict == .parsed);
    try t.expectEqual(@as(u64, 0), outcome.verdict.parsed.len);
    // Stopped at the blank line, with "nextone" still unread.
    try t.expectEqual(wire.len - "nextone".len, parse.consumed);
}
