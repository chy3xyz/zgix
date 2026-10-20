//! The head-parser comparison: zoxy-io/hparse's SIMD scanner against the
//! hand-rolled `Io.Reader` one it replaced.
//!
//! `zig build bench-head -Doptimize=ReleaseFast`. This began as an opt-in
//! experiment behind `-Dhparse`, asking whether hparse was worth a dependency
//! in a package whose whole point is being a leaf. The answer came back yes
//! once the resume cursor landed, and `src/parser.zig` runs on hparse now, so
//! the gate is gone. The harness stays: the `segmented` column below is where
//! the adoption was supposed to pay, and rule 8 says the line that shows it is
//! part of the change.
//!
//! The `zurl` column is therefore a HISTORICAL BASELINE — the scanner as it
//! was before adoption, kept here to measure against. It is not what
//! src/parser.zig does today.
//!
//! Prints numbers and asserts nothing about them (rule 8) — but it DOES
//! assert that the two parsers agree, because a faster parser that answers
//! differently is not a faster parser. docs/RESEARCH.md carries the verdict.
//!
//! Two delivery modes, because they are different questions:
//!
//!   whole      — the entire head already in the reader's buffer. The best
//!                case for hparse, and what a microbenchmark usually shows.
//!   segmented  — the head arriving in transport-sized pieces, which is what
//!                a socket actually does. This column is the whole story: the
//!                one-shot `parseResponse` re-parses from byte zero on every
//!                segment, which is the O(N²) blowup docs/RESEARCH.md
//!                measured at 250,702 ns for a 30-header head arriving one
//!                byte at a time. `parseResponseResume` is what fixed it, and
//!                what src/parser.zig calls.

const std = @import("std");
const zurl = @import("zurl");
const hparse = @import("hparse");
const Io = std.Io;
const assert = std.debug.assert;

/// hparse needs the header array up front and fails with TooManyHeaders past
/// it — a bound zurl's callback API does not have and would have to grow.
const headers_max = 64;

/// How many consecutive zero-byte fills to tolerate before calling the stream
/// dead. std says `fillMore` may add nothing without that being end-of-stream,
/// so this is what turns "eventually terminates" into a claim.
const stall_max = 16;

// ---------------------------------------------------------------------------
// the prototype: hparse behind zurl's parseHead signature

fn hparseHead(r: *Io.Reader, opts: zurl.HeadOptions) !zurl.Head {
    var headers: [headers_max]hparse.Header = undefined;
    var version: hparse.Version = .@"1.1";
    var status_code: u16 = 0;
    var status_msg: ?[]const u8 = null;
    var header_count: usize = 0;

    // The retry loop hparse's contiguous-slice API requires. Every pass
    // re-parses everything buffered so far.
    //
    // lint:unbounded-ok — `fillMore` either adds bytes, or the head does not
    // fit the buffer (HeadTooLong), or the stream stalls `stall_max` times in
    // a row. std documents fillMore as able to add zero bytes without that
    // being end-of-stream, so the stall counter is the actual bound.
    var stalled: usize = 0;
    const consumed = while (true) {
        const have = r.buffered();
        if (hparse.parseResponse(
            have,
            &version,
            &status_code,
            &status_msg,
            &headers,
            &header_count,
        )) |n| {
            break n;
        } else |err| switch (err) {
            error.Incomplete => {
                if (have.len >= opts.max_head_bytes) return error.HeadTooLong;
                // The guard that actually fires. `have` can never exceed the
                // reader's buffer, so the budget check above is unreachable
                // for any sane buffer — and hparse has no equivalent of
                // takeDelimiterInclusive's StreamTooLong, so without this a
                // head bigger than the buffer spins instead of being refused.
                // That is a capability gap in the contiguous-slice API, not a
                // bench detail: rule 7 says overlong input is refused whole.
                if (have.len >= r.buffer.len) return error.HeadTooLong;
                r.fillMore() catch |fill_err| switch (fill_err) {
                    error.EndOfStream => return error.UnexpectedEof,
                    error.ReadFailed => return error.ReadFailed,
                };
                if (r.bufferedLen() == have.len) {
                    stalled += 1;
                    if (stalled > stall_max) return error.ReadFailed;
                } else {
                    stalled = 0;
                }
            },
            error.Invalid => return error.MalformedHeader,
            // A failure mode zurl does not have: the caller's fixed array.
            error.TooManyHeaders => return error.HeadTooLong,
        }
    };

    // Slices point into the reader's buffer, so nothing is tossed until the
    // framing pass is done with them.
    const head = try extractFraming(headers[0..header_count], version, status_code, consumed, opts);
    r.toss(consumed);
    return head;
}

/// The same integration, done the way anyone would do it once they saw the
/// segmented numbers: scan for the terminator first and hand hparse a slice
/// it can parse in ONE pass, instead of re-parsing on every arriving segment.
///
/// This is hparse's strongest form and the one the verdict has to beat. It
/// trades the quadratic re-parse for an extra linear scan of the head — which
/// zurl does not pay at all, because finding the line ends IS its parse.
fn hparseHeadScan(r: *Io.Reader, opts: zurl.HeadOptions) !zurl.Head {
    var headers: [headers_max]hparse.Header = undefined;
    var version: hparse.Version = .@"1.1";
    var status_code: u16 = 0;
    var status_msg: ?[]const u8 = null;
    var header_count: usize = 0;

    // Resume the search three bytes back so a terminator split across two
    // fills is still found.
    // lint:unbounded-ok — the same bound as the loop above: the terminator is
    // found, the head outgrows the buffer, the stream ends, or it stalls.
    var searched: usize = 0;
    var stalled: usize = 0;
    const head_end = while (true) {
        const have = r.buffered();
        const from = if (searched >= 3) searched - 3 else 0;
        if (std.mem.indexOfPos(u8, have, from, "\r\n\r\n")) |at| break at + 4;
        searched = have.len;
        if (have.len >= opts.max_head_bytes) return error.HeadTooLong;
        if (have.len >= r.buffer.len) return error.HeadTooLong;
        r.fillMore() catch |fill_err| switch (fill_err) {
            error.EndOfStream => return error.UnexpectedEof,
            error.ReadFailed => return error.ReadFailed,
        };
        if (r.bufferedLen() == have.len) {
            stalled += 1;
            if (stalled > stall_max) return error.ReadFailed;
        } else {
            stalled = 0;
        }
    };

    const consumed = hparse.parseResponse(
        r.buffered()[0..head_end],
        &version,
        &status_code,
        &status_msg,
        &headers,
        &header_count,
    ) catch |err| switch (err) {
        error.Incomplete, error.Invalid => return error.MalformedHeader,
        error.TooManyHeaders => return error.HeadTooLong,
    };
    // An error, not an assertion: ReleaseFast is the only mode this is ever
    // run in, and that is exactly where assertions are gone.
    if (consumed != head_end) return error.ScanConsumedWrong;

    const head = try extractFraming(headers[0..header_count], version, status_code, consumed, opts);
    r.toss(consumed);
    return head;
}

/// The framing decisions hparse does not make and zurl must (rule 2). Shared
/// by both integrations so the comparison is not measuring two different
/// amounts of work.
fn extractFraming(
    headers: []const hparse.Header,
    version: hparse.Version,
    status_code: u16,
    head_len: usize,
    opts: zurl.HeadOptions,
) !zurl.Head {
    var head: zurl.Head = .{
        .status = status_code,
        .head_len = head_len,
        .http11 = version == .@"1.1",
        .keep_alive = version == .@"1.1",
    };
    for (headers) |header| {
        const value = std.mem.trim(u8, header.value, " \t");
        if (std.ascii.eqlIgnoreCase(header.key, "content-length")) {
            const n = std.fmt.parseInt(u64, value, 10) catch return error.MalformedHeader;
            if (head.content_length) |prev| {
                if (prev != n) return error.MalformedHeader;
            }
            head.content_length = n;
        } else if (std.ascii.eqlIgnoreCase(header.key, "transfer-encoding")) {
            if (containsToken(value, "chunked")) head.chunked = true;
        } else if (std.ascii.eqlIgnoreCase(header.key, "connection")) {
            if (containsToken(value, "close")) {
                head.keep_alive = false;
            } else if (containsToken(value, "keep-alive")) {
                head.keep_alive = true;
            }
        }
        if (opts.on_header) |f| f(opts.ctx, header.key, value);
    }
    return head;
}

fn containsToken(value: []const u8, token: []const u8) bool {
    var it = std.mem.splitScalar(u8, value, ',');
    while (it.next()) |part| {
        if (std.ascii.eqlIgnoreCase(std.mem.trim(u8, part, " \t"), token)) return true;
    }
    return false;
}

// ---------------------------------------------------------------------------
// a reader that hands over the stream in fixed-size pieces

const Segmented = struct {
    data: []const u8,
    pos: usize = 0,
    segment: usize,
    interface: Io.Reader,

    fn init(data: []const u8, segment: usize, buffer: []u8) Segmented {
        assert(segment > 0);
        assert(buffer.len > 0);
        return .{
            .data = data,
            .segment = segment,
            .interface = .{
                .vtable = &.{ .stream = stream },
                .buffer = buffer,
                .seek = 0,
                .end = 0,
            },
        };
    }

    fn stream(r: *Io.Reader, w: *Io.Writer, limit: Io.Limit) Io.Reader.StreamError!usize {
        const s: *Segmented = @alignCast(@fieldParentPtr("interface", r));
        if (s.pos >= s.data.len) return error.EndOfStream;
        const n = limit.minInt(@min(s.segment, s.data.len - s.pos));
        if (n == 0) return error.EndOfStream;
        try w.writeAll(s.data[s.pos..][0..n]);
        s.pos += n;
        return n;
    }
};

// ---------------------------------------------------------------------------
// shapes

const Shape = struct { name: []const u8, wire: []const u8 };

const small_cl = "HTTP/1.1 200 OK\r\n" ++
    "server: bench\r\ndate: Sun, 23 Aug 2026 12:00:00 GMT\r\n" ++
    "content-type: application/json\r\ncache-control: no-store\r\n" ++
    "x-request-id: 0123456789abcdef\r\nvary: accept-encoding\r\n" ++
    "etag: \"abc123\"\r\ncontent-length: 128\r\n\r\n";

const zrk_1k = "HTTP/1.1 200 OK\r\nserver: nginx\r\ncontent-length: 1024\r\n\r\n";

const many_headers = blk: {
    var acc: []const u8 = "HTTP/1.1 200 OK\r\n";
    for (0..30) |i| {
        acc = acc ++ std.fmt.comptimePrint("x-header-{d}: some reasonably long value here\r\n", .{i});
    }
    break :blk acc ++ "content-length: 64\r\n\r\n";
};

/// Shapes that can actually DISCRIMINATE the framing decisions rule 2 says the
/// library owns. Without these, "both parsers agree" is a tautology: status
/// 200, HTTP/1.1, keep-alive and not-chunked are constants across the three
/// timing shapes, so only content_length varies at all.
const chunked_close = "HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n" ++
    "connection: close\r\nserver: bench\r\n\r\n";
const http_10 = "HTTP/1.0 204 No Content\r\nserver: bench\r\n\r\n";

const shapes = [_]Shape{
    .{ .name = "small-cl", .wire = small_cl },
    .{ .name = "zrk-1k", .wire = zrk_1k },
    .{ .name = "many-hdr", .wire = many_headers },
};

/// Timed shapes plus the ones that exist only to make agreement meaningful.
const agreement_shapes = shapes ++ [_]Shape{
    .{ .name = "chunked", .wire = chunked_close },
    .{ .name = "http1.0", .wire = http_10 },
};

// ---------------------------------------------------------------------------

fn report(name: []const u8, who: []const u8, heads: u64, ns: u64) void {
    const per = @as(f64, @floatFromInt(ns)) / @as(f64, @floatFromInt(heads));
    const rate = @as(f64, @floatFromInt(heads)) / (@as(f64, @floatFromInt(ns)) / 1e9);
    std.debug.print("  {s:<10} {s:<8} {d:>9.0} head/s {d:>8.0} ns/head\n", .{ name, who, rate, per });
}

fn sameHead(a: zurl.Head, b: zurl.Head) bool {
    if (a.status != b.status) return false;
    // The head's size is part of its answer now: an integration that scanned a
    // different number of bytes parsed a different head, whatever else agrees.
    if (a.head_len != b.head_len) return false;
    if (a.http11 != b.http11) return false;
    if (a.keep_alive != b.keep_alive) return false;
    if (a.chunked != b.chunked) return false;
    // Compared as optionals: `orelse maxInt` would make a missing header and
    // `content-length: 18446744073709551615` indistinguishable.
    if (a.content_length) |x| {
        if (b.content_length) |y| return x == y;
        return false;
    }
    return b.content_length == null;
}

/// All three integrations must produce the same head under every delivery
/// that is later TIMED, or the comparison is between different programs.
///
/// Checking only the whole-buffered case would leave the 1-byte column — the
/// one carrying the widest spread, and so the most weight in the verdict —
/// agreement-checked for nobody.
fn expectAgreement(shape: *const Shape) !void {
    var buffer_naive: [8192]u8 = undefined;
    var buffer_scan: [8192]u8 = undefined;

    for ([_]usize{ 1, 7, 64, 8192 }) |segment| {
        var reader_whole: Io.Reader = .fixed(shape.wire);
        var naive = Segmented.init(shape.wire, segment, &buffer_naive);
        var scan = Segmented.init(shape.wire, segment, &buffer_scan);

        const ours = try zurl.parser.parseHead(&reader_whole, .{});
        const theirs = try hparseHead(&naive.interface, .{});
        const scanned = try hparseHeadScan(&scan.interface, .{});

        if (!sameHead(ours, theirs)) return error.HparseDisagrees;
        if (!sameHead(ours, scanned)) return error.HparseScanDisagrees;
    }
}

/// One divergence that is real, known, and a cost of adoption rather than a
/// bug in either parser: the pinned hparse is strictly CRLF-only — deliberately
/// so, because for an intermediary, two parsers disagreeing about where a line
/// ends IS request smuggling. zurl tolerates a bare LF, which is the right
/// call for a CLIENT, where the same strictness turns a lenient origin into an
/// outage. Demonstrated rather than asserted away.
fn reportBareLfDivergence() !void {
    const bare_lf = "HTTP/1.1 200 OK\ncontent-length: 5\n\n";
    var reader: Io.Reader = .fixed(bare_lf);
    const ours = zurl.parser.parseHead(&reader, .{}) catch {
        std.debug.print("bare-LF head: zurl also refuses it\n\n", .{});
        return;
    };

    var buffer: [8192]u8 = undefined;
    var seg = Segmented.init(bare_lf, bare_lf.len, &buffer);
    if (hparseHead(&seg.interface, .{})) |_| {
        std.debug.print("bare-LF head: both accept it\n\n", .{});
    } else |err| {
        std.debug.print(
            "bare-LF head: zurl parses it (status {d}), hparse returns {s}\n" ++
                "  — a behaviour change for a client, not just a dependency.\n\n",
            .{ ours.status, @errorName(err) },
        );
    }
}

pub fn main() !void {
    var gpa_state: std.heap.DebugAllocator(.{}) = .init;
    const gpa = gpa_state.allocator();
    var threaded: Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    std.debug.print("zurl bench-head ({s}) — head parsing only\n\n", .{@tagName(@import("builtin").mode)});

    for (&agreement_shapes) |*shape| try expectAgreement(shape);
    std.debug.print(
        "all three integrations agree on {d} shapes x 4 segmentations.\n\n",
        .{agreement_shapes.len},
    );
    try reportBareLfDivergence();

    const iterations = 200_000;

    std.debug.print("whole head already buffered:\n", .{});
    for (&shapes) |*shape| {
        try timeWhole(io, shape, iterations, .zurl);
        try timeWhole(io, shape, iterations, .hparse);
        try timeWhole(io, shape, iterations, .@"hparse+scan");
    }

    // 64 bytes is a plausible worst-ish case for a head split across reads;
    // 1 byte is the pathological end of the same axis.
    for ([_]usize{ 64, 1 }) |segment| {
        std.debug.print("\nhead arriving in {d}-byte segments:\n", .{segment});
        for (&shapes) |*shape| {
            try timeSegmented(io, shape, iterations / 20, segment, .zurl);
            try timeSegmented(io, shape, iterations / 20, segment, .hparse);
            try timeSegmented(io, shape, iterations / 20, segment, .@"hparse+scan");
        }
    }
}

const Who = enum { zurl, hparse, @"hparse+scan" };

fn parseWith(who: Who, r: *Io.Reader) !zurl.Head {
    return switch (who) {
        .zurl => zurl.parser.parseHead(r, .{}),
        .hparse => hparseHead(r, .{}),
        .@"hparse+scan" => hparseHeadScan(r, .{}),
    };
}

fn timeWhole(io: Io, shape: *const Shape, iterations: usize, who: Who) !void {
    // One untimed pass per variant: zurl is timed first in every group, so
    // without this it absorbs the group's cold i-cache and branch-predictor
    // cost — which matters precisely where the two are closest.
    {
        var warm: Io.Reader = .fixed(shape.wire);
        std.mem.doNotOptimizeAway(try parseWith(who, &warm));
    }
    const start = Io.Timestamp.now(io, .awake);
    for (0..iterations) |_| {
        var r: Io.Reader = .fixed(shape.wire);
        const head = try parseWith(who, &r);
        // The WHOLE head, not one field: everything `extractFraming` computes
        // feeds content_length/chunked/keep_alive, all of which are dead if
        // only `status` is observed — and a deleted framing pass would make
        // the hparse column secretly measure hparse-without-framing.
        std.mem.doNotOptimizeAway(head);
    }
    const ns = start.durationTo(.now(io, .awake)).nanoseconds;
    report(shape.name, @tagName(who), iterations, @intCast(ns));
}

fn timeSegmented(io: Io, shape: *const Shape, iterations: usize, segment: usize, who: Who) !void {
    var buffer: [8192]u8 = undefined;
    {
        var warm = Segmented.init(shape.wire, segment, &buffer);
        std.mem.doNotOptimizeAway(try parseWith(who, &warm.interface));
    }
    const start = Io.Timestamp.now(io, .awake);
    for (0..iterations) |_| {
        var seg = Segmented.init(shape.wire, segment, &buffer);
        const head = try parseWith(who, &seg.interface);
        std.mem.doNotOptimizeAway(head);
    }
    const ns = start.durationTo(.now(io, .awake)).nanoseconds;
    report(shape.name, @tagName(who), iterations, @intCast(ns));
}
