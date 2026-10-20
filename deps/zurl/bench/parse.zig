//! Parser microbenchmarks: what one response costs, with the transport taken
//! out of the picture (Reader.fixed over a prebuilt pipelined byte stream).
//!
//! Prints numbers, asserts nothing (design rule 8): a perf gate that fails on
//! a loaded laptop teaches people to delete perf gates. Run in ReleaseFast:
//!
//!   zig build bench-parse -Doptimize=ReleaseFast
//!
//! Scenarios are the two real shapes zurl exists for, plus the hot-path shape
//! zrk would need parity on before ever adopting any of this:
//!
//!   small-cl   — API-style: 8 headers, 128 B content-length body
//!   zrk-1k     — the proxy benchmark's wire shape: 1 KiB body, few headers
//!   cadvisor   — ~1.5 MiB chunked exposition in 2 KiB chunks, consumed
//!                through LineSink a line at a time

const std = @import("std");
const zurl = @import("zurl");
const Io = std.Io;

fn buildPipelined(
    gpa: std.mem.Allocator,
    count: usize,
    headers: []const u8,
    body: []const u8,
) ![]u8 {
    var out: Io.Writer.Allocating = .init(gpa);
    errdefer out.deinit();
    for (0..count) |_| {
        try out.writer.print("HTTP/1.1 200 OK\r\n{s}content-length: {d}\r\n\r\n", .{ headers, body.len });
        try out.writer.writeAll(body);
    }
    return out.toOwnedSlice();
}

fn buildChunked(gpa: std.mem.Allocator, total_body: usize, chunk: usize) ![]u8 {
    var out: Io.Writer.Allocating = .init(gpa);
    errdefer out.deinit();
    try out.writer.writeAll("HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ntransfer-encoding: chunked\r\n\r\n");
    // Exposition-shaped payload: ~100-byte metric lines, chunk framing at a
    // fixed 2 KiB cadence exactly like Go's chunked writer — the framing that
    // corrupted the benchmark's hand-rolled reader for months.
    const line = "container_cpu_usage_seconds_total{cpu=\"total\",id=\"/system.slice/docker-abc.scope\",name=\"zgix\"} 1.5 17\n";
    var body: Io.Writer.Allocating = .init(gpa);
    defer body.deinit();
    while (body.written().len < total_body) try body.writer.writeAll(line);
    var rest = body.written();
    while (rest.len > 0) {
        const n = @min(chunk, rest.len);
        try out.writer.print("{x}\r\n", .{n});
        try out.writer.writeAll(rest[0..n]);
        try out.writer.writeAll("\r\n");
        rest = rest[n..];
    }
    try out.writer.writeAll("0\r\n\r\n");
    return out.toOwnedSlice();
}

fn report(name: []const u8, responses: u64, bytes: u64, ns: u64) void {
    const s = @as(f64, @floatFromInt(ns)) / 1e9;
    const rps = @as(f64, @floatFromInt(responses)) / s;
    const mbs = @as(f64, @floatFromInt(bytes)) / 1e6 / s;
    const ns_per = @as(f64, @floatFromInt(ns)) / @as(f64, @floatFromInt(responses));
    std.debug.print("{s:<12} {d:>10.0} resp/s  {d:>8.1} MB/s  {d:>8.0} ns/resp\n", .{ name, rps, mbs, ns_per });
}

var line_count: u64 = 0;
fn countLine(ctx: ?*anyopaque, line: []const u8) void {
    _ = ctx;
    _ = line;
    line_count += 1;
}

pub fn main() !void {
    var gpa_state: std.heap.DebugAllocator(.{}) = .init;
    const gpa = gpa_state.allocator();

    // 0.16 moved the clock into Io; this Threaded exists ONLY to read it.
    // The parsing under measurement never touches an Io implementation —
    // Reader.fixed is pure memory.
    var threaded: Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    std.debug.print("zurl bench-parse ({s})\n\n", .{@tagName(@import("builtin").mode)});

    // -- small-cl and zrk-1k: pipelined content-length responses ------------
    const shapes = [_]struct { name: []const u8, headers: []const u8, body_len: usize, per_buf: usize }{
        .{
            .name = "small-cl",
            .headers = "server: bench\r\ndate: Sun, 23 Aug 2026 12:00:00 GMT\r\n" ++
                "content-type: application/json\r\ncache-control: no-store\r\n" ++
                "x-request-id: 0123456789abcdef\r\nvary: accept-encoding\r\n" ++
                "etag: \"abc123\"\r\n",
            .body_len = 128,
            .per_buf = 2000,
        },
        .{
            .name = "zrk-1k",
            .headers = "server: proxy\r\ncontent-type: application/octet-stream\r\n",
            .body_len = 1024,
            .per_buf = 2000,
        },
    };

    for (shapes) |shape| {
        const body_bytes = try gpa.alloc(u8, shape.body_len);
        defer gpa.free(body_bytes);
        @memset(body_bytes, 'x');
        const wire = try buildPipelined(gpa, shape.per_buf, shape.headers, body_bytes);
        defer gpa.free(wire);

        // Warmup, then ~1s of measurement.
        var responses: u64 = 0;
        var bytes: u64 = 0;
        const t0 = Io.Timestamp.now(io, .awake);
        var elapsed: u64 = 0;
        while (elapsed < 1 * std.time.ns_per_s) {
            var r: Io.Reader = .fixed(wire);
            var dbuf: [512]u8 = undefined;
            var discard: Io.Writer.Discarding = .init(&dbuf);
            for (0..shape.per_buf) |_| {
                const head = try zurl.parser.parseHead(&r, .{});
                _ = try zurl.parser.streamBody(&r, head, .GET, &discard.writer, .{});
            }
            responses += shape.per_buf;
            bytes += wire.len;
            elapsed = @intCast(t0.durationTo(Io.Timestamp.now(io, .awake)).nanoseconds);
        }
        report(shape.name, responses, bytes, elapsed);
    }

    // -- cadvisor: one big chunked response through LineSink ----------------
    {
        const wire = try buildChunked(gpa, 1_500_000, 2048);
        defer gpa.free(wire);

        var responses: u64 = 0;
        var bytes: u64 = 0;
        const t0 = Io.Timestamp.now(io, .awake);
        var elapsed: u64 = 0;
        while (elapsed < 1 * std.time.ns_per_s) {
            var r: Io.Reader = .fixed(wire);
            var lbuf: [4096]u8 = undefined;
            var carry: [16 * 1024]u8 = undefined;
            var sink = zurl.LineSink.init(&lbuf, &carry, null, countLine);
            const head = try zurl.parser.parseHead(&r, .{});
            _ = try zurl.parser.streamBody(&r, head, .GET, &sink.writer, .{});
            sink.finish();
            responses += 1;
            bytes += wire.len;
            elapsed = @intCast(t0.durationTo(Io.Timestamp.now(io, .awake)).nanoseconds);
        }
        report("cadvisor", responses, bytes, elapsed);
        const scrape_ms = @as(f64, @floatFromInt(elapsed)) / @as(f64, @floatFromInt(responses)) / 1e6;
        std.debug.print("             ({d} lines/scrape, {d:.2} ms/scrape)\n", .{
            line_count / responses, scrape_ms,
        });
    }
}
