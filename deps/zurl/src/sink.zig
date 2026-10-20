//! Body sinks beyond what std provides.
//!
//! `discard` and `collect` are std's own `Io.Writer.Discarding` and
//! `Io.Writer.Allocating`; the only sink zurl adds is `LineSink`, ported from
//! the zoxy benchmark's cAdvisor scrape — a body consumed a line at a time
//! while never holding more than one line of it.

const std = @import("std");
const Io = std.Io;
const assert = std.debug.assert;

/// A response body consumed a line at a time, without ever holding more than
/// one line of it.
///
/// This is what lets a ~2 MB Prometheus exposition be parsed inside a load
/// generator's own process at 1 Hz without allocating or copying it: `drain`
/// hands complete lines straight out of the transport's buffer and keeps only
/// a partial trailing line in `carry`.
///
/// The length limit applies IDENTICALLY whether a line arrives whole or
/// fragmented (design rule 4): deliverability is a property of the line, not
/// of where the transport split the stream. Overlong lines are dropped whole
/// and counted, never truncated (rule 7) — a truncated metric line still
/// parses as a metric and reports a wrong value, which is worse than a
/// missing one.
pub const LineSink = struct {
    writer: Io.Writer,
    carry: []u8,
    carry_len: usize = 0,
    /// Lines that exceeded `carry` and were dropped whole.
    overlong: u64 = 0,
    /// Mid-drop: bytes are discarded until the next newline.
    dropping: bool = false,
    ctx: ?*anyopaque,
    onLine: *const fn (ctx: ?*anyopaque, line: []const u8) void,

    /// `carry` bounds the longest line this can deliver; `buffer` is ordinary
    /// `Io.Writer` scratch and may be small.
    pub fn init(
        buffer: []u8,
        carry: []u8,
        ctx: ?*anyopaque,
        onLine: *const fn (ctx: ?*anyopaque, line: []const u8) void,
    ) LineSink {
        // Both slices are bounds, and a zero-length one is a caller bug that
        // would otherwise surface as every line being reported overlong.
        assert(buffer.len > 0);
        assert(carry.len > 0);

        return .{
            .writer = .{ .vtable = &.{ .drain = drain }, .buffer = buffer },
            .carry = carry,
            .ctx = ctx,
            .onLine = onLine,
        };
    }

    /// Deliver a final line that had no trailing newline. Call after the body
    /// has ended (`Connection.roundTrip` does it for you); calling it twice is
    /// harmless.
    pub fn finish(self: *LineSink) void {
        // `drain` below feeds the callback and always reports the full write,
        // so this error union is structural and cannot actually fail.
        self.writer.flush() catch {};
        assert(self.carry_len <= self.carry.len);

        if (self.carry_len == 0) return;
        const line = self.carry[0..self.carry_len];
        self.carry_len = 0;
        self.onLine(self.ctx, line);
    }

    fn feed(self: *LineSink, bytes: []const u8) void {
        // The carry never overfills, on any exit path — and that invariant is
        // exactly what makes the length limit a property of the line rather
        // than of where the transport split the stream (rule 4).
        assert(self.carry_len <= self.carry.len);
        defer assert(self.carry_len <= self.carry.len);

        var rest = bytes;
        // Bounded structurally: every pass either returns, breaks, or advances
        // `rest` past a newline, so its length strictly decreases.
        while (rest.len > 0) {
            if (self.dropping) {
                const nl = std.mem.indexOfScalar(u8, rest, '\n') orelse return;
                self.dropping = false;
                rest = rest[nl + 1 ..];
                continue;
            }
            const nl = std.mem.indexOfScalar(u8, rest, '\n') orelse break;
            const chunk = rest[0..nl];
            if (self.carry_len == 0) {
                // The common case, and the reason this is cheap: the line is
                // whole inside the transport's buffer, so it is never copied.
                // The limit still applies here — rule 4.
                if (chunk.len <= self.carry.len) {
                    self.onLine(self.ctx, chunk);
                } else {
                    self.overlong += 1;
                }
            } else if (self.carry_len + chunk.len <= self.carry.len) {
                @memcpy(self.carry[self.carry_len..][0..chunk.len], chunk);
                self.carry_len += chunk.len;
                self.onLine(self.ctx, self.carry[0..self.carry_len]);
                self.carry_len = 0;
            } else {
                self.overlong += 1;
                self.carry_len = 0;
            }
            rest = rest[nl + 1 ..];
        }
        if (self.dropping or rest.len == 0) return;
        if (self.carry_len + rest.len <= self.carry.len) {
            @memcpy(self.carry[self.carry_len..][0..rest.len], rest);
            self.carry_len += rest.len;
        } else {
            self.overlong += 1;
            self.carry_len = 0;
            self.dropping = true;
        }
    }

    fn drain(w: *Io.Writer, data: []const []const u8, splat: usize) Io.Writer.Error!usize {
        // The Io.Writer contract: `data` always carries at least the splat
        // pattern, and `end` indexes within the buffer it belongs to.
        assert(data.len > 0);
        assert(w.end <= w.buffer.len);

        const self: *LineSink = @alignCast(@fieldParentPtr("writer", w));
        if (w.end > 0) {
            self.feed(w.buffer[0..w.end]);
            w.end = 0;
        }
        const head = data[0 .. data.len - 1];
        const pattern = data[head.len];
        var written: usize = 0;
        for (head) |bytes| {
            self.feed(bytes);
            written += bytes.len;
        }
        for (0..splat) |_| self.feed(pattern);
        return written + pattern.len * splat;
    }
};

// ---------------------------------------------------------------------------
// tests

const t = std.testing;

const Collector = struct {
    lines: std.ArrayList([]u8),
    gpa: std.mem.Allocator,

    fn on(ctx: ?*anyopaque, line: []const u8) void {
        const self: *Collector = @ptrCast(@alignCast(ctx.?));
        const copy = self.gpa.dupe(u8, line) catch return;
        self.lines.append(self.gpa, copy) catch return;
    }

    fn deinit(self: *Collector) void {
        for (self.lines.items) |l| self.gpa.free(l);
        self.lines.deinit(self.gpa);
    }
};

test "splits lines across arbitrary write boundaries" {
    var c: Collector = .{ .lines = .empty, .gpa = t.allocator };
    defer c.deinit();
    var buf: [8]u8 = undefined;
    var carry: [64]u8 = undefined;
    var sink = LineSink.init(&buf, &carry, &c, Collector.on);

    for ([_][]const u8{ "alpha\nbet", "a\ngamm", "a\n", "delta" }) |part| {
        try sink.writer.writeAll(part);
    }
    sink.finish();

    try t.expectEqual(@as(usize, 4), c.lines.items.len);
    try t.expectEqualStrings("alpha", c.lines.items[0]);
    try t.expectEqualStrings("beta", c.lines.items[1]);
    try t.expectEqualStrings("gamma", c.lines.items[2]);
    try t.expectEqualStrings("delta", c.lines.items[3]);
    try t.expectEqual(@as(u64, 0), sink.overlong);
}

test "overlong lines drop whole, whether or not they arrive fragmented" {
    var c: Collector = .{ .lines = .empty, .gpa = t.allocator };
    defer c.deinit();
    var buf: [4]u8 = undefined;
    var carry: [8]u8 = undefined;
    var sink = LineSink.init(&buf, &carry, &c, Collector.on);

    try sink.writer.writeAll("short\n");
    try sink.writer.writeAll("this line is far longer than the carry buffer\n");
    try sink.writer.writeAll("after\n");
    sink.finish();

    try t.expectEqual(@as(u64, 1), sink.overlong);
    try t.expectEqual(@as(usize, 2), c.lines.items.len);
    try t.expectEqualStrings("short", c.lines.items[0]);
    try t.expectEqualStrings("after", c.lines.items[1]);
}
