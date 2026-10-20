//! End-to-end loopback comparison: zurl vs std.http.Client, same server, same
//! Io, same response (200 + 1 KiB content-length body).
//!
//! Two disciplines, because the two real consumers differ:
//!
//!   keep-alive  — one connection, N sequential exchanges. zurl drives a
//!                 `Connection` directly; std drives `fetch` with its pool
//!                 reusing the connection. Each side is written the way its
//!                 own consumer would actually write it.
//!   fresh-conn  — dial per request, `connection: close` (the control-plane
//!                 shape both benchmark repos use in production).
//!
//! zurl's client path takes NO allocator — that is a design property on
//! display, not an omission; std gets `smp_allocator`, its best case.
//!
//!   zig build bench-e2e -Doptimize=ReleaseFast

const std = @import("std");
const zurl = @import("zurl");
const Io = std.Io;
const net = std.Io.net;

const body_size = 1024;
const keepalive_n = 50_000;
const fresh_n = 3_000;

const Server = struct {
    listener: *net.Server,
    io: Io,

    fn run(self: *Server) void {
        while (true) {
            var stream = self.listener.accept(self.io) catch return;
            defer stream.close(self.io);
            var rbuf: [8192]u8 = undefined;
            var wbuf: [4096]u8 = undefined;
            var r = stream.reader(self.io, &rbuf);
            var w = stream.writer(self.io, &wbuf);
            connLoop(&r.interface, &w.interface);
        }
    }

    fn connLoop(r: *Io.Reader, w: *Io.Writer) void {
        while (true) {
            var close = false;
            var saw_any = false;
            while (true) {
                const line = r.takeDelimiterInclusive('\n') catch return;
                if (line.len <= 2) break; // blank line: end of head
                saw_any = true;
                if (std.ascii.startsWithIgnoreCase(line, "connection:") and
                    std.ascii.indexOfIgnoreCase(line, "close") != null) close = true;
            }
            if (!saw_any) return;
            w.writeAll(responseBytes()) catch return;
            w.flush() catch return;
            if (close) return;
        }
    }

    // The canned response, built once. A function so connLoop needs no state.
    var canned: ?[]const u8 = null;
    var canned_buf: [body_size + 128]u8 = undefined;
    fn responseBytes() []const u8 {
        if (canned) |c| return c;
        var wr: Io.Writer = .fixed(&canned_buf);
        wr.print("HTTP/1.1 200 OK\r\ncontent-length: {d}\r\n\r\n", .{body_size}) catch unreachable;
        wr.splatByteAll('x', body_size) catch unreachable;
        canned = wr.buffered();
        return canned.?;
    }
};

fn report(name: []const u8, n: u64, ns: u64) void {
    const s = @as(f64, @floatFromInt(ns)) / 1e9;
    const rps = @as(f64, @floatFromInt(n)) / s;
    const us = @as(f64, @floatFromInt(ns)) / @as(f64, @floatFromInt(n)) / 1e3;
    std.debug.print("{s:<26} {d:>9.0} req/s  {d:>7.1} us/req\n", .{ name, rps, us });
}

pub fn main() !void {
    const gpa = std.heap.smp_allocator;

    var threaded: Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const addr = try net.IpAddress.parse("127.0.0.1", 0);
    var listener = try addr.listen(io, .{ .reuse_address = true, .kernel_backlog = 64 });
    defer listener.deinit(io);
    const port = listener.socket.address.getPort();

    var server: Server = .{ .listener = &listener, .io = io };
    var group: Io.Group = .init;
    defer group.cancel(io);
    group.async(io, Server.run, .{&server});

    var url_buf: [64]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/", .{port});
    var host_buf: [64]u8 = undefined;
    const host = try std.fmt.bufPrint(&host_buf, "127.0.0.1:{d}", .{port});

    std.debug.print("zurl bench-e2e ({s}) — loopback, {d}B body\n\n", .{
        @tagName(@import("builtin").mode), body_size,
    });

    // -- keep-alive: zurl Connection ----------------------------------------
    {
        const ip = try net.IpAddress.parse("127.0.0.1", port);
        var stream = try ip.connect(io, .{ .mode = .stream });
        defer stream.close(io);
        var rbuf: [16 * 1024]u8 = undefined;
        var wbuf: [4096]u8 = undefined;
        var r = stream.reader(io, &rbuf);
        var w = stream.writer(io, &wbuf);
        var conn = zurl.Connection.init(&r.interface, &w.interface);

        const t0 = Io.Timestamp.now(io, .awake);
        for (0..keepalive_n) |_| {
            const res = try conn.roundTrip(.{ .host = host }, .discard, .{});
            if (res.status != 200) return error.BadStatus;
        }
        const ns: u64 = @intCast(t0.durationTo(Io.Timestamp.now(io, .awake)).nanoseconds);
        report("keep-alive zurl.Connection", keepalive_n, ns);
    }

    // -- keep-alive: std.http.Client (pool reuse) ---------------------------
    {
        var client: std.http.Client = .{ .allocator = gpa, .io = io };
        defer client.deinit();

        const t0 = Io.Timestamp.now(io, .awake);
        for (0..keepalive_n) |_| {
            var dbuf: [512]u8 = undefined;
            var discard: Io.Writer.Discarding = .init(&dbuf);
            const res = try client.fetch(.{
                .location = .{ .url = url },
                .response_writer = &discard.writer,
                .keep_alive = true,
            });
            if (res.status != .ok) return error.BadStatus;
        }
        const ns: u64 = @intCast(t0.durationTo(Io.Timestamp.now(io, .awake)).nanoseconds);
        report("keep-alive std.http.Client", keepalive_n, ns);
    }

    // -- fresh connection per request: zurl.fetch ---------------------------
    {
        const t0 = Io.Timestamp.now(io, .awake);
        for (0..fresh_n) |_| {
            const res = (try zurl.fetch(io, .{ .url = url })) orelse return error.TimedOut;
            if (res.status != 200) return error.BadStatus;
        }
        const ns: u64 = @intCast(t0.durationTo(Io.Timestamp.now(io, .awake)).nanoseconds);
        report("fresh-conn zurl.fetch", fresh_n, ns);
    }

    // -- fresh connection per request: std.http.Client ----------------------
    {
        var client: std.http.Client = .{ .allocator = gpa, .io = io };
        defer client.deinit();
        const t0 = Io.Timestamp.now(io, .awake);
        for (0..fresh_n) |_| {
            var dbuf: [512]u8 = undefined;
            var discard: Io.Writer.Discarding = .init(&dbuf);
            const res = try client.fetch(.{
                .location = .{ .url = url },
                .response_writer = &discard.writer,
                .keep_alive = false,
            });
            if (res.status != .ok) return error.BadStatus;
        }
        const ns: u64 = @intCast(t0.durationTo(Io.Timestamp.now(io, .awake)).nanoseconds);
        report("fresh-conn std.http.Client", fresh_n, ns);
    }
}
