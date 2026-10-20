//! One connection, held open for one origin.
//!
//! `fetch` dials, sends `connection: close`, and hangs up. That is right for a
//! poll or a one-shot and wasteful for a dozen calls to one API, where every
//! https request pays a TLS handshake to say what it said last time.
//!
//! `Connection` could always do this — it is a `*Io.Reader` and a `*Io.Writer`
//! and does not care where they came from (rule 5). What was missing is the
//! part `fetch` does and `Connection` deliberately does not: resolving a URL,
//! dialling it, and standing up a transport whose buffers outlive a single
//! request.
//!
//! The socket itself stays in `client.zig`, which rule 5 makes the only file
//! allowed to dial — the code below holds a `client.Dialed` and never names a
//! socket type. That is the seam working rather than being worked around.
//!
//! The tests at the bottom do name one, because an integration test needs a
//! real origin to talk to. That is test scaffolding, not a second dialer: no
//! declaration above the test section imports or mentions a socket.
//!
//! A `Session` is NOT a connection pool. It is one connection to one origin,
//! and it does not reconnect on its own — see `reusable`.

const std = @import("std");
const Io = std.Io;
const assert = std.debug.assert;
const client = @import("client.zig");
const connection = @import("connection.zig");
const parser = @import("parser.zig");
const tls_transport = @import("tls.zig");

/// Aliased whole rather than narrowed. It carries a few variants a session
/// cannot actually produce — `TooManyRedirects`, for one, since a session does
/// not follow redirects — and that is the lesser evil: a narrowed set would
/// have to be kept in step with `client.Error` by hand, and the day it fell
/// behind would be the day a real error had nowhere to go.
pub const Error = client.Error;
pub const Buffers = client.Buffers;

pub const Options = struct {
    buffers: Buffers,
    /// Required for https, unused for http — the same contract, and the same
    /// reason, as `FetchRequest.tls`: there is no safe default trust store,
    /// and loading one allocates.
    tls: ?tls_transport.Config = null,
};

/// A connection to one origin, reused across requests.
///
/// **Not movable once opened.** `conn` points into `dialed`, a field of this
/// struct, so copying a `Session` leaves those pointers aimed at the original.
/// `open` takes a `*Session` for exactly that reason.
pub const Session = struct {
    /// Borrowed from the URL passed to `open`, which must outlive the session.
    origin: client.Origin,
    dialed: client.Dialed,
    conn: connection.Connection,

    /// Resolve `url`, dial it, and stand up a transport.
    ///
    /// Only the ORIGIN of `url` is used; its path is not. A session is a place
    /// to send requests, not a request.
    pub fn open(session: *Session, io: Io, url: []const u8, opts: Options) Error!void {
        if (url.len == 0) return error.InvalidUrl;
        const uri = std.Uri.parse(url) catch return error.InvalidUrl;
        const origin = try client.Origin.of(uri);

        session.origin = origin;
        try session.dialed.open(io, origin, opts.buffers, opts.tls);
        errdefer session.dialed.close();

        session.conn = .init(session.dialed.reader(), session.dialed.writer());

        // The invariant the whole self-referential design rests on: `conn`
        // reads and writes through `dialed`, which is now standing.
        assert(session.dialed.secure == origin.secure);
        assert(session.conn.reusable);
    }

    /// Send one request on this session and read its response.
    ///
    /// `req.host` is filled in from the origin — a session has already been
    /// told where it points, and letting a request disagree would send a
    /// `host` header the connection does not match.
    ///
    /// There is no deadline here, and it is worth being plain about that
    /// rather than calling it a design choice. Rule 3's bound is
    /// whole-REQUEST, and `fetch` supplies it by racing a sleeper against the
    /// work. A session spans many requests, so there is nothing here for one
    /// number to bound — but that means `Session` ships NO protection against
    /// a stalled origin, and a caller who wants it has to build the same
    /// `Io.Group`-plus-sleeper race `fetch` does. Unbounded is the hazard this
    /// library exists to prevent; on this path the caller owns it.
    pub fn request(
        session: *Session,
        req: connection.Request,
        sink: connection.Sink,
        opts: parser.HeadOptions,
    ) Error!connection.Response {
        // A caller that already named the origin need not name it again, and
        // must not be able to name it differently.
        // Case-insensitive, matching `sameOrigin`: `Example.com` and
        // `example.com` are the same host, and tripping on the difference
        // would punish a caller for no real misuse.
        if (req.host.len != 0) assert(std.ascii.eqlIgnoreCase(req.host, session.origin.host));

        var owned = req;
        owned.host = session.origin.host;
        // Overridden, not honoured: a session whose request asked to close
        // would end the session, which is the one thing it exists not to do.
        // `close` is how a caller says that.
        owned.keep_alive = true;
        return session.conn.roundTrip(owned, sink, opts);
    }

    /// Whether another request may be sent.
    ///
    /// False once the origin said `connection: close`, once a response was
    /// close-delimited, or once anything errored — after which nobody knows
    /// where in the stream the next response would begin.
    ///
    /// A session does NOT reconnect on its own. Reconnecting means resending,
    /// and whether resending is safe is the same question retry asks and gets
    /// the same answer: only the caller knows. `close` this one and `open`
    /// another.
    pub fn reusable(session: *const Session) bool {
        return session.conn.reusable;
    }

    /// Shut the session down.
    ///
    /// Only valid on a session `open` returned successfully for. Every field
    /// is `undefined` before that, so the `defer session.close()` must come
    /// AFTER the `try session.open(...)`, not before it.
    pub fn close(session: *Session) void {
        session.dialed.close();
    }
};

// ---------------------------------------------------------------------------
// tests
const t = std.testing;

/// Serve `count` requests on ONE accepted connection, closing on the last.
///
/// Accepting exactly once is the point: a session that silently redialled
/// would hang here rather than quietly passing.
fn serveKeepAlive(srv: *std.Io.net.Server, sio: Io, count: usize) void {
    var s = srv.accept(sio) catch return;
    defer s.close(sio);

    var rb: [2048]u8 = undefined;
    var rr = s.reader(sio, &rb);
    var wb: [1024]u8 = undefined;
    var ww = s.writer(sio, &wb);

    var served: usize = 0;
    while (served < count) : (served += 1) {
        // lint:unbounded-ok — ends at the blank line of a head the client
        // always terminates, or at a failed read.
        while (true) {
            const line = rr.interface.takeDelimiterInclusive('\n') catch return;
            if (line.len <= 2) break;
        }
        // The last one closes, which is how the session learns it is no longer
        // reusable without anything having gone wrong.
        const body = if (served + 1 == count)
            "HTTP/1.1 200 OK\r\nconnection: close\r\ncontent-length: 4\r\n\r\nlast"
        else
            "HTTP/1.1 200 OK\r\ncontent-length: 4\r\n\r\nmore";
        ww.interface.writeAll(body) catch return;
        ww.interface.flush() catch return;
    }
}

test "one connection serves many requests" {
    var threaded: Io.Threaded = .init(t.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const addr = try std.Io.net.IpAddress.parse("127.0.0.1", 0);
    var server = try addr.listen(io, .{ .reuse_address = true });
    defer server.deinit(io);
    const port = server.socket.address.getPort();

    var group: Io.Group = .init;
    defer group.cancel(io);
    try group.concurrent(io, serveKeepAlive, .{ &server, io, 3 });

    var url_buf: [64]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/", .{port});

    var read_buf: [8 * 1024]u8 = undefined;
    var write_buf: [1024]u8 = undefined;
    var session: Session = undefined;
    try session.open(io, url, .{ .buffers = .{ .read = &read_buf, .write = &write_buf } });
    defer session.close();

    var body: Io.Writer.Allocating = .init(t.allocator);
    defer body.deinit();

    for (0..2) |_| {
        body.clearRetainingCapacity();
        const res = try session.request(.{ .target = "/page" }, .{ .collect = &body }, .{});
        try t.expectEqual(@as(u16, 200), res.status);
        try t.expectEqualStrings("more", body.written());
        try t.expect(session.reusable());
    }
}

test "an origin that says close ends the session rather than being rediscovered" {
    var threaded: Io.Threaded = .init(t.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const addr = try std.Io.net.IpAddress.parse("127.0.0.1", 0);
    var server = try addr.listen(io, .{ .reuse_address = true });
    defer server.deinit(io);
    const port = server.socket.address.getPort();

    var group: Io.Group = .init;
    defer group.cancel(io);
    try group.concurrent(io, serveKeepAlive, .{ &server, io, 1 });

    var url_buf: [64]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/", .{port});

    var read_buf: [8 * 1024]u8 = undefined;
    var write_buf: [1024]u8 = undefined;
    var session: Session = undefined;
    try session.open(io, url, .{ .buffers = .{ .read = &read_buf, .write = &write_buf } });
    defer session.close();

    var body: Io.Writer.Allocating = .init(t.allocator);
    defer body.deinit();
    _ = try session.request(.{ .target = "/only" }, .{ .collect = &body }, .{});
    try t.expectEqualStrings("last", body.written());

    // Said before the next request rather than discovered as a truncated read.
    try t.expect(!session.reusable());
    try t.expectError(error.ConnectionNotReusable, session.request(.{ .target = "/x" }, .discard, .{}));
}

test "a session refuses an https origin with no trust configuration, before dialling" {
    // Same contract as `fetch`, and the same reason: a caller who silently got
    // "verify nothing" would hold an https session that looks secure.
    var threaded: Io.Threaded = .init(t.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var read_buf: [1024]u8 = undefined;
    var write_buf: [1024]u8 = undefined;
    const buffers: Buffers = .{ .read = &read_buf, .write = &write_buf };
    var session: Session = undefined;

    try t.expectError(error.TlsNotConfigured, session.open(io, "https://example.com/", .{ .buffers = buffers }));
    try t.expectError(error.InvalidUrl, session.open(io, "", .{ .buffers = buffers }));
    try t.expectError(error.InvalidUrl, session.open(io, "ftp://example.com/", .{ .buffers = buffers }));
}
