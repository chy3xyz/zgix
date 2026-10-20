//! One HTTP/1.1 connection over an injected transport.
//!
//! A `Connection` is a `*Io.Reader` and a `*Io.Writer`, full stop (design
//! rule 5). Plain TCP, std TLS, zrk's ztls, an in-memory pipe in a test — all
//! the same type. Whoever owns the transport owns its lifetime and its close;
//! the connection only tracks whether HTTP framing permits reuse.

const std = @import("std");
const Io = std.Io;
const assert = std.debug.assert;
const parser = @import("parser.zig");
const LineSink = @import("sink.zig").LineSink;

pub const Header = struct { name: []const u8, value: []const u8 };

/// What zurl calls itself when the caller does not say otherwise.
///
/// Sent because its ABSENCE is a failure a caller cannot diagnose from a
/// status: GitHub rejects a request with no `user-agent` outright, and an
/// origin that rate-limits or blocks by agent cannot tell zurl from a scraper.
///
/// The version here is a SEPARATE literal from `build.zig.zon`'s, and nothing
/// makes them agree — a bump will drift silently, with no compiler error. That
/// is tolerable at 0.0.0 and stops being tolerable the moment the version
/// means something; the fix then is a build option, not a sharper comment.
pub const default_user_agent = "zurl/0.0.0";

/// Where a request body comes from.
///
/// `bytes` was the whole of it in v0, on the grounds that nothing needed more.
/// Uploads are what changed that: `ycs.put` holds an entire artifact in memory
/// only because there was no other way to hand one over.
pub const RequestBody = union(enum) {
    /// Already in memory. Sent with a `content-length`.
    bytes: []const u8,
    /// Read from `source` as it is sent, so the body is never held whole.
    ///
    /// A known `len` is sent with a `content-length` and the source must
    /// deliver exactly that many bytes — running short is an error, because
    /// the length has already gone out and the origin is counting. A null
    /// `len` is sent with `transfer-encoding: chunked`, which is how a body of
    /// unknown size is framed.
    stream: struct {
        source: *Io.Reader,
        len: ?u64 = null,
    },

    /// A stream can only be sent once, so a redirect that would replay the
    /// body cannot. Callers of `writeRequest` do not care; `fetch` does.
    pub fn replayable(body: *const RequestBody) bool {
        return body.* == .bytes;
    }
};

pub const Request = struct {
    method: std.http.Method = .GET,
    /// origin-form target: path plus optional query, e.g. "/metrics".
    target: []const u8 = "/",
    /// Sent as the Host header — mandatory in HTTP/1.1.
    ///
    /// Defaulted to empty only so `Session` can fill it in for a caller that
    /// has already named the origin once. Reaching `writeRequest` empty is
    /// `InvalidRequestTarget`, so a direct `Connection` caller who forgets it
    /// is told at the first request rather than sending a headless one.
    host: []const u8 = "",
    /// Convenience for the two headers every control-plane caller in the
    /// benchmark repo sets; anything else goes in `extra`.
    authorization: ?[]const u8 = null,
    content_type: ?[]const u8 = null,
    /// Sent as `user-agent`. Null sends none, which is what a caller supplying
    /// its own through `extra` wants — nothing here deduplicates, so leaving
    /// both set sends the header twice.
    user_agent: ?[]const u8 = default_user_agent,
    extra: []const Header = &.{},
    /// What to send as the request body, if anything.
    body: ?RequestBody = null,
    /// When false, sends `connection: close` — the reply then has somewhere
    /// to stop even if the server can't frame it (the benchmark's a60a95c).
    keep_alive: bool = true,
};

/// Where the response body goes. No "none" variant, on purpose: forgetting to
/// route the body is unrepresentable (design rule 1, born as d4ad5fa).
pub const Sink = union(enum) {
    discard,
    collect: *Io.Writer.Allocating,
    lines: *LineSink,
    /// Any other Io.Writer.
    stream: *Io.Writer,
};

/// The class of a status code, as RFC 9110 §15 divides them.
///
/// A caller deciding whether to retry needs this and `Response.throttled`;
/// what it does with them is its own business, because whether replaying a
/// request is safe is something only the caller knows (docs/SCOPE.md).
pub const StatusClass = enum {
    informational,
    success,
    redirect,
    client_error,
    server_error,
};

pub const Response = struct {
    status: u16,
    body_len: u64,

    /// Which of RFC 9110's five classes this status belongs to.
    pub fn class(r: Response) StatusClass {
        // Range-checked by the parser before a Response can exist.
        assert(r.status >= 100);
        assert(r.status <= 999);

        return switch (r.status / 100) {
            1 => .informational,
            2 => .success,
            3 => .redirect,
            4 => .client_error,
            // 5xx, and also the 6xx-9xx no RFC defines. An origin sending one
            // has malfunctioned, which is a server error by any reading — and
            // the alternative, a sixth class, would make every caller handle a
            // case that means nothing.
            else => .server_error,
        };
    }

    /// Whether the origin said "not now, try later".
    ///
    /// 429 and 503 are the two that carry `Retry-After` in practice and the
    /// two where retrying is the intended response rather than a gamble. Kept
    /// separate from `class` because they span two classes and mean one thing.
    pub fn throttled(r: Response) bool {
        assert(r.status >= 100);
        assert(r.status <= 999);

        return r.status == 429 or r.status == 503;
    }

    pub fn ok(r: Response) bool {
        // A Response only ever comes from a round trip, which range-checked
        // the status — the same precondition `Head.bodyless` states.
        assert(r.status >= 100);
        assert(r.status <= 999);

        return r.status == 200;
    }
};

pub const Error = parser.Error || Io.Writer.Error || RequestError || error{
    /// A previous response on this connection said close (or was
    /// close-delimited, or errored): HTTP framing forbids another request.
    ConnectionNotReusable,
};

/// Refusals raised before a single byte of the request is written.
///
/// Every one of these is a field the caller supplied that cannot appear where
/// it was going to be interpolated. They are errors and not assertions on
/// purpose: these values arrive from whatever string the caller was handed —
/// a URL from a config file, an upstream redirect, a bucket key — so a leaf
/// library that asserted on them would panic its consumer, and one that
/// asserted in Debug would simply do the wrong thing in ReleaseFast, where
/// `std.debug.assert` is compiled out.
pub const RequestError = error{
    /// The method, target or host cannot go in a request line. A space or a
    /// CR/LF in the target ends the line early, and everything after it is
    /// read by the origin as another header or another request — so this is
    /// request-header injection through a URL, not a cosmetic complaint.
    InvalidRequestTarget,
    /// A header name is not a token, or a value carries a byte that cannot
    /// appear in a field value. Same injection, one line further down.
    InvalidRequestHeader,
    /// An `extra` header names something `writeRequest` decides for itself.
    ///
    /// Sending both puts two framing headers on one request, which is the
    /// same disagreement the parser refuses on the RESPONSE side as a
    /// smuggling primitive (rule 2): an intermediary and an origin can pick
    /// different ones and disagree about where the body ends.
    ///
    /// Only the headers zurl OWNS are reserved. `authorization`,
    /// `content-type` and `user-agent` are not, because each has a field that
    /// can be nulled — supplying your own through `extra` is a documented way
    /// to use them, and refusing it would break the advice.
    ReservedRequestHeader,
    /// A streamed request body failed part-way, or ended before the
    /// `content-length` already sent for it. Distinct from `WriteFailed`,
    /// which is the transport: this is the caller's own source, and the
    /// connection is desynchronised either way.
    RequestBodyFailed,
};

pub const Connection = struct {
    in: *Io.Reader,
    out: *Io.Writer,
    /// False once framing forbids another request on this transport. Errors
    /// also clear it: after a malformed response there is no knowing where in
    /// the stream the next one would begin.
    reusable: bool = true,

    pub fn init(in: *Io.Reader, out: *Io.Writer) Connection {
        // The reader's buffer is a real bound — it limits the longest head
        // line the parser can ever see, and a zero-length one fails every
        // response for a reason that has nothing to do with the response.
        assert(in.buffer.len > 0);
        // `out` gets no length assertion: zero means "unbuffered", which is a
        // legitimate choice, and the TLS transport's writer is exactly that.
        // An earlier assertion here forbade it — a claim about what had not
        // happened yet rather than about what cannot.
        //
        // What IS still an invariant is the thing that actually broke. std
        // documents a zero-length buffer as making the DEFAULT flush a no-op,
        // so an unbuffered writer that kept it would silently swallow
        // `writeRequest`'s closing flush and the request would never reach the
        // wire — which is precisely how the TLS transport first failed, as an
        // UnexpectedEof out of the parser.
        if (out.buffer.len == 0) assert(out.vtable.flush != Io.Writer.defaultFlush);

        return .{ .in = in, .out = out };
    }

    /// One request/response exchange. The head is parsed, the body is decoded
    /// and delivered to `sink`, and `reusable` is updated from what the
    /// exchange actually was — not from what the request asked for.
    pub fn roundTrip(c: *Connection, req: Request, sink: Sink, opts: parser.HeadOptions) Error!Response {
        // No assertion on `host` or `target` here. They are caller input, and
        // `writeRequest` returns InvalidRequestTarget for an empty one — an
        // assert would panic a consumer in Debug for a case the API already
        // answers with an error, and would vanish in ReleaseFast.
        if (!c.reusable) return error.ConnectionNotReusable;
        // Any error leaves the stream at an offset nobody knows, so no further
        // request can be framed on this transport.
        errdefer c.reusable = false;

        try writeRequest(c.out, req);
        const head = try parser.parseHead(c.in, opts);
        return c.finishBody(head, req.method, sink, opts, req.keep_alive);
    }

    /// Deliver the body of a head already read, and settle reuse.
    ///
    /// Split out of `roundTrip` so a caller that must SEE the head before
    /// choosing where its body goes can do that without a second copy of this
    /// logic. `fetch` needs exactly that for redirects: the body of a 3xx it
    /// is about to follow must not reach the caller's sink, and the status
    /// that decides it is only known once the head is parsed.
    ///
    /// `keep_alive_requested` is what the request asked for; the verdict is
    /// still the exchange's.
    pub fn finishBody(
        c: *Connection,
        head: parser.Head,
        method: std.http.Method,
        sink: Sink,
        opts: parser.HeadOptions,
        keep_alive_requested: bool,
    ) Error!Response {
        // Same reason as `roundTrip`: a body that fails part-way leaves the
        // stream at an offset nobody knows.
        errdefer c.reusable = false;

        var discard_buf: [512]u8 = undefined;
        var discarding: Io.Writer.Discarding = .init(&discard_buf);
        const w: *Io.Writer = switch (sink) {
            .discard => &discarding.writer,
            .collect => |a| &a.writer,
            .lines => |l| &l.writer,
            .stream => |s| s,
        };

        const body = try parser.streamBody(c.in, head, method, w, opts);
        if (sink == .lines) sink.lines.finish();

        // Reuse is the exchange's verdict, never the request's wish: asking for
        // keep-alive cannot make a close-delimited body reusable.
        c.reusable = body.keep_alive and keep_alive_requested;
        // streamBody's postcondition, checked where it is relied on.
        if (head.bodyless(method)) assert(body.len == 0);

        return .{ .status = head.status, .body_len = body.len };
    }

    /// The probe shape: send, read the status line and headers, deliberately
    /// do NOT touch the body. The connection is never reusable afterwards —
    /// the unread body is still on the wire — which is exactly the contract a
    /// warm probe wants (it closes the transport regardless).
    pub fn roundTripHead(c: *Connection, req: Request, opts: parser.HeadOptions) Error!parser.Head {
        // Caller input, validated by `writeRequest` as an error — see roundTrip.
        if (!c.reusable) return error.ConnectionNotReusable;
        // The body is deliberately left on the wire, so nothing downstream can
        // know where the next response would begin.
        c.reusable = false;
        try writeRequest(c.out, req);
        return parser.parseHead(c.in, opts);
    }
};

/// Whether `b` may appear in a header field value.
///
/// RFC 9110 §5.5 field-value: VCHAR, SP, HTAB, and obs-text (0x80-0xFF, which
/// is deprecated but still received). Everything excluded here is a control
/// character, and the two that matter are CR and LF — those are what end a
/// header line and let a value become a line of its own.
fn isFieldValueByte(b: u8) bool {
    return b == '\t' or (b >= 0x20 and b != 0x7F);
}

/// Whether `b` may appear in a header field name.
///
/// RFC 9110 §5.6.2 token. Notably excludes the colon: a name carrying one
/// would produce a header whose name is not the name the caller asked for.
fn isTokenByte(b: u8) bool {
    return switch (b) {
        'a'...'z', 'A'...'Z', '0'...'9' => true,
        '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~' => true,
        else => false,
    };
}

/// Whether `b` may appear in an origin-form request target.
///
/// Deliberately stricter than the field-value rule: a target is delimited by
/// SPACE in the request line, so a space inside one ends it early and turns
/// the remainder into a bogus HTTP version. Non-ASCII must have been
/// percent-encoded by whoever built the URL — zurl cannot encode it here
/// without guessing whether a `?` the caller wrote is a separator or a
/// literal, which is why this refuses rather than repairs.
fn isTargetByte(b: u8) bool {
    return b > 0x20 and b != 0x7F and b < 0x80;
}

/// The request-line half of `validate`: everything that lands between the
/// method and the HTTP version, plus the host it routes on.
///
/// Public and separate because `client.zig` needs exactly this half before it
/// dials, so a URL that cannot become a request line costs no socket.
pub fn validateTarget(target: []const u8, host: []const u8) RequestError!void {
    if (target.len == 0 or host.len == 0) return error.InvalidRequestTarget;
    for (target) |b| if (!isTargetByte(b)) return error.InvalidRequestTarget;
    // The host lands in a header value, but a space or a control byte there is
    // never a real host name, and `host` is the one header an origin routes on.
    for (host) |b| if (!isTargetByte(b)) return error.InvalidRequestTarget;
}

/// Whether `writeRequest` decides this header for itself.
///
/// These four are not "headers zurl happens to send" — they are the ones that
/// say where the request goes and where its body ends. A second copy from
/// `extra` does not add a header, it creates a disagreement, and which one
/// wins is up to whatever reads the request next.
fn isReserved(name: []const u8) bool {
    const reserved = [_][]const u8{
        // Both framing. Two of either is the request-smuggling primitive.
        "content-length",
        "transfer-encoding",
        // Routing: the origin picks a virtual host from this, and zurl already
        // dialled one. Disagreeing sends a request to a host it did not open.
        "host",
        // zurl sets this from `keep_alive`, and the connection's reuse
        // bookkeeping is built on what it sent.
        "connection",
        // Not a header zurl sends — a header that changes how many responses
        // come back. An origin honouring `Expect: 100-continue` answers with
        // an interim `100 Continue` and THEN the real response, and
        // `parseHead` has no loop for that: it would return status 100 with
        // the real status line still unread, and the next request on the
        // connection would parse stale bytes. Refused until interim
        // responses are handled, because "the caller asked for it" does not
        // make a desynchronised connection the caller's fault.
        "expect",
    };

    for (reserved) |candidate| {
        if (std.ascii.eqlIgnoreCase(name, candidate)) return true;
    }
    return false;
}

/// Reject anything that cannot appear where it is about to be interpolated.
///
/// This is the whole of the request-injection defence, and it lives here
/// because `writeRequest` is the only place that composes a request — so a
/// caller reaching `Connection` directly is covered by exactly the same check
/// as one going through `fetch`.
fn validate(req: Request) RequestError!void {
    try validateTarget(req.target, req.host);

    if (req.authorization) |a| for (a) |b| {
        if (!isFieldValueByte(b)) return error.InvalidRequestHeader;
    };
    if (req.content_type) |ct| for (ct) |b| {
        if (!isFieldValueByte(b)) return error.InvalidRequestHeader;
    };
    if (req.user_agent) |ua| for (ua) |b| {
        if (!isFieldValueByte(b)) return error.InvalidRequestHeader;
    };

    for (req.extra) |h| {
        if (h.name.len == 0) return error.InvalidRequestHeader;
        for (h.name) |b| if (!isTokenByte(b)) return error.InvalidRequestHeader;
        for (h.value) |b| if (!isFieldValueByte(b)) return error.InvalidRequestHeader;
        if (isReserved(h.name)) return error.ReservedRequestHeader;
    }
}

pub fn writeRequest(out: *Io.Writer, req: Request) (Io.Writer.Error || RequestError)!void {
    // Checked BEFORE the first byte goes out, because half a request line on
    // the wire cannot be taken back: this transport would have to be dropped
    // even though nothing was wrong with it. Returning here also means every
    // field below is known interpolable, which is why nothing restates that
    // as an assertion — an assert on the line after the check that guarantees
    // it documents nothing and disappears in ReleaseFast anyway.
    try validate(req);

    try out.print("{s} {s} HTTP/1.1\r\nhost: {s}\r\n", .{
        @tagName(req.method), req.target, req.host,
    });
    if (req.user_agent) |ua| try out.print("user-agent: {s}\r\n", .{ua});
    if (req.authorization) |a| try out.print("authorization: {s}\r\n", .{a});
    if (req.content_type) |ct| try out.print("content-type: {s}\r\n", .{ct});
    // Exactly one framing header, and which one is the body's own business.
    if (req.body) |body| switch (body) {
        .bytes => |b| try out.print("content-length: {d}\r\n", .{b.len}),
        .stream => |s| if (s.len) |len|
            try out.print("content-length: {d}\r\n", .{len})
        else
            try out.writeAll("transfer-encoding: chunked\r\n"),
    };
    if (!req.keep_alive) try out.writeAll("connection: close\r\n");
    for (req.extra) |h| try out.print("{s}: {s}\r\n", .{ h.name, h.value });
    try out.writeAll("\r\n");

    if (req.body) |body| switch (body) {
        .bytes => |b| try out.writeAll(b),
        .stream => |s| if (s.len) |len| {
            // The length is already on the wire, so a source that runs short
            // has desynchronised the connection: the origin will wait for
            // bytes that are never coming.
            s.source.streamExact64(out, len) catch |err| return switch (err) {
                error.WriteFailed => error.WriteFailed,
                error.ReadFailed, error.EndOfStream => error.RequestBodyFailed,
            };
        } else try writeChunkedBody(out, s.source),
    };
    try out.flush();
}

/// Send `source` to exhaustion as chunked transfer-encoding.
///
/// Zero-copy: the reader's own buffered bytes become the chunk, so nothing is
/// staged through a second buffer. That also makes the chunk sizes whatever
/// the source happens to hand over, which is fine — chunk boundaries carry no
/// meaning, and a receiver that believes otherwise is the bug rule 4 is about.
fn writeChunkedBody(out: *Io.Writer, source: *Io.Reader) (Io.Writer.Error || RequestError)!void {
    // lint:unbounded-ok — bounded by the caller's deadline (rule 3), NOT by
    // the source being finite, and the distinction is the same one
    // `parser.scanHead` makes about the identical `fillMore` behaviour.
    //
    // Each pass either sends buffered bytes and tosses them, fills, or breaks
    // at end of stream. But `fillMore` documents that it may add zero bytes
    // without signalling EOF, and nothing stops `source` from wrapping a live
    // transport — piping one response body into the next request is exactly
    // the shape streaming exists for. So a source that never progresses and
    // never ends keeps this running, bounded by whatever is producing it.
    // `fetch` supplies rule 3's deadline; a caller driving `Connection`
    // directly owns that choice. Claiming "finite by construction" here would
    // be asserting a guarantee `scanHead` explicitly disclaims.
    while (true) {
        const chunk = source.buffered();
        if (chunk.len == 0) {
            source.fillMore() catch |err| switch (err) {
                error.EndOfStream => break,
                error.ReadFailed => return error.RequestBodyFailed,
            };
            continue;
        }

        try out.print("{x}\r\n", .{chunk.len});
        try out.writeAll(chunk);
        try out.writeAll("\r\n");
        source.toss(chunk.len);
    }

    // The loop only breaks at a real end of stream, so the source is drained
    // and the zero-length chunk that follows is the truth rather than a guess.
    assert(source.buffered().len == 0);

    // A zero-length chunk terminates the body, and the second CRLF closes an
    // empty trailer section — a receiver reads both or keeps waiting.
    try out.writeAll("0\r\n\r\n");
}

// ---------------------------------------------------------------------------
// tests

const t = std.testing;

test "round trips over an in-memory transport, keep-alive bookkeeping included" {
    // The transport is a pair of fixed buffers — rule 5's payoff: no socket,
    // no Io implementation, same code path as production.
    const wire = "HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nhi" ++
        "HTTP/1.1 200 OK\r\nconnection: close\r\ncontent-length: 2\r\n\r\nok";
    var in: Io.Reader = .fixed(wire);
    var out_buf: [1024]u8 = undefined;
    var out: Io.Writer = .fixed(&out_buf);

    var conn = Connection.init(&in, &out);

    var body: Io.Writer.Allocating = .init(t.allocator);
    defer body.deinit();
    const r1 = try conn.roundTrip(.{ .host = "test" }, .{ .collect = &body }, .{});
    try t.expectEqual(@as(u16, 200), r1.status);
    try t.expectEqualStrings("hi", body.written());
    try t.expect(conn.reusable);

    const r2 = try conn.roundTrip(.{ .host = "test" }, .discard, .{});
    try t.expectEqual(@as(u64, 2), r2.body_len);
    try t.expect(!conn.reusable); // server said close

    try t.expectError(error.ConnectionNotReusable, conn.roundTrip(.{ .host = "test" }, .discard, .{}));

    // And the request side wrote well-formed HTTP.
    const sent = out.buffered();
    try t.expect(std.mem.startsWith(u8, sent, "GET / HTTP/1.1\r\nhost: test\r\n"));
}

test "request serialization: auth, content-type, body, close" {
    var out_buf: [1024]u8 = undefined;
    var out: Io.Writer = .fixed(&out_buf);
    try writeRequest(&out, .{
        .method = .PUT,
        .target = "/bucket/key",
        .host = "storage",
        .authorization = "Bearer tok",
        .content_type = "application/json",
        .body = .{ .bytes = "{}" },
        .keep_alive = false,
    });
    const sent = out.buffered();
    try t.expect(std.mem.startsWith(u8, sent, "PUT /bucket/key HTTP/1.1\r\n"));
    try t.expect(std.mem.indexOf(u8, sent, "authorization: Bearer tok\r\n") != null);
    try t.expect(std.mem.indexOf(u8, sent, "content-length: 2\r\n") != null);
    try t.expect(std.mem.indexOf(u8, sent, "connection: close\r\n") != null);
    try t.expect(std.mem.endsWith(u8, sent, "\r\n\r\n{}"));
}

test "a request field that cannot be interpolated is refused, and nothing is written" {
    // Header injection through a URL. Every one of these would otherwise be
    // written verbatim into a request line or a header line, and everything
    // after an embedded CRLF is read by the origin as another header — or,
    // with a second CRLF, as another request entirely.
    const cases = [_]struct { Request, anyerror }{
        // Request line.
        .{ .{ .host = "h", .target = "/a\r\nX-Injected: 1" }, error.InvalidRequestTarget },
        .{ .{ .host = "h", .target = "/a\nX: 1" }, error.InvalidRequestTarget },
        .{ .{ .host = "h", .target = "/a b" }, error.InvalidRequestTarget },
        .{ .{ .host = "h", .target = "" }, error.InvalidRequestTarget },
        // The host is what an origin routes on, so it gets the same rule.
        .{ .{ .host = "h\r\nX: 1", .target = "/" }, error.InvalidRequestTarget },
        .{ .{ .host = "", .target = "/" }, error.InvalidRequestTarget },
        // Header lines. `authorization` is the dangerous one: it is the field
        // most likely to be built from something a caller was handed.
        .{ .{ .host = "h", .authorization = "Bearer x\r\nX: 1" }, error.InvalidRequestHeader },
        .{ .{ .host = "h", .content_type = "text/plain\r\nX: 1" }, error.InvalidRequestHeader },
        .{ .{ .host = "h", .extra = &.{.{ .name = "x", .value = "a\r\nY: 2" }} }, error.InvalidRequestHeader },
        // A name that is not a token: the colon would rename the header, the
        // space would produce a line no origin parses as the caller intended.
        .{ .{ .host = "h", .extra = &.{.{ .name = "x:y", .value = "1" }} }, error.InvalidRequestHeader },
        .{ .{ .host = "h", .extra = &.{.{ .name = "x y", .value = "1" }} }, error.InvalidRequestHeader },
        .{ .{ .host = "h", .extra = &.{.{ .name = "", .value = "1" }} }, error.InvalidRequestHeader },
    };

    for (cases) |case| {
        const req, const want = case;
        var out_buf: [512]u8 = undefined;
        var out: Io.Writer = .fixed(&out_buf);
        try t.expectError(want, writeRequest(&out, req));
        // The refusal has to come before any output. Half a request line on
        // the wire would force the caller to drop a transport that was fine.
        try t.expectEqual(@as(usize, 0), out.end);
    }
}

test "the bytes a valid request is allowed to carry" {
    // The complement of the test above: obs-text and a tab are legal in a
    // field value and must NOT be refused, or the check breaks real requests
    // to make a point. A `?` and a `%` are ordinary target bytes.
    var out_buf: [512]u8 = undefined;
    var out: Io.Writer = .fixed(&out_buf);
    try writeRequest(&out, .{
        .host = "example.com",
        .target = "/p%20ath?q=1&r=%C3%A9",
        .content_type = "text/plain;\tcharset=utf-8",
        .extra = &.{.{ .name = "x-note", .value = "caf\xc3\xa9" }},
    });
    try t.expect(std.mem.startsWith(u8, out.buffered(), "GET /p%20ath?q=1&r=%C3%A9 HTTP/1.1\r\n"));
    try t.expect(std.mem.indexOf(u8, out.buffered(), "x-note: caf\xc3\xa9\r\n") != null);
}

test "a user-agent is sent by default, suppressible, and validated like any value" {
    // Sent because its absence is a failure a caller cannot see in a status:
    // some APIs reject a UA-less request outright, so "no header" becomes a
    // 403 with nothing in it to explain why.
    var buf: [512]u8 = undefined;
    var out: Io.Writer = .fixed(&buf);
    try writeRequest(&out, .{ .host = "example.com" });
    try t.expect(std.mem.indexOf(u8, out.buffered(), "user-agent: " ++ default_user_agent ++ "\r\n") != null);

    // Null suppresses it, which is what a caller sending its own through
    // `extra` needs — nothing here deduplicates.
    var buf2: [512]u8 = undefined;
    var out2: Io.Writer = .fixed(&buf2);
    try writeRequest(&out2, .{ .host = "example.com", .user_agent = null });
    try t.expect(std.mem.indexOf(u8, out2.buffered(), "user-agent") == null);

    // And it is a field value like any other: no free pass for a default that
    // a caller can override with something the wire cannot carry.
    var buf3: [512]u8 = undefined;
    var out3: Io.Writer = .fixed(&buf3);
    try t.expectError(error.InvalidRequestHeader, writeRequest(&out3, .{
        .host = "example.com",
        .user_agent = "evil\r\nX-Injected: 1",
    }));
    try t.expectEqual(@as(usize, 0), out3.end);
}

test "a streamed body is framed by its length, or chunked when it has none" {
    // The point of streaming: `ycs.put` held a whole artifact in memory only
    // because bytes was the only shape there was.

    // Known length: content-length, and the bytes go out verbatim.
    var src1: Io.Reader = .fixed("hello world");
    var buf1: [512]u8 = undefined;
    var out1: Io.Writer = .fixed(&buf1);
    try writeRequest(&out1, .{
        .host = "h",
        .method = .PUT,
        .body = .{ .stream = .{ .source = &src1, .len = 11 } },
    });
    try t.expect(std.mem.indexOf(u8, out1.buffered(), "content-length: 11\r\n") != null);
    try t.expect(std.mem.indexOf(u8, out1.buffered(), "transfer-encoding") == null);
    try t.expect(std.mem.endsWith(u8, out1.buffered(), "\r\n\r\nhello world"));

    // Unknown length: chunked, terminated by the zero chunk.
    var src2: Io.Reader = .fixed("hello world");
    var buf2: [512]u8 = undefined;
    var out2: Io.Writer = .fixed(&buf2);
    try writeRequest(&out2, .{
        .host = "h",
        .method = .PUT,
        .body = .{ .stream = .{ .source = &src2 } },
    });
    try t.expect(std.mem.indexOf(u8, out2.buffered(), "transfer-encoding: chunked\r\n") != null);
    try t.expect(std.mem.indexOf(u8, out2.buffered(), "content-length") == null);
    try t.expect(std.mem.endsWith(u8, out2.buffered(), "\r\n\r\nb\r\nhello world\r\n0\r\n\r\n"));

    // An empty source is still a well-framed chunked body, not a hang.
    var src3: Io.Reader = .fixed("");
    var buf3: [512]u8 = undefined;
    var out3: Io.Writer = .fixed(&buf3);
    try writeRequest(&out3, .{ .host = "h", .method = .PUT, .body = .{ .stream = .{ .source = &src3 } } });
    try t.expect(std.mem.endsWith(u8, out3.buffered(), "\r\n\r\n0\r\n\r\n"));
}

test "a source that runs short of its declared length is an error, not a silent truncation" {
    // The content-length is already on the wire, so the origin is counting.
    // Reporting success here would leave the connection desynchronised and
    // the object half-written — exactly the class rule 7 refuses.
    var src: Io.Reader = .fixed("only七");
    var buf: [512]u8 = undefined;
    var out: Io.Writer = .fixed(&buf);
    try t.expectError(error.RequestBodyFailed, writeRequest(&out, .{
        .host = "h",
        .method = .PUT,
        .body = .{ .stream = .{ .source = &src, .len = 9999 } },
    }));
}

/// A reader that hands over one piece at a time and sometimes makes no
/// progress at all, which `Io.Reader.fixed` never does.
///
/// `fillMore` returning zero bytes WITHOUT signalling end of stream is
/// documented std behaviour and is the case `writeChunkedBody`'s bound is
/// written about — a TLS transport consuming a session ticket does exactly
/// this. Without a reader that reproduces it, that loop is only ever tested
/// on the one-chunk-then-EOF path.
const StutteringReader = struct {
    interface: Io.Reader,
    pieces: []const []const u8,
    next: usize = 0,
    /// Zero-progress fills still owed before the next piece is handed over.
    stalls: usize,
    stalls_per_piece: usize,

    fn init(buffer: []u8, pieces: []const []const u8, stalls_per_piece: usize) StutteringReader {
        return .{
            .interface = .{ .vtable = &.{ .stream = stream }, .buffer = buffer, .seek = 0, .end = 0 },
            .pieces = pieces,
            .stalls = stalls_per_piece,
            .stalls_per_piece = stalls_per_piece,
        };
    }

    fn stream(r: *Io.Reader, w: *Io.Writer, limit: Io.Limit) Io.Reader.StreamError!usize {
        const self: *StutteringReader = @alignCast(@fieldParentPtr("interface", r));
        if (self.next == self.pieces.len) return error.EndOfStream;
        if (self.stalls > 0) {
            self.stalls -= 1;
            // No bytes, no error: exactly what std permits and what the bound
            // in `writeChunkedBody` has to survive.
            return 0;
        }
        self.stalls = self.stalls_per_piece;
        const piece = self.pieces[self.next];
        self.next += 1;
        return w.write(limit.sliceConst(piece)) catch return error.WriteFailed;
    }
};

test "chunked framing survives a source that stalls and arrives in pieces" {
    // Three pieces become three chunks, and the zero-progress fills between
    // them must neither emit a chunk nor terminate the body early: a `0`
    // chunk mid-stream would end the request where the source had not.
    var read_buf: [64]u8 = undefined;
    var src = StutteringReader.init(&read_buf, &.{ "alpha", "beta", "gamma" }, 2);

    var buf: [512]u8 = undefined;
    var out: Io.Writer = .fixed(&buf);
    try writeRequest(&out, .{
        .host = "h",
        .method = .POST,
        .body = .{ .stream = .{ .source = &src.interface } },
    });

    const body_start = std.mem.indexOf(u8, out.buffered(), "\r\n\r\n").? + 4;
    try t.expectEqualStrings(
        "5\r\nalpha\r\n4\r\nbeta\r\n5\r\ngamma\r\n0\r\n\r\n",
        out.buffered()[body_start..],
    );
}

test "status classification separates the five classes from the two that mean try later" {
    const cases = [_]struct { u16, StatusClass, bool }{
        .{ 100, .informational, false },
        .{ 200, .success, false },
        .{ 204, .success, false },
        .{ 302, .redirect, false },
        .{ 404, .client_error, false },
        // Throttling spans two classes and means one thing, which is why it
        // is its own question rather than a sixth class.
        .{ 429, .client_error, true },
        .{ 500, .server_error, false },
        .{ 503, .server_error, true },
        // No RFC defines a 6xx. An origin sending one has malfunctioned, and
        // calling that a server error is the only reading that does not
        // invite a caller to treat it as success.
        .{ 699, .server_error, false },
    };

    for (cases) |case| {
        const status, const want_class, const want_throttled = case;
        const res: Response = .{ .status = status, .body_len = 0 };
        try t.expectEqual(want_class, res.class());
        try t.expectEqual(want_throttled, res.throttled());
    }
}

test "an extra header that zurl decides for itself is refused" {
    // Two framing headers on one request is the same disagreement the parser
    // refuses on the response side: an intermediary and an origin can pick
    // different ones and disagree about where the body ends.
    const reserved = [_][]const u8{
        "content-length", "Content-Length", "transfer-encoding",
        "host",           "HOST",           "connection",
        // Not a header zurl sends, but one that changes how many responses
        // come back: parseHead has no interim-response loop, so a 100
        // Continue would be returned as the answer with the real status
        // line left on the wire.
        "expect",         "Expect",
    };
    for (reserved) |name| {
        var buf: [512]u8 = undefined;
        var out: Io.Writer = .fixed(&buf);
        try t.expectError(error.ReservedRequestHeader, writeRequest(&out, .{
            .host = "h",
            .body = .{ .bytes = "hi" },
            .extra = &.{.{ .name = name, .value = "0" }},
        }));
        try t.expectEqual(@as(usize, 0), out.end);
    }

    // The three with a nullable field of their own are NOT reserved: nulling
    // the field and supplying your own through `extra` is documented advice,
    // and refusing it would break that.
    var buf: [512]u8 = undefined;
    var out: Io.Writer = .fixed(&buf);
    try writeRequest(&out, .{
        .host = "h",
        .user_agent = null,
        .extra = &.{
            .{ .name = "user-agent", .value = "mine/1" },
            .{ .name = "authorization", .value = "Bearer x" },
            .{ .name = "content-type", .value = "application/json" },
            .{ .name = "x-anything", .value = "fine" },
        },
    });
    try t.expect(std.mem.indexOf(u8, out.buffered(), "user-agent: mine/1\r\n") != null);
    try t.expect(std.mem.indexOf(u8, out.buffered(), "x-anything: fine\r\n") != null);
}
