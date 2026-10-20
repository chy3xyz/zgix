//! Streaming HTTP/1.1 origin proxy for the HTTP/3 session layer.
//!
//! One HTTP/3 request becomes one TCP exchange: render an HTTP/1.1
//! request, connect to the selected origin (or check out the origin's
//! parked keep-alive connection), send it, and stream the response back
//! as it arrives — the head the moment it parses, then body chunks
//! relayed per read. Content-Length, `Transfer-Encoding: chunked`
//! (decoded incrementally) and close-delimited bodies all ride the one
//! streaming path; the reply never needs to fit a staging buffer.
//!
//! Scope, deliberately:
//!
//! - Plaintext `http` origins, or TLS ones for clusters whose config
//!   carries a `tls` block. The TLS dial runs the same sans-I/O client
//!   engine the HTTP/1.1 path dials with (`tls/UpstreamTls.zig`, reached
//!   file-relatively so this file names no `zssl` type — the lint's
//!   crypto boundary stays in `src/tls/`), with the trust decision fed
//!   in from the runtime: one cluster `tls` block drives both protocols,
//!   so verify/CA/SNI semantics cannot drift between them. A checked-out
//!   parked TLS connection keeps its engine, so reuse never re-runs a
//!   handshake.
//! - Streaming bodies. Each response body is still capped at
//!   `Options.max_response_bytes` (64 KiB by default, a config may raise
//!   the ceiling to 16 MiB): the cap is a policy bound, enforced as the
//!   body crosses it — a body past the cap mid-stream is cut off with a
//!   stream reset (witnessed `bad_gateway`), never a silent truncation.
//! - A short `H3Session.sendData` is backpressure, not an error: the
//!   exchange parks the unsent tail, stops reading the origin, and resumes
//!   on the listener's window notify (`setWindowNotify`). The live
//!   listener wires only the plain send today, and that fallback spells
//!   the same conditions — a full datagram queue, a flow-control window
//!   the peer has not raised — as errors; those park identically.
//! - `Options.timeout_ns` (10 s by default, 0 disables) bounds one
//!   exchange end to end — dial, send and the streamed read. An exchange
//!   still running at expiry is answered 504 before its head is sent,
//!   reset mid-body after; a refused or malformed origin keeps its 502.
//!   One coarse proxy-owned timer serves every exchange and the
//!   parked-pool idle reaping, in the listener's arm-when-needed,
//!   scan-on-fire shape. Streaming moves more bytes per exchange, so a
//!   deployment forwarding large bodies wants `h3_exchange_ms` raised —
//!   the deadline is absolute, not refreshed by activity.
//! - Keep-alive pooling, the `UpstreamPool` design (DESIGN.md §5) at
//!   h3 scale: at most one parked connection per (cluster, endpoint),
//!   checked out LIFO by the round-robin pick. The pool is an accelerator,
//!   not a limiter — a checkout miss dials fresh, so a parked slot is fd
//!   state only, never a queue. A connection parks only when its response
//!   ended on an explicit frame (Content-Length met, the terminating
//!   chunk, a no-body status) and did not announce `Connection: close`;
//!   a truncated or aborted exchange closes the connection — never parks,
//!   never retries. An origin that silently closed a parked connection is
//!   discovered at checkout: the first send or recv fails and the exchange
//!   is answered 502 — never retried, because a retried non-idempotent
//!   request is a correctness bug wearing a reliability costume. Parked
//!   connections are reaped by the same timer after
//!   `constants.h3_pool_idle_ns` (30 s) idle.
//!
//! The pure request rendering, response-head parsing and the incremental
//! chunked decoder are testable without an Io backend. The generic
//! `Proxy` owns fixed exchange slots, so the data path allocates nothing
//! after `initInPlace`.

const std = @import("std");

const Io = @import("../../io/io.zig");
const constants = @import("../../constants.zig");

const request_stream = @import("request_stream.zig");
const session = @import("session.zig");
const connection = @import("connection.zig");

// The upstream TLS client engine and its trust store are zgix-side files
// shared with the HTTP/1.1 path, reached file-relatively so the `h3-check`
// build compiles them without the seam importing the zssl module by name
// (the lint boundary keeps that text in src/tls/). See `Cluster.tls`.
const UpstreamTls = @import("../../tls/UpstreamTls.zig");
const TrustStore = @import("../../tls/TrustStore.zig");
const Pool = @import("../../mem/Pool.zig").Pool;

/// The largest rendered HTTP/1.1 request head: the request line, the
/// synthesized Host/Connection/framing headers and every forwarded header.
/// A request h3 accepts decodes at most `request_stream.header_block_bytes_max`
/// (16 KiB) of header block; rendered, that is the block plus ~4 bytes of
/// `name: value\r\n` overhead per decoded header (at most
/// `request_stream.headers_max` of them) plus the request line itself —
/// 24 KiB covers the worst case the parser can hand us.
const request_head_bytes_max: usize = 24 * 1024;

/// The response head accumulates here until it parses; a head past 8 KiB
/// is refused like any malformed reply.
const response_head_bytes_max: usize = 8 * 1024;

/// One body chunk staged per read. The streaming path never needs more:
/// `sendData` either accepts the chunk or parks it, and the decoded-body
/// cap bounds the total, not the staging memory.
const chunk_bytes: usize = 16 * 1024;

/// Cap one `sendData` payload at what the session's single-packet
/// fallback always carries. The listener wires only the plain `send`
/// today, and that path hard-errors `ChunkTooLarge` past
/// `connection.max_stream_frame_payload` — the DATA frame header rides
/// in the same packet, so the payload stays a margin under it. A
/// `send_multi`-wired sender seals larger frames across datagrams
/// anyway; the cap only splits the body into a few more DATA frames,
/// invisible to the peer's parse stream.
const send_unit_bytes: usize = connection.max_stream_frame_payload - 16;

/// The default per-response-body cap: `constants.h3_response_bytes_max`.
const response_bytes_default: usize = constants.h3_response_bytes_max;

/// Forwarded response headers are bounded so one hostile origin cannot turn
/// the response buffer into an unbounded header table.
const response_headers_max: usize = 32;

pub const Options = struct {
    /// Per-exchange upstream budget in nanoseconds, stamped when the
    /// exchange begins: the dial, the send and the buffered read must all
    /// finish inside it or the exchange is answered 504. 0 disables the
    /// deadline. One coarse proxy-owned timer scans for expiry; a stalled
    /// dial is canceled, a stalled send/recv is shutdown-forced to a
    /// terminal completion.
    timeout_ns: u64 = 10 * std.time.ns_per_s,
    /// Per-response-body cap, enforced as the body streams: a body past it
    /// is cut off mid-stream (after the head went out, that is a stream
    /// reset witnessed `bad_gateway`). A `Content-Length` past it is
    /// refused before the head is sent and keeps the 502. Defaults to
    /// `constants.h3_response_bytes_max`; a config may set the ceiling
    /// `constants.h3_response_bytes_limit`.
    max_response_bytes: usize = response_bytes_default,
    /// Idle variant of `timeout_ns`: any application progress in either
    /// direction — an uploaded body piece, a parsed response head, a
    /// relayed body chunk — resets `now + idle_timeout_ns`, so a stream
    /// that keeps moving (SSE, a deliberate drip) outlives the absolute
    /// budget. The exchange expires on whichever deadline comes first.
    /// 0 disables it: the absolute budget is the only clock.
    idle_timeout_ns: u64 = 0,
    /// The listener's own error pages, one body per verdict family,
    /// null where the config names none and the built-in text answers.
    /// Borrowed slices — the embedder's config arena owns the bytes for
    /// the process's life, exactly the L7 static-response table's
    /// lifetime, so the serving path sends one immutable slice and
    /// copies nothing.
    error_pages: ErrorPages = .{},
    /// The process counters this proxy witnesses into, or null when the
    /// embedder has none. An untyped context plus an event callback
    /// rather than a counters-module pointer: the seam must keep building
    /// standalone (`zig build h3-check`), whose module cannot import the
    /// counters module's transitive dependencies (hparse, zssl). The
    /// adapter that fills this in owns the counter names, so the seam
    /// itself carries no `zgix_` vocabulary and stays testable with the
    /// hook null.
    counters: ?Counters = null,
};

/// One optional page body per verdict family the proxy answers itself.
/// The status line the answer wears is the family's own (404/502/504) —
/// these bytes replace only the built-in body text.
pub const ErrorPages = struct {
    /// The 404 a request no route matches is answered with.
    no_route: ?[]const u8 = null,
    /// The 502 the gateway's own failures are answered with.
    bad_gateway: ?[]const u8 = null,
    /// The 504 an exchange the upstream outlived is answered with.
    gateway_timeout: ?[]const u8 = null,
};

/// A witness hook into an embedder-owned counter set, installed through
/// `Options.counters`. Not a counter set itself: the mapping from event
/// to counter name lives in the adapter (one switch, the
/// `KernelPressureOp.counter()` precedent), so a seam-side event a name
/// forgot cannot compile as a misspelled field, and the library builds
/// without the counters module at all.
///
/// The hook carries `Details` with the answer events (and null with the
/// request and connection events): one pointer hands the adapter every
/// fact an access-log line needs without the seam knowing the log exists.
pub const Counters = struct {
    ctx: *anyopaque,
    note: *const fn (ctx: *anyopaque, event: Event, details: ?*const Details) void,

    /// Every observable verdict of the h3 serving path: the proxy's
    /// per-request events and the listener's per-session events share one
    /// hook, so one adapter switch owns the whole `h3_*` family.
    pub const Event = enum {
        /// A request head reached the request handler (before the
        /// exchange-slot acquire). Fired with null details — the
        /// exchange (and its `Details`) does not exist yet, and the
        /// request's own facts ride the answer event below.
        request,
        /// An origin answer was relayed to the client. Carries `Details`.
        response,
        /// The exchange was answered 502. Carries `Details`.
        bad_gateway,
        /// The exchange was answered 504 — the per-exchange deadline
        /// fired. Carries `Details`.
        gateway_timeout,
        /// No exchange slot was free; the request was answered 503.
        /// Carries `Details` (built on the handler's stack: a shed
        /// request never owns an exchange).
        shed_busy,
        /// No route matched the request; answered 404 without a dial.
        /// Carries `Details` (built on the handler's stack, like the
        /// shed's) — the `l7_no_route` sibling, the fifth verdict
        /// bucket beside `response`/`bad_gateway`/`gateway_timeout`/
        /// `shed_busy`.
        no_route,
        /// A QUIC session took a listener connection slot.
        connection_opened,
        /// A session released its slot, on any teardown path.
        connection_closed,
    };
};

/// Per-request facts handed to the witness hook with the answer events.
/// The slices point at this struct's own fixed buffers, copied at request
/// begin: the request head's slices borrow the parser slot, which the
/// session may release as soon as the handler returns, long before the
/// asynchronous exchange settles.
///
/// `bytes_in`/`bytes_out` count payload bytes — the request body and the
/// response body the client was sent — not wire bytes. The TCP log line
/// counts what crossed the socket; the h3 slice counts what the proxy
/// owned, because the QUIC-TLS framing length is the transport's, not
/// the proxy's.
pub const Details = struct {
    method: []const u8 = &.{},
    path: []const u8 = &.{},
    /// The request's `:authority` verbatim (empty when it carried none);
    /// lowercasing and port-stripping are the Record builder's job.
    authority: []const u8 = &.{},
    /// The client's UDP address (set from `H3Session.peer`).
    peer: std.Io.net.IpAddress = undefined,
    /// The origin endpoint the dial picked, or null while the dial is
    /// outstanding (or, for a shed request, forever).
    endpoint: ?std.Io.net.IpAddress = null,
    /// The seam cluster the route table selected — the index into the
    /// proxy's `clusters` the embedder installed, which the witness maps
    /// back to the configured cluster name. 0 where no dial happened (a
    /// shed request, whose table is the listener's first referenced
    /// cluster anyway — the verdict a shed reports names no route).
    cluster_index: u16 = 0,
    /// Set from the matched route's `access_log`: false suppresses the
    /// access-log line the answer event would have written, while the
    /// counters the same witness hook increments stay — the L7
    /// `access_log off` at a location, nothing more.
    suppress_log: bool = false,
    started_wall_ns: u64 = 0,
    started_mono_ns: u64 = 0,
    /// Request body bytes carried (see the struct doc).
    bytes_in: u64 = 0,
    /// Answer-time fields, filled where the verdict commits:
    status: u16 = 0,
    /// Response body bytes relayed — the origin's body on `response`, the
    /// error page's on the failure verdicts (see the struct doc).
    bytes_out: u64 = 0,

    // The storage the slices above point at. One struct keeps every fact
    // a witness needs behind the one pointer the hook passes.
    method_buf: [constants.access_log_method_bytes_max]u8 = undefined,
    path_buf: [constants.access_log_path_bytes_max]u8 = undefined,
    authority_buf: [constants.host_bytes_max]u8 = undefined,
};

/// Copy `source` into `target` for later logging, truncating with a
/// trailing `...` rather than dropping it — `access_log.captureTruncated`
/// verbatim, which the seam cannot import (access_log pulls config and
/// Server; the seam builds standalone under `h3-check`). Keep the two in
/// step.
fn captureLogged(target: []u8, source: []const u8) []const u8 {
    const marker = "...";
    assert(target.len > marker.len);
    if (source.len <= target.len) {
        @memcpy(target[0..source.len], source);
        return target[0..source.len];
    }
    const kept = target.len - marker.len;
    @memcpy(target[0..kept], source[0..kept]);
    @memcpy(target[kept..][0..marker.len], marker);
    return target[0..target.len];
}

/// A route's header predicate, `router.HeaderMatch`'s two kinds folded
/// to one optional: `equals` non-null is an exact-value match, null is
/// presence. The seam cannot import `http/router.zig` — the router pulls
/// the parser, and the seam builds standalone under `h3-check` — so
/// `config.zig`'s adapter lowers the resolved `router.HeaderMatch` into
/// this shape, and the two must stay in step (`resolveRouteHeader` is
/// the single producer of both).
pub const HeaderMatch = struct {
    name: []const u8,
    /// null matches the header's presence; non-null its exact value.
    equals: ?[]const u8,
};

/// One routing rule on this listener's table: a canonical host scope
/// (null matches any host), an optional header predicate, and a
/// canonical path prefix — a conjunction, exactly `router.Route`'s
/// shape, kept locally because the seam cannot import the router (see
/// `HeaderMatch`). The sort that makes the first match the answer —
/// host, then header, then prefix — is config-load order, shared with
/// the L7 table through the same `resolveRoutes`; this matcher only
/// implements the predicate.
pub const Route = struct {
    host: ?[]const u8 = null,
    prefix: []const u8,
    /// The #302 predicate the request must satisfy, beyond host and
    /// prefix; null matches any request.
    header: ?HeaderMatch = null,
    /// The cluster the rule selects — an index into the proxy's
    /// `clusters`, installed at startup.
    cluster_index: u16 = 0,
    /// Whether a request this rule answers is written to the access
    /// log. False suppresses only the line — the counters ride the same
    /// witness hook and stay, the L7 `access_log off` precedent
    /// (`RouteJson.access_log`): "counters, metrics and admission are
    /// unchanged".
    access_log: bool = true,
};

/// One cluster's dial state: the endpoints the config loader resolved for
/// it, the round-robin cursor walking them, and its optional upstream TLS
/// — the config's cluster `tls` block, adapted once at startup from the
/// same `ClusterTls.Runtime` the HTTP/1.1 path builds, so both protocols
/// verify an origin identity with the same anchors, name and policy. Owned
/// mutably by the proxy — the cursor advances per dial — and shared by
/// every route that selects the cluster, so a cluster named by several
/// routes keeps one rotation.
pub const Cluster = struct {
    endpoints: []const std.Io.net.IpAddress,
    next_endpoint: usize = 0,
    /// Upstream TLS for every dial this cluster makes, or null when the
    /// cluster has no `tls` block and dials in the clear.
    tls: ?Tls = null,
};

/// The seam-side shape of one cluster's upstream TLS block. The runtime
/// adapter fills this from `tls/ClusterTls.zig`'s loaded runtime, and the
/// dial hands the pieces to `UpstreamTls` verbatim — the seam owns no
/// verification logic, so `verify: false`, the CA bundle, the SNI name
/// and an mTLS identity mean exactly what they mean on the TCP path.
pub const Tls = struct {
    /// The SNI value sent and the name the origin's leaf is matched
    /// against (RFC 9525) — the config's `server_name`, never defaulted
    /// from an endpoint literal.
    server_name: []const u8,
    /// The trust anchors `server_name` is verified against, or null when
    /// the config set `verify: false` — the policy, not the file, decides
    /// whether an origin identity is checked, exactly as `ClusterTls.load`
    /// spells it. Borrowed from the loaded runtime for the process's life.
    trust: ?*const TrustStore = null,
    /// The mTLS identity presented when the origin asks for a client
    /// certificate, or null when the cluster names no client pair. Typed
    /// through the engine's own config field so this file names no zssl
    /// type — the lint's crypto boundary keeps that import in src/tls/.
    client_credentials: ?ClientCredentials = null,
};

/// `*const zssl.Credentials`, reached without the zssl import text this
/// file may not carry (lint confines that boundary to src/tls/).
const ClientCredentials =
    @typeInfo(@FieldType(UpstreamTls.Config, "client_credentials")).optional.child;

/// A session-teardown registration, installed on the listener through
/// `Listener.setExchangeTeardown`. The listener calls `forget` with a
/// session pointer right before `H3Session.deinit`, so the proxy can
/// deregister every in-flight exchange that names the dying session —
/// closing its socket or canceling its dial without ever answering the
/// session, which is being torn down and must not be touched. The
/// callback shape (untyped ctx, session pointer) keeps the seam free of
/// any zgix import, the same constraint the `Counters` hook answers.
pub const SessionTeardown = struct {
    ctx: *anyopaque,
    forget: *const fn (ctx: *anyopaque, h3: *session.H3Session) void,
};

/// The matched route for a canonical `host` (empty when the request
/// carried no usable authority, meeting only any-host routes), `path`
/// and `headers`, or null when nothing matches — the caller's 404, the
/// `l7_no_route` verdict of the TCP path. `routes` is sorted
/// most-specific-first at config load, so the first match is the
/// answer: host outermost, a route naming a header before one that
/// does not, then the longest prefix. The scan keeps in step with
/// `http/router.zig`.
pub fn find(
    routes: []const Route,
    host: []const u8,
    path: []const u8,
    headers: []const request_stream.Header,
) ?*const Route {
    assert(routes.len >= 1);
    assert(path.len >= 1);
    assert(path[0] == '/');
    for (routes) |*candidate| {
        if (!hostMatches(candidate.host, host)) continue;
        if (candidate.header) |predicate| {
            if (!headerMatches(predicate, headers)) continue;
        }
        if (prefixMatches(candidate.prefix, path)) return candidate;
    }
    return null;
}

/// `router.headerMatches`'s two route kinds, on the seam's request
/// shape: the name compares case-insensitively (a header field name),
/// the value exactly. Keep in step with `http/router.zig`.
fn headerMatches(predicate: HeaderMatch, headers: []const request_stream.Header) bool {
    assert(predicate.name.len >= 1); // A validated RFC 9110 token.
    for (headers) |header| {
        if (!std.ascii.eqlIgnoreCase(header.name, predicate.name)) continue;
        if (predicate.equals) |expected| {
            if (std.mem.eql(u8, header.value, expected)) return true;
        } else {
            return true;
        }
    }
    return false;
}

/// An any-host route (`route_host == null`) matches every request. A
/// host-scoped route matches only when the request carried a usable
/// authority and it equals the route's — so a request with none (the
/// `host` this matcher takes as empty) meets only the any-host routes,
/// exactly `router.hostMatches`'s null rule. Keep the two in step.
fn hostMatches(route_host: ?[]const u8, requested: []const u8) bool {
    const scoped = route_host orelse return true;
    if (requested.len == 0) return false;
    return std.mem.eql(u8, scoped, requested);
}

/// A prefix matches only when it covers whole path segments: the path
/// equals the prefix, the prefix is slash-terminated, or the byte right
/// after the prefix is `/`. So `/api` matches `/api` and `/api/v1` but
/// never `/apihost` — a string prefix that splits a segment is not a
/// route. `/` is slash-terminated, so the root prefix is the catch-all.
/// `router.prefixMatches` verbatim, which the seam cannot import; keep
/// the two in step.
pub fn prefixMatches(prefix: []const u8, path: []const u8) bool {
    assert(prefix.len >= 1);
    assert(prefix[0] == '/');
    assert(path.len >= 1);
    assert(path[0] == '/');
    if (!std.mem.startsWith(u8, path, prefix)) {
        return false;
    }
    if (path.len == prefix.len) {
        return true;
    }
    assert(path.len > prefix.len);
    if (prefix[prefix.len - 1] == '/') {
        return true;
    }
    return path[prefix.len] == '/';
}

/// The canonical host a route comparison keys on: the request's
/// `:authority`, lowercased with any port stripped — `h3_runtime.zig`'s
/// `canonicalAuthority` verbatim, which the seam cannot import, so the
/// fold lives here for matching and there for the log line, and the two
/// must stay in step. An empty or oversize authority canonicalizes to
/// "", meeting only any-host routes, the spelling "the request carried
/// none" wears on the TCP path too.
fn canonicalAuthority(
    authority: []const u8,
    out: *[constants.host_bytes_max]u8,
) []const u8 {
    if (authority.len == 0 or authority.len > out.len) return "";
    // An IPv6 literal wears brackets with colons of its own, so its port
    // starts only after the ']'; a plain host's first colon is the port's.
    const authority_end = if (authority[0] == '[')
        (std.mem.indexOfScalar(u8, authority, ']') orelse return "") + 1
    else
        std.mem.indexOfScalar(u8, authority, ':') orelse authority.len;
    if (authority_end == 0) return "";
    for (authority[0..authority_end], 0..) |byte, index| {
        out[index] = std.ascii.toLower(byte);
    }
    return out[0..authority_end];
}

pub const ResponseHead = struct {
    status: u16,
    body_start: usize,
    content_length: ?usize,
    chunked: bool,
    no_body: bool,
    close_delimited: bool,
    /// The origin announced `Connection: close` (or carried the token in
    /// a list): the response may be complete, but the connection will not
    /// carry another request.
    connection_close: bool,
    /// Whether the fully-received response leaves the connection fit to
    /// park for reuse: framed to an explicit end (Content-Length, the
    /// terminating chunk, or a no-body status — not close-delimited, whose
    /// end is the origin's EOF) and not announcing `Connection: close`.
    /// Computed at head parse; `complete` parks only when this is true.
    reusable: bool,
    headers: [response_headers_max]request_stream.Header = undefined,
    header_count: usize = 0,
};

const error_headers = [_]request_stream.Header{
    .{ .name = "content-type", .value = "text/plain" },
};

/// How one request's body travels to the origin, decided while the head
/// renders. The h3 request is length-agnostic (the QUIC stream's end is the
/// body's end); the HTTP/1.1 origin is not, so the proxy commits to a
/// framing before the first body byte arrives.
pub const UploadFraming = union(enum) {
    /// The client carried `Content-Length`: the value re-renders verbatim
    /// (a valid header is canonical digits anyway) and the upload sends
    /// exactly this many body bytes, no more and no less.
    content_length: u64,
    /// No `Content-Length`: the proxy generates `Transfer-Encoding:
    /// chunked` and frames each body piece `hex\r\n<piece>\r\n`, closing
    /// with the `0\r\n\r\n` terminator at fin.
    chunked,
    /// The stream's FIN rode the HEADERS frame and no `Content-Length`
    /// was declared: the request is head-only and the upload owes the
    /// origin nothing — no framing header, no bytes, no terminator. An
    /// empty upload is exactly "the upload already completed", not a
    /// chunked body of length zero.
    none,
};

/// The rendered request head plus the framing decision it committed to.
pub const RenderedHead = struct {
    len: usize,
    framing: UploadFraming,
};

/// Render one HTTP/1.1 request head — the request line and headers only;
/// the body travels afterward, piece by piece, per `framing`. Hop-by-hop
/// and framing headers are dropped: the proxy owns `Connection`,
/// `Content-Length`/`Transfer-Encoding`, `Host` and `Expect`. A client
/// `Content-Length` is validated (decimal, and any duplicates must agree)
/// and passed through; without one the proxy commits to chunked — unless
/// `bodyless` (the HTTP/3 stream's FIN arrived with the HEADERS frame and
/// no length was declared) commits it to nothing instead. `keep_alive`
/// picks the `Connection` value the proxy wants from the origin: pooled
/// exchanges ask for `keep-alive`, the close spelling remains for callers
/// that know the connection dies with this request.
pub fn renderRequestHead(
    out: []u8,
    method: []const u8,
    path: []const u8,
    authority: []const u8,
    headers: []const request_stream.Header,
    bodyless: bool,
    keep_alive: bool,
) !RenderedHead {
    if (!validToken(method)) return error.InvalidRequest;
    if (!validPath(path)) return error.InvalidRequest;
    if (!validAuthority(authority)) return error.InvalidRequest;

    var content_length: ?u64 = null;
    for (headers) |header| {
        if (!std.ascii.eqlIgnoreCase(header.name, "content-length")) continue;
        const value = std.mem.trim(u8, header.value, " \t");
        const parsed = std.fmt.parseInt(u64, value, 10) catch
            return error.InvalidRequest;
        if (content_length) |existing| {
            // RFC 9110 §8.6's duplicate rule for intermediaries: identical
            // duplicates consolidate, conflicting ones are refused.
            if (existing != parsed) return error.InvalidRequest;
        }
        content_length = parsed;
    }

    var writer: std.Io.Writer = .fixed(out);
    writer.print("{s} {s} HTTP/1.1\r\nHost: {s}\r\nConnection: {s}\r\n", .{
        method,
        path,
        authority,
        if (keep_alive) "keep-alive" else "close",
    }) catch return error.RequestTooLarge;
    for (headers) |header| {
        if (!forwardedRequestHeader(header.name)) continue;
        if (!validToken(header.name) or !validValue(header.value)) return error.InvalidRequest;
        writer.print("{s}: {s}\r\n", .{ header.name, header.value }) catch
            return error.RequestTooLarge;
    }
    if (content_length) |expected| {
        writer.print("Content-Length: {d}\r\n", .{expected}) catch
            return error.RequestTooLarge;
    } else if (!bodyless) {
        writer.writeAll("Transfer-Encoding: chunked\r\n") catch
            return error.RequestTooLarge;
    }
    writer.writeAll("\r\n") catch return error.RequestTooLarge;
    return .{
        .len = writer.end,
        .framing = if (content_length) |expected|
            UploadFraming{ .content_length = expected }
        else if (bodyless)
            UploadFraming.none
        else
            .chunked,
    };
}

/// Parse the status line and headers of one HTTP/1.x response. Returns
/// `error.Incomplete` until the blank line has arrived; slices in `headers`
/// borrow `bytes`.
pub fn parseResponseHead(bytes: []const u8) !ResponseHead {
    const terminator = std.mem.indexOf(u8, bytes, "\r\n\r\n") orelse return error.Incomplete;
    // With no headers, the terminator's first CRLF is the status line's own.
    const line_end = std.mem.indexOf(u8, bytes[0..terminator], "\r\n") orelse terminator;
    const line = bytes[0..line_end];
    const first_space = std.mem.indexOfScalar(u8, line, ' ') orelse return error.BadResponse;
    if (!std.mem.startsWith(u8, line[0..first_space], "HTTP/1.")) return error.BadResponse;
    // RFC 9112 §9.3: an HTTP/1.x connection's default persistence is
    // close for 1.0, keep-alive for 1.1 — so a 1.0 reply that did not
    // declare "Connection: keep-alive" is one the pool must not trust,
    // whatever its framing. An origin that silently closed is paid for
    // at the next checkout with a failed send; defaulting 1.0 to close
    // spares a request that cost.
    const http10 = std.mem.eql(u8, line[0..first_space], "HTTP/1.0");
    const rest = std.mem.trimStart(u8, line[first_space + 1 ..], " ");
    if (rest.len < 3) return error.BadResponse;
    const status = std.fmt.parseInt(u16, rest[0..3], 10) catch return error.BadResponse;
    if (status < 100) return error.BadResponse;

    var head = ResponseHead{
        .status = status,
        .body_start = terminator + 4,
        .content_length = null,
        .chunked = false,
        .no_body = status / 100 == 1 or status == 204 or status == 304,
        .close_delimited = false,
        .connection_close = false,
        .reusable = false,
    };

    var declares_keep_alive = false;
    var offset = line_end + 2;
    while (offset < terminator) {
        // The four-byte terminator search starts at the last header's
        // trailing CRLF, so that line ends at `terminator` itself.
        const newline = std.mem.indexOfPos(u8, bytes[0..terminator], offset, "\r\n") orelse
            terminator;
        const header_line = bytes[offset..newline];
        offset = newline + 2;

        const colon = std.mem.indexOfScalar(u8, header_line, ':') orelse continue;
        const name = std.mem.trim(u8, header_line[0..colon], " \t");
        const value = std.mem.trim(u8, header_line[colon + 1 ..], " \t");
        if (name.len == 0) continue;

        if (std.ascii.eqlIgnoreCase(name, "content-length")) {
            head.content_length = std.fmt.parseInt(usize, value, 10) catch
                return error.BadResponse;
        } else if (std.ascii.eqlIgnoreCase(name, "transfer-encoding")) {
            if (containsIgnoreCase(value, "chunked")) head.chunked = true;
        } else if (std.ascii.eqlIgnoreCase(name, "connection")) {
            if (containsIgnoreCase(value, "close")) head.connection_close = true;
            if (containsIgnoreCase(value, "keep-alive")) declares_keep_alive = true;
        }
        if (forwardedResponseHeader(name) and head.header_count < head.headers.len) {
            head.headers[head.header_count] = .{ .name = name, .value = value };
            head.header_count += 1;
        }
    }

    if (http10 and !declares_keep_alive) head.connection_close = true;
    head.close_delimited = head.content_length == null and !head.chunked and !head.no_body;
    head.reusable = !head.close_delimited and !head.connection_close;
    return head;
}

/// Incremental `Transfer-Encoding: chunked` decoder. The streaming proxy
/// feeds it whatever `recv` delivered — a SimIo delivery may split
/// anywhere, so the size line, the chunk data and the trailing CRLF each
/// carry their own progress — and it reports, per step, how many bytes
/// were framing (consume), how many are payload to relay, or that the
/// body terminated. The pump loop performs the sends; the decoder holds
/// only parse state, so a parked send resumes mid-chunk exactly where it
/// stopped.
///
/// `limit` is the decoded-body cap: a reply whose *decoded* size exceeds
/// it is refused (checked when a size line parses), the streaming twin of
/// the buffered slice's over-cap 502 — here, mid-stream, the caller cuts
/// the reply off with a stream reset instead.
pub const ChunkedDecoder = struct {
    state: State = .size_line,
    /// Bytes of the current chunk-size line seen so far (the CRLF is
    /// recognized as they arrive; the line keeps its `\r` until then).
    line: [chunk_size_line_bytes_max]u8 = undefined,
    line_len: usize = 0,
    /// Size of the chunk whose payload is being read.
    size: usize = 0,
    /// Payload bytes of the current chunk read so far.
    data_read: usize = 0,
    /// Decoded-body total so far, for the cap.
    decoded: u64 = 0,
    /// Bytes of the payload's trailing CRLF matched so far.
    crlf: u8 = 0,
    /// Whether the previous trailer byte was CR (empty-line detection).
    last_was_cr: bool = false,

    pub const State = enum { size_line, data, data_crlf, trailers, done };

    /// One decoder decision over `tail` (never empty). The pump applies
    /// it: `consume`/`done` advance `consumed`, `payload` is a send whose
    /// accepted byte count advances both `consumed` and `data_read`.
    pub const Step = union(enum) {
        /// n framing bytes at `tail[0..n]`; nothing to send.
        consume: usize,
        /// n payload bytes at `tail[0..n]` to relay (fin is never here;
        /// the body's fin follows the terminating chunk).
        payload: usize,
        /// The terminating chunk's final CRLF arrived at `tail[0]`; the
        /// body is complete.
        done: void,
        /// `tail` held only a partial frame; the caller reads more.
        need_more: void,
    };

    /// The largest chunk-size line accepted: sixteen hex digits cover a
    /// `usize` with room for a short `;ext=...`; a longer line is a
    /// hostile origin probing for buffer, refused like bad framing.
    pub const chunk_size_line_bytes_max: usize = 64;

    /// Run one step over `tail`, mutating parse state. `error.BadResponse`
    /// is malformed framing; `error.ResponseTooLarge` is the decoded cap.
    pub fn step(self: *ChunkedDecoder, tail: []const u8, limit: usize) !Step {
        assert(tail.len >= 1);
        switch (self.state) {
            .size_line => {
                for (tail, 0..) |byte, index| {
                    if (byte == '\n' and self.line_len > 0 and
                        self.line[self.line_len - 1] == '\r')
                    {
                        const size = try parseChunkSize(self.line[0 .. self.line_len - 1]);
                        self.line_len = 0;
                        if (size == 0) {
                            self.state = .trailers;
                            self.last_was_cr = false;
                        } else {
                            self.size = size;
                            self.data_read = 0;
                            self.decoded += size;
                            if (self.decoded > limit) return error.ResponseTooLarge;
                            self.state = .data;
                        }
                        return .{ .consume = index + 1 };
                    }
                    if (self.line_len >= self.line.len) return error.BadResponse;
                    self.line[self.line_len] = byte;
                    self.line_len += 1;
                }
                return .need_more;
            },
            .data => {
                const want = self.size - self.data_read;
                return .{ .payload = @min(want, tail.len) };
            },
            .data_crlf => {
                const want: u8 = if (self.crlf == 0) '\r' else '\n';
                if (tail[0] != want) return error.BadResponse;
                self.crlf += 1;
                if (self.crlf == 2) {
                    self.crlf = 0;
                    self.state = .size_line;
                }
                return .{ .consume = 1 };
            },
            .trailers => {
                const byte = tail[0];
                if (byte == '\n' and self.last_was_cr) {
                    self.state = .done;
                    return .{ .done = {} };
                }
                self.last_was_cr = byte == '\r';
                return .{ .consume = 1 };
            },
            .done => return .{ .done = {} },
        }
    }
};

fn parseChunkSize(line: []const u8) !usize {
    const size_text = if (std.mem.indexOfScalar(u8, line, ';')) |semi|
        line[0..semi]
    else
        line;
    return std.fmt.parseInt(usize, std.mem.trim(u8, size_text, " \t"), 16) catch
        return error.BadResponse;
}

fn forwardedRequestHeader(name: []const u8) bool {
    // `expect` joins the RFC 9110 connection-options list: 100-continue's
    // "hold the request until I say go" contract has no meaning at an
    // intermediary that forwards as it receives — the proxy answers the
    // client's 100-continue itself (RFC 9110 §10.1.1) by simply proceeding.
    const blocked = [_][]const u8{
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
        "host",
        "content-length",
        "expect",
    };
    for (blocked) |item| {
        if (std.ascii.eqlIgnoreCase(name, item)) return false;
    }
    return true;
}

fn forwardedResponseHeader(name: []const u8) bool {
    const allowed = [_][]const u8{
        "content-type",
        "cache-control",
        "etag",
        "last-modified",
        "expires",
        "content-language",
    };
    for (allowed) |item| {
        if (std.ascii.eqlIgnoreCase(name, item)) return true;
    }
    return false;
}

fn containsIgnoreCase(haystack: []const u8, needle: []const u8) bool {
    if (needle.len == 0) return true;
    if (haystack.len < needle.len) return false;
    var index: usize = 0;
    while (index + needle.len <= haystack.len) : (index += 1) {
        if (std.ascii.eqlIgnoreCase(haystack[index..][0..needle.len], needle)) return true;
    }
    return false;
}

fn validToken(text: []const u8) bool {
    if (text.len == 0) return false;
    for (text) |byte| {
        if (byte <= 0x20 or byte >= 0x7f or byte == ':') return false;
    }
    return true;
}

fn validPath(text: []const u8) bool {
    if (text.len == 0) return false;
    for (text) |byte| {
        if (byte <= 0x20 or byte >= 0x7f) return false;
    }
    return true;
}

fn validAuthority(text: []const u8) bool {
    if (text.len == 0) return false;
    for (text) |byte| {
        if (byte == '\r' or byte == '\n' or byte == 0) return false;
    }
    return true;
}

fn validValue(text: []const u8) bool {
    for (text) |byte| {
        if (byte == '\r' or byte == '\n' or byte == 0) return false;
    }
    return true;
}

pub fn Proxy(comptime IoType: type, comptime max_exchanges: usize) type {
    comptime Io.assertIoInterface(IoType);
    comptime {
        if (max_exchanges == 0) @compileError("an h3 proxy needs one exchange slot");
    }

    return struct {
        const Self = @This();

        comptime {
            // The banner's per-slot figure must cover the real slot,
            // including the TLS dial fields — the Server precedent that
            // keeps a bumped engine a decision rather than a drift.
            assert(@sizeOf(Exchange) <= constants.h3_exchange_slot_bytes);
            // The engine is the unit the h3 budget prices per TLS dial,
            // the same bound the TCP path's pool asserts.
            assert(@sizeOf(UpstreamTls) <= constants.upstream_tls_engine_bytes_max);
        }

        /// One parked keep-alive upstream connection. A parked slot is fd
        /// state only: it holds no armed op, just the socket, its TLS
        /// engine when the cluster dials TLS, and the idle deadline the
        /// proxy's one timer compares against. At most one slot exists
        /// per (cluster, endpoint) pair — `dial` checks the round-robin
        /// pick's slot before it dials — so a fresh checkout never queues
        /// behind a parked connection; a miss dials.
        const Parked = struct {
            socket: IoType.Socket,
            /// The session this connection handshook, kept with it exactly
            /// like the TCP path's pooled upstream slot: a parked TLS
            /// connection checks out with its engine, so the next request
            /// rides the live session instead of re-running a handshake.
            /// Null on a plaintext cluster's dial.
            tls: ?*UpstreamTls,
            cluster_index: u16,
            endpoint_index: u16,
            /// Absolute idle deadline (`park + constants.h3_pool_idle_ns`).
            deadline_ns: u64,
        };

        /// What checking out a parked connection hands back: the socket
        /// and, for a TLS dial, the connected engine parked beside it.
        const CheckedOut = struct {
            socket: IoType.Socket,
            tls: ?*UpstreamTls,
        };

        /// How one response's body is framed, decided at head parse. All
        /// three modes stream; `none` finishes at the head.
        const BodyMode = enum { none, content_length, chunked, close_delimited };

        const Exchange = struct {
            active: bool = false,
            proxy: *Self = undefined,
            h3: *session.H3Session = undefined,
            stream_id: u64 = 0,
            /// The completion behind every upload send: the dial's
            /// handshake flights, then the request head and body sends.
            /// Full duplex split: the response path's reads arm
            /// `serve_completion`, so both directions of one upstream
            /// socket hold their own op (one send + one recv, the layout
            /// both Io backends serve natively).
            completion: IoType.Completion = .{},
            /// The response path's read completion (see `completion`).
            serve_completion: IoType.Completion = .{},
            /// Whether an upload send (or a handshake flight on the same
            /// completion) is currently armed.
            send_armed: bool = false,
            /// Whether the response path's read is currently armed.
            recv_armed: bool = false,
            socket: ?IoType.Socket = null,
            /// The engine driving this exchange's TLS dial, or null on a
            /// plaintext one. Held from the dial's engine acquisition (or
            /// the parked checkout that handed it over) until the
            /// connection settles — `finish`, `discard` and a non-parking
            /// `dispose` all return it through `releaseTls`.
            tls: ?*UpstreamTls = null,
            /// Plaintext bytes of the open send unit that are staged in
            /// the engine's outbox but not yet credited to
            /// `send_offset`: the wire carries ciphertext, so the request
            /// cursor advances only once the record holding a chunk has
            /// drained. Zero on a plaintext dial and between units.
            tls_send_staged: usize = 0,
            /// Set by the decrypt sink when a record carried head bytes
            /// past the response-head cap with no terminator: the
            /// plaintext path's oversize-head 502, reached mid-record.
            tls_head_overflow: bool = false,
            /// Set by the decrypt sink when the origin's close_notify
            /// arrives: the orderly-EOF twin of `onEof`, deferred to the
            /// end of the current drive so plaintext already decrypted
            /// relays first.
            tls_peer_closed: bool = false,
            /// The verifier context the handshake borrows, built at dial
            /// from the cluster's trust store, name and wall clock — the
            /// engine copies it into its own slot at `init`, so this frame
            /// only has to outlive the call. Null when verification is
            /// off, which is when `cluster.tls.trust` is.
            tls_trust: ?TrustStore.Context = null,
            /// The endpoint this exchange is talking to, as picked (and
            /// possibly checked out) by `dial`: the pool key the socket
            /// parks under in `complete`. Unconditional where the witness
            /// facts are not — pool bookkeeping runs with no hook installed.
            cluster_index: u16 = 0,
            endpoint_index: u16 = 0,
            /// Set when the deadline timer claims this exchange: whichever
            /// completion the force then produces converts to a 504. The
            /// timer's scans skip a flagged exchange, so the verdict is
            /// delivered exactly once. Cleared at `begin` for the next
            /// exchange on the slot.
            timed_out: bool = false,
            /// Set when the listener tears the session down: the verdict
            /// must never reach a dying session, so the completion the
            /// forced shutdown/cancel produces funnels into `discard`
            /// instead of `fail`/`complete`. Checked before `timed_out`:
            /// teardown outranks even a committed 504, because the 504's
            /// answer would be written into deiniting memory. Cleared at
            /// `begin` for the next exchange on the slot.
            deregistered: bool = false,
            /// The absolute upstream deadline (`begin + timeout_ns`), or 0
            /// when the exchange carries no deadline. Cleared when the
            /// verdict commits (`finish`/`discard`) so the timer never
            /// re-selects a settled exchange.
            deadline_ns: u64 = 0,
            /// The idle variant: re-stamped to `now + idle_timeout_ns`
            /// at every application-level progress point (see
            /// `noteProgress`), or 0 where the option is off. The
            /// exchange expires on whichever of the two comes first;
            /// the timer scan reads `effectiveDeadline`, never either
            /// field alone.
            idle_deadline_ns: u64 = 0,
            /// The connectCancel op's own completion (§4: a cancel runs on
            /// a second, caller-owned completion), used while the dial is
            /// in flight — the deadline timeout and session teardown share
            /// it, since an exchange can be claimed by at most one of them.
            /// It cycles dead→pending→dead within the one cancel that arms
            /// it, so `begin` leaves it alone.
            cancel_completion: IoType.Completion = .{},

            /// The rendered request head (`renderRequestHead`), sent before
            /// any body byte. The buffer outlives the head: nothing else
            /// aliases it until the slot's next exchange.
            request_buf: [request_head_bytes_max]u8 = undefined,
            request_len: usize = 0,
            send_offset: usize = 0,
            /// How the body travels upstream, committed at render: the
            /// client's `Content-Length` verbatim, or generated chunked.
            framing: UploadFraming = .chunked,
            /// Body bytes accepted from the client so far. In
            /// Content-Length mode the fin-bearing piece must land the
            /// count exactly on the declared value; chunked mode counts
            /// toward the witness only.
            uploaded: u64 = 0,
            /// The client's fin arrived: every body byte is queued or
            /// already sent, and for chunked framing the `0\r\n\r\n`
            /// terminator is staged behind them.
            upload_fin: bool = false,
            /// The upload settled — the fin (and terminator) reached the
            /// origin, or the origin died after answering and the
            /// orphaned upload was abandoned. Settling alone does not
            /// finish the exchange: full duplex lets the response run
            /// concurrently, so completion is `serve_done && upload
            /// settled` (see `maybeComplete`).
            upload_settled: bool = false,
            /// Set when the origin's connection died (or the deadline
            /// fired) after the response completed: bytes the client
            /// sent were consumed but can never reach the origin, so the
            /// connection can never park whatever its head announced.
            upload_abandoned: bool = false,
            /// The upload FIFO, living in `upload_buf` with the
            /// `upload_spill` overflow: wire-format body bytes — chunked
            /// framing applied at append time — drained from the front
            /// by `sendMore`. Full duplex owns the buffers per
            /// direction: the response stages in `chunk`/`head_buf`
            /// while the upload still queues here, so the two pumps run
            /// concurrently on one exchange.
            q_head: usize = 0,
            q_tail: usize = 0,
            sp_head: usize = 0,
            sp_tail: usize = 0,
            /// Upload-side staging (see the FIFO cursors above). Sized
            /// like the response's `chunk`: one origin send-unit burst.
            upload_buf: [chunk_bytes]u8 = undefined,
            /// The upload FIFO's spill, taking over the role `head_buf`
            /// played under the half-duplex seam (where the two
            /// directions time-shared the one buffer).
            upload_spill: [response_head_bytes_max]u8 = undefined,

            /// The response head accumulates here until it parses. Body
            /// bytes that arrive in the same reads move to `chunk` once
            /// the head is on the wire.
            head_buf: [response_head_bytes_max]u8 = undefined,
            head_len: usize = 0,
            /// The parsed head, set the moment `sendResponseHead` accepts
            /// it — from here on a failure cannot be answered with an
            /// error page, only a stream reset.
            head: ?ResponseHead = null,
            head_sent: bool = false,
            /// A HEAD request owns no response body whatever the status:
            /// the origin sends none, so the exchange finishes at the
            /// head and the connection is framed like a no-body reply
            /// (reusable unless it announced `Connection: close`).
            no_body_override: bool = false,

            /// The body streams through this one staging buffer: bytes
            /// the origin sent live at `chunk[0..chunk_len]`, the
            /// decoder's progress is `consumed`, and the unsent tail of a
            /// backpressured send is `chunk[consumed..chunk_len]`.
            chunk: [chunk_bytes]u8 = undefined,
            chunk_len: usize = 0,
            consumed: usize = 0,

            /// Body framing, decided at head parse.
            mode: BodyMode = .none,
            /// content_length mode: body bytes still owed to the client.
            cl_remaining: u64 = 0,
            /// close-delimited mode: body bytes received so far, for the
            /// response cap.
            body_received: u64 = 0,
            chunked: ChunkedDecoder = .{},

            /// The response side is fully relayed — head parsed (1xx
            /// intermediates skipped), body drained, fin reached the
            /// client — and witnessed. Not the exchange's end: under
            /// full duplex the upload may still be draining, and
            /// `maybeComplete` settles only when both directions are
            /// done.
            serve_done: bool = false,
            /// The head's reuse verdict, committed at `finishBody`:
            /// parked only if the response completed cleanly, the head
            /// announced persistence, and neither an EOF nor an
            /// abandoned upload poisoned the connection.
            serve_reusable: bool = false,
            /// An upstream EOF (or send error — the socket is dead
            /// either way) observed before the settle: whatever the
            /// head announced, a connection watched die never parks.
            saw_eof: bool = false,
            /// A verdict — `fail`, `abortBody`, or the teardown's
            /// `discard` — committed while an op on the other direction
            /// was still armed: the sibling's delivery must not run its
            /// normal path (nor witness a second verdict). Checked in
            /// every completion's prologue, ahead of `timed_out`.
            verdict_committed: bool = false,

            /// Backpressure state. A short `sendData` parks the unsent
            /// tail and stops the upstream recv; the listener's window
            /// notify resumes the exchange. `fin_pending` carries a fin
            /// the parked tail could not deliver (a close-delimited EOF
            /// arriving while paused).
            paused: bool = false,
            fin_pending: bool = false,
            /// The open send unit: its remaining length and its fin, so
            /// a resumed send retries exactly the unsent tail — the
            /// session's continuation contract demands the retry be
            /// precisely the open frame's remainder, no more, no less.
            unit_len: usize = 0,
            unit_fin: bool = false,

            /// The facts the witness hook reports with the answer event.
            /// Only touched while a hook is installed (`capture` at
            /// `begin`): with none, an exchange never reads a clock and
            /// never copies a header.
            details: Details = .{},

            fn begin(
                self: *Exchange,
                proxy: *Self,
                h3: *session.H3Session,
                stream_id: u64,
                request: *const request_stream.Request,
            ) void {
                self.active = true;
                self.proxy = proxy;
                self.h3 = h3;
                self.stream_id = stream_id;
                self.completion = .{};
                self.serve_completion = .{};
                self.send_armed = false;
                self.recv_armed = false;
                self.socket = null;
                self.tls = null;
                self.tls_send_staged = 0;
                self.tls_head_overflow = false;
                self.tls_peer_closed = false;
                self.tls_trust = null;
                self.cluster_index = 0;
                self.endpoint_index = 0;
                self.timed_out = false;
                self.deregistered = false;
                self.deadline_ns = 0;
                self.idle_deadline_ns = 0;
                self.request_len = 0;
                self.send_offset = 0;
                self.framing = .chunked;
                self.uploaded = 0;
                self.upload_fin = false;
                self.upload_settled = false;
                self.upload_abandoned = false;
                self.q_head = 0;
                self.q_tail = 0;
                self.sp_head = 0;
                self.sp_tail = 0;
                self.head_len = 0;
                self.head = null;
                self.head_sent = false;
                self.no_body_override = std.mem.eql(u8, request.method, "HEAD");
                self.chunk_len = 0;
                self.consumed = 0;
                self.mode = .none;
                self.cl_remaining = 0;
                self.body_received = 0;
                self.chunked = .{};
                self.serve_done = false;
                self.serve_reusable = false;
                self.saw_eof = false;
                self.verdict_committed = false;
                self.paused = false;
                self.fin_pending = false;
                self.unit_len = 0;
                self.unit_fin = false;
                if (proxy.options.timeout_ns != 0) {
                    self.deadline_ns = IoType.nowNs(proxy.io) + proxy.options.timeout_ns;
                }
                if (proxy.options.idle_timeout_ns != 0) {
                    self.idle_deadline_ns = IoType.nowNs(proxy.io) +
                        proxy.options.idle_timeout_ns;
                    proxy.armTimerAt(self.idle_deadline_ns);
                }
                if (proxy.options.counters != null) self.capture(request);
            }

            /// Copy the request head's facts into `details` and stamp
            /// both clocks. The slices borrow the parser slot, which does
            /// not outlive this callback; the copies are what the answer
            /// event (an arbitrary number of loop turns later) may read.
            /// The synthesized dial authority is not the request's: a
            /// missing `:authority` logs as an empty host, exactly like a
            /// missing Host header does on the TCP path.
            fn capture(self: *Exchange, request: *const request_stream.Request) void {
                self.details.method = captureLogged(&self.details.method_buf, request.method);
                self.details.path = captureLogged(&self.details.path_buf, request.path);
                self.details.authority = captureLogged(
                    &self.details.authority_buf,
                    request.authority orelse "",
                );
                self.details.peer = self.h3.peer;
                self.details.endpoint = null;
                self.details.started_wall_ns = IoType.nowWallNs(self.proxy.io);
                self.details.started_mono_ns = IoType.nowNs(self.proxy.io);
                // Body bytes accumulate per received chunk (the client's
                // body streams in after this callback, past the capture):
                // the count a shed verdict never reaches starts at zero.
                self.details.bytes_in = 0;
                self.details.status = 0;
                self.details.bytes_out = 0;
            }

            fn fail(self: *Exchange, status: u16, fallback: []const u8) void {
                // The verdict commits here and nowhere else: every 502/504
                // path in the exchange funnels through `fail`, so the
                // witness is one switch at the choke point rather than a
                // counter at each call site. Full duplex: the commit can
                // land while the other direction's op is still armed —
                // the verdict goes out once, and the socket settles when
                // both ops have delivered (see `finish`).
                if (self.verdict_committed) return;
                self.verdict_committed = true;
                self.deadline_ns = 0;
                self.idle_deadline_ns = 0;
                // The 400 (a lying Content-Length) and any other status
                // stay on the built-in text; the 502/504 families wear a
                // configured page when the listener names one.
                const class: ?Self.ErrorClass = switch (status) {
                    502 => .bad_gateway,
                    504 => .gateway_timeout,
                    else => null,
                };
                const body = self.proxy.errorBody(class, fallback);
                self.details.status = status;
                self.details.bytes_out = body.len;
                switch (status) {
                    502 => self.proxy.noteDetails(.bad_gateway, &self.details),
                    504 => self.proxy.noteDetails(.gateway_timeout, &self.details),
                    else => {},
                }
                self.proxy.sendError(self.h3, self.stream_id, class, status, fallback);
                self.finish();
            }

            /// The verdict path's settle: close the socket, release the
            /// engine, free the slot — but only once every armed op has
            /// delivered, so no completion outlives its socket. A sibling
            /// delivery still pending re-enters here from its callback's
            /// prologue.
            fn finish(self: *Exchange) void {
                if (!self.quiet()) return;
                if (self.socket) |socket| {
                    IoType.closeNow(self.proxy.io, socket);
                    self.socket = null;
                }
                self.releaseTls();
                self.deadline_ns = 0;
                self.active = false;
            }

            /// Return a held TLS engine to the proxy's pool: the
            /// connection owning the session is gone, so the engine goes
            /// with it — a slot that left with its pointer set would
            /// strand the engine exactly like the TCP path's pool release
            /// says. Idempotent; a plaintext exchange is the null case.
            fn releaseTls(self: *Exchange) void {
                if (self.tls) |engine| {
                    engine.deinit();
                    self.proxy.tls_engines.release(engine);
                    self.tls = null;
                }
                self.tls_send_staged = 0;
                self.tls_trust = null;
            }

            /// Session teardown, the mirror of `timeOut` with no verdict:
            /// the h3 session that owns this exchange is being deinit'd,
            /// so nothing may be sent to it. Flag the exchange (its
            /// callbacks check `deregistered` before anything else and
            /// funnel into `discard`), hide it from the deadline scan, and
            /// force every armed op — both directions under full duplex —
            /// to a terminal delivery: shutdown for an established
            /// socket, connectCancel for an outstanding dial. Closing
            /// the socket here instead would strand the armed
            /// completions; the deliveries the force produces are what
            /// clean up (the last one out runs `discard`).
            fn deregister(self: *Exchange) void {
                if (!self.active or self.deregistered) return;
                self.deregistered = true;
                self.deadline_ns = 0;
                if (self.socket == null) {
                    // The dial itself is outstanding.
                    IoType.connectCancel(
                        self.proxy.io,
                        &self.completion,
                        &self.cancel_completion,
                        Exchange,
                        self,
                        onConnectCanceled,
                    );
                    return;
                }
                if (self.quiet()) {
                    // Both directions idle (an upload waiting on the
                    // client's next chunk, before the head bought a
                    // recv): no forced delivery is coming, so settle
                    // right here.
                    self.discard();
                    return;
                }
                IoType.shutdown(self.proxy.io, self.socket.?, .both);
            }

            /// The terminal cleanup for a deregistered exchange: runs from
            /// the forced deliveries (the last armed op's callback lands
            /// it in a quiet exchange), closes whatever socket
            /// materialized, and frees the slot — without answering a
            /// session that no longer exists.
            fn discard(self: *Exchange) void {
                if (!self.quiet()) return;
                if (self.socket) |socket| {
                    IoType.closeNow(self.proxy.io, socket);
                    self.socket = null;
                }
                self.releaseTls();
                self.deadline_ns = 0;
                self.idle_deadline_ns = 0;
                self.deregistered = false;
                self.active = false;
            }

            /// Whether no completion is armed on either direction. The
            /// pre-arm phases (a waiting upload, a parked response tail)
            /// are quiet; an exchange past its head credit never is,
            /// since the response read stays armed.
            fn quiet(self: *Exchange) bool {
                return !self.send_armed and !self.recv_armed;
            }

            /// The deadline the timer scan selects this exchange by:
            /// the earlier of the absolute budget and the idle budget,
            /// either alone when the other is off, 0 when neither is
            /// armed.
            fn effectiveDeadline(self: *const Exchange) u64 {
                var effective = self.deadline_ns;
                if (self.idle_deadline_ns != 0) {
                    effective = if (effective == 0)
                        self.idle_deadline_ns
                    else
                        @min(effective, self.idle_deadline_ns);
                }
                return effective;
            }

            /// Application progress in either direction: the upload took
            /// a body piece, the response head parsed, a body chunk
            /// relayed. Re-stamps the idle deadline and re-aims the
            /// shared timer — `armTimerAt`'s lazy rule no-ops while the
            /// armed target is already earlier (an absolute budget or a
            /// sibling exchange's deadline), and re-bases through the
            /// one cancel when the new idle target lands earlier. A
            /// spurious fire on a stale idle target settles itself: the
            /// tick finds nothing due and re-arms at the current
            /// earliest.
            fn noteProgress(self: *Exchange) void {
                if (self.proxy.options.idle_timeout_ns == 0) return;
                if (!self.active or self.timed_out or self.verdict_committed) return;
                self.idle_deadline_ns = IoType.nowNs(self.proxy.io) +
                    self.proxy.options.idle_timeout_ns;
                self.proxy.armTimerAt(self.idle_deadline_ns);
            }

            /// Deadline expiry, the request-deadline 504 the L7 proxy
            /// answers (RFC 9110 §15.6.5: no timely response from the
            /// upstream): flag the exchange (the timer's scans skip it,
            /// so the verdict commits once), then either commit right
            /// here — both directions quiet — or force every armed op
            /// to a terminal delivery whose callback converts (the first
            /// delivery commits; the sibling's prologue sees the
            /// committed verdict and just settles). An established
            /// socket must not be closed here: closeNow under an armed
            /// op strands the completion.
            fn timeOut(self: *Exchange) void {
                self.timed_out = true;
                if (self.socket == null) {
                    // A dial the deadline owns: connectCancel is its
                    // only legal abort, and its completion delivers
                    // error.Canceled.
                    IoType.connectCancel(
                        self.proxy.io,
                        &self.completion,
                        &self.cancel_completion,
                        Exchange,
                        self,
                        onConnectCanceled,
                    );
                    return;
                }
                if (self.quiet()) {
                    self.timeOutVerdict();
                    return;
                }
                IoType.shutdown(self.proxy.io, self.socket.?, .both);
            }

            /// The timeout's verdict, committed by whichever path got
            /// here first. After the response completed, the deadline
            /// only bounds the orphaned upload's drain: there is no
            /// second verdict for a client that already has its answer.
            fn timeOutVerdict(self: *Exchange) void {
                if (self.verdict_committed) return;
                if (self.serve_done) {
                    self.upload_abandoned = true;
                    self.upload_settled = true;
                    self.maybeComplete();
                    return;
                }
                if (self.head_sent) {
                    self.abortBody();
                } else {
                    self.fail(504, "gateway timeout\n");
                }
            }

            /// The exchange's completion, full duplex: the response is
            /// fully relayed (`finishBody`) and the upload has settled
            /// (`sendMore`'s drained fin, or an abandon) — both
            /// directions done, both completions delivered. Only here
            /// does the connection park or close.
            fn maybeComplete(self: *Exchange) void {
                if (!self.serve_done or !self.upload_settled) return;
                self.dispose(self.serve_reusable and !self.saw_eof and
                    !self.upload_abandoned);
            }

            /// Drive the request leg out: the rendered head first, then
            /// staged body bytes in region order — the upload FIFO in
            /// `upload_buf`, the `upload_spill` tail — until the client's
            /// fin (and, for chunked framing, the terminator staged
            /// behind it) has reached the origin. Full duplex: the
            /// response pump runs concurrently — the read arms the moment
            /// the head is credited (see `advanceUpload`) and the body
            /// stages ride their own `upload_buf`/`upload_spill` — so a
            /// drained upload settles this direction (`upload_settled`)
            /// while the response keeps flowing.
            ///
            /// On a plaintext dial this is one send per short write over
            /// the open region; on a TLS dial each unit is chunked through
            /// the engine (`tls_app_chunk_bytes` is what its outbox is
            /// sized against) and the wire carries the staged ciphertext —
            /// a region's cursor advances only when the record holding a
            /// unit has fully drained, so a short send resumes mid-record
            /// without re-encrypting anything.
            fn sendMore(self: *Exchange) void {
                const slice = self.nextUploadSlice() orelse {
                    // Everything staged has reached the wire. Without the
                    // client's fin the send direction idles here — the
                    // next body chunk re-drives the send — which keeps
                    // the invariant that a non-empty upload queue always
                    // owns the armed send. With the fin credited, the
                    // upload has settled; completion still waits on the
                    // response.
                    if (!self.upload_fin) return;
                    self.upload_settled = true;
                    self.maybeComplete();
                    return;
                };
                if (self.tls != null) {
                    const engine = self.tls.?;
                    if (engine.outbound().len == 0) {
                        const unit = @min(slice.len, constants.tls_app_chunk_bytes);
                        engine.sendApp(slice[0..unit]) catch {
                            // The session broke mid-request: before any
                            // response head, the verdict is the 502 page.
                            self.fail(502, "bad gateway\n");
                            return;
                        };
                        self.tls_send_staged = unit;
                    }
                    self.send_armed = true;
                    IoType.send(
                        self.proxy.io,
                        self.socket.?,
                        engine.outbound(),
                        &self.completion,
                        Exchange,
                        self,
                        onSent,
                    );
                    return;
                }
                self.send_armed = true;
                IoType.send(
                    self.proxy.io,
                    self.socket.?,
                    slice,
                    &self.completion,
                    Exchange,
                    self,
                    onSent,
                );
            }

            /// The next request-leg slice, in region order: the rendered
            /// head, the upload FIFO (after its drained prefix is
            /// compacted away), the spill moved into the FIFO's freed
            /// space. Null means every region is drained — the caller
            /// either idles (more client body may arrive) or, once fin
            /// has been staged, hands the exchange to the response pump.
            fn nextUploadSlice(self: *Exchange) ?[]const u8 {
                if (self.send_offset < self.request_len)
                    return self.request_buf[self.send_offset..self.request_len];
                if (self.q_head < self.q_tail)
                    return self.upload_buf[self.q_head..self.q_tail];
                if (self.sp_head < self.sp_tail) {
                    // FIFO drained: fold the spill forward into the
                    // FIFO's freed space.
                    const spill = self.upload_spill[self.sp_head..self.sp_tail];
                    @memcpy(self.upload_buf[0..spill.len], spill);
                    self.q_head = 0;
                    self.q_tail = spill.len;
                    self.sp_head = 0;
                    self.sp_tail = 0;
                    return self.upload_buf[0..self.q_tail];
                }
                return null;
            }

            /// Credit `written` request-leg bytes against the open region,
            /// in the same order `nextUploadSlice` offers them: a region
            /// is always fully consumed before the next is offered, so the
            /// cursor found here is exact. The TLS path credits the staged
            /// plaintext when the outbox holding its records has drained.
            /// The moment the head's last byte credits, the response read
            /// arms — full duplex: the origin may start answering before
            /// one body byte has left the proxy.
            fn advanceUpload(self: *Exchange, written: usize) void {
                if (self.send_offset < self.request_len) {
                    self.send_offset += written;
                    if (self.send_offset == self.request_len) self.armRecv();
                    return;
                }
                if (self.q_head < self.q_tail) {
                    self.q_head += written;
                    return;
                }
                assert(self.sp_head < self.sp_tail);
                self.sp_head += written;
            }

            /// Stage one received body piece into the upload queue,
            /// framing it per the render-time commitment: a chunked piece
            /// becomes the wire segments `hex\r\n`, the piece, `\r\n`,
            /// plus the `0\r\n\r\n` terminator when `fin` carries it; a
            /// Content-Length piece passes through raw; a head-only
            /// (`.none`) upload queues nothing at all — its fin marker
            /// only releases the upload to the response pump. The piece is
            /// copied — the session reuses the chunk's storage the moment
            /// this callback returns.
            ///
            /// The queue is the exchange's `upload_buf` FIFO with the
            /// `upload_spill` overflow; a piece that fits both is an
            /// `error.UploadQueueFull`, which the caller turns into a
            /// dropped upload. A Content-Length violation (more or fewer
            /// bytes than declared) is answered with a 400 here — the
            /// origin must never receive framing that lies — and keeps
            /// the connection out of the pool either way.
            fn stageUpload(self: *Exchange, piece: []const u8, fin: bool) !void {
                // Count every received payload byte for the witness, a
                // violating piece's excess included.
                self.details.bytes_in += piece.len;
                switch (self.framing) {
                    .content_length => |declared| {
                        const will_have = self.uploaded + piece.len;
                        // A fin-bearing piece must land the count exactly;
                        // an earlier piece may never pass it (RFC 9110
                        // §8.6: the sender's own declaration binds it).
                        if (will_have > declared or (fin and will_have != declared)) {
                            self.fail(400, "bad request\n");
                            return error.FramingViolation;
                        }
                    },
                    .chunked, .none => {},
                }
                self.uploaded += piece.len;

                // Everything staged so far has reached the wire: a send
                // must be armed for the new bytes (see `uploadIdle`).
                const was_idle = self.send_offset == self.request_len and
                    self.q_head == self.q_tail and
                    self.sp_head == self.sp_tail;

                const saved_q_tail = self.q_tail;
                const saved_sp_tail = self.sp_tail;
                stage: {
                    switch (self.framing) {
                        .none => {
                            // Head-only request: the stream's FIN rode the
                            // HEADERS frame, so no body byte can follow
                            // and none is owed upstream. Only the fin
                            // marker matters — it settles the upload once
                            // the head has sent.
                        },
                        .content_length => self.queueBytes(piece) catch break :stage,
                        .chunked => {
                            // An empty DATA frame stages nothing: a
                            // zero-length "chunk" would read as the
                            // terminator at the origin, and only the fin's
                            // own terminator may.
                            if (piece.len > 0) {
                                // The size line renders into stack storage,
                                // so it is queued first and must fit by copy.
                                var size_line: [18]u8 = undefined;
                                const line = std.fmt.bufPrint(&size_line, "{x}\r\n", .{piece.len}) catch unreachable;
                                self.queueBytes(line) catch break :stage;
                                self.queueBytes(piece) catch break :stage;
                                self.queueBytes("\r\n") catch break :stage;
                            }
                            if (fin) self.queueBytes("0\r\n\r\n") catch break :stage;
                        },
                    }
                    if (fin) self.upload_fin = true;
                    if (was_idle and self.socket != null and
                        (self.tls == null or self.tls.?.isConnected()))
                    {
                        self.sendMore();
                    }
                    return;
                }
                // The staging is all-or-nothing: a piece that fit nowhere
                // rolls the queue back and errors.
                self.q_tail = saved_q_tail;
                self.sp_tail = saved_sp_tail;
                return error.UploadQueueFull;
            }

            /// Queue one contiguous byte run, FIFO tail first, spill
            /// after. The staging is all-or-nothing per call: a run that
            /// fits neither region errors, and the caller rolls back.
            fn queueBytes(self: *Exchange, bytes: []const u8) !void {
                if (bytes.len == 0) return;
                const take = @min(bytes.len, self.upload_buf.len - self.q_tail);
                @memcpy(self.upload_buf[self.q_tail..][0..take], bytes[0..take]);
                self.q_tail += take;
                if (take == bytes.len) return;
                return self.spillAppend(bytes[take..]);
            }

            fn spillAppend(self: *Exchange, bytes: []const u8) !void {
                if (bytes.len > self.upload_spill.len - self.sp_tail) return error.UploadQueueFull;
                @memcpy(self.upload_spill[self.sp_tail..][0..bytes.len], bytes);
                self.sp_tail += bytes.len;
            }

            /// Begin the client-side handshake on a freshly connected TLS
            /// dial. Key material comes through the Io seam like the TCP
            /// path's engine acquire: a seeded run replays the same
            /// handshake, and zssl draws no entropy itself. The verifier
            /// context is built here, per dial, from the cluster's trust
            /// store, name and wall clock — the same facts
            /// `Server.acquireUpstreamTlsEngine` stamps. Failure before
            /// the request is even staged is an origin-side gateway
            /// failure like a refused dial: 502, no retry.
            fn tlsStart(self: *Exchange) !void {
                const tls = self.proxy.clusters[self.cluster_index].tls orelse
                    return error.TlsClusterMismatch;
                const engine = self.proxy.tls_engines.acquire() orelse
                    return error.TlsEnginesExhausted;
                var seeds: [64]u8 = undefined;
                IoType.fillRandom(self.proxy.io, &seeds);
                if (tls.trust) |store| {
                    self.tls_trust = .{
                        .store = store,
                        .server_name = tls.server_name,
                        .now_sec = @intCast(IoType.nowWallNs(self.proxy.io) /
                            std.time.ns_per_s),
                    };
                }
                engine.init(&.{
                    .client_random = seeds[0..32].*,
                    .x25519_private = seeds[32..64].*,
                    .server_name = tls.server_name,
                    .trust = if (self.tls_trust) |*context| context else null,
                    .client_credentials = tls.client_credentials,
                });
                engine.start();
                self.tls = engine;
                self.pumpHandshake();
            }

            /// The handshake drive, the `pumpUpstreamTlsOutbound` shape the
            /// L7 proxy uses: one data op at a time on the upstream socket
            /// — staged ciphertext out, the engine's record buffer in —
            /// until the engine reports connected, and only then does the
            /// request leg start. The one coarse exchange deadline covers
            /// the handshake like any other dial phase: the timeout's
            /// shutdown forces the armed op to a delivery the callback
            /// converts to the 504.
            fn pumpHandshake(self: *Exchange) void {
                const engine = self.tls.?;
                const staged = engine.outbound();
                if (staged.len >= 1) {
                    self.send_armed = true;
                    IoType.send(
                        self.proxy.io,
                        self.socket.?,
                        staged,
                        &self.completion,
                        Exchange,
                        self,
                        onHandshakeSent,
                    );
                    return;
                }
                if (engine.isConnected()) {
                    self.sendMore();
                    return;
                }
                self.recv_armed = true;
                IoType.recv(
                    self.proxy.io,
                    self.socket.?,
                    engine.recvBuffer(),
                    &self.completion,
                    Exchange,
                    self,
                    onHandshakeRecv,
                );
            }

            fn onHandshakeSent(exchange: *Exchange, result: Io.SendError!u32) void {
                exchange.send_armed = false;
                if (exchange.deregistered) {
                    exchange.discard();
                    return;
                }
                if (exchange.verdict_committed) {
                    exchange.finish();
                    return;
                }
                if (exchange.timed_out) {
                    exchange.timeOutVerdict();
                    return;
                }
                const sent = result catch {
                    exchange.fail(502, "bad gateway\n");
                    return;
                };
                if (sent == 0) {
                    exchange.fail(502, "bad gateway\n");
                    return;
                }
                exchange.tls.?.outboundSent(sent);
                exchange.pumpHandshake();
            }

            fn onHandshakeRecv(exchange: *Exchange, result: Io.RecvError!u32) void {
                exchange.recv_armed = false;
                if (exchange.deregistered) {
                    exchange.discard();
                    return;
                }
                if (exchange.verdict_committed) {
                    exchange.finish();
                    return;
                }
                if (exchange.timed_out) {
                    exchange.timeOutVerdict();
                    return;
                }
                const read = result catch {
                    // A reset or silently closed origin mid-handshake is a
                    // dead dial: the 502 page, like a refused connect.
                    exchange.fail(502, "bad gateway\n");
                    return;
                };
                if (read == 0) {
                    exchange.fail(502, "bad gateway\n");
                    return;
                }
                var sink: HandshakeSink = .{ .exchange = exchange };
                exchange.tls.?.received(read, &sink.sink()) catch {
                    // Certificate verify failed, malformed flight, or the
                    // origin's alert: nothing application-level was sent,
                    // so the exchange keeps the dial-failure 502. No
                    // retry — the request may not be idempotent.
                    exchange.fail(502, "bad gateway\n");
                    return;
                };
                if (sink.closed) {
                    // close_notify before the session was up: the origin
                    // refused the handshake. Waiting out the TCP half of
                    // the close would only stall the deadline timer.
                    exchange.fail(502, "bad gateway\n");
                    return;
                }
                exchange.pumpHandshake();
            }

            /// What a mid-handshake drive step hands back. Application
            /// data before the request is a malformed origin; the TCP
            /// path drops it and so do we (anything it said cannot be a
            /// response to a request we have not sent).
            const HandshakeSink = struct {
                exchange: *Exchange,
                closed: bool = false,

                fn sink(self: *HandshakeSink) UpstreamTls.Sink {
                    return .{ .ctx = self, .appData = appData, .closed = closedCb };
                }

                fn appData(ctx: *anyopaque, bytes: []const u8) void {
                    _ = ctx;
                    _ = bytes;
                }

                fn closedCb(ctx: *anyopaque) void {
                    const self: *HandshakeSink = @ptrCast(@alignCast(ctx));
                    self.closed = true;
                }
            };

            /// Where one TLS decrypt step's plaintext lands. Before the
            /// response head parses, bytes accumulate in `head_buf` under
            /// the same 8 KiB cap the plaintext path enforces — a record
            /// straddling the head/body boundary spills its post-terminator
            /// tail into the chunk (drained before every read, and one
            /// record's plaintext is at most the chunk's size), and
            /// `pumpHead` then moves the head buffer's own tail ahead of
            /// it. After the head, bytes land in the chunk directly.
            fn tlsAppData(ctx: *anyopaque, bytes: []const u8) void {
                const self: *Exchange = @ptrCast(@alignCast(ctx));
                assert(self.tls != null);
                if (self.head_sent) {
                    // Body phase: the chunk is drained before every read
                    // is armed, and one record yields at most its
                    // plaintext cap — the chunk always fits.
                    assert(self.chunk_len + bytes.len <= self.chunk.len);
                    @memcpy(self.chunk[self.chunk_len..][0..bytes.len], bytes);
                    self.chunk_len += bytes.len;
                    return;
                }
                var rest = bytes;
                if (self.head_len < self.head_buf.len) {
                    const take = @min(self.head_buf.len - self.head_len, rest.len);
                    @memcpy(self.head_buf[self.head_len..][0..take], rest[0..take]);
                    self.head_len += take;
                    rest = rest[take..];
                }
                if (std.mem.indexOf(u8, self.head_buf[0..self.head_len], "\r\n\r\n") != null) {
                    // The head terminated inside what we just appended;
                    // the remainder of the record is body. The chunk is
                    // empty at arm time (same invariant as above).
                    assert(self.chunk_len == 0);
                    assert(rest.len <= self.chunk.len);
                    @memcpy(self.chunk[0..rest.len], rest);
                    self.chunk_len = rest.len;
                    return;
                }
                if (rest.len > 0) {
                    // No terminator and the head buffer is full: the head
                    // can never complete within the cap. The plaintext
                    // path's oversize verdict, reached mid-record.
                    self.tls_head_overflow = true;
                }
            }

            fn tlsClosed(ctx: *anyopaque) void {
                const self: *Exchange = @ptrCast(@alignCast(ctx));
                self.tls_peer_closed = true;
            }

            fn tlsSink(self: *Exchange) UpstreamTls.Sink {
                return .{ .ctx = self, .appData = tlsAppData, .closed = tlsClosed };
            }

            /// Arm the response direction's read on `serve_completion`,
            /// independent of the upload send the other completion may
            /// hold — full duplex is exactly this pair. Before the head
            /// parses, bytes accumulate in `head_buf`; after, the body
            /// streams through `chunk`. The first call comes from
            /// `advanceUpload` the moment the request head is credited,
            /// so a fast origin answers while the upload is still
            /// sending; later calls re-arm from the recv's own delivery
            /// paths. Re-arming an already-armed read would corrupt the
            /// completion, so the flag gates it.
            fn armRecv(self: *Exchange) void {
                if (self.recv_armed) return;
                if (self.tls != null) {
                    // The wire carries records: the read lands in the
                    // engine's record buffer and `tlsAppData` routes the
                    // plaintext into the head buffer or the chunk. The
                    // same oversize-head guard as below rides the sink's
                    // overflow flag instead.
                    self.recv_armed = true;
                    IoType.recv(
                        self.proxy.io,
                        self.socket.?,
                        self.tls.?.recvBuffer(),
                        &self.serve_completion,
                        Exchange,
                        self,
                        onRecv,
                    );
                    return;
                }
                if (!self.head_sent) {
                    if (self.head_len >= self.head_buf.len) {
                        // `pumpHead` normally reaches this verdict from
                        // error.Incomplete; the invariant stays guarded
                        // here either way.
                        self.fail(502, "bad gateway\n");
                        return;
                    }
                    self.recv_armed = true;
                    IoType.recv(
                        self.proxy.io,
                        self.socket.?,
                        self.head_buf[self.head_len..],
                        &self.serve_completion,
                        Exchange,
                        self,
                        onRecv,
                    );
                    return;
                }
                // Body phase: consumed bytes are dead space; the buffer
                // only ever refills from empty (pumpBody re-arms after
                // draining it completely).
                assert(self.consumed == self.chunk_len);
                self.consumed = 0;
                self.chunk_len = 0;
                self.recv_armed = true;
                IoType.recv(
                    self.proxy.io,
                    self.socket.?,
                    self.chunk[0..],
                    &self.serve_completion,
                    Exchange,
                    self,
                    onRecv,
                );
            }

            /// Parse the accumulated head, skipping any informational
            /// 1xx that precede the final one. RFC 9110 §15.2: a 1xx is
            /// never the exchange's head — Expect is stripped from the
            /// render so the origin never sees it, but a server may still
            /// answer an upload with 100, and any other interim status
            /// rides the same rule. Returns null once the verdict for a
            /// bad or partial head committed (the caller just returns).
            fn parseFinalHead(self: *Exchange) ?ResponseHead {
                var skips: u32 = 0;
                // lint:unbounded-ok — every skipped 1xx shrinks `head_len`
                // by its full head (body_start is at least the terminator
                // length), and the buffer bound caps the 1xx a wire can
                // hold; the counter is the asserted twin of that bound.
                while (true) {
                    skips += 1;
                    assert(skips <= self.head_buf.len / 4);
                    const parsed = parseResponseHead(self.head_buf[0..self.head_len]) catch |err| switch (err) {
                        error.Incomplete => {
                            if (self.head_len >= self.head_buf.len) {
                                // A head past 8 KiB never terminates: bad
                                // gateway, like any malformed head.
                                self.fail(502, "bad gateway\n");
                                return null;
                            }
                            self.armRecv();
                            return null;
                        },
                        else => {
                            self.fail(502, "bad gateway\n");
                            return null;
                        },
                    };
                    if (parsed.status / 100 != 1) return parsed;
                    // Bytes past the 1xx terminator belong to the final
                    // head. Plaintext keeps them in the head buffer
                    // already; TLS spills a record's post-terminator tail
                    // into the chunk — fold back what fits (a spill past
                    // the buffer's room is the oversize-head case, whose
                    // verdict the cap check above reaches) and drop the
                    // 1xx.
                    if (self.chunk_len > 0) {
                        const take = @min(self.chunk_len, self.head_buf.len - self.head_len);
                        std.mem.copyForwards(
                            u8,
                            self.head_buf[self.head_len..][0..take],
                            self.chunk[0..take],
                        );
                        self.head_len += take;
                        self.chunk_len = 0;
                    }
                    const rest_len = self.head_len - parsed.body_start;
                    std.mem.copyForwards(
                        u8,
                        self.head_buf[0..rest_len],
                        self.head_buf[parsed.body_start..self.head_len],
                    );
                    self.head_len = rest_len;
                }
            }

            /// Parse the accumulated head once, then get it on the wire.
            /// The mode is decided from the head; a `Content-Length` past
            /// the cap is refused here, before the head is sent, and keeps
            /// the old 502. Everything after — the body — streams. Called
            /// only while `head_sent` is false: once the head is out,
            /// `onRecv` drives `pumpBody` directly.
            fn pumpHead(self: *Exchange) void {
                var parsed = self.parseFinalHead() orelse return;
                if (self.no_body_override) {
                    // A HEAD request owns no body whatever the status
                    // framed: the reply ends at the head and the
                    // connection is framed like a no-body one.
                    parsed.no_body = true;
                    parsed.chunked = false;
                    parsed.content_length = null;
                    parsed.close_delimited = false;
                    parsed.reusable = !parsed.connection_close;
                }
                self.head = parsed;

                // Pick the framing, and refuse an over-cap Content-Length
                // before the head is out — that verdict keeps the 502.
                const mode: BodyMode = if (parsed.no_body)
                    .none
                else if (parsed.chunked)
                    .chunked
                else if (parsed.content_length) |expected| blk: {
                    if (expected > self.proxy.options.max_response_bytes) {
                        self.fail(502, "bad gateway\n");
                        return;
                    }
                    self.cl_remaining = expected;
                    break :blk .content_length;
                } else .close_delimited;

                self.h3.sendResponseHead(
                    self.stream_id,
                    parsed.status,
                    parsed.headers[0..parsed.header_count],
                ) catch {
                    self.fail(502, "bad gateway\n");
                    return;
                };
                self.head_sent = true;
                self.mode = mode;
                // The head parsed: even where the body then drips (SSE),
                // the exchange has demonstrably not stalled.
                self.noteProgress();

                const body_prefix = self.stageHeadTail(parsed.body_start);
                if (mode == .close_delimited) {
                    self.body_received = body_prefix;
                    if (self.body_received > self.proxy.options.max_response_bytes) {
                        self.abortBody();
                        return;
                    }
                }
                if (mode == .none) {
                    // HEAD/204/304: fin rides an empty send; any stray
                    // body bytes a careless origin appended are dropped,
                    // exactly like the buffered slice left bytes past the
                    // frame end unread.
                    self.sendFinal();
                    return;
                }
                self.pumpBody();
            }

            /// Move the head buffer's body tail into the staging chunk
            /// once the head is on the wire; returns the tail's length,
            /// the close-delimited pump's starting count. The head buffer
            /// keeps the header slices `details` may still be reading. A
            /// TLS record can carry the head's terminator and body bytes
            /// in one step, and the decrypt sink will already have moved
            /// its tail into the drained chunk — the head buffer's tail
            /// precedes those bytes, so it shifts them up instead of
            /// overwriting. One record's plaintext is at most the chunk's
            /// size, so the pair always fits.
            fn stageHeadTail(self: *Exchange, body_start: usize) usize {
                const body_prefix = self.head_buf[body_start..self.head_len];
                if (body_prefix.len > 0) {
                    if (self.chunk_len == 0) {
                        @memcpy(self.chunk[0..body_prefix.len], body_prefix);
                        self.chunk_len = body_prefix.len;
                    } else {
                        assert(self.tls != null);
                        assert(self.consumed == 0);
                        assert(body_prefix.len + self.chunk_len <= self.chunk.len);
                        std.mem.copyForwards(
                            u8,
                            self.chunk[body_prefix.len..][0..self.chunk_len],
                            self.chunk[0..self.chunk_len],
                        );
                        @memcpy(self.chunk[0..body_prefix.len], body_prefix);
                        self.chunk_len += body_prefix.len;
                    }
                }
                self.consumed = 0;
                return body_prefix.len;
            }

            /// Drive the body state machine over `chunk[consumed..chunk_len]`.
            /// Leaves the exchange paused (a short send), finished (the
            /// fin landed), or recv-armed (the chunk drained), exactly one
            /// of the three. A fin the empty send could not deliver
            /// outranks the mode: the body is already fully relayed, and
            /// only the fin is owed.
            fn pumpBody(self: *Exchange) void {
                if (self.fin_pending) {
                    self.fin_pending = false;
                    self.sendFinal();
                    return;
                }
                switch (self.mode) {
                    .none => self.sendFinal(),
                    .content_length => self.pumpContentLength(),
                    .chunked => self.pumpChunked(),
                    .close_delimited => self.pumpCloseDelimited(),
                }
            }

            /// The outcome of queueing one send unit (the open DATA
            /// frame's payload): `done` means the whole unit queued;
            /// `parked` means the transport short-wrote and the
            /// remainder stays the unit to retry; `aborted` means the
            /// send errored and the exchange is already settled.
            const UnitResult = union(enum) {
                done: usize,
                parked: usize,
                aborted: void,
            };

            /// Queue the open unit — `chunk[consumed..consumed+unit_len]`
            /// with `unit_fin` — toward the client. A short count is
            /// backpressure: the caller stops and waits for the window
            /// notify, which resumes with the tail exactly as-is.
            fn sendUnit(self: *Exchange) UnitResult {
                const data = self.chunk[self.consumed..][0..self.unit_len];
                const written = self.h3.sendData(self.stream_id, data, self.unit_fin) catch |err| switch (err) {
                    // The multi-packet sender reports backpressure as a
                    // short write, but the live listener wires only the
                    // plain send, and that fallback raises the same
                    // conditions — a full datagram queue, a flow-control
                    // window the peer has not raised — as hard errors.
                    // Both leave the transport untouched (the checks run
                    // before any state advances), so the verdict is the
                    // short write's: park exactly where the unit stopped
                    // and let the window notify, or the listener's retry
                    // tick, re-drive the same open frame's remainder.
                    error.QueueFull, error.FlowControlBlocked => {
                        self.paused = true;
                        return .{ .parked = 0 };
                    },
                    else => {
                        // The stream is broken mid-body; nothing more may
                        // be queued on it. The origin's connection is
                        // finished with the exchange either way.
                        self.abortBody();
                        return .aborted;
                    },
                };
                self.details.bytes_out += written;
                self.consumed += written;
                self.unit_len -= written;
                if (self.unit_len == 0) {
                    // The unit is fully queued: the exchange is no longer
                    // parked, and the next loop iteration computes a fresh
                    // unit (or finishes on `unit_fin`).
                    self.paused = false;
                    return .{ .done = written };
                }
                self.paused = true;
                return .{ .parked = written };
            }

            fn pumpContentLength(self: *Exchange) void {
                // lint:unbounded-ok — every turn either exits (parked,
                // aborted, finished, chunk drained) or queues a unit, and
                // a queued unit advances `consumed` toward chunk_len.
                while (true) {
                    assert(self.consumed <= self.chunk_len);
                    if (!self.paused) {
                        const tail = self.chunk[self.consumed..self.chunk_len];
                        const n: usize = @min(
                            @as(usize, @intCast(@min(@as(u64, tail.len), self.cl_remaining))),
                            send_unit_bytes,
                        );
                        if (n == 0) break; // chunk drained (or only the fin is owed)
                        self.unit_len = n;
                        self.unit_fin = self.cl_remaining == n;
                    }
                    switch (self.sendUnit()) {
                        .aborted => return,
                        .parked => |written| {
                            self.cl_remaining -= written;
                            return;
                        },
                        .done => |written| {
                            self.cl_remaining -= written;
                            if (self.unit_fin) {
                                self.finishBody(self.head.?.reusable);
                                return;
                            }
                        },
                    }
                }
                if (self.cl_remaining == 0) {
                    // The fin-carrying send short-wrote and the tail has
                    // since drained: the fin goes out now, on its own.
                    self.sendFinal();
                    return;
                }
                self.armRecv();
            }

            fn pumpChunked(self: *Exchange) void {
                const decoder = &self.chunked;
                const limit = self.proxy.options.max_response_bytes;
                while (self.consumed < self.chunk_len) {
                    if (self.paused) {
                        // Resume the parked payload unit exactly, then
                        // fall back into the decode loop over what
                        // remains.
                        switch (self.sendUnit()) {
                            .aborted => return,
                            .parked => return,
                            .done => |written| {
                                decoder.data_read += written;
                                if (decoder.data_read == decoder.size) {
                                    decoder.state = .data_crlf;
                                    decoder.crlf = 0;
                                }
                            },
                        }
                        continue;
                    }
                    const tail = self.chunk[self.consumed..self.chunk_len];
                    const step = decoder.step(tail, limit) catch {
                        // Malformed framing or the decoded cap: the head
                        // is on the wire, so the client stream is reset
                        // (the verdict rides the witness, not an error
                        // page that cannot follow a 200).
                        self.abortBody();
                        return;
                    };
                    switch (step) {
                        .consume => |n| self.consumed += n,
                        .payload => |n| {
                            self.unit_len = @min(n, send_unit_bytes);
                            self.unit_fin = false;
                            switch (self.sendUnit()) {
                                .aborted => return,
                                .parked => return,
                                .done => |written| {
                                    decoder.data_read += written;
                                    if (decoder.data_read == decoder.size) {
                                        decoder.state = .data_crlf;
                                        decoder.crlf = 0;
                                    }
                                },
                            }
                        },
                        .done => {
                            self.consumed = self.chunk_len;
                            self.sendFinal();
                            return;
                        },
                        .need_more => break,
                    }
                }
                self.armRecv();
            }

            fn pumpCloseDelimited(self: *Exchange) void {
                while (self.consumed < self.chunk_len) {
                    if (self.paused) {
                        // Resume the parked unit exactly.
                        switch (self.sendUnit()) {
                            .aborted => return,
                            .parked => return,
                            .done => {},
                        }
                        continue;
                    }
                    const tail = self.chunk[self.consumed..self.chunk_len];
                    self.unit_len = @min(tail.len, send_unit_bytes);
                    self.unit_fin = false;
                    switch (self.sendUnit()) {
                        .aborted => return,
                        .parked => return,
                        .done => {},
                    }
                }
                // A fin owed past a parked tail is `pumpBody`'s to retry;
                // a live chunk here means the exchange waits on the origin.
                self.armRecv();
            }

            /// The body's last act: an empty DATA carrying fin, then the
            /// witness and the settle. Nothing can short-write; the only
            /// survivable failure is the same transient transport
            /// backpressure `sendUnit` parks on — a full datagram queue
            /// cannot take even the empty frame — and it parks the same
            /// way, with the fin itself pending.
            fn sendFinal(self: *Exchange) void {
                _ = self.h3.sendData(self.stream_id, "", true) catch |err| switch (err) {
                    error.QueueFull, error.FlowControlBlocked => {
                        self.fin_pending = true;
                        self.paused = true;
                        return;
                    },
                    else => {
                        // The stream died on the finish line.
                        self.abortBody();
                        return;
                    },
                };
                self.finishBody(self.head.?.reusable);
            }

            /// Body complete, fin delivered: witness the response and mark
            /// this direction done. The connection does not settle here —
            /// full duplex: the upload may still be draining (or already
            /// settled), and `maybeComplete` parks or closes only when
            /// both directions are done. `reusable` is the head's verdict:
            /// `maybeComplete` still vetoes parking on an observed EOF or
            /// an abandoned upload.
            fn finishBody(self: *Exchange, reusable: bool) void {
                if (self.serve_done) return;
                self.serve_done = true;
                self.serve_reusable = reusable;
                self.deadline_ns = 0;
                self.idle_deadline_ns = 0;
                self.details.status = self.head.?.status;
                self.proxy.noteDetails(.response, &self.details);
                self.maybeComplete();
            }

            /// Mid-stream failure after the head went out. The client
            /// stream cannot wear an error page anymore: it is reset, the
            /// witness records `bad_gateway` with the bytes relayed so
            /// far, and the upstream connection is finished — a truncated
            /// or aborted exchange never parks its connection.
            fn abortBody(self: *Exchange) void {
                if (self.verdict_committed) {
                    self.finish();
                    return;
                }
                self.verdict_committed = true;
                self.deadline_ns = 0;
                self.h3.abortStream(self.stream_id);
                self.details.status = 502;
                self.proxy.noteDetails(.bad_gateway, &self.details);
                self.finish();
            }

            /// The window notify resumed a parked exchange: retry the
            /// unit exactly where it stopped. `paused` stays set so the
            /// pump routes into the resume path; a still-short send
            /// re-parks.
            fn resumeSend(self: *Exchange) void {
                self.pumpBody();
            }

            /// EOF on the upstream socket. Before the head, nothing to
            /// relay: 502. After it, EOF means the connection died —
            /// only a close-delimited reply legitimately ends there, and
            /// it finishes without its connection. Every other framing
            /// was truncated: the client stream is reset, the witness
            /// records bad_gateway with the bytes relayed so far.
            fn onEof(self: *Exchange) void {
                // `onRecv` guards `deregistered` and the committed verdict
                // before calling; this function only runs for a live,
                // answering exchange. The timeout guard stays: EOF is
                // exactly what the timeout's read-shutdown makes the armed
                // recv deliver.
                if (self.timed_out) {
                    if (self.head_sent) {
                        self.abortBody();
                    } else {
                        self.fail(504, "gateway timeout\n");
                    }
                    return;
                }
                if (self.serve_done) {
                    // The response completed while the upload was still
                    // draining; the origin's close orphans it. Same
                    // disposition as the upload send's error: keep the
                    // client's answer, never park the connection.
                    self.saw_eof = true;
                    self.upload_abandoned = true;
                    self.upload_settled = true;
                    self.maybeComplete();
                    return;
                }
                if (!self.head_sent) {
                    // EOF before one byte of head: nothing to relay.
                    self.fail(502, "bad gateway\n");
                    return;
                }
                switch (self.mode) {
                    .none => {
                        // Defensive: `pumpHead` finishes a no-body reply
                        // at the head, so an EOF first means a dead
                        // origin mid-handshake.
                        self.finishBody(false);
                    },
                    .content_length, .chunked => self.abortBody(),
                    .close_delimited => {
                        if (self.paused) {
                            // The parked tail drains first; the fin rides
                            // the window-opened resume.
                            self.fin_pending = true;
                        } else {
                            self.sendFinal();
                        }
                    },
                }
            }

            /// Settle the connection after a relayed answer. A reusable
            /// socket moves to the keep-alive pool (or closes when the
            /// pool is full — the pool is an accelerator, and refusing a
            /// parking connection is always safe); anything else closes
            /// now. A TLS connection parks only when its session can
            /// carry another request — connected, not peer-closed, drained
            /// — the same verdict `net/upstream.zig`'s park asserts. The
            /// engine stays with the parked socket either way; a closed
            /// connection's engine goes back to the pool. Either way the
            /// slot frees.
            fn dispose(self: *Exchange, reusable: bool) void {
                if (self.socket) |socket| {
                    self.socket = null;
                    var parkable = reusable;
                    if (self.tls) |engine| {
                        parkable = parkable and engine.isConnected() and
                            !engine.peerClosed() and engine.outboxEmpty();
                    }
                    if (parkable) {
                        self.proxy.parkSocket(
                            socket,
                            self.tls,
                            self.cluster_index,
                            self.endpoint_index,
                        );
                        self.tls = null;
                    } else {
                        IoType.closeNow(self.proxy.io, socket);
                        self.releaseTls();
                    }
                } else {
                    self.releaseTls();
                }
                self.deadline_ns = 0;
                self.active = false;
            }
        };

        io: *IoType,
        arena: std.mem.Allocator,
        /// This listener's route table, sorted most-specific-first at
        /// config load — the request-time scan is a linear walk over
        /// immutable data, never an allocation.
        routes: []const Route,
        /// The clusters the route table can select, indexed by
        /// `Route.cluster_index`; each carries its own round-robin
        /// cursor, so two routes sharing a cluster share its rotation.
        clusters: []Cluster,
        options: Options,
        exchanges: []Exchange,
        /// Dense storage; `parked[0..parked_count]` is live. Sized at init
        /// to the smaller of the configured endpoint count and
        /// `constants.h3_parked_per_listener_max`, the fd bound the budget
        /// prices — a full pool closes what it cannot park, never queues.
        parked: []Parked = &.{},
        parked_count: usize = 0,
        /// The client-side TLS engines TLS dials draw from — the
        /// `Pool(UpstreamTls)` shape the TCP path's server owns, at h3
        /// scale. Sized at init to one engine per exchange slot plus one
        /// per parked slot, but only when some referenced cluster dials
        /// TLS: a plaintext deployment reserves none, on the same
        /// all-or-nothing terms as every other TLS pool. An engine is
        /// held by its connection for the dial's whole life — in flight
        /// or parked — and released exactly once, when the connection
        /// actually closes, so the worst case this pool must hold is
        /// every exchange handshaking at once beside a full parked set.
        tls_engines: Pool(UpstreamTls) = undefined,

        /// One coarse deadline timer for every exchange and every parked
        /// connection, the listener's shape: armed only while some
        /// deadline is pending, scanned on fire, re-armed at the next
        /// earliest. Per-item timers would need a cancel path each; the
        /// one re-base cancel below is the single exception the two
        /// populations' differing magnitudes force.
        timer_completion: IoType.Completion = .{},
        timer_armed: bool = false,
        /// The deadline the armed (or re-arming) timer is aimed at:
        /// recorded because the lazy no-rebase rule compares new
        /// deadlines against the actual target, not merely "armed".
        timer_deadline_ns: u64 = 0,
        /// The re-base cancel's own completion (§4: a cancel runs on a
        /// second, caller-owned completion), used only while a re-base
        /// drains. Like `Exchange.cancel_completion`, it cycles
        /// dead→pending→dead within the one cancel that arms it.
        timer_cancel_completion: IoType.Completion = .{},
        /// A re-base cancel is draining: the cancel pair's second
        /// delivery re-arms at `timer_deadline_ns`, and nothing may arm a
        /// fresh timer under the in-flight cancel.
        timer_rebasing: bool = false,

        /// Initialize a proxy that answers every request from one cluster
        /// — the single-upstream shape the interop dev server and the
        /// legacy tests build. Expressed as a one-route table selecting a
        /// one-cluster set; the small tables are startup arena memory,
        /// like the exchange slots below.
        pub fn initInPlace(
            self: *Self,
            io: *IoType,
            arena: std.mem.Allocator,
            endpoints: []const std.Io.net.IpAddress,
            options: Options,
        ) !void {
            const routes = try arena.alloc(Route, 1);
            routes[0] = .{ .prefix = "/" };
            const clusters = try arena.alloc(Cluster, 1);
            clusters[0] = .{ .endpoints = endpoints };
            return self.initInPlaceRouted(io, arena, routes, clusters, options);
        }

        /// Initialize a proxy with a route table and the clusters it
        /// selects. Both slices must outlive the proxy (the runtime hands
        /// over arena memory built at startup); `clusters` is owned
        /// mutably — the round-robin cursors advance per dial.
        pub fn initInPlaceRouted(
            self: *Self,
            io: *IoType,
            arena: std.mem.Allocator,
            routes: []const Route,
            clusters: []Cluster,
            options: Options,
        ) !void {
            if (options.max_response_bytes == 0 or
                options.max_response_bytes > constants.h3_response_bytes_limit)
            {
                return error.InvalidOptions;
            }
            assert(routes.len >= 1);
            self.io = io;
            self.arena = arena;
            self.routes = routes;
            self.clusters = clusters;
            self.options = options;
            self.timer_completion = .{};
            self.timer_armed = false;
            self.timer_deadline_ns = 0;
            self.timer_cancel_completion = .{};
            self.timer_rebasing = false;
            self.exchanges = try arena.alloc(Exchange, max_exchanges);
            for (self.exchanges) |*exchange| exchange.* = .{};
            // The pool never exceeds the fd bound the budget prices; an
            // endpoint count past it parks nothing extra (and dials, as a
            // miss always may).
            var endpoint_total: usize = 0;
            var tls_cluster = false;
            for (clusters) |*cluster| {
                endpoint_total += cluster.endpoints.len;
                tls_cluster = tls_cluster or cluster.tls != null;
            }
            const parked_capacity = @min(
                endpoint_total,
                @as(usize, constants.h3_parked_per_listener_max),
            );
            self.parked = try arena.alloc(Parked, parked_capacity);
            self.parked_count = 0;
            // Engines ride the same all-or-nothing terms as the TCP
            // path's pool: nothing reserved where no cluster dials TLS,
            // and every exchange plus every parked slot otherwise —
            // those are the two owners an engine can have.
            try self.tls_engines.init(
                arena,
                if (tls_cluster) @as(u32, @intCast(max_exchanges + parked_capacity)) else 0,
            );
        }

        pub fn handler(self: *Self) session.RequestHandler {
            return .{
                .ctx = self,
                .onRequest = onRequest,
                .onBodyChunk = onBodyChunk,
                .onAborted = onAborted,
            };
        }

        /// The exchange one session/stream pair owns, if any: chunks and
        /// aborts arrive outside `onRequest`, long after the handler
        /// returned, and the exchange slots are the only per-stream state
        /// the proxy keeps.
        fn exchangeFor(self: *Self, h3: *session.H3Session, stream_id: u64) ?*Exchange {
            for (self.exchanges) |*exchange| {
                if (exchange.active and exchange.h3 == h3 and
                    exchange.stream_id == stream_id) return exchange;
            }
            return null;
        }

        /// One body piece of an upload: stage it into the exchange's
        /// queue, which arms the upstream send when the exchange idled
        /// waiting. A Content-Length violation already answered its 400
        /// inside the staging; a queue overflow can only mean the origin
        /// stalled far past what the exchange's fixed staging absorbs —
        /// the honest verdict is the dropped upload the session turns
        /// the returned error into, with the exchange settled silently
        /// beside it (no response: the client's stream is about to be
        /// dropped, and the fault is not the gateway's to witness).
        fn onBodyChunk(
            ctx: *anyopaque,
            h3: *session.H3Session,
            stream_id: u64,
            chunk: []const u8,
            fin: bool,
        ) anyerror!void {
            const self: *Self = @ptrCast(@alignCast(ctx));
            const exchange = self.exchangeFor(h3, stream_id) orelse return;
            if (exchange.deregistered or exchange.timed_out) return;
            // An abandoned upload (the origin answered and closed, or the
            // deadline cut the drain after the response) keeps arriving
            // piece by piece: consume it — the session must drain the
            // client's stream — and drop every byte. The alternative, a
            // client-stream reset (RFC 9114 §4.1.2's request_error), would
            // accuse the client of a request the origin chose not to
            // read; the verdict it already holds is the honest answer.
            if (exchange.upload_abandoned) return;
            exchange.stageUpload(chunk, fin) catch |err| switch (err) {
                // (progress is noted below, on a successful stage)
                error.FramingViolation => return err, // the 400 already went out
                error.UploadQueueFull => {
                    // The dropped upload settles the exchange without a
                    // verdict: teardown's path forces every armed op
                    // (the response read is always one, full duplex) to
                    // a terminal delivery that cleans up.
                    exchange.deregister();
                    return err;
                },
            };
            // A body piece the queue accepted is upload progress: the
            // idle clock restarts.
            exchange.noteProgress();
        }

        /// The client reset its upload stream: it is gone, so the
        /// exchange is dropped silently — the upstream socket is
        /// shutdown-forced or closed, the TLS engine released, no
        /// response is attempted on the dead stream and no `bad_gateway`
        /// is witnessed (the client left; the gateway did not fail). Any
        /// exchange on another stream of the same session is untouched.
        fn onAborted(ctx: *anyopaque, h3: *session.H3Session, stream_id: u64) void {
            const self: *Self = @ptrCast(@alignCast(ctx));
            const exchange = self.exchangeFor(h3, stream_id) orelse return;
            exchange.deregister();
        }

        /// The teardown registration the listener calls before a session
        /// deinits: every in-flight exchange naming that session is
        /// deregistered — socket closed or dial canceled, never answered.
        pub fn sessionTeardown(self: *Self) SessionTeardown {
            return .{ .ctx = self, .forget = forgetSession };
        }

        /// The window notify the listener fires when a client stream's
        /// flow control opens (or on its tick): parked exchanges drain
        /// their tails, and the ones that finish their chunk re-arm the
        /// upstream read that backpressure had stopped.
        pub fn windowNotify(self: *Self) connection.WindowNotify {
            return .{ .ctx = self, .onOpen = onWindowOpen };
        }

        fn forgetSession(ctx: *anyopaque, h3: *session.H3Session) void {
            const self: *Self = @ptrCast(@alignCast(ctx));
            for (self.exchanges) |*exchange| {
                if (exchange.active and exchange.h3 == h3) exchange.deregister();
            }
        }

        /// The listener's window notify: a stalled client stream has flow
        /// control again, or a tick arrived while one was stalled. Resume
        /// every parked exchange; each re-parks, finishes, or re-arms its
        /// upstream recv — and a finish inside here settles the slot like
        /// any other completion, mid-scan.
        fn onWindowOpen(ctx: *anyopaque) void {
            const self: *Self = @ptrCast(@alignCast(ctx));
            for (self.exchanges) |*exchange| {
                if (!exchange.active or !exchange.paused) continue;
                if (exchange.deregistered or exchange.timed_out) continue;
                exchange.resumeSend();
            }
        }

        /// Parked keep-alive connections currently held. The test seam's
        /// window into the pool; the serving path reads `parked_count`
        /// directly.
        pub fn parkedCount(self: *const Self) usize {
            return self.parked_count;
        }

        /// TLS engines currently held — in flight beside an exchange or
        /// parked beside a socket. The test seam's window into the pool;
        /// every settle path returns its engine, so a finished scenario
        /// reads zero unless a parked session is still holding one.
        pub fn tlsEnginesHeld(self: *const Self) u32 {
            return self.tls_engines.acquired_count;
        }

        fn onRequest(
            ctx: *anyopaque,
            h3: *session.H3Session,
            stream_id: u64,
            request: *const request_stream.Request,
        ) void {
            const self: *Self = @ptrCast(@alignCast(ctx));
            self.note(.request);
            // The exchange outlives this callback; hold the parser entry.
            h3.deferRequest(stream_id);

            // Route before an exchange slot is spent: the table is a
            // linear scan over config-load-sorted immutable data, and a
            // request nothing matches is answered 404 — the `l7_no_route`
            // verdict of the TCP path — without a dial.
            var host_buf: [constants.host_bytes_max]u8 = undefined;
            const host = canonicalAuthority(request.authority orelse "", &host_buf);
            const matched = find(self.routes, host, request.path, request.headers) orelse {
                // The 404 the L7 path files under `l7_no_route`: no
                // exchange begins, so the facts are built on this stack
                // like the shed's, and the page body (a configured page
                // or the built-in text) is what the witness counts.
                const body = self.errorBody(.no_route, "no route\n");
                self.noRouteWitness(h3, request, body);
                self.sendError(h3, stream_id, .no_route, 404, "no route\n");
                return;
            };

            const exchange = self.acquire() orelse {
                self.shedWitness(h3, request);
                self.sendError(h3, stream_id, null, 503, "busy\n");
                return;
            };
            exchange.begin(self, h3, stream_id, request);
            // The matched route's log decision rides the exchange: a
            // route opting out suppresses only the line, never the
            // counters (Details.suppress_log's contract).
            exchange.details.suppress_log = !matched.access_log;
            // First arm for this deadline; a no-op while the timer is
            // already aimed at an earlier-or-equal one (see `armTimerAt`).
            if (exchange.deadline_ns != 0) self.armTimerAt(exchange.deadline_ns);
            self.dial(exchange, matched.cluster_index, request) catch {
                // Settled exchanges (a staged-body framing violation
                // already answered its 400) must not wear a second
                // verdict; only an unsettled failure keeps the 502.
                if (exchange.active) exchange.fail(502, "bad gateway\n");
            };
        }

        /// Report a no-route request to the witness: the same facts an
        /// exchange would carry, on the same stack-frame terms as the
        /// shed's — no exchange begins for a 404 either.
        fn noRouteWitness(
            self: *Self,
            h3: *session.H3Session,
            request: *const request_stream.Request,
            body: []const u8,
        ) void {
            if (self.options.counters == null) {
                self.note(.no_route);
                return;
            }
            var details: Details = .{};
            details.method = captureLogged(&details.method_buf, request.method);
            details.path = captureLogged(&details.path_buf, request.path);
            details.authority = captureLogged(&details.authority_buf, request.authority orelse "");
            details.peer = h3.peer;
            details.started_wall_ns = IoType.nowWallNs(self.io);
            details.started_mono_ns = IoType.nowNs(self.io);
            details.bytes_in = request.body.len;
            details.status = 404;
            details.bytes_out = body.len;
            self.noteDetails(.no_route, &details);
        }

        /// Report a shed request to the witness with the same facts an
        /// exchange would carry. A shed request never owns an exchange,
        /// so its `Details` live on this stack frame: the hook runs
        /// synchronously inside this callback, and the copies are the
        /// whole cost.
        fn shedWitness(self: *Self, h3: *session.H3Session, request: *const request_stream.Request) void {
            if (self.options.counters == null) {
                self.note(.shed_busy);
                return;
            }
            var details: Details = .{};
            details.method = captureLogged(&details.method_buf, request.method);
            details.path = captureLogged(&details.path_buf, request.path);
            details.authority = captureLogged(&details.authority_buf, request.authority orelse "");
            details.peer = h3.peer;
            details.started_wall_ns = IoType.nowWallNs(self.io);
            details.started_mono_ns = IoType.nowNs(self.io);
            details.bytes_in = request.body.len;
            details.status = 503;
            details.bytes_out = "busy\n".len;
            self.noteDetails(.shed_busy, &details);
        }

        /// Arm the shared deadline timer at `deadline_ns`. While disarmed
        /// this arms; while armed at an earlier-or-equal target it is a
        /// no-op, and a timer whose earliest item finished early fires,
        /// finds nothing due, and re-arms at the next earliest
        /// (tick-and-compare). But the two deadline populations do not
        /// share a magnitude — an exchange stamps `begin + timeout_ns`, a
        /// parked connection `now + h3_pool_idle_ns` — so a deadline can
        /// arise that targets *earlier* than the armed one (an exchange
        /// beginning under a parked connection's idle window). The lazy
        /// rule cannot absorb that direction: re-base through the one
        /// deadline cancel (§4, the `rebaseDeadline` shape), recording the
        /// target so whichever of the cancel pair drains last re-arms at
        /// it. A cancel already draining owns the re-arm; arming a fresh
        /// timer under it could let the cancel meet the fresh op.
        fn armTimerAt(self: *Self, deadline_ns: u64) void {
            if (self.timer_armed) {
                if (self.timer_deadline_ns <= deadline_ns) return;
                if (self.timer_rebasing) {
                    // The draining cancel re-arms at the recorded target;
                    // aim it at the earlier deadline instead.
                    self.timer_deadline_ns = deadline_ns;
                    return;
                }
                self.timer_rebasing = true;
                self.timer_deadline_ns = deadline_ns;
                IoType.timerCancel(
                    self.io,
                    &self.timer_completion,
                    &self.timer_cancel_completion,
                    Self,
                    self,
                    Self.onTimerRebase,
                );
                return;
            }
            if (self.timer_rebasing) {
                // The timer delivered its Canceled and the cancel is still
                // draining: no fresh arm may meet the cancel, so record the
                // earlier-or-equal target and let the rebase re-arm there.
                self.timer_deadline_ns = @min(self.timer_deadline_ns, deadline_ns);
                return;
            }
            self.timer_armed = true;
            self.timer_deadline_ns = deadline_ns;
            const delay_ns = deadline_ns -| IoType.nowNs(self.io);
            IoType.timerStart(
                self.io,
                &self.timer_completion,
                delay_ns,
                Self,
                self,
                Self.onTimer,
            );
        }

        /// The nearest deadline among live exchanges and parked
        /// connections, or null when none is counting. Bounded by
        /// `max_exchanges + parked.len`.
        fn earliestDeadline(self: *Self) ?u64 {
            var earliest: ?u64 = null;
            for (self.exchanges) |*exchange| {
                if (!exchange.active) continue;
                if (exchange.timed_out) continue;
                const deadline = exchange.effectiveDeadline();
                if (deadline == 0) continue;
                earliest = if (earliest) |current| @min(current, deadline) else deadline;
            }
            for (self.parked[0..self.parked_count]) |*slot| {
                earliest = if (earliest) |current| @min(current, slot.deadline_ns) else slot.deadline_ns;
            }
            return earliest;
        }

        /// The one deadline tick for the proxy's two idle-sensitive
        /// populations: expire what is due, reap parked connections whose
        /// idle window closed, then re-arm at the next earliest deadline
        /// or go quiet when nothing is counting. A Canceled delivery
        /// belongs to a re-base and re-arms at the recorded target here;
        /// while the re-base cancel is still draining, this completion is
        /// the pair's first or second delivery and the sibling owns the
        /// re-arm — the scans wait for it either way (a target already
        /// past due fires immediately once re-armed).
        fn onTimer(self: *Self, result: Io.TimerError!void) void {
            self.timer_armed = false;
            if (self.timer_rebasing) return;
            result catch {
                self.armTimerAt(self.timer_deadline_ns);
                return;
            };
            const now = IoType.nowNs(self.io);
            for (self.exchanges) |*exchange| {
                if (!exchange.active) continue;
                if (exchange.timed_out) continue;
                const deadline = exchange.effectiveDeadline();
                if (deadline == 0 or deadline > now) continue;
                exchange.timeOut();
            }
            // Idle reaping: a parked connection holds an fd and no armed
            // op, so its deadline passing is settled by a synchronous
            // close right here. Swap-remove keeps the scan dense. A TLS
            // slot's engine goes back to the pool with the close — the
            // session dies with its connection.
            var index: usize = 0;
            while (index < self.parked_count) {
                if (self.parked[index].deadline_ns > now) {
                    index += 1;
                    continue;
                }
                IoType.closeNow(self.io, self.parked[index].socket);
                if (self.parked[index].tls) |engine| {
                    engine.deinit();
                    self.tls_engines.release(engine);
                }
                self.parked_count -= 1;
                self.parked[index] = self.parked[self.parked_count];
            }
            if (self.earliestDeadline()) |deadline| self.armTimerAt(deadline);
        }

        /// The re-base cancel's completion (§4): `armTimerAt` canceled the
        /// armed timer so an earlier deadline could take the timer. The
        /// cancel and the timer's own delivery (fire or Canceled) both
        /// land; whichever arrives second (its sibling now drained)
        /// re-arms at the recorded target.
        fn onTimerRebase(self: *Self) void {
            self.timer_rebasing = false;
            if (!self.timer_armed) self.armTimerAt(self.timer_deadline_ns);
        }

        /// The connectCancel completion: the verdict rides the canceled
        /// dial's own completion, which may deliver before or after this
        /// one — nothing to settle here.
        fn onConnectCanceled(exchange: *Exchange) void {
            _ = exchange;
        }

        fn acquire(self: *Self) ?*Exchange {
            for (self.exchanges) |*exchange| {
                if (!exchange.active) return exchange;
            }
            return null;
        }

        /// The most recently parked connection for the endpoint, removed
        /// from the pool for reuse — or null, and `dial` connects fresh.
        /// One slot per (cluster, endpoint), so the scan is short and the
        /// "most recent" is the only one. A TLS connection checks out
        /// with its engine: the session a parked slot holds is the
        /// property the checkout exists to reuse.
        fn checkoutParked(
            self: *Self,
            cluster_index: u16,
            endpoint_index: u16,
        ) ?CheckedOut {
            var index: usize = 0;
            while (index < self.parked_count) : (index += 1) {
                const slot = &self.parked[index];
                if (slot.cluster_index != cluster_index or
                    slot.endpoint_index != endpoint_index) continue;
                const checked = CheckedOut{
                    .socket = slot.socket,
                    .tls = slot.tls,
                };
                self.parked_count -= 1;
                slot.* = self.parked[self.parked_count];
                return checked;
            }
            return null;
        }

        /// Park a reusable connection for the endpoint's next checkout,
        /// its TLS engine beside it when it has one. The pool is an
        /// accelerator, not a limiter: when it is full the connection
        /// simply closes — a later miss dials, which is the same behavior
        /// an empty pool has. Closing in either case returns the engine
        /// to the pool: the caller transfers ownership only on a park.
        fn parkSocket(
            self: *Self,
            socket: IoType.Socket,
            tls: ?*UpstreamTls,
            cluster_index: u16,
            endpoint_index: u16,
        ) void {
            if (self.parked_count == self.parked.len) {
                IoType.closeNow(self.io, socket);
                if (tls) |engine| {
                    engine.deinit();
                    self.tls_engines.release(engine);
                }
                return;
            }
            if (tls) |engine| {
                // The `net/upstream.zig` park invariants at h3 scale: a
                // parked engine must be able to carry the next request —
                // connected, not peer-closed, and with nothing staged that
                // would precede it.
                assert(engine.isConnected());
                assert(!engine.peerClosed());
                assert(engine.outboxEmpty());
            }
            const deadline_ns = IoType.nowNs(self.io) + constants.h3_pool_idle_ns;
            self.parked[self.parked_count] = .{
                .socket = socket,
                .tls = tls,
                .cluster_index = cluster_index,
                .endpoint_index = endpoint_index,
                .deadline_ns = deadline_ns,
            };
            self.parked_count += 1;
            self.armTimerAt(deadline_ns);
        }

        /// Report one observable event to the installed counter hook, if
        /// the embedder installed one. One branch on the serving path; the
        /// counters module is the adapter's business, not this file's.
        fn note(self: *Self, event: Counters.Event) void {
            if (self.options.counters) |counters| counters.note(counters.ctx, event, null);
        }

        /// Report an answer event with the request's facts. The null-hook
        /// path is the `note` one: no clock was read and no header copied
        /// to fill `details` when no hook is installed, so an unwitnessed
        /// exchange reaches here with an empty struct and the branch below
        /// is the whole overhead.
        fn noteDetails(self: *Self, event: Counters.Event, details: *const Details) void {
            if (self.options.counters) |counters| counters.note(counters.ctx, event, details);
        }

        fn dial(
            self: *Self,
            exchange: *Exchange,
            cluster_index: u16,
            request: *const request_stream.Request,
        ) !void {
            const cluster = &self.clusters[cluster_index];
            if (cluster.endpoints.len == 0) return error.NoEndpoint;
            const endpoint_index: u16 = @intCast(cluster.next_endpoint);
            const endpoint = cluster.endpoints[cluster.next_endpoint];
            cluster.next_endpoint = (cluster.next_endpoint + 1) % cluster.endpoints.len;
            // The pool key is unconditional: parking and checkout run with
            // no witness hook installed, unlike the facts below.
            exchange.cluster_index = cluster_index;
            exchange.endpoint_index = endpoint_index;
            if (self.options.counters != null) {
                exchange.details.endpoint = endpoint;
                exchange.details.cluster_index = cluster_index;
            }

            var authority_buf: [128]u8 = undefined;
            const authority = request.authority orelse
                std.fmt.bufPrint(&authority_buf, "{f}", .{endpoint}) catch
                return error.InvalidRequest;

            // Pooled exchanges ask the origin to keep the connection. The
            // render precedes the checkout so a render error takes no
            // socket out of the pool. A request whose stream FIN arrived
            // with its HEADERS frame renders head-only: no generated
            // framing header, no body, no terminator — an empty upload
            // is the upload already complete, not a zero-length chunked
            // body the origin must still decode.
            const rendered = try renderRequestHead(
                &exchange.request_buf,
                request.method,
                request.path,
                authority,
                request.headers,
                request.fin_on_headers,
                true,
            );
            exchange.request_len = rendered.len;
            exchange.send_offset = 0;
            exchange.framing = rendered.framing;
            // The body no longer exists at this point: it streams in
            // through the handler's `onBodyChunk` after this callback,
            // and the fin that completes the upload arrives with it.
            if (self.checkoutParked(cluster_index, endpoint_index)) |checked| {
                // Reuse. A parked connection whose origin silently closed
                // fails its first send or recv below; that exchange is
                // answered 502 and never retried — the pool accelerates,
                // it does not gamble a possibly non-idempotent request on
                // a dead socket being the only failure. A TLS checkout
                // inherits the parked session: connected, drained, and
                // reused without a second handshake.
                exchange.socket = checked.socket;
                exchange.tls = checked.tls;
                exchange.sendMore();
                return;
            }
            exchange.socket = null;
            IoType.connect(
                self.io,
                &.{ .ip = endpoint },
                &exchange.completion,
                Exchange,
                exchange,
                onConnect,
            );
        }

        fn onConnect(exchange: *Exchange, result: Io.ConnectError!IoType.Socket) void {
            if (exchange.deregistered) {
                // Teardown claimed this dial; whatever the backend
                // delivers (Canceled, or a socket the cancel raced), the
                // exchange is discarded, not answered.
                if (result) |socket| {
                    exchange.socket = socket;
                } else |_| {}
                exchange.discard();
                return;
            }
            const socket = result catch {
                // A dial the deadline timer canceled delivers Canceled; a
                // dial that failed on its own keeps the 502. The canceled
                // socket never exists here: both backends close it on a
                // failed connect.
                if (exchange.timed_out) {
                    exchange.fail(504, "gateway timeout\n");
                } else {
                    exchange.fail(502, "bad gateway\n");
                }
                return;
            };
            if (exchange.timed_out) {
                // The cancel raced a dial that completed anyway: the 504
                // stands, and the late socket must not leak.
                exchange.socket = socket;
                exchange.fail(504, "gateway timeout\n");
                return;
            }
            exchange.socket = socket;
            if (exchange.proxy.clusters[exchange.cluster_index].tls != null) {
                // A TLS cluster handshakes before the request leg starts:
                // `tlsStart` drives the engine to `isConnected` and only
                // then calls `sendMore`. Failure is the dial's 502.
                exchange.tlsStart() catch {
                    exchange.fail(502, "bad gateway\n");
                    return;
                };
                return;
            }
            exchange.sendMore();
        }

        fn onSent(exchange: *Exchange, result: Io.SendError!u32) void {
            exchange.send_armed = false;
            if (exchange.deregistered) {
                exchange.discard();
                return;
            }
            if (exchange.verdict_committed) {
                // The verdict committed on the response path (or the
                // sibling's forced delivery beat this one): settle the
                // socket when both directions are in.
                exchange.finish();
                return;
            }
            if (exchange.timed_out) {
                exchange.timeOutVerdict();
                return;
            }
            const written = result catch {
                if (exchange.serve_done) {
                    // The response is fully relayed and the origin closed:
                    // the upload is orphaned (RFC 9114 §4.1.2 — the client
                    // is not accused of a request the origin chose not to
                    // read). Swallow the error; the client keeps its
                    // answer and the connection never parks.
                    exchange.saw_eof = true;
                    exchange.upload_abandoned = true;
                    exchange.upload_settled = true;
                    exchange.maybeComplete();
                    return;
                }
                // A checked-out connection whose origin silently closed
                // fails here: the exchange is answered 502 and the
                // connection is finished — there is no retry, because the
                // request may not be idempotent.
                exchange.fail(502, "bad gateway\n");
                return;
            };
            if (written == 0) {
                if (exchange.serve_done) {
                    exchange.saw_eof = true;
                    exchange.upload_abandoned = true;
                    exchange.upload_settled = true;
                    exchange.maybeComplete();
                    return;
                }
                exchange.fail(502, "bad gateway\n");
                return;
            }
            if (exchange.tls != null) {
                // Ciphertext credits against the outbox; the request-leg
                // cursor advances — whichever region is open: head, FIFO,
                // or spill — only when the record holding the open unit
                // has fully drained (a short write resumes mid-record).
                const engine = exchange.tls.?;
                engine.outboundSent(written);
                if (engine.outbound().len == 0) {
                    exchange.advanceUpload(exchange.tls_send_staged);
                    exchange.tls_send_staged = 0;
                }
                exchange.noteProgress();
                exchange.sendMore();
                return;
            }
            exchange.advanceUpload(written);
            exchange.noteProgress();
            exchange.sendMore();
        }

        fn onRecv(exchange: *Exchange, result: Io.RecvError!u32) void {
            exchange.recv_armed = false;
            if (exchange.deregistered) {
                exchange.discard();
                return;
            }
            if (exchange.verdict_committed) {
                exchange.finish();
                return;
            }
            if (exchange.timed_out) {
                exchange.timeOutVerdict();
                return;
            }
            const read = result catch |err| switch (err) {
                error.EndOfStream => {
                    exchange.onEof();
                    return;
                },
                else => {
                    // A reset or silently closed checked-out connection
                    // dies here. Before the head that is the exchange's
                    // 502; mid-body the head is on the wire and the
                    // verdict is a stream reset.
                    if (exchange.head_sent) {
                        exchange.abortBody();
                    } else {
                        exchange.fail(502, "bad gateway\n");
                    }
                    return;
                },
            };
            if (read == 0) {
                exchange.onEof();
                return;
            }
            exchange.noteProgress();
            if (exchange.tls != null) {
                // Ciphertext in, plaintext through the sink into the head
                // buffer or the chunk — TLS terminates before the pumps,
                // which eat plaintext only.
                exchange.tls.?.received(read, &exchange.tlsSink()) catch {
                    if (exchange.head_sent) {
                        exchange.abortBody();
                    } else {
                        exchange.fail(502, "bad gateway\n");
                    }
                    return;
                };
                if (exchange.tls_head_overflow) {
                    // A head past the 8 KiB cap with no terminator: the
                    // plaintext path's oversize verdict.
                    exchange.fail(502, "bad gateway\n");
                    return;
                }
                if (!exchange.head_sent) {
                    exchange.pumpHead();
                    return;
                }
                exchange.pumpBody();
                // A close_notify the same record batch carried is the
                // orderly-EOF twin of `onEof` — deferred to here so the
                // plaintext already decrypted relays first.
                if (exchange.active and exchange.tls_peer_closed) exchange.onEof();
                return;
            }
            if (!exchange.head_sent) {
                exchange.head_len += read;
                exchange.pumpHead();
                return;
            }
            exchange.chunk_len += read;
            if (exchange.mode == .close_delimited) {
                exchange.body_received += read;
                if (exchange.body_received > exchange.proxy.options.max_response_bytes) {
                    exchange.abortBody();
                    return;
                }
            }
            exchange.pumpBody();
        }

        /// The error family one of the proxy's own statuses answers:
        /// the page table and the built-in fallbacks key on these, not
        /// on the bare status.
        const ErrorClass = enum {
            no_route,
            bad_gateway,
            gateway_timeout,
        };

        /// The body an answer wears: the configured page when the
        /// family names one, the built-in text otherwise — the default
        /// behavior never regresses.
        fn errorBody(self: *Self, class: ?ErrorClass, fallback: []const u8) []const u8 {
            const pages = self.options.error_pages;
            const configured: ?[]const u8 = switch (class orelse return fallback) {
                .no_route => pages.no_route,
                .bad_gateway => pages.bad_gateway,
                .gateway_timeout => pages.gateway_timeout,
            };
            return configured orelse fallback;
        }

        fn sendError(
            self: *Self,
            h3: *session.H3Session,
            stream_id: u64,
            class: ?ErrorClass,
            status: u16,
            fallback: []const u8,
        ) void {
            const body = self.errorBody(class, fallback);
            h3.sendResponse(stream_id, status, &error_headers, body, true) catch
                h3.abort(stream_id);
        }
    };
}

// ---------------------------------------------------------------------------
// Pure tests: request rendering and response-head parsing need no Io backend.
// ---------------------------------------------------------------------------

fn expectRenderedHead(
    expected: []const u8,
    expected_framing: UploadFraming,
    method: []const u8,
    path: []const u8,
    authority: []const u8,
    headers: []const request_stream.Header,
    bodyless: bool,
    keep_alive: bool,
) !void {
    var out: [4096]u8 = undefined;
    const rendered = try renderRequestHead(&out, method, path, authority, headers, bodyless, keep_alive);
    try std.testing.expectEqualStrings(expected, out[0..rendered.len]);
    switch (expected_framing) {
        .content_length => |expected_cl| {
            try std.testing.expect(rendered.framing == .content_length);
            try std.testing.expectEqual(expected_cl, rendered.framing.content_length);
        },
        .chunked => try std.testing.expect(rendered.framing == .chunked),
        .none => try std.testing.expect(rendered.framing == .none),
    }
}

test "h3 proxy: render a request head with hop-by-hop headers removed and Content-Length passed through" {
    const headers = [_]request_stream.Header{
        .{ .name = "accept", .value = "text/plain" },
        .{ .name = "Connection", .value = "keep-alive" },
        .{ .name = "content-length", .value = "4" },
        .{ .name = "host", .value = "wrong.example" },
        .{ .name = "transfer-encoding", .value = "chunked" },
        .{ .name = "expect", .value = "100-continue" },
        .{ .name = "x-test", .value = "1" },
    };
    // The proxy owns the Connection header: the caller's spellings are
    // dropped, and the keep_alive argument picks the one rendered. The
    // client's Content-Length re-renders verbatim (never the stripped
    // header, which is consumed for its value), and Expect: 100-continue
    // never forwards: the proxy proceeds immediately.
    try expectRenderedHead(
        "POST /submit HTTP/1.1\r\n" ++
            "Host: origin.test:8000\r\n" ++
            "Connection: close\r\n" ++
            "accept: text/plain\r\n" ++
            "x-test: 1\r\n" ++
            "Content-Length: 4\r\n" ++
            "\r\n",
        .{ .content_length = 4 },
        "POST",
        "/submit",
        "origin.test:8000",
        &headers,
        false,
        false,
    );
    try expectRenderedHead(
        "POST /submit HTTP/1.1\r\n" ++
            "Host: origin.test:8000\r\n" ++
            "Connection: keep-alive\r\n" ++
            "accept: text/plain\r\n" ++
            "x-test: 1\r\n" ++
            "Content-Length: 4\r\n" ++
            "\r\n",
        .{ .content_length = 4 },
        "POST",
        "/submit",
        "origin.test:8000",
        &headers,
        false,
        true,
    );
}

test "h3 proxy: a request without Content-Length commits to chunked upstream framing" {
    const headers = [_]request_stream.Header{
        .{ .name = "content-type", .value = "application/octet-stream" },
    };
    try expectRenderedHead(
        "POST /upload HTTP/1.1\r\n" ++
            "Host: origin.test:8000\r\n" ++
            "Connection: keep-alive\r\n" ++
            "content-type: application/octet-stream\r\n" ++
            "Transfer-Encoding: chunked\r\n" ++
            "\r\n",
        .chunked,
        "POST",
        "/upload",
        "origin.test:8000",
        &headers,
        false,
        true,
    );
}

test "h3 proxy: a bodyless request renders head-only, no generated framing" {
    // The QUIC stream's FIN rode the HEADERS frame (a plain GET): the
    // proxy commits to nothing — no Transfer-Encoding line, no body, no
    // terminator. Sending a zero-length chunked framing instead would
    // make origins that answer at the head wait on bytes that read as
    // the next request.
    try expectRenderedHead(
        "GET /items HTTP/1.1\r\n" ++
            "Host: origin.test:8000\r\n" ++
            "Connection: keep-alive\r\n" ++
            "accept: text/plain\r\n" ++
            "\r\n",
        .none,
        "GET",
        "/items",
        "origin.test:8000",
        &.{
            .{ .name = "accept", .value = "text/plain" },
            .{ .name = "transfer-encoding", .value = "chunked" },
        },
        true,
        true,
    );
    // A declared Content-Length wins over bodyless: the header is the
    // client's own framing commitment and re-renders verbatim.
    try expectRenderedHead(
        "POST /submit HTTP/1.1\r\n" ++
            "Host: origin.test:8000\r\n" ++
            "Connection: keep-alive\r\n" ++
            "Content-Length: 0\r\n" ++
            "\r\n",
        .{ .content_length = 0 },
        "POST",
        "/submit",
        "origin.test:8000",
        &.{.{ .name = "content-length", .value = "0" }},
        true,
        true,
    );
}

test "h3 proxy: duplicate Content-Length headers must agree" {
    var out: [4096]u8 = undefined;
    const agreeing = [_]request_stream.Header{
        .{ .name = "content-length", .value = "8" },
        .{ .name = "Content-Length", .value = "8" },
    };
    const rendered = try renderRequestHead(&out, "POST", "/x", "h", &agreeing, false, true);
    try std.testing.expectEqual(UploadFraming{ .content_length = 8 }, rendered.framing);

    const conflicting = [_]request_stream.Header{
        .{ .name = "content-length", .value = "8" },
        .{ .name = "content-length", .value = "9" },
    };
    try std.testing.expectError(
        error.InvalidRequest,
        renderRequestHead(&out, "POST", "/x", "h", &conflicting, false, true),
    );
    const malformed = [_]request_stream.Header{
        .{ .name = "content-length", .value = "eight" },
    };
    try std.testing.expectError(
        error.InvalidRequest,
        renderRequestHead(&out, "POST", "/x", "h", &malformed, false, true),
    );
}

test "h3 proxy: invalid request tokens are refused" {
    var out: [256]u8 = undefined;
    try std.testing.expectError(
        error.InvalidRequest,
        renderRequestHead(&out, "GE T", "/", "h", &.{}, false, true),
    );
    try std.testing.expectError(
        error.InvalidRequest,
        renderRequestHead(&out, "GET", "/bad path", "h", &.{}, false, true),
    );
    try std.testing.expectError(
        error.InvalidRequest,
        renderRequestHead(&out, "GET", "/", "h\r\nX: y", &.{}, false, true),
    );
}

test "h3 proxy: response head with Content-Length and filtered headers" {
    const response =
        "HTTP/1.1 200 OK\r\n" ++
        "Content-Type: text/plain\r\n" ++
        "Content-Length: 17\r\n" ++
        "Cache-Control: max-age=5\r\n" ++
        "Connection: close\r\n" ++
        "\r\n" ++
        "origin says hello";
    const head = try parseResponseHead(response);
    try std.testing.expectEqual(@as(u16, 200), head.status);
    try std.testing.expectEqual(@as(?usize, 17), head.content_length);
    try std.testing.expect(!head.chunked);
    try std.testing.expect(!head.no_body);
    try std.testing.expect(!head.close_delimited);
    try std.testing.expect(head.connection_close);
    try std.testing.expect(!head.reusable);
    try std.testing.expectEqual(@as(usize, 110), head.body_start);
    try std.testing.expectEqual(@as(usize, 2), head.header_count);
    try std.testing.expectEqualStrings("Content-Type", head.headers[0].name);
    try std.testing.expectEqualStrings("text/plain", head.headers[0].value);
    try std.testing.expectEqualStrings("Cache-Control", head.headers[1].name);
}

test "h3 proxy: close-delimited, chunked and no-body responses" {
    const close = try parseResponseHead("HTTP/1.0 200 OK\r\nServer: x\r\n\r\nbody");
    try std.testing.expect(close.close_delimited);
    try std.testing.expect(!close.reusable);
    try std.testing.expectEqual(@as(?usize, null), close.content_length);
    try std.testing.expectEqual(@as(usize, 0), close.header_count);

    // A 1.0 reply does not persist unless it declares keep-alive: fully
    // framed or not, the pool must not park it (RFC 9112 §9.3).
    const framed10 = try parseResponseHead(
        "HTTP/1.0 200 OK\r\nContent-Length: 5\r\n\r\nhello",
    );
    try std.testing.expect(framed10.connection_close);
    try std.testing.expect(!framed10.reusable);
    const persistent10 = try parseResponseHead(
        "HTTP/1.0 200 OK\r\nContent-Length: 5\r\nConnection: keep-alive\r\n\r\nhello",
    );
    try std.testing.expect(!persistent10.connection_close);
    try std.testing.expect(persistent10.reusable);

    const chunked = try parseResponseHead(
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nping\r\n0\r\n\r\n",
    );
    try std.testing.expect(chunked.chunked);
    try std.testing.expect(!chunked.close_delimited);
    try std.testing.expect(chunked.reusable);

    const no_body = try parseResponseHead("HTTP/1.1 204 No Content\r\n\r\n");
    try std.testing.expect(no_body.no_body);
    try std.testing.expect(!no_body.close_delimited);
    try std.testing.expect(no_body.reusable);
}

/// Drive a `ChunkedDecoder` over `wire` in `piece`-byte feeds, appending
/// every payload segment to `out`. Returns the decoded length — the
/// bytes a pump would have relayed. The payload bookkeeping mirrors
/// `Exchange.pumpChunked`: the decoder under test is the unit, the pump
/// is its (separately tested) driver.
fn feedChunked(out: []u8, wire: []const u8, piece: usize, limit: usize) !usize {
    var decoder: ChunkedDecoder = .{};
    var out_len: usize = 0;
    var at: usize = 0;
    while (at < wire.len) {
        const n = @min(piece, wire.len - at);
        var tail = wire[at .. at + n];
        at += n;
        while (tail.len > 0) {
            const step = try decoder.step(tail, limit);
            switch (step) {
                .consume => |k| tail = tail[k..],
                .payload => |k| {
                    @memcpy(out[out_len..][0..k], tail[0..k]);
                    out_len += k;
                    decoder.data_read += k;
                    tail = tail[k..];
                    if (decoder.data_read == decoder.size) {
                        decoder.state = .data_crlf;
                        decoder.crlf = 0;
                    }
                },
                .done => return out_len,
                .need_more => break,
            }
        }
    }
    return out_len;
}

test "h3 proxy: the incremental chunked decoder reassembles split framing" {
    // Every boundary a SimIo delivery can split at: the size line across
    // feeds, chunk data mid-payload, multi-line trailers, the bare
    // terminating CRLF.
    const wire = "5;foo=bar\r\nhello\r\n2\r\nhi\r\n0\r\nX-T: v\r\nX-U: w\r\n\r\n";
    var payload: [16]u8 = undefined;

    // Byte at a time is the adversarial case; awkward mid-line splits
    // and the whole frame at once must agree with it.
    const byte_at_a_time = try feedChunked(&payload, wire, 1, 1024);
    try std.testing.expectEqualStrings("hellohi", payload[0..byte_at_a_time]);
    const whole = try feedChunked(&payload, wire, wire.len, 1024);
    try std.testing.expectEqualStrings("hellohi", payload[0..whole]);
    const split = try feedChunked(&payload, wire, 7, 1024);
    try std.testing.expectEqualStrings("hellohi", payload[0..split]);

    // The empty chunked body decodes to nothing however it splits.
    try std.testing.expectEqual(@as(usize, 0), try feedChunked(&payload, "0\r\n\r\n", 2, 1024));
}

test "h3 proxy: the incremental chunked decoder honors the cap and the framing" {
    var payload: [16]u8 = undefined;

    // A chunk whose trailing CRLF lies is malformed however it splits.
    try std.testing.expectError(
        error.BadResponse,
        feedChunked(&payload, "4\r\npingXX\r\n0\r\n\r\n", 3, 1024),
    );
    // An oversize size line is refused as malformed framing.
    try std.testing.expectError(
        error.BadResponse,
        feedChunked(&payload, "99999999999999999999\r\n", 5, 1024),
    );
    // The decoded cap fires when the offending size line parses.
    try std.testing.expectError(
        error.ResponseTooLarge,
        feedChunked(&payload, "4\r\nping\r\n0\r\n\r\n", 1024, 3),
    );
    // A truncated body (no terminating chunk) decodes what arrived and
    // lets the caller's EOF finish the verdict — no error from the
    // decoder itself.
    try std.testing.expectEqual(
        @as(usize, 4),
        try feedChunked(&payload, "4\r\nping\r\n0\r\n", 4, 1024),
    );
}

test "h3 proxy: incomplete and malformed response heads" {
    try std.testing.expectError(error.Incomplete, parseResponseHead("HTTP/1.1 200 OK\r\n"));
    try std.testing.expectError(error.BadResponse, parseResponseHead("NOPE 200 OK\r\n\r\n"));
    try std.testing.expectError(
        error.BadResponse,
        parseResponseHead("HTTP/1.1 20\r\n\r\n"),
    );
    try std.testing.expectError(
        error.BadResponse,
        parseResponseHead("HTTP/1.1 200 OK\r\nContent-Length: nope\r\n\r\n"),
    );
}

// ---------------------------------------------------------------------------
// Routing: the seam-local route table (`Route`, `find`, `prefixMatches`)
// is the router.zig semantics kept beside the serving path, so these
// tests mirror router.zig's own: same sort order, same verdicts.
// ---------------------------------------------------------------------------

test "h3 proxy: routing matches the longest prefix at segment boundaries" {
    // As config.zig stores them: host-specific first, then longest prefix.
    const routes = [_]Route{
        .{ .prefix = "/api/v2", .cluster_index = 3 },
        .{ .prefix = "/api", .cluster_index = 2 },
        .{ .prefix = "/", .cluster_index = 0 },
    };
    try std.testing.expectEqual(@as(?u16, 3), find(&routes, "", "/api/v2", &.{}).?.cluster_index);
    try std.testing.expectEqual(@as(?u16, 3), find(&routes, "", "/api/v2/x", &.{}).?.cluster_index);
    try std.testing.expectEqual(@as(?u16, 2), find(&routes, "", "/api", &.{}).?.cluster_index);
    try std.testing.expectEqual(@as(?u16, 2), find(&routes, "", "/api/v1", &.{}).?.cluster_index);
    // A segment-splitting string prefix is not a match: "/api" must not
    // capture "/apihost", so it falls through to the catch-all.
    try std.testing.expectEqual(@as(?u16, 0), find(&routes, "", "/apihost", &.{}).?.cluster_index);
    try std.testing.expectEqual(@as(?u16, 0), find(&routes, "", "/other", &.{}).?.cluster_index);
    try std.testing.expectEqual(@as(?u16, 0), find(&routes, "", "/", &.{}).?.cluster_index);
}

test "h3 proxy: a host-scoped route beats any-host, whatever the prefix" {
    const routes = [_]Route{
        .{ .host = "a.example", .prefix = "/api", .cluster_index = 1 },
        .{ .host = "a.example", .prefix = "/", .cluster_index = 2 },
        .{ .prefix = "/deep", .cluster_index = 3 },
        .{ .prefix = "/", .cluster_index = 0 },
    };
    try std.testing.expectEqual(@as(?u16, 1), find(&routes, "a.example", "/api/x", &.{}).?.cluster_index);
    // Host specificity dominates prefix length: a.example's own
    // catch-all still wins over the longer any-host "/deep".
    try std.testing.expectEqual(@as(?u16, 2), find(&routes, "a.example", "/deep/x", &.{}).?.cluster_index);
    try std.testing.expectEqual(@as(?u16, 3), find(&routes, "b.example", "/deep/x", &.{}).?.cluster_index);
    // No usable authority ("") meets only the any-host routes.
    try std.testing.expectEqual(@as(?u16, 3), find(&routes, "", "/deep", &.{}).?.cluster_index);
    try std.testing.expectEqual(@as(?u16, 0), find(&routes, "", "/whatever", &.{}).?.cluster_index);
    // A host-scoped table 404s a request whose host is absent.
    const scoped = [_]Route{.{ .host = "only.example", .prefix = "/", .cluster_index = 1 }};
    try std.testing.expectEqual(@as(?u16, 1), find(&scoped, "only.example", "/x", &.{}).?.cluster_index);
    try std.testing.expect(find(&scoped, "other.example", "/x", &.{}) == null);
    try std.testing.expect(find(&scoped, "", "/x", &.{}) == null);
}

test "h3 proxy: no catch-all means no match is null, the caller's 404" {
    const routes = [_]Route{
        .{ .prefix = "/api", .cluster_index = 1 },
    };
    try std.testing.expectEqual(@as(?u16, 1), find(&routes, "", "/api", &.{}).?.cluster_index);
    try std.testing.expectEqual(@as(?u16, 1), find(&routes, "", "/api/deep/path", &.{}).?.cluster_index);
    try std.testing.expect(find(&routes, "", "/", &.{}) == null);
    try std.testing.expect(find(&routes, "", "/apix", &.{}) == null);
    try std.testing.expect(find(&routes, "", "/elsewhere", &.{}) == null);
}

test "h3 proxy: the routing host is the canonical authority" {
    var buf: [constants.host_bytes_max]u8 = undefined;
    // Lowercased and port-stripped before the table compare — the same
    // fold the log line's host wears.
    try std.testing.expectEqualStrings(
        "origin.test",
        canonicalAuthority("Origin.TEST:8443", &buf),
    );
    try std.testing.expectEqualStrings("origin.test", canonicalAuthority("origin.test", &buf));
    try std.testing.expectEqualStrings(
        "[2001:db8::1]",
        canonicalAuthority("[2001:DB8::1]:443", &buf),
    );
    try std.testing.expectEqualStrings("", canonicalAuthority("", &buf));
    try std.testing.expectEqualStrings("", canonicalAuthority(":443", &buf));
    // The match itself canonicalizes: an authority in any case or with a
    // port still hits a host-scoped route.
    const routes = [_]Route{
        .{ .host = "api.example", .prefix = "/", .cluster_index = 7 },
        .{ .prefix = "/", .cluster_index = 0 },
    };
    try std.testing.expectEqual(
        @as(?u16, 7),
        find(&routes, canonicalAuthority("API.EXAMPLE:443", &buf), "/x", &.{}).?.cluster_index,
    );
}

// ---------------------------------------------------------------------------
// End-to-end over SimIo: the proxy drives its full exchange state machine
// against a scripted plaintext origin, and every verdict lands in the
// installed counter hook. What the pure tests above cannot reach — the
// witness wiring itself: request/response counts, the 502/504/503 verdicts,
// the deadline timer, and the null-hook path a second proxy runs with no
// counters at all.
// ---------------------------------------------------------------------------

const assert = std.debug.assert;

/// A deep copy of the facts an answer event carried, so the assertions
/// read what the hook witnessed after the exchange slots have been
/// reused and the originals overwritten. `Details` slices point at the
/// exchange's own buffers; a snapshot owns its copy.
const TestSnapshot = struct {
    method: [constants.access_log_method_bytes_max]u8 = undefined,
    method_len: usize = 0,
    path: [constants.access_log_path_bytes_max]u8 = undefined,
    path_len: usize = 0,
    authority: [constants.host_bytes_max]u8 = undefined,
    authority_len: usize = 0,
    peer: std.Io.net.IpAddress = undefined,
    endpoint: ?std.Io.net.IpAddress = null,
    started_wall_ns: u64 = 0,
    started_mono_ns: u64 = 0,
    bytes_in: u64 = 0,
    status: u16 = 0,
    bytes_out: u64 = 0,
    /// The matched route's log decision, as the witness reads it: the
    /// counters above fire either way — only the line is at stake.
    suppress_log: bool = false,

    fn copy(snapshot: *TestSnapshot, details: *const Details) void {
        snapshot.method_len = details.method.len;
        @memcpy(snapshot.method[0..snapshot.method_len], details.method);
        snapshot.path_len = details.path.len;
        @memcpy(snapshot.path[0..snapshot.path_len], details.path);
        snapshot.authority_len = details.authority.len;
        @memcpy(snapshot.authority[0..snapshot.authority_len], details.authority);
        snapshot.peer = details.peer;
        snapshot.endpoint = details.endpoint;
        snapshot.started_wall_ns = details.started_wall_ns;
        snapshot.started_mono_ns = details.started_mono_ns;
        snapshot.bytes_in = details.bytes_in;
        snapshot.status = details.status;
        snapshot.bytes_out = details.bytes_out;
        snapshot.suppress_log = details.suppress_log;
    }
};

/// The answer events a snapshot is kept for, in the order the verdicts
/// are asserted below: one slot each, first occurrence wins.
const snapshot_events = [_]Counters.Event{
    .response,
    .bad_gateway,
    .gateway_timeout,
    .shed_busy,
    // Appended: the first four keep their indices, and every existing
    // assertion reads the slot it always did.
    .no_route,
};

fn snapshotIndex(event: Counters.Event) ?usize {
    for (snapshot_events, 0..) |snapshot_event, index| {
        if (event == snapshot_event) return index;
    }
    return null;
}

/// The test double for a process counter set: one cell per hook event, so
/// the assertions read exactly what the proxy witnessed — plus the first
/// `Details` each answer event carried.
const TestTally = struct {
    counts: [@typeInfo(Counters.Event).@"enum".field_names.len]u64 = @splat(0),
    snapshots: [snapshot_events.len]?TestSnapshot = @splat(null),

    fn note(ctx: *anyopaque, event: Counters.Event, details: ?*const Details) void {
        const tally: *TestTally = @ptrCast(@alignCast(ctx));
        tally.counts[@backingInt(event)] += 1;
        if (details) |facts| {
            if (snapshotIndex(event)) |index| {
                // First occurrence wins: a test that witnesses two of one
                // answer event (a streamed 200 then its follow-up, say)
                // reads the facts it scripted first.
                if (tally.snapshots[index] == null) {
                    tally.snapshots[index] = .{};
                    tally.snapshots[index].?.copy(facts);
                }
            }
        }
    }

    fn get(tally: *const TestTally, event: Counters.Event) u64 {
        return tally.counts[@backingInt(event)];
    }
};

/// Records everything the session sends, so the test asserts each verdict's
/// body reached the client rather than only that a counter moved. The raw
/// prefix keeps the small-response substring assertions honest; `payload`
/// reassembles DATA-frame payloads across sends so a streamed body is
/// checked byte for byte; `fin` catches whether the stream ever closed.
const TestRecorder = struct {
    bytes: [4096]u8 = undefined,
    len: usize = 0,
    sends: usize = 0,
    fin: bool = false,
    /// DATA payloads land here, concatenated, when a test arms the
    /// reassembly of a streamed body.
    payload: ?[]u8 = null,
    payload_len: usize = 0,
    /// Flow-control simulation for the backpressure test: while set,
    /// one send_multi call accepts at most this many payload bytes and
    /// the proxy parks the tail. Null accepts everything.
    window_bytes: ?usize = null,
    /// Payload bytes the window turned away — the evidence that
    /// backpressure actually happened.
    refused: u64 = 0,
    /// While nonzero, each `send_multi` call fails with the live
    /// single-packet fallback's transient backpressure error instead of
    /// accepting — the error spelling of a window that is not open.
    error_times: usize = 0,
    /// The open DATA frame's unpaid payload, so a continuation send
    /// (the proxy's retry tail, headerless by the session's contract)
    /// is told apart from a fresh frame.
    frame_owed: usize = 0,

    /// The sender the streaming tests wire: the multi-packet path with
    /// the window simulation armed.
    fn interface(self: *TestRecorder) session.Sender {
        return .{ .ctx = self, .send = send, .send_multi = sendMulti };
    }

    fn send(ctx: *anyopaque, stream_id: u64, data: []const u8, fin: bool) anyerror!void {
        _ = stream_id;
        const recorder: *TestRecorder = @ptrCast(@alignCast(ctx));
        recorder.sends += 1;
        if (fin) recorder.fin = true;
        recorder.recordRaw(data);
        recorder.recordFrames(data);
    }

    /// The multi-packet path: like `send`, but accepts only what the
    /// simulated window allows and reports the queued wire bytes so the
    /// session hands the proxy a short write.
    fn sendMulti(
        ctx: *anyopaque,
        stream_id: u64,
        framed: []const u8,
        fin: bool,
    ) anyerror!usize {
        _ = stream_id;
        const recorder: *TestRecorder = @ptrCast(@alignCast(ctx));
        recorder.sends += 1;
        if (recorder.error_times > 0) {
            // The single-packet fallback's spelling of backpressure: the
            // whole send fails, nothing queues, and the proxy must park
            // and retry the identical unit later — the failure the live
            // listener's plain-send wiring produces.
            recorder.error_times -= 1;
            return error.QueueFull;
        }
        recorder.recordRaw(framed);
        var header_len: usize = 0;
        var payload = framed;
        if (recorder.frame_owed == 0) {
            // A fresh frame: the leading varints are its header. The
            // session only reaches send_multi from sendData, so these
            // are DATA frames; accept anything else whole, defensively.
            const frame_type = request_stream.readVarint(framed) catch return 0;
            const frame_len = request_stream.readVarint(framed[frame_type.len..]) catch return 0;
            if (frame_type.value != request_stream.frame_type_data) return framed.len;
            header_len = frame_type.len + frame_len.len;
            recorder.frame_owed = @intCast(frame_len.value);
            payload = framed[header_len..];
        }
        const accept = if (recorder.window_bytes) |cap| @min(cap, payload.len) else payload.len;
        if (recorder.frame_owed > 0) recorder.frame_owed -= accept;
        recorder.refused += payload.len - accept;
        if (accept > 0) recorder.recordPayload(payload[0..accept]);
        if (fin and accept == payload.len) recorder.fin = true;
        return header_len + accept;
    }

    fn recordRaw(recorder: *TestRecorder, data: []const u8) void {
        const copy_len = @min(data.len, recorder.bytes.len - recorder.len);
        @memcpy(recorder.bytes[recorder.len..][0..copy_len], data[0..copy_len]);
        recorder.len += copy_len;
    }

    fn recordPayload(recorder: *TestRecorder, body: []const u8) void {
        if (recorder.payload) |sink| {
            const keep = @min(body.len, sink.len - recorder.payload_len);
            @memcpy(sink[recorder.payload_len..][0..keep], body[0..keep]);
            recorder.payload_len += keep;
        }
    }

    fn recordFrames(recorder: *TestRecorder, data: []const u8) void {
        if (recorder.payload == null) return;
        // The session frames whole HTTP/3 frames per send (HEADERS in
        // one, each DATA in another; the one-shot error path may
        // coalesce HEADERS+DATA). Walk them, keep the payloads.
        var rest = data;
        while (rest.len > 0) {
            const frame_type = request_stream.readVarint(rest) catch return;
            const frame_len = request_stream.readVarint(rest[frame_type.len..]) catch return;
            const total = frame_type.len + frame_len.len + @as(usize, @intCast(frame_len.value));
            if (total > rest.len) return;
            if (frame_type.value == request_stream.frame_type_data) {
                recorder.recordPayload(rest[frame_type.len + frame_len.len .. total]);
            }
            rest = rest[total..];
        }
    }
};

/// One scripted origin connection, keep-alive by default: a fully framed
/// request is read — head, then its body per the head's own framing — and
/// answered; the connection then arms its receive again and may serve the
/// next request, which is what makes pool reuse observable through the
/// origin's accept count. The request path and method pick the behavior:
///
/// - anything else: a sized 200 with the origin's `body`, kept alive; a
///   HEAD request gets the head with no body, kept alive;
/// - `/echo`: the received body is counted (decoded, when the upload is
///   chunked) and answered with its decimal size — the upload mirror the
///   live echo origin serves;
/// - `/close`: the request is read, then the connection closes without
///   answering — the exchange sees EOF before a head (a 502);
/// - `/mute...`: read and never answer — a 504 at the exchange deadline;
/// - `/close-header`: a sized 200 carrying `Connection: close`, then the
///   connection closes;
/// - `/no-content`: a 204, kept alive — the exchange finishes at the
///   head;
/// - `/close-delimited`: a 200 with no length, the body, then close —
///   the reply's end is the EOF;
/// - `/truncate`: a `Content-Length` of 100 with five body bytes, then
///   close — the proxy must relay the part, reset the stream, and
///   witness bad_gateway;
/// - `/flood`: a close-delimited body larger than the test's response
///   cap, then close — the proxy cuts the body off mid-stream;
/// - `/big-cl`: a sized 200 of `big_cl_wire` (the scripted large body),
///   kept alive;
/// - `/big-chunked`: `big_chunked_wire`, a chunked encoding of the
///   scripted large body, kept alive;
/// - `/last`: a sized 200 exactly like the default, but the connection
///   closes right after sending without saying so — the parked
///   connection the next checkout inherits is silently dead.
const TestOriginConn = struct {
    sim: *Io.SimIo,
    socket: Io.SimIo.Socket,
    body: []const u8 = "hello",
    /// Scripted large responses, shared read-only from the owning
    /// origin; empty where the test scripts none.
    big_cl_wire: []const u8 = "",
    big_chunked_wire: []const u8 = "",
    flood_wire: []const u8 = "",
    recv_completion: Io.SimIo.Completion = .{},
    send_completion: Io.SimIo.Completion = .{},
    /// Whether the read completion is armed. The full-duplex scripts
    /// answer at the head while the body read is still pending, so the
    /// send's completion can no longer assume the read has landed: an
    /// arm is one completion's worth, exactly like the exchange side.
    recv_armed: bool = false,
    /// The request head accumulates here until its blank line; body
    /// bytes never touch it — they land in `transfer` and are accounted
    /// from there.
    request: [1024]u8 = undefined,
    request_len: usize = 0,
    responded: bool = false,
    scratch: [256]u8 = undefined,
    response_buf: [256]u8 = undefined,
    /// The in-flight response, a slice of `response_buf` or one of the
    /// scripted wires.
    wire: []const u8 = "",
    send_offset: usize = 0,
    /// Close once the in-flight response has fully written, without a
    /// `Connection: close` announcement: the keep-alive shape that lies.
    close_after_send: bool = false,
    /// The full-duplex paths (/early-200, /continue on a bodied
    /// request): the response went out at the head while the request
    /// body is still arriving. The body read continues, and its
    /// completion parks the connection instead of triggering a second
    /// answer.
    early_answered: bool = false,

    /// What the incoming request's body still owes: `.head` until the
    /// blank line, then one of the framings the head declared (the proxy
    /// always declares one), or `.muted` once a mute path swallowed the
    /// exchange.
    phase: RecvPhase = .head,
    /// The declared `Content-Length`, for the tests' assertions.
    upload_cl: ?u64 = null,
    body_remaining: u64 = 0,
    /// Body bytes received, per the framing's semantics: raw bytes for a
    /// Content-Length upload, decoded payload for a chunked one.
    body_received: u64 = 0,
    /// The raw upload bytes, recorded as they arrived — a chunked
    /// upload's framing is asserted from this.
    body_sink: []u8 = &.{},
    body_sink_len: usize = 0,
    chunked_upload: ChunkedDecoder = .{},
    transfer: [chunk_bytes]u8 = undefined,

    const RecvPhase = enum { head, body_cl, body_chunked, muted };

    fn armRecv(self: *TestOriginConn) void {
        if (self.recv_armed) return;
        self.recv_armed = true;
        self.recv_completion = .{};
        const into: []u8 = switch (self.phase) {
            .head => self.request[self.request_len..],
            else => &self.transfer,
        };
        self.sim.recv(
            self.socket,
            into,
            &self.recv_completion,
            TestOriginConn,
            self,
            TestOriginConn.onServeRecv,
        );
    }

    /// Read and never answer: the exchange this connection serves mutes
    /// until its deadline.
    fn armMuteRecv(self: *TestOriginConn) void {
        if (self.recv_armed) return;
        self.recv_armed = true;
        self.phase = .muted;
        self.recv_completion = .{};
        self.sim.recv(
            self.socket,
            &self.scratch,
            &self.recv_completion,
            TestOriginConn,
            self,
            TestOriginConn.onMuteRecv,
        );
    }

    fn onServeRecv(self: *TestOriginConn, result: Io.RecvError!u32) void {
        self.recv_armed = false;
        const read = result catch {
            self.finish();
            return;
        };
        if (read == 0) {
            self.finish();
            return;
        }
        switch (self.phase) {
            .head => {
                self.request_len += read;
                const marker = std.mem.indexOf(
                    u8,
                    self.request[0..self.request_len],
                    "\r\n\r\n",
                ) orelse {
                    // Partial head deliveries re-arm until the blank line.
                    assert(self.request_len < self.request.len);
                    self.armRecv();
                    return;
                };
                // Bytes past the blank line belong to the body — a SimIo
                // delivery coalesces freely — and must be served, not left
                // stranded in the head buffer.
                const head_end = marker + 4;
                const extra_len = self.request_len - head_end;
                var extra: [1024]u8 = undefined;
                @memcpy(extra[0..extra_len], self.request[head_end..self.request_len]);
                self.request_len = head_end;
                self.headComplete();
                switch (self.phase) {
                    // The head declared a body: `headComplete` set the
                    // framing but deliberately armed nothing, so exactly
                    // one arm is issued here — for the bytes already
                    // coalesced past the head when they did not complete
                    // the body, or straight onto the transfer buffer
                    // when the head arrived alone. On the head-only
                    // paths the extra bytes belong to a request whose
                    // answer those paths already scripted: /close's die
                    // with the connection, /mute's are swallowed by the
                    // mute recv `headComplete` armed.
                    .body_cl, .body_chunked => {
                        if (extra_len > 0) {
                            if (!self.serveBody(extra[0..extra_len])) self.armRecv();
                        } else {
                            self.armRecv();
                        }
                    },
                    .head, .muted => {},
                }
            },
            .body_cl, .body_chunked => {
                if (!self.serveBody(self.transfer[0..read])) self.armRecv();
            },
            .muted => unreachable,
        }
    }

    /// Whether the path answers at the head and keeps reading the body
    /// (the full-duplex scripts). The answer for these paths must render
    /// from the head alone — `/continue` carries the 100 the client
    /// would otherwise wait on.
    fn earlyPath(self: *TestOriginConn, path: []const u8) bool {
        _ = self;
        return std.mem.eql(u8, path, "/early-200") or
            std.mem.eql(u8, path, "/continue");
    }

    /// The early answer went out at the head and the late-arriving body
    /// has now been fully consumed: the request is complete and the
    /// connection parks for the next one.
    fn parkAfterEarly(self: *TestOriginConn) bool {
        self.early_answered = false;
        self.responded = false;
        self.request_len = 0;
        self.phase = .head;
        self.armRecv();
        return true;
    }

    /// Feed arrived body bytes through the framing the head declared; true
    /// when the request completed and the response path started.
    fn serveBody(self: *TestOriginConn, bytes: []const u8) bool {
        switch (self.phase) {
            .body_cl => {
                const take: u64 = @min(bytes.len, self.body_remaining);
                self.recordBody(bytes[0..@intCast(take)]);
                self.body_remaining -= take;
                if (self.body_remaining != 0) {
                    assert(take == bytes.len); // a sized body never overshoots
                    return false;
                }
                if (self.early_answered) return self.parkAfterEarly();
                self.responded = true;
                self.respond();
                return true;
            },
            .body_chunked => {
                self.recordBody(bytes);
                var tail = bytes;
                while (tail.len > 0) {
                    const step = self.chunked_upload.step(tail, std.math.maxInt(usize)) catch {
                        // A scripted upload is well-formed; a malformed one
                        // is the proxy's bug, and the assertion below says
                        // so by name.
                        self.finish();
                        return true;
                    };
                    switch (step) {
                        .consume => |n| tail = tail[n..],
                        .payload => |n| {
                            self.body_received += n;
                            self.chunked_upload.data_read += n;
                            tail = tail[n..];
                            if (self.chunked_upload.data_read == self.chunked_upload.size) {
                                self.chunked_upload.state = .data_crlf;
                                self.chunked_upload.crlf = 0;
                            }
                        },
                        .done => {
                            if (self.early_answered) return self.parkAfterEarly();
                            self.responded = true;
                            self.respond();
                            return true;
                        },
                        .need_more => return false,
                    }
                }
                return false;
            },
            .head, .muted => unreachable,
        }
    }

    /// The head is complete: answer what needs no body (`/close`, `/mute`,
    /// a zero length or none declared), else start reading the body under
    /// its own framing.
    fn headComplete(self: *TestOriginConn) void {
        const head = self.request[0..self.request_len];
        const line_end = std.mem.indexOf(u8, head, "\r\n") orelse head.len;
        const line = head[0..line_end];
        const first_space = std.mem.indexOfScalar(u8, line, ' ') orelse
            return self.finish();
        const path_start = first_space + 1;
        const path_end = std.mem.indexOfScalarPos(u8, line, path_start, ' ') orelse line.len;
        const path = line[path_start..path_end];

        var declared_cl: ?u64 = null;
        var declared_chunked = false;
        var offset = line_end + 2;
        while (std.mem.indexOfPos(u8, head, offset, "\r\n")) |newline| {
            if (newline + 2 > head.len - 2) break; // the blank line
            const header_line = head[offset..newline];
            offset = newline + 2;
            const colon = std.mem.indexOfScalar(u8, header_line, ':') orelse continue;
            const name = std.mem.trim(u8, header_line[0..colon], " \t");
            const value = std.mem.trim(u8, header_line[colon + 1 ..], " \t");
            if (std.ascii.eqlIgnoreCase(name, "content-length")) {
                declared_cl = std.fmt.parseInt(u64, value, 10) catch null;
            } else if (std.ascii.eqlIgnoreCase(name, "transfer-encoding")) {
                if (containsIgnoreCase(value, "chunked")) declared_chunked = true;
            }
        }

        // Paths that answer (or close) at the head, whatever the framing.
        if (std.mem.startsWith(u8, path, "/mute")) {
            self.armMuteRecv();
            return;
        }
        if (std.mem.eql(u8, path, "/close")) {
            self.finish();
            return;
        }
        if (std.mem.eql(u8, path, "/reject")) {
            // The early-rejection shape: the head is refused on
            // arrival and the connection dies with the answer. The
            // proxy's upload is orphaned mid-flight — the test asserts
            // the verdict the client already holds is not a 502.
            self.close_after_send = true;
            self.responded = true;
            self.respond();
            return;
        }
        self.upload_cl = declared_cl;
        if (declared_cl) |expected| {
            if (expected == 0) {
                self.responded = true;
                self.respond();
                return;
            }
            self.phase = .body_cl;
            self.body_remaining = expected;
            if (self.earlyPath(path)) {
                // Full duplex: the answer leaves at the head while the
                // body is still arriving; `early_answered` keeps the
                // completion reading instead of answering twice.
                self.early_answered = true;
                self.responded = true;
                self.respond();
            }
            // The recv for the body proper is the caller's to arm: bytes
            // coalesced past the head may already hold it, and one
            // completion may never carry two arms.
            return;
        }
        if (declared_chunked) {
            self.phase = .body_chunked;
            self.chunked_upload = .{};
            if (self.earlyPath(path)) {
                self.early_answered = true;
                self.responded = true;
                self.respond();
            }
            return;
        }
        // No framing declared: treat the request as head-only.
        self.responded = true;
        self.respond();
    }

    /// Record raw body bytes as they arrived — the chunked upload's
    /// framing assertions read this — up to the sink's capacity.
    fn recordBody(self: *TestOriginConn, bytes: []const u8) void {
        if (self.phase == .body_cl) self.body_received += bytes.len;
        const keep = @min(bytes.len, self.body_sink.len - self.body_sink_len);
        @memcpy(self.body_sink[self.body_sink_len..][0..keep], bytes[0..keep]);
        self.body_sink_len += keep;
    }

    /// Build and send the response the request path scripts. A scripted
    /// `wire` may be large (the big-response paths); the small paths
    /// render into `response_buf`. A HEAD request wears the same head
    /// and no body, keep-alive — what a well-behaved origin does.
    fn respond(self: *TestOriginConn) void {
        const head = self.request[0..self.request_len];
        const line_end = std.mem.indexOf(u8, head, "\r\n") orelse head.len;
        const line = head[0..line_end];
        const first_space = std.mem.indexOfScalar(u8, line, ' ') orelse
            return self.finish();
        const path_start = first_space + 1;
        const path_end = std.mem.indexOfScalarPos(u8, line, path_start, ' ') orelse line.len;
        const method = line[0..first_space];
        const path = line[path_start..path_end];
        const is_head = std.mem.eql(u8, method, "HEAD");

        var response: []const u8 = undefined;
        if (std.mem.eql(u8, path, "/echo")) {
            // The upload mirror: answer with the received body's decimal
            // size, exactly the live echo origin's shape.
            var echo_text: [20]u8 = undefined;
            const echoed = std.fmt.bufPrint(&echo_text, "{d}", .{self.body_received}) catch
                unreachable;
            response = std.fmt.bufPrint(
                &self.response_buf,
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n" ++
                    "Content-Length: {d}\r\n\r\n{s}",
                .{ echoed.len, echoed },
            ) catch unreachable;
        } else if (std.mem.eql(u8, path, "/big-cl")) {
            response = self.big_cl_wire;
        } else if (std.mem.eql(u8, path, "/big-chunked")) {
            response = self.big_chunked_wire;
        } else if (std.mem.eql(u8, path, "/flood")) {
            response = self.flood_wire;
            self.close_after_send = true;
        } else {
            response = self.renderSmall(path) orelse return self.finish();
        }
        if (is_head) {
            // The head's terminator is the whole answer; the connection
            // outlives it.
            const end = (std.mem.indexOf(u8, response, "\r\n\r\n") orelse
                return self.finish()) + 4;
            response = response[0..end];
        }
        self.wire = response;
        self.send_offset = 0;
        self.sendResponse();
    }

    /// Render the small scripted responses into `response_buf`; null
    /// means the path was not recognized. Sets `close_after_send` for
    /// the paths whose connection dies with the response.
    fn renderSmall(self: *TestOriginConn, path: []const u8) ?[]const u8 {
        if (std.mem.eql(u8, path, "/close-header")) {
            self.close_after_send = true;
            return std.fmt.bufPrint(
                &self.response_buf,
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n" ++
                    "Content-Length: {d}\r\nConnection: close\r\n\r\n{s}",
                .{ self.body.len, self.body },
            ) catch unreachable; // The bodies under test are a few bytes.
        }
        if (std.mem.eql(u8, path, "/no-content"))
            return "HTTP/1.1 204 No Content\r\nContent-Type: text/plain\r\n\r\n";
        if (std.mem.eql(u8, path, "/reject")) {
            self.close_after_send = true;
            return "HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\n" ++
                "Content-Length: 7\r\n\r\ndenied\n";
        }
        if (std.mem.eql(u8, path, "/early-200"))
            return "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n" ++
                "Content-Length: 2\r\n\r\nok";
        if (std.mem.eql(u8, path, "/continue"))
            return "HTTP/1.1 100 Continue\r\n\r\n" ++
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n" ++
                "Content-Length: 2\r\n\r\nok";
        if (std.mem.eql(u8, path, "/close-delimited")) {
            self.close_after_send = true;
            return std.fmt.bufPrint(
                &self.response_buf,
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n{s}",
                .{self.body},
            ) catch unreachable;
        }
        if (std.mem.eql(u8, path, "/truncate")) {
            self.close_after_send = true;
            return std.fmt.bufPrint(
                &self.response_buf,
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n" ++
                    "Content-Length: 100\r\n\r\npartial",
                .{},
            ) catch unreachable;
        }
        if (std.mem.eql(u8, path, "/last")) {
            self.close_after_send = true;
            return std.fmt.bufPrint(
                &self.response_buf,
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n" ++
                    "Content-Length: {d}\r\n\r\n{s}",
                .{ self.body.len, self.body },
            ) catch unreachable;
        }
        return std.fmt.bufPrint(
            &self.response_buf,
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n" ++
                "Content-Length: {d}\r\n\r\n{s}",
            .{ self.body.len, self.body },
        ) catch unreachable;
    }

    /// Send the response's remaining bytes. SimIo short-writes by design
    /// (§9's partial deliveries), so a short send re-arms the remainder
    /// rather than closing on a half-written body.
    fn sendResponse(self: *TestOriginConn) void {
        self.send_completion = .{};
        self.sim.send(
            self.socket,
            self.wire[self.send_offset..],
            &self.send_completion,
            TestOriginConn,
            self,
            TestOriginConn.onSent,
        );
    }

    fn onSent(self: *TestOriginConn, result: Io.SendError!u32) void {
        const written = result catch {
            self.finish();
            return;
        };
        if (written == 0) {
            self.finish();
            return;
        }
        self.send_offset += written;
        if (self.send_offset < self.wire.len) {
            self.sendResponse();
            return;
        }
        if (self.close_after_send) {
            self.finish();
            return;
        }
        if (self.early_answered and
            (self.phase == .body_cl or self.phase == .body_chunked))
        {
            // The early answer is fully written; the request's body is
            // still arriving, so the body read continues instead of the
            // connection resetting for the next request.
            self.armRecv();
            return;
        }
        // Keep-alive: the connection serves the next request. The body
        // counters stay cumulative — a follow-up GET adds nothing — so a
        // test may assert them after the whole scenario has run.
        self.responded = false;
        self.request_len = 0;
        self.phase = .head;
        self.armRecv();
    }

    fn onMuteRecv(self: *TestOriginConn, result: Io.RecvError!u32) void {
        self.recv_armed = false;
        const read = result catch {
            // The proxy finished or its deadline shut the socket down.
            self.finish();
            return;
        };
        if (read == 0) {
            self.finish();
            return;
        }
        self.armMuteRecv();
    }

    fn finish(self: *TestOriginConn) void {
        Io.SimIo.closeNow(self.sim, self.socket);
    }
};

const TestOrigin = struct {
    sim: *Io.SimIo,
    listener: Io.SimIo.Listener,
    body: []const u8 = "hello",
    /// Scripted large responses, handed to every accepted connection.
    big_cl_wire: []const u8 = "",
    big_chunked_wire: []const u8 = "",
    flood_wire: []const u8 = "",
    /// Raw record of the first accepted connection's upload, capacity
    /// bounding the keep. Empty where a test only counts `body_received`.
    body_sink: []u8 = &.{},
    accept_completion: Io.SimIo.Completion = .{},
    accepted_count: usize = 0,
    conns: [8]TestOriginConn = undefined,

    fn armAccept(self: *TestOrigin) void {
        self.accept_completion = .{};
        self.sim.accept(
            self.listener,
            &self.accept_completion,
            TestOrigin,
            self,
            TestOrigin.onAccept,
        );
    }

    fn onAccept(self: *TestOrigin, result: Io.AcceptError!Io.SimIo.Socket) void {
        const socket = result catch return;
        assert(self.accepted_count < self.conns.len);
        const conn = &self.conns[self.accepted_count];
        self.accepted_count += 1;
        conn.* = .{
            .sim = self.sim,
            .socket = socket,
            .body = self.body,
            .big_cl_wire = self.big_cl_wire,
            .big_chunked_wire = self.big_chunked_wire,
            .flood_wire = self.flood_wire,
            .body_sink = self.body_sink,
        };
        conn.armRecv();
        self.armAccept();
    }
};

/// Fire one proxied request when the timer fires: the deterministic
/// "everything scheduled earlier has settled" point. A request fired
/// synchronously with the first can never observe pool reuse — its
/// predecessor's connection is still serving — so the pool tests fire
/// their follow-ups from a timer at t≈0, after the first exchange's
/// t=0 deliveries have all completed.
const RequestTimer = struct {
    sim: *Io.SimIo,
    handler: session.RequestHandler,
    h3: *session.H3Session,
    stream_id: u64,
    path: []const u8,
    completion: Io.SimIo.Completion = .{},
    fired: bool = false,

    fn arm(self: *RequestTimer, delay_ns: u64) void {
        self.completion = .{};
        self.sim.timerStart(
            &self.completion,
            delay_ns,
            RequestTimer,
            self,
            RequestTimer.onFire,
        );
    }

    fn onFire(self: *RequestTimer, result: Io.TimerError!void) void {
        _ = result catch {};
        self.fired = true;
        const request = testRequest(self.stream_id, self.path);
        self.handler.onRequest(self.handler.ctx, self.h3, self.stream_id, &request);
        finishBody(self.handler, self.h3, self.stream_id);
    }
};

const StopTimer = struct {
    sim: *Io.SimIo,

    fn onFire(self: *StopTimer, result: Io.TimerError!void) void {
        _ = result catch {};
        self.sim.stop();
    }
};

fn testRequest(stream_id: u64, path: []const u8) request_stream.Request {
    return testRequestAuthority(stream_id, path, null);
}

fn testRequestAuthority(
    stream_id: u64,
    path: []const u8,
    authority: ?[]const u8,
) request_stream.Request {
    return testRequestMethod(stream_id, "GET", path, authority);
}

fn testRequestMethod(
    stream_id: u64,
    method: []const u8,
    path: []const u8,
    authority: ?[]const u8,
) request_stream.Request {
    return .{
        .stream_id = stream_id,
        .method = method,
        .scheme = "https",
        .authority = authority,
        .path = path,
        .headers = &.{},
        .trailers = &.{},
        .body = "",
        // Every helper-built request is driven with `finishBody` right
        // behind `onRequest` and no body pieces — the hand-driven
        // equivalent of the session's fin-on-HEADERS delivery. Bodied
        // requests build the Request at the call site and stream pieces
        // explicitly.
        .fin_on_headers = true,
    };
}

fn neverHandler() session.RequestHandler {
    const Never = struct {
        fn onRequest(
            _: *anyopaque,
            _: *session.H3Session,
            _: u64,
            _: *const request_stream.Request,
        ) void {
            // The proxy under test is invoked directly; the session's
            // own handler must never fire. ctx is never dereferenced.
        }
    };
    return .{ .ctx = @ptrFromInt(1), .onRequest = Never.onRequest };
}

/// Drive the upload-completion the session guarantees: the proxy's
/// handler is invoked directly in these tests, bypassing the session's
/// feed loop, so the terminal body chunk — `(empty, fin)` for these
/// requests — is delivered by hand right behind `onRequest`.
fn finishBody(handler: session.RequestHandler, h3: *session.H3Session, stream_id: u64) void {
    const onBodyChunk = handler.onBodyChunk.?;
    onBodyChunk(handler.ctx, h3, stream_id, "", true) catch {};
}

test "h3 proxy: exchanges witness requests, verdicts and responses into a counter hook" {
    const SimIo = Io.SimIo;
    const TestProxy = Proxy(SimIo, 4);

    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var sim_io: SimIo = undefined;
    try sim_io.init(arena, .{ .seed = 41 });

    const loopback = try std.Io.net.IpAddress.parseLiteral("127.0.0.1:0");
    const listener = try sim_io.listen(&.{ .ip = loopback }, null);
    var origin: TestOrigin = .{ .sim = &sim_io, .listener = listener };
    origin.armAccept();
    const endpoint = sim_io.listenerAddress(listener);
    var endpoints = [_]std.Io.net.IpAddress{endpoint};

    var tally: TestTally = .{};
    var proxy_a: TestProxy = undefined;
    try proxy_a.initInPlace(&sim_io, arena, &endpoints, .{
        .timeout_ns = 100 * std.time.ns_per_ms,
        .counters = .{ .ctx = &tally, .note = TestTally.note },
    });
    var proxy_b: Proxy(SimIo, 1) = undefined;
    try proxy_b.initInPlace(&sim_io, arena, &endpoints, .{
        .timeout_ns = 50 * std.time.ns_per_ms,
    });

    var recorder: TestRecorder = .{};
    var h3: session.H3Session = undefined;
    try h3.initInPlace(
        arena,
        .{ .ctx = &recorder, .send = TestRecorder.send },
        neverHandler(),
    );
    // The listener sets this right after initInPlace; the test plays the
    // listener so the witnessed client address is a known value.
    h3.peer = try std.Io.net.IpAddress.parseLiteral("127.0.0.1:4333");

    // The stop backstop: an armed accept is never quiescent — only timers
    // schedule wakes — so once every exchange has settled the loop would
    // otherwise end in Deadlock.
    var stop = StopTimer{ .sim = &sim_io };
    var stop_completion: SimIo.Completion = .{};
    sim_io.timerStart(
        &stop_completion,
        2 * std.time.ns_per_s,
        StopTimer,
        &stop,
        StopTimer.onFire,
    );

    const request_a = proxy_a.handler();
    const request1 = testRequestAuthority(0, "/serve", "Origin.Test:8000");
    request_a.onRequest(request_a.ctx, &h3, 0, &request1);
    finishBody(request_a, &h3, 0);
    const request2 = testRequest(4, "/close");
    request_a.onRequest(request_a.ctx, &h3, 4, &request2);
    finishBody(request_a, &h3, 4);
    const request3 = testRequest(8, "/mute");
    request_a.onRequest(request_a.ctx, &h3, 8, &request3);
    finishBody(request_a, &h3, 8);
    const request4 = testRequest(12, "/mute");
    request_a.onRequest(request_a.ctx, &h3, 12, &request4);
    finishBody(request_a, &h3, 12);
    // All four exchanges fired before the loop ran: none of their
    // connections has parked yet, so every dial is fresh — the origin
    // accepts four. Both slots now carry the two mute exchanges; this
    // one is shed.
    const request5 = testRequest(16, "/busy");
    request_a.onRequest(request_a.ctx, &h3, 16, &request5);
    finishBody(request_a, &h3, 16);
    // A proxy with no hook installed must run identical traffic unwitnessed.
    const request_b = proxy_b.handler();
    const request6 = testRequest(20, "/null-hook");
    request_b.onRequest(request_b.ctx, &h3, 20, &request6);
    finishBody(request_b, &h3, 20);

    try sim_io.run();

    try std.testing.expectEqual(@as(u64, 5), tally.get(.request));
    try std.testing.expectEqual(@as(u64, 1), tally.get(.response));
    try std.testing.expectEqual(@as(u64, 1), tally.get(.bad_gateway));
    try std.testing.expectEqual(@as(u64, 2), tally.get(.gateway_timeout));
    try std.testing.expectEqual(@as(u64, 1), tally.get(.shed_busy));
    // The listener owns the session counters; this file's hook never fires them.
    try std.testing.expectEqual(@as(u64, 0), tally.get(.connection_opened));
    // Five dials, one per fired request (reuse is the pool tests' subject;
    // here every request preceded its predecessor's settle).
    try std.testing.expectEqual(@as(usize, 5), origin.accepted_count);

    // Every verdict reached the client: the 200 body, the three error
    // bodies (two 504s share one spelling), and the shed's. The 200s
    // cost HEADERS plus one DATA per delivery the origin fragmented
    // into — stream 20's "hello" arrived as "hel" and "lo", two frames.
    const transcript = recorder.bytes[0..recorder.len];
    try std.testing.expect(std.mem.indexOf(u8, transcript, "hello") != null);
    try std.testing.expect(std.mem.indexOf(u8, transcript, "bad gateway\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, transcript, "gateway timeout\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, transcript, "busy\n") != null);
    try std.testing.expectEqual(@as(usize, 9), recorder.sends);

    // The answer events carried the facts a log line needs. The verdicts
    // pair with their requests deterministically: the paths script the
    // origin — /serve answers, /close dies unanswered, /mute never
    // answers — and every request dialed fresh.
    const response = tally.snapshots[0].?;
    const bad_gateway = tally.snapshots[1].?;
    const gateway_timeout = tally.snapshots[2].?;
    const shed = tally.snapshots[3].?;

    // Facts never migrate between requests: the 200, the 502 and the
    // first 504 are three distinct requests out of the four dialed.
    try std.testing.expect(!std.mem.eql(
        u8,
        response.path[0..response.path_len],
        bad_gateway.path[0..bad_gateway.path_len],
    ));
    try std.testing.expect(!std.mem.eql(
        u8,
        response.path[0..response.path_len],
        gateway_timeout.path[0..gateway_timeout.path_len],
    ));
    try std.testing.expect(!std.mem.eql(
        u8,
        bad_gateway.path[0..bad_gateway.path_len],
        gateway_timeout.path[0..gateway_timeout.path_len],
    ));

    // The 200: payload bytes both ways ("hello" out, no body in), the
    // dial's endpoint named, both clocks stamped, the peer the listener
    // would have set.
    try std.testing.expectEqualStrings("GET", response.method[0..response.method_len]);
    try std.testing.expectEqual(h3.peer, response.peer);
    try std.testing.expectEqual(endpoint, response.endpoint.?);
    try std.testing.expect(response.started_wall_ns != 0);
    try std.testing.expect(response.started_mono_ns != 0);
    try std.testing.expectEqual(@as(u64, 0), response.bytes_in);
    try std.testing.expectEqual(@as(u16, 200), response.status);
    try std.testing.expectEqual(@as(u64, 5), response.bytes_out); // "hello"
    // Authority is captured verbatim — canonicalizing is the Record
    // builder's job — and only the /serve request carried one.
    try std.testing.expectEqualStrings(
        if (std.mem.eql(u8, response.path[0..response.path_len], "/serve")) "Origin.Test:8000" else "",
        response.authority[0..response.authority_len],
    );

    // The 502: verdict and error page size, endpoint named even though
    // the origin died on the exchange.
    try std.testing.expectEqual(@as(u16, 502), bad_gateway.status);
    try std.testing.expectEqual(@as(u64, 12), bad_gateway.bytes_out); // "bad gateway\n"
    try std.testing.expectEqual(endpoint, bad_gateway.endpoint.?);
    try std.testing.expectEqual(h3.peer, bad_gateway.peer);
    try std.testing.expect(bad_gateway.started_mono_ns != 0);

    // The 504: the deadline committed the verdict; same shape, page size
    // of the timeout's own answer.
    try std.testing.expectEqual(@as(u16, 504), gateway_timeout.status);
    try std.testing.expectEqual(@as(u64, 16), gateway_timeout.bytes_out); // "gateway timeout\n"
    try std.testing.expectEqual(endpoint, gateway_timeout.endpoint.?);

    // The shed: answered from the handler's stack, so no endpoint, but
    // the request's own facts and the 503 page size all the same. This
    // pairing *is* deterministic: the shed happens in the handler, before
    // the loop runs.
    try std.testing.expectEqualStrings("/busy", shed.path[0..shed.path_len]);
    try std.testing.expectEqual(@as(u16, 503), shed.status);
    try std.testing.expectEqual(@as(u64, 5), shed.bytes_out); // "busy\n"
    try std.testing.expect(shed.endpoint == null);
    try std.testing.expectEqual(h3.peer, shed.peer);
    try std.testing.expect(shed.started_wall_ns != 0);
}

/// The routing test's witness: besides the per-event cells, one row per
/// `.response` carrying the path and the seam cluster index the dial
/// selected — the two facts that prove the table, not just the verdicts.
const RouteTally = struct {
    counts: [@typeInfo(Counters.Event).@"enum".field_names.len]u64 = @splat(0),
    paths: [8][constants.access_log_path_bytes_max]u8 = undefined,
    path_lens: [8]usize = @splat(0),
    clusters: [8]u16 = undefined,
    responses: usize = 0,

    fn note(ctx: *anyopaque, event: Counters.Event, details: ?*const Details) void {
        const tally: *RouteTally = @ptrCast(@alignCast(ctx));
        tally.counts[@backingInt(event)] += 1;
        if (event != .response) return;
        const facts = details.?;
        assert(tally.responses < tally.paths.len);
        const at = tally.responses;
        tally.path_lens[at] = facts.path.len;
        @memcpy(tally.paths[at][0..facts.path.len], facts.path);
        tally.clusters[at] = facts.cluster_index;
        tally.responses += 1;
    }

    fn get(tally: *const RouteTally, event: Counters.Event) u64 {
        return tally.counts[@backingInt(event)];
    }

    /// How many witnessed responses paired `path` with `cluster_index`.
    fn countPair(tally: *const RouteTally, path: []const u8, cluster_index: u16) usize {
        var found: usize = 0;
        for (0..tally.responses) |at| {
            if (tally.clusters[at] == cluster_index and
                std.mem.eql(u8, tally.paths[at][0..tally.path_lens[at]], path))
            {
                found += 1;
            }
        }
        return found;
    }
};

fn countOccurrences(haystack: []const u8, needle: []const u8) usize {
    var found: usize = 0;
    var at: usize = 0;
    while (std.mem.indexOfPos(u8, haystack, at, needle)) |index| {
        found += 1;
        at = index + needle.len;
    }
    return found;
}

test "h3 proxy: routed exchanges reach the selected cluster and 404 what nothing matches" {
    const SimIo = Io.SimIo;
    const TestProxy = Proxy(SimIo, 8);

    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var sim_io: SimIo = undefined;
    try sim_io.init(arena, .{ .seed = 43 });

    const loopback = try std.Io.net.IpAddress.parseLiteral("127.0.0.1:0");
    const listener_a = try sim_io.listen(&.{ .ip = loopback }, null);
    var origin_a: TestOrigin = .{
        .sim = &sim_io,
        .listener = listener_a,
        .body = "from-a",
    };
    origin_a.armAccept();
    const endpoint_a = sim_io.listenerAddress(listener_a);
    const listener_b = try sim_io.listen(&.{ .ip = loopback }, null);
    var origin_b: TestOrigin = .{
        .sim = &sim_io,
        .listener = listener_b,
        .body = "from-b",
    };
    origin_b.armAccept();
    const endpoint_b = sim_io.listenerAddress(listener_b);

    const endpoints_a = try arena.alloc(std.Io.net.IpAddress, 1);
    endpoints_a[0] = endpoint_a;
    const endpoints_b = try arena.alloc(std.Io.net.IpAddress, 1);
    endpoints_b[0] = endpoint_b;

    // The table config.zig hands a listener: host-specific first, then
    // longest prefix, then the catch-all. Cluster 0 is origin_a, cluster
    // 1 is origin_b; each proxy owns its Cluster copies — the round-robin
    // cursors must not interleave across proxies.
    var routes = [_]Route{
        .{ .host = "vip.test", .prefix = "/", .cluster_index = 0 },
        .{ .prefix = "/a", .cluster_index = 0 },
        .{ .prefix = "/", .cluster_index = 1 },
    };
    // A table with no catch-all: what nothing matches is the caller's 404.
    var narrow_routes = [_]Route{
        .{ .prefix = "/a", .cluster_index = 0 },
    };
    var clusters = [_]Cluster{
        .{ .endpoints = endpoints_a },
        .{ .endpoints = endpoints_b },
    };
    var narrow_clusters = [_]Cluster{
        .{ .endpoints = endpoints_a },
    };

    var tally: RouteTally = .{};
    var proxy: TestProxy = undefined;
    try proxy.initInPlaceRouted(&sim_io, arena, &routes, &clusters, .{
        .timeout_ns = 100 * std.time.ns_per_ms,
        .counters = .{ .ctx = &tally, .note = RouteTally.note },
    });
    var narrow: Proxy(SimIo, 1) = undefined;
    try narrow.initInPlaceRouted(&sim_io, arena, &narrow_routes, &narrow_clusters, .{
        .timeout_ns = 100 * std.time.ns_per_ms,
        .counters = .{ .ctx = &tally, .note = RouteTally.note },
    });

    var recorder: TestRecorder = .{};
    var h3: session.H3Session = undefined;
    try h3.initInPlace(
        arena,
        .{ .ctx = &recorder, .send = TestRecorder.send },
        neverHandler(),
    );
    h3.peer = try std.Io.net.IpAddress.parseLiteral("127.0.0.1:4333");

    var stop = StopTimer{ .sim = &sim_io };
    var stop_completion: SimIo.Completion = .{};
    sim_io.timerStart(
        &stop_completion,
        2 * std.time.ns_per_s,
        StopTimer,
        &stop,
        StopTimer.onFire,
    );

    const routed = proxy.handler();
    // Longest prefix wins over the catch-all.
    const request1 = testRequestAuthority(0, "/a/deep", null);
    routed.onRequest(routed.ctx, &h3, 0, &request1);
    finishBody(routed, &h3, 0);
    // A host-scoped route beats the any-host catch-all whatever the path,
    // and the authority canonicalizes before the compare.
    const request2 = testRequestAuthority(4, "/zzz", "VIP.test:8443");
    routed.onRequest(routed.ctx, &h3, 4, &request2);
    finishBody(routed, &h3, 4);
    // Another authority falls to the catch-all.
    const request3 = testRequestAuthority(8, "/zzz", "other.test:8443");
    routed.onRequest(routed.ctx, &h3, 8, &request3);
    finishBody(routed, &h3, 8);
    // No authority meets only the any-host routes.
    const request4 = testRequest(12, "/zzz");
    routed.onRequest(routed.ctx, &h3, 12, &request4);
    finishBody(routed, &h3, 12);
    // The no-catch-all table: one matched, one answered 404 without a dial.
    const narrow_handler = narrow.handler();
    const request5 = testRequest(16, "/a");
    narrow_handler.onRequest(narrow_handler.ctx, &h3, 16, &request5);
    finishBody(narrow_handler, &h3, 16);
    const request6 = testRequest(20, "/b");
    narrow_handler.onRequest(narrow_handler.ctx, &h3, 20, &request6);
    finishBody(narrow_handler, &h3, 20);

    try sim_io.run();

    // Both proxies witness into one tally: six requests in, five relayed
    // responses out — the sixth was answered 404 without a dial — and no
    // failure verdict anywhere.
    try std.testing.expectEqual(@as(u64, 6), tally.get(.request));
    try std.testing.expectEqual(@as(u64, 5), tally.get(.response));
    try std.testing.expectEqual(@as(u64, 0), tally.get(.bad_gateway));
    try std.testing.expectEqual(@as(u64, 0), tally.get(.gateway_timeout));
    try std.testing.expectEqual(@as(u64, 0), tally.get(.shed_busy));

    // The cluster selection is witnessed per response, and the origin
    // accept counts say the same thing from the other side of the dial:
    // three dials to origin_a, two to origin_b. Every request fired
    // before the loop ran, so no connection had parked yet and each
    // request dialed fresh — reuse itself is the pool tests' subject.
    try std.testing.expectEqual(@as(usize, 5), tally.responses);
    try std.testing.expectEqual(@as(usize, 1), tally.countPair("/a/deep", 0));
    try std.testing.expectEqual(@as(usize, 1), tally.countPair("/zzz", 0));
    try std.testing.expectEqual(@as(usize, 2), tally.countPair("/zzz", 1));
    try std.testing.expectEqual(@as(usize, 1), tally.countPair("/a", 0));
    try std.testing.expectEqual(@as(usize, 3), origin_a.accepted_count);
    try std.testing.expectEqual(@as(usize, 2), origin_b.accepted_count);

    // Every verdict reached the client: three of origin_a's body, two of
    // origin_b's, and the no-route 404 — which never dialed, so the
    // accept counts above stay 3 and 2.
    const transcript = recorder.bytes[0..recorder.len];
    try std.testing.expectEqual(@as(usize, 3), countOccurrences(transcript, "from-a"));
    try std.testing.expectEqual(@as(usize, 2), countOccurrences(transcript, "from-b"));
    try std.testing.expectEqual(@as(usize, 1), countOccurrences(transcript, "no route\n"));
    // Five streamed 200s (HEADERS + DATA each) and the one-shot 404 page.
    try std.testing.expectEqual(@as(usize, 11), recorder.sends);
}

/// A bodied request the upload tests drive: a POST whose `fin_on_headers`
/// stays false — the body pieces stream in behind the head through
/// `onBodyChunk`, the way the session delivers a request that did not end
/// on its HEADERS frame.
fn testPostRequest(
    stream_id: u64,
    path: []const u8,
    headers: []request_stream.Header,
) request_stream.Request {
    return .{
        .stream_id = stream_id,
        .method = "POST",
        .scheme = "https",
        .authority = null,
        .path = path,
        .headers = headers,
        .trailers = &.{},
        .body = "",
        .fin_on_headers = false,
    };
}

/// Drive a request's upload the way the session drives it — body pieces
/// in arrival order through the handler's `onBodyChunk`, the fin marker
/// on the completing piece — but paced: a timer arms each piece, the
/// deterministic point after every earlier delivery has settled, which is
/// also what keeps a large upload inside the exchange's staging queue as
/// the wire toward the origin drains.
const UploadFeeder = struct {
    sim: *Io.SimIo,
    handler: session.RequestHandler,
    h3: *session.H3Session,
    stream_id: u64,
    body: []const u8,
    sent: usize = 0,
    piece_bytes: usize,
    step_ns: u64,
    /// Full-duplex assertion hook: runs once, just before the fin piece
    /// is staged — the point by which a concurrent response must
    /// already have reached the client.
    before_fin: ?*const fn (ctx: *anyopaque) void = null,
    before_fin_ctx: *anyopaque = undefined,
    completion: Io.SimIo.Completion = .{},

    fn arm(self: *UploadFeeder) void {
        self.completion = .{};
        self.sim.timerStart(
            &self.completion,
            self.step_ns,
            UploadFeeder,
            self,
            UploadFeeder.onFire,
        );
    }

    fn onFire(self: *UploadFeeder, result: Io.TimerError!void) void {
        _ = result catch {};
        const rest = self.body[self.sent..];
        const piece = rest[0..@min(self.piece_bytes, rest.len)];
        self.sent += piece.len;
        const fin = self.sent == self.body.len;
        if (fin) {
            if (self.before_fin) |hook| hook(self.before_fin_ctx);
        }
        const onBodyChunk = self.handler.onBodyChunk.?;
        onBodyChunk(self.handler.ctx, self.h3, self.stream_id, piece, fin) catch {
            // A staging overflow discarded the upload; the run settles
            // silently and the assertions after it read the silence.
            return;
        };
        if (!fin) self.arm();
    }
};

fn uploadPattern(arena: std.mem.Allocator, len: usize) ![]u8 {
    const pattern = try arena.alloc(u8, len);
    for (pattern, 0..) |*byte, index| byte.* = @truncate(index *% 31 +% 7);
    return pattern;
}

test "h3 proxy: a 100 KiB Content-Length upload streams to the origin whole and the echo answers 200" {
    const upload_bytes = 100 * 1024;
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var sim_io: Io.SimIo = undefined;
    try sim_io.init(arena, .{ .seed = 59 });
    const loopback = try std.Io.net.IpAddress.parseLiteral("127.0.0.1:0");
    const listener = try sim_io.listen(&.{ .ip = loopback }, null);
    var origin: TestOrigin = .{ .sim = &sim_io, .listener = listener };
    origin.armAccept();
    const endpoint = sim_io.listenerAddress(listener);
    var endpoints = [_]std.Io.net.IpAddress{endpoint};

    var tally: TestTally = .{};
    var proxy: Proxy(Io.SimIo, 2) = undefined;
    try proxy.initInPlace(&sim_io, arena, &endpoints, .{
        .counters = .{ .ctx = &tally, .note = TestTally.note },
    });

    var recorder: TestRecorder = .{};
    var payload_buf: [32]u8 = undefined;
    var h3: session.H3Session = undefined;
    try h3.initInPlace(
        arena,
        .{ .ctx = &recorder, .send = TestRecorder.send, .send_multi = TestRecorder.sendMulti },
        neverHandler(),
    );
    h3.peer = try std.Io.net.IpAddress.parseLiteral("127.0.0.1:4333");
    recorder.payload = &payload_buf;

    var stop = StopTimer{ .sim = &sim_io };
    var stop_completion: Io.SimIo.Completion = .{};
    sim_io.timerStart(
        &stop_completion,
        2 * std.time.ns_per_s,
        StopTimer,
        &stop,
        StopTimer.onFire,
    );

    const pattern = try uploadPattern(arena, upload_bytes);
    // The raw record of what reached the origin: Content-Length framing
    // passes body bytes through untouched, so the sink must hold the
    // pattern itself, byte for byte.
    const sink = try arena.alloc(u8, upload_bytes);
    origin.body_sink = sink;

    var headers = [_]request_stream.Header{
        .{ .name = "content-length", .value = "102400" },
    };
    const request = testPostRequest(0, "/echo", &headers);
    const handler = proxy.handler();
    handler.onRequest(handler.ctx, &h3, 0, &request);
    var feeder: UploadFeeder = .{
        .sim = &sim_io,
        .handler = handler,
        .h3 = &h3,
        .stream_id = 0,
        .body = pattern,
        .piece_bytes = 4 * 1024,
        .step_ns = std.time.ns_per_ms,
    };
    feeder.arm();

    try sim_io.run();

    // The whole upload reached the origin — the counted payload and the
    // raw bytes both, which is the Content-Length pass-through proof.
    const conn = &origin.conns[0];
    try std.testing.expectEqual(@as(u64, upload_bytes), conn.body_received);
    try std.testing.expectEqual(@as(usize, upload_bytes), conn.body_sink_len);
    try std.testing.expectEqualSlices(u8, pattern, sink[0..conn.body_sink_len]);
    // The echo origin answered with the body's decimal size, relayed as
    // the response payload, and the tally saw one clean response.
    try std.testing.expectEqual(@as(u64, 1), tally.get(.response));
    try std.testing.expectEqual(@as(u64, 0), tally.get(.bad_gateway));
    try std.testing.expectEqual(@as(usize, 6), recorder.payload_len);
    try std.testing.expectEqualSlices(u8, "102400", payload_buf[0..recorder.payload_len]);
    try std.testing.expect(recorder.fin);
}

test "h3 proxy: a 100 KiB chunked upload re-frames each piece and the terminator completes it at the origin" {
    const upload_bytes = 100 * 1024;
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var sim_io: Io.SimIo = undefined;
    try sim_io.init(arena, .{ .seed = 61 });
    const loopback = try std.Io.net.IpAddress.parseLiteral("127.0.0.1:0");
    const listener = try sim_io.listen(&.{ .ip = loopback }, null);
    var origin: TestOrigin = .{ .sim = &sim_io, .listener = listener };
    origin.armAccept();
    const endpoint = sim_io.listenerAddress(listener);
    var endpoints = [_]std.Io.net.IpAddress{endpoint};

    var tally: TestTally = .{};
    var proxy: Proxy(Io.SimIo, 2) = undefined;
    try proxy.initInPlace(&sim_io, arena, &endpoints, .{
        .counters = .{ .ctx = &tally, .note = TestTally.note },
    });

    var recorder: TestRecorder = .{};
    var payload_buf: [32]u8 = undefined;
    var h3: session.H3Session = undefined;
    try h3.initInPlace(
        arena,
        .{ .ctx = &recorder, .send = TestRecorder.send, .send_multi = TestRecorder.sendMulti },
        neverHandler(),
    );
    h3.peer = try std.Io.net.IpAddress.parseLiteral("127.0.0.1:4333");
    recorder.payload = &payload_buf;

    var stop = StopTimer{ .sim = &sim_io };
    var stop_completion: Io.SimIo.Completion = .{};
    sim_io.timerStart(
        &stop_completion,
        2 * std.time.ns_per_s,
        StopTimer,
        &stop,
        StopTimer.onFire,
    );

    const pattern = try uploadPattern(arena, upload_bytes);
    // No Content-Length: the proxy generates chunked framing, so the raw
    // wire record must show the size lines, the CRLFs, and the
    // terminator — 25 pieces of 4 KiB, then `0\r\n\r\n`.
    const piece_wire = 6 + 4 * 1024 + 2; // "1000\r\n" + piece + "\r\n"
    const sink = try arena.alloc(u8, 25 * piece_wire + 5);
    origin.body_sink = sink;

    var headers = [_]request_stream.Header{
        .{ .name = "content-type", .value = "application/octet-stream" },
    };
    const request = testPostRequest(0, "/echo", &headers);
    const handler = proxy.handler();
    handler.onRequest(handler.ctx, &h3, 0, &request);
    var feeder: UploadFeeder = .{
        .sim = &sim_io,
        .handler = handler,
        .h3 = &h3,
        .stream_id = 0,
        .body = pattern,
        .piece_bytes = 4 * 1024,
        .step_ns = std.time.ns_per_ms,
    };
    feeder.arm();

    try sim_io.run();

    const conn = &origin.conns[0];
    try std.testing.expectEqual(@as(u64, upload_bytes), conn.body_received);
    try std.testing.expectEqual(@as(usize, 25 * piece_wire + 5), conn.body_sink_len);
    try std.testing.expectEqualSlices(u8, "1000\r\n", sink[0..6]);
    try std.testing.expectEqualSlices(u8, "0\r\n\r\n", sink[conn.body_sink_len - 5 ..]);
    // The decoded body matches too — the framing did not corrupt a byte:
    // the first piece sits right behind its size line, as received.
    try std.testing.expectEqualSlices(u8, pattern[0 .. 4 * 1024], sink[6 .. 6 + 4 * 1024]);
    try std.testing.expectEqual(@as(u64, 1), tally.get(.response));
    try std.testing.expectEqualSlices(u8, "102400", payload_buf[0..recorder.payload_len]);
    try std.testing.expect(recorder.fin);
}

test "h3 proxy: an early rejecting origin answers 4xx while the upload is still draining" {
    // Full duplex, the refused shape: the origin answers 403 at the head
    // and closes. The verdict the client already holds is the 403 — not
    // a 502 for the orphaned upload — and a connection whose upload was
    // abandoned can never park (bytes the origin never read would desync
    // the next request).
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var sim_io: Io.SimIo = undefined;
    try sim_io.init(arena, .{ .seed = 67 });
    const loopback = try std.Io.net.IpAddress.parseLiteral("127.0.0.1:0");
    const listener = try sim_io.listen(&.{ .ip = loopback }, null);
    var origin: TestOrigin = .{ .sim = &sim_io, .listener = listener };
    origin.armAccept();
    const endpoint = sim_io.listenerAddress(listener);
    var endpoints = [_]std.Io.net.IpAddress{endpoint};

    var tally: TestTally = .{};
    var proxy: Proxy(Io.SimIo, 2) = undefined;
    try proxy.initInPlace(&sim_io, arena, &endpoints, .{
        .counters = .{ .ctx = &tally, .note = TestTally.note },
    });

    var recorder: TestRecorder = .{};
    var h3: session.H3Session = undefined;
    try h3.initInPlace(
        arena,
        .{ .ctx = &recorder, .send = TestRecorder.send, .send_multi = TestRecorder.sendMulti },
        neverHandler(),
    );
    h3.peer = try std.Io.net.IpAddress.parseLiteral("127.0.0.1:4333");

    var stop = StopTimer{ .sim = &sim_io };
    var stop_completion: Io.SimIo.Completion = .{};
    sim_io.timerStart(
        &stop_completion,
        2 * std.time.ns_per_s,
        StopTimer,
        &stop,
        StopTimer.onFire,
    );

    const pattern = try uploadPattern(arena, 64 * 1024);
    var headers = [_]request_stream.Header{
        .{ .name = "content-length", .value = "65536" },
    };
    const request = testPostRequest(0, "/reject", &headers);
    const handler = proxy.handler();
    handler.onRequest(handler.ctx, &h3, 0, &request);
    var feeder: UploadFeeder = .{
        .sim = &sim_io,
        .handler = handler,
        .h3 = &h3,
        .stream_id = 0,
        .body = pattern,
        .piece_bytes = 4 * 1024,
        .step_ns = std.time.ns_per_ms,
    };
    feeder.arm();

    try sim_io.run();

    // The refusal relayed as the response it is; the orphaned upload
    // added no gateway verdict of its own.
    const transcript = recorder.bytes[0..recorder.len];
    try std.testing.expect(std.mem.indexOf(u8, transcript, "denied\n") != null);
    try std.testing.expectEqual(@as(u64, 1), tally.get(.response));
    try std.testing.expectEqual(@as(u64, 0), tally.get(.bad_gateway));
    try std.testing.expectEqual(@as(u64, 0), tally.get(.gateway_timeout));
    // The origin answered at the head and never read a body byte, and
    // the abandoned upload keeps the connection out of the pool.
    try std.testing.expectEqual(@as(u64, 0), origin.conns[0].body_received);
    try std.testing.expectEqual(@as(usize, 0), proxy.parkedCount());
}

test "h3 proxy: the response relays while the upload is still streaming" {
    // Full duplex, the concurrent shape: the origin answers 200 at the
    // head and keeps consuming the body, then parks. The 200 must reach
    // the client before the upload's fin — the hook asserts exactly
    // that, from the feeder's final tick — and the settled connection
    // serves the follow-up without a second dial.
    const DuplexCheck = struct {
        recorder: *TestRecorder,
        missed: bool = false,

        fn beforeFin(ctx: *anyopaque) void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            const transcript = self.recorder.bytes[0..self.recorder.len];
            if (std.mem.indexOf(u8, transcript, "ok") == null) self.missed = true;
        }
    };
    var check = DuplexCheck{ .recorder = undefined };

    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var sim_io: Io.SimIo = undefined;
    try sim_io.init(arena, .{ .seed = 71 });
    const loopback = try std.Io.net.IpAddress.parseLiteral("127.0.0.1:0");
    const listener = try sim_io.listen(&.{ .ip = loopback }, null);
    var origin: TestOrigin = .{ .sim = &sim_io, .listener = listener };
    origin.armAccept();
    const endpoint = sim_io.listenerAddress(listener);
    var endpoints = [_]std.Io.net.IpAddress{endpoint};

    var tally: TestTally = .{};
    var proxy: Proxy(Io.SimIo, 2) = undefined;
    try proxy.initInPlace(&sim_io, arena, &endpoints, .{
        .counters = .{ .ctx = &tally, .note = TestTally.note },
    });

    var recorder: TestRecorder = .{};
    check.recorder = &recorder;
    var h3: session.H3Session = undefined;
    try h3.initInPlace(
        arena,
        .{ .ctx = &recorder, .send = TestRecorder.send, .send_multi = TestRecorder.sendMulti },
        neverHandler(),
    );
    h3.peer = try std.Io.net.IpAddress.parseLiteral("127.0.0.1:4333");

    var stop = StopTimer{ .sim = &sim_io };
    var stop_completion: Io.SimIo.Completion = .{};
    sim_io.timerStart(
        &stop_completion,
        2 * std.time.ns_per_s,
        StopTimer,
        &stop,
        StopTimer.onFire,
    );

    const pattern = try uploadPattern(arena, 100 * 1024);
    var headers = [_]request_stream.Header{
        .{ .name = "content-length", .value = "102400" },
    };
    const request = testPostRequest(0, "/early-200", &headers);
    const handler = proxy.handler();
    handler.onRequest(handler.ctx, &h3, 0, &request);
    var feeder: UploadFeeder = .{
        .sim = &sim_io,
        .handler = handler,
        .h3 = &h3,
        .stream_id = 0,
        .body = pattern,
        .piece_bytes = 4 * 1024,
        .step_ns = std.time.ns_per_ms,
        .before_fin = DuplexCheck.beforeFin,
        .before_fin_ctx = &check,
    };
    feeder.arm();
    // The follow-up inherits the parked connection.
    var follow_up: RequestTimer = .{
        .sim = &sim_io,
        .handler = handler,
        .h3 = &h3,
        .stream_id = 4,
        .path = "/",
    };
    follow_up.arm(60 * std.time.ns_per_ms);

    try sim_io.run();

    try std.testing.expect(!check.missed); // the 200 beat the upload's fin
    try std.testing.expectEqual(@as(u64, 2), tally.get(.response));
    try std.testing.expectEqual(@as(u64, 0), tally.get(.bad_gateway));
    // The origin read the whole upload, the connection parked, and the
    // follow-up dialed nothing.
    try std.testing.expectEqual(@as(u64, 100 * 1024), origin.conns[0].body_received);
    try std.testing.expectEqual(@as(usize, 1), origin.accepted_count);
    try std.testing.expectEqual(@as(usize, 1), proxy.parkedCount());
}

test "h3 proxy: a 100 Continue from the origin is skipped and the final head relays" {
    // RFC 9110 §15.2: a 1xx is never the exchange's head. Expect never
    // reaches the origin (the render strips it), but the pump must skip
    // an unsolicited 100 the same way — the client sees exactly one
    // HEADERS, the 200's.
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var sim_io: Io.SimIo = undefined;
    try sim_io.init(arena, .{ .seed = 73 });
    const loopback = try std.Io.net.IpAddress.parseLiteral("127.0.0.1:0");
    const listener = try sim_io.listen(&.{ .ip = loopback }, null);
    var origin: TestOrigin = .{ .sim = &sim_io, .listener = listener };
    origin.armAccept();
    const endpoint = sim_io.listenerAddress(listener);
    var endpoints = [_]std.Io.net.IpAddress{endpoint};

    var tally: TestTally = .{};
    var proxy: Proxy(Io.SimIo, 2) = undefined;
    try proxy.initInPlace(&sim_io, arena, &endpoints, .{
        .counters = .{ .ctx = &tally, .note = TestTally.note },
    });

    var recorder: TestRecorder = .{};
    var payload_buf: [8]u8 = undefined;
    var h3: session.H3Session = undefined;
    try h3.initInPlace(
        arena,
        .{ .ctx = &recorder, .send = TestRecorder.send, .send_multi = TestRecorder.sendMulti },
        neverHandler(),
    );
    h3.peer = try std.Io.net.IpAddress.parseLiteral("127.0.0.1:4333");
    recorder.payload = &payload_buf;

    var stop = StopTimer{ .sim = &sim_io };
    var stop_completion: Io.SimIo.Completion = .{};
    sim_io.timerStart(
        &stop_completion,
        2 * std.time.ns_per_s,
        StopTimer,
        &stop,
        StopTimer.onFire,
    );

    const request = testRequest(0, "/continue");
    const handler = proxy.handler();
    handler.onRequest(handler.ctx, &h3, 0, &request);
    finishBody(handler, &h3, 0);

    try sim_io.run();

    const transcript = recorder.bytes[0..recorder.len];
    try std.testing.expect(std.mem.indexOf(u8, transcript, "100 Continue") == null);
    try std.testing.expectEqualSlices(u8, "ok", payload_buf[0..recorder.payload_len]);
    try std.testing.expectEqual(@as(u64, 1), tally.get(.response));
    try std.testing.expectEqual(@as(u64, 0), tally.get(.bad_gateway));
}

test "h3 proxy: session teardown settles both directions of a duplex exchange" {
    // Full duplex arms a send and a read on the same upstream socket;
    // teardown's shutdown forces both to terminal deliveries. No verdict
    // may reach the dying session, both completions must settle (the
    // run would deadlock on a stranded op), and the slot frees.
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var sim_io: Io.SimIo = undefined;
    try sim_io.init(arena, .{ .seed = 79 });
    const loopback = try std.Io.net.IpAddress.parseLiteral("127.0.0.1:0");
    const listener = try sim_io.listen(&.{ .ip = loopback }, null);
    var origin: TestOrigin = .{ .sim = &sim_io, .listener = listener };
    origin.armAccept();
    const endpoint = sim_io.listenerAddress(listener);
    var endpoints = [_]std.Io.net.IpAddress{endpoint};

    var tally: TestTally = .{};
    var proxy: Proxy(Io.SimIo, 2) = undefined;
    try proxy.initInPlace(&sim_io, arena, &endpoints, .{
        .counters = .{ .ctx = &tally, .note = TestTally.note },
    });

    var recorder: TestRecorder = .{};
    var h3: session.H3Session = undefined;
    try h3.initInPlace(
        arena,
        .{ .ctx = &recorder, .send = TestRecorder.send, .send_multi = TestRecorder.sendMulti },
        neverHandler(),
    );
    h3.peer = try std.Io.net.IpAddress.parseLiteral("127.0.0.1:4333");

    var stop = StopTimer{ .sim = &sim_io };
    var stop_completion: Io.SimIo.Completion = .{};
    sim_io.timerStart(
        &stop_completion,
        2 * std.time.ns_per_s,
        StopTimer,
        &stop,
        StopTimer.onFire,
    );

    const pattern = try uploadPattern(arena, 64 * 1024);
    var headers = [_]request_stream.Header{
        .{ .name = "content-length", .value = "65536" },
    };
    const request = testPostRequest(0, "/mute", &headers);
    const handler = proxy.handler();
    handler.onRequest(handler.ctx, &h3, 0, &request);
    var feeder: UploadFeeder = .{
        .sim = &sim_io,
        .handler = handler,
        .h3 = &h3,
        .stream_id = 0,
        .body = pattern,
        .piece_bytes = 4 * 1024,
        .step_ns = std.time.ns_per_ms,
    };
    feeder.arm();
    var teardown = TeardownStep{
        .sim = &sim_io,
        .teardown = proxy.sessionTeardown(),
        .h3 = &h3,
    };
    teardown.arm(4 * std.time.ns_per_ms);

    try sim_io.run();

    try std.testing.expectEqual(@as(u64, 1), tally.get(.request));
    try std.testing.expectEqual(@as(u64, 0), tally.get(.response));
    try std.testing.expectEqual(@as(u64, 0), tally.get(.bad_gateway));
    try std.testing.expectEqual(@as(u64, 0), tally.get(.gateway_timeout));
    try std.testing.expectEqual(@as(usize, 0), recorder.sends);
    try std.testing.expectEqual(@as(usize, 0), proxy.parkedCount());
    try std.testing.expectEqual(@as(u32, 0), proxy.tlsEnginesHeld());
}

test "h3 proxy: route matching honors the header predicate tier" {
    // The #302 order config.zig sorts by: host, then header, then
    // prefix. The canary and the catch-all share a host and a prefix,
    // so only the header tier separates them — and the table order
    // decides the tie, exactly as on the L7 table.
    const routes = [_]Route{
        .{
            .host = "api.example",
            .prefix = "/",
            .header = .{ .name = "x-canary", .equals = "1" },
            .cluster_index = 2,
        },
        .{ .host = "api.example", .prefix = "/", .cluster_index = 1 },
        .{
            .prefix = "/",
            .header = .{ .name = "x-debug", .equals = null },
            .cluster_index = 3,
        },
        .{ .prefix = "/", .cluster_index = 0 },
    };
    const canary = [_]request_stream.Header{
        .{ .name = "X-Canary", .value = "1" },
    };
    // Header names compare case-insensitively; values exactly.
    try std.testing.expectEqual(
        @as(u16, 2),
        find(&routes, "api.example", "/x", &canary).?.cluster_index,
    );
    const wrong_value = [_]request_stream.Header{
        .{ .name = "x-canary", .value = "2" },
    };
    try std.testing.expectEqual(
        @as(u16, 1),
        find(&routes, "api.example", "/x", &wrong_value).?.cluster_index,
    );
    try std.testing.expectEqual(
        @as(u16, 1),
        find(&routes, "api.example", "/x", &.{}).?.cluster_index,
    );
    // The any-host presence route outranks the any-host catch-all; an
    // empty value still counts as present.
    const debug = [_]request_stream.Header{
        .{ .name = "X-Debug", .value = "" },
    };
    try std.testing.expectEqual(
        @as(u16, 3),
        find(&routes, "other.example", "/x", &debug).?.cluster_index,
    );
    try std.testing.expectEqual(
        @as(u16, 0),
        find(&routes, "other.example", "/x", &.{}).?.cluster_index,
    );
}

test "h3 proxy: a route opting out of the log suppresses only the line" {
    // The flag reaches the witness with the facts; the counters the
    // same hook fires stay — `access_log off` at a location, nothing
    // more. The runtime halves (table conversion, the log gate) sit in
    // h3_runtime.zig; here the seam proves the flag travels.
    const Scenario = struct {
        fn run(
            seed: u64,
            routes: []Route,
            clusters: []Cluster,
            path: []const u8,
        ) !TestTally {
            var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
            defer arena_state.deinit();
            const arena = arena_state.allocator();

            var sim_io: Io.SimIo = undefined;
            try sim_io.init(arena, .{ .seed = seed });
            const loopback = try std.Io.net.IpAddress.parseLiteral("127.0.0.1:0");
            const listener = try sim_io.listen(&.{ .ip = loopback }, null);
            var origin: TestOrigin = .{ .sim = &sim_io, .listener = listener };
            origin.armAccept();
            const endpoint = sim_io.listenerAddress(listener);
            var endpoints = [_]std.Io.net.IpAddress{endpoint};
            clusters[0].endpoints = &endpoints;

            var tally: TestTally = .{};
            var proxy: Proxy(Io.SimIo, 2) = undefined;
            try proxy.initInPlaceRouted(&sim_io, arena, routes, clusters, .{
                .counters = .{ .ctx = &tally, .note = TestTally.note },
            });

            var recorder: TestRecorder = .{};
            var h3: session.H3Session = undefined;
            try h3.initInPlace(
                arena,
                .{ .ctx = &recorder, .send = TestRecorder.send, .send_multi = TestRecorder.sendMulti },
                neverHandler(),
            );
            h3.peer = try std.Io.net.IpAddress.parseLiteral("127.0.0.1:4333");

            var stop = StopTimer{ .sim = &sim_io };
            var stop_completion: Io.SimIo.Completion = .{};
            sim_io.timerStart(
                &stop_completion,
                2 * std.time.ns_per_s,
                StopTimer,
                &stop,
                StopTimer.onFire,
            );

            const request = testRequest(0, path);
            const handler = proxy.handler();
            handler.onRequest(handler.ctx, &h3, 0, &request);
            finishBody(handler, &h3, 0);

            try sim_io.run();
            return tally;
        }
    };

    var quiet_routes = [_]Route{
        .{ .prefix = "/quiet", .cluster_index = 0, .access_log = false },
        .{ .prefix = "/", .cluster_index = 0 },
    };
    var quiet_clusters = [_]Cluster{.{ .endpoints = &.{} }};
    const quiet = try Scenario.run(83, &quiet_routes, &quiet_clusters, "/quiet");
    // The verdict counted, and the flag the witness reads is set.
    try std.testing.expectEqual(@as(u64, 1), quiet.get(.response));
    try std.testing.expectEqual(@as(u64, 0), quiet.get(.bad_gateway));
    try std.testing.expect(quiet.snapshots[0].?.suppress_log);

    // The default route leaves the flag clear.
    var loud_routes = [_]Route{
        .{ .prefix = "/quiet", .cluster_index = 0, .access_log = false },
        .{ .prefix = "/", .cluster_index = 0 },
    };
    var loud_clusters = [_]Cluster{.{ .endpoints = &.{} }};
    const loud = try Scenario.run(85, &loud_routes, &loud_clusters, "/");
    try std.testing.expectEqual(@as(u64, 1), loud.get(.response));
    try std.testing.expect(!loud.snapshots[0].?.suppress_log);
}

test "h3 proxy: configured error pages replace the built-in verdict bodies" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var sim_io: Io.SimIo = undefined;
    try sim_io.init(arena, .{ .seed = 89 });
    const loopback = try std.Io.net.IpAddress.parseLiteral("127.0.0.1:0");
    const listener = try sim_io.listen(&.{ .ip = loopback }, null);
    var origin: TestOrigin = .{ .sim = &sim_io, .listener = listener };
    origin.armAccept();
    const endpoint = sim_io.listenerAddress(listener);
    var endpoints = [_]std.Io.net.IpAddress{endpoint};

    // A host-scoped table so the unroutable host is one: the mute
    // request's synthesized authority is the endpoint literal, whose
    // canonical host is the bare loopback address.
    var routes = [_]Route{
        .{ .host = "127.0.0.1", .prefix = "/", .cluster_index = 0 },
    };
    var clusters = [_]Cluster{.{ .endpoints = &endpoints }};
    var tally: TestTally = .{};
    var proxy: Proxy(Io.SimIo, 2) = undefined;
    try proxy.initInPlaceRouted(&sim_io, arena, &routes, &clusters, .{
        .timeout_ns = 20 * std.time.ns_per_ms,
        .counters = .{ .ctx = &tally, .note = TestTally.note },
        .error_pages = .{
            .no_route = "the table has nothing for you\n",
            .bad_gateway = "the origin is unwell\n",
            .gateway_timeout = "the origin is asleep\n",
        },
    });

    var recorder: TestRecorder = .{};
    var h3: session.H3Session = undefined;
    try h3.initInPlace(
        arena,
        .{ .ctx = &recorder, .send = TestRecorder.send, .send_multi = TestRecorder.sendMulti },
        neverHandler(),
    );
    h3.peer = try std.Io.net.IpAddress.parseLiteral("127.0.0.1:4333");

    var stop = StopTimer{ .sim = &sim_io };
    var stop_completion: Io.SimIo.Completion = .{};
    sim_io.timerStart(
        &stop_completion,
        2 * std.time.ns_per_s,
        StopTimer,
        &stop,
        StopTimer.onFire,
    );

    // The mute origin never answers: the exchange deadline becomes the
    // configured 504 page. The unroutable host becomes the 404 page,
    // and it never dials. The host-scoped table demands the authority:
    // the dial's synthesized one is the bare loopback address.
    const request = testRequestAuthority(0, "/mute", "127.0.0.1");
    const handler = proxy.handler();
    handler.onRequest(handler.ctx, &h3, 0, &request);
    finishBody(handler, &h3, 0);
    const unrouted = testRequestAuthority(4, "/anything", "nowhere.test");
    handler.onRequest(handler.ctx, &h3, 4, &unrouted);
    finishBody(handler, &h3, 4);

    try sim_io.run();

    const transcript = recorder.bytes[0..recorder.len];
    try std.testing.expect(std.mem.indexOf(u8, transcript, "the origin is asleep\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, transcript, "the table has nothing for you\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, transcript, "gateway timeout\n") == null);
    try std.testing.expect(std.mem.indexOf(u8, transcript, "no route\n") == null);
    // The witness counts the page's bytes, not the built-in text's.
    const timeout_snapshot = tally.snapshots[snapshotIndex(.gateway_timeout).?];
    try std.testing.expectEqual(
        @as(u64, "the origin is asleep\n".len),
        timeout_snapshot.?.bytes_out,
    );
    try std.testing.expectEqual(@as(u64, 1), tally.get(.gateway_timeout));
    // One dial (the mute exchange): the 404 never touched a cluster.
    try std.testing.expectEqual(@as(usize, 1), origin.accepted_count);
}

test "h3 proxy: a no-route request witnesses the no_route verdict with its facts" {
    // The fifth verdict bucket: no dial, no exchange — the request
    // still counts (h3_requests at entry) and the 404 carries its own
    // event, so a deployment's probes against mistyped hosts file
    // under h3_no_route instead of vanishing from the tally.
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var sim_io: Io.SimIo = undefined;
    try sim_io.init(arena, .{ .seed = 113 });
    const loopback = try std.Io.net.IpAddress.parseLiteral("127.0.0.1:0");
    const listener = try sim_io.listen(&.{ .ip = loopback }, null);
    var origin: TestOrigin = .{ .sim = &sim_io, .listener = listener };
    origin.armAccept();
    const endpoint = sim_io.listenerAddress(listener);
    var endpoints = [_]std.Io.net.IpAddress{endpoint};

    var routes = [_]Route{
        .{ .host = "routed.test", .prefix = "/", .cluster_index = 0 },
    };
    var clusters = [_]Cluster{.{ .endpoints = &endpoints }};
    var tally: TestTally = .{};
    var proxy: Proxy(Io.SimIo, 2) = undefined;
    try proxy.initInPlaceRouted(&sim_io, arena, &routes, &clusters, .{
        .counters = .{ .ctx = &tally, .note = TestTally.note },
    });

    var recorder: TestRecorder = .{};
    var h3: session.H3Session = undefined;
    try h3.initInPlace(
        arena,
        .{ .ctx = &recorder, .send = TestRecorder.send, .send_multi = TestRecorder.sendMulti },
        neverHandler(),
    );
    h3.peer = try std.Io.net.IpAddress.parseLiteral("127.0.0.1:4333");

    var stop = StopTimer{ .sim = &sim_io };
    var stop_completion: Io.SimIo.Completion = .{};
    sim_io.timerStart(
        &stop_completion,
        2 * std.time.ns_per_s,
        StopTimer,
        &stop,
        StopTimer.onFire,
    );

    const unrouted = testRequestAuthority(0, "/anything", "nowhere.test");
    const handler = proxy.handler();
    handler.onRequest(handler.ctx, &h3, 0, &unrouted);
    finishBody(handler, &h3, 0);

    try sim_io.run();

    // Exactly the entry count and the no-route verdict: none of the
    // four exchange buckets moved, and no dial happened.
    try std.testing.expectEqual(@as(u64, 1), tally.get(.request));
    try std.testing.expectEqual(@as(u64, 1), tally.get(.no_route));
    try std.testing.expectEqual(@as(u64, 0), tally.get(.response));
    try std.testing.expectEqual(@as(u64, 0), tally.get(.bad_gateway));
    try std.testing.expectEqual(@as(u64, 0), tally.get(.gateway_timeout));
    try std.testing.expectEqual(@as(u64, 0), tally.get(.shed_busy));
    try std.testing.expect(std.mem.indexOf(
        u8,
        recorder.bytes[0..recorder.len],
        "no route\n",
    ) != null);
    // The facts a log line needs rode the event: 404, the path, the
    // verbatim authority, and the built-in body length.
    const snapshot = tally.snapshots[snapshotIndex(.no_route).?];
    try std.testing.expectEqual(@as(u16, 404), snapshot.?.status);
    try std.testing.expectEqualStrings("/anything", snapshot.?.path[0..snapshot.?.path_len]);
    try std.testing.expectEqualStrings("nowhere.test", snapshot.?.authority[0..snapshot.?.authority_len]);
    try std.testing.expectEqual(@as(u64, "no route\n".len), snapshot.?.bytes_out);
    try std.testing.expectEqual(@as(usize, 0), origin.accepted_count);
}

test "h3 proxy: the idle deadline expires an exchange the absolute budget would spare" {
    // No absolute budget at all: only the idle clock is armed, and a
    // mute origin gives it nothing to reset on.
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var sim_io: Io.SimIo = undefined;
    try sim_io.init(arena, .{ .seed = 97 });
    const loopback = try std.Io.net.IpAddress.parseLiteral("127.0.0.1:0");
    const listener = try sim_io.listen(&.{ .ip = loopback }, null);
    var origin: TestOrigin = .{ .sim = &sim_io, .listener = listener };
    origin.armAccept();
    const endpoint = sim_io.listenerAddress(listener);
    var endpoints = [_]std.Io.net.IpAddress{endpoint};

    var tally: TestTally = .{};
    var proxy: Proxy(Io.SimIo, 2) = undefined;
    try proxy.initInPlace(&sim_io, arena, &endpoints, .{
        .timeout_ns = 0,
        .idle_timeout_ns = 20 * std.time.ns_per_ms,
        .counters = .{ .ctx = &tally, .note = TestTally.note },
    });

    var recorder: TestRecorder = .{};
    var h3: session.H3Session = undefined;
    try h3.initInPlace(
        arena,
        .{ .ctx = &recorder, .send = TestRecorder.send, .send_multi = TestRecorder.sendMulti },
        neverHandler(),
    );
    h3.peer = try std.Io.net.IpAddress.parseLiteral("127.0.0.1:4333");

    var stop = StopTimer{ .sim = &sim_io };
    var stop_completion: Io.SimIo.Completion = .{};
    sim_io.timerStart(
        &stop_completion,
        2 * std.time.ns_per_s,
        StopTimer,
        &stop,
        StopTimer.onFire,
    );

    const request = testRequest(0, "/mute");
    const handler = proxy.handler();
    handler.onRequest(handler.ctx, &h3, 0, &request);
    finishBody(handler, &h3, 0);

    try sim_io.run();

    try std.testing.expectEqual(@as(u64, 1), tally.get(.gateway_timeout));
    try std.testing.expectEqual(@as(u64, 0), tally.get(.response));
    try std.testing.expect(std.mem.indexOf(
        u8,
        recorder.bytes[0..recorder.len],
        "gateway timeout\n",
    ) != null);
}

test "h3 proxy: upload progress resets the idle deadline" {
    // Pieces land every 8 ms against a 25 ms idle clock: every stage
    // resets it, and an exchange the absolute budget is too small for
    // (absolute off here — the idle clock alone carries it) completes.
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var sim_io: Io.SimIo = undefined;
    try sim_io.init(arena, .{ .seed = 101 });
    const loopback = try std.Io.net.IpAddress.parseLiteral("127.0.0.1:0");
    const listener = try sim_io.listen(&.{ .ip = loopback }, null);
    var origin: TestOrigin = .{ .sim = &sim_io, .listener = listener };
    origin.armAccept();
    const endpoint = sim_io.listenerAddress(listener);
    var endpoints = [_]std.Io.net.IpAddress{endpoint};

    var tally: TestTally = .{};
    var proxy: Proxy(Io.SimIo, 2) = undefined;
    try proxy.initInPlace(&sim_io, arena, &endpoints, .{
        .timeout_ns = 0,
        .idle_timeout_ns = 25 * std.time.ns_per_ms,
        .counters = .{ .ctx = &tally, .note = TestTally.note },
    });

    var recorder: TestRecorder = .{};
    var payload_buf: [16]u8 = undefined;
    var h3: session.H3Session = undefined;
    try h3.initInPlace(
        arena,
        .{ .ctx = &recorder, .send = TestRecorder.send, .send_multi = TestRecorder.sendMulti },
        neverHandler(),
    );
    h3.peer = try std.Io.net.IpAddress.parseLiteral("127.0.0.1:4333");
    recorder.payload = &payload_buf;

    var stop = StopTimer{ .sim = &sim_io };
    var stop_completion: Io.SimIo.Completion = .{};
    sim_io.timerStart(
        &stop_completion,
        2 * std.time.ns_per_s,
        StopTimer,
        &stop,
        StopTimer.onFire,
    );

    const pattern = try uploadPattern(arena, 64 * 1024);
    var headers = [_]request_stream.Header{
        .{ .name = "content-length", .value = "65536" },
    };
    const request = testPostRequest(0, "/echo", &headers);
    const handler = proxy.handler();
    handler.onRequest(handler.ctx, &h3, 0, &request);
    var feeder: UploadFeeder = .{
        .sim = &sim_io,
        .handler = handler,
        .h3 = &h3,
        .stream_id = 0,
        .body = pattern,
        .piece_bytes = 8 * 1024,
        .step_ns = 8 * std.time.ns_per_ms,
    };
    feeder.arm();

    try sim_io.run();

    // The pieces kept the idle clock at bay across a 64 ms upload: one
    // clean 200, no timeout verdict.
    try std.testing.expectEqual(@as(u64, 1), tally.get(.response));
    try std.testing.expectEqual(@as(u64, 0), tally.get(.gateway_timeout));
    try std.testing.expectEqualSlices(u8, "65536", payload_buf[0..recorder.payload_len]);
}

test "h3 proxy: a stall past the idle deadline kills the upload mid-flight" {
    // Piece one lands at 1 ms; piece two not until 60 ms. The 25 ms
    // idle clock expires in the gap — the exchange is answered 504
    // while its absolute budget (off) would have waited forever.
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var sim_io: Io.SimIo = undefined;
    try sim_io.init(arena, .{ .seed = 103 });
    const loopback = try std.Io.net.IpAddress.parseLiteral("127.0.0.1:0");
    const listener = try sim_io.listen(&.{ .ip = loopback }, null);
    var origin: TestOrigin = .{ .sim = &sim_io, .listener = listener };
    origin.armAccept();
    const endpoint = sim_io.listenerAddress(listener);
    var endpoints = [_]std.Io.net.IpAddress{endpoint};

    var tally: TestTally = .{};
    var proxy: Proxy(Io.SimIo, 2) = undefined;
    try proxy.initInPlace(&sim_io, arena, &endpoints, .{
        .timeout_ns = 0,
        .idle_timeout_ns = 25 * std.time.ns_per_ms,
        .counters = .{ .ctx = &tally, .note = TestTally.note },
    });

    var recorder: TestRecorder = .{};
    var h3: session.H3Session = undefined;
    try h3.initInPlace(
        arena,
        .{ .ctx = &recorder, .send = TestRecorder.send, .send_multi = TestRecorder.sendMulti },
        neverHandler(),
    );
    h3.peer = try std.Io.net.IpAddress.parseLiteral("127.0.0.1:4333");

    var stop = StopTimer{ .sim = &sim_io };
    var stop_completion: Io.SimIo.Completion = .{};
    sim_io.timerStart(
        &stop_completion,
        2 * std.time.ns_per_s,
        StopTimer,
        &stop,
        StopTimer.onFire,
    );

    const pattern = try uploadPattern(arena, 16 * 1024);
    var headers = [_]request_stream.Header{
        .{ .name = "content-length", .value = "16384" },
    };
    const request = testPostRequest(0, "/echo", &headers);
    const handler = proxy.handler();
    handler.onRequest(handler.ctx, &h3, 0, &request);
    var feeder: UploadFeeder = .{
        .sim = &sim_io,
        .handler = handler,
        .h3 = &h3,
        .stream_id = 0,
        .body = pattern,
        .piece_bytes = 8 * 1024,
        .step_ns = 59 * std.time.ns_per_ms,
    };
    feeder.arm();

    try sim_io.run();

    try std.testing.expectEqual(@as(u64, 1), tally.get(.gateway_timeout));
    try std.testing.expectEqual(@as(u64, 0), tally.get(.response));
    // The origin saw the head and the first piece, not the exchange.
    try std.testing.expect(origin.conns[0].body_received < 16384);
}

test "h3 proxy: the idle and absolute deadlines race to the earlier" {
    // Both armed, the idle shorter: the mute origin's stall dies on the
    // idle clock. Both armed with the absolute shorter: the absolute
    // clock wins. The verdict is the same 504 either way — what differs
    // is which deadline the shared timer was aimed at.
    const S = struct {
        fn runScenario(seed: u64, absolute_ms: u64, idle_ms: u64) !u64 {
            var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
            defer arena_state.deinit();
            const arena = arena_state.allocator();

            var sim_io: Io.SimIo = undefined;
            try sim_io.init(arena, .{ .seed = seed });
            const loopback = try std.Io.net.IpAddress.parseLiteral("127.0.0.1:0");
            const listener = try sim_io.listen(&.{ .ip = loopback }, null);
            var origin: TestOrigin = .{ .sim = &sim_io, .listener = listener };
            origin.armAccept();
            const endpoint = sim_io.listenerAddress(listener);
            var endpoints = [_]std.Io.net.IpAddress{endpoint};

            var tally: TestTally = .{};
            var proxy: Proxy(Io.SimIo, 2) = undefined;
            try proxy.initInPlace(&sim_io, arena, &endpoints, .{
                .timeout_ns = absolute_ms * std.time.ns_per_ms,
                .idle_timeout_ns = idle_ms * std.time.ns_per_ms,
                .counters = .{ .ctx = &tally, .note = TestTally.note },
            });

            var recorder: TestRecorder = .{};
            var h3: session.H3Session = undefined;
            try h3.initInPlace(
                arena,
                .{ .ctx = &recorder, .send = TestRecorder.send, .send_multi = TestRecorder.sendMulti },
                neverHandler(),
            );
            h3.peer = try std.Io.net.IpAddress.parseLiteral("127.0.0.1:4333");

            var stop = StopTimer{ .sim = &sim_io };
            var stop_completion: Io.SimIo.Completion = .{};
            sim_io.timerStart(
                &stop_completion,
                2 * std.time.ns_per_s,
                StopTimer,
                &stop,
                StopTimer.onFire,
            );

            const request = testRequest(0, "/mute");
            const handler = proxy.handler();
            handler.onRequest(handler.ctx, &h3, 0, &request);
            finishBody(handler, &h3, 0);

            try sim_io.run();
            return tally.get(.gateway_timeout);
        }
    };

    try std.testing.expectEqual(@as(u64, 1), try S.runScenario(107, 500, 20));
    try std.testing.expectEqual(@as(u64, 1), try S.runScenario(109, 20, 500));
}

// ---------------------------------------------------------------------------
// Keep-alive pooling: the proxy parks a fully framed, willing connection per
// (cluster, endpoint) and checks it out before dialing. These tests drive
// sequential requests — the follow-up fired from a timer, the deterministic
// point after everything scheduled earlier has settled — and read the pool
// from both sides: the proxy's parked count and the origin's accept count.
// ---------------------------------------------------------------------------

/// The shared shape of the pool tests: one keep-alive-scripted origin, one
/// witnessed proxy, one recorder-backed session. The wiring each test
/// would otherwise repeat; the requests and assertions are the tests'.
const PoolTest = struct {
    const ProxyType = Proxy(Io.SimIo, 4);

    sim: Io.SimIo = undefined,
    origin: TestOrigin = undefined,
    proxy: ProxyType = undefined,
    recorder: TestRecorder = .{},
    h3: session.H3Session = undefined,
    tally: TestTally = .{},
    stop: StopTimer = undefined,
    stop_completion: Io.SimIo.Completion = .{},
    endpoint: std.Io.net.IpAddress = undefined,
    /// The cluster table holds this slice for the proxy's whole life, so
    /// it lives here — a local in `init` would dangle the moment the
    /// helper returned.
    endpoints: [1]std.Io.net.IpAddress = undefined,
    /// Reassembly sink for the DATA payloads the session sent: the
    /// assertions read what the client actually received, frame
    /// boundaries erased — a body split across DATA frames by
    /// fragmentation re-forms here, which the raw transcript cannot
    /// show.
    payload_buf: [8192]u8 = undefined,

    fn init(self: *PoolTest, arena: std.mem.Allocator, seed: u64) !void {
        try self.initCapped(arena, seed, constants.h3_response_bytes_max);
    }

    /// The cap-sensitive tests narrow `max_response_bytes` to reach the
    /// mid-stream cutoff with a body the scripts can still send.
    fn initCapped(
        self: *PoolTest,
        arena: std.mem.Allocator,
        seed: u64,
        max_response_bytes: usize,
    ) !void {
        try self.sim.init(arena, .{ .seed = seed });
        const loopback = try std.Io.net.IpAddress.parseLiteral("127.0.0.1:0");
        const listener = try self.sim.listen(&.{ .ip = loopback }, null);
        self.origin = .{ .sim = &self.sim, .listener = listener };
        self.origin.armAccept();
        self.endpoint = self.sim.listenerAddress(listener);
        self.endpoints[0] = self.endpoint;
        try self.proxy.initInPlace(&self.sim, arena, &self.endpoints, .{
            .timeout_ns = 100 * std.time.ns_per_ms,
            .max_response_bytes = max_response_bytes,
            .counters = .{ .ctx = &self.tally, .note = TestTally.note },
        });
        try self.h3.initInPlace(
            arena,
            self.recorder.interface(),
            neverHandler(),
        );
        // The listener sets this right after initInPlace; the test plays
        // the listener so the witnessed client address is a known value.
        self.h3.peer = try std.Io.net.IpAddress.parseLiteral("127.0.0.1:4333");
        self.recorder.payload = &self.payload_buf;
        self.stop = .{ .sim = &self.sim };
    }

    /// Arm the stop backstop: an armed accept is never quiescent — only
    /// timers schedule wakes — so the loop needs a timer to end it.
    fn armBackstop(self: *PoolTest, delay_ns: u64) void {
        self.stop_completion = .{};
        self.sim.timerStart(
            &self.stop_completion,
            delay_ns,
            StopTimer,
            &self.stop,
            StopTimer.onFire,
        );
    }

    fn fire(self: *PoolTest, stream_id: u64, path: []const u8) void {
        self.fireOn(&self.h3, stream_id, path);
    }

    fn fireOn(self: *PoolTest, h3: *session.H3Session, stream_id: u64, path: []const u8) void {
        const handler = self.proxy.handler();
        const request = testRequest(stream_id, path);
        handler.onRequest(handler.ctx, h3, stream_id, &request);
        finishBody(handler, h3, stream_id);
    }

    /// Schedule one request to fire after `delay_ns` — the deterministic
    /// point after every earlier-scheduled delivery has completed, which
    /// is what makes pool reuse observable (a request fired synchronously
    /// with its predecessor always finds the pool empty).
    fn fireLater(
        self: *PoolTest,
        step: *RequestTimer,
        delay_ns: u64,
        stream_id: u64,
        path: []const u8,
    ) void {
        step.* = .{
            .sim = &self.sim,
            .handler = self.proxy.handler(),
            .h3 = &self.h3,
            .stream_id = stream_id,
            .path = path,
        };
        step.arm(delay_ns);
    }

    fn transcript(self: *PoolTest) []const u8 {
        return self.recorder.bytes[0..self.recorder.len];
    }

    /// The reassembled DATA payloads — what the client actually
    /// received, with the frame boundaries fragmentation introduced
    /// erased.
    fn payloadText(self: *PoolTest) []const u8 {
        return self.payload_buf[0..self.recorder.payload_len];
    }
};

/// Drive the proxy's window notify the way the listener's tick does:
/// each fire resumes parked exchanges; the step re-arms until its
/// scripted count runs out — a stalled exchange gets another drain
/// attempt on every beat.
const WindowOpenTick = struct {
    sim: *Io.SimIo,
    notify: connection.WindowNotify,
    remaining: usize,
    interval_ns: u64,
    completion: Io.SimIo.Completion = .{},

    fn arm(self: *WindowOpenTick) void {
        if (self.remaining == 0) return;
        self.completion = .{};
        self.sim.timerStart(
            &self.completion,
            self.interval_ns,
            WindowOpenTick,
            self,
            WindowOpenTick.onFire,
        );
    }

    fn onFire(self: *WindowOpenTick, result: Io.TimerError!void) void {
        _ = result catch {};
        self.remaining -= 1;
        self.notify.onOpen(self.notify.ctx);
        self.arm();
    }
};

/// Fire a session teardown when the timer fires — the proxy's
/// deregistration hook, the way the listener calls it right before the
/// session deinits.
const TeardownStep = struct {
    sim: *Io.SimIo,
    teardown: SessionTeardown,
    h3: *session.H3Session,
    completion: Io.SimIo.Completion = .{},

    fn arm(self: *TeardownStep, delay_ns: u64) void {
        self.completion = .{};
        self.sim.timerStart(
            &self.completion,
            delay_ns,
            TeardownStep,
            self,
            TeardownStep.onFire,
        );
    }

    fn onFire(self: *TeardownStep, result: Io.TimerError!void) void {
        _ = result catch {};
        self.teardown.forget(self.teardown.ctx, self.h3);
    }
};

test "h3 proxy: a fully framed response parks the connection and the next request reuses it" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var pool_test: PoolTest = .{};
    try pool_test.init(arena, 41);
    pool_test.armBackstop(2 * std.time.ns_per_s);

    pool_test.fire(0, "/serve");
    var follow_up: RequestTimer = undefined;
    pool_test.fireLater(&follow_up, 1 * std.time.ns_per_ms, 4, "/serve");

    try pool_test.sim.run();

    // One TCP connection carried both requests: the origin accepted once,
    // and the proxy holds the parked connection after the second answer.
    try std.testing.expectEqual(@as(usize, 1), pool_test.origin.accepted_count);
    try std.testing.expectEqual(@as(usize, 1), pool_test.proxy.parkedCount());
    try std.testing.expectEqual(@as(u64, 2), pool_test.tally.get(.response));
    try std.testing.expectEqual(@as(u64, 0), pool_test.tally.get(.bad_gateway));
    try std.testing.expectEqual(@as(usize, 2), countOccurrences(pool_test.payloadText(), "hello"));
    try std.testing.expect(follow_up.fired);
}

test "h3 proxy: a close-delimited response completes at EOF but is never reused" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var pool_test: PoolTest = .{};
    try pool_test.init(arena, 43);
    pool_test.armBackstop(2 * std.time.ns_per_s);

    // The reply's end is the origin's EOF: the response relays whole, but
    // the connection dies delivering it and must not park.
    pool_test.fire(0, "/close-delimited");
    var follow_up: RequestTimer = undefined;
    pool_test.fireLater(&follow_up, 1 * std.time.ns_per_ms, 4, "/serve");

    try pool_test.sim.run();

    try std.testing.expectEqual(@as(usize, 2), pool_test.origin.accepted_count);
    try std.testing.expectEqual(@as(u64, 2), pool_test.tally.get(.response));
    try std.testing.expectEqual(@as(u64, 0), pool_test.tally.get(.bad_gateway));
    // Only the follow-up's connection is parked; the close-delimited
    // one's disposition was close.
    try std.testing.expectEqual(@as(usize, 1), pool_test.proxy.parkedCount());
    try std.testing.expectEqual(@as(usize, 2), countOccurrences(pool_test.payloadText(), "hello"));
}

test "h3 proxy: a Connection: close response header is never reused" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var pool_test: PoolTest = .{};
    try pool_test.init(arena, 47);
    pool_test.armBackstop(2 * std.time.ns_per_s);

    pool_test.fire(0, "/close-header");
    var follow_up: RequestTimer = undefined;
    pool_test.fireLater(&follow_up, 1 * std.time.ns_per_ms, 4, "/serve");

    try pool_test.sim.run();

    try std.testing.expectEqual(@as(usize, 2), pool_test.origin.accepted_count);
    try std.testing.expectEqual(@as(u64, 2), pool_test.tally.get(.response));
    try std.testing.expectEqual(@as(u64, 0), pool_test.tally.get(.bad_gateway));
    try std.testing.expectEqual(@as(usize, 1), pool_test.proxy.parkedCount());
    try std.testing.expectEqual(@as(usize, 2), countOccurrences(pool_test.payloadText(), "hello"));
}

test "h3 proxy: an early EOF mid-body resets the stream, witnesses bad_gateway, and never parks" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var pool_test: PoolTest = .{};
    try pool_test.init(arena, 53);
    pool_test.armBackstop(2 * std.time.ns_per_s);

    // The origin declares 100 bytes and sends five: Content-Length never
    // met. Streaming already relayed the five bytes after a 200 head, so
    // the verdict cannot be an error page — the stream is reset, the
    // witness records bad_gateway with the bytes sent, and the
    // connection must not park behind it.
    pool_test.fire(0, "/truncate");
    var follow_up: RequestTimer = undefined;
    pool_test.fireLater(&follow_up, 1 * std.time.ns_per_ms, 4, "/serve");

    try pool_test.sim.run();

    try std.testing.expectEqual(@as(u64, 1), pool_test.tally.get(.bad_gateway));
    try std.testing.expectEqual(@as(u64, 1), pool_test.tally.get(.response));
    try std.testing.expectEqual(@as(usize, 2), pool_test.origin.accepted_count);
    try std.testing.expectEqual(@as(usize, 1), pool_test.proxy.parkedCount());
    const transcript = pool_test.payloadText();
    // No error page can follow a 200 head: the client saw the part
    // relayed, then the stream died.
    try std.testing.expectEqual(@as(usize, 0), countOccurrences(transcript, "bad gateway\n"));
    try std.testing.expectEqual(@as(usize, 1), countOccurrences(transcript, "partial"));
    try std.testing.expectEqual(@as(usize, 1), countOccurrences(transcript, "hello"));
    const bad_gateway = pool_test.tally.snapshots[1].?;
    try std.testing.expectEqual(@as(u16, 502), bad_gateway.status);
    try std.testing.expectEqual(@as(u64, 7), bad_gateway.bytes_out); // "partial"
}

test "h3 proxy: a silently closed parked connection fails its checkout without a retry" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var pool_test: PoolTest = .{};
    try pool_test.init(arena, 59);
    pool_test.armBackstop(2 * std.time.ns_per_s);

    // /last answers fully — Content-Length met, no Connection: close —
    // and only then the origin closes its side without saying so. The
    // proxy parks a connection that is already dead.
    pool_test.fire(0, "/last");
    var dead_checkout: RequestTimer = undefined;
    pool_test.fireLater(&dead_checkout, 1 * std.time.ns_per_ms, 4, "/serve");
    // The failed checkout must not retry: the request after it dials a
    // fresh connection and is served.
    var after: RequestTimer = undefined;
    pool_test.fireLater(&after, 2 * std.time.ns_per_ms, 8, "/serve");

    try pool_test.sim.run();

    // The dead checkout answered 502 and consumed no new accept — the
    // no-retry evidence is accepted_count == 2 across three requests.
    try std.testing.expectEqual(@as(u64, 1), pool_test.tally.get(.bad_gateway));
    try std.testing.expectEqual(@as(u64, 2), pool_test.tally.get(.response));
    try std.testing.expectEqual(@as(usize, 2), pool_test.origin.accepted_count);
    try std.testing.expectEqual(@as(usize, 1), pool_test.proxy.parkedCount());
    const transcript = pool_test.payloadText();
    try std.testing.expectEqual(@as(usize, 1), countOccurrences(transcript, "bad gateway\n"));
    try std.testing.expectEqual(@as(usize, 2), countOccurrences(transcript, "hello"));
}

test "h3 proxy: an idle parked connection is reaped and the next request dials fresh" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var pool_test: PoolTest = .{};
    try pool_test.init(arena, 61);
    // The follow-up fires one virtual second past the idle window: by
    // then the proxy's own timer must have reaped the parked connection,
    // so this request dials fresh instead of reusing.
    pool_test.armBackstop(32 * std.time.ns_per_s);

    pool_test.fire(0, "/serve");
    var follow_up: RequestTimer = undefined;
    pool_test.fireLater(
        &follow_up,
        constants.h3_pool_idle_ns + 1 * std.time.ns_per_s,
        4,
        "/serve",
    );

    try pool_test.sim.run();

    try std.testing.expectEqual(@as(u64, 2), pool_test.tally.get(.response));
    // The reap is what turned the follow-up into a second dial: a live
    // parked connection would have kept the accept count at one.
    try std.testing.expectEqual(@as(usize, 2), pool_test.origin.accepted_count);
    try std.testing.expectEqual(@as(usize, 1), pool_test.proxy.parkedCount());
    try std.testing.expectEqual(@as(usize, 2), countOccurrences(pool_test.payloadText(), "hello"));
}

test "h3 proxy: an exchange deadline arising under a parked idle window is not shadowed" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var pool_test: PoolTest = .{};
    try pool_test.init(arena, 71);
    pool_test.armBackstop(2 * std.time.ns_per_s);

    // The serve parks at t≈0; its exchange deadline fires at 100 ms and
    // the tick re-arms at the parked connection's 30 s idle window. The
    // mute begins at 200 ms — under that armed window — and its own
    // 100 ms deadline targets far earlier. Without a re-base the lazy
    // timer would sit on the idle window and the 504 would not land
    // before the backstop; the verdict arriving at all is the proof the
    // deadline moved ahead of the parked one.
    pool_test.fire(0, "/serve");
    var mute: RequestTimer = undefined;
    pool_test.fireLater(&mute, 200 * std.time.ns_per_ms, 4, "/mute");

    try pool_test.sim.run();

    try std.testing.expectEqual(@as(u64, 1), pool_test.tally.get(.response));
    try std.testing.expectEqual(@as(u64, 1), pool_test.tally.get(.gateway_timeout));
    // The mute reused the parked connection (one accept serves both) and
    // the 504 closed it: nothing is parked at the end.
    try std.testing.expectEqual(@as(usize, 1), pool_test.origin.accepted_count);
    try std.testing.expectEqual(@as(usize, 0), pool_test.proxy.parkedCount());
    const transcript = pool_test.payloadText();
    try std.testing.expectEqual(@as(usize, 1), countOccurrences(transcript, "hello"));
    try std.testing.expectEqual(@as(usize, 1), countOccurrences(transcript, "gateway timeout\n"));
}

test "h3 proxy: session teardown deregisters in-flight exchanges without answering them" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var pool_test: PoolTest = .{};
    try pool_test.init(arena, 67);
    pool_test.armBackstop(2 * std.time.ns_per_s);

    // An exchange the origin will never answer: by the time the teardown
    // fires it is recv-armed on an established socket, one shutdown away
    // from a forced delivery.
    pool_test.fire(0, "/mute");
    var teardown = TeardownStep{
        .sim = &pool_test.sim,
        .teardown = pool_test.proxy.sessionTeardown(),
        .h3 = &pool_test.h3,
    };
    teardown.arm(1 * std.time.ns_per_ms);

    try pool_test.sim.run();

    // The dying session was never answered — no response, and no verdict
    // either: the 504 its mute exchange would have earned at the deadline
    // must not fire, because the exchange was deregistered, not timed out.
    try std.testing.expectEqual(@as(usize, 0), pool_test.recorder.sends);
    try std.testing.expectEqual(@as(u64, 0), pool_test.tally.get(.response));
    try std.testing.expectEqual(@as(u64, 0), pool_test.tally.get(.bad_gateway));
    try std.testing.expectEqual(@as(u64, 0), pool_test.tally.get(.gateway_timeout));
    try std.testing.expectEqual(@as(usize, 0), pool_test.proxy.parkedCount());

    // The proxy is still whole: a fresh session dials and is served, and
    // its connection parks — the deregistered exchange's slot came back.
    var live: session.H3Session = undefined;
    try live.initInPlace(
        arena,
        .{ .ctx = &pool_test.recorder, .send = TestRecorder.send },
        neverHandler(),
    );
    live.peer = pool_test.h3.peer;
    pool_test.fireOn(&live, 4, "/serve");
    pool_test.armBackstop(2 * std.time.ns_per_s);

    try pool_test.sim.run();

    try std.testing.expectEqual(@as(u64, 1), pool_test.tally.get(.response));
    try std.testing.expectEqual(@as(usize, 1), pool_test.proxy.parkedCount());
    try std.testing.expectEqual(@as(usize, 1), countOccurrences(pool_test.payloadText(), "hello"));
}

// ---------------------------------------------------------------------------
// Streaming responses: bodies larger than the buffered slice ever forwarded
// (which capped at 64 KiB and answered a 502 past it) now relay as they
// arrive. These tests read the reassembled DATA payloads the session sent
// and the pool's side of the dial to prove the stream was whole, finite,
// and left its connection parked for reuse.
// ---------------------------------------------------------------------------

/// A deterministic byte pattern big enough to prove streaming: the
/// assertions compare what the client received against what the origin
/// sent, byte for byte.
fn testPattern(bytes: []u8) void {
    for (bytes, 0..) |*byte, index| byte.* = @truncate(index *% 31 +% 7);
}

/// Render a sized-200 wire for `body` into `out`.
fn sizedWire(out: []u8, body: []const u8) ![]const u8 {
    var writer: std.Io.Writer = .fixed(out);
    try writer.writeAll(
        "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n",
    );
    try writer.print("Content-Length: {d}\r\n\r\n", .{body.len});
    try writer.writeAll(body);
    return out[0..writer.end];
}

/// Render a chunked-200 wire for `body` into `out`, with chunk sizes
/// that align to nothing — SimIo's partial deliveries exercise the
/// incremental decoder's split paths anyway.
fn chunkedWire(out: []u8, body: []const u8, chunk_size: usize) ![]const u8 {
    var writer: std.Io.Writer = .fixed(out);
    try writer.writeAll(
        "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n" ++
            "Transfer-Encoding: chunked\r\n\r\n",
    );
    var at: usize = 0;
    while (at < body.len) {
        const n = @min(chunk_size, body.len - at);
        try writer.print("{x}\r\n", .{n});
        try writer.writeAll(body[at .. at + n]);
        try writer.writeAll("\r\n");
        at += n;
    }
    try writer.writeAll("0\r\n\r\n");
    return out[0..writer.end];
}

test "h3 proxy: a 200 KiB Content-Length response streams whole and the connection parks for reuse" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var pool_test: PoolTest = .{};
    // The default cap is 64 KiB; this body is three times that — the
    // point of the test is that a raised ceiling streams it whole.
    try pool_test.initCapped(arena, 83, 256 * 1024);
    pool_test.armBackstop(2 * std.time.ns_per_s);

    const body = try arena.alloc(u8, 200 * 1024);
    testPattern(body);
    const wire_storage = try arena.alloc(u8, body.len + 128);
    pool_test.origin.big_cl_wire = try sizedWire(wire_storage, body);
    const payload = try arena.alloc(u8, body.len);
    pool_test.recorder.payload = payload;

    pool_test.fire(0, "/big-cl");
    var follow_up: RequestTimer = undefined;
    pool_test.fireLater(&follow_up, 1 * std.time.ns_per_ms, 4, "/serve");

    try pool_test.sim.run();

    // The whole pattern crossed the proxy, byte for byte, fin and all.
    try std.testing.expectEqual(body.len, pool_test.recorder.payload_len);
    try std.testing.expectEqualSlices(u8, body, payload);
    try std.testing.expect(pool_test.recorder.fin);
    try std.testing.expectEqual(@as(u64, 2), pool_test.tally.get(.response));
    try std.testing.expectEqual(@as(u64, 0), pool_test.tally.get(.bad_gateway));
    // The streamed exchange witnessed its full byte count...
    const response = pool_test.tally.snapshots[0].?;
    try std.testing.expectEqual(@as(u64, body.len), response.bytes_out);
    try std.testing.expectEqual(@as(u16, 200), response.status);
    // ...and one TCP connection carried both requests: the big reply's
    // parked for the follow-up's checkout.
    try std.testing.expectEqual(@as(usize, 1), pool_test.origin.accepted_count);
    try std.testing.expectEqual(@as(usize, 1), pool_test.proxy.parkedCount());
}

test "h3 proxy: a 100 KiB chunked response decodes incrementally and streams whole" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var pool_test: PoolTest = .{};
    try pool_test.initCapped(arena, 89, 128 * 1024);
    pool_test.armBackstop(2 * std.time.ns_per_s);

    const body = try arena.alloc(u8, 100 * 1024);
    testPattern(body);
    const wire_storage = try arena.alloc(u8, body.len + 1024);
    pool_test.origin.big_chunked_wire = try chunkedWire(wire_storage, body, 3000);
    const payload = try arena.alloc(u8, body.len);
    pool_test.recorder.payload = payload;

    pool_test.fire(0, "/big-chunked");
    var follow_up: RequestTimer = undefined;
    pool_test.fireLater(&follow_up, 1 * std.time.ns_per_ms, 4, "/serve");

    try pool_test.sim.run();

    try std.testing.expectEqual(body.len, pool_test.recorder.payload_len);
    try std.testing.expectEqualSlices(u8, body, payload);
    try std.testing.expect(pool_test.recorder.fin);
    try std.testing.expectEqual(@as(u64, 2), pool_test.tally.get(.response));
    try std.testing.expectEqual(@as(u64, 0), pool_test.tally.get(.bad_gateway));
    // A reusable chunked reply parks exactly like a sized one.
    try std.testing.expectEqual(@as(usize, 1), pool_test.origin.accepted_count);
    try std.testing.expectEqual(@as(usize, 1), pool_test.proxy.parkedCount());
}

test "h3 proxy: a close-delimited body past the cap is cut off mid-stream" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var pool_test: PoolTest = .{};
    try pool_test.initCapped(arena, 97, 4096);
    pool_test.armBackstop(2 * std.time.ns_per_s);

    const body = try arena.alloc(u8, 32 * 1024);
    testPattern(body);
    const wire_storage = try arena.alloc(u8, body.len + 128);
    var writer: std.Io.Writer = .fixed(wire_storage);
    try writer.writeAll(
        "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n\r\n",
    );
    try writer.writeAll(body);
    pool_test.origin.flood_wire = writer.buffered();
    const payload = try arena.alloc(u8, body.len);
    pool_test.recorder.payload = payload;

    pool_test.fire(0, "/flood");
    var follow_up: RequestTimer = undefined;
    pool_test.fireLater(&follow_up, 1 * std.time.ns_per_ms, 4, "/serve");

    try pool_test.sim.run();

    // The head went out, so the cap lands as a stream reset witnessed
    // bad_gateway — never an error page after a 200 — with only the
    // bytes already relayed counted.
    try std.testing.expectEqual(@as(u64, 1), pool_test.tally.get(.bad_gateway));
    try std.testing.expectEqual(@as(u64, 1), pool_test.tally.get(.response));
    const bad_gateway = pool_test.tally.snapshots[1].?;
    try std.testing.expectEqual(@as(u16, 502), bad_gateway.status);
    try std.testing.expect(bad_gateway.bytes_out <= 4096);
    try std.testing.expect(pool_test.recorder.payload_len < body.len);
    // The aborted connection never parks; the follow-up dialed fresh and
    // parked its own.
    try std.testing.expectEqual(@as(usize, 2), pool_test.origin.accepted_count);
    try std.testing.expectEqual(@as(usize, 1), pool_test.proxy.parkedCount());
}

test "h3 proxy: a HEAD request and a 204 finish at the head and stay reusable" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var pool_test: PoolTest = .{};
    try pool_test.init(arena, 101);
    pool_test.armBackstop(2 * std.time.ns_per_s);

    // HEAD: the origin wears the GET framing with no body (what the
    // scripted origin does for any HEAD), and the exchange must not wait
    // for bytes that never come.
    {
        const handler = pool_test.proxy.handler();
        var request = testRequestMethod(0, "HEAD", "/serve", null);
        handler.onRequest(handler.ctx, &pool_test.h3, 0, &request);
        finishBody(handler, &pool_test.h3, 0);
    }
    var no_content: RequestTimer = undefined;
    pool_test.fireLater(&no_content, 1 * std.time.ns_per_ms, 4, "/no-content");
    var follow_up: RequestTimer = undefined;
    pool_test.fireLater(&follow_up, 2 * std.time.ns_per_ms, 8, "/serve");

    try pool_test.sim.run();

    // All three requests rode one connection: both head-only replies
    // finished at the head and parked it.
    try std.testing.expectEqual(@as(usize, 1), pool_test.origin.accepted_count);
    try std.testing.expectEqual(@as(usize, 1), pool_test.proxy.parkedCount());
    try std.testing.expectEqual(@as(u64, 3), pool_test.tally.get(.response));
    try std.testing.expectEqual(@as(u64, 0), pool_test.tally.get(.bad_gateway));
    const transcript = pool_test.payloadText();
    try std.testing.expectEqual(@as(usize, 1), countOccurrences(transcript, "hello"));
    // The HEAD's 200 carried no body, only HEADERS and its fin.
    const head_only = pool_test.tally.snapshots[0].?;
    try std.testing.expectEqual(@as(u16, 200), head_only.status);
    try std.testing.expectEqual(@as(u64, 0), head_only.bytes_out);
}

test "h3 proxy: a short sendData parks the tail and the window notify drains it" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var pool_test: PoolTest = .{};
    try pool_test.init(arena, 103);
    pool_test.armBackstop(2 * std.time.ns_per_s);

    // A flow-control window narrower than one send unit: every sendData
    // short-writes, the exchange parks after each one, and only the
    // tick — the listener's shape of the window-open notify — resumes
    // it. A 4 KiB body at 512 bytes a beat wants nine beats.
    const window: usize = 512;
    const body_len: usize = 4 * 1024;
    pool_test.recorder.window_bytes = window;

    const body = try arena.alloc(u8, body_len);
    testPattern(body);
    const wire_storage = try arena.alloc(u8, body_len + 128);
    pool_test.origin.big_cl_wire = try sizedWire(wire_storage, body);
    const payload = try arena.alloc(u8, body_len);
    pool_test.recorder.payload = payload;

    pool_test.fire(0, "/big-cl");
    var tick: WindowOpenTick = .{
        .sim = &pool_test.sim,
        .notify = pool_test.proxy.windowNotify(),
        .remaining = 64,
        .interval_ns = 100 * std.time.ns_per_us,
    };
    tick.arm();
    var follow_up: RequestTimer = undefined;
    pool_test.fireLater(&follow_up, 10 * std.time.ns_per_ms, 4, "/serve");

    try pool_test.sim.run();

    // Backpressure really happened, and the notify-driven resumes
    // carried the whole body home anyway.
    try std.testing.expect(pool_test.recorder.refused > 0);
    try std.testing.expectEqual(body_len, pool_test.recorder.payload_len);
    try std.testing.expectEqualSlices(u8, body, payload);
    try std.testing.expect(pool_test.recorder.fin);
    try std.testing.expectEqual(@as(u64, 2), pool_test.tally.get(.response));
    try std.testing.expectEqual(@as(u64, 0), pool_test.tally.get(.bad_gateway));
    try std.testing.expectEqual(@as(u64, 0), pool_test.tally.get(.gateway_timeout));
    const response = pool_test.tally.snapshots[0].?;
    try std.testing.expectEqual(@as(u64, body_len), response.bytes_out);
    // One connection served both requests despite the stall: the parked
    // tail never poisoned the pool entry.
    try std.testing.expectEqual(@as(usize, 1), pool_test.origin.accepted_count);
    try std.testing.expectEqual(@as(usize, 1), pool_test.proxy.parkedCount());
}

test "h3 proxy: transient transport backpressure parks the unit and the tick drains it" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var pool_test: PoolTest = .{};
    try pool_test.init(arena, 107);
    pool_test.armBackstop(2 * std.time.ns_per_s);

    // The live listener wires only the plain send, whose fallback raises
    // a full datagram queue (and a shut flow-control window) as errors.
    // Each failure must park the unit exactly where it stopped — not
    // abort the exchange — and the tick's re-drive drains the body.
    const body_len: usize = 4 * 1024;
    pool_test.recorder.error_times = 5;

    const body = try arena.alloc(u8, body_len);
    testPattern(body);
    const wire_storage = try arena.alloc(u8, body_len + 128);
    pool_test.origin.big_cl_wire = try sizedWire(wire_storage, body);
    const payload = try arena.alloc(u8, body_len);
    pool_test.recorder.payload = payload;

    pool_test.fire(0, "/big-cl");
    var tick: WindowOpenTick = .{
        .sim = &pool_test.sim,
        .notify = pool_test.proxy.windowNotify(),
        .remaining = 64,
        .interval_ns = 100 * std.time.ns_per_us,
    };
    tick.arm();
    var follow_up: RequestTimer = undefined;
    pool_test.fireLater(&follow_up, 10 * std.time.ns_per_ms, 4, "/serve");

    try pool_test.sim.run();

    // Every scripted error was consumed, nothing was refused (the error
    // path accepts nothing rather than short-writing), and the retries
    // still carried the whole body home, fin and all.
    try std.testing.expectEqual(@as(usize, 0), pool_test.recorder.error_times);
    try std.testing.expectEqual(@as(u64, 0), pool_test.recorder.refused);
    try std.testing.expectEqual(body_len, pool_test.recorder.payload_len);
    try std.testing.expectEqualSlices(u8, body, payload);
    try std.testing.expect(pool_test.recorder.fin);
    try std.testing.expectEqual(@as(u64, 2), pool_test.tally.get(.response));
    try std.testing.expectEqual(@as(u64, 0), pool_test.tally.get(.bad_gateway));
    try std.testing.expectEqual(@as(u64, 0), pool_test.tally.get(.gateway_timeout));
    const response = pool_test.tally.snapshots[0].?;
    try std.testing.expectEqual(@as(u64, body_len), response.bytes_out);
    try std.testing.expectEqual(@as(usize, 1), pool_test.origin.accepted_count);
    try std.testing.expectEqual(@as(usize, 1), pool_test.proxy.parkedCount());
}

// ---------------------------------------------------------------------------
// Upstream TLS: the exchange drives the same sans-I/O client engine the TCP
// path dials with (`src/tls/UpstreamTls.zig`, reached file-relatively),
// against a scripted zssl origin (`src/tls/TestServer.zig`) that answers
// one decrypted request with a canned 200 and closes. The tests jump the
// simulated wall clock into the fixture certificate's validity window, so
// the verification under test is the real chain-and-name check, not the
// clock.
// ---------------------------------------------------------------------------

const fixture_cert_pem = @embedFile("../../tls/testdata/cert.pem");
const fixture_key_pem = @embedFile("../../tls/testdata/key.pem");
/// The fixture identity's CN/SAN — what the cluster's `server_name` names.
const fixture_origin_name = "spike.zgix.test";
/// Inside the fixture's 2026-10-20 .. 2036-10-17 validity window. The
/// simulated wall clock starts at 2020-01-01, so every TLS test jumps to
/// here before dialing.
const fixture_valid_now_unix: u64 = 1_800_000_000;
const sim_wall_clock_base_unix: u64 = 1_577_836_800;

const TestTlsServer = @import("../../tls/TestServer.zig").TestServer;

/// The shared shape of the TLS pool tests: a scripted TLS origin, a
/// witnessed proxy over a one-cluster table that dials TLS, and the
/// recorder-backed session. `server_name` picks the name the cluster's
/// verification asks for — the fixture's own, or a wrong one for the
/// refusal test. The cluster table and route table live on this struct:
/// the proxy borrows them for its whole life.
const TlsPoolTest = struct {
    const ProxyType = Proxy(Io.SimIo, 4);

    sim: Io.SimIo = undefined,
    origin: TestTlsServer = .{},
    proxy: ProxyType = undefined,
    recorder: TestRecorder = .{},
    h3: session.H3Session = undefined,
    tally: TestTally = .{},
    stop: StopTimer = undefined,
    stop_completion: Io.SimIo.Completion = .{},
    endpoint: std.Io.net.IpAddress = undefined,
    endpoints: [1]std.Io.net.IpAddress = undefined,
    /// The trust anchors the cluster's verification reads — the fixture
    /// bundle, so a chain to the fixture cert verifies (or fails on the
    /// name alone, when the test asks for a wrong one).
    store: TrustStore = undefined,
    routes: [1]Route = .{.{ .prefix = "/" }},
    clusters: [1]Cluster = undefined,
    /// Reassembly sink for the DATA payloads the session sent: the
    /// assertions read what the client actually received, frame
    /// boundaries erased.
    payload_buf: [8192]u8 = undefined,

    fn init(
        self: *TlsPoolTest,
        arena: std.mem.Allocator,
        seed: u64,
        server_name: []const u8,
    ) !void {
        try self.sim.init(arena, .{ .seed = seed });
        self.sim.advanceWallClock(
            (fixture_valid_now_unix - sim_wall_clock_base_unix) * std.time.ns_per_s,
        );
        const loopback = try std.Io.net.IpAddress.parseLiteral("127.0.0.1:0");
        try self.origin.start(&self.sim, arena, loopback, fixture_cert_pem, fixture_key_pem);
        self.endpoint = self.sim.listenerAddress(self.origin.listener);
        self.endpoints[0] = self.endpoint;
        self.store = try TrustStore.load(arena, fixture_cert_pem);
        self.clusters = .{
            .{
                .endpoints = &self.endpoints,
                .tls = .{
                    .server_name = server_name,
                    .trust = &self.store,
                },
            },
        };
        try self.proxy.initInPlaceRouted(&self.sim, arena, &self.routes, &self.clusters, .{
            .timeout_ns = 100 * std.time.ns_per_ms,
            .counters = .{ .ctx = &self.tally, .note = TestTally.note },
        });
        try self.h3.initInPlace(arena, self.recorder.interface(), neverHandler());
        // The listener sets this right after initInPlace; the test plays
        // the listener so the witnessed client address is a known value.
        self.h3.peer = try std.Io.net.IpAddress.parseLiteral("127.0.0.1:4333");
        self.recorder.payload = &self.payload_buf;
        self.stop = .{ .sim = &self.sim };
    }

    /// Arm the stop backstop: an armed accept is never quiescent — only
    /// timers schedule wakes — so the loop needs a timer to end it.
    fn armBackstop(self: *TlsPoolTest, delay_ns: u64) void {
        self.stop_completion = .{};
        self.sim.timerStart(
            &self.stop_completion,
            delay_ns,
            StopTimer,
            &self.stop,
            StopTimer.onFire,
        );
    }

    fn fire(self: *TlsPoolTest, stream_id: u64, path: []const u8) void {
        const handler = self.proxy.handler();
        const request = testRequest(stream_id, path);
        handler.onRequest(handler.ctx, &self.h3, stream_id, &request);
        finishBody(handler, &self.h3, stream_id);
    }

    /// Schedule one request to fire after `delay_ns` — the deterministic
    /// point after every earlier-scheduled delivery has completed, which
    /// is what makes pool reuse observable.
    fn fireLater(
        self: *TlsPoolTest,
        step: *RequestTimer,
        delay_ns: u64,
        stream_id: u64,
        path: []const u8,
    ) void {
        step.* = .{
            .sim = &self.sim,
            .handler = self.proxy.handler(),
            .h3 = &self.h3,
            .stream_id = stream_id,
            .path = path,
        };
        step.arm(delay_ns);
    }

    fn payloadText(self: *TlsPoolTest) []const u8 {
        return self.payload_buf[0..self.recorder.payload_len];
    }
};

test "h3 proxy: a tls cluster verifies the origin and relays the streamed response" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tls_test: TlsPoolTest = .{};
    try tls_test.init(arena, 113, fixture_origin_name);
    tls_test.armBackstop(2 * std.time.ns_per_s);

    tls_test.fire(0, "/serve");
    // A follow-up inherits the parked session — dead, because the
    // scripted origin closes after answering — and is answered 502
    // without a retry. It is here to prove the first response parked.
    var dead_checkout: RequestTimer = undefined;
    tls_test.fireLater(&dead_checkout, 1 * std.time.ns_per_ms, 4, "/serve");
    // The request after the failed checkout dials a fresh TLS session and
    // is served: the pool stayed whole through the dead reuse.
    var after: RequestTimer = undefined;
    tls_test.fireLater(&after, 2 * std.time.ns_per_ms, 8, "/serve");

    try tls_test.sim.run();

    try std.testing.expectEqual(@as(u64, 2), tls_test.tally.get(.response));
    try std.testing.expectEqual(@as(u64, 1), tls_test.tally.get(.bad_gateway));
    try std.testing.expectEqual(@as(u64, 0), tls_test.tally.get(.gateway_timeout));
    // Three requests, two TCP accepts: the middle one consumed the parked
    // slot instead of dialing, which is exactly the no-second-handshake
    // evidence — a re-handshake would have needed a fresh connection.
    try std.testing.expectEqual(@as(u32, 2), tls_test.origin.accepted_count);
    try std.testing.expectEqual(@as(u32, 2), tls_test.origin.served);
    try std.testing.expectEqual(@as(usize, 1), tls_test.proxy.parkedCount());
    try std.testing.expectEqual(@as(u32, 1), tls_test.proxy.tlsEnginesHeld());
    const transcript = tls_test.payloadText();
    try std.testing.expectEqual(@as(usize, 2), countOccurrences(transcript, "ok"));
    try std.testing.expectEqual(@as(usize, 1), countOccurrences(transcript, "bad gateway\n"));
    try std.testing.expect(tls_test.recorder.fin);
}

test "h3 proxy: a tls handshake that fails verification answers 502 without a retry" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tls_test: TlsPoolTest = .{};
    // The cluster verifies against the fixture's anchors but asks for a
    // name the certificate does not carry: the handshake fails at the
    // chain-and-name check, exactly the TCP path's refusal semantics.
    try tls_test.init(arena, 127, "not-the-origin.example");
    tls_test.armBackstop(2 * std.time.ns_per_s);

    tls_test.fire(0, "/serve");
    var follow_up: RequestTimer = undefined;
    tls_test.fireLater(&follow_up, 1 * std.time.ns_per_ms, 4, "/serve");

    try tls_test.sim.run();

    try std.testing.expectEqual(@as(u64, 0), tls_test.tally.get(.response));
    // Each exchange failed its one dial — no retry anywhere: the first
    // request's failure is one verdict, and the follow-up's fresh dial
    // failing the same way is a second.
    try std.testing.expectEqual(@as(u64, 2), tls_test.tally.get(.bad_gateway));
    // The refusal verdict reached the client.
    const transcript = tls_test.recorder.bytes[0..tls_test.recorder.len];
    try std.testing.expect(std.mem.indexOf(u8, transcript, "bad gateway\n") != null);
    // The origin saw one TCP accept and completed no handshake: the
    // failure was the verification, not the dial. The follow-up dialed
    // fresh and failed the same way — no retry on the first exchange,
    // and the failed dial's engine went back to the pool.
    try std.testing.expectEqual(@as(u32, 2), tls_test.origin.accepted_count);
    try std.testing.expectEqual(@as(u32, 0), tls_test.origin.served);
    try std.testing.expectEqual(@as(usize, 0), tls_test.proxy.parkedCount());
    try std.testing.expectEqual(@as(u32, 0), tls_test.proxy.tlsEnginesHeld());
}

test "h3 proxy: a tls exchange deadline releases the engine and answers 504" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var sim_io: Io.SimIo = undefined;
    try sim_io.init(arena, .{ .seed = 131 });
    // The verifier context stamps the wall clock at dial; keep it inside
    // the fixture validity window like every TLS test.
    sim_io.advanceWallClock(
        (fixture_valid_now_unix - sim_wall_clock_base_unix) * std.time.ns_per_s,
    );
    const loopback = try std.Io.net.IpAddress.parseLiteral("127.0.0.1:0");
    const listener = try sim_io.listen(&.{ .ip = loopback }, null);
    var origin: TestOrigin = .{ .sim = &sim_io, .listener = listener };
    origin.armAccept();
    const endpoint = sim_io.listenerAddress(listener);

    var store = try TrustStore.load(arena, fixture_cert_pem);
    const endpoints = try arena.alloc(std.Io.net.IpAddress, 1);
    endpoints[0] = endpoint;
    var routes = [_]Route{.{ .prefix = "/" }};
    var clusters = [_]Cluster{
        .{
            .endpoints = endpoints,
            .tls = .{
                .server_name = fixture_origin_name,
                .trust = &store,
            },
        },
    };
    var proxy: Proxy(Io.SimIo, 2) = undefined;
    try proxy.initInPlaceRouted(&sim_io, arena, &routes, &clusters, .{
        // A deadline too tight to dial and handshake inside: the armed
        // handshake recv is what the timeout's shutdown forces, and the
        // verdict is the 504 — the timeout path the TCP path's handshake
        // has, inherited unchanged.
        .timeout_ns = 1 * std.time.ns_per_ms,
    });
    var recorder: TestRecorder = .{};
    var h3: session.H3Session = undefined;
    try h3.initInPlace(arena, recorder.interface(), neverHandler());
    h3.peer = try std.Io.net.IpAddress.parseLiteral("127.0.0.1:4333");

    var stop = StopTimer{ .sim = &sim_io };
    var stop_completion: Io.SimIo.Completion = .{};
    sim_io.timerStart(
        &stop_completion,
        2 * std.time.ns_per_s,
        StopTimer,
        &stop,
        StopTimer.onFire,
    );

    // The scripted origin reads and never answers: the TCP connect
    // succeeds, the ClientHello vanishes into it, and the handshake recv
    // waits until the deadline shuts the socket down.
    const handler = proxy.handler();
    const request = testRequest(0, "/mute");
    handler.onRequest(handler.ctx, &h3, 0, &request);
    finishBody(handler, &h3, 0);

    try sim_io.run();

    try std.testing.expectEqual(@as(u64, 0), proxy.parkedCount());
    try std.testing.expectEqual(@as(u32, 0), proxy.tlsEnginesHeld());
    try std.testing.expectEqual(@as(u32, 1), origin.accepted_count);
    // The verdict reached the client, and no engine leaked: the forced
    // delivery's finish returned it.
    const transcript = recorder.bytes[0..recorder.len];
    try std.testing.expect(std.mem.indexOf(u8, transcript, "gateway timeout\n") != null);
}

test "h3 proxy: session teardown releases a parked tls exchange and its engine" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tls_test: TlsPoolTest = .{};
    try tls_test.init(arena, 137, fixture_origin_name);
    tls_test.armBackstop(2 * std.time.ns_per_s);

    // A zero-byte window: the head relays, the first DATA send
    // short-writes by the whole body, and the exchange parks with its
    // TLS session still live — the state teardown must clean up.
    tls_test.recorder.window_bytes = 0;
    tls_test.fire(0, "/serve");
    var teardown = TeardownStep{
        .sim = &tls_test.sim,
        .teardown = tls_test.proxy.sessionTeardown(),
        .h3 = &tls_test.h3,
    };
    teardown.arm(1 * std.time.ns_per_ms);

    try tls_test.sim.run();

    // The dying session was never answered: no verdict of any kind.
    try std.testing.expectEqual(@as(u64, 0), tls_test.tally.get(.response));
    try std.testing.expectEqual(@as(u64, 0), tls_test.tally.get(.bad_gateway));
    try std.testing.expectEqual(@as(u64, 0), tls_test.tally.get(.gateway_timeout));
    // The parked exchange owned no armed op, so the deregister settled it
    // synchronously — socket closed, engine back in the pool.
    try std.testing.expectEqual(@as(usize, 0), tls_test.proxy.parkedCount());
    try std.testing.expectEqual(@as(u32, 0), tls_test.proxy.tlsEnginesHeld());
}
