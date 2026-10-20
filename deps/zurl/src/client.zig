//! One-shot, deadline-bounded fetch: the control-plane convenience layer.
//!
//! `Connection` does not care where its transport came from; `fetch` is the
//! layer that dials for you. Its deadline is a WHOLE-REQUEST bound enforced by
//! Io cancellation (design rule 3): one number covers DNS, connect, request
//! and response, and it works identically on `Io.Threaded` (which panics on a
//! non-none connect timeout) and on zio. Measured against a server that
//! accepts and never answers: the cancel unwinds the task in ~1 ms.

const std = @import("std");
const Io = std.Io;
const assert = std.debug.assert;
const net = std.Io.net;
const connection = @import("connection.zig");
const parser = @import("parser.zig");
const tls_transport = @import("tls.zig");

pub const default_deadline_ns: u64 = 30 * std.time.ns_per_s;

pub const FetchRequest = struct {
    /// http:// or https://. TLS arrives as a transport (design rule 5), so
    /// https needs `tls` set and changes nothing above the transport seam.
    url: []const u8,
    method: std.http.Method = .GET,
    authorization: ?[]const u8 = null,
    content_type: ?[]const u8 = null,
    /// Sent as `user-agent`. Null sends none.
    ///
    /// Defaulted because its ABSENCE is a failure a caller cannot diagnose
    /// from a status — GitHub rejects a UA-less request outright. Set your
    /// own to identify your service; nothing deduplicates against `extra`.
    user_agent: ?[]const u8 = connection.default_user_agent,
    extra: []const connection.Header = &.{},
    /// What to send as the request body. `.{ .bytes = "..." }` for something
    /// already in memory, `.{ .stream = .{ .source = r } }` to send it as it
    /// is read — see `connection.RequestBody`.
    ///
    /// A streamed body cannot be replayed, so a 307 or 308 that would resend
    /// it is `error.BodyNotReplayable` rather than a request with no body.
    body: ?connection.RequestBody = null,
    sink: connection.Sink = .discard,
    /// Called once per RESPONSE header, and again for each chunked trailer.
    /// Names arrive as the origin sent them; values are trimmed of leading and
    /// trailing space and tab.
    ///
    /// This is the only way to see a response header, and it is a callback
    /// rather than a map because of where the bytes live: `name` and `value`
    /// point into the reader's buffer, which the body stream overwrites. They
    /// are valid **for the duration of the call and no longer**, so a caller
    /// that wants one keeps it by copying it out. That constraint is the API
    /// rather than a wart — a map would have to allocate, and zurl does not.
    ///
    /// It fires while the head is being read, so it cannot be used to decide
    /// whether to send the request; for that, look at `Response.status` after.
    ///
    /// **A trailer can repeat a name the head already sent, and this callback
    /// cannot tell you which is which.** A caller that stores last-value-wins
    /// therefore lets the trailer overwrite the head — so an origin can answer
    /// `retry-after: 60` in the head and `retry-after: 0` in the trailer and
    /// defeat the backoff the header exists for. A check a caller ran against
    /// the head does not re-run against the trailer. If a value is
    /// load-bearing, keep the FIRST occurrence, or stop recording once the
    /// body starts.
    ///
    /// **With `redirects.max` above zero this fires for EVERY hop**, including
    /// ones whose status the caller never sees and whose body was dropped, and
    /// nothing in the callback says which hop it belongs to. A caller
    /// recording `location` or a rate-limit header across a chain therefore
    /// sees the intermediate origins' answers mixed with the final one. Where
    /// that matters, follow redirects yourself: `max = 0` makes each 3xx a
    /// separate `fetch` you can attribute.
    on_header: ?parser.HeaderFn = null,
    /// Passed to `on_header` untouched. It is where a caller keeps whatever it
    /// copied out during the callback.
    ctx: ?*anyopaque = null,
    /// Bounds the status line plus all headers, and separately the trailer
    /// section, in raw bytes. Exposed alongside `on_header` because the two
    /// are one decision: a caller reading rate-limit headers off a chatty API
    /// is exactly the caller who may need this raised, and an omitted bound is
    /// an accident waiting to be reinterpreted.
    ///
    /// The head must also fit whole in the transport's read buffer, so the
    /// smaller of the two wins.
    max_head_bytes: usize = parser.HeadOptions.max_head_bytes_default,
    /// Accept a body still in its `content-encoding` rather than refusing it.
    ///
    /// zurl decodes no content codings, so a `gzip` response is refused with
    /// `UnsupportedContentEncoding` by default — handing compressed bytes to a
    /// sink expecting text is the incident this library exists for. Set this
    /// when the sink genuinely wants the raw bytes, such as writing them to a
    /// file. Nothing here requests an encoding, so a compliant origin never
    /// triggers either path.
    allow_encoded_body: bool = false,
    /// Whether, and how far, to follow a 3xx. Off unless asked.
    redirects: Redirects = .{},
    deadline_ns: u64 = default_deadline_ns,
    /// Named in the timeout message. A key or a short label, never a URL — a
    /// URL can carry a token in its query, and logs are public.
    what: []const u8 = "request",
    /// Required for https, and unused for http.
    ///
    /// There is no default, and that is deliberate: the only default worth
    /// having is the system trust store, loading it allocates, and zurl
    /// allocates nothing. A caller that silently got `no_verification`
    /// instead would have an https URL that looks secure and is not.
    tls: ?tls_transport.Config = null,
};

/// Redirect policy. Following is OFF by default, and that is a decision.
///
/// `std.http.Client` follows redirects silently, so a caller migrating to zurl
/// inherits whatever its endpoints were doing without ever having seen it —
/// `Response` carries a status and nothing else. Defaulting to off turns a
/// followed 302 into a visible non-ok status on the first run, which is a loud
/// answer to a question nobody had asked. Turn it on where a run shows an
/// endpoint actually redirects.
pub const Redirects = struct {
    /// How many hops to follow. Zero means the 3xx is the answer.
    max: u8 = 0,
    /// Where the chain is built: each hop's `location` is resolved against the
    /// previous URL into this buffer, and the space is not reused between
    /// hops, because a hop's URL must stay valid while the next is resolved
    /// against it. So this bounds the whole chain, not one URL, and running
    /// out is `error.TooManyRedirects` rather than a truncated location.
    ///
    /// Unused when `max` is zero. 2 KiB is comfortable for a handful of hops.
    buf: []u8 = &.{},
};

pub const Error = error{
    InvalidUrl,
    /// The chain hit `Redirects.max`, or `Redirects.buf` ran out before it
    /// did. Distinct from a bad URL: every hop so far was well-formed.
    TooManyRedirects,
    /// A 3xx that cannot be followed — no `location`, or one that does not
    /// resolve to an http/https URL.
    InvalidRedirect,
    /// A 307 or 308 asked for the body to be resent, and the body was a
    /// stream that has already been consumed. Refused rather than silently
    /// resent as an EMPTY body, which the origin would accept as a perfectly
    /// good request that is not the one the caller made.
    BodyNotReplayable,
    /// An https URL arrived with no `tls` config. Distinct from a TLS
    /// failure: nothing was dialed and nothing was wrong with the peer.
    TlsNotConfigured,
    ConnectFailed,
    OutOfMemory,
    /// The Io backend could not give this fetch a thread for its deadline
    /// sleeper, so the request would have run unbounded. Refused instead of
    /// run: an unbounded request is the incident rule 3 exists to prevent,
    /// and it is better to say so than to hang.
    ///
    /// `fetch` needs TWO concurrent slots — the request and the deadline that
    /// bounds it — so this is returned when `concurrent_limit` is below two,
    /// and ALWAYS on a `single_threaded` build, where `Io.Threaded` cannot
    /// promise concurrency at all. That is a real limitation and it is stated
    /// here rather than discovered: on such a build every `fetch` fails, and a
    /// caller that wants an unbounded request must drive `Connection`
    /// directly, which needs no threads and no deadline.
    ConcurrencyUnavailable,
} || connection.Error || tls_transport.Error;

/// The longest legal DNS name, and so the longest host `fetch` will dial. It
/// is a bound, not storage: the host is a slice of the caller's URL and is
/// never copied anywhere.
const host_bytes_max: usize = 253;

/// The three things a URL says about where to connect.
///
/// Extracted so `fetch` and `Session` cannot disagree about what a URL means:
/// which scheme is dialable, what port a missing one implies, and how long a
/// host may be.
pub const Origin = struct {
    secure: bool,
    /// A slice of the caller's URL, never copied.
    host: []const u8,
    port: u16,

    pub fn of(uri: std.Uri) Error!Origin {
        const secure = scheme: {
            if (std.ascii.eqlIgnoreCase(uri.scheme, "https")) break :scheme true;
            if (std.ascii.eqlIgnoreCase(uri.scheme, "http")) break :scheme false;
            return error.InvalidUrl;
        };

        // Port 0 means "let the kernel choose" to a listener and nothing at
        // all to a dialer, so it is a bad URL rather than an assertion: it
        // reaches us from whatever string the caller was handed.
        const port: u16 = uri.port orelse if (secure) 443 else 80;
        if (port == 0) return error.InvalidUrl;

        const host = hostBytes(&uri) orelse return error.InvalidUrl;
        if (host.len == 0 or host.len > host_bytes_max) return error.InvalidUrl;

        return .{ .secure = secure, .host = host, .port = port };
    }

    /// Connect, by IP literal when the host is one and by name otherwise.
    pub fn dial(origin: Origin, io: Io) Error!net.Stream {
        assert(origin.host.len > 0);
        assert(origin.port != 0);

        if (net.IpAddress.parse(origin.host, origin.port)) |addr| {
            return addr.connect(io, .{ .mode = .stream }) catch error.ConnectFailed;
        } else |_| {
            const name = net.HostName.init(origin.host) catch return error.InvalidUrl;
            return name.connect(io, origin.port, .{ .mode = .stream }) catch error.ConnectFailed;
        }
    }
};

/// Buffers a transport holds for as long as it is open.
///
/// Caller-supplied, because zurl allocates nothing, and named separately from
/// any request because they outlive one: a `fetch` keeps these on its own
/// stack frame, and anything longer-lived cannot.
pub const Buffers = struct {
    /// Bounds the longest response head the parser can see. For https this is
    /// the PLAINTEXT read buffer.
    read: []u8,
    /// Request bytes staged before they go out. For https, plaintext.
    write: []u8,
    /// https only, unused for http. Each must be at least
    /// `tls.buffer_bytes_min`, because each holds one whole ciphertext record.
    ciphertext_in: []u8 = &.{},
    ciphertext_out: []u8 = &.{},
};

/// A dialed origin with its transport standing: the socket, its reader and
/// writer, and a TLS session when the origin is https.
///
/// This exists so that the socket stays in `client.zig`, which rule 5 makes
/// the only file allowed to dial. Anything longer-lived than a `fetch` —
/// `Session` today — holds one of these and never names a socket type, so the
/// seam stays one file wide instead of two.
///
/// **Not movable once open.** `reader` and `writer` point into fields of this
/// struct, which is why `open` takes a pointer.
pub const Dialed = struct {
    io: Io,
    secure: bool,
    stream: net.Stream,
    socket_reader: net.Stream.Reader,
    socket_writer: net.Stream.Writer,
    /// Meaningful only when `secure`. A plain `undefined` rather than an
    /// optional: unwrapping an optional whose payload was just written as
    /// `undefined` leans on compiler behaviour no language reference promises,
    /// and `secure` already answers the only question anyone asks of it.
    ///
    /// The cost is that a plain-HTTP `Dialed` still carries std.crypto.tls's
    /// kilobyte-plus of cipher state. That is the cost `attempt` splits its
    /// two exchange frames to avoid -- and it is worth paying here and not
    /// there, because a `Dialed` is long-lived and per-session while those
    /// frames are per-request and on a hot path.
    tls: tls_transport.Transport,

    pub fn open(dialed: *Dialed, io: Io, origin: Origin, buffers: Buffers, config: ?tls_transport.Config) Error!void {
        assert(buffers.read.len > 0);
        assert(buffers.write.len > 0);

        if (origin.secure and config == null) return error.TlsNotConfigured;

        dialed.* = .{
            .io = io,
            .secure = origin.secure,
            .stream = try origin.dial(io),
            .socket_reader = undefined,
            .socket_writer = undefined,
            .tls = undefined,
        };
        errdefer dialed.stream.close(io);

        // The socket's own buffers are the ciphertext side for https and the
        // whole story for http, which is the only difference between the arms.
        const socket_read = if (origin.secure) buffers.ciphertext_in else buffers.read;
        const socket_write = if (origin.secure) buffers.ciphertext_out else buffers.write;
        dialed.socket_reader = dialed.stream.reader(io, socket_read);
        dialed.socket_writer = dialed.stream.writer(io, socket_write);

        if (!origin.secure) return;

        try dialed.tls.init(.{
            .io = io,
            .input = &dialed.socket_reader.interface,
            .output = &dialed.socket_writer.interface,
            .host = origin.host,
            .read_buffer = buffers.read,
            .write_buffer = buffers.write,
            .config = config.?,
        });
    }

    pub fn reader(dialed: *Dialed) *Io.Reader {
        return if (dialed.secure) dialed.tls.reader() else &dialed.socket_reader.interface;
    }

    pub fn writer(dialed: *Dialed) *Io.Writer {
        return if (dialed.secure) dialed.tls.writer() else &dialed.socket_writer.interface;
    }

    /// Only valid on a `Dialed` that `open` returned successfully for — before
    /// that, every field is `undefined`.
    pub fn close(dialed: *Dialed) void {
        // close_notify before the socket goes, so the peer can tell a finished
        // session from a truncation.
        if (dialed.secure) dialed.tls.close();
        dialed.stream.close(dialed.io);
    }
};

/// The origin-form request target for `uri`: path, plus query when present,
/// written into `buf` and validated.
///
/// `buf` is the bound on the whole target. A path and query that will not fit
/// is `error.InvalidUrl` — never a truncated target, which would silently
/// request a different resource (rule 7).
///
/// `std.Uri.parse` is not the validation it looks like. It ACCEPTS CR, LF and
/// spaces inside a path and hands them back verbatim in `percent_encoded`,
/// which is how a URL becomes request-header injection. `writeRequest` refuses
/// them too — that is what covers a caller using `Connection` directly — but a
/// fetch should not spend a socket to find out, and `InvalidUrl` is the truer
/// answer here: what the caller passed was a URL.
fn originFormTarget(uri: std.Uri, host: []const u8, buf: []u8) error{InvalidUrl}![]const u8 {
    assert(buf.len > 0);
    assert(host.len > 0);

    var tw: Io.Writer = .fixed(buf);
    const path = uri.path.percent_encoded;
    tw.writeAll(if (path.len == 0) "/" else path) catch return error.InvalidUrl;
    if (uri.query) |q| tw.print("?{s}", .{q.percent_encoded}) catch return error.InvalidUrl;

    const target = tw.buffered();
    connection.validateTarget(target, host) catch return error.InvalidUrl;

    // A URI with an authority has an empty path or one beginning with a slash,
    // and the empty case was just replaced — so origin-form holds.
    assert(target.len > 0);
    assert(target[0] == '/');
    return target;
}

/// Whether a scheme is one `fetch` can dial.
fn isHttpScheme(scheme: []const u8) bool {
    return std.ascii.eqlIgnoreCase(scheme, "http") or std.ascii.eqlIgnoreCase(scheme, "https");
}

/// Default port for a scheme already known to be http or https.
fn defaultPort(scheme: []const u8) u16 {
    return if (std.ascii.eqlIgnoreCase(scheme, "https")) 443 else 80;
}

/// RFC 6454 same origin: scheme, host and effective port all equal.
///
/// This is what decides whether `authorization` survives a hop, so it is
/// deliberately strict — a subdomain is a different origin, and http and https
/// are different origins even on the same host. A hostless URI is never the
/// same origin as anything, including itself: there is nothing to compare.
fn sameOrigin(a: *const std.Uri, b: *const std.Uri) bool {
    if (!std.ascii.eqlIgnoreCase(a.scheme, b.scheme)) return false;

    // Switched exhaustively rather than reaching for `.percent_encoded`.
    // `std.Uri.parse` only ever produces that variant today, but reading the
    // wrong one is a panic, and this comparison is a SECURITY decision driven
    // partly by a `location` header the peer chose. A future std that returns
    // `.raw` here must break the build, not the credential rule.
    const a_host = hostBytes(a) orelse return false;
    const b_host = hostBytes(b) orelse return false;
    if (!std.ascii.eqlIgnoreCase(a_host, b_host)) return false;

    const a_port = a.port orelse defaultPort(a.scheme);
    const b_port = b.port orelse defaultPort(b.scheme);
    return a_port == b_port;
}

/// The host of `uri` as bytes, whichever component variant carries it.
fn hostBytes(uri: *const std.Uri) ?[]const u8 {
    const component = uri.host orelse return null;
    return switch (component) {
        .raw => |h| h,
        .percent_encoded => |h| h,
    };
}

/// Whether `status` is a redirect zurl knows how to follow.
///
/// 300 (Multiple Choices) is deliberately absent: it has no single `location`
/// to follow and picking one would be zurl inventing a policy.
fn redirectKind(status: u16) ?Redirect.Kind {
    return switch (status) {
        307, 308 => .same_method,
        301, 302 => .historical_post_rewrite,
        303 => .retrieve,
        else => null,
    };
}

/// What the next hop sends, given the status and the method that got the 3xx.
pub const Redirect = struct {
    method: std.http.Method,
    /// False when the method changed: a GET produced by a rewrite has nothing
    /// to send, and resending the old body under a new method would be a
    /// different request than either endpoint expects.
    keep_body: bool,

    const Kind = enum { same_method, historical_post_rewrite, retrieve };

    fn next(kind: Kind, from: std.http.Method) Redirect {
        // HEAD survives everything. It is already a retrieval, and turning it
        // into a GET changes WHAT is fetched rather than how it is framed — a
        // caller probing for existence would silently start pulling bodies.
        // `ycs.head` is a live caller of exactly that shape.
        if (from == .HEAD) return .{ .method = .HEAD, .keep_body = false };

        return switch (kind) {
            // 307 and 308 exist precisely to say "same method, same body".
            .same_method => .{ .method = from, .keep_body = true },
            // 303 says "GET the other thing" outright, whatever was sent.
            .retrieve => .{ .method = .GET, .keep_body = false },
            // 301 and 302 are specified to preserve the method, and the
            // universal historical deviation is narrower than it is usually
            // described: RFC 9110 §15.4.2/§15.4.3 permit changing POST to GET
            // and nothing else, and curl rewrites only POST too. A PUT or a
            // DELETE keeps its method and its body — rewriting those would
            // turn "delete this" into "fetch this" and report success.
            .historical_post_rewrite => if (from == .POST)
                .{ .method = .GET, .keep_body = false }
            else
                .{ .method = from, .keep_body = true },
        };
    }
};

/// Captures `location` for the redirect logic while passing every header on to
/// the caller's own `on_header`.
///
/// It has to be one callback because the parser offers one, and it has to copy
/// because `value` dies when the body streams.
const HeadWatch = struct {
    user: ?parser.HeaderFn,
    user_ctx: ?*anyopaque,
    /// Where `location` is copied. Also where it is resolved in place, so this
    /// is the live front of `Redirects.buf`.
    location_buf: []u8,
    len: usize = 0,
    found: bool = false,
    /// Set when a `location` arrived that `dest` could not hold. Distinguished
    /// from "no location" so the caller gets TooManyRedirects, not a silent
    /// stop — rule 7: never a truncated URL.
    overflowed: bool = false,

    fn onHeader(ctx: ?*anyopaque, name: []const u8, value: []const u8) void {
        const self: *HeadWatch = @ptrCast(@alignCast(ctx.?));
        if (self.user) |f| f(self.user_ctx, name, value);

        if (!std.ascii.eqlIgnoreCase(name, "location")) return;
        // FIRST location wins. A second one is either a broken origin or an
        // attempt to have two clients disagree about where they went.
        if (self.found or self.overflowed) return;
        // Two different failures, kept apart: an absent location is a broken
        // 3xx, an oversized one is the chain outgrowing its buffer.
        if (value.len == 0) return;
        if (value.len > self.location_buf.len) {
            self.overflowed = true;
            return;
        }
        @memcpy(self.location_buf[0..value.len], value);
        self.len = value.len;
        self.found = true;
    }
};

/// Everything one attempt in a redirect chain needs that can change between
/// hops. The first hop is the caller's request; later ones may have lost the
/// `authorization` header and had their method rewritten.
const Hop = struct {
    uri: std.Uri,
    method: std.http.Method,
    body: ?connection.RequestBody,
    authorization: ?[]const u8,
};

const Task = struct {
    io: Io,
    req: *const FetchRequest,
    result: ?(Error!connection.Response) = null,

    fn run(task: *Task) void {
        // One Task serves one request; a second run would overwrite a result
        // the racing `fetch` may already be about to read.
        assert(task.result == null);

        task.result = task.roundTrip();
    }

    /// The whole fetch, including any redirect chain.
    ///
    /// Each hop is a fresh connection: `fetch` sends `connection: close`, so
    /// there is nothing to reuse even when a redirect stays on one origin.
    fn roundTrip(task: *Task) Error!connection.Response {
        const req = task.req;

        // The URL is whatever string the caller was handed — from a config
        // file, or from a request one hop upstream. Every rejection of it is
        // an error, never an assertion: a consumer that forwards someone
        // else's URL must not be able to panic this library from off-box.
        if (req.url.len == 0) return error.InvalidUrl;
        var hop: Hop = .{
            .uri = std.Uri.parse(req.url) catch return error.InvalidUrl,
            .method = req.method,
            .body = req.body,
            .authorization = req.authorization,
        };

        // Programmer input: asking for hops without somewhere to build them is
        // a misconfiguration, and the first redirect would otherwise report
        // TooManyRedirects — true, but it would read as "the chain was long".
        assert(req.redirects.max == 0 or req.redirects.buf.len > 0);

        var chain = req.redirects.buf;
        var hops_left = req.redirects.max;

        // lint:unbounded-ok — `hops_left` strictly decreases on the only path
        // that continues, and every other path returns.
        while (true) {
            var watch: HeadWatch = .{
                .user = req.on_header,
                .user_ctx = req.ctx,
                .location_buf = chain,
            };
            const outcome = try task.attempt(&hop, &watch, hops_left > 0);

            const followable = hops_left > 0 and redirectKind(outcome.status) != null;
            if (!followable) return outcome;

            hop = try nextHop(&hop, &watch, outcome.status, &chain);
            assert(hops_left > 0);
            hops_left -= 1;
        }
    }

    /// Resolve the next hop's URL against this one and apply the policy that
    /// makes following safe.
    fn nextHop(from: *const Hop, watch: *HeadWatch, status: u16, chain: *[]u8) Error!Hop {
        // A location too long for the remaining buffer is the chain outgrowing
        // its bound, never a truncated URL pointing somewhere else (rule 7).
        if (watch.overflowed) return error.TooManyRedirects;
        if (!watch.found) return error.InvalidRedirect;

        // `location` is already at the front of `chain`, which is what
        // resolveInPlace wants; it resolves relative references against the
        // URL we came from and advances `chain` past what it used, so earlier
        // hops stay valid while later ones are built.
        // Established by `onHeader`: a found location is never empty, because
        // the zero-length case returns before setting the flag.
        assert(watch.len > 0);
        assert(watch.len <= chain.len);

        const to = std.Uri.resolveInPlace(from.uri, watch.len, chain) catch |err| return switch (err) {
            error.NoSpaceLeft => error.TooManyRedirects,
            else => error.InvalidRedirect,
        };
        if (!isHttpScheme(to.scheme)) return error.InvalidRedirect;

        const next = Redirect.next(redirectKind(status).?, from.method);

        // A stream is gone once it has been sent. Following anyway would put
        // an empty body on a PUT the origin will happily accept — a different
        // request than the caller made, reported as success.
        if (next.keep_body) {
            if (from.body) |body| {
                if (!body.replayable()) return error.BodyNotReplayable;
            }
        }
        return .{
            .uri = to,
            .method = next.method,
            .body = if (next.keep_body) from.body else null,
            // THE security rule, and structural rather than a flag: an
            // `authorization` header follows the origin it was issued for and
            // nowhere else. A redirect naming another host is otherwise a
            // credential-exfiltration primitive — point one at your own server
            // and collect whatever bearer token the caller was using.
            .authorization = if (sameOrigin(&from.uri, &to)) from.authorization else null,
        };
    }

    /// One request/response against one origin.
    ///
    /// `may_follow` decides where the body goes before the status is known,
    /// which is why the head and the body are read in two steps: the body of a
    /// 3xx that is about to be followed must not reach the caller's sink.
    fn attempt(task: *Task, hop: *const Hop, watch: *HeadWatch, may_follow: bool) Error!connection.Response {
        const io = task.io;
        const req = task.req;
        const uri = hop.uri;

        const origin = try Origin.of(uri);
        // Refused before the dial, not after: an https URL with no trust
        // configuration is a caller mistake, and finding that out only once a
        // connection is open wastes a round trip and a socket.
        if (origin.secure and req.tls == null) return error.TlsNotConfigured;
        const host = origin.host;

        // Built BEFORE the dial, so a URL that cannot become a request line
        // costs nothing — the same reason TlsNotConfigured is checked above.
        var target_buf: [2048]u8 = undefined;
        const target = try originFormTarget(uri, host, &target_buf);

        var stream = try origin.dial(io);
        defer stream.close(io);

        // The two transports get their own frames on purpose. TLS needs four
        // buffers and two of them must each hold a whole ciphertext record, so
        // its frame is ~66 KiB; a plain-HTTP fetch has no business reserving
        // that. Zig sizes a frame for all of its own locals, not for the
        // branch taken, so the split is what keeps the http path at 20 KiB.
        if (origin.secure) return task.exchangeTls(&stream, host, target, hop, watch, may_follow);
        return task.exchangePlain(&stream, host, target, hop, watch, may_follow);
    }

    /// The exchange itself, once a transport exists. Shared by both so plain
    /// and TLS cannot drift apart in redirect behaviour.
    ///
    /// The head and the body are read in two steps because the decision of
    /// where the body goes depends on the status. A 3xx that will be followed
    /// has its body left unread on the wire and the connection dropped —
    /// legitimate because `fetch` sends `connection: close` and is about to
    /// close anyway, and necessary because that body is not the caller's
    /// answer and must never reach the caller's sink.
    fn exchange(
        task: *Task,
        conn: *connection.Connection,
        host: []const u8,
        target: []const u8,
        hop: *const Hop,
        watch: *HeadWatch,
        may_follow: bool,
    ) Error!connection.Response {
        const opts = task.headOptions(watch);
        const head = try conn.roundTripHead(task.request(hop, host, target), opts);

        if (may_follow and redirectKind(head.status) != null) {
            // Nothing was delivered, and `body_len` says so rather than
            // reporting a length nobody received.
            return .{ .status = head.status, .body_len = 0 };
        }
        // `fetch` never reuses a connection, so the request never asked to.
        return conn.finishBody(head, hop.method, task.req.sink, opts, false);
    }

    /// What the parser is told about the head, built once so the two
    /// transports cannot drift apart in what they observe.
    ///
    /// `on_header` is always `HeadWatch`'s, never the caller's directly: the
    /// parser offers one callback and redirects need `location` from it, so
    /// the watch chains to the caller's.
    fn headOptions(task: *Task, watch: *HeadWatch) parser.HeadOptions {
        // Programmer input, not wire input, so an assertion is right where a
        // URL gets an error: every parser entry point asserts this, and
        // catching it at the boundary that BUILDS the options names the
        // misconfigured FetchRequest instead of a frame deep in the parser.
        assert(task.req.max_head_bytes > 0);

        return .{
            .on_header = HeadWatch.onHeader,
            .ctx = watch,
            .max_head_bytes = task.req.max_head_bytes,
            .allow_encoded_body = task.req.allow_encoded_body,
        };
    }

    /// The request every exchange sends, built once so the two transports
    /// cannot drift apart in what they ask for.
    fn request(task: *Task, hop: *const Hop, host: []const u8, target: []const u8) connection.Request {
        assert(host.len > 0);
        assert(target.len > 0);

        return .{
            // From the HOP, not the request: a redirect may have rewritten the
            // method and may have dropped the credential.
            .method = hop.method,
            .target = target,
            .host = host,
            .authorization = hop.authorization,
            .content_type = task.req.content_type,
            .user_agent = task.req.user_agent,
            .extra = task.req.extra,
            .body = hop.body,
            // One request per fetch: close is what gives a reply with no
            // discoverable body end somewhere to stop (a60a95c), and there is
            // no pool that reuse would feed.
            .keep_alive = false,
        };
    }

    fn exchangePlain(
        task: *Task,
        stream: *net.Stream,
        host: []const u8,
        target: []const u8,
        hop: *const Hop,
        watch: *HeadWatch,
        may_follow: bool,
    ) Error!connection.Response {
        assert(host.len > 0);
        assert(target.len > 0);

        const io = task.io;

        var read_buffer: [16 * 1024]u8 = undefined;
        var write_buffer: [4 * 1024]u8 = undefined;
        var r = stream.reader(io, &read_buffer);
        var w = stream.writer(io, &write_buffer);

        var conn = connection.Connection.init(&r.interface, &w.interface);
        return task.exchange(&conn, host, target, hop, watch, may_follow);
    }

    /// The same exchange with a TLS session spliced into the transport, which
    /// is the entire difference (design rule 5). `Connection` is handed two
    /// pointers and cannot tell which kind it got.
    fn exchangeTls(
        task: *Task,
        stream: *net.Stream,
        host: []const u8,
        target: []const u8,
        hop: *const Hop,
        watch: *HeadWatch,
        may_follow: bool,
    ) Error!connection.Response {
        const io = task.io;
        // Checked before the dial; re-read here rather than threaded through.
        const config = task.req.tls.?;

        // The encrypted side must hold one whole record in each direction —
        // std asserts it for the reader and demands it of the writer.
        var ciphertext_in: [tls_transport.buffer_bytes_min]u8 = undefined;
        var ciphertext_out: [tls_transport.buffer_bytes_min]u8 = undefined;
        // The plaintext side is sized like the http path: the read buffer is
        // what bounds the longest response head line the parser can see.
        var plaintext_in: [16 * 1024]u8 = undefined;
        var plaintext_out: [4 * 1024]u8 = undefined;

        var r = stream.reader(io, &ciphertext_in);
        var w = stream.writer(io, &ciphertext_out);
        // The buffers above are sized from `buffer_bytes_min`, so a
        // TlsBufferTooSmall from here would mean the stream kept part of what
        // it was handed — a failure no caller could fix, wearing an error that
        // says "caller bug".
        assert(r.interface.buffer.len >= tls_transport.buffer_bytes_min);
        assert(w.interface.buffer.len >= tls_transport.buffer_bytes_min);

        var transport: tls_transport.Transport = undefined;
        try transport.init(.{
            .io = io,
            .input = &r.interface,
            .output = &w.interface,
            .host = host,
            .read_buffer = &plaintext_in,
            .write_buffer = &plaintext_out,
            .config = config,
        });
        // close_notify before the socket goes, so the peer can tell a finished
        // session from a truncation. Ordered ahead of `stream.close` by being
        // deferred later than it.
        defer transport.close();

        var conn = connection.Connection.init(transport.reader(), transport.writer());
        return task.exchange(&conn, host, target, hop, watch, may_follow);
    }
};

/// One bounded request. `null` means the deadline elapsed and the request was
/// cancelled — `Io.Group.cancel` joins before returning, so by the time this
/// returns nothing holds a reference to any borrowed field of `req`.
///
/// The wait is a RACE, not a poll: the worker and a deadline sleeper both push
/// into a queue and the first event wins. The first draft polled a done-flag
/// every 20 ms, and bench/e2e.zig convicted it on its first run — a 120 us
/// loopback request cost 20 ms of wall clock, a 166x latency floor that a
/// correctness test can never see. Design rule 8 is not decorative.
///
/// Requires an `Io` that can actually run two things at once; see
/// `Error.ConcurrencyUnavailable`.
const Event = enum { done, deadline };

/// The two racers. At file scope rather than inside `fetch` only to keep that
/// function inside the 70-line limit — nothing else refers to them.
const Race = struct {
    fn work(tk: *Task, q: *Io.Queue(Event), rio: Io) void {
        tk.run();
        // A failed put means the deadline already won and `fetch` has stopped
        // listening. The result is still in the Task; nobody will read it, and
        // there is nothing here that could react instead.
        q.putOne(rio, .done) catch {};
    }
    fn sleeper(ns: u64, q: *Io.Queue(Event), rio: Io) void {
        // A cancelled sleep is the ordinary outcome — the request finished
        // first — and it means the deadline never elapsed, so returning
        // without posting anything is exactly right.
        rio.sleep(.fromNanoseconds(ns), .awake) catch return;
        q.putOne(rio, .deadline) catch {};
    }
};
pub fn fetch(io: Io, req: FetchRequest) Error!?connection.Response {
    // A zero deadline would race the sleeper against a request that has not
    // started; `what` is what the timeout message names, so an empty one turns
    // the only diagnostic this function emits into noise.
    assert(req.deadline_ns > 0);
    assert(req.what.len > 0);

    var task: Task = .{ .io = io, .req = &req };

    var q_buf: [2]Event = undefined;
    var queue: Io.Queue(Event) = .init(&q_buf);

    // `concurrent`, not `async`, and this is the whole mechanism. Io.Threaded
    // falls back to running an `async` task INLINE on the calling thread when
    // `busy_count >= async_limit`, and that limit defaults to cpu_count - 1 —
    // zero on a one-core box. Inline means `work` would run to completion
    // before `sleeper` was ever created, so a black-holed request would hang
    // forever with no deadline at all: nightly run #9 word for word, from the
    // mechanism written to prevent it. CI caught exactly that on a
    // four-core runner.
    //
    // `concurrent` is the API that promises a real thread and reports
    // ConcurrencyUnavailable instead of silently degrading. It is bounded by
    // `concurrent_limit` (unlimited by default), not by cpu_count, so a
    // single-core host still gets its deadline.
    var group: Io.Group = .init;

    // The errdefer is not redundant with the `group.cancel` below it. If the
    // SECOND `concurrent` fails, the first task is already running and holding
    // pointers to `task` and `queue` — both locals of this frame. Returning
    // straight out would free them under a live thread. `Group.cancel` joins
    // before it returns, so this is what makes the early exit safe.
    errdefer group.cancel(io);

    // Sleeper FIRST, and the order is load-bearing. Spawned the other way, a
    // worker that had already reached the wire would have its result thrown
    // away when the sleeper's spawn failed — a completed request discarded for
    // want of a thread. This way a failure here means nothing was ever dialed.
    try group.concurrent(io, Race.sleeper, .{ req.deadline_ns, &queue, io });
    try group.concurrent(io, Race.work, .{ &task, &queue, io });

    const event = queue.getOneUncancelable(io) catch Event.deadline;
    group.cancel(io);

    switch (event) {
        .done => {
            // The worker finished at the wire; its result stands, error or not.
            // `group.cancel` above joined it, so the write is complete and
            // visible without further synchronisation.
            assert(task.result != null);
            return try task.result.?;
        },
        .deadline => {
            // The cancel above unwound the worker mid-request. Whatever
            // partial error that unwinding produced is noise; the story is
            // the deadline.
            std.debug.print("zurl: {s} timed out after {d}ms\n", .{
                req.what, req.deadline_ns / std.time.ns_per_ms,
            });
            return null;
        },
    }
}

// ---------------------------------------------------------------------------
// tests
const t = std.testing;

/// Accept one connection, read until the blank line, write `response`.
///
/// Spawned with `Group.concurrent`, never `async`: `Io.Threaded` runs an
/// `async` task inline once its limit is reached, and an origin running inline
/// deadlocks the client that is waiting for it.
fn serveOnce(srv: *net.Server, sio: Io, response: []const u8) void {
    var s = srv.accept(sio) catch return;
    defer s.close(sio);

    var rb: [2048]u8 = undefined;
    var rr = s.reader(sio, &rb);
    // lint:unbounded-ok — the client sends a finite head and then waits; a
    // peer that never sends the blank line fails the read and returns.
    while (true) {
        const line = rr.interface.takeDelimiterInclusive('\n') catch return;
        if (line.len <= 2) break;
    }

    var wb: [512]u8 = undefined;
    var ww = s.writer(sio, &wb);
    ww.interface.writeAll(response) catch return;
    ww.interface.flush() catch return;
}

/// Records the header callback sequence, copying out of the reader's buffer
/// because those slices die when the body stream reuses it.
const HeaderLog = struct {
    buf: [256]u8 = undefined,
    len: usize = 0,
    retry_after: ?u32 = null,

    fn onHeader(ctx: ?*anyopaque, name: []const u8, value: []const u8) void {
        const self: *HeaderLog = @ptrCast(@alignCast(ctx.?));
        // Benign swallow: an overflow just stops `len` growing, and the
        // exact-match assertion in the test then fails loudly on the shortfall.
        const w = std.fmt.bufPrint(self.buf[self.len..], "{s}={s};", .{ name, value }) catch return;
        self.len += w.len;
        if (std.ascii.eqlIgnoreCase(name, "retry-after")) {
            self.retry_after = std.fmt.parseInt(u32, value, 10) catch null;
        }
    }
};

test "an https url without trust configuration is refused before any dial" {
    var threaded: Io.Threaded = .init(t.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // No `tls` field: there is no default trust store, because building one
    // allocates and zurl does not. Refused up front, before a socket exists —
    // if this ever dialed first, a typo'd https URL would cost a round trip
    // and the failure would look like the peer's fault.
    try t.expectError(error.TlsNotConfigured, fetch(io, .{ .url = "https://example.com/" }));
    // ...and with a config it gets past the scheme check, so the refusal is
    // about the missing configuration and not about https itself.
    try t.expectError(error.InvalidUrl, fetch(io, .{
        .url = "https://",
        .tls = .{ .ca = .insecure_no_verification },
    }));
    try t.expectError(error.InvalidUrl, fetch(io, .{ .url = "gopher://example.com/" }));
    try t.expectError(error.InvalidUrl, fetch(io, .{ .url = "not a url" }));
    // Every one of these is a string the caller was handed, so every one is an
    // error. A leaf library that panics on a bad URL panics its consumer.
    try t.expectError(error.InvalidUrl, fetch(io, .{ .url = "" }));
    try t.expectError(error.InvalidUrl, fetch(io, .{ .url = "http://example.com:0/" }));
    try t.expectError(error.InvalidUrl, fetch(io, .{ .url = "http:///nohost" }));
}

test "fetch against a live loopback server, deadline against a black hole" {
    var threaded: Io.Threaded = .init(t.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const addr = try net.IpAddress.parse("127.0.0.1", 0);
    var server = try addr.listen(io, .{ .reuse_address = true });
    defer server.deinit(io);
    const port = server.socket.address.getPort();

    const Serve = struct {
        fn run(srv: *net.Server, sio: Io) void {
            // Two connections: answer the first, black-hole the second.
            {
                var s = srv.accept(sio) catch return;
                defer s.close(sio);
                var rb: [2048]u8 = undefined;
                var rr = s.reader(sio, &rb);
                // Read until the blank line, then respond.
                while (true) {
                    const line = rr.interface.takeDelimiterInclusive('\n') catch return;
                    if (line.len <= 2) break;
                }
                var wb: [512]u8 = undefined;
                var ww = s.writer(sio, &wb);
                ww.interface.writeAll("HTTP/1.1 200 OK\r\ncontent-length: 4\r\n\r\nzurl") catch return;
                ww.interface.flush() catch return;
            }
            {
                var s = srv.accept(sio) catch return;
                defer s.close(sio);
                sio.sleep(.fromNanoseconds(30 * std.time.ns_per_s), .awake) catch {};
            }
        }
    };
    var group: Io.Group = .init;
    defer group.cancel(io);
    // `concurrent`: the origin must actually run beside the client. Under
    // plain `async` a host whose async_limit is exhausted runs Serve.run
    // inline and the test deadlocks on its own server — which is what a
    // single-CPU run of this file did before fetch stopped using `async`.
    try group.concurrent(io, Serve.run, .{ &server, io });

    var url_buf: [64]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/hello", .{port});

    var body: Io.Writer.Allocating = .init(t.allocator);
    defer body.deinit();
    const res = (try fetch(io, .{ .url = url, .sink = .{ .collect = &body } })).?;
    try t.expectEqual(@as(u16, 200), res.status);
    try t.expectEqualStrings("zurl", body.written());

    // Second request hits the black hole; the deadline must hand back null
    // rather than hanging — nightly run #9's 71 minutes, in miniature.
    const timed_out = try fetch(io, .{
        .url = url,
        .deadline_ns = 300 * std.time.ns_per_ms,
        .what = "black hole",
    });
    try t.expectEqual(@as(?connection.Response, null), timed_out);
}

test "a backend that cannot spawn refuses the fetch rather than running it unbounded" {
    // concurrent_limit .nothing is the shape of an Io whose threads are all
    // committed: `concurrent` cannot promise a deadline sleeper. The old code
    // used `async`, which answers that by running the request INLINE with no
    // deadline at all — unbounded, on a host already out of resources. The
    // contract now is that fetch says so before it dials.
    var threaded: Io.Threaded = .init(t.allocator, .{ .concurrent_limit = .nothing });
    defer threaded.deinit();
    const io = threaded.io();

    try t.expectError(error.ConcurrencyUnavailable, fetch(io, .{
        .url = "http://127.0.0.1:1/never-dialed",
        .deadline_ns = 100 * std.time.ns_per_ms,
        .what = "unspawnable",
    }));
}

test "a second spawn that fails unwinds the first without freeing it under a live thread" {
    // concurrent_limit 1 is the interesting case, and the one .nothing above
    // cannot reach: the FIRST `concurrent` succeeds and the second is refused,
    // so `fetch` must return an error while a task it started is still running
    // and still holding pointers to `task` and `queue` — both locals of that
    // frame. The errdefer'd `Group.cancel` joins before returning, which is the
    // only reason this is not a use-after-free.
    //
    // A one-spare-thread budget is a legitimate configuration, not a
    // pathological one, so this path is reachable in production and not just
    // in a test that contrives it.
    var threaded: Io.Threaded = .init(t.allocator, .{ .concurrent_limit = @enumFromInt(1) });
    defer threaded.deinit();
    const io = threaded.io();

    try t.expectError(error.ConcurrencyUnavailable, fetch(io, .{
        .url = "http://127.0.0.1:1/never-dialed",
        .deadline_ns = 100 * std.time.ns_per_ms,
        .what = "half-spawnable",
    }));
}

test "a URL that would inject request headers is refused before any dial" {
    // std.Uri.parse ACCEPTS every one of these and hands the path back
    // verbatim, so without an explicit check `fetch` would write the CRLF
    // straight into the request line and let whoever chose the URL append
    // headers to zurl's request. std.http.Client has the same hole today
    // (docs/RESEARCH.md), which is why this is a test and not a comment.
    //
    // Port 1 on loopback: if any of these ever DID reach the dial, the test
    // would fail on ConnectFailed rather than passing by accident.
    var threaded: Io.Threaded = .init(t.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const poisoned = [_][]const u8{
        "http://127.0.0.1:1/a\r\nX-Injected: 1",
        "http://127.0.0.1:1/a\nX-Injected: 1",
        "http://127.0.0.1:1/a b",
        "http://127.0.0.1:1/a\x00b",
        "http://127.0.0.1:1/a?q=1\r\nX: 2",
    };

    for (poisoned) |url| {
        try t.expectError(error.InvalidUrl, fetch(io, .{
            .url = url,
            .deadline_ns = 100 * std.time.ns_per_ms,
            .what = "poisoned url",
        }));
    }
}

test "response headers and trailers reach the caller through fetch" {
    // The motivating case end to end: a 429 whose `retry-after` says how long
    // to wait. `Response` is {status, body_len}, so before this no response
    // header was observable from `fetch` at all and a caller had to guess its
    // backoff — which is what the benchmark's Discord poster still does.
    var threaded: Io.Threaded = .init(t.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const addr = try net.IpAddress.parse("127.0.0.1", 0);
    var server = try addr.listen(io, .{ .reuse_address = true });
    defer server.deinit(io);
    const port = server.socket.address.getPort();

    // Chunked, so the trailer section is exercised: trailers arrive on the
    // SAME callback, which is the thing a caller can mis-attribute.
    const response = "HTTP/1.1 429 Too Many Requests\r\n" ++
        "retry-after:   7   \r\n" ++
        "x-ratelimit-remaining: 0\r\n" ++
        "transfer-encoding: chunked\r\n\r\n" ++
        "2\r\nhi\r\n0\r\nx-trailer: late\r\n\r\n";

    var group: Io.Group = .init;
    defer group.cancel(io);
    try group.concurrent(io, serveOnce, .{ &server, io, response });

    var url_buf: [64]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/x", .{port});

    var log: HeaderLog = .{};
    var body: Io.Writer.Allocating = .init(t.allocator);
    defer body.deinit();
    const res = (try fetch(io, .{
        .url = url,
        .sink = .{ .collect = &body },
        .on_header = HeaderLog.onHeader,
        .ctx = &log,
    })).?;

    try t.expectEqual(@as(u16, 429), res.status);
    try t.expectEqualStrings("hi", body.written());
    // Trimmed, so a caller never re-implements OWS handling.
    try t.expectEqual(@as(?u32, 7), log.retry_after);
    // Order preserved, and the trailer arrives on the same channel, last.
    try t.expectEqualStrings(
        "retry-after=7;x-ratelimit-remaining=0;transfer-encoding=chunked;x-trailer=late;",
        log.buf[0..log.len],
    );
}

test "max_head_bytes is the caller's, and refuses a head that outgrows it" {
    // The bound travels with `on_header` because they are one decision: the
    // caller who reads headers off a chatty API is the one who may need it
    // raised. A budget below the head must refuse rather than truncate
    // (rule 7) — and it must be the BUDGET that refuses, so the head here is
    // far smaller than the transport's read buffer.
    var threaded: Io.Threaded = .init(t.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const addr = try net.IpAddress.parse("127.0.0.1", 0);
    var server = try addr.listen(io, .{ .reuse_address = true });
    defer server.deinit(io);
    const port = server.socket.address.getPort();

    const response = "HTTP/1.1 200 OK\r\ncontent-length: 2\r\nx-pad: " ++ @as([200]u8, @splat('p')) ++ "\r\n\r\nhi";

    var group: Io.Group = .init;
    defer group.cancel(io);
    try group.concurrent(io, serveOnce, .{ &server, io, response });

    var url_buf: [64]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/x", .{port});

    try t.expectError(error.HeadTooLong, fetch(io, .{
        .url = url,
        .max_head_bytes = 64,
    }));
}

/// Serve `count` sequential connections, one canned response each.
fn serveSeq(srv: *net.Server, sio: Io, responses: []const []const u8, seen: *[4][256]u8, seen_len: *usize) void {
    for (responses) |response| {
        var s = srv.accept(sio) catch return;
        defer s.close(sio);

        var rb: [2048]u8 = undefined;
        var rr = s.reader(sio, &rb);
        var w: Io.Writer = .fixed(&seen[seen_len.*]);
        // lint:unbounded-ok — the client sends a finite head; a peer that
        // never sends the blank line fails the read and returns.
        while (true) {
            const line = rr.interface.takeDelimiterInclusive('\n') catch return;
            if (line.len <= 2) break;
            w.writeAll(line) catch {};
        }
        seen_len.* += 1;

        var wb: [512]u8 = undefined;
        var ww = s.writer(sio, &wb);
        ww.interface.writeAll(response) catch return;
        ww.interface.flush() catch return;
    }
}

test "a 3xx is the answer unless following was asked for" {
    // The default, and the whole reason it is the default: std.http.Client
    // follows silently, so a caller swapping to zurl would otherwise inherit
    // a behaviour it had never seen. Off means the 302 is visible.
    var threaded: Io.Threaded = .init(t.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const addr = try net.IpAddress.parse("127.0.0.1", 0);
    var server = try addr.listen(io, .{ .reuse_address = true });
    defer server.deinit(io);
    const port = server.socket.address.getPort();

    const responses = [_][]const u8{
        "HTTP/1.1 302 Found\r\nlocation: /moved\r\ncontent-length: 4\r\n\r\nnope",
    };
    var seen: [4][256]u8 = undefined;
    var seen_len: usize = 0;

    var group: Io.Group = .init;
    defer group.cancel(io);
    try group.concurrent(io, serveSeq, .{ &server, io, responses[0..], &seen, &seen_len });

    var url_buf: [64]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/start", .{port});

    var body: Io.Writer.Allocating = .init(t.allocator);
    defer body.deinit();
    const res = (try fetch(io, .{ .url = url, .sink = .{ .collect = &body } })).?;

    try t.expectEqual(@as(u16, 302), res.status);
    // Not following means the 3xx body IS the answer and is delivered.
    try t.expectEqualStrings("nope", body.written());
    try t.expectEqual(@as(usize, 1), seen_len);
}

test "a followed redirect rewrites the method, drops the body, and delivers only the last body" {
    var threaded: Io.Threaded = .init(t.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const addr = try net.IpAddress.parse("127.0.0.1", 0);
    var server = try addr.listen(io, .{ .reuse_address = true });
    defer server.deinit(io);
    const port = server.socket.address.getPort();

    const responses = [_][]const u8{
        // 303 says GET the other thing, so the POST body must not be resent.
        "HTTP/1.1 303 See Other\r\nlocation: /final\r\ncontent-length: 7\r\n\r\nignored",
        "HTTP/1.1 200 OK\r\ncontent-length: 5\r\n\r\nfinal",
    };
    var seen: [4][256]u8 = undefined;
    var seen_len: usize = 0;

    var group: Io.Group = .init;
    defer group.cancel(io);
    try group.concurrent(io, serveSeq, .{ &server, io, responses[0..], &seen, &seen_len });

    var url_buf: [64]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/start", .{port});

    var hop_buf: [2048]u8 = undefined;
    var body: Io.Writer.Allocating = .init(t.allocator);
    defer body.deinit();
    const res = (try fetch(io, .{
        .url = url,
        .method = .POST,
        .body = .{ .bytes = "payload" },
        .content_type = "text/plain",
        .sink = .{ .collect = &body },
        .redirects = .{ .max = 3, .buf = &hop_buf },
    })).?;

    try t.expectEqual(@as(u16, 200), res.status);
    // Only the FINAL body reaches the sink. The 303's body was never read.
    try t.expectEqualStrings("final", body.written());
    try t.expectEqual(@as(usize, 2), seen_len);

    const first = seen[0][0..];
    const second = seen[1][0..];
    try t.expect(std.mem.startsWith(u8, first, "POST /start "));
    // 303 rewrote it, and a GET carries no content-length.
    try t.expect(std.mem.startsWith(u8, second, "GET /final "));
    try t.expect(std.mem.indexOf(u8, second, "content-length") == null);
}

test "authorization follows the origin it was issued for, and nowhere else" {
    // THE security property of following redirects. `ycs` carries a live IAM
    // bearer token, so an origin that answers 302 with a location pointing
    // somewhere else must not be handed that token — otherwise a redirect is
    // a credential-exfiltration primitive: point one at your own server and
    // collect whatever the caller was using.
    //
    // Two listeners on 127.0.0.1 with different ports are two different
    // origins by RFC 6454, which is exactly the rule being tested.
    var threaded: Io.Threaded = .init(t.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const addr = try net.IpAddress.parse("127.0.0.1", 0);
    var origin_a = try addr.listen(io, .{ .reuse_address = true });
    defer origin_a.deinit(io);
    var origin_b = try addr.listen(io, .{ .reuse_address = true });
    defer origin_b.deinit(io);
    const port_a = origin_a.socket.address.getPort();
    const port_b = origin_b.socket.address.getPort();

    // A sends a same-origin hop first (relative location, so the credential
    // must survive), then a cross-origin hop to B (where it must not).
    var to_b_buf: [128]u8 = undefined;
    const to_b = try std.fmt.bufPrint(
        &to_b_buf,
        "HTTP/1.1 302 Found\r\nlocation: http://127.0.0.1:{d}/b\r\ncontent-length: 0\r\n\r\n",
        .{port_b},
    );
    const a_responses = [_][]const u8{
        "HTTP/1.1 302 Found\r\nlocation: /same\r\ncontent-length: 0\r\n\r\n",
        to_b,
    };
    const b_responses = [_][]const u8{"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok"};

    var seen_a: [4][256]u8 = undefined;
    var seen_a_len: usize = 0;
    var seen_b: [4][256]u8 = undefined;
    var seen_b_len: usize = 0;

    var group: Io.Group = .init;
    defer group.cancel(io);
    try group.concurrent(io, serveSeq, .{ &origin_a, io, a_responses[0..], &seen_a, &seen_a_len });
    try group.concurrent(io, serveSeq, .{ &origin_b, io, b_responses[0..], &seen_b, &seen_b_len });

    var url_buf: [64]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/start", .{port_a});

    var hop_buf: [2048]u8 = undefined;
    const res = (try fetch(io, .{
        .url = url,
        .authorization = "Bearer secret-iam-token",
        .redirects = .{ .max = 3, .buf = &hop_buf },
    })).?;

    try t.expectEqual(@as(u16, 200), res.status);
    try t.expectEqual(@as(usize, 2), seen_a_len);
    try t.expectEqual(@as(usize, 1), seen_b_len);

    // Same origin: the credential is still there on the second request to A.
    try t.expect(std.mem.indexOf(u8, seen_a[0][0..], "secret-iam-token") != null);
    try t.expect(std.mem.indexOf(u8, seen_a[1][0..], "secret-iam-token") != null);
    // Cross origin: B never sees it.
    try t.expect(std.mem.indexOf(u8, seen_b[0][0..], "secret-iam-token") == null);
    try t.expect(std.mem.indexOf(u8, seen_b[0][0..], "authorization") == null);
}

test "a chain that will not terminate is bounded, and says which bound it hit" {
    var threaded: Io.Threaded = .init(t.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const addr = try net.IpAddress.parse("127.0.0.1", 0);
    var server = try addr.listen(io, .{ .reuse_address = true });
    defer server.deinit(io);
    const port = server.socket.address.getPort();

    // Always redirects, never arrives.
    const loop = "HTTP/1.1 302 Found\r\nlocation: /again\r\ncontent-length: 0\r\n\r\n";
    const responses = [_][]const u8{ loop, loop, loop, loop };
    var seen: [4][256]u8 = undefined;
    var seen_len: usize = 0;

    var group: Io.Group = .init;
    defer group.cancel(io);
    try group.concurrent(io, serveSeq, .{ &server, io, responses[0..], &seen, &seen_len });

    var url_buf: [64]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/start", .{port});

    // max = 2 means three requests total, and the third 302 is the answer
    // rather than an error: the caller asked for two hops and got two.
    var hop_buf: [2048]u8 = undefined;
    const res = (try fetch(io, .{
        .url = url,
        .redirects = .{ .max = 2, .buf = &hop_buf },
    })).?;
    try t.expectEqual(@as(u16, 302), res.status);
    try t.expectEqual(@as(usize, 3), seen_len);
}

test "a 3xx with no usable location is an error, not a silent stop" {
    var threaded: Io.Threaded = .init(t.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const addr = try net.IpAddress.parse("127.0.0.1", 0);
    var server = try addr.listen(io, .{ .reuse_address = true });
    defer server.deinit(io);
    const port = server.socket.address.getPort();

    // A 302 promising a location and not giving one. Following was asked for,
    // so silently returning the 3xx would look like "the server answered 302"
    // when what happened is "zurl could not do what you asked".
    const responses = [_][]const u8{"HTTP/1.1 302 Found\r\ncontent-length: 0\r\n\r\n"};
    var seen: [4][256]u8 = undefined;
    var seen_len: usize = 0;

    var group: Io.Group = .init;
    defer group.cancel(io);
    try group.concurrent(io, serveSeq, .{ &server, io, responses[0..], &seen, &seen_len });

    var url_buf: [64]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/start", .{port});

    var hop_buf: [2048]u8 = undefined;
    try t.expectError(error.InvalidRedirect, fetch(io, .{
        .url = url,
        .redirects = .{ .max = 3, .buf = &hop_buf },
    }));
}

test "a redirected HEAD stays a HEAD" {
    // 303 means "GET the other thing", but a HEAD is already a retrieval and
    // rewriting it changes WHAT is fetched, not how it is framed: a caller
    // probing for existence would silently start pulling bodies. curl
    // preserves it and so does this. `ycs.head` is a live caller.
    var threaded: Io.Threaded = .init(t.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const addr = try net.IpAddress.parse("127.0.0.1", 0);
    var server = try addr.listen(io, .{ .reuse_address = true });
    defer server.deinit(io);
    const port = server.socket.address.getPort();

    const responses = [_][]const u8{
        "HTTP/1.1 303 See Other\r\nlocation: /final\r\ncontent-length: 0\r\n\r\n",
        // A HEAD reply advertises the length its GET would have had, and
        // carries no body — which is also why the fetch must not hang here.
        "HTTP/1.1 200 OK\r\ncontent-length: 512\r\n\r\n",
    };
    var seen: [4][256]u8 = undefined;
    var seen_len: usize = 0;

    var group: Io.Group = .init;
    defer group.cancel(io);
    try group.concurrent(io, serveSeq, .{ &server, io, responses[0..], &seen, &seen_len });

    var url_buf: [64]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/start", .{port});

    var hop_buf: [2048]u8 = undefined;
    const res = (try fetch(io, .{
        .url = url,
        .method = .HEAD,
        .redirects = .{ .max = 2, .buf = &hop_buf },
    })).?;

    try t.expectEqual(@as(u16, 200), res.status);
    try t.expectEqual(@as(u64, 0), res.body_len);
    try t.expectEqual(@as(usize, 2), seen_len);
    try t.expect(std.mem.startsWith(u8, seen[0][0..], "HEAD /start "));
    try t.expect(std.mem.startsWith(u8, seen[1][0..], "HEAD /final "));
}

test "302 rewrites only POST; DELETE keeps its method and body" {
    // The historical POST->GET deviation is narrower than it is usually
    // described. RFC 9110 §15.4.2/§15.4.3 permit changing POST to GET and
    // nothing else, and curl rewrites only POST. Rewriting a DELETE would
    // turn "delete this" into "fetch this" and then report success, which is
    // the worst shape a redirect bug can take.
    var threaded: Io.Threaded = .init(t.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const addr = try net.IpAddress.parse("127.0.0.1", 0);
    var server = try addr.listen(io, .{ .reuse_address = true });
    defer server.deinit(io);
    const port = server.socket.address.getPort();

    const responses = [_][]const u8{
        "HTTP/1.1 302 Found\r\nlocation: /moved\r\ncontent-length: 0\r\n\r\n",
        "HTTP/1.1 200 OK\r\ncontent-length: 4\r\n\r\ngone",
    };
    var seen: [4][256]u8 = undefined;
    var seen_len: usize = 0;

    var group: Io.Group = .init;
    defer group.cancel(io);
    try group.concurrent(io, serveSeq, .{ &server, io, responses[0..], &seen, &seen_len });

    var url_buf: [64]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/thing", .{port});

    var hop_buf: [2048]u8 = undefined;
    const res = (try fetch(io, .{
        .url = url,
        .method = .DELETE,
        .body = .{ .bytes = "why" },
        .redirects = .{ .max = 2, .buf = &hop_buf },
    })).?;

    try t.expectEqual(@as(u16, 200), res.status);
    try t.expectEqual(@as(usize, 2), seen_len);
    try t.expect(std.mem.startsWith(u8, seen[0][0..], "DELETE /thing "));
    // Method preserved, and so is the body it was carrying.
    try t.expect(std.mem.startsWith(u8, seen[1][0..], "DELETE /moved "));
    try t.expect(std.mem.indexOf(u8, seen[1][0..], "content-length: 3") != null);
}

test "a redirect that would replay a streamed body is refused, not sent empty" {
    // 307 says "same body" outright. A 302 on a PUT keeps it too, because the
    // historical rewrite is POST-only — so both reach the same refusal, and
    // testing only the obvious one would leave the other to a reader's faith.
    for ([_]u16{ 307, 302 }) |status| try streamReplayRefused(status);
}

fn streamReplayRefused(status: u16) !void {
    // 307 means "same method, same body", and a stream has none left to give.
    // Sending the request anyway would PUT an empty object and report 200 —
    // the origin cannot tell it was not what the caller meant, and neither
    // could the caller.
    var threaded: Io.Threaded = .init(t.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const addr = try net.IpAddress.parse("127.0.0.1", 0);
    var server = try addr.listen(io, .{ .reuse_address = true });
    defer server.deinit(io);
    const port = server.socket.address.getPort();

    const redirect = if (status == 307)
        "HTTP/1.1 307 Temporary Redirect\r\nlocation: /elsewhere\r\ncontent-length: 0\r\n\r\n"
    else
        "HTTP/1.1 302 Found\r\nlocation: /elsewhere\r\ncontent-length: 0\r\n\r\n";
    const responses = [_][]const u8{ redirect, "HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok" };
    var seen: [4][256]u8 = undefined;
    var seen_len: usize = 0;

    var group: Io.Group = .init;
    defer group.cancel(io);
    try group.concurrent(io, serveSeq, .{ &server, io, responses[0..], &seen, &seen_len });

    var url_buf: [64]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/object", .{port});

    var payload: Io.Reader = .fixed("artifact bytes");
    var hop_buf: [2048]u8 = undefined;
    try t.expectError(error.BodyNotReplayable, fetch(io, .{
        .url = url,
        .method = .PUT,
        .body = .{ .stream = .{ .source = &payload, .len = 14 } },
        .redirects = .{ .max = 2, .buf = &hop_buf },
    }));

    // The first hop really was sent — this is a refusal to CONTINUE, not a
    // refusal to start, so the caller knows the origin saw the upload.
    try t.expectEqual(@as(usize, 1), seen_len);
    try t.expect(std.mem.startsWith(u8, seen[0][0..], "PUT /object "));
}

test "a 303 after a streamed body is fine, because it drops the body anyway" {
    // The complement: refusing every redirect after a stream would be too
    // strict. A 303 rewrites to GET and carries no body, so there is nothing
    // to replay and nothing to refuse.
    var threaded: Io.Threaded = .init(t.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const addr = try net.IpAddress.parse("127.0.0.1", 0);
    var server = try addr.listen(io, .{ .reuse_address = true });
    defer server.deinit(io);
    const port = server.socket.address.getPort();

    const responses = [_][]const u8{
        "HTTP/1.1 303 See Other\r\nlocation: /receipt\r\ncontent-length: 0\r\n\r\n",
        "HTTP/1.1 200 OK\r\ncontent-length: 7\r\n\r\nreceipt",
    };
    var seen: [4][256]u8 = undefined;
    var seen_len: usize = 0;

    var group: Io.Group = .init;
    defer group.cancel(io);
    try group.concurrent(io, serveSeq, .{ &server, io, responses[0..], &seen, &seen_len });

    var url_buf: [64]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/upload", .{port});

    var payload: Io.Reader = .fixed("artifact bytes");
    var hop_buf: [2048]u8 = undefined;
    var body: Io.Writer.Allocating = .init(t.allocator);
    defer body.deinit();
    const res = (try fetch(io, .{
        .url = url,
        .method = .POST,
        .body = .{ .stream = .{ .source = &payload, .len = 14 } },
        .sink = .{ .collect = &body },
        .redirects = .{ .max = 2, .buf = &hop_buf },
    })).?;

    try t.expectEqual(@as(u16, 200), res.status);
    try t.expectEqualStrings("receipt", body.written());
    try t.expect(std.mem.startsWith(u8, seen[0][0..], "POST /upload "));
    try t.expect(std.mem.startsWith(u8, seen[1][0..], "GET /receipt "));
}
