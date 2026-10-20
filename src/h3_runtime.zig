//! Application-side wiring for the experimental HTTP/3 listeners.
//!
//! The library module exports the h3 stack as `zgix.http.h3`; this file is
//! what turns a resolved `config.h3_listeners` entry into a bound UDP
//! listener plus its buffered plaintext origin proxy. It lives beside
//! `main` rather than in `Server` because the QUIC path uses its own
//! transport (OpenSSL QUIC-TLS + zquic) and does not consume the §5 conn
//! slot or upstream slot pools. What it shares with the proxy is the Io
//! loop — `global_io.run()` drives TCP and UDP together — and the process
//! counter set and access log: `Runtime.init` borrows `Server.counters`
//! and `Server.access_log`, so every h3 witness lands in the same
//! exposition and exit tally as the HTTP/1.1 counters, and an h3 request
//! earns one access-log line when the config names a sink — all with
//! `Server` itself holding no h3 knowledge.
//!
//! Limits this slice is honest about:
//!
//! - One certificate identity per process (the config loader refuses two).
//! - A route table of host+path-prefix routes per listener — the same
//!   §7 table the HTTP/1.1 listener builds, minus the dimensions this
//!   slice refuses at load: no header predicates, no per-route
//!   `access_log` suppression, and no filters.
//! - Streaming replies: each response body is relayed to the client as it
//!   arrives from the origin (chunked bodies decoded incrementally), with
//!   `max_response_bytes` as a per-body cap enforced mid-stream; each
//!   upstream leg answers `timeouts.h3_exchange_ms` (absent is the 10 s
//!   default, `0` disables the deadline), absolute across the streamed
//!   read, so large bodies want it raised.
//! - Access-log lines name no configured headers yet: the #140
//!   named-header capture is a TCP-path table the h3 exchange does not
//!   build, so both directions ride empty — the rendering a config that
//!   names no headers already produces.

const std = @import("std");

const assert = std.debug.assert;

const zgix = @import("zgix");

const h3 = zgix.http.h3;
const constants = zgix.constants;

const XevIo = zgix.Io.XevIo;

const AccessLogXev = zgix.access_log.AccessLog(XevIo);

/// Everything one listener's witness hook needs on the h3 side of the
/// seam: the process counter set (always — the counters ride the same
/// hook), the access log the answer is logged to (null where the config
/// names no sink), and the cluster names the line reports. One per
/// listener: the names are parallel to the seam cluster table the
/// proxy's `details.cluster_index` indexes.
const Witness = struct {
    counters: *zgix.counters.Counters,
    io: *XevIo,
    log: ?*AccessLogXev,
    /// Parallel to the listener's seam cluster table: the configured
    /// name of the cluster a request routed to, indexed by
    /// `details.cluster_index`.
    cluster_names: []const []const u8,
    /// The canonicalized host scratch for the line currently being
    /// built. The hook runs on the loop thread, one call at a time, and
    /// `record` reads the slice out before returning, so one buffer per
    /// listener is exactly enough.
    host_buf: [constants.host_bytes_max]u8 = undefined,
    /// The per-listener halves of the global `h3_requests` /
    /// `h3_responses` counters, accumulated here because the hook runs
    /// per listener already and the admin's listener-status section
    /// reads them at scrape time. The failure verdicts stay global-only:
    /// five per-listener families would price a table the scrape does
    /// not need.
    count_requests: u64 = 0,
    count_responses: u64 = 0,
};

/// The seam's witness hook: one untyped entry point so the h3 seam
/// compiles without the counters or access-log modules (`zig build
/// h3-check`), one switch here so an event a counter name forgot is a
/// compile error, not a silent zero. The event-to-counter half is the
/// `KernelPressureOp.counter()` precedent; the answer-event half builds
/// the access-log line the request owes, or skips straight past when no
/// sink is configured — log off emits nothing, like every other path
/// that shares this log.
fn noteCounter(
    ctx: *anyopaque,
    event: h3.proxy.Counters.Event,
    details: ?*const h3.proxy.Details,
) void {
    const witness: *Witness = @ptrCast(@alignCast(ctx));
    switch (event) {
        .request => {
            witness.count_requests += 1;
            witness.counters.increment("h3_requests");
        },
        .response => {
            witness.count_responses += 1;
            witness.counters.increment("h3_responses");
        },
        .bad_gateway => witness.counters.increment("h3_bad_gateway"),
        .gateway_timeout => witness.counters.increment("h3_gateway_timeout"),
        .shed_busy => witness.counters.increment("h3_shed_busy"),
        .no_route => witness.counters.increment("h3_no_route"),
        .connection_opened => witness.counters.increment("h3_connections"),
        .connection_closed => witness.counters.increment("h3_connections_closed"),
    }
    const facts = details orelse return;
    // The matched route opted out of the log line: counters above are
    // already counted — suppression reaches only the Record, the L7
    // `access_log off` at a location ("suppresses only the line, not
    // counters, metrics or admission").
    if (facts.suppress_log) return;
    const log = witness.log orelse return;
    const entry = buildRecord(witness, event, facts, XevIo.nowNs(witness.io));
    log.record(&entry);
}

/// The seam's one mapping from an answer event to the line it owes.
/// `now_ns` is injected so the Record stays a pure function of what the
/// proxy witnessed — a unit test drives it without a loop. The one
/// side effect is the witness's host scratch, which the returned
/// Record's `host` slice points at for the duration of the render.
fn buildRecord(
    witness: *Witness,
    event: h3.proxy.Counters.Event,
    details: *const h3.proxy.Details,
    now_ns: u64,
) zgix.access_log.Record {
    // The event, not the status, picks the outcome: an origin's own 503
    // rides `.response` and stays `ok`; only zgix's shed is `shed`, and
    // telling those two apart is most of what the outcome field is for.
    const outcome: zgix.access_log.Outcome = switch (event) {
        .response => .ok,
        .bad_gateway => .upstream_failed,
        .gateway_timeout => .timed_out,
        .shed_busy => .shed,
        // The `l7_no_route` sibling: the TCP path files its unroutable
        // 404 under `.rejected` (http/proxy.zig's counter→outcome map),
        // and the h3 line answers to the same outcome so a grep for
        // refusals sees both protocols' no-route traffic together.
        .no_route => .rejected,
        else => unreachable, // connection events and `.request` carry no details
    };
    return .{
        .kind = .http,
        .outcome = outcome,
        .started_wall_ns = details.started_wall_ns,
        .duration_ns = now_ns - details.started_mono_ns,
        .client = details.peer,
        .upstream = if (details.endpoint) |endpoint| .{ .ip = endpoint } else null,
        .cluster = witness.cluster_names[details.cluster_index],
        .bytes_in = details.bytes_in,
        .bytes_out = details.bytes_out,
        .method = details.method,
        .host = canonicalAuthority(details.authority, &witness.host_buf),
        .path = details.path,
        .status = details.status,
    };
}

/// The access log's host: the request's `:authority`, lowercased with
/// any port stripped — the canonical routing host a `Record` doc demands.
/// `http.parser.canonicalHost` folds Host headers this way on the TCP
/// path; the h3 seam cannot import it (the seam builds standalone under
/// `h3-check`), so the fold lives here for the log line and again in
/// `h3/proxy.zig` for route matching, and every copy must stay in step.
/// An empty or oversize authority logs as "", the spelling "the request
/// carried none" wears on the TCP path too.
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

/// The PEM bytes `main` read during startup, one entry per h3 listener.
pub const Credential = struct {
    cert_pem: []const u8,
    key_pem: []const u8,
};

/// The seam-side route table for one listener: the `h3.proxy.Route`
/// rules plus the dense cluster set they select and the configured
/// names parallel to that set — the witness's table. The config table
/// references clusters by config index; this one is dense over the
/// referenced set, first reference winning the dense index, so a
/// cluster named by several routes dials through one shared cursor.
const SeamTable = struct {
    routes: []const h3.proxy.Route,
    clusters: []h3.proxy.Cluster,
    cluster_names: []const []const u8,
};

/// The seam-side TLS shape of one cluster's `tls` block, built from the
/// loaded runtime `main` produced with `ClusterTls.load` — the same
/// anchors, name and mTLS identity the TCP path's engine acquire hands
/// zssl, so one config block cannot verify one origin two ways. Null
/// config block yields null: a plaintext cluster stays plaintext. The
/// runtime is borrowed from the startup slice (never copied): the trust
/// store and client credentials the returned config points at live in
/// it for the process's life.
fn seamClusterTls(
    tls: ?zgix.config.Config.Cluster.Tls,
    runtime: ?*const zgix.tls.ClusterTls.Runtime,
) !?h3.proxy.Tls {
    const config = tls orelse return null;
    const loaded = runtime orelse return error.H3ClusterTlsMissing;
    assert(std.mem.eql(u8, config.server_name, loaded.server_name));
    return .{
        .server_name = loaded.server_name,
        .trust = if (loaded.trust) |*store| store else null,
        .client_credentials = if (loaded.client_credentials) |*credentials|
            &credentials.inner
        else
            null,
    };
}

/// Build one listener's seam table at startup. The scratch tables are
/// sized by the route count (a cluster count bound the routes
/// themselves give); the returned slices cover the used prefix.
fn buildSeamTable(
    arena: std.mem.Allocator,
    clusters: []const zgix.config.Config.Cluster,
    cluster_tls: []const ?zgix.tls.ClusterTls.Runtime,
    listener_routes: []const zgix.http.router.Route,
) !SeamTable {
    const route_count = listener_routes.len;
    const seam_routes = try arena.alloc(h3.proxy.Route, route_count);
    const seam_clusters = try arena.alloc(h3.proxy.Cluster, route_count);
    const cluster_names = try arena.alloc([]const u8, route_count);
    const cluster_refs = try arena.alloc(u16, route_count);
    var cluster_count: usize = 0;
    for (listener_routes, 0..) |route, index| {
        const known = for (cluster_refs[0..cluster_count], 0..) |ref, at| {
            if (ref == route.cluster_index) break at;
        } else null;
        const dense = known orelse blk: {
            const cluster = clusters[route.cluster_index];
            const endpoints = try arena.alloc(std.Io.net.IpAddress, cluster.endpoints.len);
            for (cluster.endpoints, endpoints) |endpoint, *address| {
                address.* = switch (endpoint) {
                    .ip => |ip| ip,
                    // The config loader refuses these; the switch keeps
                    // that verdict local if a hand-built Config slips by.
                    .unix => return error.H3UnixEndpoint,
                };
            }
            const runtime: ?*const zgix.tls.ClusterTls.Runtime =
                if (route.cluster_index < cluster_tls.len)
                    if (cluster_tls[route.cluster_index]) |*loaded| loaded else null
                else
                    null;
            seam_clusters[cluster_count] = .{
                .endpoints = endpoints,
                .tls = try seamClusterTls(cluster.tls, runtime),
            };
            cluster_refs[cluster_count] = route.cluster_index;
            cluster_names[cluster_count] = cluster.name;
            cluster_count += 1;
            break :blk cluster_count - 1;
        };
        seam_routes[index] = .{
            .host = route.host,
            .prefix = route.prefix,
            // The #302 predicate rides the seam's two-field shape:
            // `equals` non-null is the value match, null the presence
            // kind — `resolveRouteHeader` is the single producer of
            // both shapes, so the lowering cannot drift from
            // `router.headerMatches`'s semantics.
            .header = if (route.header) |match| .{
                .name = match.name,
                // `resolveRouteHeader` produces only the present/equals
                // kinds — a route's `contains` spelling is refused at
                // load — so the seam's two-field shape cannot drift.
                .equals = switch (match.kind) {
                    .equals => match.value,
                    .present => null,
                    .contains => unreachable,
                },
            } else null,
            .cluster_index = @intCast(dense),
            .access_log = route.access_log,
        };
    }
    return .{
        .routes = seam_routes,
        .clusters = seam_clusters[0..cluster_count],
        .cluster_names = cluster_names[0..cluster_count],
    };
}

pub const Runtime = struct {
    const exchanges = @as(usize, constants.h3_exchanges);

    pub const Binding = struct {
        listener: h3.listener.Listener(XevIo) = undefined,
        proxy: h3.proxy.Proxy(XevIo, exchanges) = undefined,
    };

    bindings: []Binding,
    /// Parallel to `bindings`: the per-listener witness each binding's
    /// counters hook writes through, kept here so the admin's
    /// listener-status section can read the cumulative halves at scrape
    /// time.
    witnesses: []Witness = &.{},
    started: bool = false,

    /// Bind every configured UDP socket and install its proxy handler.
    /// `credentials` is parallel to `config.h3_listeners` and was read by
    /// `main` before this point, so a missing file has already failed the
    /// start (and `--check`). `cluster_tls` is the per-cluster loaded
    /// upstream-TLS state `main` built with `ClusterTls.load`, indexed by
    /// config cluster; it is where a cluster's `tls` block — verify
    /// policy, CA bundle, SNI name, mTLS identity — becomes the seam's
    /// dial config, identical to what the TCP path's engine acquire
    /// reads. `counters` is the process counter set the proxies and
    /// listeners witness into — `Server.counters`, shared with the
    /// HTTP/1.1 path; null where the caller has none (every witness
    /// no-ops). `access_log` is the process access log, also borrowed
    /// from `Server`; null when the config names no sink, and then every
    /// hook call is counters alone.
    pub fn init(
        arena: std.mem.Allocator,
        io: *XevIo,
        config: *const zgix.config.Config,
        credentials: []const Credential,
        cluster_tls: []const ?zgix.tls.ClusterTls.Runtime,
        counters: ?*zgix.counters.Counters,
        access_log: ?*AccessLogXev,
    ) !Runtime {
        if (config.h3_listeners.len != credentials.len) return error.H3CredentialCountMismatch;
        if (config.h3_listeners.len == 0) return .{ .bindings = &.{} };

        const bindings = try arena.alloc(Binding, config.h3_listeners.len);
        // One witness per listener: the hook's context carries the
        // cluster names this listener's lines report.
        const witnesses = try arena.alloc(Witness, config.h3_listeners.len);
        // The exchange deadline is the config's cap translated into the
        // proxy's nanoseconds; `0` means the operator switched the
        // deadline off, which the proxy already spells the same way.
        const exchange_timeout_ns: u64 = if (config.h3_exchange_ms == 0)
            0
        else
            @as(u64, config.h3_exchange_ms) * std.time.ns_per_ms;
        for (config.h3_listeners, credentials, bindings, witnesses) |listener_config, credential, *binding, *witness| {
            const table = try buildSeamTable(
                arena,
                config.clusters,
                cluster_tls,
                listener_config.routes,
            );
            const counters_hook: ?h3.proxy.Counters = if (counters) |set| hook: {
                witness.* = .{
                    .counters = set,
                    .io = io,
                    .log = access_log,
                    .cluster_names = table.cluster_names,
                };
                break :hook .{ .ctx = witness, .note = noteCounter };
            } else null;

            try binding.listener.initInPlace(
                io,
                arena,
                listener_config.bind_address,
                .{
                    .cert_pem = credential.cert_pem,
                    .key_pem = credential.key_pem,
                },
                listener_config.max_connections,
            );
            const idle_timeout_ns: u64 = if (config.h3_exchange_idle_ms == 0)
                0
            else
                @as(u64, config.h3_exchange_idle_ms) * std.time.ns_per_ms;
            try binding.proxy.initInPlaceRouted(io, arena, table.routes, table.clusters, .{
                .max_response_bytes = listener_config.max_response_bytes,
                .counters = counters_hook,
                .timeout_ns = exchange_timeout_ns,
                .idle_timeout_ns = idle_timeout_ns,
                // The listener's configured pages: config-arena slices
                // for the process's life, the same lifetime the L7
                // static-response table enjoys.
                .error_pages = .{
                    .no_route = listener_config.error_pages.no_route,
                    .bad_gateway = listener_config.error_pages.bad_gateway,
                    .gateway_timeout = listener_config.error_pages.gateway_timeout,
                },
            });
            binding.listener.setRequestHandler(binding.proxy.handler());
            binding.listener.setExchangeTeardown(binding.proxy.sessionTeardown());
            binding.listener.setCounters(counters_hook);
            // Backpressure closure: a short sendData parks an exchange's
            // tail; the listener's window notify (or tick) is what
            // drains it again.
            binding.listener.setWindowNotify(binding.proxy.windowNotify());
        }
        return .{ .bindings = bindings, .witnesses = witnesses };
    }

    /// The admin scrape's h3 listener-status section: one row per
    /// listener per family — live sessions, cumulative requests,
    /// cumulative relayed responses, and the parked keep-alive pool —
    /// rendered in Prometheus text beside the global `h3_*` counters,
    /// which stay the totals these rows partition. The bind label is an
    /// address literal, which cannot carry a quote or backslash, so no
    /// escaping walks this path. Returns the bytes written.
    pub fn renderListenerStatus(runtime: *const Runtime, buffer: []u8) usize {
        if (runtime.bindings.len == 0) return 0;
        var writer: std.Io.Writer = .fixed(buffer);
        writeStatus(&writer, runtime);
        return writer.end;
    }

    /// `renderListenerStatus` behind the untyped shape the admin hook
    /// carries, so `main` names no cast.
    pub fn statusAppend(ctx_ptr: *anyopaque, buffer: []u8) usize {
        const runtime: *const Runtime = @ptrCast(@alignCast(ctx_ptr));
        return renderListenerStatus(runtime, buffer);
    }

    fn writeStatus(writer: *std.Io.Writer, runtime: *const Runtime) void {
        // The fixed writer's buffer is the admin response's tail, sized
        // by `admin.h3_listener_status_bytes_max`; every row is bounded
        // by construction (one bind render at most 64 bytes — the worst
        // address literal is a bracketed v6 with port — and one u64's
        // widest rendering), so a NoSpaceLeft here is a bug in the
        // bound, and the unreachable says so.
        writer.writeAll(
            "# TYPE zgix_h3_listener_connections gauge\n" ++
                "# TYPE zgix_h3_listener_requests counter\n" ++
                "# TYPE zgix_h3_listener_responses counter\n" ++
                "# TYPE zgix_h3_listener_parked gauge\n",
        ) catch unreachable;
        for (runtime.bindings, runtime.witnesses) |*binding, *witness| {
            var bind_buf: [64]u8 = undefined;
            const bind = std.fmt.bufPrint(&bind_buf, "{f}", .{
                binding.listener.boundAddress(),
            }) catch unreachable;
            writer.print(
                "zgix_h3_listener_connections{{bind=\"{s}\"}} {d}\n",
                .{ bind, binding.listener.connectionCount() },
            ) catch unreachable;
            writer.print(
                "zgix_h3_listener_requests{{bind=\"{s}\"}} {d}\n",
                .{ bind, witness.count_requests },
            ) catch unreachable;
            writer.print(
                "zgix_h3_listener_responses{{bind=\"{s}\"}} {d}\n",
                .{ bind, witness.count_responses },
            ) catch unreachable;
            writer.print(
                "zgix_h3_listener_parked{{bind=\"{s}\"}} {d}\n",
                .{ bind, binding.proxy.parkedCount() },
            ) catch unreachable;
        }
    }

    pub fn start(runtime: *Runtime) void {
        if (runtime.started) return;
        runtime.started = true;
        for (runtime.bindings) |*binding| binding.listener.start();
    }

    pub fn stop(runtime: *Runtime) void {
        for (runtime.bindings) |*binding| binding.listener.stop();
    }

    pub fn listenerCount(runtime: *const Runtime) usize {
        return runtime.bindings.len;
    }

    /// The bound address of listener `index`, for the startup banner. UDP
    /// port 0 is rejected by the loader, so the echo is informational.
    pub fn boundAddress(runtime: *const Runtime, index: usize) std.Io.net.IpAddress {
        return runtime.bindings[index].listener.boundAddress();
    }
};

// ---------------------------------------------------------------------------
// Tests: the Record an answer event builds, without standing up a loop or
// a Server. `buildRecord` is a pure function of the witnessed facts; the
// render is `access_log.renderLine` itself, so the assertions read the
// same bytes the sink would receive.
// ---------------------------------------------------------------------------

const testing = std.testing;

fn testWitness() Witness {
    return .{
        // `buildRecord` never touches the counters or the log; the types
        // only have to exist.
        .counters = undefined,
        .io = undefined,
        .log = null,
        .cluster_names = &.{ "origin", "backup" },
    };
}

fn testDetails() h3.proxy.Details {
    var details: h3.proxy.Details = .{};
    details.method = "GET";
    details.path = "/items";
    details.authority = "Origin.Test:8443";
    details.peer = std.Io.net.IpAddress.parseLiteral("192.0.2.1:5001") catch unreachable;
    details.endpoint = std.Io.net.IpAddress.parseLiteral("192.0.2.2:8080") catch unreachable;
    details.started_wall_ns = 1_785_489_262 * std.time.ns_per_s;
    details.started_mono_ns = 40_000 * std.time.ns_per_us;
    details.bytes_in = 4;
    details.status = 200;
    details.bytes_out = 4096;
    return details;
}

test "h3 runtime: a relayed answer builds one http record, payload bytes and all" {
    var witness = testWitness();
    const details = testDetails();
    const entry = buildRecord(&witness, .response, &details, details.started_mono_ns + 2_500);

    try testing.expectEqual(zgix.access_log.Kind.http, entry.kind);
    try testing.expectEqual(zgix.access_log.Outcome.ok, entry.outcome);
    try testing.expectEqual(details.started_wall_ns, entry.started_wall_ns);
    try testing.expectEqual(@as(u64, 2_500), entry.duration_ns);
    try testing.expectEqual(details.peer, entry.client.?);
    try testing.expectEqual(details.endpoint.?, entry.upstream.?.ip);
    // cluster_index 0 names the first referenced cluster.
    try testing.expectEqualStrings("origin", entry.cluster);
    try testing.expectEqual(@as(u64, 4), entry.bytes_in);
    try testing.expectEqual(@as(u64, 4096), entry.bytes_out);
    try testing.expectEqualStrings("GET", entry.method);
    // The host is canonical: lowercased, port stripped.
    try testing.expectEqualStrings("origin.test", entry.host);
    try testing.expectEqualStrings("/items", entry.path);
    try testing.expectEqual(@as(u16, 200), entry.status);
    // The named-header capture slice is not implemented for h3: both
    // directions ride empty, exactly like a config that names no headers.
    try testing.expectEqual(@as(usize, 0), entry.request_headers.len());
    try testing.expectEqual(@as(usize, 0), entry.response_headers.len());

    var buffer: [constants.access_log_line_bytes_max]u8 = undefined;
    const line = try zgix.access_log.renderLine(&entry, &buffer);
    try testing.expect(std.mem.indexOf(u8, line, "\"kind\":\"http\"") != null);
    try testing.expect(std.mem.indexOf(u8, line, "\"outcome\":\"ok\"") != null);
    try testing.expect(std.mem.indexOf(u8, line, "\"method\":\"GET\"") != null);
    try testing.expect(std.mem.indexOf(u8, line, "\"host\":\"origin.test\"") != null);
    try testing.expect(std.mem.indexOf(u8, line, "\"path\":\"/items\"") != null);
    try testing.expect(std.mem.indexOf(u8, line, "\"status\":200") != null);
    try testing.expect(std.mem.indexOf(u8, line, "\"cluster\":\"origin\"") != null);
    try testing.expect(std.mem.indexOf(u8, line, "\"duration_us\":2") != null);
    // The header-capture objects stay absent, not empty.
    try testing.expect(std.mem.indexOf(u8, line, "request_headers") == null);
    try testing.expect(std.mem.indexOf(u8, line, "response_headers") == null);
}

test "h3 runtime: the line names the cluster the route selected" {
    var witness = testWitness();
    var details = testDetails();
    // The seam's dense cluster index, not the config's: witness tables
    // are parallel to the proxy's cluster table, and the line reports
    // whichever cluster the matched route dialed.
    details.cluster_index = 1;
    const entry = buildRecord(&witness, .response, &details, details.started_mono_ns);
    try testing.expectEqualStrings("backup", entry.cluster);
    details.cluster_index = 0;
    const first = buildRecord(&witness, .response, &details, details.started_mono_ns);
    try testing.expectEqualStrings("origin", first.cluster);
}

test "h3 runtime: each failure verdict maps to its outcome" {
    var witness = testWitness();

    var details = testDetails();
    details.status = 502;
    const bad_gateway = buildRecord(&witness, .bad_gateway, &details, details.started_mono_ns);
    try testing.expectEqual(zgix.access_log.Outcome.upstream_failed, bad_gateway.outcome);
    try testing.expectEqual(@as(u16, 502), bad_gateway.status);

    details.status = 504;
    const gateway_timeout = buildRecord(&witness, .gateway_timeout, &details, details.started_mono_ns);
    try testing.expectEqual(zgix.access_log.Outcome.timed_out, gateway_timeout.outcome);
    try testing.expectEqual(@as(u16, 504), gateway_timeout.status);

    // A shed never picked an endpoint, and its 503 is zgix's own answer —
    // the outcome must not read as the origin's.
    details.status = 503;
    details.endpoint = null;
    const shed = buildRecord(&witness, .shed_busy, &details, details.started_mono_ns);
    try testing.expectEqual(zgix.access_log.Outcome.shed, shed.outcome);
    try testing.expectEqual(@as(u16, 503), shed.status);
    try testing.expect(shed.upstream == null);
}

test "h3 runtime: the host is the canonical authority" {
    var witness = testWitness();
    const buffer = &witness.host_buf;

    try testing.expectEqualStrings(
        "origin.test",
        canonicalAuthority("Origin.TEST:8443", buffer),
    );
    try testing.expectEqualStrings(
        "origin.test",
        canonicalAuthority("origin.test", buffer),
    );
    // A bracketed IPv6 literal keeps its brackets; the port still strips.
    try testing.expectEqualStrings(
        "[2001:db8::1]",
        canonicalAuthority("[2001:DB8::1]:443", buffer),
    );
    // None, port-only, and oversize authorities log as "the request
    // carried none" — the TCP path's empty-host spelling.
    try testing.expectEqualStrings("", canonicalAuthority("", buffer));
    try testing.expectEqualStrings("", canonicalAuthority(":443", buffer));
    const oversize: [constants.host_bytes_max + 1]u8 = @splat('a');
    try testing.expectEqualStrings("", canonicalAuthority(&oversize, buffer));
}
