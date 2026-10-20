//! The startup budget (DESIGN.md §5, §8): the closed form that prices
//! every pool this process holds for its life, the fd and ring demands
//! the *effective* config makes, and the banner that prints both.
//!
//! It lives beside `Server` rather than inside `main` because it is the
//! one part of startup an embedder (§13) cannot reasonably rewrite: the
//! closed form has to price exactly what `Server.init` reserves, and a
//! second derivation that drifted would break §5's promise — that the
//! printed total covers everything this process holds — while still
//! looking correct. `main.zig` keeps what is genuinely the application's:
//! reading files, raising `RLIMIT_NOFILE`, installing signal handlers.
//!
//! Generic over the Io backend for the same reason `Server` is: a conn
//! slot's size and an upstream slot's size are properties of the backend,
//! so the closed form cannot be stated without one.

const std = @import("std");

const config_module = @import("config.zig");
const constants = @import("constants.zig");
const Io = @import("io/io.zig");
const rate_limit = @import("rate_limit.zig");
const conn_limit = @import("conn_limit.zig");
const compress_module = @import("http/compress.zig");
const RelayBuffer = @import("net/relay.zig").RelayBuffer;
const Server = @import("Server.zig").Server;
const TlsEngine = @import("tls/Engine.zig");
const upstream_module = @import("net/upstream.zig");

const assert = std.debug.assert;

pub fn Budget(comptime IoType: type) type {
    Io.assertIoInterface(IoType);

    return struct {
        const ServerType = Server(IoType);
        const UpstreamType = upstream_module.UpstreamPool(IoType).Upstream;

        /// What the effective config demands of the process before a
        /// single connection is admitted (§8): both are pre-budgeted
        /// rather than shed, so both are known here and neither is ever
        /// a ladder rung.
        pub const Demands = struct {
            /// Listeners + conn slots + upstream slots + the ring, async
            /// and signal fds, asserted against `RLIMIT_NOFILE` by
            /// whoever can raise it.
            fds: u32,
            /// The depth the ring must be *created* with, so the
            /// worst-case in-flight ops stay within the configured fill
            /// (§4). Not the SQ, which is `constants.ring_entries`.
            cq_entries: u32,
        };

        /// What the banner's first line stamps. The name on it is zgix's
        /// either way — what follows is the budget of zgix's pools, and
        /// `bench/run.zig` parses these lines from outside the process —
        /// so an embedder names itself on a line of its own rather than
        /// through this.
        pub const Build = struct {
            version: []const u8,
            /// `main`'s `git describe` suffix, or empty where the build
            /// cannot say what it is. Printed verbatim, separator
            /// included.
            id_suffix: []const u8 = "",
        };

        /// The §5/§8 demands of the *effective* config, not the compiled
        /// ceilings — a lean deployment neither demands the c10k
        /// `RLIMIT_NOFILE` nor asks the kernel for a 65536-deep ring.
        pub fn demandsFor(config: *const config_module.Config) Demands {
            assert(config.listeners.len >= 1);
            const listeners_count: u32 = @intCast(config.listeners.len);
            const access_log_files: u32 = if (config.access_log_sink) |sink|
                @intFromBool(sink == .file)
            else
                0;
            // The prober's effective probe count (§7, #132): a config
            // with no `check` block anywhere reserves the one probe's
            // worth it always did, so this term moves nothing for a
            // deployment that did not ask for health checks.
            const health_probes = config.healthProbes();
            // Each h3 listener owns one UDP socket, its fixed exchange
            // pool owns one upstream TCP socket per slot, and its
            // keep-alive pool may park one upstream socket per endpoint
            // (`h3_parked_per_listener_max`, the fd-bound the pool is
            // capped at). QUIC sessions are outside `conn_slots`, so
            // these fds would otherwise be demanded by nobody and
            // refused by the kernel at runtime.
            const h3_sockets: u32 = if (config.h3_listeners.len == 0)
                0
            else
                @as(u32, @intCast(config.h3_listeners.len)) *
                    (1 + constants.h3_exchanges + constants.h3_parked_per_listener_max);
            const demands: Demands = .{
                .fds = constants.fdsRequired(
                    config.limits.conn_slots,
                    config.limits.upstream_slots,
                    listeners_count,
                    access_log_files,
                    health_probes,
                    h3_sockets,
                ),
                .cq_entries = constants.completionQueueDepthFor(
                    config.limits.conn_slots,
                    config.limits.upstream_slots,
                    listeners_count,
                    health_probes,
                    config.limits.cq_fill_eighths,
                ),
            };
            // The effective config never exceeds the compiled ceilings
            // (§8): the pools, the ring and the fd demand all fit what
            // the constants proved. A demand of zero would mean a proxy
            // that reserved nothing — the closed form broke.
            assert(demands.cq_entries <= constants.completion_queue_entries);
            assert(demands.fds > 0);
            return demands;
        }

        /// The §5 pool-size vector for the effective config: every term
        /// the closed form takes, sourced from the limit or `@sizeOf`
        /// that owns it.
        pub fn poolSizesFor(config: *const config_module.Config) constants.PoolSizes {
            const limits = config.limits;
            // The head-sized side buffers (§5): Server owns the closed
            // form and asserts its own allocations against it, so
            // pricing it here cannot drift from what init reserves.
            const head_scratch_bytes = ServerType.headScratchBytes(limits, config.healthProbes());
            assert(head_scratch_bytes >= limits.head_buffer_bytes);
            assert(limits.conn_slots >= 1);
            // The four upstream TLS engine terms (shared pool and h3
            // pool): zero unless a cluster dials TLS on their own terms,
            // priced here rather than in constants.zig because only this
            // side sees the parsed config.
            const tls_terms = upstreamTlsTerms(config, limits);
            // A TLS origin's first plaintext can carry the response head
            // and body bytes together, and a later drive step can yield a
            // whole record plus a small one. Both destinations — the
            // upstream head pool and the relay halves — are priced at a
            // wire record when any cluster dials TLS, which is the width
            // `Config`'s own accessors reserve. The plaintext path has no
            // such coupling: one read cannot deliver more than its buffer.
            const upstream_head_bytes = config.effectiveUpstreamHeadBufferBytes();
            const relay_buffer_bytes = config.effectiveRelayBufferBytes();
            // The h3 pool counts: per-listener session slots, the fixed
            // exchange pool and the endpoint-bounded keep-alive pool —
            // the closed forms the listener and proxy size their arrays
            // from, so the printed total and the reservations move
            // together. Zero together with an h3-free config.
            const h3_terms = h3PoolTerms(config);
            return .{
                .conn_slots = limits.conn_slots,
                .conn_bytes = @sizeOf(ServerType.ConnType),
                // One stream per connection (#274), derived from the
                // same limit `Server.init` sizes the pool from, so the
                // printed number and the reserved one cannot disagree.
                .stream_slots = constants.streamSlotsFor(limits.conn_slots),
                .stream_bytes = @sizeOf(ServerType.StreamType),
                .relay_buffers = limits.relay_buffers,
                // The pool element (free-list header and the two slab
                // slices) plus both halves it points at, the same shape
                // `upstream_head_buffer_bytes` below uses.
                .relay_buffer_pair_bytes = @sizeOf(RelayBuffer) +
                    2 * @as(u64, relay_buffer_bytes),
                .upstream_slots = limits.upstream_slots,
                .upstream_bytes = @sizeOf(UpstreamType),
                .access_log_bytes = constants.accessLogBytes(limits.access_log_buffer_bytes),
                .log_header_bytes = ServerType.logHeaderBytes(config, constants.streamSlotsFor(limits.conn_slots)),
                .endpoint_table_bytes = ServerType.endpointTableBytes(config),
                .metrics_bytes = ServerType.metricsBytes(config),
                .head_buffers = limits.head_buffers,
                .head_buffer_bytes = limits.head_buffer_bytes,
                .upstream_head_buffers = limits.upstream_head_buffers,
                // The pool element (the free-list header and the slab
                // slice) plus its share of the slab itself.
                .upstream_head_buffer_bytes = @sizeOf(upstream_module.HeadBuffer) +
                    upstream_head_bytes,
                .head_scratch_bytes = head_scratch_bytes,
                // Zero unless a listener allows an upgrade, on the same
                // terms as the TLS terms below: a feature nobody asked
                // for costs nothing. Same element as a shared relay
                // buffer, reserved apart from it (§5) — the point of the
                // pool, not an accident of it.
                .tunnels = limits.tunnels,
                .tunnel_buffer_pair_bytes = if (limits.tunnels == 0)
                    0
                else
                    @sizeOf(RelayBuffer) + 2 * @as(u64, relay_buffer_bytes),
                // Zero unless a listener configures a rate limit, on the
                // same terms as the TLS and tunnel terms: a feature
                // nobody asked for costs nothing. The unit is the real
                // entry type, so a table that changes shape changes the
                // printed number without anyone remembering to.
                .rate_limit_entries = limits.rate_limit_entries,
                .rate_limit_entry_bytes = if (limits.rate_limit_entries == 0)
                    0
                else
                    @sizeOf(rate_limit.Entry),
                // The per-client connection table, priced on the same
                // all-or-nothing terms.
                .conn_limit_entries = limits.conn_limit_entries,
                .conn_limit_entry_bytes = if (limits.conn_limit_entries == 0)
                    0
                else
                    @sizeOf(conn_limit.Entry),
                // One shared gzip state, reserved only when a listener
                // opted in. Priced at the real type so growing its
                // buffers moves the printed number.
                .compress_bytes = if (config.hasCompression())
                    @sizeOf(compress_module.Compressor)
                else
                    0,
                // Zero unless a listener terminates TLS, which is what
                // makes the whole feature free to a deployment that did
                // not ask for it. The three terms move together:
                // `limits.tls_engines` is zero exactly when no listener
                // has a `tls` block.
                .tls_engines = limits.tls_engines,
                .tls_engine_bytes = if (limits.tls_engines == 0) 0 else @sizeOf(TlsEngine),
                .tls_plaintext_bytes = if (limits.tls_engines == 0)
                    0
                else
                    TlsEngine.plaintextBytesFor(limits.head_buffer_bytes),
                // The whole compiled reservation, not this config's
                // share of it: the storage is one static array sized at
                // `tls_engines_max` (it must outlive the arena — see
                // `main.zig`'s `libcrypto_heap_storage`), so that is what
                // the process holds for its life whatever `tls_engines`
                // says, and §5 prices what is held.
                .libcrypto_heap_bytes = if (limits.tls_engines == 0)
                    0
                else
                    constants.libcrypto_heap_bytes,
                // Both upstream TLS engine pools ride the helper: zero
                // without a TLS-dialing cluster on their own terms, the
                // compiled bound per engine otherwise.
                .upstream_tls_engines = tls_terms.upstream_tls_engines,
                .upstream_tls_engine_bytes = tls_terms.upstream_tls_engine_bytes,
                .h3_upstream_tls_engines = tls_terms.h3_upstream_tls_engines,
                .h3_upstream_tls_engine_bytes = tls_terms.h3_upstream_tls_engine_bytes,
                .h3_sessions = h3_terms.sessions,
                .h3_exchanges = h3_terms.exchanges,
                .h3_parked = h3_terms.parked,
            };
        }

        /// Everything this process holds for its life, in bytes.
        ///
        /// The config arena is a term because it is never freed, and it
        /// is the one term *measured* rather than derived: there is no
        /// constant bounding a config file's size, so what the operator
        /// writes is what it costs and the only honest thing the budget
        /// can do is report it (§5).
        pub fn totalBytes(
            config: *const config_module.Config,
            config_arena_bytes: u64,
        ) u64 {
            const sizes = poolSizesFor(config);
            return totalBytesFor(&sizes, config_arena_bytes);
        }

        /// The same total for a caller that already holds the vector —
        /// the banner does, and deriving it twice would price one config
        /// through two evaluations of a form that must have exactly one.
        pub fn totalBytesFor(
            sizes: *const constants.PoolSizes,
            config_arena_bytes: u64,
        ) u64 {
            const total = constants.memoryBytesTotal(sizes) + config_arena_bytes;
            // A total of zero would be a proxy that reserved nothing.
            assert(total > 0);
            assert(total >= config_arena_bytes);
            return total;
        }

        /// Where a banner goes.
        ///
        /// Two sinks rather than two renderings: `--check` (#301) prints
        /// the same budget to stdout, and a second copy of these format
        /// strings would be a second thing to keep in step with the
        /// closed form. The union is what lets one body serve both.
        pub const Sink = union(enum) {
            /// **stderr**, through `std.debug.print`: the banner is
            /// diagnostics, and stdout belongs to the data an operator
            /// may point there — the access log's `stdout` sink must
            /// stay one uncontaminated JSON line per event. Stderr is
            /// where the counter dump already goes, and via the same
            /// plain-write path, so the two interleave whole-lines even
            /// when both land in one redirected file (a positional
            /// writer here would be silently overwritten by the dump's
            /// shared-offset writes).
            diagnostics,
            /// A writer the caller owns and flushes. This is the arm a
            /// check run takes, where the banner is not diagnostics
            /// printed beside a result — it *is* the result.
            writer: *std.Io.Writer,
        };

        /// One chunk of banner to whichever sink. The `.diagnostics` arm
        /// cannot fail (`std.debug.print` ignores its own write errors),
        /// so every error this returns belongs to the caller's writer.
        fn emit(
            sink: Sink,
            comptime format: []const u8,
            args: anytype,
        ) std.Io.Writer.Error!void {
            switch (sink) {
                .diagnostics => std.debug.print(format, args),
                .writer => |writer| try writer.print(format, args),
            }
        }

        /// The §5 banner, to stderr — `Sink.diagnostics` carries why
        /// that and not stdout.
        pub fn print(
            config: *const config_module.Config,
            demands: Demands,
            /// What the config text and its parsed structures took from
            /// the startup arena, measured (§5).
            config_arena_bytes: u64,
            build: Build,
        ) void {
            // `unreachable` rather than `catch {}`: `emit`'s
            // `.diagnostics` arm never calls `try`, so this error does
            // not exist — and stating that is what makes a future
            // fallible diagnostics path fail loudly instead of writing
            // half a banner and saying nothing.
            emitBanner(.diagnostics, config, demands, config_arena_bytes, build) catch unreachable;
        }

        /// The same banner to a writer the caller owns and flushes —
        /// `--check`'s stdout (#301). One body, so a check run and the
        /// start it predicts can never price one config two ways.
        pub fn printTo(
            writer: *std.Io.Writer,
            config: *const config_module.Config,
            demands: Demands,
            config_arena_bytes: u64,
            build: Build,
        ) std.Io.Writer.Error!void {
            return emitBanner(.{ .writer = writer }, config, demands, config_arena_bytes, build);
        }

        /// The banner itself, once, for whichever sink asked. Both
        /// public entry points land here, which is the property that
        /// matters: the startup banner and the `--check` report are the
        /// same closed form evaluated once, not two renderings that
        /// happen to agree today.
        fn emitBanner(
            sink: Sink,
            config: *const config_module.Config,
            demands: Demands,
            config_arena_bytes: u64,
            build: Build,
        ) std.Io.Writer.Error!void {
            assert(config.listeners.len >= 1);
            assert(demands.fds > 0);
            // Every budget reflects the *effective* config (§5, §8): the
            // config may shrink the pools, the fd demand and the
            // requested ring below the compiled ceilings, and all three
            // are shown as actually sized.
            const limits = config.limits;
            const in_flight = constants.inFlightOps(
                limits.conn_slots,
                limits.upstream_slots,
                @intCast(config.listeners.len),
                config.healthProbes(),
            );
            const access_log_bytes = constants.accessLogBytes(limits.access_log_buffer_bytes);
            const sizes = poolSizesFor(config);
            // The h3 line reads the same terms the memory total is built
            // from, so the detail line and the closed form cannot drift
            // apart — one source, two renderings.
            const h3_session_kib =
                @as(u64, sizes.h3_sessions) * constants.h3_session_slot_bytes / 1024;
            const h3_exchange_kib =
                @as(u64, sizes.h3_exchanges) * constants.h3_exchange_slot_bytes / 1024;
            const h3_parked_bytes =
                @as(u64, sizes.h3_parked) * constants.h3_parked_slot_bytes;
            const h3_tls_engine_kib =
                @as(u64, sizes.h3_upstream_tls_engines) * sizes.h3_upstream_tls_engine_bytes / 1024;
            const memory_total = totalBytesFor(&sizes, config_arena_bytes);
            try emitMemoryBanner(sink, config, &sizes, memory_total, access_log_bytes, build);
            try emitH3MemoryTerms(sink, &sizes);
            // A stack temporary in a function that runs once at startup,
            // not a reservation (§5).
            var fact_buffer: [failure_detection_fact_bytes]u8 = undefined;
            try emit(sink,
                \\  memory  config arena {d} KiB (measured, not closed-form)
                \\  compress  {d} B (one shared gzip state, when a listener enables compress)
                \\  h3      {d} listener(s): {d} session slot(s) ({d} KiB), {d} exchange slot(s) ({d} KiB), {d} parked slot(s) ({d} B), upstream tls engines {d} ({d} KiB, when a routed cluster sets tls)
                \\  fds     {d} required (asserted against RLIMIT_NOFILE)
                \\  ring    {d} entries, completion queue {d}, in-flight ops <= {d}
                \\  config  {d} listener(s), {d} cluster(s), {d} error page(s), access log {s}{s}
                \\
            , .{
                config_arena_bytes / 1024,
                sizes.compress_bytes,
                config.h3_listeners.len,
                sizes.h3_sessions,
                h3_session_kib,
                sizes.h3_exchanges,
                h3_exchange_kib,
                sizes.h3_parked,
                h3_parked_bytes,
                sizes.h3_upstream_tls_engines,
                h3_tls_engine_kib,
                demands.fds,
                constants.ring_entries,
                demands.cq_entries,
                in_flight,
                config.listeners.len,
                config.clusters.len,
                // Their rendered bytes live in the config arena term
                // above — read and pre-rendered at load (#159), so the
                // measured number already covers them; this count is
                // what says why it grew.
                config.error_pages.len,
                if (config.access_log_sink) |log_sink| @tagName(log_sink) else "off",
                failureDetectionFact(config, &fact_buffer),
            });
        }

        /// The rendering `failure_detection_fact_bytes` is the width of.
        /// One literal, used by the format below *and* by the buffer that
        /// holds it, so a reworded fact cannot silently outgrow its
        /// buffer — the two used to agree only by a copied string.
        const failure_detection_fact_format = ", {d} cluster(s) without failure detection";

        /// The widest that fact can render: the literal with a `u32` at
        /// full width in place of `{d}`.
        const failure_detection_fact_bytes =
            failure_detection_fact_format.len - "{d}".len +
            std.fmt.count("{d}", .{std.math.maxInt(u32)});

        /// The §7 failure-detection fact (#230), appended to the config
        /// line: how many clusters could lose an endpoint and never
        /// notice.
        ///
        /// Empty when there are none, which is deliberately unlike the
        /// tunnel and TLS terms above — those print their zeros to say
        /// "you are not paying for this", where a *pool* at zero is a
        /// standing fact about the deployment. This is not a pool; it is
        /// a count of a gap, and a gap that does not exist has nothing to
        /// report rather than a zero worth reading.
        ///
        /// This is the whole visibility answer #230 asked for, and it is
        /// deliberately not a warning. The banner is what a bug report
        /// pastes, so "why did traffic keep going to a dead backend?"
        /// becomes answerable without a round trip; a warning on a valid
        /// config would decay into noise and take the rest of stderr with
        /// it. §8's own line for the same idea: the budget is printed,
        /// not hoped for.
        fn failureDetectionFact(
            config: *const config_module.Config,
            buffer: []u8,
        ) []const u8 {
            // The claim the `catch unreachable` below rests on, checked
            // rather than argued: this buffer is the one `print` sized.
            assert(buffer.len == failure_detection_fact_bytes);
            const count = config.clustersWithoutFailureDetection();
            if (count == 0) return "";
            const rendered = std.fmt.bufPrint(
                buffer,
                failure_detection_fact_format,
                .{count},
            ) catch unreachable; // The assert above covers every u32.
            assert(rendered.len <= failure_detection_fact_bytes);
            return rendered;
        }

        /// The banner's version and memory lines — the §5 closed form
        /// itemized. Split from `emitBanner` for the length limit; the
        /// two emissions are sequential same-thread writes to one sink,
        /// so nothing interleaves.
        /// The h3 terms continue the memory block: sessions and exchanges
        /// are per-listener pools outside the conn-slot count, so they
        /// price here rather than inside it. A separate emit because the
        /// main block's format call sits at Zig's 32-argument ceiling —
        /// same style, one continuation, and the same `sizes` the total
        /// was built from.
        fn emitH3MemoryTerms(sink: Sink, sizes: *const constants.PoolSizes) std.Io.Writer.Error!void {
            try emit(sink,
                \\          + h3 sessions {d} x {d} B + h3 exchanges {d} x {d} B (per h3 listener, outside conn slots)
                \\          + h3 parked {d} x {d} B + h3 upstream tls engines {d} x {d} B (keep-alive slots; engines when a routed cluster sets tls)
                \\
            , .{
                sizes.h3_sessions,
                constants.h3_session_slot_bytes,
                sizes.h3_exchanges,
                constants.h3_exchange_slot_bytes,
                sizes.h3_parked,
                constants.h3_parked_slot_bytes,
                sizes.h3_upstream_tls_engines,
                sizes.h3_upstream_tls_engine_bytes,
            });
        }

        fn emitMemoryBanner(
            sink: Sink,
            config: *const config_module.Config,
            sizes: *const constants.PoolSizes,
            memory_total: u64,
            access_log_bytes: u64,
            build: Build,
        ) std.Io.Writer.Error!void {
            assert(memory_total > 0);
            assert(config.listeners.len >= 1);
            const limits = config.limits;
            // One rendered term rather than two arguments: the banner's
            // format call is at Zig's 32-argument ceiling, and the two
            // client-keyed tables are the newest pair.
            var client_tables_term_buffer: [96]u8 = undefined;
            const client_tables_term = renderClientTablesTerm(&client_tables_term_buffer, sizes);
            // The version leads, because this banner is what a bug
            // report pastes and `--version` is what it does not think to
            // run.
            try emit(sink,
                \\zgix {s}{s}
                \\budgets (DESIGN.md §5/§8; closed-form except where marked):
                \\  memory  total {d} KiB = conn slots {d} x {d} B + stream slots {d} x {d} B
                \\          + relay buffers {d} x {d} B
                \\          + upstream slots {d} x {d} B + head buffers {d} x {d} B (+ ring {d} B)
                \\          + upstream head buffers {d} x {d} B + head scratch {d} B
                \\          + access log {d} KiB (+ logged headers {d} B)
                \\          + endpoint tables {d} B ({d} cluster(s) x {d} wide)
                \\          + labeled metrics {d} B (tables, labels and render buffers)
                \\          + tunnels {d} x {d} B (their own relay buffers, never HTTP's)
                \\          + client tables {s} (rate-limit buckets; conn-limit counters)
                \\          + tls engines {d} x {d} B (+ plaintext {d} B each, libcrypto heap {d} KiB)
                \\          + upstream tls engines {d} x {d} B (one per upstream slot, when a cluster sets tls)
                \\
            , .{
                build.version,
                build.id_suffix,
                memory_total / 1024,
                limits.conn_slots,
                sizes.conn_bytes,
                sizes.stream_slots,
                sizes.stream_bytes,
                limits.relay_buffers,
                sizes.relay_buffer_pair_bytes,
                limits.upstream_slots,
                sizes.upstream_bytes,
                limits.head_buffers,
                // The +1 ownership byte stays out of the banner's
                // per-unit figure; the closed-form total above carries it.
                limits.head_buffer_bytes,
                constants.bufferGroupDescriptorBytes(limits.head_buffers),
                limits.upstream_head_buffers,
                sizes.upstream_head_buffer_bytes,
                sizes.head_scratch_bytes,
                access_log_bytes / 1024,
                sizes.log_header_bytes,
                sizes.endpoint_table_bytes,
                config.clusters.len,
                ServerType.endpointKeysFor(config).stride,
                sizes.metrics_bytes,
                // Both read zero unless a listener allows an upgrade —
                // printed rather than omitted, on the same terms as the
                // TLS line below.
                limits.tunnels,
                sizes.tunnel_buffer_pair_bytes,
                client_tables_term,
                // All four read zero on a plaintext deployment, which is
                // the line saying "you are not paying for this" rather
                // than omitting itself and leaving the reader to wonder.
                limits.tls_engines,
                sizes.tls_engine_bytes,
                sizes.tls_plaintext_bytes,
                sizes.libcrypto_heap_bytes / 1024,
                // Zero on a deployment that dials every origin in the
                // clear — printed rather than omitted on the same terms
                // as the line above.
                sizes.upstream_tls_engines,
                sizes.upstream_tls_engine_bytes,
            });
        }

        /// The two client-keyed tables' `N x M B` terms, pre-rendered so
        /// the banner's one format call stays inside Zig's argument limit.
        fn renderClientTablesTerm(buffer: []u8, sizes: *const constants.PoolSizes) []const u8 {
            return std.fmt.bufPrint(buffer, "rate-limit {d} x {d} B, conn-limit {d} x {d} B", .{
                sizes.rate_limit_entries,
                sizes.rate_limit_entry_bytes,
                sizes.conn_limit_entries,
                sizes.conn_limit_entry_bytes,
            }) catch unreachable;
        }
    };
}

/// How many clusters dial their origins over TLS — the one condition
/// that makes the upstream TLS engine pool nonzero. Bounded by the
/// config's cluster list, which the loader has already sized and
/// validated.
fn tlsUpstreamClusters(config: *const config_module.Config) u32 {
    var count: u32 = 0;
    for (config.clusters) |cluster| {
        if (cluster.tls != null) count += 1;
    }
    return count;
}

/// The four upstream TLS engine pool terms `poolSizesFor` carries: the
/// shared pool — one engine per upstream slot when any cluster dials TLS,
/// because any parked upstream may be a TLS one — and the h3 listeners'
/// pool — one per exchange slot plus one per parked slot, per listener
/// routing to a TLS-dialing cluster. Both zero-priced without their
/// condition; the unit is always the compiled bound.
const UpstreamTlsTerms = struct {
    upstream_tls_engines: u32,
    upstream_tls_engine_bytes: u64,
    h3_upstream_tls_engines: u32,
    h3_upstream_tls_engine_bytes: u64,
};

fn upstreamTlsTerms(
    config: *const config_module.Config,
    limits: config_module.Config.Limits,
) UpstreamTlsTerms {
    const shared: u32 = if (tlsUpstreamClusters(config) == 0) 0 else limits.upstream_slots;
    const h3 = h3UpstreamTlsEngines(config);
    return .{
        .upstream_tls_engines = shared,
        .upstream_tls_engine_bytes = if (shared == 0)
            0
        else
            constants.upstream_tls_engine_bytes_max,
        .h3_upstream_tls_engines = h3,
        .h3_upstream_tls_engine_bytes = if (h3 == 0)
            0
        else
            constants.upstream_tls_engine_bytes_max,
    };
}

/// How many upstream TLS engines the h3 listeners' proxies reserve — the
/// closed form `h3.proxy` sizes its engine pool from at init, so the
/// printed number and the reservation cannot drift. Per listener that
/// routes to a TLS-dialing cluster: one engine per exchange slot plus
/// one per parked slot the pool can hold (`constants.h3_exchanges` plus
/// the smaller of the referenced endpoint count and
/// `constants.h3_parked_per_listener_max`). The endpoint total dedups
/// the way the proxy's dense cluster table does — a cluster named by
/// several routes contributes its endpoints once. Zero where no h3
/// listener's route table selects a TLS cluster, on the same
/// all-or-nothing terms as the shared upstream pool.
fn h3UpstreamTlsEngines(config: *const config_module.Config) u32 {
    var engines: u32 = 0;
    for (config.h3_listeners) |listener| {
        var tls = false;
        var endpoint_total: u32 = 0;
        for (listener.routes, 0..) |route, at| {
            const cluster = config.clusters[route.cluster_index];
            tls = tls or cluster.tls != null;
            const first = for (listener.routes[0..at]) |prior| {
                if (prior.cluster_index == route.cluster_index) break false;
            } else true;
            if (first) endpoint_total += @intCast(cluster.endpoints.len);
        }
        if (tls) {
            engines += constants.h3_exchanges +
                @min(endpoint_total, constants.h3_parked_per_listener_max);
        }
    }
    return engines;
}

/// The routed endpoint count behind one h3 listener, with a route table's
/// clusters deduplicated (a cluster named by several routes contributes
/// its endpoints once) — the same total the proxy's dense cluster table
/// builds at init, so counts derived from it match the reservations.
fn h3RoutedEndpoints(
    config: *const config_module.Config,
    listener: config_module.Config.H3Listener,
) u32 {
    var endpoint_total: u32 = 0;
    for (listener.routes, 0..) |route, at| {
        const cluster = config.clusters[route.cluster_index];
        const first = for (listener.routes[0..at]) |prior| {
            if (prior.cluster_index == route.cluster_index) break false;
        } else true;
        if (first) endpoint_total += @intCast(cluster.endpoints.len);
    }
    return endpoint_total;
}

/// The §5 h3 pool counts, summed over `h3_listeners`: one session slot
/// per listener's `max_connections`, `constants.h3_exchanges` exchange
/// slots per listener, and a parked keep-alive slot per listener bounded
/// by the smaller of the routed endpoint count and
/// `constants.h3_parked_per_listener_max` — the closed forms the
/// listener and the proxy size their arrays from at init. Zero together
/// when the config names no h3 listener, on the all-or-nothing terms
/// `assertH3PoolTerms` checks.
fn h3PoolTerms(config: *const config_module.Config) struct { sessions: u32, exchanges: u32, parked: u32 } {
    var sessions: u32 = 0;
    var parked: u32 = 0;
    for (config.h3_listeners) |listener| {
        sessions += listener.max_connections;
        parked += @min(
            h3RoutedEndpoints(config, listener),
            constants.h3_parked_per_listener_max,
        );
    }
    return .{
        .sessions = sessions,
        .exchanges = @as(u32, @intCast(config.h3_listeners.len)) * constants.h3_exchanges,
        .parked = parked,
    };
}

const testing = std.testing;

test "demandsFor: the effective config sizes both demands, not the ceilings" {
    const SimIo = @import("io/SimIo.zig");
    const BudgetSim = Budget(SimIo);

    var arena_instance = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_instance.deinit();
    const config = try config_module.parse(arena_instance.allocator(), @embedFile("example_config"));

    const demands = BudgetSim.demandsFor(&config);
    // Both demands are the config's, so both must sit under what the
    // constants compiled — the assert `demandsFor` itself makes, restated
    // here against a config the loader actually accepted.
    try testing.expect(demands.cq_entries <= constants.completion_queue_entries);
    try testing.expect(demands.fds > config.limits.conn_slots);
    // A lean config must not demand the c10k ring: that is the whole
    // reason the depth is derived from the effective config (§4).
    try testing.expect(demands.cq_entries < constants.completion_queue_entries);
}

test "totalBytes: the measured arena joins the closed form" {
    const SimIo = @import("io/SimIo.zig");
    const BudgetSim = Budget(SimIo);

    var arena_instance = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_instance.deinit();
    const config = try config_module.parse(arena_instance.allocator(), @embedFile("example_config"));

    const pools_only = BudgetSim.totalBytes(&config, 0);
    const with_arena = BudgetSim.totalBytes(&config, 4096);
    // §5's promise is that the printed total covers everything held for
    // the process's life, the arena included — so the arena is a term,
    // not a rounding.
    try testing.expectEqual(pools_only + 4096, with_arena);
    try testing.expect(pools_only > 0);
}

/// One L4 cluster, plaintext — the shape the upstream TLS term must
/// price at zero.
const upstream_tls_plain_config =
    \\{"listeners":[{"bind":"127.0.0.1:1","http":{"cluster":"origin"}}],
    \\ "clusters":{"origin":{"endpoints":["127.0.0.1:2"]}},
    \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
;

/// The same config with the one cluster dialing TLS. `verify: false`
/// keeps the loader from requiring a CA file the test never reads —
/// nothing outside config parsing is reached here. An `http` listener is
/// required: `l4` refuses a TLS-dialing cluster because its relay never
/// originates TLS.
const upstream_tls_dialing_config =
    \\{"listeners":[{"bind":"127.0.0.1:1","http":{"cluster":"origin"}}],
    \\ "clusters":{"origin":{"endpoints":["127.0.0.1:2"],
    \\   "tls":{"server_name":"origin.example","verify":false}}},
    \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
;

test "poolSizesFor: no tls cluster reserves no upstream tls engines" {
    const SimIo = @import("io/SimIo.zig");
    const BudgetSim = Budget(SimIo);

    var arena_instance = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_instance.deinit();
    const config = try config_module.parse(arena_instance.allocator(), @embedFile("example_config"));

    const sizes = BudgetSim.poolSizesFor(&config);
    try testing.expectEqual(@as(u32, 0), sizes.upstream_tls_engines);
    try testing.expectEqual(@as(u64, 0), sizes.upstream_tls_engine_bytes);
}

test "poolSizesFor: one tls cluster sizes engines to upstream_slots" {
    const SimIo = @import("io/SimIo.zig");
    const BudgetSim = Budget(SimIo);

    var arena_instance = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_instance.deinit();
    const plain = try config_module.parse(arena_instance.allocator(), upstream_tls_plain_config);
    const dialing = try config_module.parse(arena_instance.allocator(), upstream_tls_dialing_config);

    const plain_sizes = BudgetSim.poolSizesFor(&plain);
    const dialing_sizes = BudgetSim.poolSizesFor(&dialing);
    try testing.expectEqual(@as(u32, 0), plain_sizes.upstream_tls_engines);
    // One TLS-dialing cluster is enough: the pool is shared, and any
    // parked upstream may be the one an encrypted dial takes.
    try testing.expectEqual(dialing.limits.upstream_slots, dialing_sizes.upstream_tls_engines);
    try testing.expectEqual(
        @as(u64, constants.upstream_tls_engine_bytes_max),
        dialing_sizes.upstream_tls_engine_bytes,
    );
    // The term separates the two totals: the configs differ only in the
    // cluster's `tls` block, so a reader of the banner can attribute the
    // difference to the pools and nothing else. Three pools widen: the
    // engine pool, and the two plaintext destinations a decrypt step can
    // overrun — the relay halves and the upstream head buffers.
    const widened_relay = @max(
        dialing.limits.relay_buffer_bytes,
        constants.tls_record_wire_bytes_max,
    );
    const widened_head = @max(
        dialing.limits.head_buffer_bytes,
        constants.tls_record_wire_bytes_max,
    );
    const relay_delta = @as(u64, dialing.limits.relay_buffers) * 2 *
        (widened_relay - dialing.limits.relay_buffer_bytes);
    const head_delta = @as(u64, dialing.limits.upstream_head_buffers) *
        (widened_head - dialing.limits.head_buffer_bytes);
    try testing.expectEqual(
        @as(u64, dialing.limits.upstream_slots) * constants.upstream_tls_engine_bytes_max +
            relay_delta + head_delta,
        BudgetSim.totalBytes(&dialing, 0) - BudgetSim.totalBytes(&plain, 0),
    );
}

/// One h3 listener routing at a TLS cluster — the shape upstream TLS
/// support made legal. `verify: false` keeps the loader from requiring a
/// CA file the parse never reads.
const h3_tls_dialing_config =
    \\{"listeners":[{"bind":"127.0.0.1:1","http":{"cluster":"plain"}}],
    \\ "clusters":{"plain":{"endpoints":["127.0.0.1:2"]},
    \\  "origin":{"endpoints":["127.0.0.1:3"],
    \\   "tls":{"server_name":"origin.example","verify":false}}},
    \\ "h3_listeners":[{"bind":"127.0.0.1:4443","cluster":"origin",
    \\   "tls":{"cert":"cert.pem","key":"key.pem"}}],
    \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
;

/// The same listener on the plaintext cluster: the h3 engine term must
/// price at zero, the shared-pool terms already do.
const h3_plain_config =
    \\{"listeners":[{"bind":"127.0.0.1:1","http":{"cluster":"plain"}}],
    \\ "clusters":{"plain":{"endpoints":["127.0.0.1:2"]},
    \\  "origin":{"endpoints":["127.0.0.1:3"],
    \\   "tls":{"server_name":"origin.example","verify":false}}},
    \\ "h3_listeners":[{"bind":"127.0.0.1:4443","cluster":"plain",
    \\   "tls":{"cert":"cert.pem","key":"key.pem"}}],
    \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
;

test "poolSizesFor: an h3 listener on a tls cluster reserves its engine pool" {
    const SimIo = @import("io/SimIo.zig");
    const BudgetSim = Budget(SimIo);

    var arena_instance = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_instance.deinit();
    const tls = try config_module.parse(arena_instance.allocator(), h3_tls_dialing_config);
    const plain = try config_module.parse(arena_instance.allocator(), h3_plain_config);

    const tls_sizes = BudgetSim.poolSizesFor(&tls);
    const plain_sizes = BudgetSim.poolSizesFor(&plain);
    // The closed form the h3 proxy's own pool init asserts against: one
    // engine per exchange slot plus one per parked slot, parked capacity
    // being the smaller of the endpoint count and the pool cap.
    try testing.expectEqual(
        @as(u32, constants.h3_exchanges + 1),
        tls_sizes.h3_upstream_tls_engines,
    );
    try testing.expectEqual(
        @as(u64, constants.upstream_tls_engine_bytes_max),
        tls_sizes.h3_upstream_tls_engine_bytes,
    );
    // The plaintext listener reserves none, and the printed total moves
    // by exactly the engine pool the TLS listener added.
    try testing.expectEqual(@as(u32, 0), plain_sizes.h3_upstream_tls_engines);
    try testing.expectEqual(@as(u64, 0), plain_sizes.h3_upstream_tls_engine_bytes);
    // The engine pool is what the delta isolates once the metrics terms
    // are taken out: the two configs differ only in the cluster their
    // h3 route names, and the inventory families' closed forms price a
    // config's real label bytes — the `route_info` row is one byte
    // longer for "origin" than "plain" (rendered three times over:
    // render bound, admin response, exit-dump staging) plus one in the
    // label table, which is §5 pricing reality, not engine pool.
    const engine_pool = @as(u64, tls_sizes.h3_upstream_tls_engines) *
        constants.upstream_tls_engine_bytes_max;
    const metrics_delta = tls_sizes.metrics_bytes - plain_sizes.metrics_bytes;
    try testing.expectEqual(
        engine_pool,
        BudgetSim.totalBytes(&tls, 0) - BudgetSim.totalBytes(&plain, 0) - metrics_delta,
    );
}

/// The shape without an h3 listener at all: the h3 pool terms are zero
/// together, on the all-or-nothing terms `assertH3PoolTerms` checks.
/// Cluster-identical to `h3_plain_config` — the origin cluster's TLS
/// block prices the *shared* upstream engine pool in both, so it cancels
/// in the delta and only the h3 listener's terms remain.
const no_h3_config =
    \\{"listeners":[{"bind":"127.0.0.1:1","http":{"cluster":"plain"}}],
    \\ "clusters":{"plain":{"endpoints":["127.0.0.1:2"]},
    \\  "origin":{"endpoints":["127.0.0.1:3"],
    \\   "tls":{"server_name":"origin.example","verify":false}}},
    \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
;

test "poolSizesFor: h3 sessions, exchanges and parked slots join the closed form" {
    const SimIo = @import("io/SimIo.zig");
    const BudgetSim = Budget(SimIo);

    var arena_instance = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_instance.deinit();
    const h3 = try config_module.parse(arena_instance.allocator(), h3_plain_config);
    const none = try config_module.parse(arena_instance.allocator(), no_h3_config);

    const h3_sizes = BudgetSim.poolSizesFor(&h3);
    const none_sizes = BudgetSim.poolSizesFor(&none);
    // One listener at the default connection ceiling, the fixed exchange
    // pool, and the endpoint-bounded keep-alive pool (one endpoint behind
    // the route table).
    try testing.expectEqual(
        @as(u32, constants.h3_connections_default),
        h3_sizes.h3_sessions,
    );
    try testing.expectEqual(@as(u32, constants.h3_exchanges), h3_sizes.h3_exchanges);
    try testing.expectEqual(@as(u32, 1), h3_sizes.h3_parked);
    try testing.expectEqual(@as(u32, 0), none_sizes.h3_sessions);
    try testing.expectEqual(@as(u32, 0), none_sizes.h3_exchanges);
    try testing.expectEqual(@as(u32, 0), none_sizes.h3_parked);
    // The printed total moves by exactly the three terms the h3 listener
    // added — the engines stay zero on a plaintext cluster. The metrics
    // terms move too: the inventory families price the h3 listener's
    // label bytes, which the config without one does not carry (§5
    // pricing the config's reality, the same adjustment the
    // cluster-named route makes in the engine-pool test above).
    const pool_terms = @as(u64, h3_sizes.h3_sessions) * constants.h3_session_slot_bytes +
        @as(u64, h3_sizes.h3_exchanges) * constants.h3_exchange_slot_bytes +
        @as(u64, h3_sizes.h3_parked) * constants.h3_parked_slot_bytes;
    const metrics_delta = h3_sizes.metrics_bytes - none_sizes.metrics_bytes;
    try testing.expectEqual(
        pool_terms,
        BudgetSim.totalBytes(&h3, 0) - BudgetSim.totalBytes(&none, 0) - metrics_delta,
    );
}
