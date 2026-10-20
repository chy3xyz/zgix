//! `zurl` — a curl-shaped front end for the library.
//!
//! Its real job is to be one half of a differential oracle: `zig build
//! curl-diff` sends the same request through curl and through this, and
//! requires the same answer. That is rule 4's discipline one level up — same
//! request, same answer, or one of them is wrong — and it is why the flag set
//! is chosen to make a comparison possible rather than to reimplement curl.
//!
//! **This binary allocates.** docs/SCOPE.md's scoping principle: zero
//! allocation binds `src/`, not an executable. Loading a trust store, holding
//! a response body and buffering a redirect chain all want memory, and doing
//! them here is what keeps the library austere. If this ever has to reach
//! around the public API to do its job, that is a defect report against the
//! library, not a shortcut to take here.
//!
//! One thing curl does that this deliberately does not: `--compressed`. zurl
//! decodes no content codings, so asking an origin to gzip would produce a
//! body it must then refuse. Rather than accept the flag and lie, it is not a
//! flag — and unknown flags are a usage error, so a diff can never silently
//! compare two different requests.

const std = @import("std");
const Io = std.Io;
const zurl = @import("zurl");
const cli_args = @import("args.zig");

/// curl's exit code for `-f` against a 4xx or 5xx. Matched so a differential
/// run can compare exit status and not just output.
const exit_http_error = 22;
/// Anything that stopped the request from completing.
const exit_failed = 2;
const exit_usage = 1;

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;

    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var argv: std.ArrayList([]const u8) = .empty;
    var it = init.minimal.args.iterate();
    _ = it.next();
    // lint:unbounded-ok — bounded by the argument vector the OS handed over.
    while (it.next()) |arg| try argv.append(arena, arg);

    const args = cli_args.parse(arena, argv.items) catch |err| switch (err) {
        error.Usage => {
            usage();
            std.process.exit(exit_usage);
        },
        error.OutOfMemory => return err,
    };

    var threaded: Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    std.process.exit(try run(gpa, arena, io, &args));
}

fn usage() void {
    std.debug.print(
        \\usage: zurl [options] <url>
        \\
        \\  -X, --request <method>   -H, --header <line>      -d, --data <bytes>
        \\  -o, --output <file>      -D, --dump-header <file> -i, --include
        \\  -L, --location           -u, --user <user:pass>   -A, --user-agent <ua>
        \\  -k, --insecure           --cacert <file>          --max-time <seconds>
        \\  -I, --head               -f, --fail               -s, --silent
        \\  -w, --write-out <fmt>    (%{{http_code}} %{{size_download}} %{{size_header}})
        \\
        \\No --compressed: zurl decodes no content codings, so it never asks for one.
        \\
    , .{});
}

/// Everything after parsing. Returns the process exit code.
fn run(gpa: std.mem.Allocator, arena: std.mem.Allocator, io: Io, args: *const cli_args.Args) !u8 {
    var certificates: std.crypto.Certificate.Bundle = .empty;
    defer certificates.deinit(gpa);
    var lock: Io.RwLock = .init;

    const tls_config = try trustConfig(gpa, io, args, &certificates, &lock);

    var body: Io.Writer.Allocating = .init(gpa);
    defer body.deinit();
    var headers: Io.Writer.Allocating = .init(gpa);
    defer headers.deinit();

    var recorder: HeaderRecorder = .{ .out = &headers };

    var auth_buf: [1024]u8 = undefined;
    const authorization = if (args.user) |user| try basicAuth(&auth_buf, user) else null;

    var redirect_buf: [8 * 1024]u8 = undefined;
    const outcome = zurl.fetch(io, .{
        .url = args.url,
        .method = args.effectiveMethod(),
        .authorization = authorization,
        .user_agent = args.user_agent orelse zurl.default_user_agent,
        .extra = args.headers,
        .body = if (args.data) |d| .{ .bytes = d } else null,
        // `-I` and `-o /dev/null` still need the body FRAMED, just not kept;
        // `.discard` reads and drops it, which is what keeps the connection
        // honest rather than abandoning bytes on the wire.
        .sink = .{ .collect = &body },
        .on_header = HeaderRecorder.onHeader,
        .ctx = &recorder,
        .deadline_ns = (args.max_time_s orelse 300) * std.time.ns_per_s,
        .what = "request",
        .redirects = if (args.follow_redirects)
            .{ .max = args.max_redirects, .buf = &redirect_buf }
        else
            .{},
        .tls = tls_config,
    }) catch |err| {
        if (!args.silent) std.debug.print("zurl: {s}\n", .{@errorName(err)});
        return exit_failed;
    };

    const response = outcome orelse {
        // `fetch` already printed which deadline fired.
        return exit_failed;
    };

    // A head we could not fully record is a head we must not claim to show.
    if (recorder.failed) return error.OutOfMemory;

    // curl still writes its `-w` output when `-f` fails, and still exits 22.
    // Returning early here skipped it — found by curl-diff on its first run,
    // which is the whole reason that gate exists.
    const refused = args.fail_on_error and response.status >= 400;
    if (refused and !args.silent) {
        std.debug.print("zurl: the requested URL returned error: {d}\n", .{response.status});
    }

    try writeOutputs(io, arena, args, response, headers.written(), body.written(), refused);
    return if (refused) exit_http_error else 0;
}

/// Records the response head verbatim, so `-i` and `-D` can reproduce it.
///
/// Reconstructed rather than captured raw: the parser hands over decoded
/// names and trimmed values, which is the only shape available. That means
/// what comes out is semantically the head and not byte-identical to it —
/// worth knowing before diffing this against `curl -D`.
const HeaderRecorder = struct {
    out: *Io.Writer.Allocating,
    /// A write that failed, which can only be the allocator giving up.
    ///
    /// Recorded rather than swallowed. The callback cannot return an error —
    /// the parser's signature has nowhere to put one — so the alternative is
    /// a `catch {}` that drops a header and leaves a head which still parses
    /// and is missing a line. That is rule 7's hazard, self-inflicted, on the
    /// exact buffer `-i` and `-D` promise to reproduce.
    failed: bool = false,

    fn onHeader(ctx: ?*anyopaque, name: []const u8, value: []const u8) void {
        const self: *HeaderRecorder = @ptrCast(@alignCast(ctx.?));
        self.out.writer.print("{s}: {s}\r\n", .{ name, value }) catch {
            self.failed = true;
        };
    }
};

fn trustConfig(
    gpa: std.mem.Allocator,
    io: Io,
    args: *const cli_args.Args,
    certificates: *std.crypto.Certificate.Bundle,
    lock: *Io.RwLock,
) !?zurl.tls.Config {
    if (!std.mem.startsWith(u8, args.url, "https://")) return null;

    if (args.insecure) return .{ .ca = .insecure_no_verification };

    if (args.cacert_path) |path| {
        try certificates.addCertsFromFilePath(gpa, io, .now(io, .real), .cwd(), path);
    } else {
        try certificates.rescan(gpa, io, .now(io, .real));
    }
    return .{ .ca = .{ .bundle = .{ .gpa = gpa, .lock = lock, .certificates = certificates } } };
}

fn basicAuth(buf: []u8, user: []const u8) ![]const u8 {
    // curl splits on the FIRST colon, and a missing one means an empty
    // password rather than an error.
    const colon = std.mem.indexOfScalar(u8, user, ':');
    const name = if (colon) |c| user[0..c] else user;
    const password = if (colon) |c| user[c + 1 ..] else "";
    return zurl.auth.basic(buf, name, password);
}

fn writeOutputs(
    io: Io,
    arena: std.mem.Allocator,
    args: *const cli_args.Args,
    response: zurl.Response,
    head: []const u8,
    body: []const u8,
    /// `-f` matched: curl suppresses the response but still writes `-w`.
    refused: bool,
) !void {
    if (args.dump_header_path) |path| try writeFile(io, path, head);

    // `-I` shows the head and no body, `-i` shows both. Note what is NOT here:
    // `-s`. curl's silent flag suppresses the progress meter and error
    // messages, not the response — a `-s` that swallowed the body would make
    // every differential run compare an empty file against a real one and
    // call zurl broken. Found exactly that way.
    const show_head = (args.include_headers or args.head_only) and !refused;
    const show_body = !args.head_only and !refused;

    // curl does not create the output file at all when `-f` matches — "no
    // output" means none, not an empty file where a caller might later find a
    // zero-length artifact and think the fetch succeeded.
    if (args.outputFile()) |path| {
        if (!refused) {
            const combined = if (show_head)
                try std.mem.concat(arena, u8, &.{ head, "\r\n", body })
            else
                body;
            try writeFile(io, path, combined);
        }
    }

    var stdout_buf: [4096]u8 = undefined;
    var stdout_file = Io.File.stdout();
    var stdout = stdout_file.writerStreaming(io, &stdout_buf);

    if (args.outputFile() == null) {
        if (show_head) {
            try stdout.interface.writeAll(head);
            try stdout.interface.writeAll("\r\n");
        }
        if (show_body) try stdout.interface.writeAll(body);
    }

    // `-w` goes to stdout even when the body went to a file, which is the
    // whole point of pairing `-o /dev/null` with it.
    if (args.write_out) |format| try writeOut(&stdout.interface, format, response, head, body);
    try stdout.interface.flush();
}

fn writeFile(io: Io, path: []const u8, bytes: []const u8) !void {
    try Io.Dir.cwd().writeFile(io, .{ .sub_path = path, .data = bytes });
}

/// curl's `-w`, restricted to the three variables a diff can compare.
///
/// Anything else in the format string is copied through, including an unknown
/// `%{...}`: curl leaves those alone too, and a diff that disagreed about an
/// unsupported variable would be comparing this function, not the client.
fn writeOut(
    out: *Io.Writer,
    format: []const u8,
    response: zurl.Response,
    head: []const u8,
    body: []const u8,
) !void {
    var index: usize = 0;
    // lint:unbounded-ok — `index` strictly increases on every path.
    while (index < format.len) {
        if (format[index] != '%' or index + 1 >= format.len or format[index + 1] != '{') {
            try out.writeByte(format[index]);
            index += 1;
            continue;
        }
        const close = std.mem.indexOfScalarPos(u8, format, index, '}') orelse {
            try out.writeByte(format[index]);
            index += 1;
            continue;
        };

        const name = format[index + 2 .. close];
        if (std.mem.eql(u8, name, "http_code")) {
            try out.print("{d}", .{response.status});
        } else if (std.mem.eql(u8, name, "size_download")) {
            try out.print("{d}", .{body.len});
        } else if (std.mem.eql(u8, name, "size_header")) {
            try out.print("{d}", .{head.len});
        } else {
            try out.writeAll(format[index .. close + 1]);
        }
        index = close + 1;
    }
}
