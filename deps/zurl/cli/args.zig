//! Command-line parsing for the `zurl` binary, kept apart from running it.
//!
//! Separate so it can be tested without a network. Everything here is a pure
//! function of the argument vector; nothing dials, opens a file, or allocates
//! beyond the caller's arena.
//!
//! The flag set mirrors `curl`'s deliberately and stops well short of it. The
//! point of the binary is a differential oracle — same request to curl and to
//! zurl, same answer or one of them is wrong — so a flag earns its place by
//! making that comparison possible, not by existing in curl.

const std = @import("std");
const zurl = @import("zurl");

pub const Error = error{
    /// A flag nobody recognises, a value missing after a flag, or no URL.
    /// Distinct from a request that ran and failed: this one never started.
    Usage,
    OutOfMemory,
};

/// What `-w` may interpolate. A deliberately tiny subset of curl's.
///
/// These three are what a diff compares. `%{time_total}` is not among them:
/// it differs between two clients by construction, so putting it in a
/// comparable output format would only ever produce false failures.
pub const write_out_vars = [_][]const u8{ "http_code", "size_download", "size_header" };

pub const Args = struct {
    url: []const u8,
    method: ?std.http.Method = null,
    headers: []const zurl.Header = &.{},
    data: ?[]const u8 = null,
    output_path: ?[]const u8 = null,
    dump_header_path: ?[]const u8 = null,
    /// `-i`: response headers go to the output ahead of the body.
    include_headers: bool = false,
    /// `-L`. curl's default cap is 50; the same number here so a chain that
    /// terminates for curl terminates here.
    follow_redirects: bool = false,
    max_redirects: u8 = 50,
    user: ?[]const u8 = null,
    user_agent: ?[]const u8 = null,
    max_time_s: ?u64 = null,
    insecure: bool = false,
    cacert_path: ?[]const u8 = null,
    /// `-I`: HEAD, and show the headers.
    head_only: bool = false,
    /// `-f`: exit 22 on a 4xx or 5xx instead of printing the body.
    fail_on_error: bool = false,
    silent: bool = false,
    write_out: ?[]const u8 = null,

    /// The file output goes to, or null for stdout.
    ///
    /// curl reads `-o -` as stdout, so a caller writing that gets the body on
    /// stdout and NOT a file literally named `-` in the working directory.
    pub fn outputFile(args: *const Args) ?[]const u8 {
        const path = args.output_path orelse return null;
        if (std.mem.eql(u8, path, "-")) return null;
        return path;
    }

    /// The method actually sent, once `-I`, `-d` and `-X` have argued.
    ///
    /// curl's precedence, which the oracle depends on matching: an explicit
    /// `-X` wins over everything, `-I` means HEAD, and data alone means POST.
    pub fn effectiveMethod(args: *const Args) std.http.Method {
        if (args.method) |method| return method;
        if (args.head_only) return .HEAD;
        if (args.data != null) return .POST;
        return .GET;
    }
};

/// Parse `argv` (without the program name).
///
/// `arena` owns the header list; every other slice points into `argv`.
pub fn parse(arena: std.mem.Allocator, argv: []const []const u8) Error!Args {
    var headers: std.ArrayList(zurl.Header) = .empty;
    var url: ?[]const u8 = null;
    var args: Args = .{ .url = "" };

    var index: usize = 0;
    // lint:unbounded-ok — `index` strictly increases every pass and the loop
    // ends at `argv.len`; a flag that takes a value advances it twice.
    while (index < argv.len) : (index += 1) {
        const arg = argv[index];

        // Anything that is not a flag is the URL. A second one is a usage
        // error rather than a silent last-wins, which would make a typo look
        // like a successful request to somewhere else.
        if (arg.len == 0 or arg[0] != '-' or std.mem.eql(u8, arg, "-")) {
            if (url != null) return error.Usage;
            url = arg;
            continue;
        }

        if (match(arg, "-X", "--request")) {
            args.method = try parseMethod(try next(argv, &index));
        } else if (match(arg, "-H", "--header")) {
            try headers.append(arena, try parseHeader(try next(argv, &index)));
        } else if (match(arg, "-d", "--data")) {
            args.data = try next(argv, &index);
        } else if (match(arg, "-o", "--output")) {
            args.output_path = try next(argv, &index);
        } else if (match(arg, "-D", "--dump-header")) {
            args.dump_header_path = try next(argv, &index);
        } else if (match(arg, "-u", "--user")) {
            args.user = try next(argv, &index);
        } else if (match(arg, "-A", "--user-agent")) {
            args.user_agent = try next(argv, &index);
        } else if (match(arg, "-w", "--write-out")) {
            args.write_out = try next(argv, &index);
        } else if (std.mem.eql(u8, arg, "--cacert")) {
            args.cacert_path = try next(argv, &index);
        } else if (std.mem.eql(u8, arg, "--max-time")) {
            const value = try next(argv, &index);
            const seconds = std.fmt.parseInt(u64, value, 10) catch return error.Usage;
            // curl reads 0 as "no timeout". zurl has no such thing — `fetch`
            // asserts a positive deadline, because rule 3 is that every
            // request is bounded — so 0 becomes the largest bound instead of
            // tripping that assertion with ordinary user input.
            args.max_time_s = if (seconds == 0) max_time_unbounded_s else seconds;
        } else if (match(arg, "-i", "--include")) {
            args.include_headers = true;
        } else if (match(arg, "-L", "--location")) {
            args.follow_redirects = true;
        } else if (match(arg, "-k", "--insecure")) {
            args.insecure = true;
        } else if (match(arg, "-I", "--head")) {
            args.head_only = true;
        } else if (match(arg, "-f", "--fail")) {
            args.fail_on_error = true;
        } else if (match(arg, "-s", "--silent")) {
            args.silent = true;
        } else {
            // Unknown flags are refused, never ignored. A silently dropped
            // `--compressed` would make the differential oracle compare two
            // different requests and call them equal.
            return error.Usage;
        }
    }

    args.url = url orelse return error.Usage;
    args.headers = headers.items;
    return args;
}

/// What `--max-time 0` becomes.
///
/// curl reads zero as "no timeout"; zurl has no such thing, because rule 3 is
/// that every request carries a bound. A day is not infinity, and saying so is
/// better than an unbounded request wearing a flag that claims to bound it.
pub const max_time_unbounded_s: u64 = 24 * 60 * 60;

/// `-X` names a method, and only a canonical one.
///
/// curl sends whatever string it is given, verbatim and in whatever case — so
/// `curl -X get` really does put `get` on the wire, and a strict origin
/// answers 400. zurl cannot reproduce that: `connection.Request.method` is
/// `std.http.Method`, an enum, so the library has no way to express a method
/// it does not know.
///
/// This refuses rather than upper-casing. Upper-casing was tried, and the
/// differential oracle caught it immediately: `-X get` became a 200 here and a
/// 400 in curl, which is worse than refusing — it silently sends a DIFFERENT
/// request than the one the caller typed. A usage error at least says so.
///
/// docs/SCOPE.md records the underlying limitation as the library's, not this
/// file's, because that is where it would have to be fixed.
fn parseMethod(text: []const u8) Error!std.http.Method {
    return std.meta.stringToEnum(std.http.Method, text) orelse error.Usage;
}

fn match(arg: []const u8, short: []const u8, long: []const u8) bool {
    return std.mem.eql(u8, arg, short) or std.mem.eql(u8, arg, long);
}

fn next(argv: []const []const u8, index: *usize) Error![]const u8 {
    if (index.* + 1 >= argv.len) return error.Usage;
    index.* += 1;
    return argv[index.*];
}

/// `Name: value`, curl's `-H` syntax.
fn parseHeader(text: []const u8) Error!zurl.Header {
    const colon = std.mem.indexOfScalar(u8, text, ':') orelse return error.Usage;
    const name = text[0..colon];
    if (name.len == 0) return error.Usage;
    // Leading whitespace after the colon is separator, not value — curl
    // trims it and so must this, or every diff shows a phantom space.
    const value = std.mem.trim(u8, text[colon + 1 ..], " \t");
    return .{ .name = name, .value = value };
}

// ---------------------------------------------------------------------------
// tests
const t = std.testing;

fn parseSlice(arena: std.mem.Allocator, comptime argv: []const []const u8) Error!Args {
    return parse(arena, argv);
}

test "the flags a differential run needs, long and short" {
    var arena_state: std.heap.ArenaAllocator = .init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const args = try parseSlice(arena, &.{
        "-X",           "PUT",
        "-H",           "X-One: 1",
        "--header",     "X-Two:2",
        "-d",           "body",
        "-o",           "out.bin",
        "-L",           "-i",
        "-k",           "--max-time",
        "7",            "-u",
        "user:pass",    "-A",
        "agent/1",      "--cacert",
        "/tmp/ca.pem",  "-f",
        "-s",           "-w",
        "%{http_code}", "https://example.com/thing",
    });

    try t.expectEqual(std.http.Method.PUT, args.effectiveMethod());
    try t.expectEqualStrings("https://example.com/thing", args.url);
    try t.expectEqual(@as(usize, 2), args.headers.len);
    try t.expectEqualStrings("X-One", args.headers[0].name);
    try t.expectEqualStrings("1", args.headers[0].value);
    // No leading space, even though the argument had one after the colon.
    try t.expectEqualStrings("2", args.headers[1].value);
    try t.expectEqualStrings("body", args.data.?);
    try t.expectEqualStrings("out.bin", args.output_path.?);
    try t.expect(args.follow_redirects);
    try t.expect(args.include_headers);
    try t.expect(args.insecure);
    try t.expectEqual(@as(?u64, 7), args.max_time_s);
    try t.expectEqualStrings("user:pass", args.user.?);
    try t.expectEqualStrings("agent/1", args.user_agent.?);
    try t.expectEqualStrings("/tmp/ca.pem", args.cacert_path.?);
    try t.expect(args.fail_on_error);
    try t.expect(args.silent);
    try t.expectEqualStrings("%{http_code}", args.write_out.?);
}

test "method precedence matches curl, because the oracle depends on it" {
    var arena_state: std.heap.ArenaAllocator = .init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // Bare URL is a GET.
    try t.expectEqual(std.http.Method.GET, (try parseSlice(arena, &.{"http://h/"})).effectiveMethod());
    // Data alone implies POST.
    try t.expectEqual(std.http.Method.POST, (try parseSlice(arena, &.{ "-d", "x", "http://h/" })).effectiveMethod());
    // -I is HEAD.
    try t.expectEqual(std.http.Method.HEAD, (try parseSlice(arena, &.{ "-I", "http://h/" })).effectiveMethod());
    // An explicit -X beats both, in either order.
    try t.expectEqual(std.http.Method.DELETE, (try parseSlice(arena, &.{ "-d", "x", "-X", "DELETE", "http://h/" })).effectiveMethod());
    try t.expectEqual(std.http.Method.GET, (try parseSlice(arena, &.{ "-I", "-X", "GET", "http://h/" })).effectiveMethod());
}

test "usage errors are refusals, never a request to somewhere unintended" {
    var arena_state: std.heap.ArenaAllocator = .init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // No URL at all.
    try t.expectError(error.Usage, parseSlice(arena, &.{}));
    try t.expectError(error.Usage, parseSlice(arena, &.{"-L"}));
    // A flag whose value is missing must not swallow the URL.
    try t.expectError(error.Usage, parseSlice(arena, &.{ "http://h/", "-X" }));
    // Two URLs: a typo that last-wins would turn into a successful request to
    // the wrong place.
    try t.expectError(error.Usage, parseSlice(arena, &.{ "http://a/", "http://b/" }));
    // An unknown flag is refused rather than ignored — silently dropping one
    // would make a differential run compare two different requests.
    try t.expectError(error.Usage, parseSlice(arena, &.{ "--compressed", "http://h/" }));
    try t.expectError(error.Usage, parseSlice(arena, &.{ "-Z", "http://h/" }));
    // Malformed values.
    try t.expectError(error.Usage, parseSlice(arena, &.{ "-X", "NOTAMETHOD", "http://h/" }));
    try t.expectError(error.Usage, parseSlice(arena, &.{ "-H", "no-colon", "http://h/" }));
    try t.expectError(error.Usage, parseSlice(arena, &.{ "-H", ": novalue", "http://h/" }));
    try t.expectError(error.Usage, parseSlice(arena, &.{ "--max-time", "soon", "http://h/" }));
}

test "curl's two spellings this cannot follow, and the one it can" {
    var arena_state: std.heap.ArenaAllocator = .init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // `-o -` is stdout to curl, not a file named `-`. Tested here rather than
    // in curl-diff, because that harness supplies its own `-o` to capture the
    // body and a second one would test precedence rather than either client.
    const dash = try parseSlice(arena, &.{ "-o", "-", "http://h/" });
    try t.expectEqualStrings("-", dash.output_path.?);
    try t.expectEqual(@as(?[]const u8, null), dash.outputFile());

    const named = try parseSlice(arena, &.{ "-o", "out.bin", "http://h/" });
    try t.expectEqualStrings("out.bin", named.outputFile().?);

    // `--max-time 0` is "no timeout" to curl. zurl has no such thing — rule 3
    // says every request carries a bound — so it becomes the largest bound
    // rather than a zero that would trip `fetch`'s precondition assert on
    // ordinary user input.
    const untimed = try parseSlice(arena, &.{ "--max-time", "0", "http://h/" });
    try t.expectEqual(@as(?u64, max_time_unbounded_s), untimed.max_time_s);
    try t.expect(untimed.max_time_s.? > 0);

    // A non-canonical method is refused, not upper-cased. curl would send
    // `get` verbatim; upper-casing here would send a DIFFERENT request than
    // the caller typed and the differential oracle caught exactly that.
    try t.expectError(error.Usage, parseSlice(arena, &.{ "-X", "get", "http://h/" }));
    try t.expectError(error.Usage, parseSlice(arena, &.{ "-X", "GeT", "http://h/" }));
    try t.expectEqual(std.http.Method.GET, (try parseSlice(arena, &.{ "-X", "GET", "http://h/" })).effectiveMethod());
}
