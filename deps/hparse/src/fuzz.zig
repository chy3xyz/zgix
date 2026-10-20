//! Fuzzing harness for hparse (issue #2).
//!
//! Run modes:
//! * `zig build fuzz` — replays the seed corpus through the oracles once (regression mode).
//! * `zig build fuzz --fuzz` — coverage-guided fuzzing via Zig's native fuzzer.
//!
//! The parser walks the buffer with `[*]const u8` many-item pointers, which Zig's bounds
//! checking does not cover — a 1-byte overread past the slice does not crash and silently
//! reads adjacent memory. A naive "call it and see if it faults" harness would never catch
//! that class. The first two oracles below make it visible; the third is about the
//! tiers agreeing with each other rather than about memory:
//!
//! 1. Guard-page-backed input: every parse runs on a copy whose last byte abuts a
//!    PROT_NONE page, so any read past the end is an immediate SIGSEGV.
//! 2. Prefix/consumed-length exactness: a successful parse consuming N bytes must
//!    reproduce byte-identical results when re-parsing exactly those N bytes, and every
//!    strict prefix of them must return `error.Incomplete` — never a false accept, and
//!    never `error.Invalid` (which would mean the SIMD and scalar matcher tiers, selected
//!    by remaining buffer length, disagree about the same bytes).
//! 3. Path differential: a second build of the parser with the `@Vector` tier forced
//!    off (`-Duse-vectors=false`) parses the same bytes, and must accept or refuse
//!    identically — the tiers disagreeing is what oracle 2 can only catch when the
//!    disagreement happens to fall across a truncation boundary.
//! 4. Reference differential against picohttpparser and llhttp: where hparse and a
//!    reference BOTH accept, the fields must match. Only where both accept — they
//!    disagree about what is legal by design. Two references rather than one because
//!    they are wrong differently: picohttpparser is hand-written and block-oriented,
//!    llhttp is a generated state machine walking one byte at a time.
//! 5. Disagreement snapshot: everywhere oracle 4 skips — a verdict difference rather
//!    than a field difference — is recorded in `disagreements.zig` with a required
//!    justification, and the set is re-derived and diffed on every run. That is the
//!    half of oracle 4 that used to go nowhere: this comment called such cases
//!    "triage material, not failures" while nothing triaged them, which is how a
//!    header key accepting 144 non-tchar bytes survived eight months with
//!    picohttpparser rejecting the very same input in the very same run.

const std = @import("std");
const builtin = @import("builtin");
const hparse = @import("hparse");
/// The same parser built with the @Vector tier forced off; see `diffRequestTiers`.
const scalar = @import("hparse_scalar");

/// First reference parser; see `diffRequestAgainstPico`.
const pico = @cImport({
    @cInclude("picohttpparser.h");
});

/// Seed corpus harvested from llhttp's markdown test fixtures.
const corpus_llhttp = @import("corpus_llhttp.zig");

/// Checked-in verdict disagreements; see `checkDisagreements`.
const disagreements = @import("disagreements.zig");

/// Second reference parser; see `diffRequestAgainstLlhttp`.
const llhttp = @cImport({
    @cInclude("llhttp.h");
});

/// Fuzz inputs are capped at one page so a copy always fits in front of the guard page.
const max_input = 1024;

/// Headers slice size for every parse in the harness. Must be the same for the primary
/// parse and the prefix re-parses: with equal capacity, a strict prefix of a successful
/// parse can never legitimately return `error.TooManyHeaders`.
const max_headers = 16;

/// A page of writable memory directly followed by a PROT_NONE page. Inputs are copied so
/// their last byte abuts the guard page, turning any overread into a SIGSEGV the fuzzer
/// records as a crash.
const GuardedRegion = struct {
    page: ?[]align(std.heap.page_size_min) u8 = null,

    fn copy(region: *GuardedRegion, bytes: []const u8) []const u8 {
        @disableInstrumentation();
        if (region.page == null) region.page = allocGuardedPage();
        const page = region.page.?;
        const dst = page[page.len - bytes.len ..];
        @memcpy(dst, bytes);
        return dst;
    }
};

/// Returns one writable page directly followed by an inaccessible page.
fn allocGuardedPage() []align(std.heap.page_size_min) u8 {
    @disableInstrumentation();
    const page_size = std.heap.pageSize();
    std.debug.assert(max_input <= page_size);

    if (builtin.os.tag == .windows) {
        const windows = std.os.windows;
        const process = windows.GetCurrentProcess();

        var base: ?*anyopaque = null;
        var size: windows.SIZE_T = 2 * page_size;
        if (windows.ntdll.NtAllocateVirtualMemory(
            process,
            @ptrCast(&base),
            0,
            &size,
            .{ .COMMIT = true, .RESERVE = true },
            .{ .READWRITE = true },
        ) != .SUCCESS) @panic("NtAllocateVirtualMemory failed");

        var guard_base: ?*anyopaque = @ptrFromInt(@intFromPtr(base.?) + page_size);
        var guard_size: windows.SIZE_T = page_size;
        var old_protection: windows.PAGE = .{};
        if (windows.ntdll.NtProtectVirtualMemory(
            process,
            &guard_base,
            &guard_size,
            .{ .NOACCESS = true },
            &old_protection,
        ) != .SUCCESS) @panic("NtProtectVirtualMemory failed");

        const ptr: [*]align(std.heap.page_size_min) u8 = @ptrCast(@alignCast(base.?));
        return ptr[0..page_size];
    }

    // POSIX: map both pages PROT_NONE, then remap the first page read/write in place;
    // the second page stays inaccessible as the guard.
    const mem = std.posix.mmap(
        null,
        2 * page_size,
        .{},
        .{ .TYPE = .PRIVATE, .ANONYMOUS = true },
        -1,
        0,
    ) catch @panic("mmap failed");
    return std.posix.mmap(
        mem.ptr,
        page_size,
        .{ .READ = true, .WRITE = true },
        .{ .TYPE = .PRIVATE, .ANONYMOUS = true, .FIXED = true },
        -1,
        0,
    ) catch @panic("mmap failed");
}

// Two regions so results of the primary parse (slices into `primary`) stay intact while
// re-parses and prefix probes overwrite `probe`.
var primary: GuardedRegion = .{};
var probe: GuardedRegion = .{};

/// Expects `inner` to be a subslice of `outer` (parsers must never hand out slices that
/// point outside the input buffer).
fn expectWithin(outer: []const u8, inner: []const u8) !void {
    @disableInstrumentation();
    const o_start = @intFromPtr(outer.ptr);
    const i_start = @intFromPtr(inner.ptr);
    try std.testing.expect(i_start >= o_start);
    try std.testing.expect(i_start + inner.len <= o_start + outer.len);
}

/// Drives `parseRequestResume` to the full length and requires it does not
/// accept. Used on inputs the one-shot parser refuses.
fn expectResumeRejects(g: []const u8) !void {
    @disableInstrumentation();
    var state: hparse.Resume = .{};
    var method: hparse.Method = .unknown;
    var token: ?[]const u8 = null;
    var path: ?[]const u8 = null;
    var version: hparse.Version = .@"1.0";
    var headers: [max_headers]hparse.Header = undefined;
    var count: usize = 0;

    const step = @max(1, g.len / 16);
    var have: usize = 0;
    while (have < g.len) {
        have = @min(have + step, g.len);
        if (hparse.parseRequestResume(
            g[0..have],
            &state,
            &method,
            &token,
            &path,
            &version,
            &headers,
            &count,
        )) |_| {
            return error.ResumeAcceptedWhatOneShotRefused;
        } else |_| continue;
    }
}

/// Path-differential oracle: the same bytes through a build of the parser with the
/// `@Vector` tier forced off, compared against the tier this build ships.
///
/// Which tier runs is chosen by how many bytes remain, so the two builds see the
/// same input through different code by construction — the shape of the
/// SIMD-vs-scalar space-in-key divergence this parser has already had once.
/// Accept/reject must match, and so must WHICH error: `Incomplete` from one tier
/// and `Invalid` from the other is two parsers disagreeing about whether a message
/// exists, which for a proxy is the whole bug class.
///
/// KNOWN GAP: header KEYS are no longer covered. `matchHeaderKey` is byte-at-a-time
/// in both builds now (see its comment in `root.zig` for why), so for key bytes this
/// oracle compares one implementation with itself. That is doubly worth knowing
/// because the divergence named above — and the tchar bug found later in the same
/// function — both lived exactly there. Nothing in this harness now watches header
/// keys for a tier split, because there are no longer two tiers to split.
///
/// The scalar build parses the guarded copy too, so its scalar loops
/// get the memory-safety oracle rather than only the vector ones.
///
/// A build that itself forced vectors off makes this a self-comparison. That is the
/// honest reading — the diff is against the tier being shipped — and a plain
/// `zig build fuzz` is what exercises the real thing.
///
/// KNOWN GAP: only the one-shot entry points are diffed. `parseRequestResume` and
/// `parseResponseResume` reach the same scans, but through their own phase
/// bookkeeping, so a tier disagreement that only a resumed line can reach would
/// not be seen here. Covering it means a second resume drive per input, which is
/// the most expensive thing in this harness already.
fn diffRequestTiers(
    g: []const u8,
    vector_result: hparse.ParseRequestError!usize,
    vector_method: hparse.Method,
    vector_token: ?[]const u8,
    vector_path: ?[]const u8,
    vector_version: hparse.Version,
    vector_headers: *const [max_headers]hparse.Header,
    vector_count: usize,
) !void {
    @disableInstrumentation();
    // Were the build options ever to stop reaching the parser, this would compare a
    // build against itself and the oracle would silently test nothing. Fail loudly,
    // at compile time.
    comptime std.debug.assert(!scalar.uses_vectors);

    var method: scalar.Method = .unknown;
    var token: ?[]const u8 = null;
    var path: ?[]const u8 = null;
    var version: scalar.Version = .@"1.0";
    var headers: [max_headers]scalar.Header = undefined;
    var count: usize = 0;

    const result = scalar.parseRequest(g, &method, &token, &path, &version, &headers, &count);

    const vector_n = vector_result catch |vector_err| {
        const err = if (result) |_| return error.TiersDisagreeOnAccept else |e| e;
        if (err != vector_err) return error.TiersDisagreeOnError;
        return;
    };
    const n = result catch return error.TiersDisagreeOnAccept;

    try std.testing.expectEqual(vector_n, n);
    try std.testing.expectEqual(vector_count, count);
    try std.testing.expect(count <= max_headers);
    // Separate module instances, so these are distinct types carrying the same tags.
    try std.testing.expectEqualStrings(@tagName(vector_method), @tagName(method));
    try std.testing.expectEqualStrings(@tagName(vector_version), @tagName(version));
    try std.testing.expectEqual(vector_token == null, token == null);
    if (vector_token) |vt| try std.testing.expectEqualStrings(vt, token.?);
    try std.testing.expectEqual(vector_path == null, path == null);
    if (vector_path) |vp| try std.testing.expectEqualStrings(vp, path.?);
    for (vector_headers[0..vector_count], headers[0..count]) |a, b| {
        try std.testing.expectEqualStrings(a.key, b.key);
        try std.testing.expectEqualStrings(a.value, b.value);
    }
}

/// `diffRequestTiers` for the response side.
///
/// Nothing in the status line is vectorized — `matchStatusMessage` is a byte-at-a-time
/// loop, and the only `@Vector` scans left in the parser are `matchPath` and
/// `matchHeaderValue`. `matchHeaderKey` used to be a third and is not any more. What
/// this diffs is therefore the header-value scan reached through `parseResponse`,
/// whose surrounding state differs from the request path's, plus the whole response
/// line under both builds' guard-page copy.
fn diffResponseTiers(
    g: []const u8,
    vector_result: hparse.ParseRequestError!usize,
    vector_version: hparse.Version,
    vector_status: u16,
    vector_msg: ?[]const u8,
    vector_headers: *const [max_headers]hparse.Header,
    vector_count: usize,
) !void {
    @disableInstrumentation();
    comptime std.debug.assert(!scalar.uses_vectors);

    var version: scalar.Version = .@"1.0";
    var status: u16 = 0;
    var msg: ?[]const u8 = null;
    var headers: [max_headers]scalar.Header = undefined;
    var count: usize = 0;

    const result = scalar.parseResponse(g, &version, &status, &msg, &headers, &count);

    const vector_n = vector_result catch |vector_err| {
        const err = if (result) |_| return error.TiersDisagreeOnAccept else |e| e;
        if (err != vector_err) return error.TiersDisagreeOnError;
        return;
    };
    const n = result catch return error.TiersDisagreeOnAccept;

    try std.testing.expectEqual(vector_n, n);
    try std.testing.expectEqual(vector_count, count);
    try std.testing.expect(count <= max_headers);
    try std.testing.expectEqualStrings(@tagName(vector_version), @tagName(version));
    try std.testing.expectEqual(vector_status, status);
    try std.testing.expectEqual(vector_msg == null, msg == null);
    if (vector_msg) |vm| try std.testing.expectEqualStrings(vm, msg.?);
    for (vector_headers[0..vector_count], headers[0..count]) |a, b| {
        try std.testing.expectEqualStrings(a.key, b.key);
        try std.testing.expectEqualStrings(a.value, b.value);
    }
}

/// Where picohttpparser and hparse BOTH accept, every field must agree.
///
/// Only where both accept. The two disagree about what is legal on purpose, and every
/// such disagreement is expected rather than interesting: picohttpparser takes a bare
/// LF as a line ending, an obs-fold continuation line, a leading empty line before the
/// request, and any digit as the HTTP minor version, all of which hparse refuses. So a
/// verdict mismatch is not a failure here and is not reported — what this oracle is
/// for is the case where the two agree a message is well-formed and then disagree
/// about what it SAYS, which no amount of self-consistency checking can catch.
///
/// Both parsers read the guarded copy. picohttpparser only ever loads 16-byte blocks
/// that lie entirely within the buffer, so it is safe to point at the guard page; a
/// fault inside its frames would be a finding about it, not about hparse.
fn diffRequestAgainstPico(
    g: []const u8,
    hparse_result: hparse.ParseRequestError!usize,
    hparse_method: ?[]const u8,
    hparse_path: ?[]const u8,
    hparse_version: hparse.Version,
    hparse_headers: *const [max_headers]hparse.Header,
    hparse_count: usize,
) !void {
    @disableInstrumentation();

    var method: [*c]const u8 = null;
    var method_len: usize = 0;
    var path: [*c]const u8 = null;
    var path_len: usize = 0;
    var minor_version: c_int = -1;
    var headers: [max_headers]pico.phr_header = undefined;
    // In: the capacity. Out: the count.
    var count: usize = max_headers;

    const reference_result = pico.phr_parse_request(
        @ptrCast(g.ptr),
        g.len,
        &method,
        &method_len,
        &path,
        &path_len,
        &minor_version,
        &headers,
        &count,
        0,
    );

    // -1 refused, -2 partial. Either way there is nothing to compare.
    const consumed = hparse_result catch return;
    if (reference_result < 0) return;

    try std.testing.expectEqual(consumed, @as(usize, @intCast(reference_result)));
    // A successful parse always sets both, but this oracle runs before the
    // invariant that says so — fail rather than panic if it ever does not.
    try std.testing.expect(hparse_method != null);
    try std.testing.expect(hparse_path != null);
    try std.testing.expectEqualStrings(hparse_method.?, method[0..method_len]);
    try std.testing.expectEqualStrings(hparse_path.?, path[0..path_len]);
    try std.testing.expectEqualStrings(@tagName(hparse_version), try referenceVersion(minor_version));
    try std.testing.expectEqual(hparse_count, count);
    try expectPicoHeadersMatch(hparse_headers[0..hparse_count], headers[0..count]);
}

/// `diffRequestAgainstPico` for the response side.
fn diffResponseAgainstPico(
    g: []const u8,
    hparse_result: hparse.ParseRequestError!usize,
    hparse_version: hparse.Version,
    hparse_status: u16,
    hparse_msg: ?[]const u8,
    hparse_headers: *const [max_headers]hparse.Header,
    hparse_count: usize,
) !void {
    @disableInstrumentation();

    var minor_version: c_int = -1;
    var status: c_int = -1;
    var msg: [*c]const u8 = null;
    var msg_len: usize = 0;
    var headers: [max_headers]pico.phr_header = undefined;
    var count: usize = max_headers;

    const reference_result = pico.phr_parse_response(
        @ptrCast(g.ptr),
        g.len,
        &minor_version,
        &status,
        &msg,
        &msg_len,
        &headers,
        &count,
        0,
    );

    const consumed = hparse_result catch return;
    if (reference_result < 0) return;

    try std.testing.expectEqual(consumed, @as(usize, @intCast(reference_result)));
    try std.testing.expectEqual(@as(c_int, hparse_status), status);
    try std.testing.expectEqualStrings(@tagName(hparse_version), try referenceVersion(minor_version));
    // An absent status message is `null` on one side and a zero length on the other;
    // that is a representation choice, not a disagreement about the bytes.
    try std.testing.expectEqualStrings(
        hparse_msg orelse "",
        if (msg_len == 0) "" else msg[0..msg_len],
    );
    try std.testing.expectEqual(hparse_count, count);
    try expectPicoHeadersMatch(hparse_headers[0..hparse_count], headers[0..count]);
}

/// picohttpparser reports the minor version as a digit and takes any of them;
/// `hparse.Version` has two values because it accepts only two. Reaching this with
/// anything else means hparse accepted a version it has no representation for, so it
/// is a finding rather than something to map onto the nearest tag.
fn referenceVersion(minor_version: c_int) ![]const u8 {
    @disableInstrumentation();
    return switch (minor_version) {
        0 => "1.0",
        1 => "1.1",
        else => error.ReferenceMinorVersionOutOfRange,
    };
}

/// Both parsers strip OWS from each end of a value, so the slices are directly
/// comparable — no normalization, which would be the place to accidentally define
/// away a real difference.
fn expectPicoHeadersMatch(ours: []const hparse.Header, theirs: []const pico.phr_header) !void {
    @disableInstrumentation();
    for (ours, theirs) |a, b| {
        // A null name is picohttpparser reporting an obs-fold continuation line, which
        // hparse refuses outright — so reaching this on a mutual accept would mean
        // hparse had accepted a folded header, and the slice below would fault.
        if (b.name == null) return error.ReferenceFoldedHeaderOnMutualAccept;
        try std.testing.expectEqualStrings(a.key, b.name[0..b.name_len]);
        try std.testing.expectEqualStrings(a.value, if (b.value_len == 0) "" else b.value[0..b.value_len]);
    }
}

/// One field as llhttp reports it: a run of bytes inside the input buffer.
///
/// llhttp hands a field over through callbacks rather than as a slice, and is free
/// to split one field across several of them, so a span is assembled here. Feeding
/// the whole message to a single `llhttp_execute` makes every span contiguous in
/// practice; `fragmented` records the case where it is not, rather than silently
/// splicing two disjoint ranges into one slice and comparing whatever lies between
/// them.
const Span = struct {
    ptr: ?[*]const u8 = null,
    len: usize = 0,
    fragmented: bool = false,

    fn append(span: *Span, at: [*]const u8, len: usize) void {
        @disableInstrumentation();
        const start = span.ptr orelse {
            span.ptr = at;
            span.len = len;
            return;
        };
        if (start + span.len != at) {
            span.fragmented = true;
            return;
        }
        span.len += len;
    }

    /// A field llhttp never reported and one it reported as empty both read as no
    /// bytes. The two are distinguishable (`ptr == null`) but nothing here needs to:
    /// hparse's own absent/empty split does not line up with llhttp's either, and the
    /// comparisons below are all against `hparse_x orelse ""`.
    fn bytes(span: Span) []const u8 {
        @disableInstrumentation();
        return if (span.ptr) |p| p[0..span.len] else "";
    }
};

/// Everything llhttp's callbacks record for one message.
const LlhttpRecord = struct {
    method: Span = .{},
    url: Span = .{},
    status: Span = .{},
    keys: [max_headers]Span = @splat(.{}),
    values: [max_headers]Span = @splat(.{}),
    /// Counts every header llhttp reports, including any past `max_headers`, so a
    /// count that overruns the array shows up as a mismatch instead of being
    /// truncated into agreement.
    header_count: usize = 0,
    /// The header line currently being reported, committed on value-complete.
    pending_key: Span = .{},
    pending_value: Span = .{},
    /// Copied off the parser once it accepts; llhttp keeps these as struct fields
    /// rather than reporting them through a callback.
    major: u8 = 0,
    minor: u8 = 0,
    status_code: u16 = 0,
};

fn llhttpRecord(parser: [*c]llhttp.llhttp_t) *LlhttpRecord {
    @disableInstrumentation();
    return @ptrCast(@alignCast(parser.*.data.?));
}

fn onLlhttpMethod(parser: [*c]llhttp.llhttp_t, at: [*c]const u8, len: usize) callconv(.c) c_int {
    @disableInstrumentation();
    llhttpRecord(parser).method.append(@ptrCast(at), len);
    return 0;
}

fn onLlhttpUrl(parser: [*c]llhttp.llhttp_t, at: [*c]const u8, len: usize) callconv(.c) c_int {
    @disableInstrumentation();
    llhttpRecord(parser).url.append(@ptrCast(at), len);
    return 0;
}

fn onLlhttpStatus(parser: [*c]llhttp.llhttp_t, at: [*c]const u8, len: usize) callconv(.c) c_int {
    @disableInstrumentation();
    llhttpRecord(parser).status.append(@ptrCast(at), len);
    return 0;
}

fn onLlhttpHeaderField(parser: [*c]llhttp.llhttp_t, at: [*c]const u8, len: usize) callconv(.c) c_int {
    @disableInstrumentation();
    llhttpRecord(parser).pending_key.append(@ptrCast(at), len);
    return 0;
}

fn onLlhttpHeaderValue(parser: [*c]llhttp.llhttp_t, at: [*c]const u8, len: usize) callconv(.c) c_int {
    @disableInstrumentation();
    llhttpRecord(parser).pending_value.append(@ptrCast(at), len);
    return 0;
}

fn onLlhttpHeaderValueComplete(parser: [*c]llhttp.llhttp_t) callconv(.c) c_int {
    @disableInstrumentation();
    const record = llhttpRecord(parser);
    if (record.header_count < max_headers) {
        record.keys[record.header_count] = record.pending_key;
        record.values[record.header_count] = record.pending_value;
    }
    record.header_count += 1;
    record.pending_key = .{};
    record.pending_value = .{};
    return 0;
}

fn onLlhttpHeadersComplete(_: [*c]llhttp.llhttp_t) callconv(.c) c_int {
    @disableInstrumentation();
    // Stop exactly at the end of the head. `llhttp_get_error_pos` then points at the
    // byte after the final CRLF, which is the consumed length hparse returns — and
    // without pausing llhttp would run on into the body, where there is nothing to
    // compare against a parser that does not do framing.
    return llhttp.HPE_PAUSED;
}

/// Runs llhttp over `g` as `kind` (`HTTP_REQUEST` or `HTTP_RESPONSE`), returning the
/// consumed length if it accepted a complete head, or null otherwise.
///
/// Null covers both of llhttp's ways of not accepting: a hard error, and `HPE_OK`,
/// which for a streaming parser means "no error yet, send more". Only our own
/// `on_headers_complete` pauses, so `HPE_PAUSED` is unambiguous.
fn runLlhttp(g: []const u8, kind: c_int, record: *LlhttpRecord) ?usize {
    @disableInstrumentation();
    var settings: llhttp.llhttp_settings_t = undefined;
    llhttp.llhttp_settings_init(&settings);
    settings.on_method = onLlhttpMethod;
    settings.on_url = onLlhttpUrl;
    settings.on_status = onLlhttpStatus;
    settings.on_header_field = onLlhttpHeaderField;
    settings.on_header_value = onLlhttpHeaderValue;
    settings.on_header_value_complete = onLlhttpHeaderValueComplete;
    settings.on_headers_complete = onLlhttpHeadersComplete;

    var parser: llhttp.llhttp_t = undefined;
    // `HTTP_REQUEST`/`HTTP_RESPONSE` translate as `c_int` while `llhttp_init` takes the
    // enum's unsigned underlying type; the cast is that mismatch and nothing more.
    llhttp.llhttp_init(&parser, @intCast(kind), &settings);
    parser.data = record;

    if (llhttp.llhttp_execute(&parser, @ptrCast(g.ptr), g.len) != llhttp.HPE_PAUSED) return null;
    record.major = parser.http_major;
    record.minor = parser.http_minor;
    record.status_code = parser.status_code;
    return @intFromPtr(llhttp.llhttp_get_error_pos(&parser)) - @intFromPtr(g.ptr);
}

/// llhttp reports the version as two integers and accepts more than the two hparse
/// has names for. Same reasoning as `referenceVersion`: reaching either failure means
/// hparse accepted a version it cannot represent.
fn llhttpVersion(major: u8, minor: u8) ![]const u8 {
    @disableInstrumentation();
    if (major != 1) return error.ReferenceMajorVersionOutOfRange;
    return referenceVersion(minor);
}

/// llhttp's header-value span starts after the leading OWS but runs all the way to
/// the CR, so it keeps trailing OWS that hparse and picohttpparser both strip.
/// Trimming it here is a representation difference, not a normalization — it cannot
/// hide a disagreement about non-OWS bytes.
fn expectLlhttpHeadersMatch(ours: []const hparse.Header, theirs: *const LlhttpRecord) !void {
    @disableInstrumentation();
    for (ours, theirs.keys[0..ours.len], theirs.values[0..ours.len]) |a, key, value| {
        if (key.fragmented or value.fragmented) return error.ReferenceSpanFragmented;
        try std.testing.expectEqualStrings(a.key, key.bytes());
        try std.testing.expectEqualStrings(a.value, std.mem.trimEnd(u8, value.bytes(), " \t"));
    }
}

/// Where llhttp and hparse BOTH accept, every field must agree — the same contract as
/// `diffRequestAgainstPico`, against a reference built the other way round.
///
/// Only where both accept, and llhttp refuses considerably more than picohttpparser
/// does: it rejects any method outside its own table (so every extension method hparse
/// takes is a verdict difference), rejects obs-fold, and rejects a bare LF. It is also
/// a streaming parser, so "not accepted" includes `HPE_OK` — see `runLlhttp`.
///
/// llhttp reads the guarded copy too. It is a state machine over `data..data+len` and
/// never looks ahead, so pointing it at the guard page is safe; a fault inside its
/// frames would be a finding about llhttp, not about hparse.
fn diffRequestAgainstLlhttp(
    g: []const u8,
    hparse_result: hparse.ParseRequestError!usize,
    hparse_method: ?[]const u8,
    hparse_path: ?[]const u8,
    hparse_version: hparse.Version,
    hparse_headers: *const [max_headers]hparse.Header,
    hparse_count: usize,
) !void {
    @disableInstrumentation();

    var record: LlhttpRecord = .{};
    const reference_consumed = runLlhttp(g, llhttp.HTTP_REQUEST, &record);

    const consumed = hparse_result catch return;
    const reference_n = reference_consumed orelse return;

    try std.testing.expectEqual(consumed, reference_n);
    try std.testing.expect(hparse_method != null);
    try std.testing.expect(hparse_path != null);
    if (record.method.fragmented or record.url.fragmented) return error.ReferenceSpanFragmented;
    try std.testing.expectEqualStrings(hparse_method.?, record.method.bytes());
    try std.testing.expectEqualStrings(hparse_path.?, record.url.bytes());
    try std.testing.expectEqualStrings(
        @tagName(hparse_version),
        try llhttpVersion(record.major, record.minor),
    );
    try std.testing.expectEqual(hparse_count, record.header_count);
    try expectLlhttpHeadersMatch(hparse_headers[0..hparse_count], &record);
}

/// `diffRequestAgainstLlhttp` for the response side.
fn diffResponseAgainstLlhttp(
    g: []const u8,
    hparse_result: hparse.ParseRequestError!usize,
    hparse_version: hparse.Version,
    hparse_status: u16,
    hparse_msg: ?[]const u8,
    hparse_headers: *const [max_headers]hparse.Header,
    hparse_count: usize,
) !void {
    @disableInstrumentation();

    var record: LlhttpRecord = .{};
    const reference_consumed = runLlhttp(g, llhttp.HTTP_RESPONSE, &record);

    const consumed = hparse_result catch return;
    const reference_n = reference_consumed orelse return;

    try std.testing.expectEqual(consumed, reference_n);
    try std.testing.expectEqual(hparse_status, record.status_code);
    try std.testing.expectEqualStrings(
        @tagName(hparse_version),
        try llhttpVersion(record.major, record.minor),
    );
    if (record.status.fragmented) return error.ReferenceSpanFragmented;
    // llhttp consumes exactly one space after the status code and keeps any others;
    // hparse and picohttpparser both skip the whole run. As with the header-value
    // trim, this is a representation difference and not a normalization: only spaces
    // hparse is documented to skip are dropped here.
    try std.testing.expectEqualStrings(
        hparse_msg orelse "",
        std.mem.trimStart(u8, record.status.bytes(), " "),
    );
    try std.testing.expectEqual(hparse_count, record.header_count);
    try expectLlhttpHeadersMatch(hparse_headers[0..hparse_count], &record);
}

fn checkRequest(input: []const u8) !void {
    @disableInstrumentation();
    const g = primary.copy(input);

    var method: hparse.Method = .unknown;
    var method_token: ?[]const u8 = null;
    var path: ?[]const u8 = null;
    var version: hparse.Version = .@"1.0";
    var headers: [max_headers]hparse.Header = undefined;
    var count: usize = 0;

    // Memory-safety oracle: any overread during this call faults on the guard page.
    const one_shot = hparse.parseRequest(g, &method, &method_token, &path, &version, &headers, &count);

    try diffRequestTiers(g, one_shot, method, method_token, path, version, &headers, count);
    try diffRequestAgainstPico(g, one_shot, method_token, path, version, &headers, count);
    try diffRequestAgainstLlhttp(g, one_shot, method_token, path, version, &headers, count);

    if (one_shot == error.Invalid or one_shot == error.TooManyHeaders) {
        // The direction that matters most for a proxy and was previously
        // unchecked: the resumable path must never ACCEPT a message the
        // one-shot path refuses. Incomplete is fine — it means "still waiting"
        // — but a success here would be two parsers disagreeing about whether
        // a request exists at all.
        try expectResumeRejects(g);
        return;
    }
    const n = one_shot catch return;

    // Cheap invariants on every successful parse.
    try std.testing.expect(n <= g.len);
    try std.testing.expect(count <= max_headers);
    try std.testing.expect(method != .unknown);
    try std.testing.expect(method_token != null);
    try std.testing.expect(method_token.?.len >= 1);
    try expectWithin(g, method_token.?);
    try std.testing.expect(path != null);
    try expectWithin(g, path.?);
    for (headers[0..count]) |h| {
        try expectWithin(g, h.key);
        try expectWithin(g, h.value);
    }

    // Resume oracle: feeding the SAME bytes in growing prefixes through
    // `parseRequestResume` must reach the identical answer. The resume cursor
    // carries parser state across calls, so it is the one part of this parser
    // whose correctness depends on history rather than on the current slice —
    // exactly the shape a one-shot fuzz oracle cannot reach.
    //
    // Stepped rather than byte-at-a-time so long inputs stay affordable; the
    // unit tests in root.zig cover every step size on fixed shapes.
    //
    // KNOWN GAP: these calls take sub-slices of the guarded region, so only
    // the final full-length one abuts the PROT_NONE page — an overread by an
    // intermediate call lands on the rest of the real input and goes unseen.
    // The truncation oracle below re-copies each prefix for exactly that
    // reason, which this cannot do: `copy` places bytes at the page's tail, so
    // re-copying a prefix would move the bytes already parsed and break the
    // `Resume` contract. Closing it needs a second, head-first region.
    {
        const step = @max(1, g.len / 16);
        var state: hparse.Resume = .{};
        var r_method: hparse.Method = .unknown;
        var r_token: ?[]const u8 = null;
        var r_path: ?[]const u8 = null;
        var r_version: hparse.Version = .@"1.0";
        var r_headers: [max_headers]hparse.Header = undefined;
        var r_count: usize = 0;
        var have: usize = 0;
        var resumed: ?usize = null;

        while (have < g.len) {
            have = @min(have + step, g.len);
            if (hparse.parseRequestResume(
                g[0..have],
                &state,
                &r_method,
                &r_token,
                &r_path,
                &r_version,
                &r_headers,
                &r_count,
            )) |consumed| {
                resumed = consumed;
                break;
            } else |err| switch (err) {
                error.Incomplete => {
                    // The cursor must never rewind or run past what it was given.
                    try std.testing.expect(state.offset <= have);
                    try std.testing.expect(state.scanned >= state.offset);
                    try std.testing.expect(state.scanned <= have);
                    continue;
                },
                // A prefix may legitimately be rejected earlier than the whole,
                // but the whole parsed, so a hard error here is a divergence.
                else => return error.ResumeDivergedOnError,
            }
        }

        try std.testing.expect(resumed != null);
        try std.testing.expectEqual(n, resumed.?);
        try std.testing.expectEqual(method, r_method);
        try std.testing.expectEqual(version, r_version);
        try std.testing.expectEqual(count, r_count);
        try std.testing.expectEqualStrings(path.?, r_path.?);
        try std.testing.expectEqualStrings(method_token.?, r_token.?);
        // The resumed slices must point into the message too, not at whatever
        // an earlier call happened to leave behind.
        try expectWithin(g, r_path.?);
        try expectWithin(g, r_token.?);
        for (headers[0..count], r_headers[0..r_count]) |a, b| {
            try std.testing.expectEqualStrings(a.key, b.key);
            try std.testing.expectEqualStrings(a.value, b.value);
        }
    }

    // Consumed-length round-trip: re-parsing exactly the N consumed bytes must give a
    // byte-identical result — proves the parse never depended on bytes past what it
    // claims to consume.
    {
        const g2 = probe.copy(input[0..n]);
        var method2: hparse.Method = .unknown;
        var method_token2: ?[]const u8 = null;
        var path2: ?[]const u8 = null;
        var version2: hparse.Version = .@"1.0";
        var headers2: [max_headers]hparse.Header = undefined;
        var count2: usize = 0;

        const n2 = try hparse.parseRequest(g2, &method2, &method_token2, &path2, &version2, &headers2, &count2);
        try std.testing.expectEqual(n, n2);
        try std.testing.expectEqual(method, method2);
        try std.testing.expectEqualStrings(method_token.?, method_token2.?);
        try std.testing.expectEqual(version, version2);
        try std.testing.expect(path2 != null);
        try std.testing.expectEqualStrings(path.?, path2.?);
        try std.testing.expectEqual(count, count2);
        for (headers[0..count], headers2[0..count]) |h1, h2| {
            try std.testing.expectEqualStrings(h1.key, h2.key);
            try std.testing.expectEqualStrings(h1.value, h2.value);
        }
    }

    // No false accept on truncation: every strict prefix of the consumed bytes must be
    // `error.Incomplete`. `error.Invalid` here means the matcher tier picked for the
    // shorter tail (SIMD vs scalar) judged the same bytes differently.
    for (0..n) |k| {
        const gk = probe.copy(input[0..k]);
        var mk: hparse.Method = .unknown;
        var mtk: ?[]const u8 = null;
        var pk: ?[]const u8 = null;
        var vk: hparse.Version = .@"1.0";
        var hk: [max_headers]hparse.Header = undefined;
        var ck: usize = 0;

        try std.testing.expectError(
            error.Incomplete,
            hparse.parseRequest(gk, &mk, &mtk, &pk, &vk, &hk, &ck),
        );
    }
}

fn checkResponse(input: []const u8) !void {
    @disableInstrumentation();
    const g = primary.copy(input);

    var version: hparse.Version = .@"1.0";
    var status_code: u16 = 0;
    var status_msg: ?[]const u8 = null;
    var headers: [max_headers]hparse.Header = undefined;
    var count: usize = 0;

    // Memory-safety oracle: any overread during this call faults on the guard page.
    const one_shot = hparse.parseResponse(g, &version, &status_code, &status_msg, &headers, &count);
    try diffResponseTiers(g, one_shot, version, status_code, status_msg, &headers, count);
    try diffResponseAgainstPico(g, one_shot, version, status_code, status_msg, &headers, count);
    try diffResponseAgainstLlhttp(g, one_shot, version, status_code, status_msg, &headers, count);
    const n = one_shot catch return;

    // Cheap invariants on every successful parse.
    try std.testing.expect(n <= g.len);
    try std.testing.expect(count <= max_headers);
    try std.testing.expect(status_code <= 999);
    if (status_msg) |msg| try expectWithin(g, msg);
    for (headers[0..count]) |h| {
        try expectWithin(g, h.key);
        try expectWithin(g, h.value);
    }

    // Resume oracle, the response half. `parseResponseResume` shares
    // `parseHeadersResume` with the request path, but nothing exercised it
    // here at all — half of the new code was unfuzzed.
    {
        const step = @max(1, g.len / 16);
        var state: hparse.Resume = .{};
        var r_version: hparse.Version = .@"1.0";
        var r_status: u16 = 0;
        var r_msg: ?[]const u8 = null;
        var r_headers: [max_headers]hparse.Header = undefined;
        var r_count: usize = 0;
        var have: usize = 0;
        var resumed: ?usize = null;

        while (have < g.len) {
            have = @min(have + step, g.len);
            if (hparse.parseResponseResume(
                g[0..have],
                &state,
                &r_version,
                &r_status,
                &r_msg,
                &r_headers,
                &r_count,
            )) |consumed| {
                resumed = consumed;
                break;
            } else |err| switch (err) {
                error.Incomplete => {
                    try std.testing.expect(state.scanned >= state.offset);
                    try std.testing.expect(state.scanned <= have);
                    continue;
                },
                else => return error.ResumeDivergedOnError,
            }
        }

        try std.testing.expect(resumed != null);
        try std.testing.expectEqual(n, resumed.?);
        try std.testing.expectEqual(version, r_version);
        try std.testing.expectEqual(status_code, r_status);
        try std.testing.expectEqual(count, r_count);
        for (headers[0..count], r_headers[0..r_count]) |a, b| {
            try std.testing.expectEqualStrings(a.key, b.key);
            try std.testing.expectEqualStrings(a.value, b.value);
            try expectWithin(g, b.key);
            try expectWithin(g, b.value);
        }
    }

    // Consumed-length round-trip (see checkRequest).
    {
        const g2 = probe.copy(input[0..n]);
        var version2: hparse.Version = .@"1.0";
        var status_code2: u16 = 0;
        var status_msg2: ?[]const u8 = null;
        var headers2: [max_headers]hparse.Header = undefined;
        var count2: usize = 0;

        const n2 = try hparse.parseResponse(g2, &version2, &status_code2, &status_msg2, &headers2, &count2);
        try std.testing.expectEqual(n, n2);
        try std.testing.expectEqual(version, version2);
        try std.testing.expectEqual(status_code, status_code2);
        try std.testing.expectEqual(status_msg == null, status_msg2 == null);
        if (status_msg) |msg| try std.testing.expectEqualStrings(msg, status_msg2.?);
        try std.testing.expectEqual(count, count2);
        for (headers[0..count], headers2[0..count]) |h1, h2| {
            try std.testing.expectEqualStrings(h1.key, h2.key);
            try std.testing.expectEqualStrings(h1.value, h2.value);
        }
    }

    // No false accept on truncation (see checkRequest).
    for (0..n) |k| {
        const gk = probe.copy(input[0..k]);
        var vk: hparse.Version = .@"1.0";
        var sck: u16 = 0;
        var smk: ?[]const u8 = null;
        var hk: [max_headers]hparse.Header = undefined;
        var ck: usize = 0;

        try std.testing.expectError(
            error.Incomplete,
            hparse.parseResponse(gk, &vk, &sck, &smk, &hk, &ck),
        );
    }
}

/// Bias the generator toward HTTP's structural bytes, not uniform noise.
const byte_weights = [_]std.testing.Smith.Weight{
    .rangeAtMost(u8, 0x00, 0xff, 1), // any byte
    .rangeAtMost(u8, 0x20, 0x7e, 4), // printable ASCII
    .value(u8, '\r', 4),
    .value(u8, '\n', 4),
    .value(u8, ':', 3),
    .value(u8, ' ', 3),
    .value(u8, '\t', 2),
    .value(u8, '/', 2),
};

fn fuzzParseRequest(_: void, smith: *std.testing.Smith) !void {
    @disableInstrumentation();
    var buf: [max_input]u8 = undefined;
    const len = smith.sliceWeightedBytes(&buf, &byte_weights);
    try checkRequest(buf[0..len]);
}

fn fuzzParseResponse(_: void, smith: *std.testing.Smith) !void {
    @disableInstrumentation();
    var buf: [max_input]u8 = undefined;
    const len = smith.sliceWeightedBytes(&buf, &byte_weights);
    try checkResponse(buf[0..len]);
}

/// Corpus entries are consumed in Smith's serialized form: `sliceWeightedBytes` reads a
/// 4-byte little-endian length before the bytes. Raw HTTP text as a corpus entry would
/// have its first 4 bytes eaten as that length, so encode seeds explicitly.
fn seed(comptime s: []const u8) []const u8 {
    comptime {
        var out: [4 + s.len]u8 = undefined;
        std.mem.writeInt(u32, out[0..4], s.len, .little);
        @memcpy(out[4..], s);
        const final = out;
        return &final;
    }
}

const request_corpus = [_][]const u8{
    "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    "GET / HTTP/1.1\n\n", // bare LF terminators (must reject)
    "OPTIONS /hey-this-is-kinda-long-path HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    "POST /submit HTTP/1.0\r\nContent-Length: 5\r\n\r\nhello",
    "DELETE /a/b/c?q=1&r=2#frag HTTP/1.1\r\nAccept: */*\r\n\r\n",
    "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\n",
    "PATCH /x HTTP/1.1\r\nX:\ta\tb \t \r\n\r\n", // OWS/HTAB edge cases
    "GET / HTTP/1.1\r\nA: 1\r\nB: 2\r\nC: 3\r\nD: 4\r\n\r\n",
    "GET /index.html HTTP/1.1\r\nUser-Agent: Mozilla/5.0 (X11; Linux x86_64) ~zh;q=0.9,*~\r\n\r\n",
    "GET / HTTP/1.1\r\nHost", // truncated header key
    "GET /aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", // truncated path
    "TRACE / HTTP/1.1\r\nA B: v\r\n\r\n", // space in key (must reject)
    "PROPFIND /dav HTTP/1.1\r\nDepth: 0\r\n\r\n", // extension method
    "M-SEARCH * HTTP/1.1\r\n\r\n", // extension method with tchar '-'
    "POSTER /x HTTP/1.1\r\n\r\n", // registered-method prefix collision
};

const response_corpus = [_][]const u8{
    "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
    "HTTP/1.1 418 I'm a teapot\r\nHost: localhost\r\nSome-Number-Sequence: 123291429\r\n\r\n",
    "HTTP/1.0 204\r\n\r\n", // no status message
    "HTTP/1.1 301   Moved Permanently\n\n", // multiple spaces + bare LF (must reject)
    // The same multiple spaces, accepted. llhttp consumes exactly one of them and
    // keeps the rest in its status span where hparse skips the whole run, so this is
    // the only corpus entry that reaches the trim in `diffResponseAgainstLlhttp`.
    "HTTP/1.1 301   Moved Permanently\r\nLocation: /x  \t\r\n\r\n",
    "HTTP/1.1 200 OK\r\nHost: x", // truncated header value
};

/// Length-prefixes a whole array of raw messages, so `corpus_llhttp.zig` can stay
/// plain data and the Smith encoding stays a concern of this file alone.
fn seedAll(comptime inputs: []const []const u8) [inputs.len][]const u8 {
    comptime {
        var out: [inputs.len][]const u8 = undefined;
        for (inputs, 0..) |s, i| out[i] = seed(s);
        const final = out;
        return final;
    }
}

// The hand-written seeds above pin the shapes this parser's own invariants turn on
// and are worth reading; llhttp's are breadth, and there are two hundred of them.
// Keeping them in separate arrays means the curated list stays legible.
const all_request_inputs = request_corpus ++ corpus_llhttp.requests;
const all_response_inputs = response_corpus ++ corpus_llhttp.responses;
const all_request_corpus = seedAll(&all_request_inputs);
const all_response_corpus = seedAll(&all_response_inputs);

test "fuzz parseRequest" {
    return std.testing.fuzz({}, fuzzParseRequest, .{ .corpus = &all_request_corpus });
}

test "fuzz parseResponse" {
    return std.testing.fuzz({}, fuzzParseResponse, .{ .corpus = &all_response_corpus });
}

/// What each parser made of `g`: hparse, picohttpparser, llhttp. Accepted a
/// complete message, or did not.
fn requestVerdicts(g: []const u8) [3]bool {
    @disableInstrumentation();
    var method: hparse.Method = .unknown;
    var token: ?[]const u8 = null;
    var path: ?[]const u8 = null;
    var version: hparse.Version = .@"1.0";
    var headers: [max_headers]hparse.Header = undefined;
    var count: usize = 0;
    const ours = if (hparse.parseRequest(g, &method, &token, &path, &version, &headers, &count)) |_| true else |_| false;

    var p_method: [*c]const u8 = null;
    var p_method_len: usize = 0;
    var p_path: [*c]const u8 = null;
    var p_path_len: usize = 0;
    var p_minor: c_int = -1;
    var p_headers: [max_headers]pico.phr_header = undefined;
    var p_count: usize = max_headers;
    const theirs = pico.phr_parse_request(@ptrCast(g.ptr), g.len, &p_method, &p_method_len, &p_path, &p_path_len, &p_minor, &p_headers, &p_count, 0) >= 0;

    var record: LlhttpRecord = .{};
    return .{ ours, theirs, runLlhttp(g, llhttp.HTTP_REQUEST, &record) != null };
}

/// `requestVerdicts` for the response side.
fn responseVerdicts(g: []const u8) [3]bool {
    @disableInstrumentation();
    var version: hparse.Version = .@"1.0";
    var status: u16 = 0;
    var msg: ?[]const u8 = null;
    var headers: [max_headers]hparse.Header = undefined;
    var count: usize = 0;
    const ours = if (hparse.parseResponse(g, &version, &status, &msg, &headers, &count)) |_| true else |_| false;

    var p_minor: c_int = -1;
    var p_status: c_int = -1;
    var p_msg: [*c]const u8 = null;
    var p_msg_len: usize = 0;
    var p_headers: [max_headers]pico.phr_header = undefined;
    var p_count: usize = max_headers;
    const theirs = pico.phr_parse_response(@ptrCast(g.ptr), g.len, &p_minor, &p_status, &p_msg, &p_msg_len, &p_headers, &p_count, 0) >= 0;

    var record: LlhttpRecord = .{};
    return .{ ours, theirs, runLlhttp(g, llhttp.HTTP_RESPONSE, &record) != null };
}

fn findEntry(snapshot: []const disagreements.Entry, input: []const u8) ?disagreements.Entry {
    @disableInstrumentation();
    for (snapshot) |e| {
        if (std.mem.eql(u8, e.input, input)) return e;
    }
    return null;
}

fn corpusHas(corpus: []const []const u8, input: []const u8) bool {
    @disableInstrumentation();
    for (corpus) |c| {
        if (std.mem.eql(u8, c, input)) return true;
    }
    return false;
}

/// Prints an input as a Zig string literal, so a NEW line can be pasted straight
/// into `disagreements.zig`.
fn printLiteral(s: []const u8) void {
    @disableInstrumentation();
    for (s) |c| switch (c) {
        '\r' => std.debug.print("\\r", .{}),
        '\n' => std.debug.print("\\n", .{}),
        '\t' => std.debug.print("\\t", .{}),
        '"' => std.debug.print("\\\"", .{}),
        '\\' => std.debug.print("\\\\", .{}),
        0x20...0x21, 0x23...0x5b, 0x5d...0x7e => std.debug.print("{c}", .{c}),
        else => std.debug.print("\\x{x:0>2}", .{c}),
    };
}

/// Recomputes which corpus inputs the three parsers disagree about and holds it
/// against `disagreements.zig`.
///
/// Keyed by input rather than by position, so adding a corpus seed reports one new
/// line instead of reshuffling forty-four. The output is a delta for the same
/// reason the snapshot is not regenerated in bulk: the `why` lines are the only
/// part of that file that cannot be recomputed, and a bulk rewrite would drop them.
fn checkDisagreements(
    comptime is_request: bool,
    corpus: []const []const u8,
    snapshot: []const disagreements.Entry,
) !usize {
    @disableInstrumentation();
    const side = if (is_request) "request" else "response";
    var problems: usize = 0;

    for (corpus) |input| {
        if (input.len > max_input) continue;
        const g = primary.copy(input);
        const v = if (is_request) requestVerdicts(g) else responseVerdicts(g);
        const unanimous = v[0] == v[1] and v[1] == v[2];
        const entry = findEntry(snapshot, input);

        if (unanimous) {
            if (entry != null) {
                problems += 1;
                std.debug.print("\n  RESOLVED ({s}): all three now agree — delete this entry:\n    \"", .{side});
                printLiteral(input);
                std.debug.print("\"\n", .{});
            }
            continue;
        }

        const e = entry orelse {
            problems += 1;
            std.debug.print(
                "\n  NEW ({s}): an unjustified disagreement. Explain it, then add:\n" ++
                    "    .{{ .hparse = {}, .pico = {}, .llhttp = {}, .why = \"EXPLAIN THIS\", .input = \"",
                .{ side, v[0], v[1], v[2] },
            );
            printLiteral(input);
            std.debug.print("\" }},\n", .{});
            if (v[0] and !v[1] and !v[2]) {
                std.debug.print(
                    "    ^ hparse is the ONLY parser accepting this. That was the tchar bug's\n" ++
                        "      signature — treat it as a bug in hparse until proven otherwise.\n",
                    .{},
                );
            }
            continue;
        };

        if (e.hparse != v[0] or e.pico != v[1] or e.llhttp != v[2]) {
            problems += 1;
            std.debug.print(
                "\n  CHANGED ({s}): was h={} p={} l={}, now h={} p={} l={}:\n    \"",
                .{ side, e.hparse, e.pico, e.llhttp, v[0], v[1], v[2] },
            );
            printLiteral(input);
            std.debug.print("\"\n", .{});
        }
    }

    for (snapshot) |e| {
        if (corpusHas(corpus, e.input)) continue;
        problems += 1;
        std.debug.print("\n  ORPHAN ({s}): no corpus seed has these bytes any more — delete this entry:\n    \"", .{side});
        printLiteral(e.input);
        std.debug.print("\"\n", .{});
    }

    return problems;
}

test "reference disagreements match the checked-in snapshot" {
    var problems = try checkDisagreements(true, &all_request_inputs, &disagreements.requests);
    problems += try checkDisagreements(false, &all_response_inputs, &disagreements.responses);

    // An unexplained entry is the state this whole file exists to prevent, so it
    // fails the same way an unrecorded disagreement does.
    for (disagreements.requests ++ disagreements.responses) |e| {
        if (e.why.len != 0 and !std.mem.eql(u8, e.why, "EXPLAIN THIS") and !std.mem.eql(u8, e.why, "TODO")) continue;
        problems += 1;
        std.debug.print("\n  UNJUSTIFIED: an entry still has a placeholder `why`:\n    \"", .{});
        printLiteral(e.input);
        std.debug.print("\"\n", .{});
    }

    if (problems != 0) {
        std.debug.print(
            "\n  {d} disagreement(s) moved. Edit src/disagreements.zig by hand — the\n" ++
                "  existing `why` lines are not reproducible and must survive.\n\n",
            .{problems},
        );
        return error.DisagreementSnapshotStale;
    }
}
