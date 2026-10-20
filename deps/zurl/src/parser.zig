//! HTTP/1.x response parsing: a head, then framed body delivery to a sink.
//!
//! The parser owns framing entirely (docs/DESIGN.md rule 2). The caller never
//! sees an undecoded byte: content-length bodies, chunked bodies (including
//! trailers) and close-delimited bodies all arrive at the sink as the same
//! logical byte stream. This is the property whose absence cost the zgix
//! benchmark months of silently corrupted cAdvisor scrapes.
//!
//! Zero allocation, by construction rather than effort: nothing here takes an
//! allocator. Head lines are parsed in place inside the reader's buffer;
//! bodies stream through `Io.Reader.streamExact64`/`streamRemaining` without
//! ever being held whole.
//!
//! Every assertion in this file states an INTERNAL invariant. Every byte it
//! reads was written by someone else, so a malformed status line is expected
//! input and returns an error: an assertion a remote server can trip is a
//! remote panic, and it would vanish from the ReleaseFast build a consumer is
//! free to choose. Errors survive every build mode; assertions do not.

const std = @import("std");
const hparse = @import("hparse");
const Io = std.Io;
const assert = std.debug.assert;

/// The most header fields one response head may carry.
///
/// hparse writes spans into a caller-supplied array and reports
/// `TooManyHeaders` rather than growing one, which is the same bargain as every
/// other buffer here: a stated bound and no allocation. 128 fields is far more
/// than any origin sends and costs 4 KiB of stack frame.
pub const headers_max = 128;

pub const Error = error{
    MalformedStatusLine,
    MalformedHeader,
    MalformedChunk,
    /// A head (or trailer) line exceeded the reader's buffer, or the head as a
    /// whole exceeded `max_head_bytes`. Never truncated (rule 7): the caller
    /// gets an error, not a clipped header.
    HeadTooLong,
    UnexpectedEof,
    ReadFailed,
    /// The body carries a `content-encoding` zurl does not decode, and the
    /// caller did not ask for it undecoded. Refused rather than passed
    /// through: rule 2 says the caller never sees an undecoded byte, and
    /// handing compressed bytes to a sink expecting text is exactly the
    /// incident this library exists for.
    UnsupportedContentEncoding,
    /// The SINK failed, not the transport. Distinct on purpose: a full collect
    /// buffer and a dead connection demand different reactions.
    WriteFailed,
};

pub const Head = struct {
    status: u16,
    /// Raw bytes this head occupied on the wire: the status line, every header
    /// line, and the blank line that ends them, terminators included.
    ///
    /// Exposed because a byte counter cannot reconstruct it. Everything else
    /// here describes what the head MEANT; this is what it COST, and a caller
    /// reporting throughput off the wire (zrk's `Transfer/sec`, which is wrk's)
    /// needs the head's share of it as much as the body's. `Body.wire_len` is
    /// the other half; the two sum to what the exchange took off the transport.
    ///
    /// A `usize` rather than a `u64`: it is bounded by `max_head_bytes`, which
    /// is a buffer bound and therefore a machine-word quantity — unlike a body
    /// length, which is bounded by nothing this side of the wire.
    head_len: usize,
    /// The status line began "HTTP/1.1". Decides the keep-alive default.
    http11: bool,
    /// What the head SAID. The final verdict is `Body.keep_alive`, because a
    /// close-delimited body forces false regardless of any header.
    keep_alive: bool,
    content_length: ?u64 = null,
    chunked: bool = false,
    /// The origin named a `content-encoding` other than `identity`, so the
    /// body on the wire is NOT the body the caller asked for.
    ///
    /// A bool rather than the name, because the name is a slice of the
    /// reader's buffer and would dangle the moment the body streams.
    encoded_body: bool = false,

    /// RFC 9112 §6.3: HEAD responses and 1xx/204/304 statuses never carry a
    /// body, whatever Content-Length or Transfer-Encoding claim. Consuming a
    /// body there eats into the next response and breaks framing — this is
    /// ziglang/zig#25181, open at `urgent` in std.http.Client today.
    pub fn bodyless(h: Head, method: std.http.Method) bool {
        // Only ever called on a head `parseHead` returned, which range-checked
        // the status; the class division below is meaningless without it.
        assert(h.status >= 100);
        assert(h.status <= 999);

        return method == .HEAD or h.status / 100 == 1 or h.status == 204 or h.status == 304;
    }
};

/// Slices are valid ONLY for the duration of the call — they point into the
/// reader's buffer, which the body stream will overwrite.
pub const HeaderFn = *const fn (ctx: ?*anyopaque, name: []const u8, value: []const u8) void;

pub const HeadOptions = struct {
    /// Called once per header line, and again for chunked trailers. Names are
    /// as sent; values are trimmed of leading/trailing space and tab.
    on_header: ?HeaderFn = null,
    ctx: ?*anyopaque = null,
    /// Hand the sink a body still in its `content-encoding`, instead of
    /// refusing it.
    ///
    /// Named to be conspicuous in a diff. zurl decodes no content codings, so
    /// with this set a `gzip` body reaches the sink as gzip — which is fine
    /// when the caller is writing it to a file, and is the cAdvisor incident
    /// rebuilt when the caller is a `LineSink` expecting text.
    allow_encoded_body: bool = false,
    /// Budget for the status line plus all headers (and, separately reused,
    /// all trailers), counted in raw bytes including line endings.
    max_head_bytes: usize = max_head_bytes_default,

    /// One constant so `client.FetchRequest` can default to the same bound
    /// without restating the number.
    pub const max_head_bytes_default: usize = 64 * 1024;
};

pub const Body = struct {
    /// Decoded length: what reached the sink. Chunk framing is not in it,
    /// because chunk framing is not the body.
    len: u64,
    /// Raw bytes the body cost on the wire, chunk-size lines, their CRLFs and
    /// any trailer section included. Equal to `len` for a content-length or
    /// close-delimited body, strictly greater for a chunked one, zero for a
    /// bodyless reply.
    ///
    /// Separate from `len` because the two answer different questions and a
    /// caller that conflates them is wrong in one of them: a byte-throughput
    /// meter wants this one, and a caller sizing what it received wants `len`.
    wire_len: u64,
    /// The connection's fate: the head's verdict, downgraded to false when the
    /// body ran to connection close (nothing further can be framed).
    keep_alive: bool,
};

/// Read the status line and headers, through the blank line.
///
/// The head must arrive WHOLE inside the reader's buffer. hparse scans a
/// contiguous slice, so the buffer bounds the entire head rather than only the
/// longest line as the hand-rolled scanner did; `max_head_bytes` bounds it
/// again, and whichever is smaller wins. A server spewing endless valid-sized
/// header lines still terminates, now against a bound one line earlier.
///
/// Segmentation cannot change the answer (rule 4). hparse's `Resume` carries
/// the scan position through a partial parse, so a head arriving one byte at a
/// time is scanned once, not once per segment — that quadratic re-scan is the
/// whole reason the dependency was worth taking. docs/RESEARCH.md has the
/// numbers.
pub fn parseHead(r: *Io.Reader, opts: HeadOptions) Error!Head {
    // Both are bounds the caller chose. A zero for either means no head can
    // ever parse, which is a caller bug, not a bad server.
    assert(opts.max_head_bytes > 0);
    assert(r.buffer.len > 0);

    // `undefined`, and a local rather than a field of `Scan`: see Scan.
    var headers: [headers_max]hparse.Header = undefined;
    var scan: Scan = .{};
    const consumed = try scanHead(r, opts, &scan, &headers);

    // RFC 9112 §4: exactly three digits, so every status lands in a 1xx..5xx
    // class bucket and `bodyless` can divide by 100.
    if (scan.status < 100 or scan.status > 999) return error.MalformedStatusLine;
    assert(consumed <= r.bufferedLen());

    var head: Head = .{
        .status = scan.status,
        // What `scanHead` consumed IS the head, by its own postcondition: it
        // returns only when hparse has parsed a complete one out of the window.
        .head_len = consumed,
        .http11 = scan.version == .@"1.1",
        // HTTP/1.1 defaults to keep-alive; 1.0 defaults to close.
        .keep_alive = scan.version == .@"1.1",
    };

    for (headers[0..scan.header_count]) |field| {
        try applyFraming(&head, field.key, field.value);
        if (opts.on_header) |f| f(opts.ctx, field.key, field.value);
    }

    // Only now. Every slice above points into the reader's buffer, and tossing
    // is what lets the body stream overwrite it.
    r.toss(consumed);

    // Range-checked above, and `applyFraming` never touches the status.
    assert(head.status >= 100);
    assert(head.status <= 999);
    return head;
}

/// Everything `scanHead` fills in, so that `parseHead` can hand hparse one
/// pointer instead of six and still fit in a screen.
///
/// The 128-entry header array is deliberately NOT a field here. Defaulting a
/// 4 KiB array inside a `= .{}` struct literal makes the compiler materialise
/// an initialiser for it on every parse, which cost 5x on small-cl and 10x on
/// zrk-1k when this struct was first written that way — caught by bench-parse,
/// exactly as rule 8 intends. It stays an `undefined` local in `parseHead` and
/// is passed by pointer, which also satisfies hparse's `Resume` contract that
/// every resumed call see the SAME array.
const Scan = struct {
    state: hparse.Resume = .{},
    header_count: usize = 0,
    version: hparse.Version = .@"1.0",
    status: u16 = 0,
    /// hparse writes the reason phrase whether or not anyone wants it; `Head`
    /// has no field for it and nothing reads it. Kept only because the API is
    /// positional, not because it is a forgotten wire-up.
    status_msg: ?[]const u8 = null,
};

/// Grow the reader's buffer until hparse can parse a whole head out of it, and
/// return how many bytes that head occupies.
///
/// ## What stops this
///
/// The caller's whole-request deadline (rule 3), NOT a byte count — and the
/// difference is worth stating because two of the three exits look like byte
/// counts and the third is not.
///
/// The budget guard and the full-buffer guard both fire after a finite number
/// of PRODUCTIVE reads, because each of those adds at least one byte. But
/// `Io.Reader.fillMore` documents that it "may result in zero bytes added to
/// the buffer, which is not an end of stream condition": a TLS transport
/// consuming a NewSessionTicket or KeyUpdate record does exactly that, and a
/// peer willing to send those forever keeps this loop running without ever
/// tripping either guard.
///
/// That is bounded by the peer's own bandwidth rather than by us — every such
/// pass consumes a record the peer had to send — which is the same bargain
/// `streamChunked` already makes: a slow origin and a malicious one differ in
/// duration, not in shape, and only the caller knows which it asked for.
/// `fetch` supplies rule 3's deadline; a caller driving `Connection` directly
/// owns that choice, and this is where it gets spent.
fn scanHead(
    r: *Io.Reader,
    opts: HeadOptions,
    scan: *Scan,
    headers: *[headers_max]hparse.Header,
) Error!usize {
    assert(opts.max_head_bytes > 0);
    assert(r.buffer.len > 0);

    // lint:unbounded-ok — see this function.s doc comment: bounded by the
    // caller.s deadline (rule 3), not by a byte count, because fillMore may
    // legitimately add zero bytes without signalling end of stream.
    while (true) {
        // The budget caps what the HEAD may consume, so the window handed to
        // hparse is capped too — not the reader's buffered length, which also
        // holds however much of the body has arrived. Testing the latter made
        // the verdict depend on how much turned up in one read, which is rule
        // 4's exact prohibition; the fuzz oracle caught it on the first run.
        const buffered = r.buffered();
        const window = buffered[0..@min(buffered.len, opts.max_head_bytes)];

        if (hparse.parseResponseResume(
            window,
            &scan.state,
            &scan.version,
            &scan.status,
            &scan.status_msg,
            headers,
            &scan.header_count,
        )) |consumed| {
            assert(consumed <= window.len);
            return consumed;
        } else |err| switch (err) {
            // hparse reports one `Invalid` for the whole head. `line_done` is
            // what says which half of this file's taxonomy it belongs to: it
            // is set the moment the status line parses, so still-false means
            // the status line is what failed.
            error.Invalid => return if (scan.state.line_done)
                error.MalformedHeader
            else
                error.MalformedStatusLine,
            // Rule 7: refused whole, never clipped to the first 128 fields.
            error.TooManyHeaders => return error.HeadTooLong,
            error.Incomplete => {},
        }

        // A head still unterminated after spending its whole budget, or with
        // nowhere left to put more bytes, has outgrown its bound rather than
        // arrived slowly — and the distinction matters, because one is the
        // peer's fault and the other is a timeout.
        if (window.len == opts.max_head_bytes) return error.HeadTooLong;
        if (r.bufferedLen() == r.buffer.len) return error.HeadTooLong;

        r.fillMore() catch |err| switch (err) {
            error.EndOfStream => return error.UnexpectedEof,
            error.ReadFailed => return error.ReadFailed,
        };
    }
}

/// Fold one header field into the head's framing decision.
///
/// Rule 2: this is the only place a header changes how the body is read, and
/// it is deliberately separate from the scan that produced the field — hparse
/// decides what a header IS, zurl decides what it MEANS.
fn applyFraming(head: *Head, name: []const u8, value: []const u8) Error!void {
    // hparse rejects an empty field name before it ever reaches here, so this
    // states what the parse established rather than trusting the peer.
    assert(name.len > 0);
    assert(head.status >= 100);

    if (std.ascii.eqlIgnoreCase(name, "content-length")) {
        const n = std.fmt.parseInt(u64, value, 10) catch return error.MalformedHeader;
        if (head.content_length) |prev| {
            // Duplicate Content-Length: equal copies are tolerated (some
            // proxies stack them), a DISAGREEMENT is the request-smuggling
            // primitive and is refused outright.
            if (prev != n) return error.MalformedHeader;
        }
        head.content_length = n;
    } else if (std.ascii.eqlIgnoreCase(name, "content-encoding")) {
        // `identity` means "no coding applied" and is the one value that
        // needs nothing. Anything else — including a LIST like "gzip, br",
        // which is why this is not an equality test against known names --
        // means the bytes on the wire are not the bytes the caller wants.
        // Recorded here and refused in `streamBody`, because whether it
        // matters depends on whether a body is coming at all.
        const identity = std.ascii.eqlIgnoreCase(std.mem.trim(u8, value, " \t"), "identity");
        if (!identity and value.len > 0) head.encoded_body = true;
    } else if (std.ascii.eqlIgnoreCase(name, "transfer-encoding")) {
        if (containsTokenIgnoreCase(value, "chunked")) head.chunked = true;
    } else if (std.ascii.eqlIgnoreCase(name, "connection")) {
        if (containsTokenIgnoreCase(value, "close")) {
            head.keep_alive = false;
        } else if (containsTokenIgnoreCase(value, "keep-alive")) {
            head.keep_alive = true;
        }
    }
}

/// Deliver the body (decoded, if chunked) to `sink`, per the head's framing.
///
/// Precedence is RFC 9112 §6.3: Transfer-Encoding beats Content-Length —
/// when both are present the length header is a lie or an attack, and the
/// chunked framing is what the wire actually carries. Bodyless heads consume
/// nothing regardless of either header.
pub fn streamBody(
    r: *Io.Reader,
    head: Head,
    method: std.http.Method,
    sink: *Io.Writer,
    opts: HeadOptions,
) Error!Body {
    assert(opts.max_head_bytes > 0);

    // Bodyless FIRST, and the order is the whole subtlety. A HEAD response
    // echoes the headers its GET would have sent, `content-encoding` among
    // them, while carrying no body — so refusing on the header alone would
    // break every HEAD against a gzip-serving origin, and `ycs.head` is a
    // real caller. Nothing reaches a sink here, so nothing can be misread.
    if (head.bodyless(method)) return .{ .len = 0, .wire_len = 0, .keep_alive = head.keep_alive };

    // Rule 2: the caller never sees an undecoded byte. zurl decodes no
    // content codings, so the only honest answers are to refuse or to be told
    // explicitly that raw bytes are wanted.
    if (head.encoded_body and !opts.allow_encoded_body) return error.UnsupportedContentEncoding;

    if (head.chunked) {
        const chunked = try streamChunked(r, sink, opts);
        // Framing is never free: the zero-size chunk and its blank line alone
        // are five bytes, so a chunked body always costs more wire than it
        // delivers. Stated as an assertion because `wire_len` is what a
        // throughput meter reports, and an equality here would mean the
        // framing was counted as nothing.
        assert(chunked.wire_len > chunked.len);
        return .{ .len = chunked.len, .wire_len = chunked.wire_len, .keep_alive = head.keep_alive };
    }
    if (head.content_length) |len| {
        // Transfer-Encoding already won above, so a length that survives to
        // here is the whole framing: streamExact64 delivers exactly it, or
        // errors. There is no partial-body success to account for.
        assert(!head.chunked);
        r.streamExact64(sink, len) catch |err| return switch (err) {
            error.EndOfStream => error.UnexpectedEof,
            error.ReadFailed => error.ReadFailed,
            error.WriteFailed => error.WriteFailed,
        };
        // Content-length framing puts nothing on the wire around the body, so
        // the decoded length and the wire cost are the same number.
        return .{ .len = len, .wire_len = len, .keep_alive = head.keep_alive };
    }

    // No framing information: the body runs to connection close, which is
    // itself the reason the connection cannot be kept alive.
    assert(!head.chunked);
    assert(head.content_length == null);
    const n = r.streamRemaining(sink) catch |err| return switch (err) {
        error.ReadFailed => error.ReadFailed,
        error.WriteFailed => error.WriteFailed,
    };
    // Close-delimited: the body is every remaining byte, undecorated.
    return .{ .len = n, .wire_len = n, .keep_alive = false };
}

/// What a chunked body cost, decoded and on the wire. Two numbers because
/// chunk framing is the difference between them and no caller can rederive it.
const Chunked = struct { len: u64, wire_len: u64 };

fn streamChunked(r: *Io.Reader, sink: *Io.Writer, opts: HeadOptions) Error!Chunked {
    assert(opts.max_head_bytes > 0);

    var total: u64 = 0;
    var wire: u64 = 0;
    // lint:unbounded-ok — every pass consumes a chunk-size line and returns on
    // the zero-size chunk, so it either advances the stream or ends. A server
    // that streams chunks forever is bounded by the caller's whole-request
    // deadline (rule 3), not by a byte cap: a 1.5 MiB cAdvisor scrape and a
    // malicious stream differ in duration, not in shape, and only the caller
    // knows which one it asked for.
    while (true) {
        const size_budget_max: usize = 1024; // a chunk-size line is a hex number and maybe extensions
        var size_budget: usize = size_budget_max;
        const size_line = takeLine(r, &size_budget) catch return error.MalformedChunk;
        // takeLine charges the line's RAW size, terminator included, which is
        // exactly what the wire cost — so what it spent is what to count.
        wire += size_budget_max - size_budget;
        // Size is hex, optionally followed by ";extensions" (ignored).
        const semi = std.mem.indexOfScalar(u8, size_line, ';') orelse size_line.len;
        const size = std.fmt.parseInt(u64, std.mem.trim(u8, size_line[0..semi], " \t"), 16) catch
            return error.MalformedChunk;

        if (size == 0) {
            wire += try streamTrailers(r, opts);
            // The zero-size chunk's own line is already counted, and the
            // trailer section is at minimum the blank line that ends it.
            assert(wire > total);
            return .{ .len = total, .wire_len = wire };
        }

        // The zero-size chunk returned above, so every pass reaching here moves
        // the stream forward by at least one body byte — the loop's progress
        // guarantee, stated where it is made.
        assert(size > 0);
        r.streamExact64(sink, size) catch |err| return switch (err) {
            error.EndOfStream => error.MalformedChunk,
            error.ReadFailed => error.ReadFailed,
            error.WriteFailed => error.WriteFailed,
        };
        total += size;
        wire += size;

        // Each chunk's data is followed by CRLF — and by exactly that. The
        // hand-rolled reader this replaces ignored the line's content, which
        // let a desynchronised stream limp on to a stranger error later.
        const crlf_budget_max: usize = 8;
        var crlf_budget: usize = crlf_budget_max;
        const crlf = takeLine(r, &crlf_budget) catch return error.MalformedChunk;
        if (crlf.len != 0) return error.MalformedChunk;
        wire += crlf_budget_max - crlf_budget;
    }
}

/// The trailer section: header fields until the blank line, delivered through
/// the same callback as the head's, under a fresh head-sized budget. Returns
/// what it consumed, which is the section's share of `Body.wire_len`.
///
/// A trailer IS a header field (RFC 9112 §7.1.2), so it is held to the head's
/// rule AND reports the head's errors — a nameless field is
/// `error.MalformedHeader` here exactly as it is there, an over-long line is
/// `error.HeadTooLong` (which is what that error's own doc has always
/// claimed), and a truncated section is `error.UnexpectedEof` rather than a
/// vaguer complaint about chunk framing. One position-independent answer.
///
/// The fuzzer found both halves of the old behaviour: this section delivered
/// a nameless field that `parseHead` refuses, so the same bytes meant two
/// different things depending on where in the message they appeared; and the
/// validation sat inside the `on_header` branch, so whether a line was
/// inspected at all depended on whether the caller had installed a listener.
fn streamTrailers(r: *Io.Reader, opts: HeadOptions) Error!u64 {
    assert(opts.max_head_bytes > 0);

    var budget = opts.max_head_bytes;
    // lint:unbounded-ok — the head's bound exactly: takeLine charges every
    // trailer line against `budget` and fails when it is spent.
    while (true) {
        const line = try takeLine(r, &budget);
        assert(budget < opts.max_head_bytes);
        // What the budget lost is what the section cost, terminators included
        // — the same accounting `streamChunked` does for a chunk-size line,
        // and the reason `budget` is spent rather than merely checked.
        if (line.len == 0) return opts.max_head_bytes - budget;

        const colon = std.mem.indexOfScalar(u8, line, ':') orelse return error.MalformedHeader;
        const name = line[0..colon];
        if (name.len == 0) return error.MalformedHeader;

        if (opts.on_header) |f| {
            f(opts.ctx, name, std.mem.trim(u8, line[colon + 1 ..], " \t"));
        }
    }
}

/// One head/trailer line: CRLF-terminated (bare LF tolerated), returned
/// without the terminator, charged against `budget` at its raw on-wire size.
fn takeLine(r: *Io.Reader, budget: *usize) Error![]const u8 {
    const budget_before = budget.*;

    const raw = r.takeDelimiterInclusive('\n') catch |err| switch (err) {
        error.StreamTooLong => return error.HeadTooLong,
        error.EndOfStream => return error.UnexpectedEof,
        error.ReadFailed => return error.ReadFailed,
    };
    // takeDelimiterInclusive returns the delimiter with the line, so a
    // successful line is never empty and the budget therefore strictly
    // decreases. That is what bounds every loop in this file.
    assert(raw.len > 0);
    if (raw.len > budget.*) return error.HeadTooLong;
    budget.* -= raw.len;
    assert(budget.* < budget_before);

    var line = raw;
    if (line.len > 0 and line[line.len - 1] == '\n') line = line[0 .. line.len - 1];
    if (line.len > 0 and line[line.len - 1] == '\r') line = line[0 .. line.len - 1];
    assert(line.len < raw.len); // the terminator is always stripped
    return line;
}

/// Whether a comma-separated header value contains `token`, ASCII
/// case-insensitively, as a whole token rather than a substring — "close"
/// must not match a hypothetical "not-close".
fn containsTokenIgnoreCase(value: []const u8, token: []const u8) bool {
    // Every call site passes a comptime literal; an empty token would match
    // every empty list element and quietly turn a header into a verdict.
    assert(token.len > 0);

    var it = std.mem.splitScalar(u8, value, ',');
    while (it.next()) |part| {
        if (std.ascii.eqlIgnoreCase(std.mem.trim(u8, part, " \t"), token)) return true;
    }
    return false;
}

// ---------------------------------------------------------------------------
// tests

const t = std.testing;
const SegmentedReader = @import("SegmentedReader.zig");

fn parseAll(reader: *Io.Reader, method: std.http.Method, out: *Io.Writer.Allocating) !struct { Head, Body } {
    const head = try parseHead(reader, .{});
    const body = try streamBody(reader, head, method, &out.writer, .{});
    return .{ head, body };
}

test "content-length body, plain" {
    const wire = "HTTP/1.1 200 OK\r\ncontent-length: 5\r\n\r\nhello";
    var buf: [256]u8 = undefined;
    var sr = SegmentedReader.init(wire, wire.len, null, &buf);
    var out: Io.Writer.Allocating = .init(t.allocator);
    defer out.deinit();
    const head, const body = try parseAll(&sr.interface, .GET, &out);
    try t.expectEqual(@as(u16, 200), head.status);
    try t.expect(head.keep_alive and body.keep_alive);
    try t.expectEqual(@as(u64, 5), body.len);
    try t.expectEqualStrings("hello", out.written());
}

test "chunked body reassembles across chunk boundaries, with trailers" {
    const wire = "HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n" ++
        "4\r\nWiki\r\n5\r\npedia\r\n0\r\nx-trailer: yes\r\n\r\n";
    var buf: [256]u8 = undefined;
    var sr = SegmentedReader.init(wire, wire.len, null, &buf);
    var out: Io.Writer.Allocating = .init(t.allocator);
    defer out.deinit();
    const head, const body = try parseAll(&sr.interface, .GET, &out);
    try t.expect(head.chunked);
    try t.expectEqual(@as(u64, 9), body.len);
    try t.expectEqualStrings("Wikipedia", out.written());
}

test "the two wire counts add up to the whole response, in every framing" {
    // What a byte-throughput meter is made of. `head_len + wire_len` must be
    // the entire response as it appeared on the wire — every framing, every
    // segmentation — or a `Transfer/sec` built on them silently under-reports
    // whatever it forgot to count. The bug this forecloses has no symptom: the
    // number is merely wrong, and looks fine.
    const cases = [_]struct { wire: []const u8, method: std.http.Method, len: u64 }{
        // Content-length: the body costs exactly what it delivers.
        .{ .wire = "HTTP/1.1 200 OK\r\ncontent-length: 5\r\n\r\nhello", .method = .GET, .len = 5 },
        // Chunked: nine bytes delivered, and the size lines, their CRLFs, the
        // zero chunk and the trailer section are the gap between the counts.
        .{
            .wire = "HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n" ++
                "4\r\nWiki\r\n5\r\npedia\r\n0\r\nx-trailer: yes\r\n\r\n",
            .method = .GET,
            .len = 9,
        },
        // Close-delimited: undecorated, so the two counts agree again.
        .{ .wire = "HTTP/1.0 200 OK\r\n\r\nrest of stream", .method = .GET, .len = 14 },
        // Bodyless: the head IS the response, and a body that never comes
        // costs nothing however loudly content-length announces it.
        .{ .wire = "HTTP/1.1 204 No Content\r\n\r\n", .method = .GET, .len = 0 },
        .{ .wire = "HTTP/1.1 200 OK\r\ncontent-length: 1234\r\n\r\n", .method = .HEAD, .len = 0 },
    };

    // Whole, then one byte per read: rule 4 applies to these two numbers as
    // much as to the parse that produced them.
    for ([_]usize{ 0, 1 }) |segment| {
        for (cases) |case| {
            var buf: [256]u8 = undefined;
            var sr = SegmentedReader.init(
                case.wire,
                if (segment == 0) case.wire.len else 1,
                null,
                &buf,
            );
            var out: Io.Writer.Allocating = .init(t.allocator);
            defer out.deinit();
            const head, const body = try parseAll(&sr.interface, case.method, &out);
            try t.expectEqual(case.len, body.len);
            try t.expectEqual(case.wire.len, head.head_len + body.wire_len);
        }
    }
}

test "segmentation invariance: every split point and byte-at-a-time" {
    // The property the cAdvisor bug violated: the parse result is a function
    // of the bytes, never of where the transport split them. Chunk framing is
    // deliberately positioned so splits land inside the size line, inside the
    // CRLFs, and inside chunk data.
    const wire = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nX-A: b\r\n\r\n" ++
        "6\r\nmetric\r\nb;ext=1\r\n_total 42.5\r\n0\r\n\r\n";
    const want = "metric_total 42.5";

    // Every two-segment split.
    var split: usize = 1;
    while (split < wire.len) : (split += 1) {
        var buf: [256]u8 = undefined;
        var sr = SegmentedReader.init(wire, wire.len, split, &buf);
        var out: Io.Writer.Allocating = .init(t.allocator);
        defer out.deinit();
        _, const body = try parseAll(&sr.interface, .GET, &out);
        try t.expectEqual(@as(u64, want.len), body.len);
        try t.expectEqualStrings(want, out.written());
    }

    // One byte per read — every boundary at once.
    var buf: [256]u8 = undefined;
    var sr = SegmentedReader.init(wire, 1, null, &buf);
    var out: Io.Writer.Allocating = .init(t.allocator);
    defer out.deinit();
    _, const body = try parseAll(&sr.interface, .GET, &out);
    try t.expectEqualStrings(want, out.written());
    try t.expectEqual(@as(u64, want.len), body.len);
}

test "bodyless: 204 with keep-alive does not hang, and HEAD ignores content-length" {
    // ziglang/zig#25181 is exactly this shape hanging in std.http.Client.
    const wire204 = "HTTP/1.1 204 No Content\r\n\r\n" ++ "HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok";
    var buf: [256]u8 = undefined;
    var sr = SegmentedReader.init(wire204, wire204.len, null, &buf);
    var out: Io.Writer.Allocating = .init(t.allocator);
    defer out.deinit();

    _, const b1 = try parseAll(&sr.interface, .GET, &out);
    try t.expectEqual(@as(u64, 0), b1.len);
    try t.expect(b1.keep_alive);
    // The very next bytes must parse as the next response — proof nothing of
    // the 204 "body" was consumed.
    const h2, const b2 = try parseAll(&sr.interface, .GET, &out);
    try t.expectEqual(@as(u16, 200), h2.status);
    try t.expectEqual(@as(u64, 2), b2.len);

    const head_wire = "HTTP/1.1 200 OK\r\ncontent-length: 100\r\n\r\n";
    var sr2 = SegmentedReader.init(head_wire, head_wire.len, null, &buf);
    var out2: Io.Writer.Allocating = .init(t.allocator);
    defer out2.deinit();
    _, const hb = try parseAll(&sr2.interface, .HEAD, &out2);
    try t.expectEqual(@as(u64, 0), hb.len);
}

test "transfer-encoding beats content-length; conflicting lengths are refused" {
    const smuggle = "HTTP/1.1 200 OK\r\ncontent-length: 4\r\ntransfer-encoding: chunked\r\n\r\n" ++
        "2\r\nab\r\n0\r\n\r\n";
    var buf: [256]u8 = undefined;
    var sr = SegmentedReader.init(smuggle, smuggle.len, null, &buf);
    var out: Io.Writer.Allocating = .init(t.allocator);
    defer out.deinit();
    _, const body = try parseAll(&sr.interface, .GET, &out);
    try t.expectEqualStrings("ab", out.written()); // chunked won; CL ignored

    const conflict = "HTTP/1.1 200 OK\r\ncontent-length: 4\r\ncontent-length: 5\r\n\r\n";
    var sr2 = SegmentedReader.init(conflict, conflict.len, null, &buf);
    try t.expectError(error.MalformedHeader, parseHead(&sr2.interface, .{}));
    _ = body;
}

test "close-delimited body forces keep_alive false" {
    const wire = "HTTP/1.0 200 OK\r\n\r\nrest of stream";
    var buf: [256]u8 = undefined;
    var sr = SegmentedReader.init(wire, wire.len, null, &buf);
    var out: Io.Writer.Allocating = .init(t.allocator);
    defer out.deinit();
    const head, const body = try parseAll(&sr.interface, .GET, &out);
    try t.expect(!head.http11);
    try t.expect(!body.keep_alive);
    try t.expectEqualStrings("rest of stream", out.written());
}

test "a trailer is held to the head's rule, listener or no listener" {
    // Found by src/fuzz.zig: the head refuses a nameless field, and the
    // trailer section used to deliver one. The same bytes must not mean two
    // different things depending on where in the message they appear.
    const nameless = "HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n2\r\nab\r\n0\r\n: v\r\n\r\n";
    const colonless = "HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n2\r\nab\r\n0\r\ngarbage\r\n\r\n";
    const head_nameless = "HTTP/1.1 200 OK\r\n: v\r\n\r\n";

    var buf: [256]u8 = undefined;
    var head_reader = SegmentedReader.init(head_nameless, head_nameless.len, null, &buf);
    try t.expectError(error.MalformedHeader, parseHead(&head_reader.interface, .{}));

    // And the verdict does not depend on whether anyone is listening: the
    // callback used to be where the check lived.
    const Sink = struct {
        fn ignore(_: ?*anyopaque, _: []const u8, _: []const u8) void {}
    };
    for ([_][]const u8{ nameless, colonless }) |wire| {
        for ([_]?HeaderFn{ null, Sink.ignore }) |listener| {
            var sr = SegmentedReader.init(wire, wire.len, null, &buf);
            var out: Io.Writer.Allocating = .init(t.allocator);
            defer out.deinit();
            const opts: HeadOptions = .{ .on_header = listener };
            const head = try parseHead(&sr.interface, opts);
            // The head's error, not a vaguer one about chunk framing: the
            // whole point is that position does not change the answer.
            try t.expectError(
                error.MalformedHeader,
                streamBody(&sr.interface, head, .GET, &out.writer, opts),
            );
        }
    }
}

test "connection tokens match whole tokens, not substrings" {
    try t.expect(containsTokenIgnoreCase("Keep-Alive, Upgrade", "keep-alive"));
    try t.expect(!containsTokenIgnoreCase("not-close", "close"));
    try t.expect(containsTokenIgnoreCase("close", "CLOSE"));
}

test "head budget terminates an endless-header server" {
    // Valid-sized lines forever: the line length never trips the reader
    // buffer, so only max_head_bytes stands between us and spinning forever.
    var wire: [4096]u8 = undefined;
    var w: Io.Writer = .fixed(&wire);
    w.writeAll("HTTP/1.1 200 OK\r\n") catch unreachable;
    for (0..100) |_| w.writeAll("x-h: aaaaaaaaaaaaaaaaaaaaaaaaaa\r\n") catch unreachable;
    var buf: [256]u8 = undefined;
    var sr = SegmentedReader.init(w.buffered(), wire.len, null, &buf);
    try t.expectError(error.HeadTooLong, parseHead(&sr.interface, .{ .max_head_bytes = 512 }));
}

test "headers are delivered through the callback with trimmed values" {
    const Ctx = struct {
        seen: usize = 0,
        fn on(ctx: ?*anyopaque, name: []const u8, value: []const u8) void {
            const self: *@This() = @ptrCast(@alignCast(ctx.?));
            if (std.ascii.eqlIgnoreCase(name, "x-spaced")) {
                std.testing.expectEqualStrings("v", value) catch unreachable;
                self.seen += 1;
            }
        }
    };
    const wire = "HTTP/1.1 200 OK\r\nx-spaced:   v  \r\ncontent-length: 0\r\n\r\n";
    var buf: [256]u8 = undefined;
    var sr = SegmentedReader.init(wire, wire.len, null, &buf);
    var ctx: Ctx = .{};
    _ = try parseHead(&sr.interface, .{ .on_header = Ctx.on, .ctx = &ctx });
    try t.expectEqual(@as(usize, 1), ctx.seen);
}

test "bare LF line endings are refused in the head, CRLF only" {
    // A behaviour CHANGE, and a deliberate one. The hand-rolled scanner
    // stripped an optional CR and so accepted bare-LF heads, which RFC 9112
    // §2.2 permits a recipient to do; hparse is CRLF-only, which it is
    // permitted to be, and docs/RESEARCH.md listed this as the adoption cost
    // that reaches a caller. It is recorded here so the strictness is a
    // decision rather than a side effect nobody noticed.
    //
    // Refusing is the safer half of the choice: bare LF inside a head is the
    // request-smuggling primitive intermediaries disagree over (rule 2), and
    // a client that rejects it cannot be the party that disagrees.
    // Rejection is a wire-reading behaviour, so it gets rule 4's treatment
    // like any other: the SAME error at every split position and byte-at-a-
    // time, not just when the whole response lands in one read. A refusal that
    // depends on where the transport split is the cAdvisor bug wearing an
    // error code.
    const cases = .{
        // Bare LF throughout: the status line is what fails.
        .{ "HTTP/1.1 200 OK\ncontent-length: 5\n\nhello", Error.MalformedStatusLine },
        // CRLF status line, bare LF between fields: fails as a header
        // instead, so the taxonomy still tells the caller where.
        .{ "HTTP/1.1 200 OK\r\ncontent-length: 5\n\r\nhello", Error.MalformedHeader },
    };

    inline for (cases) |case| {
        const wire, const want = case;

        var split: usize = 1;
        while (split < wire.len) : (split += 1) {
            var buf: [256]u8 = undefined;
            var sr = SegmentedReader.init(wire, wire.len, split, &buf);
            var out: Io.Writer.Allocating = .init(t.allocator);
            defer out.deinit();
            try t.expectError(want, parseAll(&sr.interface, .GET, &out));
        }

        var buf: [256]u8 = undefined;
        var sr = SegmentedReader.init(wire, 1, null, &buf);
        var out: Io.Writer.Allocating = .init(t.allocator);
        defer out.deinit();
        try t.expectError(want, parseAll(&sr.interface, .GET, &out));
    }
}

test "a content-encoding this parser cannot decode is refused, not passed through" {
    // The cAdvisor incident, rebuilt: a body that is not what it claims,
    // handed to a sink that parses it as text. Nothing here sends
    // `accept-encoding`, so a compliant origin never does this — but rule 2
    // says the caller never sees an undecoded byte, and "the server should
    // not have" is not a framing guarantee.
    const gzip = "HTTP/1.1 200 OK\r\ncontent-encoding: gzip\r\ncontent-length: 4\r\n\r\n\x1f\x8b\x08\x00";
    var buf: [256]u8 = undefined;
    var sr = SegmentedReader.init(gzip, gzip.len, null, &buf);
    var out: Io.Writer.Allocating = .init(t.allocator);
    defer out.deinit();
    try t.expectError(error.UnsupportedContentEncoding, parseAll(&sr.interface, .GET, &out));
    // Refused before delivery: a sink that got half a body and then an error
    // would still have been handed bytes it cannot read.
    try t.expectEqualStrings("", out.written());

    // Two SEPARATE content-encoding fields, both orders. `encoded_body` is
    // monotonic — set, never cleared — so a later `identity` cannot talk the
    // parser out of a gzip it already saw. Written as a test rather than left
    // to that argument, because a bypass here is the founding incident.
    const dup_after = "HTTP/1.1 200 OK\r\ncontent-encoding: gzip\r\ncontent-encoding: identity\r\ncontent-length: 1\r\n\r\nx";
    const dup_before = "HTTP/1.1 200 OK\r\ncontent-encoding: identity\r\ncontent-encoding: gzip\r\ncontent-length: 1\r\n\r\nx";
    for ([_][]const u8{ dup_after, dup_before }) |wire| {
        var db: [256]u8 = undefined;
        var ds = SegmentedReader.init(wire, wire.len, null, &db);
        var dout: Io.Writer.Allocating = .init(t.allocator);
        defer dout.deinit();
        try t.expectError(error.UnsupportedContentEncoding, parseAll(&ds.interface, .GET, &dout));
    }

    // A list is refused too. `gzip, identity` is still gzip on the wire, so
    // matching known names one at a time would be the wrong test.
    const list = "HTTP/1.1 200 OK\r\ncontent-encoding: gzip, identity\r\ncontent-length: 1\r\n\r\nx";
    var b2: [256]u8 = undefined;
    var s2 = SegmentedReader.init(list, list.len, null, &b2);
    var o2: Io.Writer.Allocating = .init(t.allocator);
    defer o2.deinit();
    try t.expectError(error.UnsupportedContentEncoding, parseAll(&s2.interface, .GET, &o2));
}

test "identity, a bodyless response, and an opted-in caller all still pass" {
    // The complement. A check that refuses more than it must is a check people
    // route around, and each of these is a case a blanket refusal would break.

    // `identity` is the one coding that means "nothing was applied".
    const identity = "HTTP/1.1 200 OK\r\ncontent-encoding: identity\r\ncontent-length: 2\r\n\r\nhi";
    var b1: [256]u8 = undefined;
    var s1 = SegmentedReader.init(identity, identity.len, null, &b1);
    var o1: Io.Writer.Allocating = .init(t.allocator);
    defer o1.deinit();
    _, const body1 = try parseAll(&s1.interface, .GET, &o1);
    try t.expectEqualStrings("hi", o1.written());
    try t.expectEqual(@as(u64, 2), body1.len);

    // A HEAD echoes the headers its GET would have sent, `content-encoding`
    // among them, and carries no body. Refusing it would break every HEAD
    // against a gzip-serving origin — `ycs.head` is a real caller.
    const head_resp = "HTTP/1.1 200 OK\r\ncontent-encoding: gzip\r\ncontent-length: 900\r\n\r\n";
    var b2: [256]u8 = undefined;
    var s2 = SegmentedReader.init(head_resp, head_resp.len, null, &b2);
    var o2: Io.Writer.Allocating = .init(t.allocator);
    defer o2.deinit();
    const h2 = try parseHead(&s2.interface, .{});
    const body2 = try streamBody(&s2.interface, h2, .HEAD, &o2.writer, .{});
    try t.expectEqual(@as(u64, 0), body2.len);
    try t.expect(h2.encoded_body);

    // And a caller that says it wants the raw bytes gets them.
    const raw = "HTTP/1.1 200 OK\r\ncontent-encoding: gzip\r\ncontent-length: 3\r\n\r\nabc";
    var b3: [256]u8 = undefined;
    var s3 = SegmentedReader.init(raw, raw.len, null, &b3);
    var o3: Io.Writer.Allocating = .init(t.allocator);
    defer o3.deinit();
    const h3 = try parseHead(&s3.interface, .{ .allow_encoded_body = true });
    _ = try streamBody(&s3.interface, h3, .GET, &o3.writer, .{ .allow_encoded_body = true });
    try t.expectEqualStrings("abc", o3.written());
}
