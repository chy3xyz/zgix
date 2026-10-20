//! Every corpus input where hparse and a reference parser reach different verdicts.
//!
//! The reference differentials in `fuzz.zig` compare fields only where hparse AND a
//! reference both accept. Everywhere they disagree about whether a message is legal
//! at all, the comparison is skipped — correctly, because the three refuse different
//! things on purpose. The old comment called those cases "triage material, not
//! failures", and for eight months nothing triaged them, because nothing recorded
//! them. That is exactly how hparse came to accept 144 non-tchar bytes in a header
//! field name (b65ea98): picohttpparser rejected `Fo@:`, hparse accepted it, and the
//! oracle silently dropped the disagreement on the floor. llhttp's own fixture for
//! that input was even in the corpus, and it ran clean.
//!
//! So the skipped set is written down here instead. `fuzz.zig` recomputes it and
//! fails when it moves: a NEW entry is a disagreement nobody has justified, a GONE
//! entry means hparse changed its mind about something, and a CHANGED entry means a
//! verdict flipped under it. All three want a human.
//!
//! `why` is required, and that is the point. A disagreement you cannot explain in
//! one line is a bug you have not found yet. Filling it in with "reference is
//! stricter" defeats the whole file — say WHICH rule and WHY hparse is entitled to
//! differ.
//!
//! The direction matters when triaging:
//!
//! * `hparse = false` — hparse is the strict one. Nearly always fine; this parser
//!   refuses bare LF, obs-fold and leading empty lines by design, and each is
//!   argued for in CLAUDE.md.
//! * `hparse = true` with ONE reference disagreeing — usually a layering
//!   difference. llhttp does framing and method-table validation that hparse
//!   deliberately does not; that is most of this file.
//! * `hparse = true` with BOTH references disagreeing — **read this one carefully.**
//!   It means the only parser in the room that thinks the message is well-formed is
//!   this one. That was the tchar bug's exact signature, and there are currently
//!   zero such entries. Adding one should take more than a line of justification.
//!
//! Regenerate by hand, not in bulk: `fuzz.zig` prints only what moved, so existing
//! `why` lines survive. That is deliberate — a bulk rewrite would silently discard
//! the reasoning, which is the only part of this file that is hard to reproduce.

/// One input the three parsers do not agree about. `hparse`/`pico`/`llhttp` are
/// whether that parser accepted a complete message.
pub const Entry = struct {
    hparse: bool,
    pico: bool,
    llhttp: bool,
    why: []const u8,
    input: []const u8,
};

pub const requests = [_]Entry{
    .{ .hparse = false, .pico = true, .llhttp = false, .why = "bare LF line terminator; hparse is CRLF-only, and accepting both is how smuggling starts", .input = "GET / HTTP/1.1\n\n" },
    .{ .hparse = true, .pico = true, .llhttp = false, .why = "llhttp has a closed method table; hparse accepts any RFC 9110 token as an extension method", .input = "POSTER /x HTTP/1.1\r\n\r\n" },
    .{ .hparse = false, .pico = true, .llhttp = false, .why = "obs-fold continuation line; hparse refuses folding outright (RFC 9112 deprecates it)", .input = "GET /demo HTTP/1.1\r\nHost: example.com\r\nConnection: Something,\r\n Upgrade, ,Keep-Alive\r\nSec-WebSocket-Key2: 12998 5 Y3 1  .P00\r\nSec-WebSocket-Protocol: sample\r\nUpgrade: WebSocket\r\nSec-WebSocket-Key1: 4 @1  46546xW%0l 1 5\r\nOrigin: http://example.com\r\n\r\nHot diggity dogg" },
    .{ .hparse = false, .pico = true, .llhttp = false, .why = "obs-fold continuation line; hparse refuses folding outright (RFC 9112 deprecates it)", .input = "GET /demo HTTP/1.1\r\nConnection: keep-alive, \r\n upgrade\r\nUpgrade: WebSocket\r\n\r\nHot diggity dogg" },
    .{ .hparse = true, .pico = true, .llhttp = false, .why = "llhttp validates Transfer-Encoding semantics; hparse does no framing, so the field is just a header to it", .input = "PUT /url HTTP/1.1\r\nContent-Length: 1\r\nTransfer-Encoding: identity\r\n\r\n" },
    .{ .hparse = true, .pico = true, .llhttp = false, .why = "llhttp validates the Content-Length VALUE; hparse does no framing, so the field is just a header to it", .input = "POST / HTTP/1.1\r\nContent-Length: 4 2\r\n\r\n" },
    .{ .hparse = true, .pico = true, .llhttp = false, .why = "llhttp validates the Content-Length VALUE; hparse does no framing, so the field is just a header to it", .input = "POST / HTTP/1.1\r\nContent-Length: 13 37\r\n\r\n" },
    .{ .hparse = true, .pico = true, .llhttp = false, .why = "llhttp validates the Content-Length VALUE; hparse does no framing, so the field is just a header to it", .input = "POST / HTTP/1.1\r\nContent-Length:\r\n\r\n" },
    .{ .hparse = true, .pico = true, .llhttp = false, .why = "llhttp has a closed method table; hparse accepts any RFC 9110 token as an extension method", .input = "ANNOUNCE /music/sweet/music HTTP/1.0\r\nHost: example.com\r\n\r\n" },
    .{ .hparse = false, .pico = true, .llhttp = false, .why = "bare LF line terminator; hparse is CRLF-only, and accepting both is how smuggling starts", .input = "POST / HTTP/1.1\r\nHost: localhost:5000\r\nx:x\nTransfer-Encoding: chunked\r\n\r\n1\r\nA\r\n0\r\n" },
    .{ .hparse = false, .pico = true, .llhttp = false, .why = "bare LF line terminator; hparse is CRLF-only, and accepting both is how smuggling starts", .input = "POST / HTTP/1.1\r\nHost: localhost:5000\r\nx:\nTransfer-Encoding: chunked\r\n\r\n1\r\nA\r\n0\r\n" },
    .{ .hparse = true, .pico = true, .llhttp = false, .why = "llhttp has a closed method table; hparse accepts any RFC 9110 token as an extension method", .input = "MKCOLA / HTTP/1.1\r\n\r\n" },
    .{ .hparse = false, .pico = true, .llhttp = false, .why = "bare LF line terminator; hparse is CRLF-only, and accepting both is how smuggling starts", .input = "GET / HTTP/1.1\r\nHost: localhost\r\nDummy: x\nContent-Length: 23\r\n\r\nGET / HTTP/1.1\r\nDummy: GET /admin HTTP/1.1\r\nHost: localhost\r\n\r\n" },
    .{ .hparse = false, .pico = true, .llhttp = false, .why = "bare LF line terminator; hparse is CRLF-only, and accepting both is how smuggling starts", .input = "POST / HTTP/1.1\nTransfer-Encoding: chunked\nTrailer: Baz\r\nFoo: abc\nBar: def\n\n1\nA\n1;abc\nB\n1;def=ghi\nC\n1;jkl=\"mno\"\nD\n0\n\nBaz: ghi\n\n\\" },
    .{ .hparse = false, .pico = true, .llhttp = false, .why = "bare LF line terminator; hparse is CRLF-only, and accepting both is how smuggling starts", .input = "POST / HTTP/1.1\nTransfer-Encoding: chunked\nTrailer: Baz\r\nFoo: abc\nBar: def\n\n1\nA\n1;abc\nB\n1;def=ghi\nC\n1;jkl=\"mno\"\nD\n0\n\nBaz: ghi\n\n" },
    .{ .hparse = false, .pico = true, .llhttp = false, .why = "obs-fold continuation line; hparse refuses folding outright (RFC 9112 deprecates it)", .input = "POST /hello HTTP/1.1\r\nHost: localhost\r\nFoo: bar\r\n Content-Length: 38\r\n\r\nGET /bye HTTP/1.1\r\nHost: localhost\r\n\r\n" },
    .{ .hparse = false, .pico = false, .llhttp = true, .why = "a non-HTTP/1.x protocol token; llhttp is lenient about it, hparse parses HTTP 1.0 and 1.1 only", .input = "SOURCE /music/sweet/music ICE/1.0\r\nHost: example.com\r\n\r\n" },
    .{ .hparse = false, .pico = false, .llhttp = true, .why = "a non-HTTP/1.x protocol token; llhttp is lenient about it, hparse parses HTTP 1.0 and 1.1 only", .input = "OPTIONS /music/sweet/music RTSP/1.0\r\nHost: example.com\r\n\r\n" },
    .{ .hparse = false, .pico = false, .llhttp = true, .why = "a non-HTTP/1.x protocol token; llhttp is lenient about it, hparse parses HTTP 1.0 and 1.1 only", .input = "ANNOUNCE /music/sweet/music RTSP/1.0\r\nHost: example.com\r\n\r\n" },
    .{ .hparse = true, .pico = true, .llhttp = false, .why = "llhttp has a closed method table; hparse accepts any RFC 9110 token as an extension method", .input = "PRI * HTTP/1.1\r\n\r\nSM\r\n\r\n" },
    .{ .hparse = false, .pico = true, .llhttp = true, .why = "leading empty line before the start line; both references skip it, hparse refuses", .input = "\r\nGET /test HTTP/1.1\r\n\r\n" },
    .{ .hparse = false, .pico = false, .llhttp = true, .why = "HTTP/0.9-style request line with no version; llhttp allows it, hparse requires one", .input = "GET /\r\n\r\n" },
    .{ .hparse = false, .pico = true, .llhttp = false, .why = "obs-fold continuation line; hparse refuses folding outright (RFC 9112 deprecates it)", .input = "GET / HTTP/1.1\r\nLine1:   abc\r\n\tdef\r\n ghi\r\n\t\tjkl\r\n  mno \r\n\t \tqrs\r\nLine2: \t line2\t\r\nLine3:\r\n line3\r\nLine4: \r\n \r\nConnection:\r\n close\r\n\r\n" },
    .{ .hparse = false, .pico = true, .llhttp = false, .why = "obs-fold continuation line; hparse refuses folding outright (RFC 9112 deprecates it)", .input = "GET / HTTP/1.1\r\nLine1:   abc\n\tdef\n ghi\n\t\tjkl\n  mno \n\t \tqrs\nLine2: \t line2\t\nLine3:\n line3\nLine4: \n \nConnection:\n close\n\n" },
    .{ .hparse = false, .pico = true, .llhttp = true, .why = "leading empty line before the start line; both references skip it, hparse refuses", .input = "\r\nGET /url HTTP/1.1\r\nHeader1: Value1\r\n\r\n" },
    .{ .hparse = true, .pico = true, .llhttp = false, .why = "llhttp validates Transfer-Encoding semantics; hparse does no framing, so the field is just a header to it", .input = "POST /first HTTP/1.1\r\nTransfer-Encoding:\r\nContent-Length: 5\r\n\r\nhello" },
    .{ .hparse = true, .pico = true, .llhttp = false, .why = "llhttp validates Transfer-Encoding semantics; hparse does no framing, so the field is just a header to it", .input = "POST /post_identity_body_world?q=search#hey HTTP/1.1\r\nAccept: */*\r\nTransfer-Encoding: identity\r\nContent-Length: 5\r\n\r\nWorld" },
    .{ .hparse = true, .pico = true, .llhttp = false, .why = "llhttp validates Transfer-Encoding semantics; hparse does no framing, so the field is just a header to it", .input = "POST /post_identity_body_world?q=search#hey HTTP/1.1\r\nAccept: */*\r\nTransfer-Encoding: identity\r\nContent-Length: 1\r\n\r\nWorld" },
    .{ .hparse = true, .pico = true, .llhttp = false, .why = "llhttp validates Transfer-Encoding semantics; hparse does no framing, so the field is just a header to it", .input = "POST / HTTP/1.1\r\nHost: foo\r\nContent-Length: 10\r\nTransfer-Encoding:\r\nTransfer-Encoding:\r\nTransfer-Encoding:\r\n\r\n2\r\nAA\r\n0" },
    .{ .hparse = true, .pico = true, .llhttp = false, .why = "llhttp validates Transfer-Encoding semantics; hparse does no framing, so the field is just a header to it", .input = "POST /post_identity_body_world?q=search#hey HTTP/1.1\r\nAccept: */*\r\nTransfer-Encoding: chunked, deflate\r\n\r\nWorld" },
    .{ .hparse = true, .pico = true, .llhttp = false, .why = "llhttp validates Transfer-Encoding semantics; hparse does no framing, so the field is just a header to it", .input = "POST /post_identity_body_world?q=search#hey HTTP/1.1\r\nAccept: */*\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: deflate\r\n\r\nWorld" },
    .{ .hparse = false, .pico = true, .llhttp = false, .why = "obs-fold continuation line; hparse refuses folding outright (RFC 9112 deprecates it)", .input = "PUT /url HTTP/1.1\r\nTransfer-Encoding: chunked\r\n  abc\r\n\r\n5\r\nWorld\r\n0\r\n\r\n" },
    .{ .hparse = false, .pico = true, .llhttp = false, .why = "raw non-ASCII in the request-target; RFC 3986 requires it percent-encoded and hparse now enforces that, so the proxy and the origin cannot normalize one byte string into two different paths", .input = "GET /\xce\xb4\xc2\xb6/\xce\xb4t/pope?q=1#narf HTTP/1.1\r\nHost: github.com\r\n\r\n" },
    .{ .hparse = false, .pico = true, .llhttp = true, .why = "a double quote and a backslash in the request-target, neither of which is pchar. The backslash is the reason the rule exists: an origin that normalizes it to '/' resolves a different path than the one the proxy routed on", .input = "GET /with_\"lovely\"_quotes?foo=\\\"bar\\\" HTTP/1.1\r\n\r\n" },
    .{ .hparse = false, .pico = true, .llhttp = true, .why = "a pipe in a query string; not pchar, so RFC 3986 wants it percent-encoded. Both references take it and llhttp ships a fixture for it, which makes this the clearest measure of what the pchar rule costs in compatibility", .input = "GET /test.cgi?query=| HTTP/1.1\r\n\r\n" },
};

pub const responses = [_]Entry{
    .{ .hparse = false, .pico = true, .llhttp = false, .why = "bare LF line terminator; hparse is CRLF-only, and accepting both is how smuggling starts", .input = "HTTP/1.1 301   Moved Permanently\n\n" },
    .{ .hparse = false, .pico = true, .llhttp = false, .why = "two spaces after the version; hparse requires exactly one before the status code", .input = "HTTP/1.1  200 OK\r\n\r\n" },
    .{ .hparse = false, .pico = true, .llhttp = false, .why = "bare LF line terminator; hparse is CRLF-only, and accepting both is how smuggling starts", .input = "HTTP/1.1 200 OK\nContent-Length: 0\n\n" },
    .{ .hparse = false, .pico = true, .llhttp = false, .why = "bare LF line terminator; hparse is CRLF-only, and accepting both is how smuggling starts", .input = "HTTP/1.1 200 OK\nFoo: abc\nBar: def\n\nBODY\n\\" },
    .{ .hparse = false, .pico = false, .llhttp = true, .why = "a non-HTTP/1.x protocol token; llhttp is lenient about it, hparse parses HTTP 1.0 and 1.1 only", .input = "RTSP/1.1 200 OK\r\n\r\n" },
    .{ .hparse = false, .pico = false, .llhttp = true, .why = "a non-HTTP/1.x protocol token; llhttp is lenient about it, hparse parses HTTP 1.0 and 1.1 only", .input = "ICE/1.1 200 OK\r\n\r\n" },
    .{ .hparse = false, .pico = true, .llhttp = false, .why = "bare LF line terminator; hparse is CRLF-only, and accepting both is how smuggling starts", .input = "HTTP/1.1 200 OK\nContent-Type: text/html; charset=utf-8\nConnection: close\n\nthese headers are from http://news.ycombinator.com/" },
    .{ .hparse = false, .pico = false, .llhttp = true, .why = "a non-HTTP/1.x protocol token; llhttp is lenient about it, hparse parses HTTP 1.0 and 1.1 only", .input = "HTTP/0.9 200 OK\r\n\r\n" },
    .{ .hparse = false, .pico = false, .llhttp = true, .why = "leading empty line before the start line; both references skip it, hparse refuses", .input = "\r\nHTTP/1.1 200 OK\r\nHeader1: Value1\r\nHeader2:\t Value2\r\nContent-Length: 0\r\n\r\n" },
    .{ .hparse = true, .pico = true, .llhttp = false, .why = "llhttp validates Transfer-Encoding semantics; hparse does no framing, so the field is just a header to it", .input = "HTTP/1.1 200 OK\r\nTransfer-Encoding:\r\nContent-Length: 5\r\n\r\nhello" },
    .{ .hparse = false, .pico = true, .llhttp = false, .why = "obs-fold continuation line; hparse refuses folding outright (RFC 9112 deprecates it)", .input = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n  abc\r\n\r\n5\r\nWorld\r\n0\r\n\r\n" },
};
