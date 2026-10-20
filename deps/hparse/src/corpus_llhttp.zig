//! Fuzz corpus harvested from llhttp's own test fixtures.
//!
//! GENERATED — do not hand-edit. Source: nodejs/llhttp v9.4.3 (MIT),
//! `test/request/*.md` and `test/response/*.md`, the same release already
//! vendored under `bench/llhttp/`. Each entry keeps a `file:line — test name`
//! comment so a fuzz failure can be traced back to the case it came from.
//!
//! These are inputs only. llhttp's fixtures pair each input with an expected
//! event trace, and none of that transfers: hparse reports a consumed length and
//! slices, not `on_url`/`on_header_field` callbacks. It does not need to. The
//! oracles in `fuzz.zig` are differential and self-consistency checks, so a seed
//! carries its own verdict — what these buy is *reach*, hand-written HTTP edge
//! cases nobody on this side thought to write down.
//!
//! Decoding replicates `test/md-test.ts` exactly and in order: strip one trailing
//! newline, drop backslash-escaped newlines, normalize every line ending to CRLF,
//! then expand `\r` `\n` `\t` `\f`, `\xHH` and octal `\NNN`. The order is
//! load-bearing — normalizing before expanding is what makes a blank line a CRLF
//! while leaving an explicit `\n` a bare LF, and doing it the other way round
//! would silently turn every bare-LF rejection case into an accepted one.
//!
//! One deliberate deviation: `\xHH` becomes that single byte. JavaScript's
//! `String.fromCharCode` produces a UTF-16 code unit that llhttp's runner then
//! UTF-8-encodes, so upstream `\xff` is two bytes, not one. A single high byte is
//! both what the fixture author wrote and the more interesting input for a parser
//! that scans bytes; five escapes across the whole corpus are affected. Byte-exact
//! agreement with llhttp's own harness is not a goal here — these are seeds, not
//! assertions.
//!
//! Dropped on extraction: 41 entries that were exact duplicates of an earlier one,
//! and one 2044-byte entry (`request/sample.md:576`) over `fuzz.zig`'s 1024-byte
//! `max_input`, which is itself bounded by the guard page.
//!
//! Plenty of what remains tests framing hparse deliberately does not do — chunked
//! bodies, pipelining, keep-alive. The heads are still heads, and several carry
//! trailing bytes after the final CRLF, which is exactly what the consumed-length
//! round-trip oracle is for.
//!
//! To regenerate against a newer llhttp tag, run `tools/extract_llhttp_corpus.pl`
//! and splice its two arrays in below this comment. It reproduces everything from
//! here down byte for byte, and prints what it dropped to stderr — read that,
//! because a corpus that quietly loses entries still looks like a corpus.

pub const requests = [_][]const u8{
    // request/connection.md:9 — Setting flag
    "PUT /url HTTP/1.1\r\nConnection: keep-alive\r\n\r\n",
    // request/connection.md:37 — Restarting when keep-alive is explicitly
    "PUT /url HTTP/1.1\r\nConnection: keep-alive\r\n\r\nPUT /url HTTP/1.1\r\nConnection: keep-alive\r\n\r\n",
    // request/connection.md:84 — No restart when keep-alive is off (1.0)
    "PUT /url HTTP/1.0\r\n\r\nPUT /url HTTP/1.1\r\n\r\n",
    // request/connection.md:113 — Resetting flags when keep-alive is off (1.0, lenient)
    "PUT /url HTTP/1.0\r\nContent-Length: 0\r\n\r\nPUT /url HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n",
    // request/connection.md:159 — CRLF between requests, implicit `keep-alive`
    "POST / HTTP/1.1\r\nHost: www.example.com\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 4\r\n\r\nq=42\r\n\r\nGET / HTTP/1.1",
    // request/connection.md:211 — Not treating `\r` as `-`
    "PUT /url HTTP/1.1\r\nConnection: keep\ralive\r\n\r\n",
    // request/connection.md:239 — Setting flag on `close`
    "PUT /url HTTP/1.1\r\nConnection: close\r\n\r\n",
    // request/connection.md:267 — Setting flag on `close` followed by tab
    "PUT /url HTTP/1.1\r\nConnection: close\t\r\n\r\n",
    // request/connection.md:297 — CRLF between requests, explicit `close`
    "POST / HTTP/1.1\r\nHost: www.example.com\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 4\r\nConnection: close\r\n\r\nq=42\r\n\r\nGET / HTTP/1.1",
    // request/connection.md:347 — CRLF between requests, explicit `close` followed by tab
    "POST / HTTP/1.1\r\nHost: www.example.com\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 4\r\nConnection: close\t\r\n\r\nq=42\r\n\r\nGET / HTTP/1.1",
    // request/connection.md:456 — Sample
    "PUT /url HTTP/1.1\r\nConnection: close, token, upgrade, token, keep-alive\r\n\r\n",
    // request/connection.md:484 — Multiple tokens with folding
    "GET /demo HTTP/1.1\r\nHost: example.com\r\nConnection: Something,\r\n Upgrade, ,Keep-Alive\r\nSec-WebSocket-Key2: 12998 5 Y3 1  .P00\r\nSec-WebSocket-Protocol: sample\r\nUpgrade: WebSocket\r\nSec-WebSocket-Key1: 4 @1  46546xW%0l 1 5\r\nOrigin: http://example.com\r\n\r\nHot diggity dogg",
    // request/connection.md:545 — Multiple tokens with folding and LWS
    "GET /demo HTTP/1.1\r\nConnection: keep-alive, upgrade\r\nUpgrade: WebSocket\r\n\r\nHot diggity dogg",
    // request/connection.md:579 — Multiple tokens with folding, LWS, and CRLF
    "GET /demo HTTP/1.1\r\nConnection: keep-alive, \r\n upgrade\r\nUpgrade: WebSocket\r\n\r\nHot diggity dogg",
    // request/connection.md:614 — Invalid whitespace token with `Connection` header field
    "PUT /url HTTP/1.1\r\nConnection : upgrade\r\nContent-Length: 4\r\nUpgrade: ws\r\n\r\nabcdefgh",
    // request/connection.md:682 — Setting a flag and pausing
    "PUT /url HTTP/1.1\r\nConnection: upgrade\r\nUpgrade: ws\r\n\r\n",
    // request/connection.md:716 — Emitting part of body and pausing
    "PUT /url HTTP/1.1\r\nConnection: upgrade\r\nContent-Length: 4\r\nUpgrade: ws\r\n\r\nabcdefgh",
    // request/connection.md:756 — Upgrade GET request
    "GET /demo HTTP/1.1\r\nHost: example.com\r\nConnection: Upgrade\r\nSec-WebSocket-Key2: 12998 5 Y3 1  .P00\r\nSec-WebSocket-Protocol: sample\r\nUpgrade: WebSocket\r\nSec-WebSocket-Key1: 4 @1  46546xW%0l 1 5\r\nOrigin: http://example.com\r\n\r\nHot diggity dogg",
    // request/connection.md:815 — Upgrade POST request
    "POST /demo HTTP/1.1\r\nHost: example.com\r\nConnection: Upgrade\r\nUpgrade: HTTP/2.0\r\nContent-Length: 15\r\n\r\nsweet post bodyHot diggity dogg",
    // request/content-length.md:7 — `Content-Length` with zeroes
    "PUT /url HTTP/1.1\r\nContent-Length: 003\r\n\r\nabc",
    // request/content-length.md:44 — `Content-Length` with follow-up headers
    "PUT /url HTTP/1.1\r\nContent-Length: 003\r\nOhai: world\r\n\r\nabc",
    // request/content-length.md:78 — Error on `Content-Length` overflow
    "PUT /url HTTP/1.1\r\nContent-Length: 1000000000000000000000\r\n",
    // request/content-length.md:103 — Error on duplicate `Content-Length`
    "PUT /url HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 2\r\n",
    // request/content-length.md:132 — Error on simultaneous `Content-Length` and `Transfer-Encoding: identity`
    "PUT /url HTTP/1.1\r\nContent-Length: 1\r\nTransfer-Encoding: identity\r\n\r\n",
    // request/content-length.md:162 — Invalid whitespace token with `Content-Length` header field
    "PUT /url HTTP/1.1\r\nConnection: upgrade\r\nContent-Length : 4\r\nUpgrade: ws\r\n\r\nabcdefgh",
    // request/content-length.md:264 — Funky `Content-Length` with body
    "GET /get_funky_content_length_body_hello HTTP/1.0\r\nconTENT-Length: 5\r\n\r\nHELLO",
    // request/content-length.md:293 — Spaces in `Content-Length` (surrounding)
    "POST / HTTP/1.1\r\nContent-Length:  42 \r\n\r\n",
    // request/content-length.md:320 — Tabs in `Content-Length` (surrounding)
    "POST / HTTP/1.1\r\nContent-Length:\t42\t  \r\n\r\n",
    // request/content-length.md:347 — Spaces in `Content-Length` #2
    "POST / HTTP/1.1\r\nContent-Length: 4 2\r\n\r\n",
    // request/content-length.md:373 — Spaces in `Content-Length` #3
    "POST / HTTP/1.1\r\nContent-Length: 13 37\r\n\r\n",
    // request/content-length.md:399 — Empty `Content-Length`
    "POST / HTTP/1.1\r\nContent-Length:\r\n\r\n",
    // request/content-length.md:424 — `Content-Length` with CR instead of dash
    "PUT /url HTTP/1.1\r\nContent\rLength: 003\r\n\r\nabc",
    // request/content-length.md:447 — Content-Length reset when no body is received
    "PUT /url HTTP/1.1\r\nContent-Length: 123\r\n\r\nPOST /url HTTP/1.1\r\nContent-Length: 456\r\n\r\n",
    // request/content-length.md:496 — Missing CRLF-CRLF before body
    "PUT /url HTTP/1.1\r\nContent-Length: 3\r\n\rabc",
    // request/finish.md:9 — It should be safe to finish after GET request
    "GET / HTTP/1.1\r\n\r\n",
    // request/finish.md:33 — It should be unsafe to finish after incomplete PUT request
    "PUT / HTTP/1.1\r\nContent-Length: 100\r\n",
    // request/finish.md:58 — It should be unsafe to finish inside of the header
    "PUT / HTTP/1.1\r\nContent-Leng",
    // request/invalid.md:7 — ICE protocol and GET method
    "GET /music/sweet/music ICE/1.0\r\nHost: example.com\r\n\r\n",
    // request/invalid.md:28 — ICE protocol, but not really
    "GET /music/sweet/music IHTTP/1.0\r\nHost: example.com\r\n\r\n",
    // request/invalid.md:48 — RTSP protocol and PUT method
    "PUT /music/sweet/music RTSP/1.0\r\nHost: example.com\r\n\r\n",
    // request/invalid.md:69 — HTTP protocol and ANNOUNCE method
    "ANNOUNCE /music/sweet/music HTTP/1.0\r\nHost: example.com\r\n\r\n",
    // request/invalid.md:90 — Headers separated by CR
    "GET / HTTP/1.1\r\nFoo: 1\rBar: 2\r\n\r\n",
    // request/invalid.md:116 — Headers separated by LF
    "POST / HTTP/1.1\r\nHost: localhost:5000\r\nx:x\nTransfer-Encoding: chunked\r\n\r\n1\r\nA\r\n0\r\n",
    // request/invalid.md:150 — Headers separated by dummy characters
    "GET / HTTP/1.1\r\nConnection: close\r\nHost: a\r\n\rZGET /evil: HTTP/1.1\r\nHost: a\r\n",
    // request/invalid.md:219 — Empty headers separated by CR
    "POST / HTTP/1.1\r\nConnection: Close\r\nHost: localhost:5000\r\nx:\rTransfer-Encoding: chunked\r\n\r\n1\r\nA\r\n0\r\n",
    // request/invalid.md:257 — Empty headers separated by LF
    "POST / HTTP/1.1\r\nHost: localhost:5000\r\nx:\nTransfer-Encoding: chunked\r\n\r\n1\r\nA\r\n0\r\n",
    // request/invalid.md:290 — Invalid header token #1
    "GET / HTTP/1.1\r\nFo@: Failure\r\n\r\n",
    // request/invalid.md:313 — Invalid header token #2
    "GET / HTTP/1.1\r\nFoo\x01\test: Bar\r\n\r\n",
    // request/invalid.md:336 — Invalid header token #3
    "GET / HTTP/1.1\r\n: Bar\r\n\r\n",
    // request/invalid.md:359 — Invalid method
    "MKCOLA / HTTP/1.1\r\n\r\n",
    // request/invalid.md:375 — Illegal header field name line folding
    "GET / HTTP/1.1\r\nname\r\n : value\r\n\r\n",
    // request/invalid.md:399 — Corrupted Connection header
    "GET / HTTP/1.1\r\nHost: www.example.com\r\nConnection\r\x1b5\xd5eep-Alive\r\nAccept-Encoding: gzip\r\n\r\n",
    // request/invalid.md:428 — Corrupted header name
    "GET / HTTP/1.1\r\nHost: www.example.com\r\nX-Some-Header\r\x1b5\xd5eep-Alive\r\nAccept-Encoding: gzip\r\n\r\n",
    // request/invalid.md:458 — Missing CR between headers
    "GET / HTTP/1.1\r\nHost: localhost\r\nDummy: x\nContent-Length: 23\r\n\r\nGET / HTTP/1.1\r\nDummy: GET /admin HTTP/1.1\r\nHost: localhost\r\n\r\n",
    // request/invalid.md:493 — Invalid HTTP version
    "GET / HTTP/5.6",
    // request/invalid.md:512 — Invalid space after start line
    "GET / HTTP/1.1\r\n Host: foo",
    // request/invalid.md:534 — Only LFs present
    "POST / HTTP/1.1\nTransfer-Encoding: chunked\nTrailer: Baz\r\nFoo: abc\nBar: def\n\n1\nA\n1;abc\nB\n1;def=ghi\nC\n1;jkl=\"mno\"\nD\n0\n\nBaz: ghi\n\n\\",
    // request/invalid.md:571 — Only LFs present (lenient)
    "POST / HTTP/1.1\nTransfer-Encoding: chunked\nTrailer: Baz\r\nFoo: abc\nBar: def\n\n1\nA\n1;abc\nB\n1;def=ghi\nC\n1;jkl=\"mno\"\nD\n0\n\nBaz: ghi\n\n",
    // request/invalid.md:654 — Spaces before headers
    "POST /hello HTTP/1.1\r\nHost: localhost\r\nFoo: bar\r\n Content-Length: 38\r\n\r\nGET /bye HTTP/1.1\r\nHost: localhost\r\n\r\n",
    // request/lenient-header-value-relaxed.md:13 — Control char in header value (relaxed)
    "GET /url HTTP/1.1\r\nHeader1: hello\x0cworld\r\n\r\n",
    // request/lenient-header-value-relaxed.md:106 — CR without LF in header value should be rejected even with relaxed flag
    "POST / HTTP/1.1\r\nHost: localhost:5000\r\nx:\rTransfer-Encoding: chunked\r\n\r\n1\r\nA\r\n0\r\n",
    // request/lenient-header-value-relaxed.md:141 — Space after start line must still fail
    "GET /url HTTP/1.1\r\n Header1: value\r\n",
    // request/lenient-headers.md:9 — Header value (lenient)
    "GET /url HTTP/1.1\r\nHeader1: \x0c\r\n\r\n",
    // request/lenient-headers.md:37 — Second request header value (lenient)
    "GET /url HTTP/1.1\r\nHeader1: Okay\r\n\r\n\r\nGET /url HTTP/1.1\r\nHeader1: \x0c\r\n\r\n",
    // request/lenient-headers.md:85 — Header value
    "GET /url HTTP/1.1\r\nHeader1: \x0c\r\n\r\n\r\n",
    // request/lenient-version.md:7 — Invalid HTTP version (lenient)
    "GET / HTTP/5.6\r\n\r\n",
    // request/method.md:7 — REPORT request
    "REPORT /test HTTP/1.1\r\n\r\n",
    // request/method.md:30 — CONNECT request
    "CONNECT 0-home0.netscape.com:443 HTTP/1.0\r\nUser-agent: Mozilla/1.1N\r\nProxy-authorization: basic aGVsbG86d29ybGQ=\r\n\r\nsome data\r\nand yet even more data",
    // request/method.md:65 — CONNECT request with CAPS
    "CONNECT HOME0.NETSCAPE.COM:443 HTTP/1.0\r\nUser-agent: Mozilla/1.1N\r\nProxy-authorization: basic aGVsbG86d29ybGQ=\r\n\r\n",
    // request/method.md:99 — CONNECT with body
    "CONNECT foo.bar.com:443 HTTP/1.0\r\nUser-agent: Mozilla/1.1N\r\nProxy-authorization: basic aGVsbG86d29ybGQ=\r\nContent-Length: 10\r\n\r\nblarfcicle\"",
    // request/method.md:138 — M-SEARCH request
    "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nST: \"ssdp:all\"\r\n\r\n",
    // request/method.md:176 — PATCH request
    "PATCH /file.txt HTTP/1.1\r\nHost: www.example.com\r\nContent-Type: application/example\r\nIf-Match: \"e0023aa4e\"\r\nContent-Length: 10\r\n\r\ncccccccccc",
    // request/method.md:220 — PURGE request
    "PURGE /file.txt HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
    // request/method.md:248 — SEARCH request
    "SEARCH / HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
    // request/method.md:276 — LINK request
    "LINK /images/my_dog.jpg HTTP/1.1\r\nHost: example.com\r\nLink: <http://example.com/profiles/joe>; rel=\"tag\"\r\nLink: <http://example.com/profiles/sally>; rel=\"tag\"\r\n\r\n",
    // request/method.md:314 — LINK request
    "UNLINK /images/my_dog.jpg HTTP/1.1\r\nHost: example.com\r\nLink: <http://example.com/profiles/sally>; rel=\"tag\"\r\n\r\n",
    // request/method.md:347 — SOURCE request
    "SOURCE /music/sweet/music HTTP/1.1\r\nHost: example.com\r\n\r\n",
    // request/method.md:375 — SOURCE request with ICE
    "SOURCE /music/sweet/music ICE/1.0\r\nHost: example.com\r\n\r\n",
    // request/method.md:405 — OPTIONS request with RTSP
    "OPTIONS /music/sweet/music RTSP/1.0\r\nHost: example.com\r\n\r\n",
    // request/method.md:433 — ANNOUNCE request with RTSP
    "ANNOUNCE /music/sweet/music RTSP/1.0\r\nHost: example.com\r\n\r\n",
    // request/method.md:461 — PRI request HTTP2
    "PRI * HTTP/1.1\r\n\r\nSM\r\n\r\n",
    // request/method.md:485 — QUERY request
    "QUERY /contacts HTTP/1.1\r\nHost: example.org\r\nContent-Type: example/query\r\nAccept: text/csv\r\nContent-Length: 41\r\n\r\nselect surname, givenname, email limit 10",
    // request/pausing.md:7 — on_message_begin
    "POST / HTTP/1.1\r\nContent-Length: 3\r\n\r\nabc",
    // request/pausing.md:277 — on_chunk_header
    "PUT / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\na\r\n0123456789\r\n0\r\n\r\n",
    // request/pausing.md:316 — on_chunk_extension_name
    "PUT / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\na;foo=bar\r\n0123456789\r\n0\r\n\r\n",
    // request/pipelining.md:7 — Should parse multiple events
    "POST /aaa HTTP/1.1\r\nContent-Length: 3\r\n\r\nAAA\r\nPUT /bbb HTTP/1.1\r\nContent-Length: 4\r\n\r\nBBBB\r\nPATCH /ccc HTTP/1.1\r\nContent-Length: 5\r\n\r\nCCCC",
    // request/sample.md:9 — Simple request
    "OPTIONS /url HTTP/1.1\r\nHeader1: Value1\r\nHeader2:\t Value2\r\n\r\n",
    // request/sample.md:47 — Request with method starting with `H`
    "HEAD /url HTTP/1.1\r\n\r\n",
    // request/sample.md:70 — curl GET
    "GET /test HTTP/1.1\r\nUser-Agent: curl/7.18.0 (i486-pc-linux-gnu) libcurl/7.18.0 OpenSSL/0.9.8g zlib/1.2.3.3 libidn/1.1\r\nHost: 0.0.0.0=5000\r\nAccept: */*\r\n\r\n",
    // request/sample.md:108 — Firefox GET
    "GET /favicon.ico HTTP/1.1\r\nHost: 0.0.0.0=5000\r\nUser-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9) Gecko/2008061015 Firefox/3.0\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: en-us,en;q=0.5\r\nAccept-Encoding: gzip,deflate\r\nAccept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7\r\nKeep-Alive: 300\r\nConnection: keep-alive\r\n\r\n",
    // request/sample.md:171 — DUMBPACK
    "GET /dumbpack HTTP/1.1\r\naaaaaaaaaaaaa:++++++++++\r\n\r\n",
    // request/sample.md:199 — No headers and no body
    "GET /get_no_headers_no_body/world HTTP/1.1\r\n\r\n",
    // request/sample.md:222 — One header and no body
    "GET /get_one_header_no_body HTTP/1.1\r\nAccept: */*\r\n\r\n",
    // request/sample.md:253 — Apache bench GET
    "GET /test HTTP/1.0\r\nHost: 0.0.0.0:5000\r\nUser-Agent: ApacheBench/2.3\r\nAccept: */*\r\n\r\n",
    // request/sample.md:294 — Prefix newline
    "\r\nGET /test HTTP/1.1\r\n\r\n",
    // request/sample.md:317 — No HTTP version
    "GET /\r\n\r\n",
    // request/sample.md:336 — Line folding in header value with CRLF
    "GET / HTTP/1.1\r\nLine1:   abc\r\n\tdef\r\n ghi\r\n\t\tjkl\r\n  mno \r\n\t \tqrs\r\nLine2: \t line2\t\r\nLine3:\r\n line3\r\nLine4: \r\n \r\nConnection:\r\n close\r\n\r\n",
    // request/sample.md:398 — Line folding in header value with LF
    "GET / HTTP/1.1\r\nLine1:   abc\n\tdef\n ghi\n\t\tjkl\n  mno \n\t \tqrs\nLine2: \t line2\t\nLine3:\n line3\nLine4: \n \nConnection:\n close\n\n",
    // request/sample.md:436 — No LF after CR
    "GET / HTTP/1.1\rLine: 1\r\n",
    // request/sample.md:481 — Request starting with CRLF
    "\r\nGET /url HTTP/1.1\r\nHeader1: Value1\r\n\r\n",
    // request/sample.md:511 — Extended Characters
    "GET / HTTP/1.1\r\nTest: D\xc3\xbcsseldorf\r\n\r\n",
    // request/sample.md:541 — 255 ASCII in header value
    "OPTIONS /url HTTP/1.1\r\nHeader1: Value1\r\nHeader2: \xffValue2\r\n\r\n",
    // request/transfer-encoding.md:7 — Empty `Transfer-Encoding` with `Content-Length`
    "POST /first HTTP/1.1\r\nTransfer-Encoding:\r\nContent-Length: 5\r\n\r\nhello",
    // request/transfer-encoding.md:35 — Parsing and setting flag
    "PUT /url HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n",
    // request/transfer-encoding.md:62 — Parse chunks with lowercase size
    "PUT /url HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\na\r\n0123456789\r\n0\r\n\r\n",
    // request/transfer-encoding.md:99 — Parse chunks with uppercase size
    "PUT /url HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\nA\r\n0123456789\r\n0\r\n\r\n",
    // request/transfer-encoding.md:136 — POST with `Transfer-Encoding: chunked`
    "POST /post_chunked_all_your_base HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n1e\r\nall your base are belong to us\r\n0\r\n\r\n",
    // request/transfer-encoding.md:173 — Two chunks and triple zero prefixed end chunk
    "POST /two_chunks_mult_zero_end HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n000\r\n\r\n",
    // request/transfer-encoding.md:215 — Trailing headers
    "POST /chunked_w_trailing_headers HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\nVary: *\r\nContent-Type: text/plain\r\n\r\n",
    // request/transfer-encoding.md:267 — Chunk extensions
    "POST /chunked_w_unicorns_after_length HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5;ilovew3;somuchlove=aretheseparametersfor;another=withvalue\r\nhello\r\n6;blahblah;blah\r\n world\r\n0\r\n",
    // request/transfer-encoding.md:320 — No semicolon before chunk extensions
    "POST /chunked_w_unicorns_after_length HTTP/1.1\r\nHost: localhost\r\nTransfer-encoding: chunked\r\n\r\n2 erfrferferf\r\naa\r\n0 rrrr\r\n\r\n",
    // request/transfer-encoding.md:357 — No extension after semicolon
    "POST /chunked_w_unicorns_after_length HTTP/1.1\r\nHost: localhost\r\nTransfer-encoding: chunked\r\n\r\n2;\r\naa\r\n0\r\n\r\n",
    // request/transfer-encoding.md:395 — Chunk extensions quoting
    "POST /chunked_w_unicorns_after_length HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5;ilovew3=\"I \\\"love\\\"; \\\\extensions\\\\\";somuchlove=\"aretheseparametersfor\";blah;foo=bar\r\nhello\r\n6;blahblah;blah\r\n world\r\n0\r\n",
    // request/transfer-encoding.md:453 — Unbalanced chunk extensions quoting
    "POST /chunked_w_unicorns_after_length HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5;ilovew3=\"abc\";somuchlove=\"def; ghi\r\nhello\r\n6;blahblah;blah\r\n world\r\n0\r\n",
    // request/transfer-encoding.md:496 — Ignoring `pigeons`
    "PUT /url HTTP/1.1\r\nTransfer-Encoding: pigeons\r\n\r\n",
    // request/transfer-encoding.md:524 — POST with `Transfer-Encoding` and `Content-Length`
    "POST /post_identity_body_world?q=search#hey HTTP/1.1\r\nAccept: */*\r\nTransfer-Encoding: identity\r\nContent-Length: 5\r\n\r\nWorld",
    // request/transfer-encoding.md:565 — POST with `Transfer-Encoding` and `Content-Length` (lenient)
    "POST /post_identity_body_world?q=search#hey HTTP/1.1\r\nAccept: */*\r\nTransfer-Encoding: identity\r\nContent-Length: 1\r\n\r\nWorld",
    // request/transfer-encoding.md:603 — POST with empty `Transfer-Encoding` and `Content-Length` (lenient)
    "POST / HTTP/1.1\r\nHost: foo\r\nContent-Length: 10\r\nTransfer-Encoding:\r\nTransfer-Encoding:\r\nTransfer-Encoding:\r\n\r\n2\r\nAA\r\n0",
    // request/transfer-encoding.md:642 — POST with `chunked` before other transfer coding names
    "POST /post_identity_body_world?q=search#hey HTTP/1.1\r\nAccept: */*\r\nTransfer-Encoding: chunked, deflate\r\n\r\nWorld",
    // request/transfer-encoding.md:673 — POST with `chunked` and duplicate transfer-encoding
    "POST /post_identity_body_world?q=search#hey HTTP/1.1\r\nAccept: */*\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: deflate\r\n\r\nWorld",
    // request/transfer-encoding.md:780 — POST with `chunked` as last transfer-encoding
    "POST /post_identity_body_world?q=search#hey HTTP/1.1\r\nAccept: */*\r\nTransfer-Encoding: deflate, chunked\r\n\r\n5\r\nWorld\r\n0\r\n\r\n",
    // request/transfer-encoding.md:822 — POST with `chunked` as last transfer-encoding (multiple headers)
    "POST /post_identity_body_world?q=search#hey HTTP/1.1\r\nAccept: */*\r\nTransfer-Encoding: deflate\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nWorld\r\n0\r\n\r\n",
    // request/transfer-encoding.md:869 — POST with `chunkedchunked` as transfer-encoding
    "POST /post_identity_body_world?q=search#hey HTTP/1.1\r\nAccept: */*\r\nTransfer-Encoding: chunkedchunked\r\n\r\n5\r\nWorld\r\n0\r\n\r\n",
    // request/transfer-encoding.md:906 — Missing last-chunk
    "PUT /url HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nfoo\r\n\r\n",
    // request/transfer-encoding.md:940 — Validate chunk parameters
    "PUT /url HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n3 \n  \r\nfoo\r\n\r\n",
    // request/transfer-encoding.md:971 — Invalid OBS fold after chunked value
    "PUT /url HTTP/1.1\r\nTransfer-Encoding: chunked\r\n  abc\r\n\r\n5\r\nWorld\r\n0\r\n\r\n",
    // request/transfer-encoding.md:1006 — Chunk header not terminated by CRLF
    "GET / HTTP/1.1\r\nHost: a\r\nConnection: close \r\nTransfer-Encoding: chunked \r\n\r\n5\r\r;ABCD\r\n34\r\nE\r\n0\r\n\r\nGET / HTTP/1.1 \r\nHost: a\r\nContent-Length: 5\r\n\r\n0\r\n",
    // request/transfer-encoding.md:1055 — Chunk header not terminated by CRLF (lenient)
    "GET / HTTP/1.1\r\nHost: a\r\nConnection: close \r\nTransfer-Encoding: chunked \r\n\r\n6\r\r;ABCD\r\n33\r\nE\r\n0\r\n\r\nGET / HTTP/1.1 \r\nHost: a\r\nContent-Length: 5\r\n0\r\n\r\n",
    // request/transfer-encoding.md:1127 — Chunk data not terminated by CRLF
    "GET / HTTP/1.1\r\nHost: a\r\nConnection: close \r\nTransfer-Encoding: chunked \r\n\r\n5\r\nABCDE0\r\n",
    // request/transfer-encoding.md:1213 — Space after chunk header
    "PUT /url HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\na \r\n0123456789\r\n0\r\n\r\n",
    // request/uri.md:7 — Quotes in URI
    "GET /with_\"lovely\"_quotes?foo=\\\"bar\\\" HTTP/1.1\r\n\r\n",
    // request/uri.md:32 — Query URL with question mark
    "GET /test.cgi?foo=bar?baz HTTP/1.1\r\n\r\n",
    // request/uri.md:55 — Host terminated by a query string
    "GET http://hypnotoad.org?hail=all HTTP/1.1\r\n\r\n\r\n",
    // request/uri.md:78 — `host:port` terminated by a query string
    "GET http://hypnotoad.org:1234?hail=all HTTP/1.1\r\n\r\n",
    // request/uri.md:105 — Query URL with vertical bar character
    "GET /test.cgi?query=| HTTP/1.1\r\n\r\n",
    // request/uri.md:128 — `host:port` terminated by a space
    "GET http://hypnotoad.org:1234 HTTP/1.1\r\n\r\n",
    // request/uri.md:151 — Disallow UTF-8 in URI path in strict mode
    "GET /\xce\xb4\xc2\xb6/\xce\xb4t/pope?q=1#narf HTTP/1.1\r\nHost: github.com\r\n\r\n",
    // request/uri.md:168 — Fragment in URI
    "GET /forums/1/topics/2375?page=1#posts-17408 HTTP/1.1\r\n\r\n",
    // request/uri.md:191 — Underscore in hostname
    "CONNECT home_0.netscape.com:443 HTTP/1.0\r\nUser-agent: Mozilla/1.1N\r\nProxy-authorization: basic aGVsbG86d29ybGQ=\r\n\r\n",
    // request/uri.md:225 — `host:port` and basic auth
    "GET http://a%12:b!&*$@hypnotoad.org:1234/toto HTTP/1.1\r\n\r\n",
    // request/uri.md:248 — Space in URI
    "GET /foo bar/ HTTP/1.1\r\n\r\n",
};

pub const responses = [_][]const u8{
    // response/connection.md:7 — Proxy-Connection
    "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=UTF-8\r\nContent-Length: 11\r\nProxy-Connection: close\r\nDate: Thu, 31 Dec 2009 20:55:48 +0000\r\n\r\nhello world",
    // response/connection.md:52 — HTTP/1.0 with keep-alive and EOF-terminated 200 status
    "HTTP/1.0 200 OK\r\nConnection: keep-alive\r\n\r\nHTTP/1.0 200 OK",
    // response/connection.md:80 — HTTP/1.0 with keep-alive and 204 status
    "HTTP/1.0 204 No content\r\nConnection: keep-alive\r\n\r\nHTTP/1.0 200 OK",
    // response/connection.md:116 — HTTP/1.1 with EOF-terminated 200 status
    "HTTP/1.1 200 OK\r\n\r\nHTTP/1.1 200 OK",
    // response/connection.md:139 — HTTP/1.1 with 204 status
    "HTTP/1.1 204 No content\r\n\r\nHTTP/1.1 200 OK",
    // response/connection.md:167 — HTTP/1.1 with keep-alive disabled and 204 status
    "HTTP/1.1 204 No content\r\nConnection: close\r\n\r\nHTTP/1.1 200 OK",
    // response/connection.md:196 — HTTP/1.1 with keep-alive disabled, content-length (lenient)
    "HTTP/1.1 200 No content\r\nContent-Length: 5\r\nConnection: close\r\n\r\n2ad731e3-4dcd-4f70-b871-0ad284b29ffc",
    // response/connection.md:296 — HTTP 101 response with Upgrade and Content-Length header
    "HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\nUpgrade: h2c\r\nContent-Length: 4\r\n\r\nbodyproto",
    // response/connection.md:334 — HTTP 101 response with Upgrade and Transfer-Encoding header
    "HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\nUpgrade: h2c\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nbo\r\n2\r\ndy\r\n0\r\n\r\nproto",
    // response/connection.md:377 — HTTP 200 response with Upgrade header
    "HTTP/1.1 200 OK\r\nConnection: upgrade\r\nUpgrade: h2c\r\n\r\nbody",
    // response/connection.md:408 — HTTP 200 response with Upgrade header and Content-Length
    "HTTP/1.1 200 OK\r\nConnection: upgrade\r\nUpgrade: h2c\r\nContent-Length: 4\r\n\r\nbody",
    // response/connection.md:445 — HTTP 200 response with Upgrade header and Transfer-Encoding
    "HTTP/1.1 200 OK\r\nConnection: upgrade\r\nUpgrade: h2c\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nbo\r\n2\r\ndy\r\n0\r\n\r\n",
    // response/connection.md:495 — HTTP 304 with Content-Length
    "HTTP/1.1 304 Not Modified\r\nContent-Length: 10\r\n\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello",
    // response/connection.md:540 — HTTP 304 with Transfer-Encoding
    "HTTP/1.1 304 Not Modified\r\nTransfer-Encoding: chunked\r\n\r\nHTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n",
    // response/connection.md:589 — HTTP 100 first, then 400
    "HTTP/1.1 100 Continue\r\n\r\n\r\nHTTP/1.1 404 Not Found\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: 14\r\nDate: Fri, 15 Sep 2023 19:47:23 GMT\r\nServer: Python/3.10 aiohttp/4.0.0a2.dev0\r\n\r\n404: Not Found",
    // response/connection.md:644 — HTTP 103 first, then 200
    "HTTP/1.1 103 Early Hints\r\nLink: </styles.css>; rel=preload; as=style\r\n\r\nHTTP/1.1 200 OK\r\nDate: Wed, 13 Sep 2023 11:09:41 GMT\r\nConnection: keep-alive\r\nKeep-Alive: timeout=5\r\nContent-Length: 17\r\n\r\nresponse content",
    // response/content-length.md:13 — Response without `Content-Length`, but with body
    "HTTP/1.1 200 OK\r\nDate: Tue, 04 Aug 2009 07:59:32 GMT\r\nServer: Apache\r\nX-Powered-By: Servlet/2.5 JSP/2.1\r\nContent-Type: text/xml; charset=utf-8\r\nConnection: close\r\n\r\n<?xml version=\\\"1.0\\\" encoding=\\\"UTF-8\\\"?>\n<SOAP-ENV:Envelope xmlns:SOAP-ENV=\\\"http://schemas.xmlsoap.org/soap/envelope/\\\">\n  <SOAP-ENV:Body>\n    <SOAP-ENV:Fault>\n       <faultcode>SOAP-ENV:Client</faultcode>\n       <faultstring>Client Error</faultstring>\n    </SOAP-ENV:Fault>\n  </SOAP-ENV:Body>\n</SOAP-ENV:Envelope>",
    // response/content-length.md:86 — Content-Length-X
    "HTTP/1.1 200 OK\r\nContent-Length-X: 0\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nOK\r\n0\r\n\r\n",
    // response/content-length.md:126 — Content-Length reset when no body is received
    "HTTP/1.1 200 OK\r\nContent-Length: 123\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 456\r\n\r\n",
    // response/content-length.md:171 — Tabs in `Content-Length` (surrounding)
    "HTTP/1.1 200 OK\r\nContent-Length:\t42\t\r\n\r\n",
    // response/finish.md:9 — It should be safe to finish with cb after empty response
    "HTTP/1.1 200 OK\r\n\r\n",
    // response/invalid.md:7 — Incomplete HTTP protocol
    "HTP/1.1 200 OK\r\n\r\n",
    // response/invalid.md:22 — Extra digit in HTTP major version
    "HTTP/01.1 200 OK\r\n\r\n",
    // response/invalid.md:39 — Extra digit in HTTP major version #2
    "HTTP/11.1 200 OK\r\n\r\n",
    // response/invalid.md:56 — Extra digit in HTTP minor version
    "HTTP/1.01 200 OK\r\n\r\n",
    // response/invalid.md:75 — Tab after HTTP version
    "HTTP/1.1\t200 OK\r\n\r\n",
    // response/invalid.md:93 — CR before response and tab after HTTP version
    "\rHTTP/1.1\t200 OK\r\n\r\n",
    // response/invalid.md:111 — Headers separated by CR
    "HTTP/1.1 200 OK\r\nFoo: 1\rBar: 2\r\n\r\n",
    // response/invalid.md:135 — Bare CR after response line
    "HTTP/1.1 200 OK\rContent-Length: 0\r\n\r\n",
    // response/invalid.md:179 — Bare CR followed by CR after response line
    "HTTP/1.1 200 OK\r\rContent-Length: 4\r\n\r\nEvil",
    // response/invalid.md:198 — Invalid HTTP version
    "HTTP/5.6 200 OK\r\n\r\n",
    // response/invalid.md:215 — Invalid space after start line
    "HTTP/1.1 200 OK\r\n Host: foo",
    // response/invalid.md:234 — Extra space between HTTP version and status code
    "HTTP/1.1  200 OK\r\n\r\n",
    // response/invalid.md:252 — Extra space between status code and reason
    "HTTP/1.1 200  OK\r\n\r\n",
    // response/invalid.md:272 — One-digit status code
    "HTTP/1.1 2 OK\r\n\r\n",
    // response/invalid.md:290 — Only LFs present and no body
    "HTTP/1.1 200 OK\nContent-Length: 0\n\n",
    // response/invalid.md:330 — Only LFs present
    "HTTP/1.1 200 OK\nFoo: abc\nBar: def\n\nBODY\n\\",
    // response/pausing.md:7 — on_message_begin
    "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc",
    // response/pausing.md:203 — on_chunk_header
    "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\na\r\n0123456789\r\n0\r\n\r\n",
    // response/pausing.md:240 — on_chunk_extension_name
    "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\na;foo=bar\r\n0123456789\r\n0\r\n\r\n",
    // response/pipelining.md:7 — Should parse multiple events
    "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nAAA\r\nHTTP/1.1 201 Created\r\nContent-Length: 4\r\n\r\nBBBB\r\nHTTP/1.1 202 Accepted\r\nContent-Length: 5\r\n\r\nCCCC",
    // response/sample.md:7 — Simple response
    "HTTP/1.1 200 OK\r\nHeader1: Value1\r\nHeader2:\t Value2\r\nContent-Length: 0\r\n\r\n",
    // response/sample.md:43 — RTSP response
    "RTSP/1.1 200 OK\r\n\r\n",
    // response/sample.md:63 — ICE response
    "ICE/1.1 200 OK\r\n\r\n",
    // response/sample.md:85 — Error on invalid response start
    "HTTPER/1.1 200 OK\r\n\r\n",
    // response/sample.md:121 — Google 301
    "HTTP/1.1 301 Moved Permanently\r\nLocation: http://www.google.com/\r\nContent-Type: text/html; charset=UTF-8\r\nDate: Sun, 26 Apr 2009 11:11:49 GMT\r\nExpires: Tue, 26 May 2009 11:11:49 GMT\r\nX-$PrototypeBI-Version: 1.6.0.3\r\nCache-Control: public, max-age=2592000\r\nServer: gws\r\nContent-Length:  219  \r\n\r\n<HTML><HEAD><meta http-equiv=content-type content=text/html;charset=utf-8>\n<TITLE>301 Moved</TITLE></HEAD><BODY>\n<H1>301 Moved</H1>\nThe document has moved\n<A HREF=\"http://www.google.com/\">here</A>.\r\n</BODY></HTML>",
    // response/sample.md:199 — amazon.com
    "HTTP/1.1 301 MovedPermanently\r\nDate: Wed, 15 May 2013 17:06:33 GMT\r\nServer: Server\r\nx-amz-id-1: 0GPHKXSJQ826RK7GZEB2\r\np3p: policyref=\"http://www.amazon.com/w3c/p3p.xml\",CP=\"CAO DSP LAW CUR ADM IVAo IVDo CONo OTPo OUR DELi PUBi OTRi BUS PHY ONL UNI PUR FIN COM NAV INT DEM CNT STA HEA PRE LOC GOV OTC \"\r\nx-amz-id-2: STN69VZxIFSz9YJLbz1GDbxpbjG6Qjmmq5E3DxRhOUw+Et0p4hr7c/Q8qNcx4oAD\r\nLocation: http://www.amazon.com/Dan-Brown/e/B000AP9DSU/ref=s9_pop_gw_al1?_encoding=UTF8&refinementId=618073011&pf_rd_m=ATVPDKIKX0DER&pf_rd_s=center-2&pf_rd_r=0SHYY5BZXN3KR20BNFAY&pf_rd_t=101&pf_rd_p=1263340922&pf_rd_i=507846\r\nVary: Accept-Encoding,User-Agent\r\nContent-Type: text/html; charset=ISO-8859-1\r\nTransfer-Encoding: chunked\r\n\r\n1\r\n\n\r\n0\r\n\r\n",
    // response/sample.md:274 — No headers and no body
    "HTTP/1.1 404 Not Found\r\n\r\n",
    // response/sample.md:294 — No reason phrase
    "HTTP/1.1 301\r\n\r\n",
    // response/sample.md:313 — Empty reason phrase after space
    "HTTP/1.1 200 \r\n\r\n",
    // response/sample.md:333 — No carriage ret
    "HTTP/1.1 200 OK\nContent-Type: text/html; charset=utf-8\nConnection: close\n\nthese headers are from http://news.ycombinator.com/",
    // response/sample.md:387 — Underscore in header key
    "HTTP/1.1 200 OK\r\nServer: DCLK-AdSvr\r\nContent-Type: text/xml\r\nContent-Length: 0\r\nDCLK_imp: v7;x;114750856;0-0;0;17820020;0/0;21603567/21621457/1;;~okv=;dcmt=text/xml;;~cs=o\r\n\r\n",
    // response/sample.md:431 — bonjourmadame.fr
    "HTTP/1.0 301 Moved Permanently\r\nDate: Thu, 03 Jun 2010 09:56:32 GMT\r\nServer: Apache/2.2.3 (Red Hat)\r\nCache-Control: public\r\nPragma: \r\nLocation: http://www.bonjourmadame.fr/\r\nVary: Accept-Encoding\r\nContent-Length: 0\r\nContent-Type: text/html; charset=UTF-8\r\nConnection: keep-alive\r\n\r\n",
    // response/sample.md:497 — Spaces in header value
    "HTTP/1.1 200 OK\r\nDate: Tue, 28 Sep 2010 01:14:13 GMT\r\nServer: Apache\r\nCache-Control: no-cache, must-revalidate\r\nExpires: Mon, 26 Jul 1997 05:00:00 GMT\r\n.et-Cookie: PlaxoCS=1274804622353690521; path=/; domain=.plaxo.com\r\nVary: Accept-Encoding\r\n_eep-Alive: timeout=45\r\n_onnection: Keep-Alive\r\nTransfer-Encoding: chunked\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n0\r\n\r\n",
    // response/sample.md:577 — Spaces in header name
    "HTTP/1.1 200 OK\r\nServer: Microsoft-IIS/6.0\r\nX-Powered-By: ASP.NET\r\nen-US Content-Type: text/xml\r\nContent-Type: text/xml\r\nContent-Length: 16\r\nDate: Fri, 23 Jul 2010 18:45:38 GMT\r\nConnection: keep-alive\r\n\r\n<xml>hello</xml>",
    // response/sample.md:612 — Non ASCII in status line
    "HTTP/1.1 500 Ori\xc3\xabntatieprobleem\r\nDate: Fri, 5 Nov 2010 23:07:12 GMT+2\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    // response/sample.md:648 — HTTP version 0.9
    "HTTP/0.9 200 OK\r\n\r\n",
    // response/sample.md:672 — No Content-Length, no Transfer-Encoding
    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nhello world",
    // response/sample.md:698 — Response starting with CRLF
    "\r\nHTTP/1.1 200 OK\r\nHeader1: Value1\r\nHeader2:\t Value2\r\nContent-Length: 0\r\n\r\n",
    // response/transfer-encoding.md:7 — Empty `Transfer-Encoding` with `Content-Length`
    "HTTP/1.1 200 OK\r\nTransfer-Encoding:\r\nContent-Length: 5\r\n\r\nhello",
    // response/transfer-encoding.md:31 — Trailing space on chunked body
    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n25  \r\nThis is the data in the first chunk\r\n\r\n1C\r\nand this is the second one\r\n\r\n0  \r\n\r\n",
    // response/transfer-encoding.md:70 — `chunked` before other transfer-encoding
    "HTTP/1.1 200 OK\r\nAccept: */*\r\nTransfer-Encoding: chunked, deflate\r\n\r\nWorld",
    // response/transfer-encoding.md:101 — multiple transfer-encoding where chunked is not the last one
    "HTTP/1.1 200 OK\r\nAccept: */*\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: identity\r\n\r\nWorld",
    // response/transfer-encoding.md:139 — `chunkedchunked` transfer-encoding does not enable chunked enconding
    "HTTP/1.1 200 OK\r\nAccept: */*\r\nTransfer-Encoding: chunkedchunked\r\n\r\n2\r\nOK\r\n0\r\n\r\n",
    // response/transfer-encoding.md:184 — Chunk extensions
    "HTTP/1.1 200 OK\r\nHost: localhost\r\nTransfer-encoding: chunked\r\n\r\n5;ilovew3;somuchlove=aretheseparametersfor\r\nhello\r\n6;blahblah;blah\r\n world\r\n0\r\n\r\n",
    // response/transfer-encoding.md:239 — No semicolon before chunk extensions
    "HTTP/1.1 200 OK\r\nHost: localhost\r\nTransfer-encoding: chunked\r\n\r\n2 erfrferferf\r\naa\r\n0 rrrr\r\n\r\n",
    // response/transfer-encoding.md:275 — No extension after semicolon
    "HTTP/1.1 200 OK\r\nHost: localhost\r\nTransfer-encoding: chunked\r\n\r\n2;\r\naa\r\n0\r\n\r\n",
    // response/transfer-encoding.md:311 — Chunk extensions quoting
    "HTTP/1.1 200 OK\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n5;ilovew3=\"I love; extensions\";somuchlove=\"aretheseparametersfor\";blah;foo=bar\r\nhello\r\n6;blahblah;blah\r\n world\r\n0\r\n",
    // response/transfer-encoding.md:372 — Unbalanced chunk extensions quoting
    "HTTP/1.1 200 OK\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n5;ilovew3=\"abc\";somuchlove=\"def; ghi\r\nhello\r\n6;blahblah;blah\r\n world\r\n0\r\n",
    // response/transfer-encoding.md:416 — Invalid OBS fold after chunked value
    "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n  abc\r\n\r\n5\r\nWorld\r\n0\r\n\r\n",
};
