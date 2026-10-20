# zurl

[![CI](https://github.com/zoxy-io/zurl/actions/workflows/ci.yml/badge.svg)](https://github.com/zoxy-io/zurl/actions/workflows/ci.yml)

An **experimental** `std.Io`-native HTTP/1.1 client for Zig 0.16 — zero
allocation, one dependency, and a whole-request deadline that actually fires.

Every design choice traces back to a real incident — a segfault, an unbounded
hang, a leak on timeout, a body read as plain text — recorded as a rule in
[docs/DESIGN.md](docs/DESIGN.md).

> Experimental. The API moves — see [docs/SCOPE.md](docs/SCOPE.md) for what
> is settled and what is not.

## Requirements

Zig **0.16.0** exactly — `std.Io` moves, so 0.15 and master are both wrong.

One dependency, [zoxy-io/hparse](https://github.com/zoxy-io/hparse), for the
head scan. It is std-only and does no I/O, so zurl stays a leaf package: it
brings no runtime and no TLS stack that could collide with one you already pin.

## Install

`direnv allow` brings up a pinned shell with the toolchain and curl (the
other half of `zig build curl-diff`); `devenv shell` does the same without
direnv. Neither is required if you already have 0.16.0 on `PATH`.

```sh
zig fetch --save git+https://github.com/zoxy-io/zurl
```

```zig
const zurl = b.dependency("zurl", .{ .target = target, .optimize = optimize });
exe.root_module.addImport("zurl", zurl.module("zurl"));
```

## Guarantees

Framing is the library's job, always: content-length, chunked (with trailers),
close-delimited, bodyless statuses, `Transfer-Encoding` beating
`Content-Length`, conflicting `Content-Length` refused. You never see an
undecoded byte and never choose whether a 204 has a body.

That extends to content codings. zurl decodes none, so a body arriving as
`gzip` is `error.UnsupportedContentEncoding` rather than compressed bytes
handed to a sink expecting text. Nothing here sends `accept-encoding`, so a
compliant origin never triggers it; pass `allow_encoded_body` if the raw bytes
are what you actually want.

Works identically on `Io.Threaded` and zio — both are production backends for
its consumers, so a mechanism that only works on one is not a mechanism zurl
uses.

Requests carry `user-agent: zurl/0.0.0` unless you set `user_agent` yourself
(or null it, if you send your own).

[docs/SCOPE.md](docs/SCOPE.md) lists what is next and what is deliberately
refused (HTTP/2, cookies, connection pools, signing schemes).

## Use

Every request is bounded. `fetch` returns `null` when the deadline elapsed —
that is not an error case you may forget to handle, it is the return type.

```zig
var body: std.Io.Writer.Allocating = .init(gpa);
defer body.deinit();

const res = try zurl.fetch(io, .{
    .url = "http://127.0.0.1:8080/metrics",
    .sink = .{ .collect = &body },
    .deadline_ns = 5 * std.time.ns_per_s,
    .what = "metrics",           // named in the timeout message, never a URL
}) orelse return error.TimedOut;

if (!res.ok()) return error.BadStatus;
std.debug.print("{d} bytes\n", .{body.written().len});
```

**Bodies go to a sink; there is no way to forget one.** Pick how you want it:

```zig
.sink = .discard,                 // HEAD, DELETE, a webhook's 204
.sink = .{ .collect = &body },    // keep the whole thing
.sink = .{ .lines = &line_sink }, // parse a line at a time, keep none of it
.sink = .{ .stream = writer },    // any other Io.Writer
```

`lines` is what lets a 1.5 MiB Prometheus exposition be parsed without ever
holding more than one line. Lines too long for `carry` are dropped whole and
counted, never truncated — a truncated metric line still parses, and reports a
wrong number.

```zig
var buf: [64 * 1024]u8 = undefined;
var carry: [8 * 1024]u8 = undefined;
var sink = zurl.LineSink.init(&buf, &carry, &ctx, onLine);
```

### Reading response headers

One callback, fired per header and again per chunked trailer, in order, with
values already trimmed. `name` and `value` point into the reader's buffer and
the body is about to overwrite them — **copy what you want to keep.** A map
would have to allocate, and zurl does not.

```zig
fn onHeader(ctx: ?*anyopaque, name: []const u8, value: []const u8) void {
    const wait: *?zurl.RetryAfter = @ptrCast(@alignCast(ctx.?));
    // First occurrence wins: a trailer can repeat a header name.
    if (wait.* == null and std.ascii.eqlIgnoreCase(name, "retry-after"))
        wait.* = zurl.retry.parse(value);
}

var retry_after: ?zurl.RetryAfter = null;
const res = try zurl.fetch(io, .{
    .url = url,
    .on_header = onHeader,
    .ctx = &retry_after,
}) orelse return error.TimedOut;
```

### Backing off

zurl never retries — whether replaying a request is safe is something only you
know, and a silent second `POST` is worse than any duplication it would save.
What it does is give you the two things a retry loop needs, so you are not
guessing a backoff or writing a date parser:

```zig
if (res.throttled()) {                  // 429 or 503
    const wait_s: u64 = switch (retry_after orelse .{ .seconds = 1 }) {
        .seconds => |s| s,
        // A date may be in the past, which means "no delay".
        .at_unix_s => |at| @intCast(@max(0, at - std.time.timestamp())),
    };
    // A cancelled sleep means the caller's own deadline fired, which is a
    // reason to stop waiting, not an error to report.
    io.sleep(.fromNanoseconds(wait_s * std.time.ns_per_s), .awake) catch {};
}
switch (res.class()) { .success => {}, .server_error => {}, else => {} }
```

### Redirects

**Off by default.** `std.http.Client` follows them silently, so a 302 there is
invisible; here it comes back as a 302 you can see. Opt in with a hop count and
a buffer, which bounds the whole chain:

```zig
var hops: [2 * 1024]u8 = undefined;
const res = try zurl.fetch(io, .{
    .url = url,
    .authorization = "Bearer …",
    .redirects = .{ .max = 3, .buf = &hops },
}) orelse return error.TimedOut;
```

`authorization` follows the origin it was issued for and **nowhere else** — a
hop to a different scheme, host or port drops it. That is structural, not a
flag: otherwise a redirect is a way to collect your bearer token.

303 rewrites the method to GET and drops the body; 301 and 302 do that for a
POST only, because that is the whole of the historical deviation RFC 9110
permits — a PUT or DELETE keeps both. 307 and 308 always keep both, and HEAD
survives every one of them. The body of a 3xx that gets followed is never
delivered to your sink.

### https

Trust anchors are **yours**. There is no default, on purpose: loading a store
allocates and zurl does not, and a caller who silently got "verify nothing"
would hold an https URL that looks secure and is not. An https URL with no
`tls` config is `error.TlsNotConfigured`, refused before anything is dialled.

```zig
var certificates: std.crypto.Certificate.Bundle = .empty;
defer certificates.deinit(gpa);
try certificates.rescan(gpa, io, .now(io, .real));   // once, at startup
var lock: std.Io.RwLock = .init;

const res = try zurl.fetch(io, .{
    .url = "https://api.example.com/v1/things",
    .authorization = "Bearer …",
    .sink = .{ .collect = &body },
    .tls = .{ .ca = .{ .bundle = .{
        .gpa = gpa, .lock = &lock, .certificates = &certificates,
    } } },
}) orelse return error.TimedOut;
```

### Many requests, one connection

`fetch` dials, sends `connection: close`, and hangs up — right for a poll or a
one-shot, wasteful for a dozen calls to one origin. `Connection` is the layer
underneath: a `*Io.Reader` and a `*Io.Writer`, and it does not care where they
came from — plain TCP, std TLS, zrk's ztls, or two fixed buffers in a test.

```zig
var conn = zurl.Connection.init(transport.reader(), transport.writer());
const res = try conn.roundTrip(.{ .host = "example.com", .target = "/" }, sink, .{});
```

## The `zurl` binary

A curl-shaped front end ships alongside the library:

```sh
zig build -Doptimize=ReleaseFast
./zig-out/bin/zurl -s -w "%{http_code}" -o page.html https://example.com/
```

It exists to be one half of a **differential oracle**. `zig build curl-diff`
sends the same request through curl and through it and requires the same body
bytes, status and exit code — rule 4's discipline one level up.

Flags: `-X -H -d -o -i -D -L -u -A --max-time -k --cacert -I -f -s` and a `-w`
subset. Not `--compressed`: zurl decodes no content codings, so asking an
origin to gzip would produce a body it must refuse — and unknown flags are a
usage error rather than a silent difference.

## Performance

Benchmarked with `zig build bench-parse -Doptimize=ReleaseFast` (parser) and
`bench-e2e` (wire, against `std.http.Client`). Compare bands from a run on your
own box, not a number from this file — rule 8 in
[docs/DESIGN.md](docs/DESIGN.md) explains why, and
[docs/RESEARCH.md](docs/RESEARCH.md) has the comparison against std.

## Licence

MIT — see [LICENSE](LICENSE), the same terms as the sibling `zoxy` and `zrk`
repositories.

## Docs

| | |
|---|---|
| [docs/DESIGN.md](docs/DESIGN.md) | the eight rules, each traceable to an incident — *what must be true* |
| [docs/SCOPE.md](docs/SCOPE.md) | what is in, what is the caller's, what is refused, and what is next |
| [docs/RESEARCH.md](docs/RESEARCH.md) | what exists in the ecosystem and why none of it fits |
| [docs/TIGER_STYLE.md](docs/TIGER_STYLE.md) | how it is written |
| [CLAUDE.md](CLAUDE.md) | how a change lands: slices, and the gates each one passes |
