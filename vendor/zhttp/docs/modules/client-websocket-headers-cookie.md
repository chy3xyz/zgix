# Client · WebSocket · Headers · Cookie

API reference for the HTTP client, WebSocket connection, HTTP headers, and cookie
management modules.

---

## Client (`src/client/Client.zig`)

RFC 2616 HTTP/1.1 client with TLS (OpenSSL) and HTTP/2 (ALPN / h2c) support.
Built on `std.Io`.

### Types

```zig
pub const Config = struct {
    host: []const u8,
    port: u16 = 80,
    read_buffer_size: usize = 8192,
    write_buffer_size: usize = 8192,
    connection_timeout_s: u32 = 30,
    read_timeout_s: u32 = 60,
    max_response_size: usize = 10 * 1024 * 1024,
    tls_config: ?tls.config.Client = null,
    h2_prior_knowledge: bool = false,
};
```

```zig
pub const Url = struct {
    scheme: []const u8,
    host: []const u8,
    port: u16,
    path: []const u8,

    pub fn parse(url_str: []const u8) ?Url;
};
```

```zig
pub const StreamResponse = struct {
    response: Response,
    reader: *Io.Reader,
    chunked: bool,
    content_length: ?usize,
};
```

### Error Sets

```zig
const ClientError = error{
    ConnectionFailed, SendFailed, ResponseTooLarge,
    InvalidResponse, ReadTimeout, WriteFailed,
    TlsCertificateExpired, TlsCertificateRevoked,
    TlsCertificateUnknown, TlsUnsupportedCertificate,
    TlsCertificateRequired, TlsHandshakeFailure,
    TlsAlert, TlsUnexpectedMessage, TlsCipherNoSpaceLeft,
};

pub const ResponseParseError = ClientError || error{
    InvalidStatusLine, InvalidVersion, InvalidStatusCode,
    InvalidHeader, MissingContentLength, InvalidChunkedEncoding,
};
```

### Functions

```zig
pub fn init(allocator: std.mem.Allocator, config: Config) Client
```
Create a client. Allocates internal read/write buffers from `allocator`.

```zig
pub fn deinit(self: *Client) void
```
Close the connection and free buffers. Safe to call multiple times.

```zig
pub fn connect(self: *Client, io: Io) ClientError!void
```
Open a TCP connection. Performs TLS handshake and h2c/ALPN negotiation if
configured. Closes any previous connection first.

```zig
pub fn close(self: *Client) void
```
Close the active connection (TLS, H2, TCP).

```zig
pub fn request(
    self: *Client,
    io: Io,
    method: Request.Method,
    uri: []const u8,
    headers: ?Headers,
    body: ?[]const u8,
) ResponseParseError!Response
```
Send a request and return the full, buffered response. HTTP/2 requests use the
h2 sub-system automatically.

```zig
pub fn requestStream(
    self: *Client,
    io: Io,
    method: Request.Method,
    uri: []const u8,
    headers: ?Headers,
    body: ?[]const u8,
) ResponseParseError!StreamResponse
```
Like `request`, but returns `StreamResponse` with a body `reader`. The caller
reads the body incrementally. Do not `response.deinit()` until done reading.
Not supported for HTTP/2.

```zig
pub fn intToStatusCode(code: u16) ?Response.StatusCode
```
Map an integer status code to the `Response.StatusCode` enum. Returns `null`
for unknown codes.

### Example

```zig
const url = Client.Url.parse("http://example.com/path").?;

var client = Client.init(allocator, .{
    .host = url.host,
    .port = url.port,
    .connection_timeout_s = 10,
    .read_timeout_s = 10,
});
defer client.deinit();

try client.connect(io);

var resp = try client.request(io, .GET, url.path, null, null);
defer resp.deinit(allocator);
```

---

## WebSocket (`src/server/WebSocket.zig`)

RFC 6455 WebSocket server support: upgrade validation, frame encoding/decoding,
fragmentation reassembly, and connection lifecycle.

### Types

```zig
pub const Handler = *const fn (*Conn, *const Request) void;
```
Handler signature. Called after the 101 handshake completes; owns the
connection loop.

```zig
pub const CloseCode = enum(u16) {
    normal = 1000,
    going_away = 1001,
    protocol_error = 1002,
    unsupported_data = 1003,
    no_status = 1005,
    abnormal = 1006,
    invalid_payload = 1007,
    policy_violation = 1008,
    message_too_big = 1009,
    mandatory_extension = 1010,
    internal_error = 1011,
};
```

```zig
pub const Opcode = enum(u4) {
    continuation = 0,
    text = 1,
    binary = 2,
    close = 8,
    ping = 9,
    pong = 10,
    _,
};
```

```zig
pub const Frame = struct {
    fin: bool,
    opcode: Opcode,
    payload: []const u8,
};
```

```zig
pub const Message = struct {
    opcode: Opcode,
    payload: []const u8,
};
```

### Constants

```zig
pub const max_frame_size: usize = 16 * 1024 * 1024;
```

### Conn

```zig
pub const Conn = struct {
    reader: *Io.Reader,
    writer: *Io.Writer,
    buf: []u8,
    closed: bool = false,

    pub fn init(reader: *Io.Reader, writer: *Io.Writer, buf: []u8) Conn;

    /// Receive the next complete message. Handles control frames
    /// internally and reassembles fragments. Returns null on close.
    pub fn recv(self: *Conn) !?Message;

    /// Send a text frame.
    pub fn send(self: *Conn, data: []const u8) !void;

    /// Send a binary frame.
    pub fn sendBinary(self: *Conn, data: []const u8) !void;

    /// Send a ping frame.
    pub fn ping(self: *Conn) !void;

    /// Send a pong frame.
    pub fn pong(self: *Conn, data: []const u8) !void;

    /// Send a close frame and mark the connection closed.
    pub fn close(self: *Conn, code: u16, reason: []const u8) !void;
};
```

### Upgrade Handshake

```zig
pub fn validateUpgrade(request: *const Request) ?[]const u8
```
Returns `Sec-WebSocket-Key` if the request has valid `Upgrade`,
`Connection`, and `Sec-WebSocket-Version: 13` headers. Returns `null`
otherwise.

```zig
pub fn computeAcceptKey(key: []const u8, buf: *[28]u8) []const u8
```
Compute `Sec-WebSocket-Accept = base64(SHA-1(key + magic))`.

```zig
pub fn upgradeResponse(request: *const Request) ?Response
```
Build a 101 Switching Protocols response from a valid upgrade request.
Returns `null` if the request fails validation.

### Example

```zig
fn handleWsUpgrade(_: std.mem.Allocator, _: std.Io, request: *const httpz.Request) httpz.Response {
    return httpz.WebSocket.upgradeResponse(request) orelse
        httpz.Response.init(.bad_request, "text/plain", "WebSocket upgrade required");
}

fn wsHandler(conn: *httpz.WebSocket.Conn, _: *const httpz.Request) void {
    while (true) {
        const msg = conn.recv() catch break orelse break;
        switch (msg.opcode) {
            .text => conn.send(msg.payload) catch break,
            .binary => conn.sendBinary(msg.payload) catch break,
            else => {},
        }
    }
}
```

---

## Headers (`src/Headers.zig`)

RFC 2616 §4.2 case-insensitive HTTP header storage. Fixed-capacity inline
array (no dynamic allocation).

### Types

```zig
pub const Entry = struct {
    name: []const u8,
    value: []const u8,
};
```

```zig
pub const Error = error{
    TooManyHeaders,
    InvalidHeaderName,
    InvalidHeaderValue,
};
```

### Fields

```zig
entries: [max_headers]Entry = undefined,
len: usize = 0,
```

### Constants

```zig
pub const max_headers = 64;
pub const reserved_headers = 8;
pub const max_name_len = 256;
pub const max_value_len = 8192;
```

### Functions

```zig
pub fn append(self: *Headers, name: []const u8, value: []const u8) Error!void
```
Append a header. Rejects invalid tokens, empty names, CR/LF in values, and
values over `max_value_len`. User-facing headers are capped at
`max_headers - reserved_headers`.

```zig
pub fn appendServer(self: *Headers, name: []const u8, value: []const u8) void
```
Append a server-generated header. Uses reserved slots. Panics in debug if the
reserved space is exhausted (indicates a server-logic bug).

```zig
pub fn get(self: *const Headers, name: []const u8) ?[]const u8
```
Case-insensitive lookup. Returns the value of the first matching header.

```zig
pub fn getAll(self: *const Headers, name: []const u8, buf: [][]const u8) usize
```
Return all values for a header name, up to `buf.len`. Returns total count
(which may exceed `buf.len`).

```zig
pub fn remove(self: *Headers, name: []const u8) void
```
Remove all headers with the given name (case-insensitive).

```zig
pub fn isValidToken(s: []const u8) bool
```
RFC 2616 §2.2 — token = 1\*\<CHAR except CTLs and separators>.

```zig
pub fn eqlIgnoreCase(a: []const u8, b: []const u8) bool
```
Case-insensitive ASCII comparison.

### Example

```zig
var h: Headers = .{};
try h.append("Content-Type", "text/html");
try h.append("Set-Cookie", "a=1");
try h.append("Set-Cookie", "b=2");

const ct = h.get("content-type");  // "text/html"
const ct2 = h.get("CONTENT-TYPE"); // "text/html"

var buf: [4][]const u8 = undefined;
const count = h.getAll("Set-Cookie", &buf); // count = 2, buf[0] = "a=1", buf[1] = "b=2"

h.remove("Set-Cookie");
```

---

## Cookie (`src/Cookie.zig`)

RFC 6265 cookie parsing from `Cookie` request headers and `Set-Cookie`
response header generation.

### Types

```zig
pub const Entry = struct {
    name: []const u8,
    value: []const u8,
};
```

```zig
pub const Iterator = struct {
    raw: []const u8,
    pos: usize = 0,

    pub fn next(self: *Iterator) ?Entry;
};
```
Zero-copy lazy iterator over `Cookie: n1=v1; n2=v2` header pairs. Skips
whitespace and malformed pairs.

```zig
pub const SameSite = enum {
    strict,
    lax,
    none,
};
```

```zig
pub const SetOptions = struct {
    name: []const u8,
    value: []const u8 = "",
    max_age: ?i64 = null,
    domain: ?[]const u8 = null,
    path: ?[]const u8 = null,
    secure: bool = false,
    http_only: bool = false,
    same_site: ?SameSite = null,
    expires: ?[]const u8 = null,         // pre-formatted RFC 1123 HTTP-date
};
```

```zig
pub const RemoveOptions = struct {
    name: []const u8,
    domain: ?[]const u8 = null,
    path: ?[]const u8 = null,
};
```

```zig
pub const Error = error{
    CookieNameInvalid,
    CookieValueInvalid,
} || std.mem.Allocator.Error || Headers.Error;
```

### Functions

```zig
pub fn iterator(request: *const Request) Iterator
```
Return an iterator over all cookies in the request's `Cookie` header.

```zig
pub fn get(request: *const Request, name: []const u8) ?[]const u8
```
Get the first cookie value matching `name`.

```zig
pub fn set(
    response: *Response,
    allocator: std.mem.Allocator,
    options: SetOptions,
) Error!void
```
Append a `Set-Cookie` header. The allocator formats the header value; use a
per-request arena so the memory lives until serialization.

```zig
pub fn remove(
    response: *Response,
    allocator: std.mem.Allocator,
    options: RemoveOptions,
) Error!void
```
Delete a cookie by setting `Max-Age=0`. `domain` and `path` must match the
original cookie.

```zig
pub fn isValidName(name: []const u8) bool
```
RFC 6265 §4.1.1 — cookie names must be valid HTTP tokens.

```zig
pub fn isValidValue(value: []const u8) bool
```
RFC 6265 §4.1.1 — cookie-octet character validation.

### Example

```zig
// Reading
fn handler(allocator: std.mem.Allocator, _: std.Io, request: *const httpz.Request) httpz.Response {
    const session = httpz.Cookie.get(request, "session_id") orelse
        return httpz.Response.init(.unauthorized, "text/plain", "No session");

    var iter = httpz.Cookie.iterator(request);
    while (iter.next()) |cookie| {
        std.debug.print("{s} = {s}\n", .{ cookie.name, cookie.value });
    }
    _ = session;
    _ = allocator;
    return httpz.Response.init(.ok, "text/plain", "OK");
}

// Setting
fn login(allocator: std.mem.Allocator, _: std.Io, _: *const httpz.Request) httpz.Response {
    var resp = httpz.Response.init(.ok, "text/plain", "Logged in");
    httpz.Cookie.set(&resp, allocator, .{
        .name = "session_id",
        .value = "abc123",
        .path = "/",
        .http_only = true,
        .secure = true,
        .same_site = .lax,
    }) catch {};
    return resp;
}

// Deleting
fn logout(allocator: std.mem.Allocator, _: std.Io, _: *const httpz.Request) httpz.Response {
    var resp = httpz.Response.init(.ok, "text/plain", "Logged out");
    httpz.Cookie.remove(&resp, allocator, .{ .name = "session_id", .path = "/" }) catch {};
    return resp;
}
```
