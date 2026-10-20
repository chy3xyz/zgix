# Module: middleware + tls

CORS and gzip compression middleware, plus OpenSSL-based TLS for HTTPS server
and client.

**Import paths:**
- `httpz.middleware.cors` — `src/middleware/cors.zig`
- `httpz.middleware.compression` — `src/middleware/compression.zig`
- `httpz.tls` — `src/openssl.zig`

---

## Middleware — CORS

### Types

```zig
pub const Config = struct {
    origin: []const u8 = "*",
    methods: []const u8 = "GET, POST, PUT, DELETE, OPTIONS, PATCH",
    headers: []const u8 = "Content-Type, Authorization",
    max_age: []const u8 = "86400",
};
```

### Functions

```zig
/// Create a CORS middleware with the given comptime configuration.
/// Returns a struct with a `.wrap` function.
pub fn init(comptime config: Config) type;
```

The returned type's `wrap` method:

```zig
/// Wrap a handler to add CORS headers to every response and respond to
/// OPTIONS preflight requests with a 204 No Content.
pub fn wrap(comptime inner: Connection.Handler) Connection.Handler;
```

### Headers Added

| Header                          | Source         |
| ------------------------------- | -------------- |
| `Access-Control-Allow-Origin`   | `config.origin`  |
| `Access-Control-Allow-Methods`  | `config.methods` |
| `Access-Control-Allow-Headers`  | `config.headers` |
| `Access-Control-Max-Age`        | `config.max_age` (preflight only) |
| `Vary: Origin`                  | always added   |

### Example

```zig
const cors = httpz.middleware.cors.init(.{
    .origin = "https://myapp.com",
    .methods = "GET, POST",
    .headers = "Content-Type, X-Custom",
    .max_age = "3600",
});

// Per-route
comptime httpz.Router.handler(&.{
    .{ .method = .GET, .path = "/api", .handler = cors.wrap(handleApi) },
});

// Global
var server = httpz.Server.init(config, cors.wrap(handler));
```

---

## Middleware — Compression

### Functions

```zig
/// Wrap a handler to automatically gzip-compress responses when the client
/// sends `Accept-Encoding: gzip` and the content type is compressible.
/// Handles both static body and streaming responses transparently.
pub fn wrap(comptime inner: Connection.Handler) Connection.Handler;
```

### Behavior

The middleware compresses a response body in place when **all** conditions are met:

1. The client sends `Accept-Encoding: gzip`
2. The `Content-Type` is **compressible** (see `src/server/Compression.zig`)
3. The body is non-empty and not already encoded

If compression doesn't shrink the body, the original is kept. Streaming responses
are wrapped on-the-fly via a gzip compressor writer.

Headers added:
- `Content-Encoding: gzip`
- `Vary: Accept-Encoding`
- `Content-Length` removed from streaming responses (size is unknown ahead of time)

### Example

```zig
const compress = httpz.middleware.compression;

// Per-route
comptime httpz.Router.handler(&.{
    .{ .method = .GET, .path = "/data", .handler = compress.wrap(handleData) },
});

// Composed: CORS then compression
comptime httpz.Router.handler(&.{
    .{ .method = .GET, .path = "/api", .handler = cors.wrap(compress.wrap(handleData)) },
});

// Global
var server = httpz.Server.init(config, compress.wrap(handler));
```

---

## TLS — OpenSSL

TLS wrapping using system OpenSSL (libssl + libcrypto). Provides `Io.Reader`
and `Io.Writer` interfaces over encrypted socket fds for seamless integration
with the HTTP layer.

### Constants

```zig
pub const input_buffer_len = 16645;
pub const output_buffer_len = 16469;
```

### Types

```zig
pub const config = struct {
    pub const cert = struct {
        pub const Bundle = enum {
            empty,   // skip certificate verification (client only)
            system,  // system default CA store
        };
    };

    pub const CertKeyPair = struct {
        cert_pem: []const u8,
        key_pem: []const u8,
        allocator: std.mem.Allocator,

        pub fn fromFilePath(
            allocator: std.mem.Allocator,
            io: Io,
            dir: Io.Dir,
            cert_name: []const u8,
            key_name: []const u8,
        ) !CertKeyPair;

        pub fn deinit(self: *CertKeyPair, _: std.mem.Allocator) void;
    };

    pub const Client = struct {
        host: []const u8,
        root_ca: cert.Bundle = .system,
        insecure_skip_verify: bool = false,
        disable_h2: bool = false,
    };

    pub const Server = struct {
        auth: ?*const CertKeyPair = null,
        alpn_protocols: []const []const u8 = &.{},
        sni_context: ?*SniContext = null,
    };
};
```

```zig
pub const Connection = struct {
    ssl: *c.SSL,
    ctx: *c.SSL_CTX,
    alpn_protocol: ?[]const u8 = null,
    owns_ctx: bool = true,
    read_buf: [16384]u8 = undefined,

    /// Read next chunk of cleartext data. Returns null on end of stream.
    pub fn next(conn: *Connection) anyerror!?[]const u8;

    /// Encrypt and write all data to the underlying connection.
    pub fn writeAll(conn: *Connection, data: []const u8) !void;

    /// Read decrypted data into the provided buffer.
    pub fn read(conn: *Connection, buf: []u8) !usize;

    /// Gracefully close the TLS connection.
    pub fn close(conn: *Connection) !void;

    /// Free the SSL object and, if owned, the SSL_CTX.
    pub fn deinit(conn: *Connection) void;

    // Io.Reader adaptor
    pub const Reader = struct {
        conn: *Connection,
        interface: Io.Reader,
        err: ?anyerror = null,

        pub fn init(conn_ptr: *Connection, buffer: []u8) Reader;
    };

    pub fn reader(conn: *Connection, buffer: []u8) Reader;

    // Io.Writer adaptor
    pub const Writer = struct {
        conn: *Connection,
        interface: Io.Writer,
        err: ?anyerror = null,

        pub fn init(conn_ptr: *Connection, buffer: []u8) Writer;
    };

    pub fn writer(conn: *Connection, buffer: []u8) Writer;
};
```

### SNI Context

```zig
/// Per-domain certificate selection via Server Name Indication.
/// Holds a shared SSL_CTX with an SNI callback for multi-domain servers.
pub const SniContext = struct {
    default_ctx: *c.SSL_CTX,
    domain_contexts: std.StringHashMap(*c.SSL_CTX),
    allocator: std.mem.Allocator,
    mutex: Mutex,

    pub fn init(allocator: std.mem.Allocator, default_cert: *const config.CertKeyPair) !SniContext;

    pub fn addDomain(self: *SniContext, domain: []const u8, cert_pem: []const u8, key_pem: []const u8) !void;

    pub fn removeDomain(self: *SniContext, domain: []const u8) void;

    pub fn deinit(self: *SniContext) void;
};
```

### Functions

```zig
/// Perform a TLS client handshake on the given socket fd.
/// Negotiates ALPN (h2 or http/1.1). Returns the TLS-wrapped connection.
pub fn client(fd: posix.fd_t, opts: config.Client) !Connection;

/// Perform a TLS server handshake on the given socket fd.
/// Uses a shared SniContext when available, otherwise creates a per-connection
/// SSL_CTX. Returns the TLS-wrapped connection.
pub fn server(fd: posix.fd_t, opts: config.Server) !Connection;

/// Load a certificate chain and private key into an SSL_CTX.
pub fn loadCertIntoCtx(ctx: *c.SSL_CTX, cert_pem: []const u8, key_pem: []const u8) !void;
```

### Error Sets

```zig
// Handshake failures
error{ TlsHandshakeFailure, TlsCertificateExpired, TlsCertificateRevoked,
        TlsCertificateUnknown, TlsUnsupportedCertificate, TlsCertificateRequired };

// I/O errors on Connection methods
error{ EndOfStream, WouldBlock, ReadFailed, TlsAlert };
```

### Example — Server TLS

```zig
const tls = httpz.tls;

// Load cert + key
var auth = try tls.config.CertKeyPair.fromFilePath(allocator, io, cwd, "cert.pem", "key.pem");
defer auth.deinit(allocator);

var server = httpz.Server.init(.{
    .port = 4433,
    .address = "127.0.0.1",
    .tls_config = .{ .auth = &auth },
}, handler);

try server.run(io);
```

### Example — Client TLS

```zig
var client = httpz.Client.init(allocator, .{
    .host = "example.com",
    .port = 443,
    .tls_config = .{
        .host = "example.com",
        .root_ca = .system,
    },
});
defer client.deinit();

try client.connect(io);
var resp = try client.request(io, .GET, "/", null, null);
defer resp.deinit(allocator);
```

### Example — SNI (Multi-Domain Server)

```zig
const tls = httpz.tls;

var default_auth = try tls.config.CertKeyPair.fromFilePath(allocator, io, cwd, "default.pem", "default-key.pem");
defer default_auth.deinit(allocator);

var sni = try tls.SniContext.init(allocator, &default_auth);
defer sni.deinit();

try sni.addDomain("app.example.com", app_cert_pem, app_key_pem);
try sni.addDomain("api.example.com", api_cert_pem, api_key_pem);

var server = httpz.Server.init(.{
    .port = 443,
    .address = "0.0.0.0",
    .tls_config = .{ .sni_context = &sni },
}, handler);

try server.run(io);
```
