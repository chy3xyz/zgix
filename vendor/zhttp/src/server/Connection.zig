const Connection = @This();
const std = @import("std");
const Request = @import("../Request.zig");
const Response = @import("../Response.zig");
const Headers = @import("../Headers.zig");
const Date = @import("Date.zig");

/// RFC 2616 Section 8.1: Persistent Connections
///
/// HTTP/1.1 connections are persistent by default. A connection is closed
/// when either side sends "Connection: close" or after a timeout.
///
/// HTTP/1.0 connections are non-persistent by default unless
/// "Connection: keep-alive" is explicitly specified.
pub const Handler = *const fn (std.mem.Allocator, std.Io, *const Request) Response;

/// RFC 2616 Section 8.1.2: Overall Operation
/// Determine if the connection should be kept alive.
///
/// RFC 2616 Section 8.1.2.1: For HTTP/1.1, persistent connections are the
/// default behavior. The client signals it wants to close with
/// "Connection: close".
///
/// For HTTP/1.0, connections are non-persistent by default. The client
/// must send "Connection: keep-alive" to request persistence.
pub fn shouldKeepAlive(request: *const Request) bool {
    if (request.headers.get("Connection")) |conn| {
        if (Headers.eqlIgnoreCase(conn, "close")) return false;
        if (Headers.eqlIgnoreCase(conn, "keep-alive")) return true;
    }
    return request.version == .http_1_1;
}

/// Process a single request and produce a response.
///
/// This handles the core HTTP/1.1 server-side logic per RFC 2616:
/// - RFC 2616 Section 9.4: HEAD responses must not include a body
/// - RFC 2616 Section 9.8: TRACE echoes the request
/// - RFC 2616 Section 14.13: Content-Length header
/// - RFC 2616 Section 14.18: Date header (MUST be sent by origin servers)
/// - RFC 2616 Section 14.38: Server header
/// - RFC 2616 Section 8.1: Connection header for keep-alive management
/// RFC 2616 Section 9.2 / 10.4.6: The Allow header lists the set of methods
/// supported by the resource. Used in OPTIONS and 405 responses.
pub const default_allow = "GET, HEAD, POST, PUT, DELETE, OPTIONS, TRACE, PATCH";
pub const default_allow_no_trace = "GET, HEAD, POST, PUT, DELETE, OPTIONS, PATCH";

pub const ProcessOptions = struct {
    enable_trace: bool = false,
};

pub fn processRequest(allocator: std.mem.Allocator, io: std.Io, timestamp: i64, request: *const Request, handler: Handler) Response {
    return processRequestWithOptions(allocator, io, timestamp, request, handler, .{});
}

pub fn processRequestWithOptions(allocator: std.mem.Allocator, io: std.Io, timestamp: i64, request: *const Request, handler: Handler, options: ProcessOptions) Response {
    // RFC 2616 Section 9.8: TRACE method echoes the request.
    // Disabled by default to prevent Cross-Site Tracing (XST) attacks.
    if (request.method == .TRACE) {
        if (!options.enable_trace) {
            var response: Response = .{ .status = .method_not_allowed, .body = "Method Not Allowed" };
            response.headers.appendServer("Allow", default_allow_no_trace);
            addStandardHeaders(&response, timestamp, request);
            return response;
        }
        var response = handleTrace(request);
        addStandardHeaders(&response, timestamp, request);
        return response;
    }

    var response = handler(allocator, io, request);

    // RFC 2616 Section 10.4.6: 405 responses MUST include an Allow header.
    if (response.status == .method_not_allowed and response.headers.get("Allow") == null) {
        response.headers.appendServer("Allow", default_allow);
    }

    // RFC 2616 Section 10.4.2: 401 responses MUST include a WWW-Authenticate header.
    if (response.status == .unauthorized and response.headers.get("WWW-Authenticate") == null) {
        response.headers.appendServer("WWW-Authenticate", "Basic realm=\"httpz\"");
    }

    // RFC 2616 Section 10.2.2: 201 responses SHOULD include a Location header.
    // RFC 2616 Section 10.3.x: Redirect responses MUST include a Location header.
    if (isRedirect(response.status) and response.headers.get("Location") == null) {
        response.headers.appendServer("Location", "/");
    }

    addStandardHeaders(&response, timestamp, request);

    // RFC 2616 Section 9.2: OPTIONS responses should include Allow header.
    if (request.method == .OPTIONS and response.headers.get("Allow") == null) {
        response.headers.appendServer("Allow", default_allow);
    }

    // RFC 2616 Section 13.5.1 / 14.10: Remove hop-by-hop headers from the
    // response. Also parse the Connection header for additional hop-by-hop
    // header names specified by the client.
    // RFC 6455: Skip for 101 Switching Protocols — Upgrade and Connection
    // headers must be preserved for WebSocket handshake.
    if (response.status != .switching_protocols) {
        removeHopByHopHeaders(&response.headers, request);
    }

    // RFC 2616 Section 8.1.2.1: Connection header.
    if (!shouldKeepAlive(request)) {
        response.headers.appendServer("Connection", "close");
    }

    // Streaming responses: force Connection: close (no keep-alive) for simplicity
    if (response.stream_fn != null) {
        if (response.headers.get("Connection") == null) {
            response.headers.appendServer("Connection", "close");
        }
    }

    // RFC 2616 Section 9.4: HEAD must return same headers as GET but no body.
    if (request.method == .HEAD) {
        response.strip_body = true;
        // HEAD responses must not send a body, so disable streaming
        response.stream_fn = null;
        response.stream_context = null;
    }

    // RFC 2616 Section 3.1: Respond with HTTP/1.0 to HTTP/1.0 clients.
    if (request.version == .http_1_0) {
        response.version = .http_1_0;
        // RFC 2616 Section 3.6: MUST NOT send Transfer-Encoding to HTTP/1.0 clients.
        if (response.chunked) {
            response.chunked = false;
            response.auto_content_length = true;
        }
        // HTTP/1.0 doesn't support chunked — streaming uses raw connection close
        if (response.stream_fn != null and response.chunked) {
            response.chunked = false;
        }
    }

    // Streaming safety net: if streaming with no Content-Length and not chunked,
    // force chunked encoding to prevent HTTP clients from hanging
    if (response.stream_fn != null and
        response.headers.get("Content-Length") == null and
        !response.chunked and
        request.version != .http_1_0)
    {
        response.chunked = true;
    }

    // RFC 2616 Section 4.3: Responses to body-forbidden status codes
    // MUST NOT include a message body.
    if (isBodyForbidden(response.status)) {
        response.auto_content_length = false;
        response.strip_body = true;
        response.body = "";
        response.stream_fn = null;
        response.stream_context = null;
    }

    return response;
}

/// Add Date and Server headers common to all responses including TRACE.
fn addStandardHeaders(response: *Response, timestamp: i64, request: *const Request) void {
    _ = request;
    // RFC 2616 Section 14.18: Origin servers MUST include a Date header.
    if (response.headers.get("Date") == null) {
        // Store the date string in the response's embedded buffer so the
        // header value slice has a well-defined lifetime (not threadlocal).
        if (response.allocServerBuf(29)) |date_buf| {
            _ = Date.formatRfc1123(timestamp, date_buf[0..29]);
            response.headers.appendServer("Date", date_buf);
        }
    }

    // RFC 2616 Section 14.38: Server header.
    if (response.headers.get("Server") == null) {
        response.headers.appendServer("Server", "httpz/0.1");
    }
}

/// RFC 2616 Section 9.8: The TRACE method requests that the server
/// echo the received request message back to the client. The response
/// body contains the raw request message as received by the server.
fn handleTrace(request: *const Request) Response {
    var response: Response = .{
        .status = .ok,
        .body = request.raw,
    };
    response.headers.appendServer("Content-Type", "message/http");

    return response;
}

/// RFC 2616 Section 13.5.1: Remove hop-by-hop headers that must not be
/// forwarded. These are meaningful only for a single transport-level
/// connection and should not be stored by caches or forwarded by proxies.
///
/// RFC 2616 Section 14.10: The Connection header may list additional
/// hop-by-hop headers that must also be removed.
fn removeHopByHopHeaders(headers: *Headers, request: *const Request) void {
    const hop_by_hop = [_][]const u8{
        "Keep-Alive",
        "Proxy-Authenticate",
        "Proxy-Authorization",
        "TE",
        "Trailers",
        "Transfer-Encoding",
        "Upgrade",
    };
    for (hop_by_hop) |name| {
        headers.remove(name);
    }

    // RFC 2616 Section 14.10: Parse Connection header for additional
    // hop-by-hop header names. "Connection: close, X-Custom" means
    // X-Custom is also hop-by-hop and must not be forwarded.
    if (request.headers.get("Connection")) |conn| {
        var it = std.mem.splitScalar(u8, conn, ',');
        while (it.next()) |token_raw| {
            const token = Request.trimOws(token_raw);
            if (token.len == 0) continue;
            // Skip the standard tokens we handle separately
            if (Headers.eqlIgnoreCase(token, "close")) continue;
            if (Headers.eqlIgnoreCase(token, "keep-alive")) continue;
            headers.remove(token);
        }
    }
}

/// RFC 2616 Section 4.3: Certain responses MUST NOT include a message-body.
/// 1xx, 204, 304 responses.
pub fn isBodyForbidden(status: Response.StatusCode) bool {
    const code = status.toInt();
    return (code >= 100 and code < 200) or code == 204 or code == 304;
}

/// Check if status code is a redirect that requires a Location header.
fn isRedirect(status: Response.StatusCode) bool {
    return switch (status) {
        .moved_permanently, .found, .see_other, .use_proxy, .temporary_redirect => true,
        else => false,
    };
}

fn formatUsize(value: usize, buf: *[20]u8) []const u8 {
    var v = value;
    var i: usize = 20;
    if (v == 0) {
        buf[19] = '0';
        return buf[19..20];
    }
    while (v > 0) {
        i -= 1;
        buf[i] = @intCast(v % 10 + '0');
        v /= 10;
    }
    return buf[i..20];
}

// --- Tests ---

const testing = std.testing;

const test_io: std.Io = .{ .userdata = null, .vtable = undefined };

fn testHandler(_: std.mem.Allocator, _: std.Io, _: *const Request) Response {
    return Response.init(.ok, "text/plain", "Hello, World!");
}

fn notFoundHandler(_: std.mem.Allocator, _: std.Io, _: *const Request) Response {
    return Response.init(.not_found, "text/plain", "Not Found");
}

// RFC 2616 Section 8.1.2.1: HTTP/1.1 defaults to persistent connections.
// A connection is persistent unless "Connection: close" is sent.
test "Connection: HTTP/1.1 defaults to keep-alive" {
    const req = try Request.parseConst(
        "GET / HTTP/1.1\r\n" ++
            "Host: example.com\r\n" ++
            "\r\n",
    );
    try testing.expect(shouldKeepAlive(&req));
}

// /// RFC 2616 Section 8.1.2.1: Connection: close signals non-persistent.
test "Connection: HTTP/1.1 with Connection: close" {
    const req = try Request.parseConst(
        "GET / HTTP/1.1\r\n" ++
            "Host: example.com\r\n" ++
            "Connection: close\r\n" ++
            "\r\n",
    );
    try testing.expect(!shouldKeepAlive(&req));
}

// /// RFC 2616 Section 8.1.2.1: HTTP/1.0 defaults to non-persistent.
test "Connection: HTTP/1.0 defaults to close" {
    const req = try Request.parseConst(
        "GET / HTTP/1.0\r\n" ++
            "\r\n",
    );
    try testing.expect(!shouldKeepAlive(&req));
}

// /// RFC 2616 Section 8.1.2.1: HTTP/1.0 with explicit keep-alive.
test "Connection: HTTP/1.0 with Connection: keep-alive" {
    const req = try Request.parseConst(
        "GET / HTTP/1.0\r\n" ++
            "Connection: keep-alive\r\n" ++
            "\r\n",
    );
    try testing.expect(shouldKeepAlive(&req));
}

// /// RFC 2616 Section 14.18: Origin servers MUST include a Date header.
test "Connection: processRequest adds Date header" {
    const req = try Request.parseConst(
        "GET / HTTP/1.1\r\n" ++
            "Host: example.com\r\n" ++
            "\r\n",
    );
    const resp = processRequest(std.testing.allocator, test_io, 0, &req, testHandler);
    try testing.expect(resp.headers.get("Date") != null);
}

// /// RFC 2616 Section 14.38: Server header identification.
test "Connection: processRequest adds Server header" {
    const req = try Request.parseConst(
        "GET / HTTP/1.1\r\n" ++
            "Host: example.com\r\n" ++
            "\r\n",
    );
    const resp = processRequest(std.testing.allocator, test_io, 0, &req, testHandler);
    try testing.expectEqualStrings("httpz/0.1", resp.headers.get("Server").?);
}

// /// RFC 2616 Section 14.13: Content-Length header is added for known bodies.
test "Connection: processRequest adds Content-Length" {
    const req = try Request.parseConst(
        "GET / HTTP/1.1\r\n" ++
            "Host: example.com\r\n" ++
            "\r\n",
    );
    const resp = processRequest(std.testing.allocator, test_io, 0, &req, testHandler);
    // Content-Length is auto-generated during serialization, not as a header
    try testing.expect(resp.auto_content_length);
    // Verify it appears in serialized output
    var buf: [1024]u8 = undefined;
    const serialized = try resp.serialize(&buf);
    try testing.expect(std.mem.indexOf(u8, serialized, "Content-Length: 13\r\n") != null);
}

// /// RFC 2616 Section 8.1.2.1: Connection: close is added when client requests it.
test "Connection: processRequest adds Connection: close when requested" {
    const req = try Request.parseConst(
        "GET / HTTP/1.1\r\n" ++
            "Host: example.com\r\n" ++
            "Connection: close\r\n" ++
            "\r\n",
    );
    const resp = processRequest(std.testing.allocator, test_io, 0, &req, testHandler);
    try testing.expectEqualStrings("close", resp.headers.get("Connection").?);
}

// /// RFC 2616 Section 9.8: TRACE echoes the received request (when enabled).
test "Connection: TRACE method echoes request" {
    const req = try Request.parseConst(
        "TRACE /path HTTP/1.1\r\n" ++
            "Host: example.com\r\n" ++
            "\r\n",
    );
    const resp = processRequestWithOptions(std.testing.allocator, test_io, 0, &req, testHandler, .{ .enable_trace = true });
    try testing.expectEqual(Response.StatusCode.ok, resp.status);
    try testing.expectEqualStrings("message/http", resp.headers.get("Content-Type").?);
    // Body should contain the echoed request
    try testing.expect(resp.body.len > 0);
    // Should start with the request method
    try testing.expect(std.mem.startsWith(u8, resp.body, "TRACE"));
}

// RFC 2616 Section 14.18: TRACE responses MUST include a Date header.
test "Connection: TRACE response includes Date header" {
    const req = try Request.parseConst(
        "TRACE /path HTTP/1.1\r\n" ++
            "Host: example.com\r\n" ++
            "\r\n",
    );
    const resp = processRequestWithOptions(std.testing.allocator, test_io, 0, &req, testHandler, .{ .enable_trace = true });
    try testing.expect(resp.headers.get("Date") != null);
    try testing.expect(resp.headers.get("Server") != null);
}

// /// RFC 2616 Section 4.3: 1xx, 204, 304 responses MUST NOT include a body.
test "Connection: isBodyForbidden" {
    try testing.expect(isBodyForbidden(.@"continue"));
    try testing.expect(isBodyForbidden(.switching_protocols));
    try testing.expect(isBodyForbidden(.no_content));
    try testing.expect(isBodyForbidden(.not_modified));
    try testing.expect(!isBodyForbidden(.ok));
    try testing.expect(!isBodyForbidden(.not_found));
    try testing.expect(!isBodyForbidden(.internal_server_error));
}

// /// RFC 2616 Section 14.13: No Content-Length for body-forbidden responses.
test "Connection: no Content-Length for 204 No Content" {
    const req = try Request.parseConst(
        "GET / HTTP/1.1\r\n" ++
            "Host: example.com\r\n" ++
            "\r\n",
    );
    const handler = struct {
        fn handle(_: std.mem.Allocator, _: std.Io, _: *const Request) Response {
            return .{ .status = .no_content };
        }
    }.handle;
    const resp = processRequest(std.testing.allocator, test_io, 0, &req, handler);
    try testing.expect(resp.headers.get("Content-Length") == null);
}

// RFC 2616 Section 4.3: Body-forbidden responses MUST NOT include a body.
test "Connection: 204 response body is stripped" {
    const req = try Request.parseConst(
        "GET / HTTP/1.1\r\n" ++
            "Host: example.com\r\n" ++
            "\r\n",
    );
    const handler = struct {
        fn handle(_: std.mem.Allocator, _: std.Io, _: *const Request) Response {
            return .{ .status = .no_content, .body = "should be stripped" };
        }
    }.handle;
    const resp = processRequest(std.testing.allocator, test_io, 0, &req, handler);
    try testing.expect(resp.strip_body);
    try testing.expectEqualStrings("", resp.body);
}

// RFC 2616 Section 4.3: 304 response body is stripped.
test "Connection: 304 response body is stripped" {
    const req = try Request.parseConst(
        "GET / HTTP/1.1\r\n" ++
            "Host: example.com\r\n" ++
            "\r\n",
    );
    const handler = struct {
        fn handle(_: std.mem.Allocator, _: std.Io, _: *const Request) Response {
            return .{ .status = .not_modified, .body = "should be stripped" };
        }
    }.handle;
    const resp = processRequest(std.testing.allocator, test_io, 0, &req, handler);
    try testing.expect(resp.strip_body);
    try testing.expectEqualStrings("", resp.body);
    var buf: [1024]u8 = undefined;
    const serialized = try resp.serialize(&buf);
    try testing.expect(std.mem.indexOf(u8, serialized, "should be stripped") == null);
}

// RFC 2616 Section 9.4: HEAD responses have headers but no body.
test "Connection: HEAD response strips body but keeps Content-Length" {
    const req = try Request.parseConst(
        "HEAD / HTTP/1.1\r\n" ++
            "Host: example.com\r\n" ++
            "\r\n",
    );
    const resp = processRequest(std.testing.allocator, test_io, 0, &req, testHandler);
    try testing.expect(resp.strip_body);
    // Serialized output should have Content-Length but no body
    var buf: [1024]u8 = undefined;
    const serialized = try resp.serialize(&buf);
    try testing.expect(std.mem.indexOf(u8, serialized, "Content-Length: 13\r\n") != null);
    // Body should not appear after the header terminator
    const header_end = std.mem.indexOf(u8, serialized, "\r\n\r\n").?;
    try testing.expectEqual(serialized.len, header_end + 4);
}

// RFC 2616 Section 3.1: Respond with HTTP/1.0 to HTTP/1.0 clients.
test "Connection: HTTP/1.0 version downgrade" {
    const req = try Request.parseConst(
        "GET / HTTP/1.0\r\n" ++
            "\r\n",
    );
    const resp = processRequest(std.testing.allocator, test_io, 0, &req, testHandler);
    try testing.expectEqual(Request.Version.http_1_0, resp.version);
    var buf: [1024]u8 = undefined;
    const serialized = try resp.serialize(&buf);
    try testing.expect(std.mem.startsWith(u8, serialized, "HTTP/1.0"));
}

// RFC 2616 Section 3.6: MUST NOT send chunked to HTTP/1.0 clients.
test "Connection: chunked disabled for HTTP/1.0 clients" {
    const req = try Request.parseConst(
        "GET / HTTP/1.0\r\n" ++
            "\r\n",
    );
    const handler = struct {
        fn handle(_: std.mem.Allocator, _: std.Io, _: *const Request) Response {
            return .{ .status = .ok, .body = "chunked body", .chunked = true };
        }
    }.handle;
    const resp = processRequest(std.testing.allocator, test_io, 0, &req, handler);
    try testing.expect(!resp.chunked);
    try testing.expect(resp.auto_content_length);
    try testing.expectEqual(Request.Version.http_1_0, resp.version);
}

// RFC 2616 Section 9.2: OPTIONS response includes Allow header.
test "Connection: OPTIONS response includes Allow" {
    const req = try Request.parseConst(
        "OPTIONS * HTTP/1.1\r\n" ++
            "Host: example.com\r\n" ++
            "\r\n",
    );
    const resp = processRequest(std.testing.allocator, test_io, 0, &req, testHandler);
    try testing.expect(resp.headers.get("Allow") != null);
    const allow = resp.headers.get("Allow").?;
    try testing.expect(std.mem.indexOf(u8, allow, "GET") != null);
    try testing.expect(std.mem.indexOf(u8, allow, "HEAD") != null);
    try testing.expect(std.mem.indexOf(u8, allow, "OPTIONS") != null);
}

// RFC 2616 Section 10.4.6: 405 responses MUST include Allow header.
test "Connection: 405 response includes Allow" {
    const req = try Request.parseConst(
        "GET / HTTP/1.1\r\n" ++
            "Host: example.com\r\n" ++
            "\r\n",
    );
    const handler = struct {
        fn handle(_: std.mem.Allocator, _: std.Io, _: *const Request) Response {
            return .{ .status = .method_not_allowed, .body = "Method Not Allowed" };
        }
    }.handle;
    const resp = processRequest(std.testing.allocator, test_io, 0, &req, handler);
    try testing.expect(resp.headers.get("Allow") != null);
}

// RFC 2616 Section 13.5.1: Hop-by-hop headers are removed from responses.
test "Connection: hop-by-hop headers removed" {
    const req = try Request.parseConst(
        "GET / HTTP/1.1\r\n" ++
            "Host: example.com\r\n" ++
            "\r\n",
    );
    const handler = struct {
        fn handle(_: std.mem.Allocator, _: std.Io, _: *const Request) Response {
            var resp = Response.init(.ok, "text/plain", "OK");
            resp.headers.append("Keep-Alive", "timeout=5") catch {};
            resp.headers.append("Proxy-Authenticate", "Basic") catch {};
            resp.headers.append("Transfer-Encoding", "chunked") catch {};
            return resp;
        }
    }.handle;
    const resp = processRequest(std.testing.allocator, test_io, 0, &req, handler);
    try testing.expect(resp.headers.get("Keep-Alive") == null);
    try testing.expect(resp.headers.get("Proxy-Authenticate") == null);
    try testing.expect(resp.headers.get("Transfer-Encoding") == null);
    // Regular headers should remain
    try testing.expect(resp.headers.get("Content-Type") != null);
}

// RFC 2616 Section 14.10: Connection header tokens identify additional hop-by-hop headers.
test "Connection: custom hop-by-hop headers from Connection field removed" {
    const req = try Request.parseConst(
        "GET / HTTP/1.1\r\n" ++
            "Host: example.com\r\n" ++
            "Connection: close, X-Custom-Hop\r\n" ++
            "\r\n",
    );
    const handler = struct {
        fn handle(_: std.mem.Allocator, _: std.Io, _: *const Request) Response {
            var resp = Response.init(.ok, "text/plain", "OK");
            resp.headers.append("X-Custom-Hop", "should-be-removed") catch {};
            resp.headers.append("X-Regular", "should-remain") catch {};
            return resp;
        }
    }.handle;
    const resp = processRequest(std.testing.allocator, test_io, 0, &req, handler);
    try testing.expect(resp.headers.get("X-Custom-Hop") == null);
    try testing.expectEqualStrings("should-remain", resp.headers.get("X-Regular").?);
}

// RFC 2616 Section 10.4.2: 401 responses MUST include WWW-Authenticate.
test "Connection: 401 response includes WWW-Authenticate" {
    const req = try Request.parseConst(
        "GET / HTTP/1.1\r\n" ++
            "Host: example.com\r\n" ++
            "\r\n",
    );
    const handler = struct {
        fn handle(_: std.mem.Allocator, _: std.Io, _: *const Request) Response {
            return .{ .status = .unauthorized, .body = "Unauthorized" };
        }
    }.handle;
    const resp = processRequest(std.testing.allocator, test_io, 0, &req, handler);
    try testing.expect(resp.headers.get("WWW-Authenticate") != null);
    try testing.expectEqualStrings("Basic realm=\"httpz\"", resp.headers.get("WWW-Authenticate").?);
}

// RFC 2616 Section 10.4.2: 401 with user-provided WWW-Authenticate is preserved.
test "Connection: 401 preserves user WWW-Authenticate" {
    const req = try Request.parseConst(
        "GET / HTTP/1.1\r\n" ++
            "Host: example.com\r\n" ++
            "\r\n",
    );
    const handler = struct {
        fn handle(_: std.mem.Allocator, _: std.Io, _: *const Request) Response {
            var resp: Response = .{ .status = .unauthorized, .body = "Unauthorized" };
            resp.headers.append("WWW-Authenticate", "Bearer realm=\"api\"") catch {};
            return resp;
        }
    }.handle;
    const resp = processRequest(std.testing.allocator, test_io, 0, &req, handler);
    try testing.expectEqualStrings("Bearer realm=\"api\"", resp.headers.get("WWW-Authenticate").?);
}

// RFC 2616 Section 10.3.x: Redirect responses MUST include Location.
test "Connection: redirect response gets default Location" {
    const req = try Request.parseConst(
        "GET / HTTP/1.1\r\n" ++
            "Host: example.com\r\n" ++
            "\r\n",
    );
    const handler = struct {
        fn handle(_: std.mem.Allocator, _: std.Io, _: *const Request) Response {
            return .{ .status = .moved_permanently };
        }
    }.handle;
    const resp = processRequest(std.testing.allocator, test_io, 0, &req, handler);
    try testing.expect(resp.headers.get("Location") != null);
}

// RFC 2616 Section 10.3.x: User-provided Location is preserved.
test "Connection: redirect preserves user Location" {
    const req = try Request.parseConst(
        "GET / HTTP/1.1\r\n" ++
            "Host: example.com\r\n" ++
            "\r\n",
    );
    const handler = struct {
        fn handle(_: std.mem.Allocator, _: std.Io, _: *const Request) Response {
            return Response.redirect(.found, "/new-page");
        }
    }.handle;
    const resp = processRequest(std.testing.allocator, test_io, 0, &req, handler);
    try testing.expectEqualStrings("/new-page", resp.headers.get("Location").?);
}

// isRedirect utility
test "Connection: isRedirect" {
    try testing.expect(isRedirect(.moved_permanently));
    try testing.expect(isRedirect(.found));
    try testing.expect(isRedirect(.see_other));
    try testing.expect(isRedirect(.use_proxy));
    try testing.expect(isRedirect(.temporary_redirect));
    try testing.expect(!isRedirect(.ok));
    try testing.expect(!isRedirect(.not_found));
    try testing.expect(!isRedirect(.not_modified));
}

// TRACE is disabled by default
test "Connection: TRACE disabled by default returns 405" {
    const req = try Request.parseConst(
        "TRACE /path HTTP/1.1\r\n" ++
            "Host: example.com\r\n" ++
            "\r\n",
    );
    const resp = processRequestWithOptions(std.testing.allocator, test_io, 0, &req, testHandler, .{ .enable_trace = false });
    try testing.expectEqual(Response.StatusCode.method_not_allowed, resp.status);
    try testing.expect(resp.headers.get("Allow") != null);
    // Should not contain TRACE in allowed methods
    const allow = resp.headers.get("Allow").?;
    try testing.expect(std.mem.indexOf(u8, allow, "TRACE") == null);
}

// TRACE works when explicitly enabled
test "Connection: TRACE works when enabled" {
    const req = try Request.parseConst(
        "TRACE /path HTTP/1.1\r\n" ++
            "Host: example.com\r\n" ++
            "\r\n",
    );
    const resp = processRequestWithOptions(std.testing.allocator, test_io, 0, &req, testHandler, .{ .enable_trace = true });
    try testing.expectEqual(Response.StatusCode.ok, resp.status);
    try testing.expectEqualStrings("message/http", resp.headers.get("Content-Type").?);
}

// Streaming: HEAD request nulls out stream_fn
test "Connection: HEAD nulls stream_fn" {
    const req = try Request.parseConst(
        "HEAD / HTTP/1.1\r\n" ++
            "Host: example.com\r\n" ++
            "\r\n",
    );
    const handler = struct {
        fn handle(_: std.mem.Allocator, _: std.Io, _: *const Request) Response {
            var resp: Response = .{ .status = .ok, .chunked = true };
            resp.stream_fn = dummyStreamFn;
            return resp;
        }
        fn dummyStreamFn(_: ?*anyopaque, _: *std.Io.Writer) void {}
    }.handle;
    const resp = processRequest(std.testing.allocator, test_io, 0, &req, handler);
    try testing.expect(resp.stream_fn == null);
    try testing.expect(resp.strip_body);
}

// Streaming: body-forbidden status nulls out stream_fn
test "Connection: 204 nulls stream_fn" {
    const req = try Request.parseConst(
        "GET / HTTP/1.1\r\n" ++
            "Host: example.com\r\n" ++
            "\r\n",
    );
    const handler = struct {
        fn handle(_: std.mem.Allocator, _: std.Io, _: *const Request) Response {
            var resp: Response = .{ .status = .no_content };
            resp.stream_fn = dummyStreamFn;
            return resp;
        }
        fn dummyStreamFn(_: ?*anyopaque, _: *std.Io.Writer) void {}
    }.handle;
    const resp = processRequest(std.testing.allocator, test_io, 0, &req, handler);
    try testing.expect(resp.stream_fn == null);
}

// Streaming: auto-chunked when no Content-Length for HTTP/1.1
test "Connection: streaming auto-chunked" {
    const req = try Request.parseConst(
        "GET / HTTP/1.1\r\n" ++
            "Host: example.com\r\n" ++
            "\r\n",
    );
    const handler = struct {
        fn handle(_: std.mem.Allocator, _: std.Io, _: *const Request) Response {
            var resp: Response = .{ .status = .ok };
            resp.stream_fn = dummyStreamFn;
            return resp;
        }
        fn dummyStreamFn(_: ?*anyopaque, _: *std.Io.Writer) void {}
    }.handle;
    const resp = processRequest(std.testing.allocator, test_io, 0, &req, handler);
    try testing.expect(resp.stream_fn != null);
    try testing.expect(resp.chunked);
}

// Streaming: Connection: close is set
test "Connection: streaming sets Connection close" {
    const req = try Request.parseConst(
        "GET / HTTP/1.1\r\n" ++
            "Host: example.com\r\n" ++
            "\r\n",
    );
    const handler = struct {
        fn handle(_: std.mem.Allocator, _: std.Io, _: *const Request) Response {
            var resp: Response = .{ .status = .ok, .chunked = true };
            resp.stream_fn = dummyStreamFn;
            return resp;
        }
        fn dummyStreamFn(_: ?*anyopaque, _: *std.Io.Writer) void {}
    }.handle;
    const resp = processRequest(std.testing.allocator, test_io, 0, &req, handler);
    try testing.expectEqualStrings("close", resp.headers.get("Connection").?);
}

// /// formatUsize utility
test "Connection: formatUsize" {
    var buf: [20]u8 = undefined;
    try testing.expectEqualStrings("0", formatUsize(0, &buf));
    try testing.expectEqualStrings("13", formatUsize(13, &buf));
    try testing.expectEqualStrings("1000", formatUsize(1000, &buf));
    try testing.expectEqualStrings("1048576", formatUsize(1048576, &buf));
}
