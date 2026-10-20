const Proxy = @This();
const std = @import("std");
const Headers = @import("../Headers.zig");
const Request = @import("../Request.zig");
const Response = @import("../Response.zig");

/// RFC 2616 Section 9.9: CONNECT method for tunneling.
/// RFC 2616 Section 14.45: Via header for proxy chains.
pub const Authority = struct {
    host: []const u8,
    port: u16,
};

/// RFC 2616 Section 5.1.2: Parse authority (host:port) from a CONNECT
/// request URI. The Request-URI for CONNECT uses authority-form.
pub fn parseAuthority(uri: []const u8) ?Authority {
    if (uri.len == 0) return null;

    const colon = std.mem.lastIndexOfScalar(u8, uri, ':') orelse return null;
    if (colon == 0 or colon == uri.len - 1) return null;

    const host = uri[0..colon];
    const port_str = uri[colon + 1 ..];
    const port = std.fmt.parseInt(u16, port_str, 10) catch return null;

    return .{ .host = host, .port = port };
}

/// RFC 2616 Section 14.45: Add or append a Via header.
///
/// Format: Via: <protocol-version> <pseudonym>
/// If a Via header already exists, the new entry is appended as a
/// comma-separated value to preserve the proxy chain.
///
/// Uses the Response's embedded buffer for the composed Via value
/// so the header slice has a well-defined lifetime.
pub fn addViaHeader(response: *Response, version: Request.Version) void {
    const headers = &response.headers;
    const existing = headers.get("Via");
    const via_entry: []const u8 = if (version == .http_1_1) "1.1 httpz" else "1.0 httpz";

    if (existing) |prev| {
        // Append to existing Via chain
        const needed = prev.len + 2 + via_entry.len;
        const via_buf = response.allocServerBuf(needed) orelse return;
        var pos: usize = 0;
        @memcpy(via_buf[pos..][0..prev.len], prev);
        pos += prev.len;
        @memcpy(via_buf[pos..][0..2], ", ");
        pos += 2;
        @memcpy(via_buf[pos..][0..via_entry.len], via_entry);
        pos += via_entry.len;
        headers.remove("Via");
        headers.appendServer("Via", via_buf[0..pos]);
    } else {
        headers.appendServer("Via", via_entry);
    }
}

/// Build the "200 Connection Established" response sent to the client
/// after a successful CONNECT tunnel setup.
pub fn connectionEstablishedResponse(buf: []u8) ?[]const u8 {
    const resp = "HTTP/1.1 200 Connection Established\r\n\r\n";
    if (resp.len > buf.len) return null;
    @memcpy(buf[0..resp.len], resp);
    return buf[0..resp.len];
}

// --- Tests ---

const testing = std.testing;

// RFC 2616 Section 9.9: Parse authority from CONNECT URI
test "Proxy: parseAuthority basic" {
    const auth = parseAuthority("example.com:443").?;
    try testing.expectEqualStrings("example.com", auth.host);
    try testing.expectEqual(@as(u16, 443), auth.port);
}

test "Proxy: parseAuthority port 80" {
    const auth = parseAuthority("www.example.com:80").?;
    try testing.expectEqualStrings("www.example.com", auth.host);
    try testing.expectEqual(@as(u16, 80), auth.port);
}

test "Proxy: parseAuthority high port" {
    const auth = parseAuthority("localhost:8443").?;
    try testing.expectEqualStrings("localhost", auth.host);
    try testing.expectEqual(@as(u16, 8443), auth.port);
}

test "Proxy: parseAuthority invalid - no port" {
    try testing.expect(parseAuthority("example.com") == null);
}

test "Proxy: parseAuthority invalid - empty" {
    try testing.expect(parseAuthority("") == null);
}

test "Proxy: parseAuthority invalid - no host" {
    try testing.expect(parseAuthority(":443") == null);
}

test "Proxy: parseAuthority invalid - non-numeric port" {
    try testing.expect(parseAuthority("example.com:abc") == null);
}

test "Proxy: parseAuthority invalid - trailing colon" {
    try testing.expect(parseAuthority("example.com:") == null);
}

test "Proxy: parseAuthority invalid - port overflow" {
    try testing.expect(parseAuthority("example.com:99999") == null);
}

// RFC 2616 Section 14.45: Via header
test "Proxy: addViaHeader new HTTP/1.1" {
    var resp: Response = .{};
    addViaHeader(&resp, .http_1_1);
    try testing.expectEqualStrings("1.1 httpz", resp.headers.get("Via").?);
}

test "Proxy: addViaHeader new HTTP/1.0" {
    var resp: Response = .{};
    addViaHeader(&resp, .http_1_0);
    try testing.expectEqualStrings("1.0 httpz", resp.headers.get("Via").?);
}

test "Proxy: addViaHeader appends to existing chain" {
    var resp: Response = .{};
    try resp.headers.append("Via", "1.1 upstream-proxy");
    addViaHeader(&resp, .http_1_1);
    try testing.expectEqualStrings("1.1 upstream-proxy, 1.1 httpz", resp.headers.get("Via").?);
}

test "Proxy: addViaHeader appends to multi-hop chain" {
    var resp: Response = .{};
    try resp.headers.append("Via", "1.0 first, 1.1 second");
    addViaHeader(&resp, .http_1_1);
    try testing.expectEqualStrings("1.0 first, 1.1 second, 1.1 httpz", resp.headers.get("Via").?);
}

// Connection Established response
test "Proxy: connectionEstablishedResponse" {
    var buf: [256]u8 = undefined;
    const resp = connectionEstablishedResponse(&buf).?;
    try testing.expectEqualStrings("HTTP/1.1 200 Connection Established\r\n\r\n", resp);
}

test "Proxy: connectionEstablishedResponse buffer too small" {
    var buf: [5]u8 = undefined;
    try testing.expect(connectionEstablishedResponse(&buf) == null);
}
