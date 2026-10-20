/// RFC 6265: HTTP State Management Mechanism
///
/// Provides cookie parsing from requests (§4.2) and Set-Cookie header
/// generation for responses (§4.1).
const Cookie = @This();
const std = @import("std");
const Request = @import("Request.zig");
const Response = @import("Response.zig");
const Headers = @import("Headers.zig");

/// A single cookie name/value pair.
pub const Entry = struct {
    name: []const u8,
    value: []const u8,
};

/// RFC 6265 §4.2: Lazy iterator over "Cookie: n1=v1; n2=v2" header pairs.
/// Zero-copy — slices directly into the header value.
pub const Iterator = struct {
    raw: []const u8,
    pos: usize = 0,

    pub fn next(self: *Iterator) ?Entry {
        const raw = self.raw;
        // Skip leading OWS and semicolons
        while (self.pos < raw.len and (raw[self.pos] == ' ' or raw[self.pos] == ';')) {
            self.pos += 1;
        }
        if (self.pos >= raw.len) return null;

        const start = self.pos;

        // Find '=' separator
        const eq = std.mem.indexOfScalarPos(u8, raw, start, '=') orelse {
            // Malformed pair — skip to next semicolon or end
            self.pos = std.mem.indexOfScalarPos(u8, raw, start, ';') orelse raw.len;
            return self.next();
        };

        const name = trimOws(raw[start..eq]);
        self.pos = eq + 1;

        // Value runs until ';' or end
        const val_start = self.pos;
        const semi = std.mem.indexOfScalarPos(u8, raw, val_start, ';') orelse raw.len;
        const value = trimOws(raw[val_start..semi]);
        self.pos = semi;

        if (name.len == 0) return self.next();

        return .{ .name = name, .value = value };
    }
};

/// Get an iterator over all cookie pairs from a request's Cookie header.
pub fn iterator(request: *const Request) Iterator {
    const raw = request.headers.get("Cookie") orelse return .{ .raw = "" };
    return .{ .raw = raw };
}

/// Get a specific cookie value by name (first match).
pub fn get(request: *const Request, name: []const u8) ?[]const u8 {
    var iter = iterator(request);
    while (iter.next()) |entry| {
        if (std.mem.eql(u8, entry.name, name)) return entry.value;
    }
    return null;
}

/// RFC 6265 §4.1.2.7 / draft-ietf-httpbis-rfc6265bis: SameSite attribute.
pub const SameSite = enum {
    strict,
    lax,
    none,

    fn toBytes(self: SameSite) []const u8 {
        return switch (self) {
            .strict => "Strict",
            .lax => "Lax",
            .none => "None",
        };
    }
};

/// Options for setting a cookie via Set-Cookie header (RFC 6265 §4.1).
pub const SetOptions = struct {
    name: []const u8,
    value: []const u8 = "",
    /// RFC 6265 §4.1.2.2: Max-Age in seconds. Takes precedence over expires.
    max_age: ?i64 = null,
    /// RFC 6265 §4.1.2.3: Domain scope.
    domain: ?[]const u8 = null,
    /// RFC 6265 §4.1.2.4: Path scope.
    path: ?[]const u8 = null,
    /// RFC 6265 §4.1.2.5: Secure flag — only send over HTTPS.
    secure: bool = false,
    /// RFC 6265 §4.1.2.6: HttpOnly flag — no JS access.
    http_only: bool = false,
    /// SameSite attribute.
    same_site: ?SameSite = null,
    /// RFC 6265 §4.1.2.1: Expires as pre-formatted HTTP-date (RFC 1123).
    expires: ?[]const u8 = null,
};

/// Options for removing (expiring) a cookie.
pub const RemoveOptions = struct {
    name: []const u8,
    domain: ?[]const u8 = null,
    path: ?[]const u8 = null,
};

pub const Error = error{
    CookieNameInvalid,
    CookieValueInvalid,
} || std.mem.Allocator.Error || Headers.Error;

/// RFC 6265 §4.1: Append a Set-Cookie header to the response.
///
/// The allocator is used to format the header value; its lifetime must
/// span until the response is serialized (i.e. a per-request arena).
pub fn set(response: *Response, allocator: std.mem.Allocator, options: SetOptions) Error!void {
    if (!isValidName(options.name)) return error.CookieNameInvalid;
    if (!isValidValue(options.value)) return error.CookieValueInvalid;

    // Calculate total length
    var len: usize = options.name.len + 1 + options.value.len; // name=value
    if (options.expires) |v| len += "; Expires=".len + v.len;
    if (options.max_age) |age| len += "; Max-Age=".len + i64Len(age);
    if (options.domain) |v| len += "; Domain=".len + v.len;
    if (options.path) |v| len += "; Path=".len + v.len;
    if (options.secure) len += "; Secure".len;
    if (options.http_only) len += "; HttpOnly".len;
    if (options.same_site) |v| len += "; SameSite=".len + v.toBytes().len;

    const buf = try allocator.alloc(u8, len);
    var pos: usize = 0;

    pos = appendBuf(buf, pos, options.name);
    buf[pos] = '=';
    pos += 1;
    pos = appendBuf(buf, pos, options.value);

    if (options.expires) |v| {
        pos = appendBuf(buf, pos, "; Expires=");
        pos = appendBuf(buf, pos, v);
    }
    if (options.max_age) |age| {
        pos = appendBuf(buf, pos, "; Max-Age=");
        pos = appendI64(buf, pos, age);
    }
    if (options.domain) |v| {
        pos = appendBuf(buf, pos, "; Domain=");
        pos = appendBuf(buf, pos, v);
    }
    if (options.path) |v| {
        pos = appendBuf(buf, pos, "; Path=");
        pos = appendBuf(buf, pos, v);
    }
    if (options.secure) {
        pos = appendBuf(buf, pos, "; Secure");
    }
    if (options.http_only) {
        pos = appendBuf(buf, pos, "; HttpOnly");
    }
    if (options.same_site) |v| {
        pos = appendBuf(buf, pos, "; SameSite=");
        pos = appendBuf(buf, pos, v.toBytes());
    }

    try response.headers.append("Set-Cookie", buf[0..pos]);
}

/// Delete a cookie by setting Max-Age=0 (RFC 6265 §3.1).
/// Domain and Path must match the original cookie for deletion to work.
pub fn remove(response: *Response, allocator: std.mem.Allocator, options: RemoveOptions) Error!void {
    return set(response, allocator, .{
        .name = options.name,
        .value = "",
        .max_age = 0,
        .domain = options.domain,
        .path = options.path,
    });
}

/// RFC 6265 §4.1.1: Cookie names must be HTTP tokens (RFC 2616 §2.2).
pub fn isValidName(name: []const u8) bool {
    return Headers.isValidToken(name);
}

/// RFC 6265 §4.1.1: cookie-value restricts characters.
/// Allowed: %x21 / %x23-2B / %x2D-3A / %x3C-5B / %x5D-7E
/// Disallowed: CTLs, space, double-quote, comma, semicolon, backslash, DEL.
pub fn isValidValue(value: []const u8) bool {
    for (value) |c| {
        if (!isCookieOctet(c)) return false;
    }
    return true;
}

fn isCookieOctet(c: u8) bool {
    return switch (c) {
        0x21 => true,
        0x23...0x2B => true,
        0x2D...0x3A => true,
        0x3C...0x5B => true,
        0x5D...0x7E => true,
        else => false,
    };
}

fn trimOws(s: []const u8) []const u8 {
    var start: usize = 0;
    while (start < s.len and s[start] == ' ') start += 1;
    var end = s.len;
    while (end > start and s[end - 1] == ' ') end -= 1;
    return s[start..end];
}

fn appendBuf(buf: []u8, pos: usize, data: []const u8) usize {
    @memcpy(buf[pos..][0..data.len], data);
    return pos + data.len;
}

const max_i64_digits = 20; // "-9223372036854775808"

fn i64Len(value: i64) usize {
    var count: usize = 0;
    const negative = value < 0;
    var v: u64 = if (negative) @intCast(-value) else @intCast(value);
    if (v == 0) return 1;
    if (negative) count += 1;
    while (v > 0) {
        count += 1;
        v /= 10;
    }
    return count;
}

fn appendI64(buf: []u8, pos: usize, value: i64) usize {
    var tmp: [max_i64_digits]u8 = undefined;
    var p: usize = max_i64_digits;
    const negative = value < 0;
    var v: u64 = if (negative) @intCast(-value) else @intCast(value);
    if (v == 0) {
        buf[pos] = '0';
        return pos + 1;
    }
    while (v > 0) {
        p -= 1;
        tmp[p] = @intCast(v % 10 + '0');
        v /= 10;
    }
    if (negative) {
        p -= 1;
        tmp[p] = '-';
    }
    const slice = tmp[p..max_i64_digits];
    @memcpy(buf[pos..][0..slice.len], slice);
    return pos + slice.len;
}

// --- Tests ---

const testing = std.testing;

// RFC 6265 §4.2: Parse simple Cookie header
test "Cookie: parse single cookie" {
    const req = try Request.parseConst(
        "GET / HTTP/1.1\r\n" ++
            "Host: localhost\r\n" ++
            "Cookie: session=abc123\r\n" ++
            "\r\n",
    );
    try testing.expectEqualStrings("abc123", get(&req, "session").?);
    try testing.expect(get(&req, "missing") == null);
}

// RFC 6265 §4.2: Multiple cookies in one header
test "Cookie: parse multiple cookies" {
    const req = try Request.parseConst(
        "GET / HTTP/1.1\r\n" ++
            "Host: localhost\r\n" ++
            "Cookie: a=1; b=2; c=3\r\n" ++
            "\r\n",
    );
    try testing.expectEqualStrings("1", get(&req, "a").?);
    try testing.expectEqualStrings("2", get(&req, "b").?);
    try testing.expectEqualStrings("3", get(&req, "c").?);
}

// No Cookie header present
test "Cookie: no cookie header" {
    const req = try Request.parseConst(
        "GET / HTTP/1.1\r\n" ++
            "Host: localhost\r\n" ++
            "\r\n",
    );
    try testing.expect(get(&req, "anything") == null);
    var iter = iterator(&req);
    try testing.expect(iter.next() == null);
}

// Iterator yields all pairs
test "Cookie: iterator" {
    const req = try Request.parseConst(
        "GET / HTTP/1.1\r\n" ++
            "Host: localhost\r\n" ++
            "Cookie: x=10; y=20\r\n" ++
            "\r\n",
    );
    var iter = iterator(&req);
    const first = iter.next().?;
    try testing.expectEqualStrings("x", first.name);
    try testing.expectEqualStrings("10", first.value);
    const second = iter.next().?;
    try testing.expectEqualStrings("y", second.name);
    try testing.expectEqualStrings("20", second.value);
    try testing.expect(iter.next() == null);
}

// Whitespace tolerance
test "Cookie: whitespace handling" {
    const req = try Request.parseConst(
        "GET / HTTP/1.1\r\n" ++
            "Host: localhost\r\n" ++
            "Cookie:  a = 1 ;  b=2 \r\n" ++
            "\r\n",
    );
    try testing.expectEqualStrings("1", get(&req, "a").?);
    try testing.expectEqualStrings("2", get(&req, "b").?);
}

// RFC 6265 §4.1: Set-Cookie with all attributes
test "Cookie: set with all attributes" {
    var resp: Response = .{};
    try set(&resp, testing.allocator, .{
        .name = "session",
        .value = "abc123",
        .max_age = 3600,
        .domain = "example.com",
        .path = "/",
        .secure = true,
        .http_only = true,
        .same_site = .lax,
    });
    const header = resp.headers.get("Set-Cookie").?;
    try testing.expect(std.mem.startsWith(u8, header, "session=abc123"));
    try testing.expect(std.mem.indexOf(u8, header, "; Max-Age=3600") != null);
    try testing.expect(std.mem.indexOf(u8, header, "; Domain=example.com") != null);
    try testing.expect(std.mem.indexOf(u8, header, "; Path=/") != null);
    try testing.expect(std.mem.indexOf(u8, header, "; Secure") != null);
    try testing.expect(std.mem.indexOf(u8, header, "; HttpOnly") != null);
    try testing.expect(std.mem.indexOf(u8, header, "; SameSite=Lax") != null);
    // Free the allocated header value
    testing.allocator.free(header);
}

// Minimal Set-Cookie — name=value only
test "Cookie: set minimal" {
    var resp: Response = .{};
    try set(&resp, testing.allocator, .{
        .name = "theme",
        .value = "dark",
    });
    const header = resp.headers.get("Set-Cookie").?;
    try testing.expectEqualStrings("theme=dark", header);
    testing.allocator.free(header);
}

// Multiple Set-Cookie headers
test "Cookie: set multiple cookies" {
    var resp: Response = .{};
    try set(&resp, testing.allocator, .{ .name = "a", .value = "1" });
    try set(&resp, testing.allocator, .{ .name = "b", .value = "2" });

    var buf: [4][]const u8 = undefined;
    const count = resp.headers.getAll("Set-Cookie", &buf);
    try testing.expectEqual(@as(usize, 2), count);
    try testing.expectEqualStrings("a=1", buf[0]);
    try testing.expectEqualStrings("b=2", buf[1]);
    testing.allocator.free(buf[0]);
    testing.allocator.free(buf[1]);
}

// Delete a cookie via remove()
test "Cookie: remove" {
    var resp: Response = .{};
    try remove(&resp, testing.allocator, .{
        .name = "session",
        .path = "/",
    });
    const header = resp.headers.get("Set-Cookie").?;
    try testing.expect(std.mem.startsWith(u8, header, "session="));
    try testing.expect(std.mem.indexOf(u8, header, "; Max-Age=0") != null);
    try testing.expect(std.mem.indexOf(u8, header, "; Path=/") != null);
    testing.allocator.free(header);
}

// Invalid cookie name rejected
test "Cookie: invalid name rejected" {
    var resp: Response = .{};
    try testing.expectError(error.CookieNameInvalid, set(&resp, testing.allocator, .{
        .name = "bad name",
        .value = "x",
    }));
    try testing.expectError(error.CookieNameInvalid, set(&resp, testing.allocator, .{
        .name = "",
        .value = "x",
    }));
}

// Invalid cookie value rejected
test "Cookie: invalid value rejected" {
    var resp: Response = .{};
    try testing.expectError(error.CookieValueInvalid, set(&resp, testing.allocator, .{
        .name = "ok",
        .value = "has space",
    }));
    try testing.expectError(error.CookieValueInvalid, set(&resp, testing.allocator, .{
        .name = "ok",
        .value = "semi;colon",
    }));
    try testing.expectError(error.CookieValueInvalid, set(&resp, testing.allocator, .{
        .name = "ok",
        .value = "back\\slash",
    }));
}

// RFC 6265 §4.1.1: Validate cookie-octet characters
test "Cookie: isValidValue" {
    try testing.expect(isValidValue("abc123"));
    try testing.expect(isValidValue(""));
    try testing.expect(!isValidValue(" "));
    try testing.expect(!isValidValue("\""));
    try testing.expect(!isValidValue(","));
    try testing.expect(!isValidValue(";"));
    try testing.expect(!isValidValue("\\"));
    try testing.expect(!isValidValue("\x00"));
    try testing.expect(!isValidValue("\x7f"));
    try testing.expect(isValidValue("abc123"));
    try testing.expect(isValidValue("a/b"));
}

// Negative Max-Age
test "Cookie: negative max-age" {
    var resp: Response = .{};
    try set(&resp, testing.allocator, .{
        .name = "old",
        .value = "x",
        .max_age = -1,
    });
    const header = resp.headers.get("Set-Cookie").?;
    try testing.expect(std.mem.indexOf(u8, header, "; Max-Age=-1") != null);
    testing.allocator.free(header);
}

// Set-Cookie with Expires
test "Cookie: set with expires" {
    var resp: Response = .{};
    try set(&resp, testing.allocator, .{
        .name = "token",
        .value = "xyz",
        .expires = "Thu, 01 Jan 2026 00:00:00 GMT",
    });
    const header = resp.headers.get("Set-Cookie").?;
    try testing.expect(std.mem.indexOf(u8, header, "; Expires=Thu, 01 Jan 2026 00:00:00 GMT") != null);
    testing.allocator.free(header);
}

// SameSite variants
test "Cookie: same_site variants" {
    {
        var resp: Response = .{};
        try set(&resp, testing.allocator, .{ .name = "s", .value = "v", .same_site = .strict });
        const h1 = resp.headers.get("Set-Cookie").?;
        try testing.expect(std.mem.indexOf(u8, h1, "; SameSite=Strict") != null);
        testing.allocator.free(h1);
    }
    {
        var resp: Response = .{};
        try set(&resp, testing.allocator, .{ .name = "s", .value = "v", .same_site = .lax });
        const h2 = resp.headers.get("Set-Cookie").?;
        try testing.expect(std.mem.indexOf(u8, h2, "; SameSite=Lax") != null);
        testing.allocator.free(h2);
    }
    {
        var resp: Response = .{};
        try set(&resp, testing.allocator, .{ .name = "s", .value = "v", .same_site = .none });
        const h3 = resp.headers.get("Set-Cookie").?;
        try testing.expect(std.mem.indexOf(u8, h3, "; SameSite=None") != null);
        testing.allocator.free(h3);
    }
}

// Empty cookie value is valid (session cookie deletion pattern)
test "Cookie: empty value" {
    var resp: Response = .{};
    try set(&resp, testing.allocator, .{
        .name = "cleared",
    });
    const header = resp.headers.get("Set-Cookie").?;
    try testing.expectEqualStrings("cleared=", header);
    testing.allocator.free(header);
}

// appendI64 edge cases
test "Cookie: appendI64 zero" {
    var buf: [20]u8 = undefined;
    const end = appendI64(&buf, 0, 0);
    try testing.expectEqualStrings("0", buf[0..end]);
}

test "Cookie: appendI64 negative" {
    var buf: [20]u8 = undefined;
    const end = appendI64(&buf, 0, -42);
    try testing.expectEqualStrings("-42", buf[0..end]);
}
