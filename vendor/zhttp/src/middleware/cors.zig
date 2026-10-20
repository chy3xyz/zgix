const std = @import("std");
const Request = @import("../Request.zig");
const Response = @import("../Response.zig");
const Connection = @import("../server/Connection.zig");

pub const Config = struct {
    origin: []const u8 = "*",
    methods: []const u8 = "GET, POST, PUT, DELETE, OPTIONS, PATCH",
    headers: []const u8 = "Content-Type, Authorization",
    max_age: []const u8 = "86400",
};

/// Create a CORS middleware with the given configuration.
/// Returns a struct with a `wrap` function.
pub fn init(comptime config: Config) type {
    return struct {
        pub fn wrap(comptime inner: Connection.Handler) Connection.Handler {
            return struct {
                fn handle(allocator: std.mem.Allocator, io: std.Io, req: *const Request) Response {
                    // Handle OPTIONS preflight
                    if (req.method == .OPTIONS) {
                        return preflightResponse();
                    }

                    var resp = inner(allocator, io, req);
                    addCorsHeaders(&resp);
                    return resp;
                }
            }.handle;
        }

        fn preflightResponse() Response {
            var resp: Response = .{
                .status = .no_content,
            };
            addCorsHeaders(&resp);
            resp.headers.append("Access-Control-Max-Age", config.max_age) catch {};
            return resp;
        }

        fn addCorsHeaders(resp: *Response) void {
            resp.headers.append("Access-Control-Allow-Origin", config.origin) catch {};
            resp.headers.append("Access-Control-Allow-Methods", config.methods) catch {};
            resp.headers.append("Access-Control-Allow-Headers", config.headers) catch {};
            resp.headers.append("Vary", "Origin") catch {};
        }
    };
}

// --- Tests ---

const testing = std.testing;

test "CORS middleware: adds headers to response" {
    const Cors = init(.{});
    const inner = struct {
        fn h(_: std.mem.Allocator, _: std.Io, _: *const Request) Response {
            return Response.init(.ok, "application/json", "{\"ok\":true}");
        }
    }.h;

    const wrapped = Cors.wrap(inner);
    const req = try Request.parseConst(
        "GET / HTTP/1.1\r\n" ++
            "Host: localhost\r\n" ++
            "Origin: https://example.com\r\n" ++
            "\r\n",
    );
    const test_io: std.Io = .{ .userdata = null, .vtable = undefined };
    const resp = wrapped(std.testing.allocator, test_io, &req);
    try testing.expectEqualStrings("*", resp.headers.get("Access-Control-Allow-Origin").?);
    try testing.expect(resp.headers.get("Access-Control-Allow-Methods") != null);
    try testing.expect(resp.headers.get("Access-Control-Allow-Headers") != null);
}

test "CORS middleware: handles OPTIONS preflight" {
    const Cors = init(.{ .origin = "https://example.com" });
    const inner = struct {
        fn h(_: std.mem.Allocator, _: std.Io, _: *const Request) Response {
            return Response.init(.ok, "text/plain", "should not reach here");
        }
    }.h;

    const wrapped = Cors.wrap(inner);
    const req = try Request.parseConst(
        "OPTIONS / HTTP/1.1\r\n" ++
            "Host: localhost\r\n" ++
            "Origin: https://example.com\r\n" ++
            "\r\n",
    );
    const test_io: std.Io = .{ .userdata = null, .vtable = undefined };
    const resp = wrapped(std.testing.allocator, test_io, &req);
    try testing.expectEqual(Response.StatusCode.no_content, resp.status);
    try testing.expectEqualStrings("https://example.com", resp.headers.get("Access-Control-Allow-Origin").?);
    try testing.expect(resp.headers.get("Access-Control-Max-Age") != null);
}

test "CORS middleware: custom config" {
    const Cors = init(.{
        .origin = "https://myapp.com",
        .methods = "GET, POST",
        .headers = "X-Custom-Header",
        .max_age = "3600",
    });

    const inner = struct {
        fn h(_: std.mem.Allocator, _: std.Io, _: *const Request) Response {
            return Response.init(.ok, "text/plain", "ok");
        }
    }.h;

    const wrapped = Cors.wrap(inner);
    const req = try Request.parseConst(
        "GET / HTTP/1.1\r\n" ++
            "Host: localhost\r\n" ++
            "\r\n",
    );
    const test_io: std.Io = .{ .userdata = null, .vtable = undefined };
    const resp = wrapped(std.testing.allocator, test_io, &req);
    try testing.expectEqualStrings("https://myapp.com", resp.headers.get("Access-Control-Allow-Origin").?);
    try testing.expectEqualStrings("GET, POST", resp.headers.get("Access-Control-Allow-Methods").?);
    try testing.expectEqualStrings("X-Custom-Header", resp.headers.get("Access-Control-Allow-Headers").?);
}
