//! Experimental HTTP/3 server for interoperability work.
//!
//! Runs the `h3-check` stack over a real XevIo UDP listener and answers
//! every request with a fixed 200. It is a development binary, not the
//! proxy: there is no config file, routing or upstream yet. Its purpose is
//! to let a real client (aioquic, quiche, curl with HTTP/3) drive the
//! transport and expose the gaps a synthetic client cannot.
//!
//! Usage:
//!   h3-serve [bind] [cert.pem] [key.pem] [upstream]
//!   h3-serve --upstream HOST:PORT [bind] [cert.pem] [key.pem]
//! Defaults: 127.0.0.1:4443, src/tls/testdata/cert.pem/key.pem.
//!
//! With an upstream, requests are proxied over plaintext HTTP/1.1 and the
//! origin's buffered response is returned (chunked responses are a 502 in
//! this slice). Without one, every request still gets the fixed 200.

const std = @import("std");

const constants = @import("constants.zig");
const Io = @import("io/io.zig");
const XevIo = @import("io/XevIo.zig");
const h3 = @import("http/h3/root.zig");
const proxy = @import("http/h3/proxy.zig");

const listener_module = h3.listener;
const session_module = h3.session;
const request_stream = h3.request_stream;

const default_bind = "127.0.0.1:4443";
const default_cert = "src/tls/testdata/cert.pem";
const default_key = "src/tls/testdata/key.pem";

const Handler = struct {
    fn onRequest(
        _: *anyopaque,
        session: *session_module.H3Session,
        stream_id: u64,
        request: *const request_stream.Request,
    ) void {
        _ = request;
        session.sendResponse(
            stream_id,
            200,
            &.{.{ .name = "content-type", .value = "text/plain" }},
            "hello from zgix h3\n",
            true,
        ) catch {};
    }
};

fn useUpstream(
    upstream_proxy: *proxy.Proxy(XevIo, 16),
    server: *listener_module.Listener(XevIo),
    io: *XevIo,
    arena: std.mem.Allocator,
    text: []const u8,
) !void {
    const endpoint = try std.Io.net.IpAddress.parseLiteral(text);
    const endpoints = try arena.alloc(std.Io.net.IpAddress, 1);
    endpoints[0] = endpoint;
    try upstream_proxy.initInPlace(io, arena, endpoints, .{});
    server.setRequestHandler(upstream_proxy.handler());
}

pub fn main(init: std.process.Init) !u8 {
    const arena = init.arena.allocator();
    const args = try init.minimal.args.toSlice(arena);
    var positional: [4][]const u8 = undefined;
    var positional_count: usize = 0;
    var upstream_text: ?[]const u8 = null;
    var arg_index: usize = 1;
    while (arg_index < args.len) : (arg_index += 1) {
        if (std.mem.eql(u8, args[arg_index], "--upstream")) {
            if (arg_index + 1 >= args.len) return error.MissingUpstream;
            upstream_text = args[arg_index + 1];
            arg_index += 1;
        } else if (positional_count < positional.len) {
            positional[positional_count] = args[arg_index];
            positional_count += 1;
        }
    }
    if (upstream_text == null and positional_count > 3) upstream_text = positional[3];

    const bind_text = if (positional_count > 0) positional[0] else default_bind;
    const cert_path = if (positional_count > 1) positional[1] else default_cert;
    const key_path = if (positional_count > 2) positional[2] else default_key;

    const cert = try std.Io.Dir.cwd().readFileAlloc(
        init.io,
        cert_path,
        arena,
        .limited(constants.tls_pem_bytes_max),
    );
    const key = try std.Io.Dir.cwd().readFileAlloc(
        init.io,
        key_path,
        arena,
        .limited(constants.tls_pem_bytes_max),
    );
    const bind = try std.Io.net.IpAddress.parseLiteral(bind_text);

    var xev_io: XevIo = undefined;
    try XevIo.init(
        &xev_io,
        arena,
        1024,
        0, // no TCP listeners
        1, // XevIo requires a non-empty group even when unused
        1024,
        XevIo.log_sink_stdout,
        null,
    );
    defer xev_io.deinit();

    var server: listener_module.Listener(XevIo) = undefined;
    try server.initInPlace(&xev_io, arena, bind, .{
        .cert_pem = cert,
        .key_pem = key,
    }, 2);
    var fixed_handler: Handler = .{};
    var upstream_proxy: proxy.Proxy(XevIo, 16) = undefined;
    if (upstream_text) |text| {
        try useUpstream(&upstream_proxy, &server, &xev_io, arena, text);
    } else {
        server.setRequestHandler(.{ .ctx = &fixed_handler, .onRequest = Handler.onRequest });
    }
    server.start();

    if (upstream_text) |text| {
        std.debug.print("h3-serve: listening on {f}, upstream {s}\n", .{
            server.boundAddress(),
            text,
        });
    } else {
        std.debug.print("h3-serve: listening on {f}\n", .{server.boundAddress()});
    }
    try xev_io.run();
    return 0;
}
