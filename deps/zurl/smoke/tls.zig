//! The live TLS gate: a real handshake against a real origin.
//!
//! Not part of `zig build test`, on purpose. A unit test that needs DNS, a
//! route to the internet and somebody else's certificate to still be valid is
//! a test that fails for reasons that are not the code's, and a gate that
//! fails for reasons that are not the code's is a gate people learn to ignore.
//! std ships no TLS server, so there is no way to hold a handshake entirely
//! in-process without taking a dependency — which rule 6 forbids — and this
//! is the honest alternative: run it deliberately, by name.
//!
//!     zig build tls-smoke                              # https://example.com/
//!     zig build tls-smoke -- https://host/path         # anywhere else
//!     zig build tls-smoke -- https://host/ self-signed # the other ca arms
//!     zig build tls-smoke -- https://host/ insecure
//!
//! What it proves is exactly what the unit tests cannot: that the adapter's
//! four buffers are sized right, that the handshake completes against a real
//! certificate chain out of the system trust store, and that an HTTP response
//! parses out the far side of it.

const std = @import("std");
const Io = std.Io;
const zurl = @import("zurl");

const default_url = "https://example.com/";

/// The trust mode named on the command line. Split out so `main` stays under
/// the 70-line limit and so the arms read as a list rather than a chain.
fn selectCa(
    name: []const u8,
    gpa: std.mem.Allocator,
    lock: *Io.RwLock,
    certificates: *std.crypto.Certificate.Bundle,
) zurl.tls.Ca {
    if (std.mem.eql(u8, name, "bundle")) {
        return .{ .bundle = .{ .gpa = gpa, .lock = lock, .certificates = certificates } };
    }
    if (std.mem.eql(u8, name, "self-signed")) return .self_signed;
    if (std.mem.eql(u8, name, "insecure")) return .insecure_no_verification;

    std.debug.print("unknown ca mode '{s}': bundle | self-signed | insecure\n", .{name});
    std.process.exit(2);
}

/// Everything the gate asserts about a response that came back at all. A
/// handshake that silently produced an empty body would otherwise pass.
fn checkResponse(response: zurl.Response, received: usize) void {
    if (response.status != 200) {
        std.debug.print("FAIL: expected status 200, got {d}\n", .{response.status});
        std.process.exit(1);
    }
    if (response.body_len == 0 or received != response.body_len) {
        std.debug.print(
            "FAIL: body_len {d} but sink received {d} bytes\n",
            .{ response.body_len, received },
        );
        std.process.exit(1);
    }
}

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;

    // Io.Threaded explicitly rather than the one `init` hands over: both
    // backends are first class (rule 3), so which one a gate ran on is
    // something the gate should state rather than inherit.
    var threaded: Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var args = init.minimal.args.iterate();
    _ = args.next();
    const url = args.next() orelse default_url;
    // Which trust mode to use. The bundle is the real one; the other two are
    // escape hatches that would otherwise be code nothing ever executes.
    const ca_name = args.next() orelse "bundle";

    // The trust store is the CALLER's, which is the whole shape of the API:
    // loading it allocates, and zurl allocates nothing. Loaded once here,
    // exactly as a control plane would load it once at startup.
    var certificates: std.crypto.Certificate.Bundle = .empty;
    defer certificates.deinit(gpa);
    try certificates.rescan(gpa, io, .now(io, .real));

    var lock: Io.RwLock = .init;

    var body: Io.Writer.Allocating = .init(gpa);
    defer body.deinit();

    const ca = selectCa(ca_name, gpa, &lock, &certificates);

    std.debug.print("zurl tls-smoke: GET {s} (ca: {s})\n", .{ url, ca_name });

    // The four-error API is for deciding; this is for diagnosing, which is
    // exactly what a gate wants when it goes red.
    var diagnostics: zurl.tls.Diagnostics = .{};

    const started = Io.Timestamp.now(io, .awake);
    const response = zurl.fetch(io, .{
        .url = url,
        .sink = .{ .collect = &body },
        .what = "tls-smoke",
        .tls = .{ .ca = ca, .diagnostics = &diagnostics },
    }) catch |err| {
        std.debug.print("FAIL: {s}", .{@errorName(err)});
        if (diagnostics.raw) |raw| std.debug.print(" (std: {s})", .{@errorName(raw)});
        if (diagnostics.alert) |alert| std.debug.print(
            " (peer alert: {s} {s})",
            .{ @tagName(alert.level), @tagName(alert.description) },
        );
        std.debug.print("\n", .{});
        std.process.exit(1);
    } orelse {
        std.debug.print("FAIL: deadline elapsed\n", .{});
        std.process.exit(1);
    };
    const elapsed_ms = @divFloor(started.durationTo(.now(io, .awake)).nanoseconds, std.time.ns_per_ms);

    std.debug.print(
        "  status {d}, {d} body bytes, {d} ms\n",
        .{ response.status, response.body_len, elapsed_ms },
    );

    // Equalities on what actually came back, not just "it did not crash".
    checkResponse(response, body.written().len);

    std.debug.print("  OK\n", .{});
}
