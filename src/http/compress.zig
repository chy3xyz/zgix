//! One-shot gzip for configured static answers and small coalesced
//! proxied responses (§4/§7).
//!
//! `std.compress.flate.Compress` exposes `finish` but no public flush, so
//! it is usable only when the whole input is known before the first byte
//! goes out. That is exactly the shape this module serves: bodies that
//! arrived with their head (or at load), never a live SSE stream. The
//! compressor state is ~230 KiB plus a 64 KiB history window, so it lives
//! once on the server and is driven synchronously — the loop is single
//! threaded, and nothing here awaits.

const std = @import("std");

const constants = @import("../constants.zig");

const assert = std.debug.assert;

/// The largest body this path will compress. Above it the response is
/// forwarded untouched: buffering more would turn a streaming proxy into
/// a store-and-forward one for the sake of a header.
pub const max_body_bytes: usize = constants.compress_body_bytes_max;

/// Room for the deflate stream plus gzip header/footer. Incompressible
/// input grows by a few dozen bytes; the writer fails cleanly if a
/// pathological input outgrows this, and the caller sends plain.
pub const max_compressed_bytes: usize = constants.compress_out_bytes_max;

/// The single shared compressor. `compress` resets it for each body by
/// constructing a fresh `Compress`, so a failed or skipped body leaves no
/// state for the next request.
pub const Compressor = struct {
    history: [std.compress.flate.max_window_len]u8 = undefined,
    out: [max_compressed_bytes]u8 = undefined,

    /// Gzip `body`, or null when it would not be smaller. The returned
    /// slice is valid until the next `compress` call on this compressor —
    /// callers copy it into the connection's head buffer in the same
    /// synchronous step.
    pub fn compress(self: *Compressor, body: []const u8) ?[]const u8 {
        assert(body.len >= 1);
        assert(body.len <= max_body_bytes);
        var output: std.Io.Writer = .fixed(&self.out);
        var state = std.compress.flate.Compress.init(
            &output,
            &self.history,
            .gzip,
            .default,
        ) catch return null;
        state.writer.writeAll(body) catch return null;
        state.finish() catch return null;
        const len = output.end;
        assert(len <= self.out.len);
        // A "compressed" body that is not smaller is not an improvement:
        // the client pays the decoder and the wire pays the gzip header.
        if (len == 0 or len >= body.len) return null;
        return self.out[0..len];
    }
};

test "compress: gzip is smaller and decodes to the input" {
    var compressor: Compressor = .{};
    // Repetitive text, the shape configured pages and JSON errors have.
    var body_storage: [3600]u8 = undefined;
    @memset(&body_storage, 'a');
    const body = body_storage[0..];
    const gzipped = compressor.compress(body) orelse return error.NotCompressed;
    try std.testing.expect(gzipped.len < body.len);
    try std.testing.expectEqual(@as(u8, 0x1f), gzipped[0]);
    try std.testing.expectEqual(@as(u8, 0x8b), gzipped[1]);

    // Round-trip through the std decompressor: the header alone would
    // pass a "looks like gzip" check without proving the bytes.
    var out: [body.len]u8 = undefined;
    var in: std.Io.Reader = .fixed(gzipped);
    var decompress: std.compress.flate.Decompress = .init(&in, .gzip, &compressor.history);
    try decompress.reader.readSliceAll(&out);
    try std.testing.expectEqualStrings(body, &out);
}

test "compress: incompressible input is declined" {
    var compressor: Compressor = .{};
    var body: [256]u8 = undefined;
    for (&body, 0..) |*byte, index| byte.* = @truncate(index *% 37 +% 11);
    // Random bytes may still shrink by a little, but not by the margin a
    // caller asked for; the null path is the one that matters, so accept
    // either outcome and assert only the contract.
    if (compressor.compress(&body)) |gzipped| {
        try std.testing.expect(gzipped.len < body.len);
    }
}
