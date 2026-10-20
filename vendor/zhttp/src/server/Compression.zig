const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const flate = std.compress.flate;

/// Gzip-compress an in-memory body slice.
/// Caller owns the returned slice and must free it with `allocator`.
pub fn compress(body: []const u8, allocator: Allocator) ![]u8 {
    // The output writer collects compressed bytes into a growable buffer.
    // Pre-allocate enough for the Compress init assertion (buffer.len > 8).
    var output: Io.Writer.Allocating = Io.Writer.Allocating.initCapacity(allocator, 4096) catch return error.CompressionFailed;
    errdefer output.deinit();

    // The compressor needs a window buffer of at least max_window_len (64KB).
    const window_buf = allocator.alloc(u8, flate.max_window_len) catch return error.CompressionFailed;
    defer allocator.free(window_buf);

    var comp = flate.Compress.init(&output.writer, window_buf, .gzip, .default) catch return error.CompressionFailed;
    comp.writer.writeAll(body) catch return error.CompressionFailed;
    comp.finish() catch return error.CompressionFailed;

    var list = output.toArrayList();
    return list.toOwnedSlice(allocator);
}

/// Returns true if the content type is compressible (text, JSON, XML, etc).
/// Returns false for binary/already-compressed types.
pub fn isCompressible(content_type: []const u8) bool {
    // Check for types that should NOT be compressed
    const skip_prefixes = [_][]const u8{
        "image/",
        "video/",
        "audio/",
        "font/",
    };
    for (skip_prefixes) |prefix| {
        if (std.mem.startsWith(u8, content_type, prefix)) return false;
    }

    const skip_exact = [_][]const u8{
        "application/zip",
        "application/gzip",
        "application/x-gzip",
        "application/x-compress",
        "application/x-bzip2",
        "application/x-xz",
        "application/zstd",
        "application/octet-stream",
        "application/wasm",
    };
    // Compare only the media type part (before any parameters like ;charset=)
    const semi = std.mem.indexOfScalar(u8, content_type, ';');
    const media_type = if (semi) |s| std.mem.trimEnd(u8, content_type[0..s], &.{' '}) else content_type;

    for (skip_exact) |skip| {
        if (std.mem.eql(u8, media_type, skip)) return false;
    }

    return true;
}

const testing = std.testing;

test "Compression: isCompressible" {
    // Should be compressible
    try testing.expect(isCompressible("text/html"));
    try testing.expect(isCompressible("text/plain"));
    try testing.expect(isCompressible("text/css"));
    try testing.expect(isCompressible("application/json"));
    try testing.expect(isCompressible("application/javascript"));
    try testing.expect(isCompressible("application/xml"));
    try testing.expect(isCompressible("text/html; charset=utf-8"));

    // Should NOT be compressible
    try testing.expect(!isCompressible("image/png"));
    try testing.expect(!isCompressible("image/jpeg"));
    try testing.expect(!isCompressible("video/mp4"));
    try testing.expect(!isCompressible("audio/mpeg"));
    try testing.expect(!isCompressible("font/woff2"));
    try testing.expect(!isCompressible("application/zip"));
    try testing.expect(!isCompressible("application/gzip"));
    try testing.expect(!isCompressible("application/octet-stream"));
}
