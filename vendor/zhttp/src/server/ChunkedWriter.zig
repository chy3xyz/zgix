// RFC 7230 §4.1 chunked transfer encoding writer.
//
// Wraps an underlying `*std.Io.Writer` and turns every drained slice into
// a `<hex-length>\r\n<bytes>\r\n` chunk. Caller invokes `finish` to emit
// the terminating `0\r\n\r\n` end-of-stream marker.
//
// Intended for the streaming-response path in Server.zig: when the
// response advertises `Transfer-Encoding: chunked` and uses a `stream_fn`,
// the function receives this writer's `interface` field and writes its
// raw NDJSON / SSE / whatever bytes through it; the wrapper handles
// the on-wire framing.

const std = @import("std");

const ChunkedWriter = @This();

/// The underlying network writer. Owned by the caller (typically the
/// per-connection writer in Server.zig); this wrapper never closes it.
underlying: *std.Io.Writer,

/// The Writer surface to hand to a stream_fn. Unbuffered — every write
/// goes straight to `drain` which produces one chunk per call.
interface: std.Io.Writer,

pub fn init(underlying: *std.Io.Writer) ChunkedWriter {
    return .{
        .underlying = underlying,
        .interface = .{
            .vtable = &vtable,
            .buffer = &.{},
        },
    };
}

const vtable: std.Io.Writer.VTable = .{
    .drain = drain,
    .flush = flush,
};

fn drain(
    w: *std.Io.Writer,
    data: []const []const u8,
    splat: usize,
) std.Io.Writer.Error!usize {
    const self: *ChunkedWriter = @fieldParentPtr("interface", w);
    var total: usize = 0;

    for (data, 0..) |slice, i| {
        // The last element is repeated `splat` times (Writer interface
        // contract). For all other elements, write once.
        const reps: usize = if (i + 1 == data.len) splat else 1;
        for (0..reps) |_| {
            if (slice.len == 0) continue;

            // Chunk header: `<hex-length>\r\n`
            var hex: [16]u8 = undefined;
            const hex_str = std.fmt.bufPrint(&hex, "{x}", .{slice.len}) catch unreachable;
            try self.underlying.writeAll(hex_str);
            try self.underlying.writeAll("\r\n");

            // Chunk data
            try self.underlying.writeAll(slice);

            // Chunk trailer: `\r\n`
            try self.underlying.writeAll("\r\n");

            total += slice.len;
        }
    }

    return total;
}

fn flush(w: *std.Io.Writer) std.Io.Writer.Error!void {
    const self: *ChunkedWriter = @fieldParentPtr("interface", w);
    try self.underlying.flush();
}

/// Emit the terminating `0\r\n\r\n` marker that closes the chunked
/// stream, then flush the underlying writer.
pub fn finish(self: *ChunkedWriter) !void {
    try self.underlying.writeAll("0\r\n\r\n");
    try self.underlying.flush();
}
