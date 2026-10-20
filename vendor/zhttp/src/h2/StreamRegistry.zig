const std = @import("std");
const Stream = @import("Stream.zig");
const frame = @import("frame.zig");
const FrameType = frame.FrameType;
const Flags = frame.Flags;

/// Manages all streams on an HTTP/2 connection.
///
/// Tracks active streams, enforces concurrency limits, and manages
/// stream ID allocation (RFC 9113 §5.1.1).
///
/// Client-initiated streams use odd IDs (1, 3, 5, ...).
/// Server-initiated streams use even IDs (2, 4, 6, ...).
pub const StreamRegistry = @This();

const max_streams = 256;

/// Stream storage. Uses a flat array with linear scan.
/// Fine for the expected concurrent stream counts (typically <100).
streams: [max_streams]Stream = undefined,
len: usize = 0,

/// Highest stream ID initiated by the peer.
last_peer_stream_id: u31 = 0,
/// Highest stream ID initiated by us.
last_local_stream_id: u31 = 0,

/// Maximum concurrent streams the peer allows us to have open.
max_concurrent_streams: u32 = 100,

/// Whether we are the client (true) or server (false).
/// Determines which stream IDs are "ours" vs "theirs".
is_server: bool,

/// Get an existing stream by ID, or null if not tracked.
pub fn get(self: *StreamRegistry, id: u31) ?*Stream {
    for (self.streams[0..self.len]) |*s| {
        if (s.id == id) return s;
    }
    return null;
}

/// Get or create a stream for a received frame.
/// Handles implicit stream creation for new peer-initiated streams.
pub fn getOrCreate(self: *StreamRegistry, id: u31) !*Stream {
    // Check if stream already exists
    if (self.get(id)) |s| return s;

    // Validate stream ID direction
    const is_peer_stream = if (self.is_server) id % 2 == 1 else id % 2 == 0;
    if (!is_peer_stream) {
        // We should have created this stream ourselves
        return error.ProtocolError;
    }

    // New peer-initiated stream: ID must be greater than all previous
    if (id <= self.last_peer_stream_id) {
        return error.ProtocolError;
    }

    // Check concurrency limit
    if (self.activeCount() >= self.max_concurrent_streams) {
        return error.RefusedStream;
    }

    self.last_peer_stream_id = id;
    return self.insert(id);
}

/// Open a new locally-initiated stream. Returns the new stream.
pub fn open(self: *StreamRegistry) !*Stream {
    const next_id = if (self.is_server)
        if (self.last_local_stream_id == 0) @as(u31, 2) else self.last_local_stream_id + 2
    else if (self.last_local_stream_id == 0) @as(u31, 1) else self.last_local_stream_id + 2;

    if (self.activeCount() >= self.max_concurrent_streams) {
        return error.RefusedStream;
    }

    self.last_local_stream_id = next_id;
    return self.insert(next_id);
}

/// Count streams that are active (open or half-closed).
pub fn activeCount(self: *const StreamRegistry) u32 {
    var count: u32 = 0;
    for (self.streams[0..self.len]) |*s| {
        if (s.isActive()) count += 1;
    }
    return count;
}

/// Remove closed streams to free slots. Call periodically.
pub fn gc(self: *StreamRegistry) void {
    var write: usize = 0;
    for (0..self.len) |read| {
        if (!self.streams[read].isClosed()) {
            if (write != read) {
                self.streams[write] = self.streams[read];
            }
            write += 1;
        }
    }
    self.len = write;
}

/// Close all streams with ID > last_stream_id (GOAWAY handling).
pub fn goaway(self: *StreamRegistry, last_stream_id: u31) void {
    for (self.streams[0..self.len]) |*s| {
        if (s.id > last_stream_id and !s.isClosed()) {
            s.state = .closed;
            s.close_reason = .goaway;
        }
    }
}

fn insert(self: *StreamRegistry, id: u31) !*Stream {
    // GC closed streams if we're full
    if (self.len >= max_streams) {
        self.gc();
    }
    if (self.len >= max_streams) {
        return error.InternalError;
    }

    self.streams[self.len] = .{ .id = id };
    self.len += 1;
    return &self.streams[self.len - 1];
}

// --- Tests ---

const testing = std.testing;

test "server: client opens streams with odd IDs" {
    var reg: StreamRegistry = .{ .is_server = true };

    const s1 = try reg.getOrCreate(1);
    try testing.expectEqual(@as(u31, 1), s1.id);
    try testing.expectEqual(Stream.State.idle, s1.state);

    const s3 = try reg.getOrCreate(3);
    try testing.expectEqual(@as(u31, 3), s3.id);

    try testing.expectEqual(@as(usize, 2), reg.len);
}

test "server: reject even stream IDs from client" {
    var reg: StreamRegistry = .{ .is_server = true };
    try testing.expectError(error.ProtocolError, reg.getOrCreate(2));
}

test "server: reject non-monotonic stream IDs" {
    var reg: StreamRegistry = .{ .is_server = true };
    _ = try reg.getOrCreate(3);
    try testing.expectError(error.ProtocolError, reg.getOrCreate(1));
}

test "server: open server-initiated stream" {
    var reg: StreamRegistry = .{ .is_server = true };
    const s = try reg.open();
    try testing.expectEqual(@as(u31, 2), s.id);

    const s2 = try reg.open();
    try testing.expectEqual(@as(u31, 4), s2.id);
}

test "client: open client-initiated stream" {
    var reg: StreamRegistry = .{ .is_server = false };
    const s = try reg.open();
    try testing.expectEqual(@as(u31, 1), s.id);

    const s2 = try reg.open();
    try testing.expectEqual(@as(u31, 3), s2.id);
}

test "get existing stream" {
    var reg: StreamRegistry = .{ .is_server = true };
    const s1 = try reg.getOrCreate(1);
    s1.state = .open;

    const s1_again = try reg.getOrCreate(1);
    try testing.expectEqual(Stream.State.open, s1_again.state);
    try testing.expectEqual(@as(usize, 1), reg.len);
}

test "activeCount" {
    var reg: StreamRegistry = .{ .is_server = true };

    const s1 = try reg.getOrCreate(1);
    try testing.expectEqual(@as(u32, 0), reg.activeCount()); // idle doesn't count

    s1.state = .open;
    try testing.expectEqual(@as(u32, 1), reg.activeCount());

    const s3 = try reg.getOrCreate(3);
    s3.state = .half_closed_local;
    try testing.expectEqual(@as(u32, 2), reg.activeCount());

    s1.state = .closed;
    try testing.expectEqual(@as(u32, 1), reg.activeCount());
}

test "concurrency limit" {
    var reg: StreamRegistry = .{ .is_server = true, .max_concurrent_streams = 2 };

    const s1 = try reg.getOrCreate(1);
    s1.state = .open;
    const s3 = try reg.getOrCreate(3);
    s3.state = .open;

    try testing.expectError(error.RefusedStream, reg.getOrCreate(5));

    // Close one stream, now we can open another
    s1.state = .closed;
    const s5 = try reg.getOrCreate(5);
    try testing.expectEqual(@as(u31, 5), s5.id);
}

test "gc removes closed streams" {
    var reg: StreamRegistry = .{ .is_server = true };

    const s1 = try reg.getOrCreate(1);
    s1.state = .open;
    const s3 = try reg.getOrCreate(3);
    s3.state = .closed;
    const s5 = try reg.getOrCreate(5);
    s5.state = .open;

    try testing.expectEqual(@as(usize, 3), reg.len);
    reg.gc();
    try testing.expectEqual(@as(usize, 2), reg.len);

    // Verify remaining streams are correct
    try testing.expectEqual(@as(u31, 1), reg.streams[0].id);
    try testing.expectEqual(@as(u31, 5), reg.streams[1].id);
}

test "goaway closes streams above last_stream_id" {
    var reg: StreamRegistry = .{ .is_server = true };

    const s1 = try reg.getOrCreate(1);
    s1.state = .open;
    const s3 = try reg.getOrCreate(3);
    s3.state = .open;
    const s5 = try reg.getOrCreate(5);
    s5.state = .open;

    reg.goaway(3);

    // Stream 1 and 3 should still be open
    try testing.expectEqual(Stream.State.open, reg.get(1).?.state);
    try testing.expectEqual(Stream.State.open, reg.get(3).?.state);
    // Stream 5 should be closed
    try testing.expectEqual(Stream.State.closed, reg.get(5).?.state);
    try testing.expectEqual(Stream.CloseReason.goaway, reg.get(5).?.close_reason);
}
