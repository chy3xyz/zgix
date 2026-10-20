const std = @import("std");
const frame = @import("frame.zig");
const ErrorCode = @import("errors.zig").ErrorCode;

/// Per-stream or connection-level flow control window (RFC 9113 §5.2).
///
/// Flow control applies only to DATA frames. The window tracks how many
/// bytes the sender is permitted to emit. The receiver advertises capacity
/// via WINDOW_UPDATE frames.
///
/// Window values can go negative when SETTINGS_INITIAL_WINDOW_SIZE is
/// reduced after streams are already open (RFC 9113 §6.9.2).
pub const Window = struct {
    /// Current window size. Can be negative after settings changes.
    size: i32 = frame.default_initial_window_size,

    /// Consume bytes from the window (sender side, before sending DATA).
    /// Returns error if the send would exceed the window.
    pub fn consume(self: *Window, n: u31) !void {
        if (n > self.size) return error.FlowControlError;
        self.size -= n;
    }

    /// How many bytes can be sent right now.
    pub fn available(self: *const Window) u31 {
        return if (self.size <= 0) 0 else @intCast(self.size);
    }

    /// Replenish the window (receiver side, via WINDOW_UPDATE).
    /// Returns error on overflow (RFC 9113 §6.9: must not exceed 2^31-1).
    pub fn replenish(self: *Window, increment: u31) !void {
        const new: i64 = @as(i64, self.size) + @as(i64, increment);
        if (new > std.math.maxInt(i32)) return error.FlowControlError;
        self.size = @intCast(new);
    }

    /// Adjust window when SETTINGS_INITIAL_WINDOW_SIZE changes.
    /// delta = new_initial - old_initial (can be negative).
    pub fn adjustInitial(self: *Window, delta: i32) !void {
        const new: i64 = @as(i64, self.size) + @as(i64, delta);
        if (new > std.math.maxInt(i32)) return error.FlowControlError;
        self.size = @intCast(new);
    }
};

/// Connection-level flow control that manages both the connection window
/// and coordinates with per-stream windows.
pub const FlowController = struct {
    /// Connection-level send window (how much we can send total).
    send_window: Window = .{},
    /// Connection-level receive window (how much peer can send us total).
    recv_window: Window = .{},

    /// Bytes received but not yet acknowledged via WINDOW_UPDATE.
    recv_bytes_unacked: u32 = 0,

    /// Threshold at which we send a WINDOW_UPDATE for the connection.
    /// When unacked bytes exceed this, we replenish.
    recv_window_update_threshold: u32 = frame.default_initial_window_size / 2,

    /// Record that we're about to send `n` bytes of DATA.
    /// Caller must also consume from the stream-level window.
    pub fn consumeSend(self: *FlowController, n: u31) !void {
        try self.send_window.consume(n);
    }

    /// Record that we received `n` bytes of DATA from the peer.
    /// Returns true if a connection-level WINDOW_UPDATE should be sent.
    pub fn recordRecv(self: *FlowController, n: u31) !bool {
        try self.recv_window.consume(n);
        self.recv_bytes_unacked += n;
        return self.recv_bytes_unacked >= self.recv_window_update_threshold;
    }

    /// Get the WINDOW_UPDATE increment to send, and reset the counter.
    /// Returns 0 if no update is needed.
    pub fn pendingWindowUpdate(self: *FlowController) !u31 {
        if (self.recv_bytes_unacked == 0) return 0;
        const increment: u31 = @intCast(self.recv_bytes_unacked);
        try self.recv_window.replenish(increment);
        self.recv_bytes_unacked = 0;
        return increment;
    }

    /// Apply a received WINDOW_UPDATE for the connection (stream 0).
    pub fn recvWindowUpdate(self: *FlowController, increment: u31) !void {
        try self.send_window.replenish(increment);
    }

    /// How many bytes can we send right now, considering the connection window.
    pub fn sendAvailable(self: *const FlowController) u31 {
        return self.send_window.available();
    }

    /// The effective amount we can send on a given stream is the minimum
    /// of the connection window and the stream window.
    pub fn effectiveSendWindow(self: *const FlowController, stream_send_window: i32) u31 {
        const conn = self.send_window.available();
        const strm: u31 = if (stream_send_window <= 0) 0 else @intCast(stream_send_window);
        return @min(conn, strm);
    }
};

// --- Tests ---

const testing = std.testing;

test "Window: basic consume and available" {
    var w: Window = .{};
    try testing.expectEqual(@as(u31, 65535), w.available());

    try w.consume(1000);
    try testing.expectEqual(@as(u31, 64535), w.available());
}

test "Window: consume rejects over-spend" {
    var w: Window = .{ .size = 100 };
    try testing.expectError(error.FlowControlError, w.consume(101));
    // Window unchanged on error
    try testing.expectEqual(@as(u31, 100), w.available());
}

test "Window: replenish" {
    var w: Window = .{ .size = 100 };
    try w.replenish(50);
    try testing.expectEqual(@as(i32, 150), w.size);
}

test "Window: replenish overflow" {
    var w: Window = .{ .size = std.math.maxInt(i32) };
    try testing.expectError(error.FlowControlError, w.replenish(1));
}

test "Window: adjustInitial positive" {
    var w: Window = .{ .size = 65535 };
    try w.adjustInitial(1000);
    try testing.expectEqual(@as(i32, 66535), w.size);
}

test "Window: adjustInitial negative" {
    var w: Window = .{ .size = 65535 };
    try w.adjustInitial(-60000);
    try testing.expectEqual(@as(i32, 5535), w.size);
}

test "Window: adjustInitial can go negative" {
    var w: Window = .{ .size = 100 };
    try w.adjustInitial(-200);
    try testing.expectEqual(@as(i32, -100), w.size);
    try testing.expectEqual(@as(u31, 0), w.available());
}

test "FlowController: send flow" {
    var fc: FlowController = .{};
    try testing.expectEqual(@as(u31, 65535), fc.sendAvailable());

    try fc.consumeSend(1000);
    try testing.expectEqual(@as(u31, 64535), fc.sendAvailable());

    try fc.recvWindowUpdate(500);
    try testing.expectEqual(@as(u31, 65035), fc.sendAvailable());
}

test "FlowController: recv triggers window update" {
    var fc: FlowController = .{};
    // Threshold is 65535/2 = 32767
    const should_update = try fc.recordRecv(32767);
    try testing.expect(should_update);

    const inc = try fc.pendingWindowUpdate();
    try testing.expectEqual(@as(u31, 32767), inc);
    // After sending update, unacked resets
    try testing.expectEqual(@as(u32, 0), fc.recv_bytes_unacked);
}

test "FlowController: recv below threshold" {
    var fc: FlowController = .{};
    const should_update = try fc.recordRecv(100);
    try testing.expect(!should_update);
}

test "FlowController: effectiveSendWindow is min of connection and stream" {
    var fc: FlowController = .{};
    fc.send_window.size = 1000;

    // Stream window smaller
    try testing.expectEqual(@as(u31, 500), fc.effectiveSendWindow(500));
    // Connection window smaller
    try testing.expectEqual(@as(u31, 1000), fc.effectiveSendWindow(2000));
    // Negative stream window
    try testing.expectEqual(@as(u31, 0), fc.effectiveSendWindow(-100));
}
