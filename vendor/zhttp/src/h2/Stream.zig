const std = @import("std");
const mem = std.mem;
const frame = @import("frame.zig");
const FrameType = frame.FrameType;
const Flags = frame.Flags;
const ErrorCode = @import("errors.zig").ErrorCode;

/// HTTP/2 stream states (RFC 9113 §5.1).
///
///                        +--------+
///                send PP |        | recv PP
///               ,--------| idle   |--------.
///              /          |        |         \
///             v           +--------+          v
///      +----------+          |           +----------+
///      |          |          | send H /  |          |
///      | reserved |          | recv H    | reserved |
///      | (local)  |          |           | (remote) |
///      +----------+          v           +----------+
///          |            +--------+            |
///          |   send H / |        | recv H /   |
///          |            |  open  |             |
///          |            |        |             |
///          |            +--------+             |
///          |          /          \             |
///          | send ES /            \ recv ES    |
///          v        v              v           v
///     +-----------+   +-----------+
///     | half-     |   | half-     |
///     | closed    |   | closed    |
///     | (remote)  |   | (local)   |
///     +-----------+   +-----------+
///          |                |
///          | send ES /      | recv ES /
///          | send R /       | send R /
///          | recv R         | recv R
///          v                v
///                +--------+
///                | closed |
///                +--------+
///
pub const State = enum {
    idle,
    reserved_local,
    reserved_remote,
    open,
    half_closed_local,
    half_closed_remote,
    closed,
};

/// Reason a stream was closed.
pub const CloseReason = enum {
    not_closed,
    /// Closed normally via END_STREAM from both sides.
    end_stream,
    /// Closed via RST_STREAM.
    reset,
    /// Closed because a GOAWAY was received with a lower last-stream-id.
    goaway,
};

/// A single HTTP/2 stream's state.
pub const Stream = @This();

id: u31,
state: State = .idle,
close_reason: CloseReason = .not_closed,

/// Flow control: bytes we can send (peer's window for this stream).
send_window: i32 = frame.default_initial_window_size,
/// Flow control: bytes we can receive (our window for this stream).
recv_window: i32 = frame.default_initial_window_size,

/// Apply a received frame to this stream's state machine.
/// Returns error on protocol violations.
pub fn recv(self: *Stream, frame_type: FrameType, flags: Flags) !void {
    const es = flags.has(Flags.end_stream);

    switch (self.state) {
        .idle => switch (frame_type) {
            .headers => self.state = if (es) .half_closed_remote else .open,
            .push_promise => self.state = .reserved_remote,
            .priority => {}, // allowed on idle streams
            else => return error.ProtocolError,
        },
        .reserved_remote => switch (frame_type) {
            .headers => self.state = if (es) .closed else .half_closed_local,
            .rst_stream => {
                self.state = .closed;
                self.close_reason = .reset;
            },
            .priority, .window_update => {},
            else => return error.ProtocolError,
        },
        .reserved_local => switch (frame_type) {
            .rst_stream => {
                self.state = .closed;
                self.close_reason = .reset;
            },
            .priority, .window_update => {},
            else => return error.ProtocolError,
        },
        .open => switch (frame_type) {
            .data, .headers, .continuation => {
                if (es) self.state = .half_closed_remote;
            },
            .rst_stream => {
                self.state = .closed;
                self.close_reason = .reset;
            },
            .priority, .window_update, .push_promise => {},
            else => return error.ProtocolError,
        },
        .half_closed_local => switch (frame_type) {
            .data, .headers, .continuation => {
                if (es) {
                    self.state = .closed;
                    self.close_reason = .end_stream;
                }
            },
            .rst_stream => {
                self.state = .closed;
                self.close_reason = .reset;
            },
            .priority, .window_update => {},
            else => return error.ProtocolError,
        },
        .half_closed_remote => switch (frame_type) {
            .rst_stream => {
                self.state = .closed;
                self.close_reason = .reset;
            },
            .priority, .window_update => {},
            // Receiving data/headers on half_closed_remote is a stream error
            else => return error.StreamClosed,
        },
        .closed => switch (frame_type) {
            .priority => {}, // allowed on closed streams
            .window_update, .rst_stream => {
                // May arrive due to race conditions; tolerate briefly after close
            },
            else => return error.StreamClosed,
        },
    }
}

/// Apply a sent frame to this stream's state machine.
pub fn send(self: *Stream, frame_type: FrameType, flags: Flags) !void {
    const es = flags.has(Flags.end_stream);

    switch (self.state) {
        .idle => switch (frame_type) {
            .headers => self.state = if (es) .half_closed_local else .open,
            .push_promise => self.state = .reserved_local,
            .priority => {},
            else => return error.ProtocolError,
        },
        .reserved_local => switch (frame_type) {
            .headers => self.state = if (es) .closed else .half_closed_remote,
            .rst_stream => {
                self.state = .closed;
                self.close_reason = .reset;
            },
            .priority => {},
            else => return error.ProtocolError,
        },
        .reserved_remote => switch (frame_type) {
            .rst_stream => {
                self.state = .closed;
                self.close_reason = .reset;
            },
            .priority, .window_update => {},
            else => return error.ProtocolError,
        },
        .open => switch (frame_type) {
            .data, .headers, .continuation => {
                if (es) self.state = .half_closed_local;
            },
            .rst_stream => {
                self.state = .closed;
                self.close_reason = .reset;
            },
            .priority, .window_update, .push_promise => {},
            else => return error.ProtocolError,
        },
        .half_closed_local => switch (frame_type) {
            .rst_stream => {
                self.state = .closed;
                self.close_reason = .reset;
            },
            .priority, .window_update => {},
            // Cannot send data/headers on half_closed_local
            else => return error.StreamClosed,
        },
        .half_closed_remote => switch (frame_type) {
            .data, .headers, .continuation => {
                if (es) {
                    self.state = .closed;
                    self.close_reason = .end_stream;
                }
            },
            .rst_stream => {
                self.state = .closed;
                self.close_reason = .reset;
            },
            .priority, .window_update => {},
            else => return error.ProtocolError,
        },
        .closed => switch (frame_type) {
            .priority => {},
            else => return error.StreamClosed,
        },
    }
}

/// Returns true if the stream is in a terminal state.
pub fn isClosed(self: *const Stream) bool {
    return self.state == .closed;
}

/// Returns true if the stream counts toward SETTINGS_MAX_CONCURRENT_STREAMS.
/// Per RFC 9113 §5.1.2: open or half-closed streams count.
pub fn isActive(self: *const Stream) bool {
    return switch (self.state) {
        .open, .half_closed_local, .half_closed_remote => true,
        else => false,
    };
}

// --- Tests ---

const testing = std.testing;

test "idle -> open via HEADERS recv" {
    var s: Stream = .{ .id = 1 };
    try s.recv(.headers, Flags.none);
    try testing.expectEqual(State.open, s.state);
}

test "idle -> half_closed_remote via HEADERS+ES recv" {
    var s: Stream = .{ .id = 1 };
    try s.recv(.headers, .{ .value = Flags.end_stream });
    try testing.expectEqual(State.half_closed_remote, s.state);
}

test "open -> half_closed_remote via DATA+ES recv" {
    var s: Stream = .{ .id = 1, .state = .open };
    try s.recv(.data, .{ .value = Flags.end_stream });
    try testing.expectEqual(State.half_closed_remote, s.state);
}

test "open -> half_closed_local via DATA+ES send" {
    var s: Stream = .{ .id = 1, .state = .open };
    try s.send(.data, .{ .value = Flags.end_stream });
    try testing.expectEqual(State.half_closed_local, s.state);
}

test "half_closed_local -> closed via DATA+ES recv" {
    var s: Stream = .{ .id = 1, .state = .half_closed_local };
    try s.recv(.data, .{ .value = Flags.end_stream });
    try testing.expectEqual(State.closed, s.state);
    try testing.expectEqual(CloseReason.end_stream, s.close_reason);
}

test "half_closed_remote -> closed via DATA+ES send" {
    var s: Stream = .{ .id = 1, .state = .half_closed_remote };
    try s.send(.data, .{ .value = Flags.end_stream });
    try testing.expectEqual(State.closed, s.state);
    try testing.expectEqual(CloseReason.end_stream, s.close_reason);
}

test "open -> closed via RST_STREAM recv" {
    var s: Stream = .{ .id = 1, .state = .open };
    try s.recv(.rst_stream, Flags.none);
    try testing.expectEqual(State.closed, s.state);
    try testing.expectEqual(CloseReason.reset, s.close_reason);
}

test "open -> closed via RST_STREAM send" {
    var s: Stream = .{ .id = 1, .state = .open };
    try s.send(.rst_stream, Flags.none);
    try testing.expectEqual(State.closed, s.state);
    try testing.expectEqual(CloseReason.reset, s.close_reason);
}

test "idle: recv DATA is protocol error" {
    var s: Stream = .{ .id = 1 };
    try testing.expectError(error.ProtocolError, s.recv(.data, Flags.none));
}

test "half_closed_remote: recv DATA is stream closed error" {
    var s: Stream = .{ .id = 1, .state = .half_closed_remote };
    try testing.expectError(error.StreamClosed, s.recv(.data, Flags.none));
}

test "half_closed_local: send DATA is stream closed error" {
    var s: Stream = .{ .id = 1, .state = .half_closed_local };
    try testing.expectError(error.StreamClosed, s.send(.data, Flags.none));
}

test "closed: recv PRIORITY is ok" {
    var s: Stream = .{ .id = 1, .state = .closed };
    try s.recv(.priority, Flags.none);
    try testing.expectEqual(State.closed, s.state);
}

test "closed: recv DATA is stream closed error" {
    var s: Stream = .{ .id = 1, .state = .closed };
    try testing.expectError(error.StreamClosed, s.recv(.data, Flags.none));
}

test "full request/response lifecycle" {
    var s: Stream = .{ .id = 1 };

    // Client sends HEADERS (request)
    try s.send(.headers, Flags.none);
    try testing.expectEqual(State.open, s.state);

    // Client sends DATA with END_STREAM (request body done)
    try s.send(.data, .{ .value = Flags.end_stream });
    try testing.expectEqual(State.half_closed_local, s.state);

    // Server sends HEADERS (response)
    try s.recv(.headers, Flags.none);
    try testing.expectEqual(State.half_closed_local, s.state);

    // Server sends DATA with END_STREAM (response body done)
    try s.recv(.data, .{ .value = Flags.end_stream });
    try testing.expectEqual(State.closed, s.state);
    try testing.expectEqual(CloseReason.end_stream, s.close_reason);
    try testing.expect(s.isClosed());
    try testing.expect(!s.isActive());
}

test "reserved_remote -> half_closed_local via HEADERS recv" {
    var s: Stream = .{ .id = 2, .state = .reserved_remote };
    try s.recv(.headers, Flags.none);
    try testing.expectEqual(State.half_closed_local, s.state);
    try testing.expect(s.isActive());
}

test "reserved_local -> half_closed_remote via HEADERS send" {
    var s: Stream = .{ .id = 2, .state = .reserved_local };
    try s.send(.headers, Flags.none);
    try testing.expectEqual(State.half_closed_remote, s.state);
}

test "isActive for various states" {
    try testing.expect(!(Stream{ .id = 1, .state = .idle }).isActive());
    try testing.expect((Stream{ .id = 1, .state = .open }).isActive());
    try testing.expect((Stream{ .id = 1, .state = .half_closed_local }).isActive());
    try testing.expect((Stream{ .id = 1, .state = .half_closed_remote }).isActive());
    try testing.expect(!(Stream{ .id = 1, .state = .reserved_local }).isActive());
    try testing.expect(!(Stream{ .id = 1, .state = .reserved_remote }).isActive());
    try testing.expect(!(Stream{ .id = 1, .state = .closed }).isActive());
}
