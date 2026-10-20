/// HTTP/2 error codes as defined in RFC 9113 Section 7.
pub const ErrorCode = enum(u32) {
    /// Graceful shutdown.
    no_error = 0x0,
    /// Protocol violation detected.
    protocol_error = 0x1,
    /// Implementation fault.
    internal_error = 0x2,
    /// Flow-control limits exceeded.
    flow_control_error = 0x3,
    /// Settings not acknowledged in time.
    settings_timeout = 0x4,
    /// Frame received for closed stream.
    stream_closed = 0x5,
    /// Frame size was incorrect.
    frame_size_error = 0x6,
    /// Stream not processed, safe to retry.
    refused_stream = 0x7,
    /// Stream cancelled by endpoint.
    cancel = 0x8,
    /// Compression state not updated.
    compression_error = 0x9,
    /// TCP connection error for CONNECT.
    connect_error = 0xa,
    /// Endpoint detected excessive load.
    enhance_your_calm = 0xb,
    /// Negotiated TLS parameters not acceptable.
    inadequate_security = 0xc,
    /// Use HTTP/1.1 for this request.
    http_1_1_required = 0xd,

    _,
};

/// A connection-level error that renders the entire connection unusable.
/// Must be followed by a GOAWAY frame and TCP close.
pub const ConnectionError = struct {
    code: ErrorCode,
    debug_data: []const u8 = "",
};

/// A stream-level error that only affects the individual stream.
/// Communicated via RST_STREAM.
pub const StreamError = struct {
    stream_id: u31,
    code: ErrorCode,
};
