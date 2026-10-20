//! HTTP/2 framing (RFC 9113 sections 4 to 6).
//!
//! Framing only: no connection state machine, no stream table, and no policy
//! about which frames a peer ought to send. What belongs here is what the
//! octets themselves decide — a length that contradicts its type, a stream
//! identifier a type forbids, a padding length that does not fit. Whether to
//! refuse a `PUSH_PROMISE` or advertise `SETTINGS_ENABLE_PUSH = 0` is a
//! consumer's decision, and this package has two consumers who would answer
//! differently.

const std = @import("std");

pub const BlockAssembler = @import("frame/BlockAssembler.zig");
pub const Header = @import("frame/Header.zig");
pub const payload = @import("frame/payload.zig");
pub const Payload = payload.Payload;
pub const Type = Header.Type;
pub const Flag = Header.Flag;
pub const ErrorCode = Header.ErrorCode;
pub const Severity = Header.Severity;

test {
    _ = BlockAssembler;
    _ = Header;
    _ = payload;
}
