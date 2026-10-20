//! h2 — HTTP/2 frame codec (RFC 9113 sections 4-6), HPACK (RFC 7541), and the
//! message-level rules of RFC 9113 section 8.
//!
//! Bytes in, frames and header fields out. Nothing here reads a socket or
//! holds connection state: the two consumers do not share a runtime, so
//! anything that needs one belongs to them. See README.md for scope and
//! docs/TIGER_STYLE.md for the rules `zig build lint` enforces.

const std = @import("std");

/// `assert` and the `-Dassertions` build option. Named for the option rather
/// than for the function, so the flag reads `h2.assertions.enabled` and the
/// function does not stutter as `h2.assert.assert`.
pub const assertions = @import("assert.zig");

pub const fields = @import("fields.zig");
pub const frame = @import("frame.zig");
pub const hpack = @import("hpack.zig");

test {
    _ = assertions;
    _ = fields;
    _ = frame;
    _ = hpack;
}
