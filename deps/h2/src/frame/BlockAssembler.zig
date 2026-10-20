//! RFC 9113 section 4.3: reassembling a field block from the frames it spans.
//!
//! A field section arrives as either one HEADERS or PUSH_PROMISE frame with
//! END_HEADERS set, or one without it followed by CONTINUATION frames, the last
//! of which sets it. The sequence must be contiguous — "no interleaved frames
//! of any other type or from any other stream" — and a CONTINUATION must follow
//! a frame that left the block open. Those are framing rules, decidable from
//! the frames alone, so they live here.
//!
//! This is the first thing in the package that holds state between calls.
//! Everything else is a pure function over borrowed octets, and it stays that
//! way where it can; a field block simply is not a property of one frame.
//!
//! ## What the caller owns
//!
//! The buffer, and the frame bound. The buffer is where fragments are
//! assembled, and its length *is* the octet bound — the same arrangement
//! HPACK's decoder uses, where the caller's output buffer is what a compression
//! bomb runs into. The frame bound is a separate parameter because it cannot be
//! derived from the octet one.
//!
//! The buffer is reused from offset zero by every block, so a completed
//! `Block.fragment` is valid only until the next frame lands one. Decode it
//! before offering the next frame. The frame bound is per block, not per
//! connection: how many blocks a peer may open is a question about streams, and
//! `SETTINGS_MAX_CONCURRENT_STREAMS` is where the caller answers it.
//!
//! That last point is the whole shape of the CONTINUATION flood, and it is
//! worth being explicit about. HPACK's decoder needs no field-count bound: every
//! field costs at least 32 octets against the size bound, so a count bound
//! follows from it. A CONTINUATION frame can carry an *empty* fragment. A peer
//! can therefore send them forever, accumulating zero octets, and an octet
//! bound alone never fires. The two bounds are independent because one of them
//! can be spent without spending the other.
//!
//! ## Two kinds of failure
//!
//! Sequencing violations are the peer breaking RFC 9113, and section 4.3 makes
//! them connection errors of type PROTOCOL_ERROR. Exceeding a bound is the peer
//! staying inside the rules and being expensive anyway, which is what
//! ENHANCE_YOUR_CALM exists for (section 7: "the endpoint detected that its
//! peer is exhibiting a behavior that might be generating excessive load").
//! Reporting both as PROTOCOL_ERROR would tell a peer it is malformed when it
//! is merely unwelcome.

const std = @import("std");

const BlockAssembler = @This();

const assert = @import("../assert.zig").assert;

const Header = @import("Header.zig");
const payload_codec = @import("payload.zig");

pub const Payload = payload_codec.Payload;
pub const ErrorCode = Header.ErrorCode;
pub const Severity = Header.Severity;

/// Frames one field block may span, when the caller offers no opinion.
///
/// A block that needs more than this many frames is either a peer with a very
/// small `SETTINGS_MAX_FRAME_SIZE` or a peer spending frames on purpose. Sixteen
/// is generous for the first — at the 16 KiB floor it allows a quarter-megabyte
/// field block — and cheap for the second.
pub const frames_max_default: u32 = 16;

comptime {
    assert(frames_max_default >= 1);
    // The quarter-megabyte the comment above claims, stated so that moving
    // either side breaks the build rather than the sentence.
    assert(frames_max_default * Header.max_frame_size_min == 256 * 1024);
}

pub const Error = error{
    /// A CONTINUATION arrived with no field block open (section 4.3).
    UnexpectedContinuation,
    /// A frame arrived while a field block was open. Section 4.3 admits no
    /// frame of any type from any stream between the fragments of one block,
    /// and section 5.5 says the same of an extension frame in as many words —
    /// which is what reconciles this with section 4.1's rule that an unknown
    /// type be ignored. Ignored, but not here.
    InterleavedFrame,
    /// The fragments did not fit the caller's buffer.
    BlockTooLarge,
    /// The block spanned more frames than the caller allows.
    TooManyFrames,
};

/// The code a peer should be sent.
pub fn errorCode(err: Error) ErrorCode {
    return switch (err) {
        // Section 4.3 names both of these outright.
        error.UnexpectedContinuation, error.InterleavedFrame => .protocol_error,
        // Our bound, not the RFC's. The peer is expensive, not malformed.
        error.BlockTooLarge, error.TooManyFrames => .enhance_your_calm,
    };
}

/// Every failure here ends the connection.
///
/// A field block spans frames, so a decoder that gave up partway through one
/// has lost its place in the HPACK compression context — which is shared by
/// every stream on the connection and cannot be resynchronized. That is true of
/// the bound failures as much as the sequencing ones, so unlike
/// `payload.severity` this needs no header to decide.
pub fn severity(err: Error) Severity {
    return switch (err) {
        error.UnexpectedContinuation,
        error.InterleavedFrame,
        error.BlockTooLarge,
        error.TooManyFrames,
        => .connection,
    };
}

/// What a field block turned out to be, once its last frame arrived.
pub const Block = struct {
    /// `.headers` or `.push_promise` — the frame that opened it.
    frame_type: Header.Type,
    stream_identifier: u31,
    /// From the opening HEADERS, when it carried the PRIORITY flag.
    priority: ?payload_codec.Priority = null,
    /// From the opening PUSH_PROMISE.
    promised_stream_identifier: ?u31 = null,
    /// END_STREAM on the opening frame, which the block outlives.
    end_stream: bool = false,
    /// The assembled fragments, in the caller's buffer.
    ///
    /// Valid only until the next `accept` that lands a fragment: the following
    /// block reuses the same buffer from offset zero. That is a lifetime rule,
    /// not an optimization, and it is the opposite of the one everywhere else
    /// in this package — every other borrowed slice points at the caller's own
    /// wire octets and lives as long as they do. Decode the field block before
    /// offering the next frame.
    fragment: []const u8,
};

/// What one frame did to the assembler.
pub const Accepted = union(enum) {
    /// Not part of a field block. The caller handles it as it would have
    /// anyway; the assembler only confirmed it was allowed to arrive.
    passthrough,
    /// A fragment landed and the block is still open.
    fragment,
    /// The block is complete.
    block: Block,
};

/// True when a payload is the one a header of this type would have produced.
fn payloadMatchesType(frame_type: Header.Type, frame_payload: *const Payload) bool {
    return switch (frame_payload.*) {
        .data => frame_type == .data,
        .headers => frame_type == .headers,
        .priority => frame_type == .priority,
        .rst_stream => frame_type == .rst_stream,
        .settings => frame_type == .settings,
        .push_promise => frame_type == .push_promise,
        .ping => frame_type == .ping,
        .goaway => frame_type == .goaway,
        .window_update => frame_type == .window_update,
        .continuation => frame_type == .continuation,
        .unknown => !frame_type.known(),
    };
}

const State = enum { idle, open };

buffer: []u8,
frames_max: u32,
state: State = .idle,
/// Octets of `buffer` spent by the block in progress.
octets_used: u32 = 0,
/// Frames the block in progress has spanned, the opening one included.
frames_count: u32 = 0,
/// Only meaningful while `state` is `.open`.
block: Block = undefined,

/// `buffer` is both the assembly space and the octet bound: a field block that
/// does not fit is one this caller was never going to accept.
pub fn init(buffer: []u8, frames_max: u32) BlockAssembler {
    assert(buffer.len <= std.math.maxInt(u32));
    assert(frames_max >= 1);
    // The counter is incremented before it is compared, so a bound at the very
    // top of the range would overflow before it could fire.
    assert(frames_max < std.math.maxInt(u32));
    return .{ .buffer = buffer, .frames_max = frames_max };
}

/// True while a field block is waiting for more frames.
///
/// A connection with a block open cannot be idle-timed out as though nothing
/// were in flight, and it cannot process anything else — which is the whole
/// point of section 4.3's contiguity rule.
pub fn isOpen(assembler: *const BlockAssembler) bool {
    return assembler.state == .open;
}

/// Offer one frame to the assembler.
///
/// Every frame on the connection goes through this, not only the ones carrying
/// fragments: a block that is open forbids all of them, and that is exactly the
/// rule being enforced.
pub fn accept(
    assembler: *BlockAssembler,
    header: Header,
    frame_payload: *const Payload,
) Error!Accepted {
    // The header and the payload must have come from the same frame. Nothing
    // else here would notice a caller that mixed them, and the flags read below
    // are the header's while the fragments are the payload's.
    assert(payloadMatchesType(header.frame_type, frame_payload));
    assert(assembler.octets_used <= assembler.buffer.len);
    return switch (assembler.state) {
        .idle => assembler.acceptIdle(header, frame_payload),
        .open => assembler.acceptOpen(header, frame_payload),
    };
}

fn acceptIdle(
    assembler: *BlockAssembler,
    header: Header,
    frame_payload: *const Payload,
) Error!Accepted {
    assert(assembler.state == .idle);
    switch (frame_payload.*) {
        .headers => |headers| {
            assembler.block = .{
                .frame_type = .headers,
                .stream_identifier = header.stream_identifier,
                .priority = headers.priority,
                .end_stream = header.has(.end_stream),
                .fragment = &.{},
            };
            return assembler.open(header, headers.fragment);
        },
        .push_promise => |promise| {
            assembler.block = .{
                .frame_type = .push_promise,
                .stream_identifier = header.stream_identifier,
                .promised_stream_identifier = promise.promised_stream_identifier,
                .fragment = &.{},
            };
            return assembler.open(header, promise.fragment);
        },
        // Section 4.3: a CONTINUATION must be preceded by a frame that left a
        // block open, and nothing has.
        .continuation => return error.UnexpectedContinuation,
        // Enumerated rather than an `else`, so a variant added later that
        // carries a field block has to be decided about here instead of
        // silently passing through.
        .data, .priority, .rst_stream, .settings => return .passthrough,
        .ping, .goaway, .window_update, .unknown => return .passthrough,
    }
}

fn acceptOpen(
    assembler: *BlockAssembler,
    header: Header,
    frame_payload: *const Payload,
) Error!Accepted {
    assert(assembler.state == .open);
    // "No interleaved frames of any other type or from any other stream." Both
    // halves, and the stream check matters as much as the type one: a
    // CONTINUATION for a different stream is how a peer would otherwise splice
    // one block's fragments into another's compression context.
    const continuation = switch (frame_payload.*) {
        .continuation => |continuation| continuation,
        else => {
            assembler.reset();
            return error.InterleavedFrame;
        },
    };
    if (header.stream_identifier != assembler.block.stream_identifier) {
        assembler.reset();
        return error.InterleavedFrame;
    }
    return assembler.append(header, continuation.fragment);
}

/// Start a block, and finish it immediately when END_HEADERS is already set.
fn open(assembler: *BlockAssembler, header: Header, fragment: []const u8) Error!Accepted {
    assert(assembler.state == .idle);
    assembler.state = .open;
    assembler.octets_used = 0;
    assembler.frames_count = 0;
    return assembler.append(header, fragment);
}

/// Copy one frame's fragment into the buffer and decide whether that was the
/// last of them.
fn append(assembler: *BlockAssembler, header: Header, fragment: []const u8) Error!Accepted {
    assert(assembler.state == .open);

    assembler.frames_count += 1;
    // Counted whatever the fragment's length, including zero. An empty
    // CONTINUATION is the flood's whole trick: it spends a frame without
    // spending an octet.
    if (assembler.frames_count > assembler.frames_max) {
        assembler.reset();
        return error.TooManyFrames;
    }

    // Subtract rather than add: `fragment.len` is the peer's and `buffer.len`
    // is ours, and adding them before comparing is how this package's earlier
    // bounds went wrong.
    assert(assembler.octets_used <= assembler.buffer.len);
    const remaining = assembler.buffer.len - assembler.octets_used;
    if (fragment.len > remaining) {
        assembler.reset();
        return error.BlockTooLarge;
    }

    @memcpy(assembler.buffer[assembler.octets_used..][0..fragment.len], fragment);
    assembler.octets_used += @intCast(fragment.len);
    assert(assembler.octets_used <= assembler.buffer.len);

    if (!header.has(.end_headers)) return .fragment;

    var finished = assembler.block;
    finished.fragment = assembler.buffer[0..assembler.octets_used];
    assembler.reset();
    return .{ .block = finished };
}

/// Return to idle. Called on completion and on every failure, because a
/// connection that hit either of these is over and leaving state behind only
/// invites a caller to keep using it.
fn reset(assembler: *BlockAssembler) void {
    assembler.state = .idle;
    assembler.octets_used = 0;
    assembler.frames_count = 0;
    // Scrubbed rather than left readable: `block.fragment` would otherwise
    // still alias the buffer while the assembler is idle, and a stale read
    // should trip rather than succeed.
    assembler.block = undefined;
    assert(!assembler.isOpen());
}

const testing = std.testing;

/// Parse a frame and offer it, the way a caller would.
fn offer(assembler: *BlockAssembler, wire: []const u8) !Accepted {
    const header = try Header.parse(wire);
    try header.validate(Header.max_frame_size_min);
    const body = wire[Header.octets..][0..header.length];
    const parsed = try payload_codec.parse(header, body);
    return assembler.accept(header, &parsed);
}

test "a HEADERS frame with END_HEADERS is a whole block" {
    var buffer: [256]u8 = undefined;
    var assembler = init(&buffer, frames_max_default);

    // END_HEADERS, stream 1, fragment "hello".
    const wire = [_]u8{ 0, 0, 5, 0x01, 0x04, 0, 0, 0, 1 } ++ "hello".*;
    const accepted = try offer(&assembler, &wire);

    try testing.expectEqualStrings("hello", accepted.block.fragment);
    try testing.expectEqual(Header.Type.headers, accepted.block.frame_type);
    try testing.expectEqual(@as(u31, 1), accepted.block.stream_identifier);
    try testing.expect(!assembler.isOpen());
}

test "fragments assemble across CONTINUATION frames, in order" {
    var buffer: [256]u8 = undefined;
    var assembler = init(&buffer, frames_max_default);

    const opening = [_]u8{ 0, 0, 3, 0x01, 0x00, 0, 0, 0, 1 } ++ "one".*;
    try testing.expectEqual(Accepted.fragment, try offer(&assembler, &opening));
    try testing.expect(assembler.isOpen());

    const middle = [_]u8{ 0, 0, 3, 0x09, 0x00, 0, 0, 0, 1 } ++ "two".*;
    try testing.expectEqual(Accepted.fragment, try offer(&assembler, &middle));

    const last = [_]u8{ 0, 0, 5, 0x09, 0x04, 0, 0, 0, 1 } ++ "three".*;
    const accepted = try offer(&assembler, &last);

    try testing.expectEqualStrings("onetwothree", accepted.block.fragment);
    try testing.expect(!assembler.isOpen());
}

test "the opening frame's metadata outlives the frames it spanned" {
    var buffer: [256]u8 = undefined;
    var assembler = init(&buffer, frames_max_default);

    // HEADERS with END_STREAM and PRIORITY, no END_HEADERS.
    const opening = [_]u8{ 0, 0, 7, 0x01, 0x21, 0, 0, 0, 3, 0x80, 0, 0, 20, 9 } ++ "hi".*;
    try testing.expectEqual(Accepted.fragment, try offer(&assembler, &opening));

    const last = [_]u8{ 0, 0, 2, 0x09, 0x04, 0, 0, 0, 3 } ++ "!!".*;
    const accepted = try offer(&assembler, &last);

    try testing.expectEqualStrings("hi!!", accepted.block.fragment);
    try testing.expect(accepted.block.end_stream);
    try testing.expectEqual(@as(u31, 20), accepted.block.priority.?.stream_dependency);
    try testing.expectEqual(@as(u31, 3), accepted.block.stream_identifier);
}

test "a PUSH_PROMISE block keeps its promised stream" {
    var buffer: [256]u8 = undefined;
    var assembler = init(&buffer, frames_max_default);

    const opening = [_]u8{ 0, 0, 6, 0x05, 0x00, 0, 0, 0, 1, 0, 0, 0, 12 } ++ "hi".*;
    try testing.expectEqual(Accepted.fragment, try offer(&assembler, &opening));

    const last = [_]u8{ 0, 0, 0, 0x09, 0x04, 0, 0, 0, 1 };
    const accepted = try offer(&assembler, &last);

    try testing.expectEqual(Header.Type.push_promise, accepted.block.frame_type);
    try testing.expectEqual(@as(u31, 12), accepted.block.promised_stream_identifier.?);
    try testing.expectEqualStrings("hi", accepted.block.fragment);
}

test "a frame that is not part of a block passes through" {
    var buffer: [256]u8 = undefined;
    var assembler = init(&buffer, frames_max_default);

    const ping = [_]u8{ 0, 0, 8, 0x06, 0x00, 0, 0, 0, 0 } ++ "deadbeef".*;
    try testing.expectEqual(Accepted.passthrough, try offer(&assembler, &ping));
    try testing.expect(!assembler.isOpen());
}

test "a CONTINUATION with no block open is refused" {
    var buffer: [256]u8 = undefined;
    var assembler = init(&buffer, frames_max_default);

    const orphan = [_]u8{ 0, 0, 2, 0x09, 0x04, 0, 0, 0, 1 } ++ "hi".*;
    try testing.expectError(error.UnexpectedContinuation, offer(&assembler, &orphan));
}

test "nothing may interleave into an open block, of any type or any stream" {
    const opening = [_]u8{ 0, 0, 2, 0x01, 0x00, 0, 0, 0, 1 } ++ "hi".*;

    // A frame of another type, on the same stream.
    {
        var buffer: [256]u8 = undefined;
        var assembler = init(&buffer, frames_max_default);
        _ = try offer(&assembler, &opening);
        const data = [_]u8{ 0, 0, 2, 0x00, 0x00, 0, 0, 0, 1 } ++ "hi".*;
        try testing.expectError(error.InterleavedFrame, offer(&assembler, &data));
        try testing.expect(!assembler.isOpen());
    }

    // A connection-level frame, which is no more allowed than a stream one.
    {
        var buffer: [256]u8 = undefined;
        var assembler = init(&buffer, frames_max_default);
        _ = try offer(&assembler, &opening);
        const ping = [_]u8{ 0, 0, 8, 0x06, 0x00, 0, 0, 0, 0 } ++ "deadbeef".*;
        try testing.expectError(error.InterleavedFrame, offer(&assembler, &ping));
        try testing.expect(!assembler.isOpen());
    }

    // A CONTINUATION for a different stream, which is how a peer would splice
    // one block's fragments into another's compression context.
    {
        var buffer: [256]u8 = undefined;
        var assembler = init(&buffer, frames_max_default);
        _ = try offer(&assembler, &opening);
        const elsewhere = [_]u8{ 0, 0, 2, 0x09, 0x04, 0, 0, 0, 3 } ++ "hi".*;
        try testing.expectError(error.InterleavedFrame, offer(&assembler, &elsewhere));
        try testing.expect(!assembler.isOpen());
    }

    // And another HEADERS, which is a different frame even on the same stream.
    {
        var buffer: [256]u8 = undefined;
        var assembler = init(&buffer, frames_max_default);
        _ = try offer(&assembler, &opening);
        try testing.expectError(error.InterleavedFrame, offer(&assembler, &opening));
        try testing.expect(!assembler.isOpen());
    }
}

test "an interrupted block cannot be resumed by the frames that follow it" {
    // The failure the four cases above missed by checking only the error. An
    // interleave used to leave the block open with its fragments intact, so the
    // next CONTINUATION spliced into it and produced a field block assembled
    // across the very interruption section 4.3 forbids.
    var buffer: [256]u8 = undefined;
    var assembler = init(&buffer, frames_max_default);

    const opening = [_]u8{ 0, 0, 2, 0x01, 0x00, 0, 0, 0, 1 } ++ "hi".*;
    try testing.expectEqual(Accepted.fragment, try offer(&assembler, &opening));

    const ping = [_]u8{ 0, 0, 8, 0x06, 0x00, 0, 0, 0, 0 } ++ "deadbeef".*;
    try testing.expectError(error.InterleavedFrame, offer(&assembler, &ping));
    try testing.expect(!assembler.isOpen());
    try testing.expectEqual(@as(u32, 0), assembler.octets_used);

    // The continuation has nothing to belong to, which is the answer that keeps
    // "hi" from becoming the head of somebody else's field block.
    const resumed = [_]u8{ 0, 0, 2, 0x09, 0x04, 0, 0, 0, 1 } ++ "!!".*;
    try testing.expectError(error.UnexpectedContinuation, offer(&assembler, &resumed));
}

test "a block larger than the buffer is refused rather than truncated" {
    var buffer: [8]u8 = undefined;
    var assembler = init(&buffer, frames_max_default);

    const opening = [_]u8{ 0, 0, 6, 0x01, 0x00, 0, 0, 0, 1 } ++ "abcdef".*;
    try testing.expectEqual(Accepted.fragment, try offer(&assembler, &opening));

    // Two more octets fit exactly; three do not.
    var full = init(&buffer, frames_max_default);
    _ = try offer(&full, &opening);
    const exact = [_]u8{ 0, 0, 2, 0x09, 0x04, 0, 0, 0, 1 } ++ "gh".*;
    const accepted = try offer(&full, &exact);
    try testing.expectEqualStrings("abcdefgh", accepted.block.fragment);

    const overflowing = [_]u8{ 0, 0, 3, 0x09, 0x04, 0, 0, 0, 1 } ++ "ghi".*;
    try testing.expectError(error.BlockTooLarge, offer(&assembler, &overflowing));
    // And it did not leave the block half-open for a caller to keep feeding.
    try testing.expect(!assembler.isOpen());
}

test "empty CONTINUATION frames are bounded, which an octet limit cannot do" {
    // The CONTINUATION flood: fragments of zero octets, forever. The buffer
    // never fills, so only the frame count stops it — which is why the two
    // bounds are independent and neither can be derived from the other.
    var buffer: [4096]u8 = undefined;
    var assembler = init(&buffer, 4);

    const opening = [_]u8{ 0, 0, 0, 0x01, 0x00, 0, 0, 0, 1 };
    try testing.expectEqual(Accepted.fragment, try offer(&assembler, &opening));

    const empty = [_]u8{ 0, 0, 0, 0x09, 0x00, 0, 0, 0, 1 };
    try testing.expectEqual(Accepted.fragment, try offer(&assembler, &empty));
    try testing.expectEqual(Accepted.fragment, try offer(&assembler, &empty));
    try testing.expectEqual(Accepted.fragment, try offer(&assembler, &empty));

    // The fifth frame is one past the bound, and not one octet has been spent.
    try testing.expectError(error.TooManyFrames, offer(&assembler, &empty));
    try testing.expectEqual(@as(u32, 0), assembler.octets_used);
    try testing.expect(!assembler.isOpen());
}

test "a failure leaves nothing open, so the next call cannot resume a dead block" {
    var buffer: [4]u8 = undefined;
    var assembler = init(&buffer, frames_max_default);

    const opening = [_]u8{ 0, 0, 4, 0x01, 0x00, 0, 0, 0, 1 } ++ "abcd".*;
    _ = try offer(&assembler, &opening);
    const overflowing = [_]u8{ 0, 0, 1, 0x09, 0x04, 0, 0, 0, 1 } ++ "e".*;
    try testing.expectError(error.BlockTooLarge, offer(&assembler, &overflowing));

    // A CONTINUATION now has no block to belong to, which is the right answer
    // rather than a silent continuation of one that failed.
    const orphan = [_]u8{ 0, 0, 1, 0x09, 0x04, 0, 0, 0, 1 } ++ "f".*;
    try testing.expectError(error.UnexpectedContinuation, offer(&assembler, &orphan));
}

test "sequencing failures and bound failures are told apart" {
    // A peer that breaks section 4.3 is malformed; a peer that stays inside it
    // and is expensive anyway is not, and telling it PROTOCOL_ERROR would be
    // wrong about what it did.
    try testing.expectEqual(ErrorCode.protocol_error, errorCode(error.UnexpectedContinuation));
    try testing.expectEqual(ErrorCode.protocol_error, errorCode(error.InterleavedFrame));
    try testing.expectEqual(ErrorCode.enhance_your_calm, errorCode(error.BlockTooLarge));
    try testing.expectEqual(ErrorCode.enhance_your_calm, errorCode(error.TooManyFrames));

    // All four end the connection: a block spans frames, so giving up partway
    // through one loses the HPACK context every stream shares.
    try testing.expectEqual(Severity.connection, severity(error.UnexpectedContinuation));
    try testing.expectEqual(Severity.connection, severity(error.BlockTooLarge));
}
