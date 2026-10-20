//! Blocking fd helpers for startup paths that have no Io — the seam's
//! two backends are asynchronous completions driven by the loop, and
//! nothing here participates in that: `Labeled.init`'s certificate
//! snapshot reads a handful of files once, before the loop exists, and
//! stamps `days_left` against the wall clock (§B1). The lint's rule is
//! the doctrine's: raw syscall surfaces live under `src/io/` only
//! (DESIGN.md §4) — these two calls are the entire non-seam, non-main
//! fd surface, gathered here so the rule stays a one-place check.
//!
//! Serving paths must not grow to use these: a blocking read on the
//! loop is a stall the §4 model forbids, and there is no Io to hand
//! them at runtime anyway.

const std = @import("std");

const assert = std.debug.assert;

/// Read up to `scratch.len` bytes of `path`, or null on any failure —
/// unopenable, unreadable, or exactly filling the scratch (a full
/// scratch cannot be told apart from a truncated read, and a caller
/// whose bound the file genuinely exceeds is refused rather than
/// partially read). The bytes live in the caller's scratch; the caller
/// parses from them before reusing it.
pub fn readFilePrefix(path: []const u8, scratch: []u8) ?[]const u8 {
    assert(path.len >= 1);
    assert(scratch.len >= 1);
    const fd = std.posix.openat(std.posix.AT.FDCWD, path, .{ .ACCMODE = .RDONLY }, 0) catch
        return null;
    defer {
        // `posix.close` does not exist in this std — the raw syscall
        // through `system`, `XevIo.closeFd`'s exact spelling, is the
        // close this layer gets. A close can race a signal and come
        // back EINTR after closing anyway, which is a success here.
        const rc = std.posix.system.close(fd);
        const errno = std.posix.errno(rc);
        assert(errno == .SUCCESS or errno == .INTR);
    }
    var len: usize = 0;
    while (len < scratch.len) {
        const read = std.posix.read(fd, scratch[len..]) catch return null;
        if (read == 0) break;
        len += read;
    }
    if (len == scratch.len) return null;
    return scratch[0..len];
}

/// The wall clock in whole seconds — `XevIo.nowWallNs`'s read, standing
/// alone for callers that have no Io to ask. Startup-only: the serving
/// loop reads its clocks through the seam.
pub fn wallClockSeconds() u64 {
    var ts: std.posix.timespec = undefined;
    const rc = std.posix.system.clock_gettime(std.posix.CLOCK.REALTIME, &ts);
    assert(std.posix.errno(rc) == .SUCCESS);
    assert(ts.sec >= 0);
    return @intCast(ts.sec);
}
