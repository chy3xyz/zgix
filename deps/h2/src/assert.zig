//! `assert`, and the build option that decides whether it ships.
//!
//! ## Why this is not `std.debug.assert`
//!
//! `std.debug.assert` is `if (!ok) unreachable`, and in `ReleaseFast` and
//! `ReleaseSmall` `unreachable` is undefined behaviour rather than a trap. The
//! optimizer is therefore entitled to assume the condition holds and delete the
//! check — so a consumer building for speed gets a codec whose safety argument
//! rests on roughly 350 checks that are not in the binary.
//!
//! ## The rule this makes load-bearing
//!
//! An assertion may not be the only guard on a `catch unreachable`. Once
//! assertions are optional, an `unreachable` behind one is reachable — and in
//! ReleaseFast that is undefined behaviour rather than a panic. This package
//! violated the rule exactly once, in `Encoder.encodeSizeUpdate`, where the
//! guard on a peer-supplied capacity was an assertion and the fallout was a
//! spin that could not be interrupted. The guard there is a returned error now,
//! and the assertion beside it is documentation.
//!
//! ## Not a hypothetical
//!
//! Several assertions are the only check on an arithmetic relation:
//! `Encoder`'s `!aliasesArena`, `Decoder`'s `!overlaps` before a `@memcpy`,
//! `huffman`'s accumulator width, and the
//! postconditions the reviews of the field validators kept finding bugs behind.
//! `DynamicTable.evictTo` is written with its bound in the loop *condition*
//! precisely because of this, and says so at the site.
//!
//! ## The option, and why it is an option
//!
//! docs/TIGER_STYLE.md records the one place the two consumers genuinely
//! disagree. zoxy wants assertions on in production: it is the security
//! boundary and it points this decoder at the open internet. zrk is a
//! latency-measuring tool whose whole pitch is not injecting client-side noise
//! into the measurement.
//!
//! A library cannot decide that for its consumers, so `-Dassertions` decides
//! it, defaulting to on. zoxy inherits the default and states nothing; zrk opts
//! out in a line a reviewer can see. A consumer depending on this package
//! passes it the same way it passes any other option:
//!
//!     const h2 = b.dependency("h2", .{
//!         .target = target,
//!         .optimize = optimize,
//!         .assertions = false,
//!     });
//!
//! ## Comptime is not part of the bargain
//!
//! An assertion evaluated during the build costs a consumer nothing at run
//! time, and several of this package's are proofs its correctness rests on —
//! `syntax.zig` checks its vector kernel against a transcription of the RFC
//! over all 256 octets in a `comptime` block, and `MessageValidator` checks its
//! pseudo-header registry against its own enum. Turning those off with the
//! option would silently delete the proofs, so `assert` detects comptime and
//! ignores the option there. Nothing has to remember to use a different name.

const std = @import("std");
const build_options = @import("build_options");

/// Whether run-time assertions are compiled in. Public so a consumer can branch
/// on it — a test that measures assertion behaviour has to know — and so the
/// benchmark can print which build it measured.
pub const enabled: bool = build_options.assertions;

/// Check an invariant.
///
/// A failure is a bug in this package or a violated precondition in its caller,
/// never a malformed input: every wire-format error has a named error value and
/// a path that returns it. So this is the "downgrade correctness bugs into
/// liveness bugs" trade of docs/TIGER_STYLE.md — a crash a consumer can see and
/// report, in place of a wrong answer it cannot.
pub inline fn assert(ok: bool) void {
    // At comptime the option does not apply; see the note above. `unreachable`
    // here is a compile error rather than undefined behaviour, which is exactly
    // what a failed proof should be.
    if (@inComptime()) {
        if (!ok) unreachable;
        return;
    }
    // Folded away when the option is off. Two limits worth stating rather than
    // implying: the *computation* of `ok` goes with it only in ReleaseFast and
    // ReleaseSmall — measured at 15x on a loop of pure predicates, against 10%
    // in Debug, where the condition is still evaluated. And it goes only
    // because the condition is pure; every one in this package is, but nothing
    // enforces it, so an assertion that called something with a side effect
    // would keep running with the option off.
    if (!enabled) return;
    if (!ok) {
        @branchHint(.cold);
        fail();
    }
}

/// Out of line, so a holding assertion costs a not-taken branch and nothing
/// else — no panic path inlined into a decode loop, and no register pressure
/// from one.
///
/// The `@branchHint` is intent rather than a measured win: moving it between
/// here and the call site changed `huffman encode` by 0.9% on an M-series
/// laptop, which is noise. What is *not* noise is the cost of the checks
/// themselves; see the table in the commit that added this file.
fn fail() noreturn {
    @branchHint(.cold);
    @panic("h2: assertion failed");
}

test "assert admits what is true" {
    assert(true);
    assert(1 + 1 == 2);
}

test "the option is what the build said it was" {
    // Weak on purpose, and the comment says so rather than dressing it up. The
    // claim worth proving — that a *comptime* assertion is checked whichever
    // way `-Dassertions` was set — cannot be made in a `test` block, because
    // the failing case is a compile error rather than a failing test. The first
    // version of this file tried anyway, with `comptime assert(true)`, which
    // passes even if the `@inComptime()` branch is deleted outright: a
    // tautology wearing a proof's name.
    //
    // The real gate is `checks/comptime_assert_is_not_optional.zig`, a fixture
    // `zig build checks` requires to *fail* to compile.
    try std.testing.expectEqual(@import("build_options").assertions, enabled);
}
