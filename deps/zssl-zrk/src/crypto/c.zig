//! The single C import in zssl. Every libcrypto symbol enters through this
//! file, so "what does the C surface consist of" is answered by one import
//! list rather than a grep — and a second C import anywhere else in the
//! tree is a review failure, not a style preference.
//!
//! Zig 0.17 removed `@cImport`; the includes live in `c.h` and the build
//! translates that header into the `c` module this file re-exports.

pub const c = @import("c");

