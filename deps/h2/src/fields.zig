//! RFC 9113 section 8.2: what a field name and value may contain, and section
//! 8.3: which pseudo-header fields may appear where.
//!
//! This is not framing and it is not HPACK, which is why it is a third module
//! rather than a corner of one of the other two. HPACK will carry any octets at
//! all — that is its job — and the frame codec sees a field block as an opaque
//! run. The rules that make a *message* well-formed sit between them, and this
//! is where.
//!
//! ## Checks, not enforcement
//!
//! Everything here answers a question and refuses nothing. Whether a malformed
//! field ends a stream, gets logged, or is deliberately sent anyway is a
//! consumer's decision, and this package has two consumers who answer
//! differently: zoxy refuses, and zrk is a load generator that may want to send
//! something malformed to find out what a server does with it. The check itself
//! is RFC text and is identical for both, so this package owns the check and
//! neither consumer owns a copy of it.
//!
//! That is the same boundary the frame codec draws for `PUSH_PROMISE`: parse
//! and render, and say nothing about who should refuse what.
//!
//! ## Two shapes, because there are two kinds of question
//!
//! `validateName` and `validateValue` are pure functions of one string, and a
//! consumer can call either on its own. `MessageValidator` is fed a whole field
//! block one field at a time, because section 8.3's rules are about position
//! and repetition and so need to remember what came before.

const std = @import("std");

const Field = @import("hpack/Field.zig");

pub const MessageValidator = @import("fields/MessageValidator.zig");
pub const syntax = @import("fields/syntax.zig");

pub const Rules = syntax.Rules;
pub const NameError = syntax.NameError;
pub const ValueError = syntax.ValueError;
pub const validateName = syntax.validateName;
pub const validateValue = syntax.validateValue;

/// The name and value rules together, which is how a consumer walking a
/// decoded block wants them.
///
/// Every member says which half it came from — `Colon` and `Empty` can only be
/// a name's, `Delimiter`, `Control` and `Whitespace` only a value's, and
/// `Character` is a name's because the value set does not use that name. That
/// is why `ValueError` spells its control-octet case `Control`: the union is
/// by name, and one shared member would make this type lossy.
pub const FieldError = NameError || ValueError;

/// Check one decoded field.
///
/// The name is checked first: a name that is not a name makes the question of
/// what its value may contain moot, and a consumer that logs one violation per
/// field would rather log the one that identifies the field badly.
pub fn validate(field: *const Field, rules: Rules) FieldError!void {
    try validateName(field.name, rules);
    try validateValue(field.value, rules);
}

/// Whether a name is a pseudo-header field's (section 8.3): it begins with a
/// colon. Says nothing about whether it is one this document defines, or
/// whether it is allowed where it appeared — `MessageValidator` answers both,
/// because both are questions about the field block rather than the name.
pub fn isPseudo(name: []const u8) bool {
    return name.len > 0 and name[0] == syntax.pseudo_prefix;
}

test {
    _ = MessageValidator;
    _ = syntax;
}

test "a field is checked name first" {
    const bad_both: Field = .{ .name = "Host", .value = "a\r\nb" };
    try std.testing.expectError(error.Character, validate(&bad_both, .minimal));
}

test "every FieldError member says which half it came from" {
    const name_bad: Field = .{ .name = "a\x01b", .value = "ok" };
    const value_bad: Field = .{ .name = "ab", .value = "a\x01b" };
    // The pair that would be indistinguishable if both sets spelled this
    // `Character`.
    try std.testing.expectError(error.Character, validate(&name_bad, .strict));
    try std.testing.expectError(error.Control, validate(&value_bad, .strict));
}

test "isPseudo looks at the first octet and nothing else" {
    try std.testing.expect(isPseudo(":method"));
    try std.testing.expect(isPseudo(":"));
    try std.testing.expect(!isPseudo("method"));
    try std.testing.expect(!isPseudo(""));
}
