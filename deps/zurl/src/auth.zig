//! Building an `authorization` header value.
//!
//! `Bearer <token>` needs no help — it is the token with a word in front, and
//! every caller in the benchmark repo writes it inline. Basic does need help,
//! because it is base64 of a colon-joined pair and getting it wrong produces a
//! header that looks right and authenticates as somebody else, or as nobody.
//!
//! Into a caller buffer, like everything here. The result is a slice a caller
//! hands straight to `FetchRequest.authorization`.

const std = @import("std");
const assert = std.debug.assert;

pub const Error = error{
    /// `buf` cannot hold the header value. Never a truncated credential:
    /// half a base64 blob still decodes, to the wrong thing.
    NoSpaceLeft,
    /// The user id contains a colon. RFC 7617 §2 forbids it because the colon
    /// is what separates the two halves — a `user:name` and password `p`
    /// encodes identically to user `user` with password `name:p`, so the
    /// origin cannot tell which was meant. Refused rather than encoded into
    /// an ambiguity.
    InvalidUserId,
    /// `user` plus `password` exceed `credential_bytes_max`.
    CredentialTooLong,
};

/// The longest `user:password` this will encode.
///
/// A stated bound rather than a guess, like every other buffer here. It exists
/// because the joined pair has to be staged somewhere before it is encoded,
/// and the obvious place — the tail of the caller's own buffer — OVERLAPS the
/// encoder's output whenever that buffer is sized exactly to fit, which is
/// exactly what a caller using `basicLen` does. The first draft staged there,
/// and its own overlap assertion caught it on the first run.
pub const credential_bytes_max = 512;

const prefix = "Basic ";
const encoder = std.base64.standard.Encoder;

/// Bytes `basic` needs for `user` and `password`.
pub fn basicLen(user: []const u8, password: []const u8) usize {
    // The colon is what joins them, and it is inside the encoded blob.
    return prefix.len + encoder.calcSize(user.len + 1 + password.len);
}

/// `Basic <base64(user:password)>`, written into `buf`.
///
/// RFC 7617. The credential is encoded, NOT encrypted — anyone who can read
/// the request can read the password, which is why this is only ever sent
/// over https in practice. zurl does not enforce that, because a caller
/// talking to a loopback origin over http has a legitimate use for it and
/// refusing would be zurl deciding the caller's threat model.
pub fn basic(buf: []u8, user: []const u8, password: []const u8) Error![]const u8 {
    // The one input that cannot be encoded unambiguously.
    if (std.mem.indexOfScalar(u8, user, ':') != null) return error.InvalidUserId;

    const joined_len = user.len + 1 + password.len;
    if (joined_len > credential_bytes_max) return error.CredentialTooLong;

    const needed = basicLen(user, password);
    if (buf.len < needed) return error.NoSpaceLeft;

    // Staged separately, never in `buf`: see `credential_bytes_max`.
    //
    // Not zeroed on return, and that is a decision rather than an oversight:
    // the credential is already in the caller's `user`/`password` and in the
    // header value this returns, so scrubbing one copy of three buys nothing
    // a caller cannot do better itself. Recorded so it is not mistaken for
    // something nobody thought about.
    assert(joined_len <= credential_bytes_max);
    var staging: [credential_bytes_max]u8 = undefined;
    @memcpy(staging[0..user.len], user);
    staging[user.len] = 0x3a;
    @memcpy(staging[user.len + 1 ..][0..password.len], password);

    @memcpy(buf[0..prefix.len], prefix);
    const written = encoder.encode(buf[prefix.len..needed], staging[0..joined_len]);
    assert(written.len == needed - prefix.len);
    return buf[0..needed];
}

// ---------------------------------------------------------------------------
// tests
const t = std.testing;

test "basic encodes the pair RFC 7617 gives as its own example" {
    // RFC 7617 §2 uses `Aladdin:open sesame`, and names the encoding it
    // produces — an independent check rather than this agreeing with itself.
    var buf: [128]u8 = undefined;
    try t.expectEqualStrings(
        "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==",
        try basic(&buf, "Aladdin", "open sesame"),
    );

    // Empty halves are legal and each still needs the colon.
    try t.expectEqualStrings("Basic Og==", try basic(&buf, "", ""));
    try t.expectEqualStrings("Basic dTo=", try basic(&buf, "u", ""));
    try t.expectEqualStrings("Basic OnA=", try basic(&buf, "", "p"));
}

test "a colon in the user id is refused rather than encoded into an ambiguity" {
    // `a:b` with password `c` and `a` with password `b:c` produce the same
    // bytes, so an origin cannot tell them apart. Encoding either would be
    // guessing which the caller meant.
    var buf: [128]u8 = undefined;
    try t.expectError(error.InvalidUserId, basic(&buf, "a:b", "c"));

    // A colon in the PASSWORD is fine — everything after the first one is
    // the password, so there is nothing ambiguous about it.
    const with_colon = try basic(&buf, "a", "b:c");
    try t.expectEqualStrings("Basic YTpiOmM=", with_colon);
}

test "a buffer too small is an error, never a truncated credential" {
    // Half a base64 blob still decodes — to a different credential, which an
    // origin rejects with a 401 that says nothing about why.
    var small: [8]u8 = undefined;
    try t.expectError(error.NoSpaceLeft, basic(&small, "Aladdin", "open sesame"));

    // Exactly enough is enough, which is what makes basicLen usable.
    var exact: [basicLen("user", "pass")]u8 = undefined;
    try t.expectEqual(exact.len, basicLen("user", "pass"));
    try t.expectEqualStrings("Basic dXNlcjpwYXNz", try basic(&exact, "user", "pass"));
}

test "basicLen agrees with basic across lengths, including where padding changes" {
    // base64 pads to a multiple of four, so the length steps rather than
    // growing smoothly — the three residues are where an off-by-one hides.
    var buf: [256]u8 = undefined;
    for (0..24) |user_len| {
        for (0..4) |password_len| {
            const user = "uuuuuuuuuuuuuuuuuuuuuuuu"[0..user_len];
            const password = "pppp"[0..password_len];
            const value = try basic(&buf, user, password);
            try t.expectEqual(basicLen(user, password), value.len);
            try t.expect(std.mem.startsWith(u8, value, "Basic "));
        }
    }
}
