//! Percent-encoding, for callers building a URL out of values they were
//! handed.
//!
//! This is the other half of the request-target refusal. `writeRequest`
//! rejects a target carrying a byte that cannot appear in a request line,
//! which tells a caller it built a wrong URL; this is how it builds a right
//! one. Neither is much use alone: refusal without an encoder means the
//! caller is stuck, and an encoder without refusal means a missed call
//! silently changes which resource is fetched.
//!
//! It writes into a caller buffer and allocates nothing, like everything else
//! here. `encodedLen` is how a caller sizes that buffer without guessing.
//!
//! Decoding is deliberately absent. zurl builds requests and never needs to
//! read a percent-encoded value back, and a decoder invites the double-decode
//! bug that turns `%252e%252e` into `..` one layer too late.

const std = @import("std");
const assert = std.debug.assert;

/// Which part of a URL the text is going into.
///
/// The distinction that matters is what counts as a DELIMITER there: a byte
/// left unescaped in the wrong component does not corrupt the string, it
/// silently restructures the URL.
pub const Component = enum {
    /// One path segment. `/` is escaped, so a value containing one cannot
    /// quietly become two segments — which is the difference between an
    /// object named `a/b` and an object `b` inside `a`.
    segment,
    /// A whole path, with `/` preserved as the separator it is.
    path,
    /// A query parameter name or value. `&` and `=` are escaped, so a value
    /// cannot introduce a parameter of its own, and `+` is escaped rather
    /// than treated as a space — that convention belongs to form encoding,
    /// not to URLs, and guessing wrong flips a value's meaning.
    query,
};

/// Whether `byte` may appear literally in `component`.
fn isLiteral(byte: u8, component: Component) bool {
    // RFC 3986 §2.3 unreserved: never escaped anywhere, and never ambiguous.
    switch (byte) {
        'A'...'Z', 'a'...'z', '0'...'9', '-', '.', '_', '~' => return true,
        else => {},
    }

    return switch (component) {
        .segment => false,
        .path => byte == '/',
        // Sub-delims that are not delimiters WITHIN a parameter stay literal:
        // escaping them is legal but makes URLs that no longer match what an
        // origin logged, and these carry no structural meaning under RFC
        // 3986.
        //
        // `;` was considered and left literal. Some frameworks once read it
        // as an alternate parameter separator, which is the same class of
        // ambiguity `&` and `=` are escaped for — but it is not a separator
        // in the grammar, and escaping it would mangle the `;`-bearing paths
        // that are still common in practice. Escape it yourself with
        // `.segment` if you are talking to something that splits on it.
        .query => switch (byte) {
            '/', ':', '@', '!', '$', '\'', '(', ')', '*', ',', ';' => true,
            else => false,
        },
    };
}

/// How many bytes `text` needs once encoded for `component`.
///
/// Exact, not an upper bound, so a caller can size a buffer to fit rather than
/// to the worst case of three bytes per input byte.
pub fn encodedLen(text: []const u8, component: Component) usize {
    var len: usize = 0;
    for (text) |byte| len += if (isLiteral(byte, component)) 1 else 3;

    // Every byte contributes at least itself, and at most a three-byte escape.
    assert(len >= text.len);
    assert(len <= text.len * 3);
    return len;
}

/// Percent-encode `text` into `buf`, returning the written slice.
///
/// `error.NoSpaceLeft` when `buf` cannot hold the result — never a truncated
/// URL, which would point at a different resource than the caller meant
/// (rule 7). `encodedLen` says how much is needed.
pub fn encode(buf: []u8, text: []const u8, component: Component) error{NoSpaceLeft}![]const u8 {
    // Uppercase, per RFC 3986 §2.1: both cases are legal on the wire, but
    // origins that compare or sign a canonical URL expect these.
    const hex = "0123456789ABCDEF";

    var written: usize = 0;
    for (text) |byte| {
        if (isLiteral(byte, component)) {
            if (written + 1 > buf.len) return error.NoSpaceLeft;
            buf[written] = byte;
            written += 1;
            continue;
        }

        if (written + 3 > buf.len) return error.NoSpaceLeft;
        buf[written] = '%';
        buf[written + 1] = hex[byte >> 4];
        buf[written + 2] = hex[byte & 0x0f];
        written += 3;
    }

    // What `encodedLen` promised, checked where a caller relies on it.
    assert(written == encodedLen(text, component));
    return buf[0..written];
}

// ---------------------------------------------------------------------------
// tests
const t = std.testing;

test "unreserved bytes survive and everything else is escaped" {
    var buf: [256]u8 = undefined;

    // RFC 3986 §2.3 unreserved, which must never be escaped in any component.
    const unreserved = "ABCXYZabcxyz0189-._~";
    for ([_]Component{ .segment, .path, .query }) |component| {
        try t.expectEqualStrings(unreserved, try encode(&buf, unreserved, component));
    }

    // Uppercase hex, and a space is %20 rather than a plus.
    try t.expectEqualStrings("a%20b", try encode(&buf, "a b", .segment));
    try t.expectEqualStrings("%7B%7D", try encode(&buf, "{}", .segment));
    // Non-ASCII goes byte by byte: e-acute is two UTF-8 bytes, two escapes.
    try t.expectEqualStrings("caf%C3%A9", try encode(&buf, "caf\xc3\xa9", .segment));
}

test "each component escapes the bytes that would restructure it" {
    var buf: [256]u8 = undefined;

    // The case this exists for: a bucket key containing a slash is ONE name,
    // and leaving it literal would make it a directory and a file.
    try t.expectEqualStrings("a%2Fb", try encode(&buf, "a/b", .segment));
    try t.expectEqualStrings("a/b", try encode(&buf, "a/b", .path));

    // A `?` or `#` in a path silently ends it, turning the rest into a query
    // or a fragment that is never sent at all.
    try t.expectEqualStrings("a%3Fb%23c", try encode(&buf, "a?b#c", .path));

    // In a query, `&` and `=` would add a parameter the caller did not write.
    try t.expectEqualStrings("a%26b%3Dc", try encode(&buf, "a&b=c", .query));
    // `+` is escaped rather than passed through: reading it as a space is a
    // form-encoding convention, and an origin that applies it would see a
    // different value than the one sent.
    try t.expectEqualStrings("a%2Bb", try encode(&buf, "a+b", .query));
}

test "a buffer too small is an error, never a truncated URL" {
    // Truncation here does not corrupt a string, it names a different
    // resource — the same reason rule 7 refuses a clipped header.
    var small: [4]u8 = undefined;
    try t.expectError(error.NoSpaceLeft, encode(&small, "abcde", .segment));
    // One byte short of an escape is still short: no half-written `%C3`.
    var tight: [2]u8 = undefined;
    try t.expectError(error.NoSpaceLeft, encode(&tight, " ", .segment));

    // And exactly enough is enough, which is what makes `encodedLen` usable.
    const text = "a b/c";
    var exact: [encodedLen("a b/c", .segment)]u8 = undefined;
    try t.expectEqual(exact.len, encodedLen(text, .segment));
    try t.expectEqualStrings("a%20b%2Fc", try encode(&exact, text, .segment));
}

test "encodedLen agrees with encode for every byte value" {
    // The postcondition inside `encode` asserts this, but only for inputs a
    // test happens to try. This tries all 256.
    var buf: [8]u8 = undefined;
    for ([_]Component{ .segment, .path, .query }) |component| {
        for (0..256) |value| {
            const byte: u8 = @intCast(value);
            const text = [_]u8{byte};
            const encoded = try encode(&buf, &text, component);
            try t.expectEqual(encodedLen(&text, component), encoded.len);
            // A literal byte is itself; an escaped one is three bytes of
            // uppercase hex that decode back to the original.
            if (encoded.len == 1) {
                try t.expectEqual(byte, encoded[0]);
            } else {
                try t.expectEqual(@as(usize, 3), encoded.len);
                try t.expectEqual(@as(u8, '%'), encoded[0]);
                try t.expectEqual(byte, try std.fmt.parseInt(u8, encoded[1..3], 16));
            }
        }
    }
}
