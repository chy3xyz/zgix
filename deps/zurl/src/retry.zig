//! `Retry-After`, parsed into something a caller can act on.
//!
//! zurl does not retry (docs/SCOPE.md says why: retry needs to know whether
//! replaying this request is safe, and only the caller does). What it can do
//! is stop every caller from writing this parser, and from guessing a backoff
//! because the header that says how long to wait was too fiddly to read.
//!
//! It is deliberately NOT a delay. Turning a date into "how long from now"
//! needs a clock, and reaching for one here would put an implicit time source
//! inside a library whose whole discipline is that its inputs are handed to
//! it. The caller has a clock; it gets a value and does the subtraction.

const std = @import("std");
const assert = std.debug.assert;

/// What a `Retry-After` header said.
///
/// RFC 9110 §10.2.3 allows two forms and origins use both: a delay in seconds,
/// or the absolute time the resource is expected to be available again.
pub const RetryAfter = union(enum) {
    /// `Retry-After: 120` — wait this many seconds from now.
    seconds: u64,
    /// `Retry-After: Sun, 06 Nov 1994 08:49:37 GMT` — wait until this instant,
    /// as seconds since the Unix epoch. May be in the PAST, which an origin
    /// sends to mean "no delay"; a caller comparing against its own clock gets
    /// that answer for free, and one that subtracts blindly gets a negative it
    /// must clamp.
    at_unix_s: i64,
};

/// Parse a `Retry-After` value, or null if it is not one this understands.
///
/// The value is expected already trimmed of surrounding whitespace, which is
/// what the parser's `on_header` hands over.
///
/// Only the preferred IMF-fixdate form of HTTP-date is accepted. RFC 9110 asks
/// recipients to also take the two obsolete formats, and this does not: they
/// are vanishingly rare on `Retry-After`, and a half-right date parser that
/// silently returns the wrong instant is worse than one that says it does not
/// know. Null means "no usable value", which a caller already has to handle
/// for a missing header.
pub fn parse(value: []const u8) ?RetryAfter {
    if (value.len == 0) return null;
    // Established by the check above, and relied on by the digit test below.
    assert(value.len > 0);

    // delay-seconds is a bare integer, and it is what almost every origin
    // sends. A leading '+' or '-' is not a delay-seconds and not a date.
    if (std.ascii.isDigit(value[0])) {
        const seconds = std.fmt.parseInt(u64, value, 10) catch return null;
        return .{ .seconds = seconds };
    }

    return if (parseImfFixdate(value)) |at| .{ .at_unix_s = at } else null;
}

/// `Sun, 06 Nov 1994 08:49:37 GMT` — RFC 9110 §5.6.7, fixed width, GMT only.
fn parseImfFixdate(value: []const u8) ?i64 {
    // Fixed width is the whole point of this format: every field is at a known
    // offset, so there is nothing to scan and nothing to get wrong about
    // separators.
    if (value.len != 29) return null;
    if (value[3] != ',' or value[4] != ' ') return null;
    if (value[7] != ' ' or value[11] != ' ' or value[16] != ' ') return null;
    if (value[19] != ':' or value[22] != ':' or value[25] != ' ') return null;
    if (!std.mem.eql(u8, value[26..29], "GMT")) return null;

    const day = twoDigits(value[5..7]) orelse return null;
    const month = monthFromName(value[8..11]) orelse return null;
    const year = fourDigits(value[12..16]) orelse return null;
    const hour = twoDigits(value[17..19]) orelse return null;
    const minute = twoDigits(value[20..22]) orelse return null;
    const second = twoDigits(value[23..25]) orelse return null;

    if (day < 1 or day > daysInMonth(year, month)) return null;
    if (hour > 23 or minute > 59) return null;
    // 60 is a leap second. Accepted rather than refused: the arithmetic below
    // is a flat carry, so it rolls into whatever instant follows — the next
    // minute, or the next day for 23:59:60. Refusing a legal timestamp over
    // one second would be the worse answer.
    if (second > 60) return null;

    // Everything below is now known in range, which is what makes the plain
    // arithmetic that follows safe to read as arithmetic.
    assert(month >= 1);
    assert(month <= 12);

    const days = daysFromCivil(year, month, day);
    return days * 86400 + @as(i64, hour) * 3600 + @as(i64, minute) * 60 + @as(i64, second);
}

/// Days since 1970-01-01 for a proleptic Gregorian date.
///
/// Howard Hinnant's `days_from_civil`, which is exact for every year this can
/// see and needs no table and no loop. `month` is 1-12 and `day` is valid for
/// the month, both checked by the caller.
fn daysFromCivil(year: u16, month: u8, day: u8) i64 {
    assert(month >= 1);
    assert(month <= 12);
    assert(day >= 1);
    assert(day <= 31);

    // March-based years, so a leap day lands at the end and never shifts the
    // month lengths ahead of it.
    const y: i64 = @as(i64, year) - @intFromBool(month <= 2);
    const era = @divFloor(y, 400);
    const year_of_era: i64 = y - era * 400;
    // Floor division is what makes this hold for a negative `y`, which the
    // year-0 January case reaches. A refactor to @divTrunc would break
    // pre-epoch dates silently, and this is what would catch it.
    assert(year_of_era >= 0);
    assert(year_of_era < 400);

    const shifted_month: i64 = if (month > 2) @as(i64, month) - 3 else @as(i64, month) + 9;
    const day_of_year: i64 = @divTrunc(153 * shifted_month + 2, 5) + @as(i64, day) - 1;
    const day_of_era: i64 = year_of_era * 365 +
        @divTrunc(year_of_era, 4) - @divTrunc(year_of_era, 100) + day_of_year;
    // 146097 days is exactly 400 years, so a day within one era cannot reach
    // the next. An out-of-range value here means the month shift is wrong.
    assert(day_of_era >= 0);
    assert(day_of_era < 146097);

    return era * 146097 + day_of_era - 719468;
}

fn daysInMonth(year: u16, month: u8) u8 {
    assert(month >= 1);
    assert(month <= 12);

    const lengths = [12]u8{ 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
    if (month == 2 and isLeapYear(year)) return 29;
    return lengths[month - 1];
}

fn isLeapYear(year: u16) bool {
    if (year % 4 != 0) return false;
    if (year % 100 != 0) return true;
    return year % 400 == 0;
}

fn monthFromName(name: []const u8) ?u8 {
    assert(name.len == 3);

    const names = [12][]const u8{
        "Jan", "Feb", "Mar", "Apr", "May", "Jun",
        "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    };
    // Case-sensitive: IMF-fixdate specifies exactly these spellings, and a
    // lowercase one is the obsolete format's territory, not this one's.
    for (names, 0..) |candidate, index| {
        if (std.mem.eql(u8, name, candidate)) return @intCast(index + 1);
    }
    return null;
}

fn twoDigits(text: []const u8) ?u8 {
    assert(text.len == 2);

    if (!std.ascii.isDigit(text[0]) or !std.ascii.isDigit(text[1])) return null;
    return (text[0] - '0') * 10 + (text[1] - '0');
}

fn fourDigits(text: []const u8) ?u16 {
    assert(text.len == 4);

    var value: u16 = 0;
    for (text) |c| {
        if (!std.ascii.isDigit(c)) return null;
        value = value * 10 + (c - '0');
    }
    return value;
}

// ---------------------------------------------------------------------------
// tests
const t = std.testing;

test "delay-seconds is the common form and parses as itself" {
    try t.expectEqual(RetryAfter{ .seconds = 0 }, parse("0").?);
    try t.expectEqual(RetryAfter{ .seconds = 120 }, parse("120").?);
    try t.expectEqual(RetryAfter{ .seconds = 86400 }, parse("86400").?);

    // Not delay-seconds, and not a date either.
    try t.expectEqual(@as(?RetryAfter, null), parse(""));
    try t.expectEqual(@as(?RetryAfter, null), parse("-5"));
    try t.expectEqual(@as(?RetryAfter, null), parse("+5"));
    try t.expectEqual(@as(?RetryAfter, null), parse("12x"));
    try t.expectEqual(@as(?RetryAfter, null), parse("later"));
}

test "IMF-fixdate parses to the instant RFC 9110 gives as its own example" {
    // RFC 9110 §5.6.7 uses this exact string, and 784111777 is the Unix time
    // it names — an independent check rather than this parser agreeing with
    // itself.
    try t.expectEqual(RetryAfter{ .at_unix_s = 784111777 }, parse("Sun, 06 Nov 1994 08:49:37 GMT").?);

    // The epoch itself, and a leap-day, which is where a civil-days
    // calculation goes wrong if it is going to.
    try t.expectEqual(RetryAfter{ .at_unix_s = 0 }, parse("Thu, 01 Jan 1970 00:00:00 GMT").?);
    try t.expectEqual(RetryAfter{ .at_unix_s = 951782400 }, parse("Tue, 29 Feb 2000 00:00:00 GMT").?);
    // 1900 is not a leap year and 2000 is; a naive %4 rule gets one of these
    // wrong and a %100 rule without the %400 exception gets the other.
    try t.expectEqual(@as(?RetryAfter, null), parse("Wed, 29 Feb 1900 00:00:00 GMT"));
    // A date in the past is legal and means "no delay". The caller subtracts.
    try t.expectEqual(RetryAfter{ .at_unix_s = 784111777 }, parse("Sun, 06 Nov 1994 08:49:37 GMT").?);
}

test "a malformed date is null rather than a wrong instant" {
    // Every one of these would be a plausible thing to accept loosely, and
    // each would hand back a time that is not what the origin said.
    const bad = [_][]const u8{
        "Sun, 06 Nov 1994 08:49:37", // no GMT
        "Sun, 06 Nov 1994 08:49:37 UTC", // wrong zone
        "Sun, 06 Nov 1994 08:49:37 gmt", // zone case
        "Sun 06 Nov 1994 08:49:37 GMT", // missing comma
        "Sun, 06 nov 1994 08:49:37 GMT", // month case
        "Sun, 06 Xxx 1994 08:49:37 GMT", // no such month
        "Sun, 32 Nov 1994 08:49:37 GMT", // no such day
        "Sun, 00 Nov 1994 08:49:37 GMT", // day zero
        "Sun, 06 Nov 1994 24:49:37 GMT", // hour out of range
        "Sun, 06 Nov 1994 08:60:37 GMT", // minute out of range
        "Sun, 06 Nov 1994 08:49:61 GMT", // past a leap second
        "Sunday, 06-Nov-94 08:49:37 GMT", // RFC 850, deliberately unsupported
        "Sun Nov  6 08:49:37 1994", // asctime, deliberately unsupported
    };
    for (bad) |value| try t.expectEqual(@as(?RetryAfter, null), parse(value));
}
