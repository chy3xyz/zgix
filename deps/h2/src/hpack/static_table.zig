//! RFC 7541 Appendix A: the 61-entry static table.
//!
//! HPACK indices are 1-based and the static table occupies 1..61, so
//! `entries[index - 1]` is the entry index names. Dynamic table indices continue
//! from `dynamic_offset`.

const std = @import("std");

const assert = @import("../assert.zig").assert;

const Field = @import("Field.zig");

/// The first index that names a dynamic table entry (RFC 7541 section 2.3.3).
pub const dynamic_offset: u32 = 62;

pub const entries = [61]Field{
    .{ .name = ":authority", .value = "" }, // 1
    .{ .name = ":method", .value = "GET" }, // 2
    .{ .name = ":method", .value = "POST" }, // 3
    .{ .name = ":path", .value = "/" }, // 4
    .{ .name = ":path", .value = "/index.html" }, // 5
    .{ .name = ":scheme", .value = "http" }, // 6
    .{ .name = ":scheme", .value = "https" }, // 7
    .{ .name = ":status", .value = "200" }, // 8
    .{ .name = ":status", .value = "204" }, // 9
    .{ .name = ":status", .value = "206" }, // 10
    .{ .name = ":status", .value = "304" }, // 11
    .{ .name = ":status", .value = "400" }, // 12
    .{ .name = ":status", .value = "404" }, // 13
    .{ .name = ":status", .value = "500" }, // 14
    .{ .name = "accept-charset", .value = "" }, // 15
    .{ .name = "accept-encoding", .value = "gzip, deflate" }, // 16
    .{ .name = "accept-language", .value = "" }, // 17
    .{ .name = "accept-ranges", .value = "" }, // 18
    .{ .name = "accept", .value = "" }, // 19
    .{ .name = "access-control-allow-origin", .value = "" }, // 20
    .{ .name = "age", .value = "" }, // 21
    .{ .name = "allow", .value = "" }, // 22
    .{ .name = "authorization", .value = "" }, // 23
    .{ .name = "cache-control", .value = "" }, // 24
    .{ .name = "content-disposition", .value = "" }, // 25
    .{ .name = "content-encoding", .value = "" }, // 26
    .{ .name = "content-language", .value = "" }, // 27
    .{ .name = "content-length", .value = "" }, // 28
    .{ .name = "content-location", .value = "" }, // 29
    .{ .name = "content-range", .value = "" }, // 30
    .{ .name = "content-type", .value = "" }, // 31
    .{ .name = "cookie", .value = "" }, // 32
    .{ .name = "date", .value = "" }, // 33
    .{ .name = "etag", .value = "" }, // 34
    .{ .name = "expect", .value = "" }, // 35
    .{ .name = "expires", .value = "" }, // 36
    .{ .name = "from", .value = "" }, // 37
    .{ .name = "host", .value = "" }, // 38
    .{ .name = "if-match", .value = "" }, // 39
    .{ .name = "if-modified-since", .value = "" }, // 40
    .{ .name = "if-none-match", .value = "" }, // 41
    .{ .name = "if-range", .value = "" }, // 42
    .{ .name = "if-unmodified-since", .value = "" }, // 43
    .{ .name = "last-modified", .value = "" }, // 44
    .{ .name = "link", .value = "" }, // 45
    .{ .name = "location", .value = "" }, // 46
    .{ .name = "max-forwards", .value = "" }, // 47
    .{ .name = "proxy-authenticate", .value = "" }, // 48
    .{ .name = "proxy-authorization", .value = "" }, // 49
    .{ .name = "range", .value = "" }, // 50
    .{ .name = "referer", .value = "" }, // 51
    .{ .name = "refresh", .value = "" }, // 52
    .{ .name = "retry-after", .value = "" }, // 53
    .{ .name = "server", .value = "" }, // 54
    .{ .name = "set-cookie", .value = "" }, // 55
    .{ .name = "strict-transport-security", .value = "" }, // 56
    .{ .name = "transfer-encoding", .value = "" }, // 57
    .{ .name = "user-agent", .value = "" }, // 58
    .{ .name = "vary", .value = "" }, // 59
    .{ .name = "via", .value = "" }, // 60
    .{ .name = "www-authenticate", .value = "" }, // 61
};

comptime {
    @setEvalBranchQuota(20000);
    assert(entries.len == dynamic_offset - 1);
    for (entries) |entry| {
        assert(entry.name.len > 0);
        // Static names are already lowercase; a decoder that trusts this must
        // not be handed a table where it is false.
        for (entry.name) |byte| assert(byte < 'A' or byte > 'Z');
    }
}

/// A run of entries sharing one name.
///
/// RFC 7541 Appendix A keeps same-named entries adjacent — `:status` occupies
/// 8 through 14, and it is the longest run there is — so a name maps to a
/// contiguous range of indices, and finding a value is a short scan of that
/// range rather than a second map keyed on the pair.
const NameRun = struct {
    first: u32,
    count: u32,
};

const name_runs = blk: {
    @setEvalBranchQuota(20_000);
    var runs: [entries.len]struct { []const u8, NameRun } = undefined;
    var run_count: usize = 0;
    var index: usize = 0;
    while (index < entries.len) {
        const name = entries[index].name;
        var length: u32 = 1;
        while (index + length < entries.len and
            std.mem.eql(u8, entries[index + length].name, name)) : (length += 1)
        {}
        runs[run_count] = .{ name, .{ .first = @intCast(index + 1), .count = length } };
        run_count += 1;
        index += length;
    }
    break :blk runs[0..run_count].*;
};

comptime {
    @setEvalBranchQuota(200_000);
    // The runs must partition the table: adjacency is an assumption about the
    // RFC's ordering, and a name appearing in two separate runs would leave the
    // map silently holding only one of them.
    var covered: u32 = 0;
    for (name_runs) |run| covered += run[1].count;
    assert(covered == entries.len);
    for (name_runs, 0..) |run, outer| {
        for (name_runs, 0..) |other, inner| {
            if (outer == inner) continue;
            assert(!std.mem.eql(u8, run[0], other[0]));
        }
    }
}

const by_name = std.StaticStringMap(NameRun).initComptime(name_runs);

/// What one probe of the static table found.
pub const Match = struct {
    /// Lowest index sharing the name, or null. Named for what it holds: these
    /// are wire indices, and confusing one with a count or a position is a
    /// compression bug rather than a crash.
    name_index: ?u32 = null,
    /// Index matching both name and value, or null.
    field_index: ?u32 = null,
};

/// Probe once for both answers.
///
/// Separate `findName` and `findField` would hash the name twice for every
/// field encoded, and the encoder wants both answers on every field it does not
/// find fully indexed.
pub fn find(name: []const u8, value: []const u8) Match {
    const run = by_name.get(name) orelse return .{};
    assert(run.first >= 1);
    assert(run.first + run.count <= dynamic_offset);

    var index = run.first;
    while (index < run.first + run.count) : (index += 1) {
        if (std.mem.eql(u8, entries[index - 1].value, value)) {
            return .{ .name_index = run.first, .field_index = index };
        }
    }
    return .{ .name_index = run.first };
}

/// The lowest index of an entry with this name, or null.
///
/// Lowest because a smaller index encodes in fewer octets, and because the
/// entry a name-only match points at is only used for its name anyway.
pub fn findName(name: []const u8) ?u32 {
    const run = by_name.get(name) orelse return null;
    assert(run.first >= 1);
    assert(run.first + run.count <= dynamic_offset);
    return run.first;
}

/// The entry named by a static index, or null when `index` is out of range.
/// Callers pass the raw wire index, so 0 and anything past 61 are ordinary
/// inputs here rather than programming errors.
pub fn get(index: u32) ?Field {
    if (index == 0) return null;
    if (index >= dynamic_offset) return null;
    return entries[index - 1];
}
