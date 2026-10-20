//! RFC 7541 Appendix C, the worked examples, extracted from the RFC text
//! rather than transcribed by hand.
//!
//! Transcription is exactly where a codec's test vectors go wrong, and quietly:
//! a mistyped byte string still decodes to *something*, so the test fails
//! against a plausible answer and the reader blames the decoder. These were
//! machine-lifted from the "Header list to encode" and "Hex dump of encoded
//! data" blocks of https://www.rfc-editor.org/rfc/rfc7541.txt.
//!
//! The four stories are four separate compression contexts. Within a story the
//! examples are consecutive on one connection and share a dynamic table, so
//! they must be replayed in order — that is what makes them a test of eviction
//! and not just of representations. C.5 and C.6 run with
//! SETTINGS_HEADER_TABLE_SIZE at 256 octets, which is what forces evictions.

const std = @import("std");

const Field = @import("Field.zig");

pub const Example = struct {
    name: []const u8,
    wire: []const u8,
    fields: []const Field,
    /// Dynamic table size once this block has been decoded, per the RFC's
    /// "Table size:" line.
    table_size: u32,
};

pub const Story = struct {
    name: []const u8,
    /// SETTINGS_HEADER_TABLE_SIZE in force for the whole story.
    table_size_max: u32,
    /// Whether the encoder that produced these blocks used Huffman coding.
    /// Both halves decode identically; it decides what an encoder must
    /// reproduce.
    huffman: bool,
    examples: []const Example,
};

pub const stories = [_]Story{
    .{
        .name = "C.3  requests, no Huffman",
        .table_size_max = 4096,
        .huffman = false,
        .examples = &.{
            .{
                .name = "C.3.1",
                .wire = "\x82\x86\x84A\x0fwww.example.com",
                .table_size = 57,
                .fields = &.{
                    .{ .name = ":method", .value = "GET" },
                    .{ .name = ":scheme", .value = "http" },
                    .{ .name = ":path", .value = "/" },
                    .{ .name = ":authority", .value = "www.example.com" },
                },
            },
            .{
                .name = "C.3.2",
                .wire = "\x82\x86\x84\xbeX\x08no-cache",
                .table_size = 110,
                .fields = &.{
                    .{ .name = ":method", .value = "GET" },
                    .{ .name = ":scheme", .value = "http" },
                    .{ .name = ":path", .value = "/" },
                    .{ .name = ":authority", .value = "www.example.com" },
                    .{ .name = "cache-control", .value = "no-cache" },
                },
            },
            .{
                .name = "C.3.3",
                .wire = "\x82\x87\x85\xbf@\x0acustom-key\x0ccustom-value",
                .table_size = 164,
                .fields = &.{
                    .{ .name = ":method", .value = "GET" },
                    .{ .name = ":scheme", .value = "https" },
                    .{ .name = ":path", .value = "/index.html" },
                    .{ .name = ":authority", .value = "www.example.com" },
                    .{ .name = "custom-key", .value = "custom-value" },
                },
            },
        },
    },
    .{
        .name = "C.4  requests, Huffman",
        .table_size_max = 4096,
        .huffman = true,
        .examples = &.{
            .{
                .name = "C.4.1",
                .wire = "\x82\x86\x84A\x8c\xf1\xe3\xc2\xe5\xf2:k\xa0\xab\x90\xf4\xff",
                .table_size = 57,
                .fields = &.{
                    .{ .name = ":method", .value = "GET" },
                    .{ .name = ":scheme", .value = "http" },
                    .{ .name = ":path", .value = "/" },
                    .{ .name = ":authority", .value = "www.example.com" },
                },
            },
            .{
                .name = "C.4.2",
                .wire = "\x82\x86\x84\xbeX\x86\xa8\xeb\x10d\x9c\xbf",
                .table_size = 110,
                .fields = &.{
                    .{ .name = ":method", .value = "GET" },
                    .{ .name = ":scheme", .value = "http" },
                    .{ .name = ":path", .value = "/" },
                    .{ .name = ":authority", .value = "www.example.com" },
                    .{ .name = "cache-control", .value = "no-cache" },
                },
            },
            .{
                .name = "C.4.3",
                .wire = "\x82\x87\x85\xbf@\x88%\xa8I\xe9[\xa9}\x7f\x89%\xa8I\xe9[\xb8\xe8\xb4\xbf",
                .table_size = 164,
                .fields = &.{
                    .{ .name = ":method", .value = "GET" },
                    .{ .name = ":scheme", .value = "https" },
                    .{ .name = ":path", .value = "/index.html" },
                    .{ .name = ":authority", .value = "www.example.com" },
                    .{ .name = "custom-key", .value = "custom-value" },
                },
            },
        },
    },
    .{
        .name = "C.5  responses, no Huffman",
        .table_size_max = 256,
        .huffman = false,
        .examples = &.{
            .{
                .name = "C.5.1",
                .wire = "H\x03302X\x07privatea\x1dMon, 21 Oct 2013 20:13:21 GMTn\x17https://www.example.com",
                .table_size = 222,
                .fields = &.{
                    .{ .name = ":status", .value = "302" },
                    .{ .name = "cache-control", .value = "private" },
                    .{ .name = "date", .value = "Mon, 21 Oct 2013 20:13:21 GMT" },
                    .{ .name = "location", .value = "https://www.example.com" },
                },
            },
            .{
                .name = "C.5.2",
                .wire = "H\x03307\xc1\xc0\xbf",
                .table_size = 222,
                .fields = &.{
                    .{ .name = ":status", .value = "307" },
                    .{ .name = "cache-control", .value = "private" },
                    .{ .name = "date", .value = "Mon, 21 Oct 2013 20:13:21 GMT" },
                    .{ .name = "location", .value = "https://www.example.com" },
                },
            },
            .{
                .name = "C.5.3",
                .wire = "\x88\xc1a\x1dMon, 21 Oct 2013 20:13:22 GMT\xc0Z\x04gzipw8foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1",
                .table_size = 215,
                .fields = &.{
                    .{ .name = ":status", .value = "200" },
                    .{ .name = "cache-control", .value = "private" },
                    .{ .name = "date", .value = "Mon, 21 Oct 2013 20:13:22 GMT" },
                    .{ .name = "location", .value = "https://www.example.com" },
                    .{ .name = "content-encoding", .value = "gzip" },
                    .{ .name = "set-cookie", .value = "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1" },
                },
            },
        },
    },
    .{
        .name = "C.6  responses, Huffman",
        .table_size_max = 256,
        .huffman = true,
        .examples = &.{
            .{
                .name = "C.6.1",
                .wire = "H\x82d\x02X\x85\xae\xc3w\x1aKa\x96\xd0z\xbe\x94\x10T\xd4D\xa8 \x05\x95\x04\x0b\x81f\xe0\x82\xa6-\x1b\xffn\x91\x9d)\xad\x17\x18c\xc7\x8f\x0b\x97\xc8\xe9\xae\x82\xaeC\xd3",
                .table_size = 222,
                .fields = &.{
                    .{ .name = ":status", .value = "302" },
                    .{ .name = "cache-control", .value = "private" },
                    .{ .name = "date", .value = "Mon, 21 Oct 2013 20:13:21 GMT" },
                    .{ .name = "location", .value = "https://www.example.com" },
                },
            },
            .{
                .name = "C.6.2",
                .wire = "H\x83d\x0e\xff\xc1\xc0\xbf",
                .table_size = 222,
                .fields = &.{
                    .{ .name = ":status", .value = "307" },
                    .{ .name = "cache-control", .value = "private" },
                    .{ .name = "date", .value = "Mon, 21 Oct 2013 20:13:21 GMT" },
                    .{ .name = "location", .value = "https://www.example.com" },
                },
            },
            .{
                .name = "C.6.3",
                .wire = "\x88\xc1a\x96\xd0z\xbe\x94\x10T\xd4D\xa8 \x05\x95\x04\x0b\x81f\xe0\x84\xa6-\x1b\xff\xc0Z\x83\x9b\xd9\xabw\xad\x94\xe7\x82\x1d\xd7\xf2\xe6\xc7\xb35\xdf\xdf\xcd[9`\xd5\xaf'\x08\x7f6r\xc1\xab'\x0f\xb5)\x1f\x95\x871`e\xc0\x03\xedN\xe5\xb1\x06=P\x07",
                .table_size = 215,
                .fields = &.{
                    .{ .name = ":status", .value = "200" },
                    .{ .name = "cache-control", .value = "private" },
                    .{ .name = "date", .value = "Mon, 21 Oct 2013 20:13:22 GMT" },
                    .{ .name = "location", .value = "https://www.example.com" },
                    .{ .name = "content-encoding", .value = "gzip" },
                    .{ .name = "set-cookie", .value = "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1" },
                },
            },
        },
    },
};

/// Individual Huffman-coded strings lifted from the decoding walk-throughs.
///
/// The full blocks above already exercise the codec; these localize a failure
/// to the string layer when one happens. Two of the RFC's strings are omitted:
/// its comment column wraps long values mid-token, so the text cannot be
/// recovered unambiguously, and both are covered by C.3.3/C.4.3 and
/// C.5.3/C.6.3 in full.
pub const huffman_strings = [_]struct { wire: []const u8, text: []const u8 }{
    .{ .wire = "d\x02", .text = "302" },
    .{ .wire = "d\x0e\xff", .text = "307" },
    .{ .wire = "\x9b\xd9\xab", .text = "gzip" },
    .{ .wire = "\xae\xc3w\x1aK", .text = "private" },
    .{ .wire = "\xa8\xeb\x10d\x9c\xbf", .text = "no-cache" },
    .{ .wire = "%\xa8I\xe9[\xa9}\x7f", .text = "custom-key" },
    .{ .wire = "\xf1\xe3\xc2\xe5\xf2:k\xa0\xab\x90\xf4\xff", .text = "www.example.com" },
    .{ .wire = "\x9d)\xad\x17\x18c\xc7\x8f\x0b\x97\xc8\xe9\xae\x82\xaeC\xd3", .text = "https://www.example.com" },
    .{ .wire = "\xd0z\xbe\x94\x10T\xd4D\xa8 \x05\x95\x04\x0b\x81f\xe0\x82\xa6-\x1b\xff", .text = "Mon, 21 Oct 2013 20:13:21 GMT" },
    .{ .wire = "\xd0z\xbe\x94\x10T\xd4D\xa8 \x05\x95\x04\x0b\x81f\xe0\x84\xa6-\x1b\xff", .text = "Mon, 21 Oct 2013 20:13:22 GMT" },
};
