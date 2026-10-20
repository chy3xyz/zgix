//! RFC 7541 Appendix B: the fixed Huffman code table.
//!
//! Generated from the RFC and cross-checked against golang.org/x/net/http2/hpack.
//! The comptime block below re-proves what can be checked from this table
//! alone, so a transcription error is a compile error rather than a wrong
//! answer: every code lies within its stated length, and the lengths are in
//! range.
//!
//! Prefix-freeness is the other property the decoder rests on, and it is proven
//! where it is used rather than here: `huffman.buildTree` asserts that no code
//! descends through a leaf and that none lands on an interior node, which is
//! both halves of it, and then that the tree came out complete.

const std = @import("std");

const assert = @import("../assert.zig").assert;

/// One symbol's code. `code` is right-aligned in `bits` significant bits.
pub const Code = struct {
    code: u32,
    bits: u5,
};

/// The EOS symbol. It never appears in a valid encoded string: a Huffman string
/// containing it is a decoding error (RFC 7541 section 5.2), and it exists here
/// only because its most significant bits are what legal padding must match.
pub const eos: u16 = 256;

/// Shortest and longest code, which bound every buffer sized off this table.
pub const bits_min: u5 = 5;
pub const bits_max: u5 = 30;

pub const codes = [257]Code{
    .{ .code = 0x00001ff8, .bits = 13 }, //   0 0x00
    .{ .code = 0x007fffd8, .bits = 23 }, //   1 0x01
    .{ .code = 0x0fffffe2, .bits = 28 }, //   2 0x02
    .{ .code = 0x0fffffe3, .bits = 28 }, //   3 0x03
    .{ .code = 0x0fffffe4, .bits = 28 }, //   4 0x04
    .{ .code = 0x0fffffe5, .bits = 28 }, //   5 0x05
    .{ .code = 0x0fffffe6, .bits = 28 }, //   6 0x06
    .{ .code = 0x0fffffe7, .bits = 28 }, //   7 0x07
    .{ .code = 0x0fffffe8, .bits = 28 }, //   8 0x08
    .{ .code = 0x00ffffea, .bits = 24 }, //   9 0x09
    .{ .code = 0x3ffffffc, .bits = 30 }, //  10 0x0a
    .{ .code = 0x0fffffe9, .bits = 28 }, //  11 0x0b
    .{ .code = 0x0fffffea, .bits = 28 }, //  12 0x0c
    .{ .code = 0x3ffffffd, .bits = 30 }, //  13 0x0d
    .{ .code = 0x0fffffeb, .bits = 28 }, //  14 0x0e
    .{ .code = 0x0fffffec, .bits = 28 }, //  15 0x0f
    .{ .code = 0x0fffffed, .bits = 28 }, //  16 0x10
    .{ .code = 0x0fffffee, .bits = 28 }, //  17 0x11
    .{ .code = 0x0fffffef, .bits = 28 }, //  18 0x12
    .{ .code = 0x0ffffff0, .bits = 28 }, //  19 0x13
    .{ .code = 0x0ffffff1, .bits = 28 }, //  20 0x14
    .{ .code = 0x0ffffff2, .bits = 28 }, //  21 0x15
    .{ .code = 0x3ffffffe, .bits = 30 }, //  22 0x16
    .{ .code = 0x0ffffff3, .bits = 28 }, //  23 0x17
    .{ .code = 0x0ffffff4, .bits = 28 }, //  24 0x18
    .{ .code = 0x0ffffff5, .bits = 28 }, //  25 0x19
    .{ .code = 0x0ffffff6, .bits = 28 }, //  26 0x1a
    .{ .code = 0x0ffffff7, .bits = 28 }, //  27 0x1b
    .{ .code = 0x0ffffff8, .bits = 28 }, //  28 0x1c
    .{ .code = 0x0ffffff9, .bits = 28 }, //  29 0x1d
    .{ .code = 0x0ffffffa, .bits = 28 }, //  30 0x1e
    .{ .code = 0x0ffffffb, .bits = 28 }, //  31 0x1f
    .{ .code = 0x00000014, .bits = 6 }, //  32 ' '
    .{ .code = 0x000003f8, .bits = 10 }, //  33 '!'
    .{ .code = 0x000003f9, .bits = 10 }, //  34 '"'
    .{ .code = 0x00000ffa, .bits = 12 }, //  35 '#'
    .{ .code = 0x00001ff9, .bits = 13 }, //  36 '$'
    .{ .code = 0x00000015, .bits = 6 }, //  37 '%'
    .{ .code = 0x000000f8, .bits = 8 }, //  38 '&'
    .{ .code = 0x000007fa, .bits = 11 }, //  39 "'"
    .{ .code = 0x000003fa, .bits = 10 }, //  40 '('
    .{ .code = 0x000003fb, .bits = 10 }, //  41 ')'
    .{ .code = 0x000000f9, .bits = 8 }, //  42 '*'
    .{ .code = 0x000007fb, .bits = 11 }, //  43 '+'
    .{ .code = 0x000000fa, .bits = 8 }, //  44 ','
    .{ .code = 0x00000016, .bits = 6 }, //  45 '-'
    .{ .code = 0x00000017, .bits = 6 }, //  46 '.'
    .{ .code = 0x00000018, .bits = 6 }, //  47 '/'
    .{ .code = 0x00000000, .bits = 5 }, //  48 '0'
    .{ .code = 0x00000001, .bits = 5 }, //  49 '1'
    .{ .code = 0x00000002, .bits = 5 }, //  50 '2'
    .{ .code = 0x00000019, .bits = 6 }, //  51 '3'
    .{ .code = 0x0000001a, .bits = 6 }, //  52 '4'
    .{ .code = 0x0000001b, .bits = 6 }, //  53 '5'
    .{ .code = 0x0000001c, .bits = 6 }, //  54 '6'
    .{ .code = 0x0000001d, .bits = 6 }, //  55 '7'
    .{ .code = 0x0000001e, .bits = 6 }, //  56 '8'
    .{ .code = 0x0000001f, .bits = 6 }, //  57 '9'
    .{ .code = 0x0000005c, .bits = 7 }, //  58 ':'
    .{ .code = 0x000000fb, .bits = 8 }, //  59 ';'
    .{ .code = 0x00007ffc, .bits = 15 }, //  60 '<'
    .{ .code = 0x00000020, .bits = 6 }, //  61 '='
    .{ .code = 0x00000ffb, .bits = 12 }, //  62 '>'
    .{ .code = 0x000003fc, .bits = 10 }, //  63 '?'
    .{ .code = 0x00001ffa, .bits = 13 }, //  64 '@'
    .{ .code = 0x00000021, .bits = 6 }, //  65 'A'
    .{ .code = 0x0000005d, .bits = 7 }, //  66 'B'
    .{ .code = 0x0000005e, .bits = 7 }, //  67 'C'
    .{ .code = 0x0000005f, .bits = 7 }, //  68 'D'
    .{ .code = 0x00000060, .bits = 7 }, //  69 'E'
    .{ .code = 0x00000061, .bits = 7 }, //  70 'F'
    .{ .code = 0x00000062, .bits = 7 }, //  71 'G'
    .{ .code = 0x00000063, .bits = 7 }, //  72 'H'
    .{ .code = 0x00000064, .bits = 7 }, //  73 'I'
    .{ .code = 0x00000065, .bits = 7 }, //  74 'J'
    .{ .code = 0x00000066, .bits = 7 }, //  75 'K'
    .{ .code = 0x00000067, .bits = 7 }, //  76 'L'
    .{ .code = 0x00000068, .bits = 7 }, //  77 'M'
    .{ .code = 0x00000069, .bits = 7 }, //  78 'N'
    .{ .code = 0x0000006a, .bits = 7 }, //  79 'O'
    .{ .code = 0x0000006b, .bits = 7 }, //  80 'P'
    .{ .code = 0x0000006c, .bits = 7 }, //  81 'Q'
    .{ .code = 0x0000006d, .bits = 7 }, //  82 'R'
    .{ .code = 0x0000006e, .bits = 7 }, //  83 'S'
    .{ .code = 0x0000006f, .bits = 7 }, //  84 'T'
    .{ .code = 0x00000070, .bits = 7 }, //  85 'U'
    .{ .code = 0x00000071, .bits = 7 }, //  86 'V'
    .{ .code = 0x00000072, .bits = 7 }, //  87 'W'
    .{ .code = 0x000000fc, .bits = 8 }, //  88 'X'
    .{ .code = 0x00000073, .bits = 7 }, //  89 'Y'
    .{ .code = 0x000000fd, .bits = 8 }, //  90 'Z'
    .{ .code = 0x00001ffb, .bits = 13 }, //  91 '['
    .{ .code = 0x0007fff0, .bits = 19 }, //  92 '\\'
    .{ .code = 0x00001ffc, .bits = 13 }, //  93 ']'
    .{ .code = 0x00003ffc, .bits = 14 }, //  94 '^'
    .{ .code = 0x00000022, .bits = 6 }, //  95 '_'
    .{ .code = 0x00007ffd, .bits = 15 }, //  96 '`'
    .{ .code = 0x00000003, .bits = 5 }, //  97 'a'
    .{ .code = 0x00000023, .bits = 6 }, //  98 'b'
    .{ .code = 0x00000004, .bits = 5 }, //  99 'c'
    .{ .code = 0x00000024, .bits = 6 }, // 100 'd'
    .{ .code = 0x00000005, .bits = 5 }, // 101 'e'
    .{ .code = 0x00000025, .bits = 6 }, // 102 'f'
    .{ .code = 0x00000026, .bits = 6 }, // 103 'g'
    .{ .code = 0x00000027, .bits = 6 }, // 104 'h'
    .{ .code = 0x00000006, .bits = 5 }, // 105 'i'
    .{ .code = 0x00000074, .bits = 7 }, // 106 'j'
    .{ .code = 0x00000075, .bits = 7 }, // 107 'k'
    .{ .code = 0x00000028, .bits = 6 }, // 108 'l'
    .{ .code = 0x00000029, .bits = 6 }, // 109 'm'
    .{ .code = 0x0000002a, .bits = 6 }, // 110 'n'
    .{ .code = 0x00000007, .bits = 5 }, // 111 'o'
    .{ .code = 0x0000002b, .bits = 6 }, // 112 'p'
    .{ .code = 0x00000076, .bits = 7 }, // 113 'q'
    .{ .code = 0x0000002c, .bits = 6 }, // 114 'r'
    .{ .code = 0x00000008, .bits = 5 }, // 115 's'
    .{ .code = 0x00000009, .bits = 5 }, // 116 't'
    .{ .code = 0x0000002d, .bits = 6 }, // 117 'u'
    .{ .code = 0x00000077, .bits = 7 }, // 118 'v'
    .{ .code = 0x00000078, .bits = 7 }, // 119 'w'
    .{ .code = 0x00000079, .bits = 7 }, // 120 'x'
    .{ .code = 0x0000007a, .bits = 7 }, // 121 'y'
    .{ .code = 0x0000007b, .bits = 7 }, // 122 'z'
    .{ .code = 0x00007ffe, .bits = 15 }, // 123 '{'
    .{ .code = 0x000007fc, .bits = 11 }, // 124 '|'
    .{ .code = 0x00003ffd, .bits = 14 }, // 125 '}'
    .{ .code = 0x00001ffd, .bits = 13 }, // 126 '~'
    .{ .code = 0x0ffffffc, .bits = 28 }, // 127 0x7f
    .{ .code = 0x000fffe6, .bits = 20 }, // 128 0x80
    .{ .code = 0x003fffd2, .bits = 22 }, // 129 0x81
    .{ .code = 0x000fffe7, .bits = 20 }, // 130 0x82
    .{ .code = 0x000fffe8, .bits = 20 }, // 131 0x83
    .{ .code = 0x003fffd3, .bits = 22 }, // 132 0x84
    .{ .code = 0x003fffd4, .bits = 22 }, // 133 0x85
    .{ .code = 0x003fffd5, .bits = 22 }, // 134 0x86
    .{ .code = 0x007fffd9, .bits = 23 }, // 135 0x87
    .{ .code = 0x003fffd6, .bits = 22 }, // 136 0x88
    .{ .code = 0x007fffda, .bits = 23 }, // 137 0x89
    .{ .code = 0x007fffdb, .bits = 23 }, // 138 0x8a
    .{ .code = 0x007fffdc, .bits = 23 }, // 139 0x8b
    .{ .code = 0x007fffdd, .bits = 23 }, // 140 0x8c
    .{ .code = 0x007fffde, .bits = 23 }, // 141 0x8d
    .{ .code = 0x00ffffeb, .bits = 24 }, // 142 0x8e
    .{ .code = 0x007fffdf, .bits = 23 }, // 143 0x8f
    .{ .code = 0x00ffffec, .bits = 24 }, // 144 0x90
    .{ .code = 0x00ffffed, .bits = 24 }, // 145 0x91
    .{ .code = 0x003fffd7, .bits = 22 }, // 146 0x92
    .{ .code = 0x007fffe0, .bits = 23 }, // 147 0x93
    .{ .code = 0x00ffffee, .bits = 24 }, // 148 0x94
    .{ .code = 0x007fffe1, .bits = 23 }, // 149 0x95
    .{ .code = 0x007fffe2, .bits = 23 }, // 150 0x96
    .{ .code = 0x007fffe3, .bits = 23 }, // 151 0x97
    .{ .code = 0x007fffe4, .bits = 23 }, // 152 0x98
    .{ .code = 0x001fffdc, .bits = 21 }, // 153 0x99
    .{ .code = 0x003fffd8, .bits = 22 }, // 154 0x9a
    .{ .code = 0x007fffe5, .bits = 23 }, // 155 0x9b
    .{ .code = 0x003fffd9, .bits = 22 }, // 156 0x9c
    .{ .code = 0x007fffe6, .bits = 23 }, // 157 0x9d
    .{ .code = 0x007fffe7, .bits = 23 }, // 158 0x9e
    .{ .code = 0x00ffffef, .bits = 24 }, // 159 0x9f
    .{ .code = 0x003fffda, .bits = 22 }, // 160 0xa0
    .{ .code = 0x001fffdd, .bits = 21 }, // 161 0xa1
    .{ .code = 0x000fffe9, .bits = 20 }, // 162 0xa2
    .{ .code = 0x003fffdb, .bits = 22 }, // 163 0xa3
    .{ .code = 0x003fffdc, .bits = 22 }, // 164 0xa4
    .{ .code = 0x007fffe8, .bits = 23 }, // 165 0xa5
    .{ .code = 0x007fffe9, .bits = 23 }, // 166 0xa6
    .{ .code = 0x001fffde, .bits = 21 }, // 167 0xa7
    .{ .code = 0x007fffea, .bits = 23 }, // 168 0xa8
    .{ .code = 0x003fffdd, .bits = 22 }, // 169 0xa9
    .{ .code = 0x003fffde, .bits = 22 }, // 170 0xaa
    .{ .code = 0x00fffff0, .bits = 24 }, // 171 0xab
    .{ .code = 0x001fffdf, .bits = 21 }, // 172 0xac
    .{ .code = 0x003fffdf, .bits = 22 }, // 173 0xad
    .{ .code = 0x007fffeb, .bits = 23 }, // 174 0xae
    .{ .code = 0x007fffec, .bits = 23 }, // 175 0xaf
    .{ .code = 0x001fffe0, .bits = 21 }, // 176 0xb0
    .{ .code = 0x001fffe1, .bits = 21 }, // 177 0xb1
    .{ .code = 0x003fffe0, .bits = 22 }, // 178 0xb2
    .{ .code = 0x001fffe2, .bits = 21 }, // 179 0xb3
    .{ .code = 0x007fffed, .bits = 23 }, // 180 0xb4
    .{ .code = 0x003fffe1, .bits = 22 }, // 181 0xb5
    .{ .code = 0x007fffee, .bits = 23 }, // 182 0xb6
    .{ .code = 0x007fffef, .bits = 23 }, // 183 0xb7
    .{ .code = 0x000fffea, .bits = 20 }, // 184 0xb8
    .{ .code = 0x003fffe2, .bits = 22 }, // 185 0xb9
    .{ .code = 0x003fffe3, .bits = 22 }, // 186 0xba
    .{ .code = 0x003fffe4, .bits = 22 }, // 187 0xbb
    .{ .code = 0x007ffff0, .bits = 23 }, // 188 0xbc
    .{ .code = 0x003fffe5, .bits = 22 }, // 189 0xbd
    .{ .code = 0x003fffe6, .bits = 22 }, // 190 0xbe
    .{ .code = 0x007ffff1, .bits = 23 }, // 191 0xbf
    .{ .code = 0x03ffffe0, .bits = 26 }, // 192 0xc0
    .{ .code = 0x03ffffe1, .bits = 26 }, // 193 0xc1
    .{ .code = 0x000fffeb, .bits = 20 }, // 194 0xc2
    .{ .code = 0x0007fff1, .bits = 19 }, // 195 0xc3
    .{ .code = 0x003fffe7, .bits = 22 }, // 196 0xc4
    .{ .code = 0x007ffff2, .bits = 23 }, // 197 0xc5
    .{ .code = 0x003fffe8, .bits = 22 }, // 198 0xc6
    .{ .code = 0x01ffffec, .bits = 25 }, // 199 0xc7
    .{ .code = 0x03ffffe2, .bits = 26 }, // 200 0xc8
    .{ .code = 0x03ffffe3, .bits = 26 }, // 201 0xc9
    .{ .code = 0x03ffffe4, .bits = 26 }, // 202 0xca
    .{ .code = 0x07ffffde, .bits = 27 }, // 203 0xcb
    .{ .code = 0x07ffffdf, .bits = 27 }, // 204 0xcc
    .{ .code = 0x03ffffe5, .bits = 26 }, // 205 0xcd
    .{ .code = 0x00fffff1, .bits = 24 }, // 206 0xce
    .{ .code = 0x01ffffed, .bits = 25 }, // 207 0xcf
    .{ .code = 0x0007fff2, .bits = 19 }, // 208 0xd0
    .{ .code = 0x001fffe3, .bits = 21 }, // 209 0xd1
    .{ .code = 0x03ffffe6, .bits = 26 }, // 210 0xd2
    .{ .code = 0x07ffffe0, .bits = 27 }, // 211 0xd3
    .{ .code = 0x07ffffe1, .bits = 27 }, // 212 0xd4
    .{ .code = 0x03ffffe7, .bits = 26 }, // 213 0xd5
    .{ .code = 0x07ffffe2, .bits = 27 }, // 214 0xd6
    .{ .code = 0x00fffff2, .bits = 24 }, // 215 0xd7
    .{ .code = 0x001fffe4, .bits = 21 }, // 216 0xd8
    .{ .code = 0x001fffe5, .bits = 21 }, // 217 0xd9
    .{ .code = 0x03ffffe8, .bits = 26 }, // 218 0xda
    .{ .code = 0x03ffffe9, .bits = 26 }, // 219 0xdb
    .{ .code = 0x0ffffffd, .bits = 28 }, // 220 0xdc
    .{ .code = 0x07ffffe3, .bits = 27 }, // 221 0xdd
    .{ .code = 0x07ffffe4, .bits = 27 }, // 222 0xde
    .{ .code = 0x07ffffe5, .bits = 27 }, // 223 0xdf
    .{ .code = 0x000fffec, .bits = 20 }, // 224 0xe0
    .{ .code = 0x00fffff3, .bits = 24 }, // 225 0xe1
    .{ .code = 0x000fffed, .bits = 20 }, // 226 0xe2
    .{ .code = 0x001fffe6, .bits = 21 }, // 227 0xe3
    .{ .code = 0x003fffe9, .bits = 22 }, // 228 0xe4
    .{ .code = 0x001fffe7, .bits = 21 }, // 229 0xe5
    .{ .code = 0x001fffe8, .bits = 21 }, // 230 0xe6
    .{ .code = 0x007ffff3, .bits = 23 }, // 231 0xe7
    .{ .code = 0x003fffea, .bits = 22 }, // 232 0xe8
    .{ .code = 0x003fffeb, .bits = 22 }, // 233 0xe9
    .{ .code = 0x01ffffee, .bits = 25 }, // 234 0xea
    .{ .code = 0x01ffffef, .bits = 25 }, // 235 0xeb
    .{ .code = 0x00fffff4, .bits = 24 }, // 236 0xec
    .{ .code = 0x00fffff5, .bits = 24 }, // 237 0xed
    .{ .code = 0x03ffffea, .bits = 26 }, // 238 0xee
    .{ .code = 0x007ffff4, .bits = 23 }, // 239 0xef
    .{ .code = 0x03ffffeb, .bits = 26 }, // 240 0xf0
    .{ .code = 0x07ffffe6, .bits = 27 }, // 241 0xf1
    .{ .code = 0x03ffffec, .bits = 26 }, // 242 0xf2
    .{ .code = 0x03ffffed, .bits = 26 }, // 243 0xf3
    .{ .code = 0x07ffffe7, .bits = 27 }, // 244 0xf4
    .{ .code = 0x07ffffe8, .bits = 27 }, // 245 0xf5
    .{ .code = 0x07ffffe9, .bits = 27 }, // 246 0xf6
    .{ .code = 0x07ffffea, .bits = 27 }, // 247 0xf7
    .{ .code = 0x07ffffeb, .bits = 27 }, // 248 0xf8
    .{ .code = 0x0ffffffe, .bits = 28 }, // 249 0xf9
    .{ .code = 0x07ffffec, .bits = 27 }, // 250 0xfa
    .{ .code = 0x07ffffed, .bits = 27 }, // 251 0xfb
    .{ .code = 0x07ffffee, .bits = 27 }, // 252 0xfc
    .{ .code = 0x07ffffef, .bits = 27 }, // 253 0xfd
    .{ .code = 0x07fffff0, .bits = 27 }, // 254 0xfe
    .{ .code = 0x03ffffee, .bits = 26 }, // 255 0xff
    .{ .code = 0x3fffffff, .bits = 30 }, // 256 EOS
};

comptime {
    @setEvalBranchQuota(20000);
    assert(codes.len == eos + 1);
    assert(codes[eos].bits == bits_max);
    for (codes) |entry| {
        assert(entry.bits >= bits_min);
        assert(entry.bits <= bits_max);
        // The code must fit the length it claims, or every table built from it
        // silently aliases a shorter one.
        assert(entry.code < (@as(u32, 1) << entry.bits));
    }
}
