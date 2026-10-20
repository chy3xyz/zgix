# h2

![GitHub License](https://img.shields.io/github/license/zoxy-io/h2?color=orange)
![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/zoxy-io/h2/test-x86_64-linux.yml?label=x86_64-linux)
![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/zoxy-io/h2/test-aarch64-linux.yml?label=aarch64-linux)
![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/zoxy-io/h2/test-x86_64-windows.yml?label=x86_64-windows)
![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/zoxy-io/h2/test-macos.yml?label=macos)

HTTP/2 frame codec, HPACK, and field validation.

## Scope

* **RFC 9113 frame codec** — framing only, not the connection state machine.
* **RFC 7541 HPACK** — encoder, decoder, Huffman, static and dynamic tables.
* **RFC 9113 §8.2 and §8.3 message validation** — the octet rules for field
  names and values, and the pseudo-header rules that make a request or response
  well-formed. Between them they are the guard against request smuggling
  through an HTTP/1.1 downgrade. A check, never an enforcement: what to do
  about a malformed message is the consumer's decision, and the two consumers
  answer differently.

Out of scope, permanently: sockets, TLS, ALPN, flow control policy, stream
scheduling, and the connection state machine. Those differ per consumer and
stay in the consumer.

## Properties

* Never allocates — no `std.mem.Allocator` in the public API.
* Never copies where a slice will do.
* Caller-owned, caller-sized buffers, including HPACK's dynamic table.
* Zero dependencies beyond the Zig toolchain.
* Assertions ship by default, in every optimize mode. Roughly 350 of them, and
  several are the only check on an arithmetic relation. `-Dassertions=false`
  removes them for a consumer that has made that argument — see
  [`src/assert.zig`](src/assert.zig) for why this is not `std.debug.assert`.
* Bytes in, frames and header fields out — no reader, writer or `std.Io` in the
  seam. Its two consumers, [zoxy](https://github.com/zoxy-io/zoxy) (reverse
  proxy, libxev completion callbacks) and
  [zrk](https://github.com/zoxy-io/zrk) (load generator, zio green threads
  through `std.Io`), do not share a runtime, so a reader in a signature would
  exclude one of them. `zig build lint` enforces it.

## Usage

The receive path, end to end — a frame header, its payload, a field block spread
across CONTINUATION frames, HPACK, and the RFC 9113 §8 rules that decide whether
the result is a message at all:

```zig
const h2 = @import("h2");

var assembler: h2.frame.BlockAssembler = .init(&block_buffer, 16);
var decoder: h2.hpack.Decoder = .init(hpack_storage.table(), list_size_max);

// 1. The nine octets, and everything they can decide on their own.
const header = try h2.frame.Header.parse(wire[offset..]);
try header.validate(max_frame_size);

// 2. The payload, sliced by the length the header declared.
const payload = try h2.frame.payload.parse(header, body);

// 3. The CONTINUATION state machine: was this frame allowed to arrive?
const block = switch (try assembler.accept(header, &payload)) {
    .passthrough, .fragment => continue,
    .block => |complete| complete,
};

// 4. HPACK and the §8 rules, in one pass. The decoder is an iterator and the
//    validator is fed one field at a time, because a field's slices borrow
//    from `field_buffer` and the next field may reuse it.
var validator: h2.fields.MessageValidator = .init(.{ .kind = .request, .rules = .strict });
var iterator = decoder.iterate(&field_buffer, block.fragment);
while (try iterator.next()) |field| {
    try validator.field(&field);
    // ... field.name, field.value
}
try validator.finish();
```

[`example/receive.zig`](example/receive.zig) is the whole thing, including the
send path that produces the octets it reads back. It is a compiled, run program
rather than a snippet — `zig build example`, and `zig build ci` runs it — so a
usage example that stopped building fails the build instead of greeting the next
reader.

Nothing above allocates. Every buffer is caller-owned and caller-sized, and
every size traces to a setting or an RFC clause: `block_buffer`'s length *is*
the bound on a field block, which is what stops the CONTINUATION flood.

## Gates

```sh
zig build ci      # format check, tests, fuzz corpus, interop corpus, boundary lint
zig build ci -Doptimize=ReleaseFast                     # zoxy's build
zig build ci -Doptimize=ReleaseFast -Dassertions=false  # zrk's build
zig build bench   # decode/encode microbenchmarks (ReleaseFast)
zig build fuzz    # replay the fuzz corpus; --fuzz to actually fuzz
zig build corpus  # interoperability conformance against other implementations
zig build fmt-fix # reformat in place
zig build example # build and run the usage example above
```

CI runs `zig build ci` natively on each target, so the tests run rather than
merely cross-compile, and runs all three rows above. The release rows are not
redundant: `-Dassertions=false` in Debug removes the `if (!ok)` and nothing
else, so only a release mode tests that the checks are actually gone — and only
a release mode reaches the undefined behaviour that a `catch unreachable`
guarded by a removed assertion becomes.

## Style

[`docs/TIGER_STYLE.md`](docs/TIGER_STYLE.md) — zoxy's TigerStyle, plus the
deltas a shared library forces. [`CLAUDE.md`](CLAUDE.md) carries the same rules
as working instructions, including the review and benchmark gates.

## Context

* zoxy-io/zoxy#173 — HTTP/2 support in the proxy (slices #272 HPACK, #273 frame codec).
* zoxy-io/zrk#21 — HTTP/2 support in the load generator.
