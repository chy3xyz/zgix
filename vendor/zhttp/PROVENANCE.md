# Vendored: zhttp

- Upstream: https://github.com/chy3xyz/zhttp
- Commit: cf8696f77fd9b6c7dc8b140e33d6cb9c2db9c674 (2026-10-18, v0.22.0)
- Version: 0.22.0 (build.zig.zon)
- Vendored: 2026-10-18

zgix compiles `src/h2/root.zig` as the `zhttp-h2` module: the frame
codec, HPACK/Huffman, settings, flow-control and stream-registry types.
The experimental `h3-check` step additionally compiles
`src/openssl_c.zig`, `src/h3/native/qtls.zig` and
`src/h3/native/qpack.zig` — the hand-written OpenSSL bindings, the
`SSL_set_quic_tls_cbs` bridge and the RFC 9204 QPACK codec — against the
`libssl` artifact of the vendored OpenSSL 3.5.7. `src/qpack_export.zig`
is zgix's module-root wrapper. One local patch: `qpack.zig` imports the
Huffman codec as `@import("zhttp-h2").huffman` rather than by relative
path, because zgix compiles this tree as two modules (`zhttp-h2` for the
HTTP/2 codec, `qpack` for HTTP/3) and Zig allows a file in only one
module. The h2 module re-exports `huffman` from its root. The rest of the
tree is kept for provenance and future reuse (client h2, compression and
rate-limit references) and is not built.

**Trimmed snapshot:** upstream v0.22.0 also vendors `vendor/zquic` (2.8 MiB)
and names it as a path dependency in `build.zig.zon`. That tree is omitted
here — nothing zgix builds reaches it, and the h2 codec has no dependency
on it. Building the vendored package directly would therefore need that
tree restored; zgix never does, it creates the `zhttp-h2` module against
`src/h2/root.zig` directly in its own `build.zig`.

Between b322bcf (the previously vendored commit) and this one, `src/h2`
is unchanged; the upgrade is the release/version bump and HTTP/3 work.
The API zgix consumes is identical, so no adaptation was needed beyond
the snapshot refresh.

Upstream carries no LICENSE file at this commit (its README points at one
that is not in the repository). Vendoring here is authorized by the
upstream maintainer; add a license upstream before redistributing this
copy.

## Local patches

- 2026-10-19, dynamic-QPACK wiring (zgix): `h3/native/qpack.zig` gains
  `Encoder.consumePendingInstructions(n)`, which drops the first n staged
  encoder-stream bytes so a caller that short-writes `pendingInstructions()`
  across several transport sends can resume the flush without re-sending
  instructions the peer already applied. No other upstream source changed;
  `src/qpack_export.zig` (zgix's own module-root wrapper, not upstream
  source) additionally re-exports the instruction-level names
  (`applyEncoderInstruction`, `scanDecoderInstruction`,
  `writeDecoderInstruction`, their enums/limits, `peekRequiredInsertCount`,
  `DynamicTable`, `static_table`, the scan enums) that zgix's HTTP/3
  session now consumes.
