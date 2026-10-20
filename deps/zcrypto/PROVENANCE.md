# Vendored: zcrypto

- Upstream: https://github.com/ghostkellz/zcrypto
- Tag: v1.0.7 (commit 1863817757c9c8ce37880c752a63ac7e9d1e3dda)
- Version: 1.0.7
- Vendored: 2026-10-18

zcrypto is a dependency of the zquic snapshot under `vendor/zquic`
(zhttp v0.22.0's copy). Its `build.zig.zon` declares an optional `zsync`
URL dependency; zgix builds zcrypto with `enable_async = false`, so
`src/async_crypto.zig` is never imported and zsync is not required.

zgix does not build zcrypto into the proxy. It is compiled only by the
experimental `zig build h3-check` step, with feature switches supplied by
zgix's own `build.zig` (TLS and hardware acceleration on; post-quantum,
VPN, blockchain, WASM, enterprise, ZKP, async, TPM, PKCS#11 and Secure
Enclave off).

License: MIT (see LICENSE in this directory).
