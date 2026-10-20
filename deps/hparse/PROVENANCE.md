# Vendored: hparse

- Upstream: https://github.com/chy3xyz/hparse (private monorepo path dep)
- Vendored: as part of the "all-local path dependencies" migration.

## Local patches

1. `src/root.zig` (`VectorInt`): `std.meta.Int(.unsigned, vec_size)` →
   `std.math.IntFittingRange(0, (1 << vec_size) - 1)` — Zig 0.17 removed
   `std.meta.Int`. Only reachable on x86_64-family vector paths (aarch64
   takes the NEON branch), which is why native arm64 builds never saw it.
