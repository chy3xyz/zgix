---
title: Installation
sidebar_label: Installation
description: Build zgix from source with Zig 0.17, or activate the devenv shell for the pinned toolchain.
---

# Requirements

- **Zig 0.17.** The tree is pinned and CI-tested against it.

With [devenv](https://devenv.sh), `.envrc` activates the same shell
automatically on `cd`; otherwise enter it by hand:

```sh
devenv shell        # zig 0.17, zls, kcov
```

# Build

```sh
git clone https://github.com/chy3xyz/zgix
cd zgix
zig build -Doptimize=ReleaseSafe
```

The binary lands at `zig-out/bin/zgix`. Plain `zig build` produces a Debug
binary — fine for developing zgix, but quote numbers only from a
`-Doptimize=ReleaseFast` or `ReleaseSafe` build.

Useful build targets:

```sh
zig build                 # zig-out/bin/zgix (Debug)
zig build ci              # the per-change gate: tests + lint + simulation + smoke
zig build test            # unit tests
zig build sim -- 0 500    # deterministic simulator: [seed] [iterations]
zig build smoke           # live gate: the real binary against a real origin
zig build schema          # emit zig-out/config.schema.json
```

# Check it runs

```sh
zgix --version      # print the version (-V)
zgix --help         # usage summary (-h)
```

A release build prints its bare version, e.g. `zgix 0.9.0`; a build from
source after a release adds what distinguishes it,
`zgix 0.9.0 (v0.9.0-5-gabc1234)`, and `-dirty` when the tree had uncommitted
changes — so the version in a bug report identifies the exact build.

# Prebuilt binaries

There is no release channel yet: build from source. A one-line installer
(`curl -fsSL https://zgix.click/install.sh | sh`) ships with the first
release.
