---
layout: home
title: zgix documentation
description: How to run, configure and operate zgix — a zero-allocation L4/L7 edge proxy with experimental HTTP/3.
hero:
  name: zgix
  text: A zero-allocation L4/L7 edge proxy, in Zig.
  tagline: All memory reserved at startup, every limit a compile-time constant, exhaustion sheds load at a defined rung of the ladder. HTTP/3 over QUIC is experimental but observed like everything else.
  actions:
    - theme: brand
      text: Get started
      link: 01-getting-started/
    - theme: alt
      text: 中文文档
      link: https://zgix.click/docs/zh/
features:
  - title: Zero-allocation serving
    details: The request path allocates nothing. Pools are sized at startup from compile-time constants and printed in the banner, asserted against RLIMIT_NOFILE before a port is bound.
  - title: HTTP/3 over QUIC
    details: Experimental h3_listeners terminate QUIC-TLS and proxy over a pooled HTTP/1.1 leg — verdict counters and access-log records included.
  - title: SNI multi-tenant TLS
    details: Terminate TLS 1.3 with up to 16 certificate pairs per listener, or relay blind by SNI. One :443 fronts many TLS services.
  - title: WebSocket tunnels
    details: An opt-in upgrade relay with its own bounded pool, so long-lived sessions never starve HTTP of buffers.
  - title: Declarative JSON config
    details: One file, unknown fields refused, --check prices the config before anything binds. Replaced by process handoff, never reloaded.
  - title: Prometheus-grade observability
    details: zgix_* counter families, per-endpoint health, RED histograms, a JSON access log, a bounded log tail on the scrape, and a bundled control panel.
---

# Quick start

Build from source (Zig 0.17), then run the binary against one JSON config:

```sh
git clone https://github.com/chy3xyz/zgix
cd zgix
zig build -Doptimize=ReleaseSafe
```

The binary takes exactly one argument, the path to a JSON config. `--check`
loads it, prices every pool and measures the fd demand — everything a start
does up to the banner — then exits without binding a port:

```sh
zgix --check config.json   # validate and price it, bind nothing
zgix config.json           # start the proxy
```

A minimal config — one L4 listener forwarding to one origin — is the whole
file; every other block has defaults:

```json
{
    "listeners": [
        { "bind": "127.0.0.1:8080", "l4": { "cluster": "origin" } }
    ],
    "clusters": {
        "origin": { "endpoints": ["127.0.0.1:9000"] }
    }
}
```

Start in [Getting started](01-getting-started/), browse the
[guides](02-guides/), or jump to the [reference](03-reference/).

::: warning
zgix is experimental software. HTTP/3 in particular is a deliberately narrow
path — no filters, no rate limits — and its counters carry an `h3_` prefix so
you can watch it independently of the TCP path.
:::
