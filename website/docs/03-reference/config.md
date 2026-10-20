---
title: Config overview
sidebar_label: Config overview
description: Every block a zgix config can carry — listeners, clusters, bodies, timeouts, limits, admin, access_log — and the authoritative JSON Schema.
---

Config is parsed once at startup and never reloaded; a change is a process
restart. Unknown fields are rejected.

The authoritative list of fields, enums and numeric bounds is the **JSON
Schema** — generated from the parser, emitted by `zig build schema` as
`zig-out/config.schema.json` and shipped as a release asset. It is rendered
field-by-field at [zgix.click/config](https://zgix.click/config/) for the
latest release. This page is the tour; the schema is the contract.

# The shape of the file

```json
{
    "listeners":      [],
    "h3_listeners":   [],
    "clusters":       {},
    "bodies":         {},
    "error_pages":    {},
    "timeouts":       {},
    "limits":         {},
    "admin":          {},
    "access_log":     {}
}
```

# `listeners` — what accepts traffic

Each entry binds an address and speaks exactly one protocol:

- `http` — the HTTP/1.1 reverse proxy: `cluster` or a `routes` table
  (host, optional header predicate, longest prefix), `request_filters`,
  `response_filters`, `upgrades`, `forwarded`, `rate_limit`, `conn_limit`,
  `waf`, `compress`, `max_body_bytes`, `keepalive_requests`,
  `h3_advertise`, `proxy_status`, `error_pages`.
- `l4` — the blind TCP relay: `cluster` or an SNI `routes` table,
  `proxy_protocol: { "mode": "require" }`.

`bind` and `tls` sit outside the protocol body and apply to both; `bind`
may be `unix:/abs/path.sock` with a `mode`. Every entry is bound with
`SO_REUSEPORT`.

# `h3_listeners` — experimental HTTP/3

A UDP socket that terminates QUIC-TLS and proxies over HTTP/1.1: `routes`
(the same table dimensions as `http`), `tls` (required — no SNI set, one
process identity), `max_connections`, `max_response_bytes`, `error_pages`.
Narrower than the TCP path: no filters, no rate limits.

# `clusters` — where traffic goes

A named set of endpoints plus how one is chosen:

- `endpoints`: `IP:port` strings or `{ "address": …, "weight": … }` objects
  (weights to 256; `0` drains), or `unix:` socket paths.
- `pick`: `"p2c"` (default, power-of-two-choices on in-flight work),
  `"rr"` (smooth weighted rotation), or
  `{ "policy": "hash", "key": "source_ip" | "header" | "cookie" }` for
  stickiness that keeps no table.
- `check`: active probes, `tcp` or `http` with `path`, `expect_status`,
  `fall`/`rise` counters.
- `passive_ejection`: eject an endpoint after `fall` consecutive failed
  requests, re-admit after `recovery_ms`. A `5xx` is **not** a failure.
- `max_inflight`: per-endpoint concurrent-work cap — the one limit that
  fails closed (503) instead of open.
- `tls`: originate TLS 1.3 to the origin (`server_name`, `ca_file`,
  `verify`, `client_cert`, `client_key`).
- `proxy_protocol: { "send": "v1" | "v2" }` — announce the client to the
  origin; only `l4` listeners may route to a sending cluster.

# `bodies` and `error_pages` — canned answers

Every status zgix sends itself is empty by default. `bodies` names content
once — `file` or `inline` plus a required `content_type` — and
`error_pages` maps the statuses zgix actually sends (`400`, `403`, `404`,
`408`, `413`, `414`, `429`, `431`, `501`, `502`, `503`, `504`) to a body.
Filter `respond` actions reference the same table. Bodies are read and
gzipped once at startup; changing one needs a restart.

# `timeouts` — the deadline ladder

Every field optional, the whole block optional:

| field | default | meaning |
|---|---|---|
| `connect_ms` | `5000` | per-try upstream connect budget |
| `head_ms` | derived | budget for one request head — what a slowloris meets (`408`) |
| `idle_ms` | `60000` | how long a connection may stay quiet |
| `drain_deadline_ms` | `0` | SIGTERM drain cap; `0` waits for the last connection |
| `max_lifetime_ms` | `0` | absolute connection-age cap; `0` disables |
| `request_ms` | `0` | cap on one L7 exchange, not refreshed by activity; `0` disables |
| `h3_exchange_ms` | `10000` | absolute budget on one h3 exchange; `0` disables |
| `h3_exchange_idle_ms` | `0` | idle variant, reset by progress; set 15000–30000 for SSE |
| `tunnel_ms` | `3600000` | a tunnel's whole life, 1 s to 1 day; `0` is not legal |
| `health_interval_ms` | `2000` | pause between health-probe sweeps |
| `loop_watchdog_ms` | absent | kill the process (exit 6) if the event loop stalls this long; off unless set |

`connect_ms` must be strictly below `head_ms`, which must be at or below
`idle_ms`, or the config is rejected — one timer per connection is re-based
down the ladder and never moves earlier once armed.

# `limits` — the pool sizes

The compiled constants are hard ceilings; this block sizes the actual pools
from 1 up to them:

```json
"limits": {
    "conn_slots": 4096,
    "relay_buffers": 4096,
    "upstream_slots": 4096,
    "head_buffers": 1024,
    "upstream_head_buffers": 512,
    "head_buffer_bytes": 16384,
    "rate_limit_entries": 4096,
    "conn_limit_entries": 4096,
    "tls_engines": 1024,
    "tunnels": 512
}
```

Defaults are lean (1386 conn slots, about 34 MiB of pools), sized to start
under a stock 4096 `RLIMIT_NOFILE`; the ceiling is 11457 of each. Two keys
are conditional: `tls_engines` is refused unless some listener terminates
TLS, and `tunnels` is **required** (no default exists) once any listener
names an `upgrades` allowlist. `head_buffers`/`upstream_head_buffers` bound
request heads in flight — idle connections hold none, so a keep-alive-heavy
deployment trades these down. `head_buffer_bytes` sizes every head buffer
and is therefore the largest head accepted (`414`/`431` beyond it), 1 KiB
to 1 MiB, default 8 KiB.

# `admin` and `access_log` — the observability blocks

`admin` binds the scrape endpoint (see [Access log and admin
panel](/02-guides/access-log-and-admin-panel.md)); `access_log` takes
`sink` `stdout` or `file`+`path`, plus optional `request_headers` /
`response_headers` lists.

# Validation

`zgix --check config.json` runs the whole loader — files opened, pools
priced, fd demand measured — and exits `0`/`1`/`2` (valid / wrong config /
right config, machine too small). Wire it into CI: a build agent with a
stock `RLIMIT_NOFILE` may accept `2` on a production-sized config and must
never accept `1`.
