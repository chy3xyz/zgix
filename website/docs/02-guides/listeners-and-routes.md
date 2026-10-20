---
title: Listeners and routes
sidebar_label: Listeners and routes
description: How zgix accepts traffic — l4 relays and http reverse proxies, host/header/prefix route tables, and multi-tenant SNI routing.
---

A listener binds an address and speaks one protocol, named by the key its
settings live under: `l4` relays bytes without inspecting them, `http` runs
the HTTP/1.1 reverse proxy. Exactly one of the two is required — there is no
default.

```json
"listeners": [
    { "bind": "0.0.0.0:80",   "http": { "cluster": "web" } },
    { "bind": "0.0.0.0:5432", "l4":   { "cluster": "postgres" } }
]
```

`bind` and `tls` sit outside the protocol body because they apply to both.
Everything else lives inside the body, so a setting that only makes sense for
one protocol cannot be written for the other — `max_body_bytes` on an `l4`
listener is a rejected config, not a key that silently does nothing.

Each listener is bound with `SO_REUSEPORT`: several processes on one port is
the supported way to use more than one core and to
[replace a running instance](/04-deployment/systemd.md). Every
connection, accepted and upstream alike, gets `TCP_NODELAY` — Nagle plus
delayed ACK costs a reused keep-alive connection a 40 ms stall. A `bind` may
also be a `unix:` socket path; see the [reference](/03-reference/config.md).

# HTTP route tables

`"cluster": "name"` is sugar for a single catch-all route. An `http`
listener can instead carry a route table, matched **longest-prefix within
the matching host**:

```json
{
    "bind": "0.0.0.0:80",
    "http": {
        "routes": [
            { "host": "api.example.com", "prefix": "/v2", "cluster": "api-v2" },
            { "host": "api.example.com", "prefix": "/",   "cluster": "api" },
            { "prefix": "/static",                        "cluster": "cdn" },
            { "prefix": "/",                              "cluster": "web" }
        ]
    }
}
```

A route with no `host` matches any host, and a host-specific route always
beats an any-host one. Matching uses the **canonical** path — percent-escapes
decoded, dot-segments collapsed — and the origin receives that same canonical
path, so the router and the backend cannot disagree about which resource was
named. Structure-changing escapes (`%2F`, `%00`, truncated escapes) are
rejected with `400`. A request nothing matches is answered `404`.

# Header predicates

A route may also match a header — `present` for any value, or `equals` for
one. This is how a pinned canary is written: percentage canaries are
[endpoint weights](/03-reference/config.md), but a pinned canary for a
test account or an internal gateway's header is a route:

```json
"routes": [
    { "header": { "name": "X-Canary", "present": true },
      "prefix": "/", "cluster": "next" },
    { "prefix": "/", "cluster": "stable" }
]
```

**Host, then header, then prefix.** Every key a route states must hold, and
where several routes match, the most specific wins in that order. The table
is sorted once at startup, so routes can be written in any sequence. Config
order decides exactly one case: two routes sharing a host and a prefix but
naming *different* headers are equally specific, and a request carrying both
headers matches both — the one written first wins.

Two things to know before relying on a header route:

- A request that gains or loses the header **moves to a different cluster**,
  so a `hash` pick holds within each cluster but not across the change.
- The header is a routing key *and* is forwarded: the origin sees it and can
  log which side served the request.

A route may also carry `"access_log": false`, which suppresses the
access-log line for its requests — nginx's `access_log off` at a location.
Counters, metrics, admission and the traffic itself are unchanged.

# Odd requests

- `CONNECT` and `TRACE` are answered `501` and never reach a backend —
  forward-proxy behaviour and the Cross-Site Tracing vector respectively.
- `OPTIONS` honours `Max-Forwards`: at `0` zgix answers `200` with an
  `Allow` describing itself; above `0` the request forwards with the value
  decremented.
- An absolute-form request target (`GET http://api.example.com/v2/x`) is
  accepted per RFC 9112, and the target's authority **wins over the `Host`
  header** for routing, filtering, logging and what the origin receives.
  Only `http` and `https` targets are accepted; anything else is a `400`.

# Multi-tenant TLS: routing an `l4` listener by SNI

One `:443` can front several TLS services without terminating any of them.
Give the `l4` body a route table keyed on the server name, and zgix reads
that name out of the ClientHello and relays every byte onward unchanged:

```json
{
    "bind": "0.0.0.0:443",
    "l4": {
        "routes": [
            { "sni": "api.example.com", "cluster": "api" },
            { "sni": "grpc.example.com", "cluster": "grpc" },
            { "cluster": "fallback" }
        ]
    }
}
```

zgix holds no key material and runs no handshake: the backend completes the
TLS session exactly as it would without a proxy in the path, and zgix never
sees a plaintext byte. This is how you front a service whose certificate the
proxy must not be able to present.

A route with no `sni` is the catch-all — it answers any connection,
including one whose hello named nothing at all. Without a catch-all, a name
the table does not cover is closed. Matching is exact in both tables:
`api.example.com` matches that name and not `x.api.example.com`, and neither
table has wildcards.

Four counters report what the table did — `zgix_l4_sni_routed`,
`zgix_l4_sni_absent` (the client named nothing), `zgix_l4_sni_no_route`
(named something no route claims) and `zgix_l4_sni_invalid` (the opening
bytes were not a ClientHello). The hello must arrive in one TLS record,
which every real client sends; a fragmented first flight counts
`zgix_l4_sni_invalid` and is closed rather than reassembled inside a parser
that reads attacker-controlled bytes.

Two combinations are refused at load:

| config | why |
|---|---|
| `routes` beside this listener's own `tls` | terminating consumes the hello this reads; the two are different proxies |
| `limits.relay_buffer_bytes` below 16 KiB | the hello is staged in the relay buffer, and a modern one with post-quantum key shares runs past 2 KiB |

To terminate TLS instead — one or many certificate pairs per listener — see
[TLS certificates](tls-certificates.md).
