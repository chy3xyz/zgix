---
title: HTTP/3 (experimental)
sidebar_label: HTTP/3
description: The experimental QUIC listener — h3_listeners, route tables over QUIC, streaming relays, deadlines, Alt-Svc advertisement and interop checks.
---

An `h3_listeners` entry binds a UDP socket, terminates QUIC-TLS, and proxies
each request over plaintext HTTP/1.1 to the cluster its route table selects:

```json
"h3_listeners": [
    {
        "bind": "0.0.0.0:4443",
        "routes": [
            { "host": "api.example.com", "prefix": "/api", "cluster": "api" },
            { "prefix": "/", "cluster": "origin" }
        ],
        "tls": {
            "cert": "/etc/zgix/fullchain.pem",
            "key": "/etc/zgix/key.pem"
        },
        "max_connections": 64,
        "max_response_bytes": 65536
    }
]
```

`"cluster": "name"` remains sugar for a single catch-all route. The table is
the HTTP/1.1 listener's routing, every dimension included: a host scope, an
optional `header` predicate (`equals` or `present`), and the longest path
prefix that respects segment boundaries — a conjunction, matched
most-specific-first (host, then header, then prefix). A request nothing
matches is answered `404`, the `h3_no_route` verdict. A route may set
`access_log: false` to drop its requests from the log only — counters and
admission stay.

QUIC has no plaintext mode, so `tls` is required. The process presents one
identity: two HTTP/3 listeners naming different certificate paths are
refused at load, and `--check` reads the same files, so a missing
certificate is a startup error that names it.

# The upstream leg

The upstream leg is HTTP/1.1 — plaintext, or TLS when the selected cluster
carries a `tls` block — keep-alive pooled: a fully framed response that does
not announce `Connection: close` parks its connection for the endpoint's
next request (one parked connection per endpoint, idle-reaped after 30 s).
A parked connection the origin silently closed fails its next exchange with
a 502, never retried — the request may not be idempotent. A TLS dial runs
the same client engine as the TCP path, with `verify`, the CA bundle,
`server_name` and optional client certificate meaning one thing on both
protocols; a parked TLS connection checks out with its session and never
pays a second handshake.

Requests and responses both stream: heads relay the moment they parse, body
chunks relay as they arrive, and `Content-Length`, `chunked` (decoded
incrementally) and close-delimited bodies all ride the one path. The
exchange is full duplex — an origin that answers early starts relaying
while the upload is still streaming.

# Limits and deadlines

Each response body is capped at `max_response_bytes` (64 KiB default,
configurable up to 16 MiB): a `Content-Length` past the cap is refused
before the head goes out; a chunked or close-delimited body that crosses it
mid-stream is cut with a stream reset.

`max_connections` is the listener's memory knob — each session slot embeds a
fixed 256 KiB arena. The default is 64 (about 16 MiB per listener), and the
loader caps the value at 1024.

One exchange carries two deadlines and expires on whichever comes first:

- `timeouts.h3_exchange_ms` (default 10 s, `0` disables) is the absolute
  budget from the exchange's begin — dial, send and receive window across
  the streamed response. A leg that outlives it is answered `504`, or, after
  the head went out, its stream is reset and recorded as `bad_gateway`.
- `timeouts.h3_exchange_idle_ms` (default `0`, off) is the idle variant: any
  application progress in either direction resets it, so a stream that keeps
  moving (SSE, a deliberate drip) is never killed by the absolute budget its
  longevity would outrun. Set 15000–30000 for SSE endpoints.

# What it answers itself

The answers the listener writes itself can wear configured pages:

```json
"h3_listeners": [
    {
        "bind": "0.0.0.0:4443",
        "routes": [ { "prefix": "/", "cluster": "origin" } ],
        "tls": { "cert": "/etc/zgix/fullchain.pem", "key": "/etc/zgix/key.pem" },
        "error_pages": {
            "no_route": "friendly-404",
            "bad_gateway": "origin-down",
            "gateway_timeout": "origin-slow"
        }
    }
]
```

Each value names a body from the global `bodies` table; absent keys keep the
built-in text. The h3 answer writes its own HEADERS, so only the page's body
crosses the seam; the status the family wears (404/502/504) is unchanged.

# Observing it

This path is deliberately narrower than the HTTP/1.1 listener — no filters,
rate limits or connection limits — but it is observed like the TCP path. An
h3 request earns one access-log line (the same `kind:"http"` record the TCP
listener writes), and every request lands in exactly one global verdict
bucket, rendered as the `zgix_h3_*` family:

| counter | meaning |
|---|---|
| `zgix_h3_requests` | requests the listener accepted |
| `zgix_h3_responses` | exchanges answered 2xx–5xx from an origin |
| `zgix_h3_bad_gateway` | dial failed, origin reset, or malformed origin data |
| `zgix_h3_gateway_timeout` | the exchange outlived `h3_exchange_ms` before the head |
| `zgix_h3_shed_busy` | refused because `max_connections` was full |
| `zgix_h3_no_route` | no route matched — the mistyped-host operational signal |

plus session-open/close counters, and after the labeled breakdown one row
per configured h3 listener — live sessions, cumulative requests and relayed
responses, and the parked keep-alive pool, each labeled by the listener's
`bind`.

# Advertising the UDP port

Until a client trusts the deployment, an `http` listener can advertise the
UDP port per listener with an `Alt-Svc` value (RFC 7838), sent **verbatim**
on every proxied final response head:

```json
{ "bind": "0.0.0.0:443", "http": { "cluster": "origin",
  "h3_advertise": "h3=\":4443\"; ma=3600" } }
```

The value must be 1–128 bytes and the operator writes the full field content
(`ma=` included), since what sits in front of the socket decides whether the
announcement is true.

For a scripted interop check, `scripts/h3-interop-client.py` is a minimal
aioquic client pinned to an IPv4 socket — aioquic's default dual-stack path
can look exactly like a server-side hang on some hosts:

```sh
pip install aioquic            # any venv
python3 scripts/h3-interop-client.py 4443
# -> STATUS 200 / BODY ...
```

See [Verify it works](/01-getting-started/verify.md) for the client
side and [Metrics](/03-reference/metrics.md) for the full `zgix_h3_*`
list.
