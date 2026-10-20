---
title: Rate limiting and the WAF
sidebar_label: Rate limiting and WAF
description: Per-client token buckets, connection caps, and the listener-level literal denylist — the three admission controls of the HTTP path.
---

Three admission controls run on the `http` path, each opt-in and each with
its own counter so a refusal never blurs into an origin's answer.

# Rate limiting

A token bucket keyed by the client's IPv4 `/32` or IPv6 `/64` (the same
identity `client` filters and `source_ip` hashing use). Above the rate,
requests are answered `429` and the connection closes, because the body may
still be unread:

```json
"listeners": [
    { "bind": "0.0.0.0:443", "http": {
        "cluster": "api",
        "rate_limit": { "requests": 100, "window_ms": 1000, "burst": 200 } } }
],
"limits": { "rate_limit_entries": 4096 }
```

| field | meaning |
|---|---|
| `requests` | tokens refilled per `window_ms` |
| `window_ms` | refill window |
| `burst` | bucket capacity; optional, defaults to `requests`, must be at least `requests` |
| `limits.rate_limit_entries` | process-wide table slots (32 B each), **required** when any listener has a limit |

The table is fixed at load and probed at most eight slots deep — no
allocation per request and no unbounded scan. Keying is per address, not
per listener, so one client hitting two listeners shares a bucket. A table
with no free slot within the probe **fails open** and increments
`zgix_l7_rate_limit_full` — a rising count is the signal to widen
`rate_limit_entries`, not an outage. `zgix_l7_rate_limited` counts the
`429`s.

The bucket is consumed by any admitted request — including one a WAF rule
then refuses — and malformed or oversized requests are answered before this
check, so a bad actor cannot burn tokens on garbage.

# Connection limits

`conn_limit` caps how many connections one client identity holds at once.
Where the token bucket answers "too many requests", this answers "too many
sockets", and the two are independent:

```json
"listeners": [
    { "bind": "0.0.0.0:443", "http": {
        "cluster": "api",
        "conn_limit": { "max": 256 } } }
],
"limits": { "conn_limit_entries": 4096 }
```

A connection is counted at its **first admitted request**, not at accept —
after a PROXY protocol header is parsed is the first point a listener knows
the real client. Every request on a keep-alive connection shares that one
count. A request past `max` is answered `503`; an identity the table cannot
place within eight probes fails open and increments
`zgix_l7_conn_limit_full`, while `zgix_l7_conn_limited` counts the `503`s.

# WAF-lite: the literal denylist

A listener-level literal denylist, evaluated once per request before the
filter walk. A hit is answered with the configured status and never routed
or dialed; a filter `allow` cannot exempt it:

```json
"http": {
    "cluster": "api",
    "waf": { "deny": ["union select", "<script", "../"], "status": 403 }
}
```

- `deny` is 1..64 literals, each 1..256 bytes, matched ASCII
  case-insensitively against the canonical path, the raw query, and every
  header **value**.
- `status` is `403` by default and may be `400`, `403`, `404` or `429`.
- `zgix_l7_waf_blocked` counts hits.

It is deliberately head-only: no body inspection, no percent-decoding, no
regex, no Unicode folding, no provenance for a substring. Those are bypass
surfaces and false-positive surfaces at once — a benign `select` in a query
parameter is refused like an injection. Use it as one layer beside strict
request parsing, CIDR rules and rate limiting, not as a replacement for a
full WAF. Body scanning is not implemented.

For richer rules — `allow` lists, CIDR matches, header edits, rewrites, and
terminal `reject`/`redirect`/`respond` actions — use
`request_filters`; see the [config reference](/03-reference/config.md).
