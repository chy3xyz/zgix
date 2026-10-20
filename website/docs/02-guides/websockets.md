---
title: WebSockets and tunnelled upgrades
sidebar_label: WebSockets
description: Carrying WebSocket upgrades through zgix — the upgrades allowlist, the separate tunnel pool, and the deadlines that bound a tunnel's life.
---

By default any request carrying `Upgrade` is answered `501`, the same as
`CONNECT`. An `http` listener opts in by naming what it will carry:

```json
"listeners": [
    { "bind": "0.0.0.0:80", "http": { "cluster": "web",
      "upgrades": { "websocket": true } } }
],
"limits": { "tunnels": 512 }
```

zgix does not speak WebSocket. It forwards the handshake, recognises the
origin's `101 Switching Protocols`, and from that point relays bytes both
ways until one side closes — the same byte relay an `l4` listener runs.
Routing, filters and health checks apply to the handshake exactly as they do
to any request; after `101` the connection is opaque, so filters, routes and
header rules stop applying.

One flag per protocol rather than a list of tokens: the vocabulary lives in
the schema, and an editor rejects `"h2c"` before the loader does — `h2c`
would carry HTTP/2 to an origin zgix cannot parse, and is refused by name at
load. Omitting the block, writing `{}`, or setting every flag `false` all
mean *allow none and reserve nothing*.

# The tunnel pool

`limits.tunnels` is **required** when any upgrade is allowed, and has no
default: how many long-lived sessions the origins should carry is a capacity
decision zgix cannot infer from a connection count. It may not exceed
`conn_slots`.

The pool is separate from the buffers ordinary traffic uses. Every other
pool is sized for concurrent *activity* — an idle keep-alive connection
holds no head buffer — but a tunnel pins its relay buffer for its whole
life. A separate pool means tunnels cannot starve HTTP. Each tunnel costs
one relay pair — 32,808 bytes at the 16 KiB default, 33,330 when a `tls`
cluster widens both halves — printed in the startup banner.

When the pool is full the upgrade is answered `503` **before** the handshake
reaches the origin, so a refusal costs no backend connection.
`zgix_l7_shed_tunnels` counts those refusals; `zgix_tunnels_established`
counts the sessions that came of the ones allowed through.

Three more consequences ride on the pool:

- `timeouts.tunnel_ms` replaces the other deadlines once a connection
  becomes a tunnel — default one hour, floor one second, ceiling one day,
  and no `0` for "no cap", because a tunnel holds a pool slot for its whole
  life. A WebSocket's own keepalive is application-level ping/pong that zgix
  cannot see through opaque bytes.
- The upgraded upstream connection leaves the keep-alive pool and is never
  reused, but still counts against the cluster's `max_inflight` for as long
  as the tunnel lives.
- Through a `tls` cluster the tunnel also holds that connection's TLS
  engine for its whole life: `upstream_slots` is the ceiling on concurrent
  TLS tunnels, and exhausting it sheds fresh TLS dials, never an established
  tunnel.

# Draining and the access log

A draining process refuses new upgrades with `503` and cuts live ones at
`drain_deadline_ms` — or five seconds when none is set, since a WebSocket
has no message boundary to finish at. `zgix_tunnels_drained` counts the ones
cut.

The access log writes one line when the tunnel closes: `kind` `http`,
`status` `101`, the request facts that opened it, and `bytes_in`/`bytes_out`
for the whole session — so a WebSocket's lifetime cost appears in the same
sink as every other exchange.
