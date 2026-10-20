---
title: TLS to the origin
sidebar_label: Upstream TLS
description: Originating TLS 1.3 from zgix to your backends — server_name, verification, CA bundles, mTLS, and how the pooled leg behaves.
---

A cluster with a `tls` block dials its endpoints over TLS 1.3 instead of
plaintext. It is the same key as a listener's, read from position: here it
originates, there it terminates.

```json
"clusters": {
    "api": {
        "endpoints": ["10.0.0.1:8443"],
        "tls": {
            "server_name": "api.internal.example",
            "ca_file": "/etc/zgix/origin-ca.pem",
            "client_cert": "/etc/zgix/zgix.pem",
            "client_key": "/etc/zgix/zgix.key"
        }
    }
}
```

| field | required | meaning |
|---|---|---|
| `server_name` | yes | The SNI name sent to the origin and the name its certificate must match. It is never inferred from an endpoint: `10.0.0.1:8443` is an address, not an identity. |
| `ca_file` | when `verify` is true | PEM bundle of trust anchors. |
| `client_cert` | with `client_key` | PEM client chain, leaf first, presented when the origin asks for a client certificate (mTLS). |
| `client_key` | with `client_cert` | The client chain's PEM private key. |
| `verify` | no; default `true` | Verify the origin's chain to `ca_file` and its leaf against `server_name` (RFC 9525). |

The trust anchors are exactly `ca_file`; there is no system CA store. A
deployment that wants the host's bundle names it explicitly.

`verify: false` still encrypts but authenticates nothing — any peer able to
intercept the TCP stream is accepted, and `ca_file` is ignored even when
present. Use it only on a controlled network where another layer
authenticates the origin; it never means "verify nothing" on a public link.
`server_name` remains required and is still sent as SNI.

# Files and reloads

The files this block names are read once at startup: a missing or unusable
file stops the process with an error naming the path, before a port is
taken, rather than failing under traffic. `SIGHUP` does not re-read them —
it rotates listener certificates only — so changing a cluster's CA or client
pair needs a restart. The client key follows the listener's rule (ECDSA
P-256/P-384) because both directions go through one credential loader and
the handshake runs on the event loop.

# How the leg behaves

- TLS upstream connections park and reuse like plaintext ones, and a reuse
  skips the handshake entirely. A parked session the origin closed while
  idle is discovered on first use, and that early failure takes the one free
  replay on a fresh dial: the request head is re-encrypted under the new
  session's keys. Once any body chunk has been pumped, the try is no longer
  reconstructible and the failure reaches the client.
- An `http` health check on a TLS cluster completes its own handshake and
  probes over it; a `tcp` check stays a plain connect, since it only wants
  the SYN/ACK.
- An `Upgrade` may cross this hop: the tunnel relay encrypts and decrypts
  both ends independently, and a half-close is announced with `close_notify`
  before the write half shuts down. See [WebSockets](websockets.md) for the
  tunnel pool consequences.
- Request bodies forward under the ordinary cap and framing rules: a
  declared over-cap body is still `413`, and a chunked body streams through
  the same relay discipline a plaintext origin uses.

# What cannot reach a TLS cluster

An `l4` listener routing to a `tls` cluster is refused at load: the relay is
transparent and never originates TLS, so the origin would receive the
client's bytes with no handshake in front of them. That refusal is
load-time rather than best-effort — a config that cannot mean what it says
stops with an error naming the rule.
