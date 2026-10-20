---
title: TLS certificates
sidebar_label: TLS certificates
description: Terminate TLS 1.3 on zgix — single and SNI certificate sets, ECDSA keys, SIGHUP reloads, session resumption.
---

Add a `tls` block to a listener and it speaks TLS 1.3 instead of plaintext.
Its routes, cluster and filters are unchanged — the handshake runs as a
phase ahead of the protocol, so routing, filters, redirects and access logs
work exactly as they do in the clear.

```json
"listeners": [
    { "bind": "0.0.0.0:443", "http": { "cluster": "web" },
      "tls": { "cert": "/etc/zgix/site.crt", "key": "/etc/zgix/site.key" } }
]
```

Both files are read once at startup, so a missing or unusable file stops the
proxy with an error naming the file — never mid-handshake. `cert` is a PEM
chain, leaf first; `key` is the leaf's PEM private key.

The key must be **ECDSA P-256 or P-384**. Handshakes run on the event loop,
where an RSA signature's millisecond would stall every other connection
sharing it; an ECDSA signature costs about 260 µs. An RSA key is refused at
startup.

# More than one name on one listener

`certificates` is the SNI form: one or more `cert`/`key` pairs, selected by
the name the client asked for. The first entry is the default — what a
client with no SNI, or a name no entry claims, receives.

```json
"tls": {
    "certificates": [
        { "cert": "/etc/zgix/api.crt", "key": "/etc/zgix/api.key",
          "names": ["api.example.com"] },
        { "cert": "/etc/zgix/www.crt", "key": "/etc/zgix/www.key" }
    ]
}
```

`names` is optional. Absent or empty, the names come from the leaf's
`subjectAltName` DNS entries, falling back to its common name. Matching is
ASCII case-insensitive and follows RFC 6125: an exact name, or a leftmost
`*.` wildcard matching exactly one label (`*.example.com` matches
`a.example.com`, not `example.com` or `a.b.example.com`). A trailing dot is
ignored. One listener carries at most 16 pairs.

# Reloading certificates

`SIGHUP` reloads the set from the configured paths. The new generation
serves new handshakes while the old one finishes those already in flight; a
reload that fails names the listener and certificate and keeps the old
generation, so a bad certificate cannot take the listener down. Four
generations are reserved at startup (the initial load plus three rotations)
— after the fourth, a reload is refused and the process must restart.

That reload is inbound only: a cluster's upstream `ca_file`, `client_cert`
and `client_key` are read once at startup and never re-read on `SIGHUP`.

# Session resumption

Resumption is on and has no settings. Every completed handshake hands the
client two session tickets, and a client that offers one back resumes
without a signature. Tickets are stateless — each sealed under a key zgix
keeps in memory — so resumption costs no per-session memory and the banner's
budget does not move. Two consequences:

- A restart invalidates every outstanding ticket (the sealing keys are never
  written anywhere), so returning clients pay one full handshake each and
  then resume again.
- Tickets are not shared between processes, so during a `SO_REUSEPORT`
  handoff a client may land on the process that did not issue its ticket.

The ticket flight also carries the ACK for the client's `Finished`; without
it, a client that writes `Finished` and then its request has the second
write held by its own Nagle for about 45 ms.

# What termination is not

- Termination is inbound only. An `http` listener's connection to its
  backend is plaintext unless the cluster sets its own `tls` block (see
  [upstream TLS](upstream-tls.md)), and an `l4` listener never originates
  TLS.
- `limits.tls_engines` bounds how many TLS sessions may be in flight at
  once — by far the largest per-connection object zgix holds, about 111 KiB
  plus a 32 KiB plaintext buffer, so 1024 of them is roughly 170 MiB. It
  defaults to your connection slots capped at 1024, and the startup banner
  prints the total.
- A cluster with `proxy_protocol.send` cannot be reached from a terminating
  listener: the header is staged in the relay buffer, which terminated wire
  bytes do not pass through. The combination is rejected at load.

Handshakes and resumes are counted — `zgix_tls_handshakes_completed` and
`zgix_tls_resumed` — so a resumption regression after a restart shows up in
the scrape within one client generation.
