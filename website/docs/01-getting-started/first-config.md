---
title: First config
sidebar_label: First config
description: A complete minimal zgix config — L4 listener, HTTP listener, h3 listener, health checks, admin endpoint and access log — validated with --check before anything binds.
---

This config is the smallest thing that exercises every block you will touch
in daily operation: an L4 relay, an HTTP reverse proxy with host routing, an
experimental HTTP/3 listener, health checks, the admin scrape, and a JSON
access log. Save it as `config.json`:

```json
{
    "listeners": [
        {
            "bind": "0.0.0.0:80",
            "http": {
                "routes": [
                    { "host": "api.example.com", "prefix": "/", "cluster": "api" },
                    { "prefix": "/", "cluster": "web" }
                ]
            }
        },
        {
            "bind": "0.0.0.0:443",
            "l4": {
                "routes": [
                    { "sni": "db.example.com", "cluster": "postgres" },
                    { "cluster": "fallback" }
                ]
            }
        }
    ],
    "h3_listeners": [
        {
            "bind": "0.0.0.0:4443",
            "routes": [
                { "host": "api.example.com", "prefix": "/", "cluster": "api" },
                { "prefix": "/", "cluster": "web" }
            ],
            "tls": { "cert": "/etc/zgix/fullchain.pem", "key": "/etc/zgix/key.pem" }
        }
    ],
    "clusters": {
        "web": {
            "endpoints": ["127.0.0.1:9000"],
            "check": { "type": "tcp", "fall": 3, "rise": 2 }
        },
        "api": {
            "endpoints": ["127.0.0.1:9001", "127.0.0.1:9002"],
            "pick": "p2c",
            "check": { "type": "http", "path": "/healthz", "expect_status": 200 }
        },
        "postgres": { "endpoints": ["127.0.0.1:5432"] },
        "fallback": { "endpoints": ["127.0.0.1:8443"] }
    },
    "admin": { "bind": "127.0.0.1:9100" },
    "access_log": { "sink": "stdout" }
}
```

Reading it top to bottom:

- The `:80` listener is an `http` reverse proxy. Its route table matches
  `host`, then a `header` predicate if one is named, then the longest
  `prefix` — `api.example.com` goes to the `api` cluster, everything else to
  `web`.
- The `:443` listener is an `l4` relay that routes by TLS server name (SNI)
  without terminating TLS — the backend completes the handshake with the
  client and zgix never sees a plaintext byte.
- The h3 listener terminates QUIC-TLS on UDP `:4443` and proxies over the
  same clusters. QUIC has no plaintext mode, so `tls` is required.
- Every cluster names endpoints and, except the trivially local ones, a
  health check: `tcp` proves the port accepts, `http` proves the app
  answers.
- `admin` serves the Prometheus scrape plus a bounded access-log tail.
- `access_log` writes one JSON line per exchange to stdout.

Exactly one protocol key (`l4` or `http`) is required per TCP listener;
`bind` and `tls` sit outside the protocol body because they apply to both.

# Price it before you run it

```sh
zgix --check config.json
```

`--check` loads the config, opens every file it names, prices the pools and
measures the fd demand against `RLIMIT_NOFILE` — everything a start does up
to the banner — then exits without binding a port:

```text
zgix 0.9.0
budgets:
  memory  total 47297 KiB = conn slots 1386 x 512 B + stream slots 1386 x 1552 B
          + relay buffers 1386 x 32808 B
          + ...
  fds     4093 required (asserted against RLIMIT_NOFILE)
  ring    4096 entries, completion queue 8192, in-flight ops <= 6869
  config  2 listener(s), 4 cluster(s), 0 error page(s), access log on
  rlimit  RLIMIT_NOFILE 1024 soft, 524288 hard (a start raises the soft limit to the fd budget)
  check   config.json: valid, and this box can start it
```

The exit code is a signal you can branch a CI job on:

| exit | meaning |
|---|---|
| `0` | the config loads and this machine can start it |
| `1` | the config is wrong — unreadable, unparseable, semantically refused, or naming a file that will not load |
| `2` | the config is right and *this machine* cannot fit it: the fd budget is above the `RLIMIT_NOFILE` hard limit |

::: tip
`--check` does the full load, so it needs the same file permissions the
proxy would — a config naming production certificates cannot be checked on
an agent that does not hold them. And an `access_log` `file` sink is created
if it is absent, exactly as a start creates it.
:::

# Start it

```sh
zgix config.json
```

The startup banner and the exit tally go to stderr; stdout belongs to the
access log. A valid config whose fd budget is above this machine's
`RLIMIT_NOFILE` hard limit is refused after the banner, with the numbers on
screen next to the reason.

There is no config reload: the pools, the ring and every table are sized
from the config at startup and never grow. To change the config, replace the
process — see [systemd](/04-deployment/systemd.md) for the supervised
handoff.
