---
title: A VPS deployment
sidebar_label: VPS walkthrough
description: A recorded single-VPS deployment — one wildcard certificate, three applications, host routing on :443, and an h3 listener on the same name.
---

A small box, three applications, one edge. The point of the recording: a
wildcard certificate covers every app, and the route table — not extra
infrastructure — is what separates them.

# Topology

```text
                        VPS (one public IPv4)
┌──────────────────────────────────────────────────────────┐
│  zgix                                                    │
│    :80   http  → redirects to https, serves acme http-01 │
│    :443  http+tls → host routes:                         │
│           app.example.com   → cluster app  (unix socket) │
│           api.example.com   → cluster api  (127.0.0.1)   │
│           grafana.example.com → cluster grafana          │
│           example.com, www  → cluster web                │
│    :443/udp h3 (same cert, same route table)             │
│    127.0.0.1:9100 admin (scrape + log tail)              │
└──────────────────────────────────────────────────────────┘
```

Three reasons this shape earns its keep:

- One wildcard certificate fronts every app; renewal touches one file pair
  and one `SIGHUP`.
- Each app is a cluster with its own health check, balancing policy and
  inflight cap — a slow grafana never borrows web's upstream leases.
- The h3 listener answers HTTP/3 clients on the same name with the same
  routes, so QUIC adoption is a client decision, not a config fork.

# DNS

```text
example.com      A     <vps-ip>
*.example.com    A     <vps-ip>
```

The wildcard is what makes the rest boring: every app you add later is a
route row and a cluster, not a certificate request.

# Certificates

Issue once (any ACME client), store in the layout the unit expects:

```sh
install -d -m 0755 /etc/zgix
install -m 0644 fullchain.pem /etc/zgix/fullchain.pem
install -m 0600 key.pem       /etc/zgix/key.pem
```

The key must be ECDSA P-256 or P-384 — an RSA key is refused at startup.
Renewal is two commands wired to the ACME client's deploy hook:

```sh
# deploy hook, runs on the VPS after each successful renewal
install -m 0644 fullchain.pem /etc/zgix/fullchain.pem
install -m 0600 key.pem       /etc/zgix/key.pem
systemctl reload zgix        # SIGHUP: new generation, old finishes in flight
```

A failed reload keeps the old generation and names the bad file — a renewal
that breaks cannot take the listener down. `zgix_cert_info` on the scrape
carries `not_after`/`days_left` per pair, so expiry pages long before it
bites.

# Config

```json
{
    "listeners": [
        {
            "bind": "0.0.0.0:80",
            "http": {
                "cluster": "nowhere",
                "request_filters": [
                    { "match": { "path_prefix": "/.well-known/acme-challenge/" },
                      "actions": [{ "allow": true }] },
                    { "actions": [{ "redirect": { "status": 308, "scheme": "https" } }] }
                ]
            }
        },
        {
            "bind": "0.0.0.0:443",
            "http": {
                "routes": [
                    { "host": "app.example.com",     "prefix": "/", "cluster": "app" },
                    { "host": "api.example.com",     "prefix": "/", "cluster": "api" },
                    { "host": "grafana.example.com", "prefix": "/", "cluster": "grafana" },
                    { "host": "www.example.com",     "prefix": "/", "cluster": "web" },
                    { "prefix": "/", "cluster": "web" }
                ]
            },
            "tls": {
                "certificates": [
                    { "cert": "/etc/zgix/fullchain.pem", "key": "/etc/zgix/key.pem" }
                ]
            }
        }
    ],
    "h3_listeners": [
        {
            "bind": "0.0.0.0:443",
            "routes": [
                { "host": "app.example.com",     "prefix": "/", "cluster": "app" },
                { "host": "api.example.com",     "prefix": "/", "cluster": "api" },
                { "host": "grafana.example.com", "prefix": "/", "cluster": "grafana" },
                { "prefix": "/", "cluster": "web" }
            ],
            "tls": { "cert": "/etc/zgix/fullchain.pem", "key": "/etc/zgix/key.pem" },
            "error_pages": { "no_route": "friendly-404" }
        }
    ],
    "clusters": {
        "app": {
            "endpoints": ["unix:/run/app/app.sock"],
            "check": { "type": "http", "path": "/healthz", "expect_status": 200 },
            "passive_ejection": { "fall": 5, "recovery_ms": 30000 }
        },
        "api": {
            "endpoints": ["127.0.0.1:9001", "127.0.0.1:9002"],
            "pick": "p2c",
            "check": { "type": "http", "path": "/healthz", "expect_status": 200 }
        },
        "grafana": {
            "endpoints": ["127.0.0.1:3000"],
            "check": { "type": "tcp" }
        },
        "web": {
            "endpoints": ["127.0.0.1:8080"],
            "check": { "type": "tcp" }
        },
        "nowhere": { "endpoints": ["127.0.0.1:9"] }
    },
    "bodies": {
        "friendly-404": {
            "inline": "nothing here matches your request",
            "content_type": "text/plain"
        }
    },
    "admin": { "bind": "127.0.0.1:9100" },
    "access_log": { "sink": "file", "path": "/var/log/zgix/access.log" }
}
```

Details worth stealing:

- The `:80` listener exists to redirect and to answer ACME http-01. The
  challenge path is `allow`ed before the catch-all 308, so renewal never
  depends on the apps. The `nowhere` cluster is a loader formality — a
  listener must name a cluster, but filters answer first, so nothing is ever
  dialed.
- `app` listens on a **unix socket** — no loopback ports to collide with,
  filesystem permissions as the ACL, and no ephemeral-port exhaustion on
  the busiest leg. See the [config reference](/03-reference/config.md)
  for the path rules (absolute, ≤ 103 bytes).
- `passive_ejection` on `app`: a `tcp` check passes whenever the kernel
  accepts, even when the app behind it is wedged; five consecutive failed
  *requests* eject it, and recovery is re-judged by traffic after 30 s.
- The h3 route table is the TCP table minus `www` — same cert, same
  clusters. Watch `zgix_h3_no_route`: it is the operational signal for
  mistyped-host probes.

# Firewall

```sh
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow 443/udp        # QUIC — the h3 listener
ufw deny 9100/tcp        # admin stays loopback anyway
```

Omitting `443/udp` is the classic h3 deployment bug: TCP works, QUIC
silently never flows, and the only symptom is the absence of
`zgix_h3_requests`.

# Bringing it up

```sh
zgix --check /etc/zgix/config.json
systemctl enable --now zgix
curl -sI http://example.com/                       # 308 to https
curl -s  https://api.example.com/healthz           # via the route table
curl --http3-only -s https://app.example.com/      # the QUIC leg
ssh -L 9100:127.0.0.1:9100 vps 'sleep 3600' &      # panel in a tab:
#   python3 -m http.server 8080 --directory panel  → http://127.0.0.1:8080/
```

The panel's 概览 view shows h3 sessions against the TCP pools within the
first minute of real traffic; the 站点 view reads
`zgix_listener_info`/`zgix_route_info` back — the topology you drew in the
config, rendered from the scrape.
