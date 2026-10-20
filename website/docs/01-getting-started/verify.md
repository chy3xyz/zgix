---
title: Verify it works
sidebar_label: Verify
description: Verify a running zgix with curl over TCP and TLS, an HTTP/3 client over QUIC, the admin scrape, and the access log.
---

With `zgix config.json` running (see [first config](first-config.md)), four
checks confirm every leg is alive.

# 1. The TCP leg

```sh
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:80/
```

Route a request at the `api` host to exercise the route table:

```sh
curl -s -H 'Host: api.example.com' http://127.0.0.1:80/healthz
```

# 2. The L4 leg

Any TLS client pointed at the SNI listener should behave exactly as if the
backend were contacted directly — zgix relays the handshake byte for byte:

```sh
psql 'host=db.example.com port=443 sslmode=require' -c 'select 1'
```

# 3. The HTTP/3 leg

Point an HTTP/3-capable client at the UDP port directly. With a curl built
for HTTP/3:

```sh
curl --http3-only -kv https://127.0.0.1:4443/
```

or use the bundled interop client, a minimal aioquic client pinned to an
IPv4 socket — aioquic's default dual-stack IPv6 path can look exactly like a
server-side hang on some hosts:

```sh
pip install aioquic
python3 scripts/h3-interop-client.py 4443
# -> STATUS 200 / BODY ...
```

Until clients trust the `Alt-Svc` hint you may also choose to advertise the
UDP port from an `http` listener; see [HTTP/3](/02-guides/http3.md).

# 4. The admin scrape

```sh
curl -s 127.0.0.1:9100/metrics | grep -E '^zgix_(info|h3_)'
```

You should see the inventory row and the h3 verdict counters:

```text
zgix_info{version="0.9.0"} 1
zgix_h3_requests 2
zgix_h3_responses 2
```

The scrape ends with a `# zgix_access_log` marker and the newest 128 access
lines as `# <json>` comments — the [control panel](/02-guides/access-log-and-admin-panel.md)
parses exactly that section for its *logs* view.

# 5. The access log

With `"access_log": { "sink": "stdout" }`, one JSON object lands per
exchange:

```json
{"time":"2026-10-20T09:14:22.481Z","kind":"http","outcome":"ok","client":"10.1.2.3:52344","method":"GET","host":"api.example.com","path":"/v1/items","status":200,"upstream_reused":true,"upstream_replayed":false,"duration_us":1873,"bytes_in":142,"bytes_out":4096,"cluster":"api","upstream":"10.0.0.7:8080"}
```

Every request lands in exactly one verdict bucket — the simulator asserts
the identities between log lines, counters and histogram counts on every
seed — so `zgix_l7_responses` plus the shed counters always reconcile with
the lines you see.
