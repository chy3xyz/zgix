---
title: Guides
sidebar_label: Guides
description: Task-oriented guides — routing, TLS, HTTP/3, WebSockets, rate limiting and the WAF, compression, upstream TLS, and observability.
---

Task-oriented guides, one per subject:

- [Listeners and routes](listeners-and-routes.md) — `l4` vs `http`, host/header/prefix route tables, multi-tenant SNI.
- [TLS certificates](tls-certificates.md) — terminating TLS 1.3, SNI certificate sets, reloads.
- [HTTP/3](http3.md) — the experimental QUIC listener, its limits and its counters.
- [WebSockets](websockets.md) — tunnelled upgrades and their own pool.
- [Rate limiting and the WAF](rate-limiting-and-waf.md) — token buckets, connection caps, the literal denylist.
- [Compression](compression.md) — precompressed static bodies and the narrow proxied-response case.
- [Upstream TLS](upstream-tls.md) — originating TLS 1.3 to your backends, mTLS, verification.
- [Access log and admin panel](access-log-and-admin-panel.md) — the JSON log, sinks and rotation, the admin scrape, and the bundled panel.
