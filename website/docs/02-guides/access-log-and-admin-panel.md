---
title: Access log and the admin panel
sidebar_label: Access log and admin panel
description: The JSON access log — sinks, rotation, logged headers — the admin scrape with its bounded log tail, and the bundled control panel.
---

# The access log

One JSON object per line: one per HTTP exchange (rejects, `503` sheds and
timeouts included), one per L4 connection, and one per tunnel when it
closes.

```json
"access_log": { "sink": "stdout" }
```

```json
{"time":"2026-10-20T09:14:22.481Z","kind":"http","outcome":"ok","client":"10.1.2.3:52344","method":"GET","host":"api.example.com","path":"/v1/items","status":200,"upstream_reused":true,"upstream_replayed":false,"duration_us":1873,"bytes_in":142,"bytes_out":4096,"cluster":"api","upstream":"10.0.0.7:8080"}
```

`outcome` is what `status` cannot tell you: an origin answering `503` and
zgix shedding a request with `503` are the same three digits and opposite
events. It reads `ok`, `rejected`, `shed`, `timed_out`, `upstream_failed`,
`aborted`, or `closed` — the last for L4 connections and tunnels, which end
the way a relay ends rather than the way an exchange does.

Logging never blocks the event loop, so a sink that stalls costs dropped
lines rather than latency; `zgix_access_log_dropped` counts them exactly.

# Sinks and rotation

`sink` is either `stdout` — the process's own standard output, inherited
rather than opened, costing no fd and having no rotation story of its own —
or `file` with a `path`:

```json
"access_log": { "sink": "file", "path": "/var/log/zgix/access.log" }
```

The file is created if absent and opened append-only at startup, never
truncated, which is what makes copy-truncate rotation (logrotate) safe:
every write lands at the current end. Move-based rotation is served by
`SIGHUP`, which reopens the path — the new fd opens *first*, and a reopen
that cannot open its file keeps the old one and counts
`zgix_access_log_reopen_failed`, because a failed rotation must not destroy
a working log. `zgix_access_log_reopened` counts the rotations that took,
and a successful reopen also heals a sink that had broken.

# Logging request and response headers

By default a zgix line and the backend's line for the same request share no
key, so a slow request cannot be attributed to a hop. Naming headers fixes
that without changing a byte on the wire:

```json
"access_log": {
    "sink": "stdout",
    "request_headers": ["X-Request-ID", "User-Agent"],
    "response_headers": ["X-Cache"]
}
```

zgix does not mint an identifier: a CDN or ingress in front almost always
sets `X-Request-ID` or `traceparent`, and that header reaches the origin
untouched, so logging it at both ends is the whole join. Names match
case-insensitively and log lowercased; a header that did not arrive is
omitted rather than nulled; values truncate at 256 bytes; up to 8 headers
may be named across both lists. The values are held per connection for the
life of a request, so naming headers costs memory proportional to
`conn_slots` — the startup banner prints it, and a too-narrow staging buffer
is a startup refusal rather than a dropped line.

# The admin endpoint

```json
"admin": { "bind": "127.0.0.1:9100" }
```

The admin listener serves Prometheus exposition text: every shed rung, every
lifecycle counter, the inventory families, live pool-occupancy gauges, and a
bounded access-log tail — whether or not a sink is configured. One scrape is
served at a time from a slot reserved outside the data-path pools, so a
scrape and a request can never shed one another. It is the only way to read
live counters; no signal prints them, because two snapshots on one stream
would invalidate each first.

The scrape ends with a `# zgix_access_log` marker and the newest HTTP lines
as `# <json>` comments — a bounded ring, the newest 128 lines at 512 bytes
each, oldest first — so it answers without reading a file and never blocks
the loop. See [Metrics](/03-reference/metrics.md) for the full
reference.

The admin endpoint answers with `Access-Control-Allow-Origin: *`, so any
static server can host the panel against it.

# The bundled panel

`panel/` in the repository is a control panel for a running zgix: plain
static files, SolidJS vendored in `panel/vendor/`, no build step. ES modules
do not load over `file://`, so serve the directory:

```sh
python3 -m http.server 8080 --directory panel
# open http://127.0.0.1:8080/
```

Type the admin endpoint of the zgix you want to watch into the header field
(default `http://127.0.0.1:9100`, remembered in localStorage) and pick a
poll interval. Four views:

- **概览 (Overview):** h3 listener table, per-tick rate sparklines, the h3
  verdict distribution, pool gauges, raw scrape.
- **站点 (Sites):** listeners and their route tables, from the
  `zgix_listener_info` / `zgix_route_info` inventory families.
- **应用 (Apps):** clusters with avg/p50/p90/p99 latency from the
  `zgix_cluster_duration_seconds` histogram, per-endpoint health,
  responses, connect failures and inflight levels.
- **关于 (About):** version (`zgix_info`) and target summary.

A minimal config with the admin endpoint enabled is the one from
[First config](/01-getting-started/first-config.md) — the
`"admin": { "bind": "127.0.0.1:9100" }` line is the only requirement.
