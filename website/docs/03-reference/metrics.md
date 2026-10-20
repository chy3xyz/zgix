---
title: Metrics reference
sidebar_label: Metrics
description: The zgix_* metric families rendered on the admin scrape — inventory, RED, per-endpoint, the shed ladder, policy counters, and pool gauges.
---

The admin endpoint renders Prometheus exposition text: every shed rung,
every lifecycle counter, live pool-occupancy gauges, and a bounded
access-log tail. All names carry the `zgix_` prefix. Labels are prebuilt at
startup — cardinality is bounded by the config (clusters, endpoints,
listener binds, certificate names), never by request data — and the render
is zero-allocation like everything else on this endpoint.

# Reading the scrape

- **Counters move when walls are hit.** The `shed_*`, `*_limited`,
  `*_blocked` and verdict counters only move once something happened.
- **Gauges show the approach.** `zgix_conn_slots_in_use` against
  `zgix_conn_slots_capacity` shows the wall coming; the shed counter shows
  it being hit. Each pool also raises a pressure flag at 3/4 occupancy and
  lowers it only after draining back to 1/2 — while raised, idle timeouts
  are cut to a quarter so quiet connections return resources before the
  wall.
- **Families reconcile.** Each labeled family sums to the bare process
  total it breaks down — an identity the deterministic simulator asserts on
  every seed. `zgix_cluster_duration_seconds_count` equals
  `zgix_l7_responses` exactly, because only completed exchanges are
  observed.

# Inventory — the `*_info` convention

A constant-1 gauge whose information lives in the labels — a control panel
gets its site/application 清单 view straight off the scrape:

```text
zgix_info{version="0.9.0"} 1
zgix_listener_info{bind="0.0.0.0:443",kind="http",routes="12"} 1
zgix_route_info{listener="0.0.0.0:443",host="api.example",prefix="/api",header="x-canary",cluster="api"} 1
zgix_endpoint_info{cluster="api",endpoint="10.0.0.1:8080"} 1
zgix_cert_info{name="edge.example",listener="127.0.0.1:8443",not_after="...",days_left="42"} 1
```

`kind` is `http`, `l4` or `h3` — TLS termination does not rename an http
listener. A route's `host` and `header` labels appear only when the route
names them (an absent label means "any", the Prometheus convention);
`header` carries the predicate's name. h3 listeners' routes share
`zgix_route_info`, disambiguated by the `listener` label. `zgix_cert_info`
carries one row per configured certificate pair with its validity window, so
an expiring cert pages before it breaks handshakes.

# Rate, Errors, Duration

```text
zgix_cluster_responses{cluster="api",class="2xx"} 4182
zgix_cluster_responses{cluster="api",class="5xx"} 17
zgix_cluster_duration_seconds_bucket{cluster="api",le="0.005000000"} 3910
zgix_cluster_duration_seconds_bucket{cluster="api",le="+Inf"} 4199
zgix_cluster_duration_seconds_sum{cluster="api"} 12.884901888
zgix_cluster_duration_seconds_count{cluster="api"} 4199
```

- `zgix_cluster_responses` is the status the **client actually received**,
  classed — without it, an origin returning `500` to every request shows up
  only in the access log.
- `zgix_cluster_duration_seconds` is a standard histogram with a compiled-in
  ladder — eighteen boundaries, 2.5× apart from 25 µs to 10 s — so every
  zgix's histogram is directly comparable to every other's, and
  `histogram_quantile` works on it directly.
- Both are labelled by cluster, not endpoint: per-endpoint 5xx is already
  acted on by passive ejection, and cluster is the granularity that answers
  "which backend got slow" without multiplying the dominant axis.

An exchange the client cut off mid-response is not in the histogram — p99
measures how long serving takes, not how long clients wait before giving
up. Those show as `outcome: aborted` in the access log.

# Per-endpoint

```text
zgix_endpoint_responses{cluster="api",endpoint="10.0.0.1:8080"} 4182
zgix_endpoint_connect_failed{cluster="api",endpoint="10.0.0.2:8080"} 17
zgix_endpoint_health_down{cluster="api",endpoint="10.0.0.2:8080"} 2
zgix_endpoint_healthy{cluster="api",endpoint="10.0.0.2:8080"} 0
zgix_endpoint_inflight{cluster="api",endpoint="10.0.0.1:8080"} 7
```

Dial failures, responses served and health transitions carry both labels;
the "every endpoint was full" sheds carry only `cluster`, since no single
endpoint was full. `zgix_endpoint_inflight` is the level the balancer
compares; `zgix_endpoint_healthy` is the prober's current verdict, rendered
for health-checked clusters only.

# The shed ladder

Every rung of exhaustion has a defined answer and a counter that names it:

| counter | raised when |
|---|---|
| `zgix_l7_shed_upstream_slots` | no upstream slot for an HTTP request — zgix wants a wider pool, not a busier backend |
| `zgix_l4_shed_endpoint_inflight` / `zgix_l7_shed_endpoint_inflight` | every endpoint was at its `max_inflight` — the one limit that fails closed |
| `zgix_l7_shed_tunnels` | the tunnel pool was full; the upgrade was refused `503` before it cost a backend connection |
| `zgix_l7_shed_relay_buffers` | no relay buffer pair for an admitted exchange |
| `zgix_l7_rate_limited` / `zgix_l7_rate_limit_full` | a client exceeded its token bucket (`429`) / the identity table had no free slot in eight probes (fails open — widen `rate_limit_entries`) |
| `zgix_l7_conn_limited` / `zgix_l7_conn_limit_full` | a client held more than `conn_limit.max` connections (`503`) / table placement failed (fails open) |
| `zgix_l7_body_over_limit` | a declared `Content-Length` past `max_body_bytes`, answered `413` before the origin was dialed |
| `zgix_l7_body_cut_mid_stream` | a chunked body crossed the cap after the response leg was armed — the only answer left is a teardown |
| `zgix_l7_keepalive_requests_capped` | a connection passed `keepalive_requests`; the response announced `Connection: close` |

A rising `*_full` is the signal to widen a table, not an outage; the
`*_limited`/`*_shed_*` counters are the refusals themselves.

# Verdicts and policy

| counter | meaning |
|---|---|
| `zgix_l7_responses` | exchanges completed with an origin's (or canned) status |
| `zgix_l7_bad_gateway` / `zgix_l7_gateway_timeout` | the dial failed or the origin answered too slowly (`502` / `504`) |
| `zgix_l7_request_timeout` | one exchange outlived `request_ms` |
| `zgix_l7_head_budget_expired` | a connection said nothing within `head_ms` — the slowloris reap, answered `408` when answerable |
| `zgix_l7_redirected` / `zgix_l7_responded` / `zgix_l7_rejected` | filter terminal actions: relocated traffic, served-from-body traffic, refused traffic — never blurred |
| `zgix_l7_waf_blocked` | hits on the literal denylist |
| `zgix_l7_sticky_followed` / `_assigned` / `_repicked` | cookie-stickiness partitions: honoured assignment, minted assignment, re-placement after ejection. A rising repick rate means backends are flapping under a sticky population |
| `zgix_forwarded_chain_dropped` | an `X-Forwarded-For` chain past 512 bytes, dropped whole rather than truncated |
| `zgix_tunnels_established` / `zgix_tunnels_drained` | upgrades that became sessions / live tunnels cut at drain |
| `zgix_l7_responses` + the shed counters | reconcile with access-log lines and histogram counts exactly |

# The L4 tables

| counter | meaning |
|---|---|
| `zgix_l4_sni_routed` / `_absent` / `_no_route` / `_invalid` | SNI route outcomes: relayed, no server name named, named but unclaimed, opening bytes not a ClientHello |
| `zgix_l4_proxy_header_accepted` / `_invalid` | PROXY protocol v1/v2 headers parsed / refused — a rising `invalid` means something other than the configured proxy is reaching the listener |
| `zgix_l4_proxy_header_sent` | headers staged to sending clusters, one per dialed connection |

# TLS and kernel pressure

- `zgix_tls_handshakes_completed`, `zgix_tls_resumed` — handshake volume and
  the resumption share; a restart shows up here as a resumption dip within
  one client generation.
- `zgix_kernel_pressure_errors` with the per-op split
  (`zgix_kernel_pressure_accept`, `_connect`, `_recv`, `_send`,
  `_set_option`) and the per-cause split (`_out_of_buffers`, `_out_of_memory`,
  `_fd_limit`, `_address_unavailable`, `_other_cause`) — both partitions sum
  to the total, asserted on every simulation seed. Non-zero here means the
  kernel refused resources, the first thing to check before blaming zgix.

# Pool gauges

For each pool, an in-use gauge against its capacity:

```text
zgix_conn_slots_in_use 42
zgix_conn_slots_capacity 1386
zgix_relay_buffers_in_use 17
zgix_head_buffers_in_use 9
zgix_upstream_head_buffers_in_use 3
```

…plus `zgix_upstream_slots_*` when TLS clusters dial, and the pressure
flags `zgix_conn_pressure_engaged`, `zgix_relay_pressure_engaged`,
`zgix_head_pressure_engaged`, `zgix_upstream_pressure_engaged`,
`zgix_upstream_head_pressure_engaged` — each raised at 3/4 occupancy,
lowered only after draining to 1/2.

# Access log

`zgix_access_log_dropped` (a stalled sink costs dropped lines, never
latency), `zgix_access_log_reopened`, `zgix_access_log_reopen_failed`. The
scrape itself ends with a `# zgix_access_log` marker and the newest 128
lines as `# <json>` comments.

# The exit tally

`SIGTERM` prints the counters once on the way out — the only other place
they reach stderr, beside a stuck drain's diagnostic. Prometheus exposition
stays a snapshot: two of them on one stream would not parse.
