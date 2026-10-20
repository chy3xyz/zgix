# zgix panel

A control panel for a running zgix: it scrapes the admin endpoint
(Prometheus text) on a timer. T-shaped layout — top bar (target /
interval / status) and a left nav:

- **Overview**: h3 listener table, per-tick rate sparklines, the h3 verdict
  distribution, pool gauges, raw scrape.
- **Sites**: listeners and their route tables, from the `zgix_listener_info`
  / `zgix_route_info` inventory families (needs a zgix build that emits
  them; older builds show an upgrade hint).
- **Apps**: clusters with avg/p50/p90/p99 latency from the
  `duration_seconds` histogram, per-endpoint health / responses /
  connect-failed / inflight.
- **About**: version (`zgix_info`) and target summary.

No build step — SolidJS (v1.9.3) is vendored in `vendor/` and loaded as
an ES module.

## Run

The panel is plain static files, but ES modules do not load over
`file://`, so serve the directory:

```sh
python3 -m http.server 8080 --directory panel
# open http://127.0.0.1:8080/
```

Type the admin endpoint of the zgix you want to watch into the header
field (default `http://127.0.0.1:9100`, remembered in localStorage) and
pick a poll interval. The admin endpoint answers with
`Access-Control-Allow-Origin: *`, so any static server works.

## Minimal zgix config with admin

```json
{
  "listeners": [{ "bind": "127.0.0.1:8080",
    "http": { "routes": [{ "prefix": "/", "cluster": "origin" }] } }],
  "admin": { "bind": "127.0.0.1:9100" },
  "h3_listeners": [ ... ],
  "clusters": { "origin": { "endpoints": ["127.0.0.1:9000"],
    "check": { "type": "tcp" } } },
  "access_log": { "sink": "stdout" }
}
```
