# zgix documentation

How to run, configure and operate zgix: starting and replacing the process,
every block a config can carry, what the proxy exposes while it runs, and
what it does when a resource runs out.

The authoritative list of fields, enums and numeric bounds is the JSON
Schema shipped as a release asset and emitted locally by `zig build schema`.
It is generated from the parser, and [zgix.io/config](https://zgix.io/config/)
renders it for the latest release. This document is the tour. The reasoning
behind each behaviour is in [DESIGN.md](DESIGN.md); a bare `§` reference
points there.

## Running zgix

### The command line

The binary takes one argument, the path to a JSON config:

```sh
zgix config.json           # start the proxy
zgix --check config.json   # validate and price it, bind nothing (-c)
zgix --help                # usage summary (-h)
zgix --version             # print the version (-V)
```

A release build prints its bare version, `zgix 0.8.2`. A build from source
after a release adds what distinguishes it, `zgix 0.8.2 (v0.8.2-5-gabc1234)`,
and `-dirty` when the tree had uncommitted changes, so the version in a bug
report identifies the exact build. Packagers can name a build with
`zig build -Dbuild-id=…`. The same line opens the startup banner.

A config zgix will not accept is refused before anything is bound: the
process prints `zgix: invalid config '<path>': <reason>` and exits `1`. A
valid config whose fd budget is above this machine's `RLIMIT_NOFILE` hard
limit is refused the same way, after the startup banner, so the numbers that
refused it are on screen with the reason.

### Checking a config without running it

`--check` loads the config, opens every file it names, prices the pools and
measures the fd demand against `RLIMIT_NOFILE`, which is everything a start
does up to the banner, then exits without binding a port:

```console
$ zgix --check config.json
zgix 0.8.2
budgets (DESIGN.md §5/§8; closed-form except where marked):
  memory  total 47297 KiB = conn slots 1386 x 512 B + stream slots 1386 x 1552 B
          + relay buffers 1386 x 32808 B
          + upstream slots 1311 x 48 B + head buffers 0 x 8192 B (+ ring 0 B)
          + upstream head buffers 0 x 8216 B + head scratch 8192 B
          + access log 0 KiB (+ logged headers 0 B)
          + endpoint tables 29 B (1 cluster(s) x 1 wide)
          + labeled metrics 26450 B (tables, labels and render buffers)
          + tunnels 0 x 0 B (their own relay buffers, never HTTP's)
          + tls engines 0 x 0 B (+ plaintext 0 B each, libcrypto heap 0 KiB)
          + config arena 2 KiB (measured, not closed-form)
  fds     4093 required (asserted against RLIMIT_NOFILE)
  ring    4096 entries, completion queue 8192, in-flight ops <= 6869
  config  1 listener(s), 1 cluster(s), 0 error page(s), access log off
  rlimit  RLIMIT_NOFILE 1024 soft, 524288 hard (a start raises the soft limit to the fd budget)
  check   config.json: valid, and this box can start it
```

The report shows what the config will cost, not only whether it parses, so
a CI job, a config-management dry run or a pre-deploy hook can run it. The
report goes to stdout. Reasons for a refusal go to stderr, as they do at
startup.

| exit | meaning |
|---|---|
| `0` | the config loads and this machine can start it |
| `1` | the config is wrong — unreadable, unparseable, semantically refused, or naming a file that will not load |
| `2` | the config is right and *this machine* cannot fit it: the fd budget is above the `RLIMIT_NOFILE` hard limit |

A CI job branches on the split: a build agent with a stock `RLIMIT_NOFILE`
may accept `2` on a config sized for production, and must never accept `1`.

Two things to know before wiring it into a pipeline. It does the full load,
so it needs the same file permissions the proxy would, and a config naming
production certificates cannot be checked on an agent that does not hold
them. And an `access_log` `file` sink is created if it is absent, exactly
as a start creates it.

### Signals

The startup banner and the exit tally go to stderr. stdout belongs to the
access log, whose `stdout` sink writes one JSON line per event. `--check`
is the exception: it never serves, so its report can use stdout.

| signal | effect |
|---|---|
| `SIGTERM`, `SIGINT` | drain in-flight connections, then exit 0 |
| `SIGHUP` | reopen the access log's `file` sink and load the next TLS certificate generation |
| `SIGUSR1` | ignored |

A completed drain prints the counters once on its way out. A drain that
gets stuck prints them too, beside a diagnostic naming which plane never
finished. Those are the only two times counters reach stderr: Prometheus
exposition is a snapshot, and two of them on one stream would not parse.
Live counters come from [`/metrics`](#metrics).

`SIGUSR1` is explicitly ignored rather than left unhandled, because its
default disposition is to terminate the process.

### A minimal config

One L4 listener forwarding to one origin:

```json title="config.json"
{
    "listeners": [
        { "bind": "127.0.0.1:8080", "l4": { "cluster": "origin" } }
    ],
    "clusters": {
        "origin": { "endpoints": ["127.0.0.1:9000"] }
    }
}
```

That is the whole file. Every other block (`timeouts`, `limits`,
`access_log`) has defaults. [`config/example.json`](../config/example.json)
is the same listener with health checks and the access log turned on.

### Replacing a running instance

There is no config reload. The pools, the ring and every table are sized
from the config at startup and never grow, so nothing re-reads the file.
`SIGHUP` reopens the access log and reloads the TLS certificate set, but
it never re-reads `config.json`; hot restart is a non-goal
([DESIGN.md](DESIGN.md) §1).

Instead, every listener is bound with `SO_REUSEPORT`, so a second process
can hold the same port as the first. Replacing a config is two commands, in
this order:

<!-- figure: reuseport-handoff -->

```sh
zgix --check new-config.json || exit 1   # refuse to proceed on a bad config
zgix new-config.json &   # the replacement binds the same port and starts serving
kill -TERM "$old_pid"    # the old process drains its work, then exits 0
```

Start the replacement first. A config zgix refuses never reaches a
listener: the new process exits `1` with its reason and the old one, which
was never signalled, keeps serving. Signalling first would put the port out
of service for as long as the replacement took to fail. The `--check` line
is optional; it keeps a bad config from ever reaching a `&`.

Between the two commands both configs are live. The kernel picks a listener
per connection by hashing the 4-tuple, so the overlap is a window where
both answer, not a cutover. That is fine for tuning a timeout, adding an
endpoint or moving a cluster. For a change that has to take effect at a
known instant, such as withdrawing a route, stop the old process before
starting the new one and accept the gap.

> [!WARNING]
> The handoff is not lossless by default. Connections the old process had
> accepted but not yet served are reset when it closes its listener. Linux
> 5.14 added `net.ipv4.tcp_migrate_req`, off by default, which migrates
> them to another socket in the group; turn it on where the handoff has to
> be clean. zgix keeps the backlog drained because accept never pauses
> (§8), which narrows the window but cannot close it.

Both processes must run as the same effective user. The kernel will not add
a socket to a `SO_REUSEPORT` group bound by a different UID.

`timeouts.drain_deadline_ms` bounds how long the old process lingers; the
default `0` waits for its last connection to finish. Its exit prints the
final counters.

[Tunnels](#tunnelled-upgrades-websocket) are the exception. A WebSocket has
no message boundary to finish at, so a draining process refuses new
upgrades with `503` and cuts the live ones at `drain_deadline_ms`, or five
seconds in when none is set. `zgix_tunnels_drained` counts the ones cut.

The same two commands add capacity: start N processes on the same port and
signal none of them. That is the supported way to use more than one core.

## Configuration

Config is parsed once at startup and never reloaded; a change is a process
restart. Unknown fields are rejected.

The sections below follow a request: what a **listener** accepts, including
whether it terminates TLS, which **cluster** it routes to, how that cluster
picks an endpoint and protects it, who zgix believes the client is, the
edits and canned bodies applied at the edge, and last the process-wide
`timeouts` and `limits`. The two remaining process-wide blocks, `admin` and
`access_log`, are documented under [Observability](#observability).

### Listeners

A listener binds an address and speaks one protocol, named by the key its
settings live under: `l4` relays bytes without inspecting them, `http` runs
the HTTP/1.1 reverse proxy. Exactly one of the two is required. There is no
default.

`bind` and `tls` sit outside the protocol body because they apply to both.
Everything else lives inside the body, so a setting that only makes sense
for one protocol cannot be written for the other: `max_body_bytes` on an
`l4` listener is a rejected config, not a key that silently does nothing.

```json
"listeners": [
    { "bind": "0.0.0.0:80",   "http": { "cluster": "web" } },
    { "bind": "0.0.0.0:5432", "l4":   { "cluster": "postgres" } }
]
```

Listener count is bounded by the config's own ring and fd budgets, which
are checked at startup and printed in the banner, not by a compiled
ceiling.

Each listener is bound with `SO_REUSEPORT`, so several processes on one
port is the supported way to use more than one core and to
[replace a running instance](#replacing-a-running-instance). Every
connection, accepted and upstream alike, gets `TCP_NODELAY`: Nagle plus
delayed ACK costs a reused keep-alive connection a 40 ms stall.

#### Routing an `l4` listener by TLS name (SNI)

One `:443` can front several TLS services without terminating any of them.
Give the `l4` body a route table keyed on the server name, and zgix reads
that name out of the ClientHello and relays every byte onward unchanged:

```json
{
    "bind": "0.0.0.0:443",
    "l4": {
        "routes": [
            { "sni": "api.example.com", "cluster": "api" },
            { "sni": "grpc.example.com", "cluster": "grpc" },
            { "cluster": "fallback" }
        ]
    }
}
```

zgix holds no key material and runs no handshake. The backend completes the
TLS session with the client exactly as it would without a proxy in the
path, and zgix never sees a plaintext byte. This is how to front a service
whose certificate the proxy must not be able to present.

A route with no `sni` is the catch-all. It answers any connection,
including one whose hello named nothing at all (an IP-only client, an older
stack). Without a catch-all, a name the table does not cover is closed.

Matching is exact: `api.example.com` matches that name and not
`x.api.example.com`. `http` routes match a `host` by the same rule, and
neither table has wildcards.

Two combinations are refused at load:

| config | why |
|---|---|
| `routes` beside this listener's own `tls` | terminating consumes the hello this reads; the two are different proxies |
| `limits.relay_buffer_bytes` below 16 KiB | the hello is staged in the relay buffer, and a modern one with post-quantum key shares runs past 2 KiB — a narrow buffer would route short hellos and drop long ones from the same config |

Four counters report what the table did: `zgix_l4_sni_routed`,
`zgix_l4_sni_absent` (the client named nothing), `zgix_l4_sni_no_route`
(named something no route claims) and `zgix_l4_sni_invalid` (the opening
bytes were not a ClientHello: a plaintext client, or a handshake this proxy
could not read).

The hello must arrive in one TLS record. Every client sends it that way; a
fragmented first flight is legal but does not occur in practice, and
reassembling one would mean buffering inside a parser that reads
attacker-controlled bytes. Such a connection counts `zgix_l4_sni_invalid`
and is closed.

#### Terminating TLS

Add a `tls` block and the listener speaks TLS 1.3 instead of plaintext. Its
routes, cluster and filters are unchanged.

```json
"listeners": [
    { "bind": "0.0.0.0:443", "http": { "cluster": "web" },
      "tls": { "cert": "/etc/zgix/site.crt", "key": "/etc/zgix/site.key" } }
]
```

Both files are read once at startup, so a missing or unusable file stops
the proxy with an error naming the file, never mid-handshake. `cert` is a
PEM chain, leaf first; `key` is the leaf's PEM private key.

#### More than one name on one listener

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

Every certificate follows the same rules as the one-pair form: ECDSA
P-256/P-384, read once at startup, and a bad file is refused with the
listener and certificate number named.

`SIGHUP` reloads the set from the configured paths. The new generation
serves new handshakes while the old one finishes the handshakes already in
flight; a reload that fails names the listener and certificate and keeps
the old generation, so a bad certificate cannot take the listener down.
Four generations are reserved at startup (the initial load plus three
rotations), and the banner prints that reservation as `tls reload`. After
the fourth, a reload is refused and the process restarts to pick up the
new files.

That reload is inbound only. A cluster's upstream `ca_file`, `client_cert`
and `client_key` are read once at startup and are not re-read on `SIGHUP`;
changing them needs a restart.

Either protocol may terminate. The handshake runs as a phase ahead of the
protocol, so routing, filters, redirects and access logs work exactly as
they do in the clear.

The key must be **ECDSA P-256 or P-384**. Handshakes run on the event loop,
where an RSA signature's millisecond would stall every other connection
sharing it; an ECDSA signature costs about 260 µs. An RSA key is refused at
startup.

A cluster with `proxy_protocol.send` cannot be reached from a terminating
listener. That header is staged in the relay buffer, which a terminated
connection's wire bytes do not pass through, so the combination is
rejected at load rather than sent to the origin as garbage.

Termination is inbound only. An `http` listener's connection to its
backend is plaintext unless that cluster sets its own `tls` block (see
[TLS to the origin](#tls-to-the-origin)); an `l4` listener does not
originate TLS, whether or not it terminates it. Terminating on one side
never implies TLS on the other.

`limits.tls_engines` bounds how many TLS sessions may be in flight at once.
It is the largest single line in the startup banner's memory budget; see
[Limits](#limits).

Session resumption is on and has no settings. Every completed handshake
hands the client two session tickets, and a client that offers one back
resumes without a signature. Tickets are stateless, each sealed under a key
zgix keeps in memory, so resumption costs no per-session memory and the
banner's budget does not move. Two consequences follow. A restart
invalidates every outstanding ticket, because the sealing keys are never
written anywhere, so returning clients pay one full handshake each and
then resume again. And tickets are not shared between processes, so during
a `SO_REUSEPORT` handoff a client may land on the process that did not
issue its ticket and do a full handshake.

The ticket flight also carries the ACK for the client's `Finished`. Without
it, a client that writes `Finished` and then its request has the second
write held by its own Nagle for about 45 ms.

Measured on a `Connection: close` workload, a fresh handshake per request:
a terminated hop runs at a p50 of 158–161 µs against HAProxy's 429–607 µs.
On steady keep-alive traffic the two are at parity, about 20k req/s at a
p50 within a few µs of each other. Bulk transfer is the one band zgix
trails on, by a third to two-fifths: 507–542 µs against 383–385 µs at the
same 100 MiB/s.

#### Tunnelled upgrades (WebSocket)

By default any request carrying `Upgrade` is answered `501`, the same as
`CONNECT`. An `http` listener opts in by naming what it will carry:

```json
"listeners": [
    { "bind": "0.0.0.0:80", "http": { "cluster": "web",
      "upgrades": { "websocket": true } } }
],
"limits": { "tunnels": 512 }
```

One flag per protocol rather than a list of tokens, so the vocabulary lives
in the schema and an editor rejects `"h2c"` before the loader does.
Omitting the block, writing `{}`, or setting every flag `false` all mean
allow none and reserve nothing.

zgix does not speak WebSocket. It forwards the handshake, recognises the
origin's `101 Switching Protocols`, and from that point relays bytes both
ways until one side closes, the same byte relay an `l4` listener runs.
Routing, filters and health checks apply to the handshake exactly as they
do to any request.

After `101` the connection is opaque. Filters, routes, header rules and
canonicalisation stop applying, because there are no more HTTP messages to
apply them to. That is why the block is an allowlist and not a switch:
`websocket` is the only token zgix accepts, and `h2c`, which would carry
HTTP/2 to an origin zgix cannot parse, is refused by name at load.

`limits.tunnels` is required and has no default. How many long-lived
sessions the origins should carry is a capacity decision zgix cannot infer
from a connection count, so a listener that allows an upgrade without it is
refused at startup. It may not exceed `conn_slots`.

The pool is separate from the buffers ordinary traffic uses. Every other
pool is sized for concurrent activity, and an idle keep-alive connection
holds no head buffer, but a tunnel pins its relay buffer for its whole
life. A separate pool means tunnels cannot starve HTTP. Each costs one
relay pair — 32,808 bytes at the 16 KiB default, 33,330 when a `tls`
cluster widens both halves — printed in the startup banner.

When the pool is full the upgrade is refused with `503` before the
handshake reaches the origin, so a refusal costs no backend connection.
`zgix_l7_shed_tunnels` counts those; `zgix_tunnels_established` counts the
ones that became sessions.

- `timeouts.tunnel_ms` replaces the other deadlines once a connection
  becomes a tunnel. `idle_ms` defaults to 60 s and a WebSocket is
  legitimately idle for hours, its keepalive being application-level
  ping/pong zgix cannot see through opaque bytes. Default one hour, floor
  one second, ceiling one day. Unlike `request_ms` there is no `0` for no
  cap, because a tunnel holds a pool slot for its whole life.
- The upgraded upstream connection leaves the keep-alive pool and is never
  reused for another client. It still counts against the cluster's
  `max_inflight` for as long as the tunnel lives.
- Through a `tls` cluster the tunnel also holds that connection's TLS
  engine for its whole life. `upstream_slots` is therefore the ceiling on
  concurrent TLS tunnels; exhausting it sheds fresh TLS dials, never an
  established tunnel.

The access log writes one line when the tunnel closes: `kind` `http`,
`status` `101`, the request facts that opened it, and `bytes_in` and
`bytes_out` for the whole session.

#### Bounding a request body

An `http` listener caps how large a request body it will carry. The default
is 1 MiB, nginx's `client_max_body_size`; `0` accepts any size:

```json
{ "bind": "0.0.0.0:80", "http": { "cluster": "api",
  "max_body_bytes": 5242880 } }
```

zgix itself is unharmed by a large upload: the recv → send → recv relay
keeps per-connection memory constant whatever the stream size, so an
unbounded body costs one relay buffer and no more. The cap protects the
origin, which most application stacks assume the proxy in front will do.

It is per listener rather than in `limits` because it reserves nothing. It
states policy, like `forwarded` and `upgrades`, and a listener fronting an
upload endpoint and one fronting an API want different numbers.

A declared `Content-Length` over the cap is answered `413` before the
origin is dialed, and the connection closes with the body still unread in
the socket. A chunked body announces no size, so it is measured as it
arrives: caught before the response leg is armed it gets the same `413`,
and caught later it can only be a teardown, since by then no status can be
sent. `zgix_l7_body_over_limit` counts the first, a client told why, and
`zgix_l7_body_cut_mid_stream` the second, a client that lost its
connection.

> [!IMPORTANT]
> Releases up to 0.3.0 bounded nothing. A deployment proxying uploads
> larger than 1 MiB needs `max_body_bytes` raised, or set to `0`, before
> upgrading.

### HTTP/3 listeners (experimental)

An `h3_listeners` entry binds a UDP socket, terminates QUIC-TLS, and
proxies each request over plaintext HTTP/1.1 to the cluster its route
table selects:

```json
"h3_listeners": [
    {
        "bind": "0.0.0.0:443",
        "routes": [
            { "host": "api.example", "prefix": "/api", "cluster": "api" },
            { "prefix": "/", "cluster": "origin" }
        ],
        "tls": {
            "cert": "/etc/zgix/fullchain.pem",
            "key": "/etc/zgix/key.pem"
        },
        "max_connections": 64,
        "max_response_bytes": 65536
    }
]
```

`"cluster": "name"` remains sugar for a single catch-all route. The
table is the HTTP/1.1 listener's §7 routing, every dimension included:
a host scope, an optional `header` predicate (`equals` or `present`,
#302), and the longest path prefix that respects segment boundaries —
a conjunction, matched most-specific-first (host, then header, then
prefix), the same table the TCP listener builds. A route may also set
`access_log: false`: its requests drop out of the access log only — the
counters and admission stay, nginx's `access_log off` at a location. A
request nothing matches is answered `404`, the `l7_no_route` verdict of
the TCP path. Every cluster a route can select must dial over IP: a
`unix:` endpoint is refused, exactly as the old single-cluster form
refused it.

The answers the listener writes itself can wear configured pages:

```json
"h3_listeners": [
    {
        "bind": "0.0.0.0:443",
        "routes": [ { "prefix": "/", "cluster": "origin" } ],
        "tls": { "cert": "/etc/zgix/fullchain.pem", "key": "/etc/zgix/key.pem" },
        "error_pages": {
            "no_route": "friendly-404",
            "bad_gateway": "origin-down",
            "gateway_timeout": "origin-slow"
        }
    }
]
```

Each value names a body from the global `bodies` table, rendered through
the same pipeline the HTTP/1.1 listener's `error_pages` use — one
rendering per (body, status) pair, shared across both protocols. Absent
keys keep the built-in text. The h3 answer writes its own HEADERS, so
only the page's body crosses the seam; the status the family wears
(404/502/504) is unchanged.

QUIC has no plaintext mode, so `tls` is required. There is no SNI set: the
process presents one identity, and two HTTP/3 listeners naming different
certificate paths are refused at load. `--check` reads the same files, so
a missing certificate is a startup error that names it rather than a
failed first handshake.

The upstream leg is HTTP/1.1 — plaintext, or TLS when the selected
cluster carries a `tls` block — keep-alive pooled: a fully framed
response that does not announce `Connection: close` parks its
connection for the endpoint's next request (one parked connection per
endpoint, idle-reaped after 30 s), and a checkout miss simply dials
fresh. A connection whose origin silently closed fails its next
exchange with a 502 — never retried, because the request may not be
idempotent. A TLS dial runs the same sans-I/O client engine the TCP
path dials with (`src/tls/UpstreamTls.zig`) against the same loaded
`cluster.tls` state — `verify`, the CA bundle, `server_name` (SNI and
the RFC 9525 name check) and an optional client certificate mean one
thing on both protocols. The handshake runs before the request leg and
inside the same `h3_exchange_ms` deadline; a handshake failure — refused
verification, malformed flight, origin alert — is the dial's 502, and a
parked TLS connection checks out with its session and never pays a
second handshake.

Responses stream: the head relays the moment it parses, then body
chunks relay as they arrive — `Content-Length`, `Transfer-Encoding:
chunked` (decoded incrementally, split size lines and all) and
close-delimited bodies all ride the one streaming path, so replies
are not bounded by a staging buffer. Each response body is still
capped at `max_response_bytes` (64 KiB default, configurable up to
16 MiB): a `Content-Length` past the cap is refused before the head
goes out (the 502), a chunked or close-delimited body that crosses it
mid-stream is cut off with a stream reset (counted as a `bad_gateway`),
and a truncated or malformed chunked body — or a `Content-Length` the
origin's EOF arrives before — ends the same way once the head is on
the wire. A short client window pauses the relay (the origin's TCP
backs up naturally) and the listener's window notify resumes it.

Requests stream the same way. The session hands body bytes to the
handler as DATA-frame chunks — `Request.body` is always empty, and a
handler that neither answers nor subscribes to the chunks cannot
consume the upload, which the session drops as malformed — and the
proxy stages them into the exchange's upload queue, re-framing per the
head it rendered at dial time: a client `Content-Length` passes through
verbatim, a piece that under- or over-runs the declared count answered
`400` before the origin can receive framing that lies, and a request
without one commits to generated `Transfer-Encoding: chunked`, each
piece riding its own size line with the client's fin staging the
`0\r\n\r\n` terminator. A request whose QUIC stream ended on its
HEADERS frame — the plain GET — renders head-only instead: no generated
framing header and no terminator, an empty upload read as "the upload
already complete" rather than a zero-length chunked body the origin
must still decode. The exchange is full duplex: the response read arms
the moment the request head is credited, so an origin that answers
early — a 4xx refusal, a 100, an echo that beats the upload's fin —
starts relaying while the upload is still streaming. The two directions
own separate staging (`upload_buf`/`upload_spill` against the
response's `chunk`/`head_buf`) and separate completions on the one
upstream socket, so send backpressure and recv backpressure park
independently. An early answer that closes the connection orphans the
upload: the proxy keeps consuming the client's stream and drops the
bytes (never a reset — the client is not accused of a request the
origin chose not to read), and the connection never parks, since bytes
the origin never read would desync the next request. A 1xx from the
origin is skipped per RFC 9110 §15.2 and never relayed. The connection
settles — parks for reuse, or closes — only when both directions are
done: the response fully relayed, the upload's fin (and terminator, for
chunked) reached the origin.

One exchange carries two deadlines, and expires on whichever comes
first. `timeouts.h3_exchange_ms` (default 10 s, `0` disables) is the
absolute budget from the exchange's begin — the dial, the send and the
receive window across the streamed response — and a leg that outlives it
is answered `504`, or, after the head went out, its stream is reset and
the witness records a `bad_gateway`. `timeouts.h3_exchange_idle_ms`
(default `0`, off) is the idle variant: any application progress in
either direction — an uploaded body piece, a parsed response head, a
relayed body chunk — resets it, so a stream that keeps moving (SSE, a
deliberate drip) is never killed by the absolute budget its longevity
would outrun. Set it to 15000-30000 for SSE endpoints; leave it off
where the absolute budget is the policy.

`max_connections` is the listener's memory knob: each session slot embeds
a fixed 256 KiB arena. The default is 64 (about 16 MiB per listener), and
the loader caps the value at 1024.

This path is deliberately narrower than the HTTP/1.1 listener: no
filters, rate limits or connection limits. It is observed like the
HTTP/1.1 traffic, though.
An h3 request earns one access-log line in the configured sink — the
same `kind:"http"` record the TCP listener writes, naming the cluster
the matched route selected, counting payload
bytes where the TCP line counts wire bytes, and naming no configured
headers yet — and its requests, responses, `502`/`504` verdicts, `503`
sheds and opened/closed sessions land in the same process counters as
the HTTP/1.1 traffic, rendering through `/metrics` and the exit tally
as the `zgix_h3_*` family: every h3 request lands in exactly one verdict
bucket — `h3_responses`, `h3_bad_gateway`, `h3_gateway_timeout`,
`h3_shed_busy`, or `h3_no_route` — the sum a deployment's h3 traffic
answers to, with `h3_no_route` the operational signal a mistyped-host
probe files under. With no `access_log` block the path stays
silent: no line, no reservation, counters only.

An `http` listener points HTTP/1.1 clients at the UDP port with an
`Alt-Svc` advertisement (RFC 7838): name the value and every proxied
final response head carries it, so a client that trusts the hint can
open the next connection over QUIC. The value is sent **verbatim** — the
operator writes the full field content, `ma=` included — and the choice
is per listener, since what sits in front of the socket decides whether
the announcement is true:

```json
{ "bind": "0.0.0.0:443", "http": { "cluster": "origin",
  "h3_advertise": "h3=\":4443\"; ma=3600" } }
```

The value must be 1–128 bytes; an empty or over-long one is refused at
load. Until a client trusts the hint, point it at the UDP port directly
(for example, `curl --http3-only https://host:443/` with a client built
for HTTP/3). For a scripted interop check, `scripts/h3-interop-client.py`
is a minimal aioquic client pinned to an IPv4 socket — aioquic's default
path opens a dual-stack IPv6 socket whose IPv4-mapped sends some hosts
(mostly observed on macOS) drop intermittently, which reads exactly like
a server-side hang; the script removes that variable:

```sh
pip install aioquic            # any venv
python3 scripts/h3-interop-client.py 4443
# -> STATUS 200 / BODY ...
```

### Routing

`"cluster"` is sugar for a single catch-all route. An `http` listener can
instead carry a route table, matched **longest-prefix within the matching
host**:

```json
{
    "bind": "0.0.0.0:80",
    "http": {
        "routes": [
            { "host": "api.example.com", "prefix": "/v2", "cluster": "api-v2" },
            { "host": "api.example.com", "prefix": "/",   "cluster": "api" },
            { "prefix": "/static",                        "cluster": "cdn" },
            { "prefix": "/",                              "cluster": "web" }
        ]
    }
}
```

A route with no `host` matches any host, and a host-specific route always
beats an any-host one. Matching uses the **canonical** path, with
percent-escapes decoded and dot-segments collapsed, and the origin receives
that same canonical path, so the router and the backend cannot disagree
about which resource was named. Structure-changing escapes (`%2F`, `%00`,
truncated escapes) are rejected with `400`. No matching route is a `404`.

#### Pinning a canary with a header

Percentage canaries are [endpoint weights](#weights): put the new version's
endpoints in the same cluster at low weight and every pick policy honours
it. A pinned canary, for a specific client, a test account or an internal
gateway's header, is a route that matches a header:

```json
"routes": [
    { "header": { "name": "X-Canary", "present": true },
      "prefix": "/", "cluster": "next" },
    { "prefix": "/", "cluster": "stable" }
]
```

Either `{ "present": true }` for any value, or `{ "equals": "..." }` for
one. Names match case-insensitively (RFC 9110); values do not. There is no
substring or regex matching.

**Host, then header, then prefix.** Every key a route states must hold, and
where several routes match, the most specific wins in that order: a
host-scoped route beats an any-host one, and within a host group a route
naming a header beats one that does not.

```json
"routes": [
    { "host": "api.example.com", "header": { "name": "X-Canary", "present": true },
      "prefix": "/", "cluster": "api-canary" },
    { "host": "api.example.com", "prefix": "/",  "cluster": "api" },
    { "header": { "name": "X-Canary", "present": true },
      "prefix": "/", "cluster": "canary" },
    { "prefix": "/", "cluster": "web" }
]
```

Those four can be written in any sequence and answer identically: the table
is sorted once at startup.

Config order decides one case. Two routes sharing a host and a prefix but
naming **different** headers are equally specific, and a request carrying
both headers matches both. The one written first wins.

A route may also carry `"access_log": false`, which suppresses the
access-log line for requests it answers — nginx's `access_log off` at a
location. Counters, metrics, admission and the traffic itself are
unchanged; the line is the only thing omitted.

Two things to know before relying on this. A request that gains or loses
the header **moves to a different cluster**, so a `hash` pick holds within
each cluster but not across the change. And the header is a routing key
*and* is forwarded, so the origin sees it and can log which side served
the request.

`CONNECT` and `TRACE` are answered `501` and never reach a backend.
`CONNECT` asks the proxy to open an arbitrary destination, which is
forward-proxy behaviour. `TRACE` echoes a request back, which is the
Cross-Site Tracing vector.

`OPTIONS` honours `Max-Forwards`. At `0` zgix answers it with `200` and an
`Allow` describing zgix itself, and never dials a backend. Above `0` the
request is forwarded with the value decremented. The field is read only
for `OPTIONS`, and CORS preflights carry no `Max-Forwards`, so ordinary
traffic is unaffected.

A request may name its authority in the request line itself,
`GET http://api.example.com/v2/x HTTP/1.1`, which is what a client sends
when it thinks it is talking to a forward proxy. That form is accepted
(RFC 9112 requires it), and the authority in the target **wins over the
`Host` header**: it is what routes, what filters match, what the access
log records, and what the origin receives as the request's `Host`. Only
`http` and `https` targets are accepted; any other scheme is a `400`.

### Clusters and load balancing

A cluster is a named set of endpoints plus how one is chosen. Endpoints
are static `IP:port` literals or
[`unix:` socket paths](#reaching-a-local-app-over-a-unix-socket), resolved
once at load; dynamic DNS is out of scope. Cluster and endpoint counts are
bounded by the config, not by a compiled ceiling, and the startup banner
prints what the endpoint tables cost.

```json
"clusters": {
    "api": {
        "endpoints": ["10.0.0.1:8080", "10.0.0.2:8080", "10.0.0.3:8080"],
        "pick": "p2c"
    }
}
```

| `pick` | behavior |
|---|---|
| `p2c` *(default)* | two weight-biased candidates; the one carrying less in-flight work wins — HTTP requests and L4 connections both count |
| `rr` | smooth weighted rotation — exact rotation at equal weights, predictable spread, useful for cache warming |
| `hash` | the same key always reaches the same endpoint — object form only, naming what the cluster is sticky on |

`pick` is either a bare policy string or an object carrying the policy and
its settings. `hash` takes only the object form, naming its key
(`source_ip`, `header` or `cookie`).

Upstream connections are pooled process-wide and reusable by any request.
A cluster with a `tls` block parks and reuses its TLS connections the same
way: a checked-out session that is still healthy skips the handshake. A
parked session the origin closed while idle is discovered on first use,
and — as on the plaintext path — that early failure takes the one free
replay on a fresh dial, which re-encrypts the still-intact request head
under the new session's keys.

#### TLS to the origin

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

The trust anchors are exactly this file; there is no system CA store. A
deployment that wants the host's bundle names it in `ca_file`.

`client_cert` and `client_key` are both or neither; naming one alone is
refused at load. The key follows the listener's rule — ECDSA P-256 or
P-384 — because both directions go through one credential loader and the
handshake runs on the event loop. A key the listener would refuse is
refused here too, at startup.

The files this block names are read once at startup. A missing or unusable
file stops the process with an error naming the path, before a port is
taken, rather than failing under traffic. `SIGHUP` does not re-read them:
it rotates listener certificates only, so changing a cluster's CA or
client pair needs a restart.

`verify` is on by default. Setting it to `false` still encrypts the
connection but authenticates nothing: any peer able to intercept the TCP
stream is accepted, and `ca_file` is ignored even when present. Use it only
on a controlled network where another layer authenticates the origin — it
never means "verify nothing" on a public link. `server_name` is still
required and still sent as SNI.

The remaining limits are deliberate, not gaps discovered in use:

- Request bodies are forwarded, chunked ones included, under the ordinary
  §7 cap and framing rules: a declared over-cap body is still `413`, and
  the body streams through the same relay discipline a plaintext origin
  uses.
- TLS upstream connections park and reuse like plaintext ones; a reuse
  skips the handshake. An `http` health check on a TLS cluster performs
  its own handshake and probes over it; a `tcp` check stays a plain
  connect, since it only wants the SYN/ACK and never speaks HTTP.
- An `Upgrade` may cross this hop. The tunnel relay encrypts and decrypts
  both ends independently, so a client side and an origin side can each
  speak TLS, and a half-close is announced with `close_notify` before the
  write half shuts down.
- A failed TLS exchange takes the same one free replay as a plaintext
  one: a stale parked session (or an early failure before any response
  byte) is retried on a fresh dial, re-encrypting the request head under
  the new session's keys. Once any request-body chunk has been pumped,
  the try is no longer reconstructible and the failure reaches the
  client.
- An `l4` listener routing to this cluster is refused at load: the relay
  is transparent and never originates TLS, so the origin would receive
  the client's bytes without a handshake in front of them.

That refusal is load-time rather than best-effort: a config that cannot
mean what it says stops with an error naming the rule.

#### Weights

An endpoint is a bare `"IP:port"` string, weight 1, or an object adding a
relative share, up to 256:

```json
"endpoints": ["10.0.0.1:8080", { "address": "10.0.0.2:8080", "weight": 3 }]
```

Every policy honours weights: a 16-core box can take four times a 4-core
box's share, a canary can start at 1-in-20 and move by editing one number,
and a pool can be drained gradually by shifting weight. A weight of `0`
**drains** the endpoint: still health-checked, never picked, not even when
everything else is ejected. At least one endpoint must hold weight, or the
config is rejected.

#### Reaching a local app over a Unix socket

When zgix runs on the same host as the application it fronts, an endpoint
can be a socket file instead of a loopback address:

```json
"clusters": {
    "app": {
        "endpoints": ["unix:/run/app.sock"]
    }
}
```

Three reasons to prefer it:

- **No ephemeral-port exhaustion.** A busy proxy in front of a local app
  burns through the loopback's ephemeral range, and dials start failing
  while the backend is healthy. A socket file has no port.
- **Filesystem permissions as the ACL.** A socket in a directory the app
  user owns is unreachable by anything else on the box, with no firewall
  rule.
- **Less work per byte.** No checksum, no loopback routing, no TCP state
  machine, on the leg that runs for every request.

The `unix:` prefix is grammar, not part of the path; what reaches the
kernel is the path you would `ls`. The path must be **absolute** and at
most 103 bytes: a `sockaddr_un` carries 108 bytes on Linux and 104 on
macOS, and 103 is the smaller minus the terminator, so one config works on
both. It must be printable ASCII with no quote or backslash, because the
address lands verbatim in every access-log line and Prometheus label,
where one control byte invalidates the whole line or scrape. A path that
breaks any of these rules is refused at load, never truncated: a shortened
path names a different socket.

Everything above the dial is unchanged. The two forms mix in one cluster,
so a migration can move one endpoint at a time. Weights, `pick`, health
checks, retries and `max_inflight` work as they do on an IP endpoint,
`hash` stickiness keys on the path, and the access log, the `endpoint`
metrics label and the startup banner print the endpoint exactly as
spelled, `unix:` included:

```json
{"upstream":"unix:/run/app.sock", ...}
```

A [`proxy_protocol`](#sending-proxy-protocol) send block still announces
the *client's* addresses; the header describes the connection that
arrived, not the leg it is written on.

A listener can take the same grammar; see
[accepting on a socket file](#accepting-on-a-socket-file).

The abstract namespace (a leading NUL) is out of scope: it has no
filesystem permissions.

#### Accepting on a socket file

`bind` takes the same `unix:` grammar, so a local process reaches zgix
through a file rather than a port:

```json
{
    "bind": "unix:/run/zgix.sock",
    "mode": "0660",
    "http": { "cluster": "app" }
}
```

The path rules are the endpoint's: absolute, at most 103 bytes, printable
ASCII with no quote or backslash. Two listeners on one path are a
duplicate, as two on one `IP:port` are.

The socket file's lifecycle:

| at startup, the path… | zgix |
|---|---|
| does not exist | creates it |
| is a socket | removes it, then creates it — a killed process must not wedge every later start |
| is anything else (file, directory, symlink) | **refuses to start** and says so |

A clean stop removes the file it made. A `SIGKILL` cannot, which is what
the second row is for. The third row keeps a typo in `bind` from deleting
anything, and a symlink is judged as itself rather than followed.

**`mode`** sets the socket's permission bits after the bind, as an octal
string. It is a string rather than a number because `0660` is not valid
JSON and `660` is decimal, and the two readings differ by a factor of
eight in the direction that widens access. Absent leaves whatever the
umask gives, which under a typical umask is world-connectable; if the
socket itself is meant to be the ACL rather than the directory holding
it, set the field.

A request arriving on a socket file has no client IP, so the loader
refuses the four things that would need one:

| rejected | because |
|---|---|
| a `forwarded` block | `X-Forwarded-For` would state an address nobody connected from |
| a filter with `match.client` | an allowlist would be comparing against a fiction |
| routing to a `hash` cluster keyed on `source_ip` | every local client would land on one endpoint while looking sticky |
| routing to a cluster with `proxy_protocol` send | the header announces source *and* destination addresses; this listener has neither |

The last two are checked against every cluster the listener can *reach*,
which on an `l4` listener includes every name in its
[SNI table](#routing-an-l4-listener-by-tls-name-sni).

Each is a startup error naming the pair. The access log states the
absence rather than hiding it:

```json
{"client":null, "upstream":"10.0.0.1:8080", ...}
```

Everything that does not depend on a client address is unchanged: routing,
header and path filters, `hash` on a header or cookie, TLS termination,
upgrades, body limits, timeouts and the shed ladder.

A `unix:` listener is not part of the `SO_REUSEPORT` scale-out (see
[Under load](#under-load)): two processes cannot bind one path. Run N
processes behind a TCP listener, or one process behind a socket file.

### Sticky sessions

`pick: {"policy": "hash", ...}` keeps clients on one backend, and `key`
names what "one client" means:

```json
"api": {
    "endpoints": ["10.0.0.1:8080", "10.0.0.2:8080"],
    "pick": { "policy": "hash", "key": "source_ip" }
}
```

It keeps **no table**. The kernel spreads one client's connections across
zgix processes by hashing the 4-tuple, so a per-process table would be
consulted by processes that never saw that client. Being a pure function
of the key and the healthy set, every process agrees without sharing
anything.

When a backend is ejected, only *its* clients move, and they return when
it recovers. `source_ip` uses all four bytes of an IPv4 address and the
/64 prefix of an IPv6 one, so stickiness survives privacy-address
rotation.

Hashing on client address has an inherent limit: NAT hides many clients
behind one address, and one heavy client cannot be split. The other two
keys exist for that case, and where even load matters more than
stickiness, use `p2c`.

The key is the *observed* client address. Behind another proxy or load
balancer every connection carries that machine's address and the whole
cluster hashes to one endpoint; see
[Receiving PROXY protocol](#receiving-proxy-protocol) for how an `l4`
listener recovers the real client.

#### Sticky on a header

```json
"pick": { "policy": "hash", "key": "header", "name": "x-tenant" }
```

Hashes the named header's value: stickiness on an identity the client
states, such as a tenant, a user id or an API key, which survives NAT. A
request without the header is placed by load like a `p2c` pick. Only
`http` listeners can route to a header- or cookie-keyed cluster; an `l4`
listener never parses a request.

#### Sticky on a cookie

```json
"api": {
    "endpoints": ["10.0.0.1:8080", "10.0.0.2:8080"],
    "pick": { "policy": "hash", "key": "cookie", "name": "srv_id" }
}
```

The named cookie carries the assignment itself: a 16-hex **endpoint tag**
zgix mints from the endpoint's address, stable across restarts, processes
and config reordering. A request with no cookie is placed on the calmest
backend and the response sets one (`Set-Cookie: srv_id=<tag>; Path=/;
HttpOnly`, a session cookie with no expiry, plus `; Secure` when the
listener terminates TLS). A request whose tag names a healthy,
under-capacity backend goes there and is **not** re-stamped. A tag naming
an ejected, drained or removed backend is re-placed and the response
re-announces. Every user behind one NAT address carries their own
assignment.

Pick a cookie name the application does not use; zgix adds its
`Set-Cookie` beside the origin's, never in place of them. The tag is not
signed: a forged cookie can only choose which of *your* backends serves
that client.

Three counters partition a cookie cluster's responses:
`zgix_l7_sticky_followed`, `..._assigned` and `..._repicked`. A rising
repick rate means backends are flapping under a sticky population.

### Health checks

Per cluster and opt-in. A prober sweeps every checked endpoint, several at
a time. `fall` consecutive failures eject an endpoint from balancing and
close its pooled connections; `rise` consecutive successes restore it.

```json
"api": {
    "endpoints": ["10.0.0.1:8080", "10.0.0.2:8080"],
    "check": { "type": "http", "path": "/healthz", "expect_status": 200 }
}
```

`type` is `tcp` (the port accepts) or `http` (a path answered the expected
status). Defaults: `fall` 3, `rise` 2, `expect_status` 200, and a probe
budget of `timeouts.connect_ms` unless `timeout_ms` overrides it.
`timeouts.health_interval_ms` (default 2000) paces the gap between sweeps.

On a cluster with a `tls` block, an `http` check completes the handshake
and sends the probe encrypted, judging the status exactly as it does in
the clear. A `tcp` check stays a plain connect: it only wants the SYN/ACK
and never speaks HTTP. Probes draw their TLS engine from the same pool as
data traffic; if every engine is serving a request, that probe is skipped
rather than recorded as a failure, so saturation cannot eject a healthy
endpoint.

If *every* endpoint in a cluster is ejected, zgix fails open and uses them
all. Routing nowhere would turn a probe verdict into an outage.

### Passive ejection

A `tcp` check passes whenever the kernel accepts, and the kernel accepts
from the backlog even when the application behind it never does. A wedged
process, an exhausted thread pool or a GC-stalled backend looks healthy to
it while every real request times out. An `http` check catches that but
needs a path you have to know. `passive_ejection` uses the traffic you
already have:

```json
"api": {
    "endpoints": ["10.0.0.1:8080", "10.0.0.2:8080"],
    "passive_ejection": { "fall": 5, "recovery_ms": 30000 }
}
```

`fall` consecutive **failed requests** eject the endpoint. A failure is a
dial that failed, or an exchange that returned no response byte before
its deadline. A `5xx` response is *not* a failure: a bad deploy answering
500s is a software bug, and ejecting for it would take out a whole
cluster. Any response resets the count.

After `recovery_ms` the endpoint is let back in and traffic judges it
again; if it is still dead, `fall` more failures eject it once more.
Passive detection finds the failure and active checks find the recovery,
so a cluster that would rather re-test with one probe than with `fall`
real requests should configure both.

Defaults: `fall` 5, higher than a probe's 3 because real traffic carries
transient failures a probe never sees, and `recovery_ms` 30000. Ejection,
fail-open and the closing of pooled connections work exactly as they do
for active checks.

If no cluster has either kind of detection, the startup banner says so:

```
config  1 listener(s), 3 cluster(s), 0 error page(s), access log off, 1 cluster(s) without failure detection
```

The line is informational. A multi-endpoint cluster with no checks is
reasonable behind a service mesh, or when the endpoints are themselves
load balancers. A cluster is counted only when two of its endpoints are
reachable, so a single-endpoint cluster never is, nor one whose second
endpoint is drained with `"weight": 0`.

### Per-endpoint in-flight cap

`max_inflight` caps the concurrent work zgix will ask of **one endpoint**.
It is per server, so a three-endpoint cluster with a cap of 100 admits up
to 300, the same shape as HAProxy's `server ... maxconn`.

```json
"api": {
    "endpoints": ["10.0.0.1:8080", "10.0.0.2:8080"],
    "max_inflight": 100
}
```

An endpoint at its cap is skipped, so requests keep flowing while any
endpoint has room. When *every* endpoint is full zgix refuses: an HTTP
request is answered `503` and an L4 connection is closed, since a byte
relay has no way to say "try later". Absent, a cluster is uncapped.

This is the one limit that fails **closed**. An ejected cluster means zgix
does not know whether the endpoints work, so trying is better than
refusing; a capped one means zgix knows they are full.

Both protocols count against the same figure: an in-flight HTTP request
and a live L4 connection are each one unit of work.
`zgix_l7_shed_endpoint_inflight` and `zgix_l4_shed_endpoint_inflight`
count refusals, kept apart from `zgix_l7_shed_upstream_slots`, which means
zgix ran out of its own slots and wants a wider pool rather than a busier
backend.

### Rate limiting

Per listener and opt-in: a token bucket keyed by the client's IPv4 `/32`
or IPv6 `/64` (the same identity `client` filters and `source_ip` hashing
use). Above the rate, HTTP requests are answered `429`; the connection
closes because the body may still be unread.

```json
"listeners": [
    { "bind": "0.0.0.0:443", "http": {
        "cluster": "api",
        "rate_limit": { "requests": 100, "window_ms": 1000, "burst": 200 } } }
],
"limits": { "rate_limit_entries": 4096 }
```

| field | meaning |
|---|---|
| `requests` | tokens refilled per `window_ms` (1..1,048,576) |
| `window_ms` | refill window (1..`timeout_ms_max`) |
| `burst` | bucket capacity; optional, defaults to `requests`, must be at least `requests` |
| `limits.rate_limit_entries` | table slots (32 B each), **required** when any listener has a limit, refused without one |

The table is fixed at load and probed at most eight slots deep: no
allocation per request and no unbounded scan. Keying is per address, not
per listener, so one client hitting two listeners shares a bucket. A
table with no free slot within the probe **fails open** and increments
`zgix_l7_rate_limit_full` — a rising count is the signal to widen
`rate_limit_entries`, not an outage. `zgix_l7_rate_limited` counts the
`429`s. A `unix:`-bound listener has no client address and is inert.

Limit the head only: malformed or oversized requests are answered before
this check, and the bucket is consumed by any admitted request, including
one a [WAF](#waf-lite-denylist) then refuses.

### Connection limits

A listener may also cap how many connections one client holds at once.
The token bucket above answers "too many requests"; this answers "too
many sockets", and the two are independent:

```json
"listeners": [
    { "bind": "0.0.0.0:443", "http": {
        "cluster": "api",
        "conn_limit": { "max": 256 } } }
],
"limits": { "conn_limit_entries": 4096 }
```

| field | meaning |
|---|---|
| `max` | concurrent connections one client identity may hold (1..11457) |
| `limits.conn_limit_entries` | table slots (24 B each), **required** when any listener has a cap, refused without one |

A connection is counted at its **first admitted request**, not at
accept: after a PROXY protocol header is parsed is the first point a
listener knows the real client. Every request on a keep-alive connection
shares that one count. A request that would take the client past `max`
is answered `503` and the connection closes, because the request body may
still be unread.

One request that fits but whose identity the table cannot place (no free
slot within eight probes) **fails open** and increments
`zgix_l7_conn_limit_full`; `zgix_l7_conn_limited` counts the `503`s. As
with rate limiting, a rising `conn_limit_full` is the signal to widen
`limits.conn_limit_entries`, not an outage. Connections that never send a
request are bounded by the global `conn_slots` pool instead.

### Client address

One address is used everywhere it matters: the `source_ip` hash pick, a
filter's `client` match, the access log. Three blocks decide what it is
and who hears it. A listener learns it and states it; a cluster states it
to its origins. A deployment that needs one usually needs another: learn
the address first, then pass it on in whichever form the origin can read.

#### Receiving PROXY protocol

Behind a load balancer, zgix sees only the balancer. That breaks more than
logging: a `source_ip`-keyed hash pick reads the client address, so every
connection hashes alike and the whole fleet lands on one endpoint. An `l4`
listener can instead require each connection to open with a PROXY protocol
header, v1 or v2, which is what AWS NLB, GCP and HAProxy emit:

```json
{
    "bind": "0.0.0.0:5432",
    "l4": {
        "cluster": "postgres",
        "proxy_protocol": { "mode": "require" }
    }
}
```

`require` is the only mode. A listener that accepted a header whenever one
happened to show up would let any client choose its own address, and with
it its own sticky backend and its own access-log lines. The PROXY protocol
spec forbids that of receivers, and HAProxy gates the same feature behind
an explicit `accept-proxy`. A `require` listener closes any connection
that does not open with a valid header, so it is unusable by anything
except the proxy in front of it. Turn it on only where the listener is
reachable exclusively through that proxy.

What the header announces is what zgix believes everywhere the client
address is used. A header that announces nothing (v1 `UNKNOWN`, v2
`LOCAL`, the shapes a balancer's own health checks arrive in) is accepted
and keeps the observed peer. Headers are capped at 512 bytes: v2 TLVs
within the cap are skipped, and a declared length past it is refused at
once. Header bytes never count toward the log's `bytes_in`.

`zgix_l4_proxy_header_accepted` and `zgix_l4_proxy_header_invalid` count
the verdicts. A rising `invalid` means something other than the configured
proxy is reaching the listener. `http` listeners reject the block: the L7
receive phase does not exist yet.

#### X-Forwarded-For

Without this, everything *behind* zgix sees zgix: origin logs, IP
allowlists, per-client rate limits. An `http` listener can add
`X-Forwarded-For`:

```json
{
    "bind": "0.0.0.0:80",
    "http": {
        "cluster": "web",
        "forwarded": { "mode": "replace" }
    }
}
```

There is no default mode. Each answer is a security bug in the other's
position, and zgix cannot tell from the inside which position it is in.

| mode | behaviour | use when |
|---|---|---|
| `replace` | state the peer zgix observed, discard any inbound chain | **at the edge** — an inbound chain is client-controlled there, so honouring it lets a caller pick the address your allowlists then trust |
| `append` | extend the inbound chain with the observed peer | **only behind proxies you own** — anywhere else this is the forgery above, appended to |

Omit the block and the header is passed through untouched.

The same block can also write the two companion headers nginx deployments
expect. Both are off by default, because a deployment that does not read
them should not be handed a second spelling of the same fact:

```json
"forwarded": { "mode": "replace", "real_ip": true, "proto": true }
```

- `real_ip` writes `X-Real-IP` with the same observed peer as
  `X-Forwarded-For` — the PROXY-announced address on a listener that
  accepts one, never an inbound header.
- `proto` writes `X-Forwarded-Proto` as `http` or `https` from whether
  this listener terminates TLS.

When either is written, inbound copies of that header are suppressed for
the same reason as `X-Forwarded-For`: two spellings that disagree is the
disagreement the header exists to prevent. Filters may not set
`X-Forwarded-For`, `X-Real-IP` or `X-Forwarded-Proto`; the loader rejects
them.

The carried chain is bounded. A chain grows by an address per hop and
nothing in HTTP caps it, so past `forwarded_chain_bytes_max` (512) it is
dropped *whole*, leaving the line stating only the observed peer. A
truncated chain would read as complete. `zgix_forwarded_chain_dropped`
counts that.

#### Sending PROXY protocol

An origin behind an `l4` relay has no header to read an address from, so
the only way to tell it who connected is to open the upstream connection
with a PROXY protocol header. A *cluster* opts in, because this states
what its origins expect, the same unit as HAProxy's `send-proxy`:

```json
"clusters": {
    "postgres": {
        "endpoints": ["10.0.0.1:5432"],
        "proxy_protocol": { "send": "v2" }
    }
}
```

`send` is `v1` (text, readable in a tcpdump) or `v2` (binary, what cloud
load balancers speak). The header names the client zgix believes, which
behind a `require` listener is the client the *fronting* proxy announced,
so a chain of proxies carries one identity end to end.

The header is per *connection*, with two consequences:

- Only `l4` listeners may route to a sending cluster. A pooled HTTP
  upstream is shared across clients, and a header naming one client would
  lie to every other, so the loader rejects the pairing. For HTTP origins,
  use [`forwarded`](#x-forwarded-for) instead.
- Health probes do not send the header. A `tcp` check is unaffected, since
  it proves the port accepts and sends nothing, but an `http` check
  against a sending cluster probes bare. If the origin strictly requires
  the header, use `tcp` checks there.

`zgix_l4_proxy_header_sent` counts headers staged, one per dialed
connection to a sending cluster.

### Filters

An `http` listener can carry `request_filters`, a list of rules evaluated
top-down against each request. Each rule has a match predicate, where an
absent field matches anything, and a list of actions applied in order.
Nothing caps the list but the file you write.

Order decides. The first terminal action a matching rule carries
(`reject`, `redirect`, `respond` or `allow`) ends the walk, and no rule
beneath it is read. The first three answer the request; `allow` forwards
it. Write the specific rule above the general one. This is the opposite
of [routes](#routing), which are sorted by specificity at load.

```json
"request_filters": [
    {
        "match": {
            "path_prefix": "/admin",
            "headers": [{ "name": "X-Internal", "present": true }]
        },
        "actions": [{ "header_set": { "name": "X-Role", "value": "admin" } }]
    },
    {
        "match": { "path_prefix": "/admin", "client": ["203.0.113.0/24"] },
        "actions": [{ "reject": 403 }]
    },
    {
        "match": { "method": ["GET"], "host": "cdn.example.com" },
        "actions": [{ "rewrite_prefix": { "from": "/static", "to": "/" } }]
    }
]
```

Match on `method`, `host`, `path_prefix`, `path_contains`, `query_contains`,
`query_prefix`, header predicates (`present`, `equals`, `contains`), and
`client`, a list of CIDR ranges the connection's address must fall inside.
Actions are `reject` with a status, `redirect`, `respond` (answer from a
configured body), `allow` (forward and stop reading rules), `header_set`,
`header_add`, `header_remove`, and `rewrite_prefix`. The three new
predicates are ASCII case-insensitive; `query_contains`/`query_prefix` see
the raw query with no percent-decoding, and `path_contains` sees the same
canonical path routing uses.

Only `reject`, `redirect`, `respond` and `allow` end the walk. A rule
whose actions are all edits, such as the `header_set` above or a
`rewrite_prefix`, records what the render should do and evaluation
carries on, so an edit never shields a request from a `reject` written
beneath it. An `allow` does, which is how an allowlist is written; see
[matching the client address](#matching-the-client-address).

Rules compile into immutable tables at load and are interpreted with
bounded loops: no plugins, no scripting, nothing that can allocate or run
unbounded. A rewrite changes only what is *forwarded*. Routing already
chose the cluster from the original path, so a rewrite never re-routes.

#### WAF-lite denylist

A listener-level literal denylist, evaluated once per request before the
filter walk. A hit is answered with the configured status and never
routed or dialed; a filter `allow` cannot exempt it.

```json
"http": {
    "cluster": "api",
    "waf": { "deny": ["union select", "<script", "../"], "status": 403 }
}
```

- `deny` is 1..64 literals, each 1..256 bytes, matched ASCII
  case-insensitively against the canonical path, the raw query, and every
  header **value**.
- `status` is `403` by default and may be `400`, `403`, `404` or `429`
  (the static reject set).
- `zgix_l7_waf_blocked` counts hits.

It is deliberately head-only: no body inspection, no percent-decoding, no
regex, no Unicode folding, and no provenance for a substring. Those are
bypass surfaces and false-positive surfaces at once — a benign `select`
in a query parameter is refused like an injection. Use it as one layer
beside strict request parsing, CIDR rules and [rate limiting](#rate-limiting),
not as a replacement for a full WAF. Body scanning is not implemented.

#### Matching the client address

`client` is a list of CIDR ranges the connection's address must fall
inside: any-of across the list, conjoined with the rest of the match. On
its own it refuses a range:

```json
"request_filters": [
    { "match": { "path_prefix": "/admin", "client": ["203.0.113.0/24"] },
      "actions": [{ "reject": 403 }] }
]
```

With `allow` it admits one range and refuses everyone else. `/admin` from
the office ranges and nowhere else is two rules whose order is the whole
rule:

```json
"request_filters": [
    { "match": { "path_prefix": "/admin",
                 "client": ["10.0.0.0/8", "192.168.1.0/24"] },
      "actions": [{ "allow": true }] },
    { "match": { "path_prefix": "/admin" }, "actions": [{ "reject": 403 }] }
]
```

`allow` answers nothing and edits nothing. It forwards the request and
stops the walk, so the office ranges never reach the `reject` beneath and
everyone else does. `true` is the only value it takes.

> [!IMPORTANT]
> The rule that admits must be terminal. A `header_set` in its place is
> an edit, and edits do not stop the walk, so the `reject` beneath would
> still answer `403` to the office too. Tagging a range for the origin to
> judge is a useful idiom, but it is a rule with no rule beneath it:
>
> ```json
> "request_filters": [
>     { "match": { "path_prefix": "/admin", "client": ["10.0.0.0/8"] },
>       "actions": [{ "header_set": { "name": "X-Internal", "value": "1" } }] }
> ]
> ```

The address matched is the one zgix believes: the TCP peer, or the
[PROXY-protocol-announced client](#receiving-proxy-protocol) on a
listener that requires the header. Never an `X-Forwarded-For` chain,
which any client can write. Prefixes run to `/32` for IPv4 and `/64` for
IPv6 (the same rule sticky hashing uses), the `/len` is mandatory, and
host bits past the prefix are rejected: `10.0.0.1/8` is a typo for one of
two different ranges, and zgix will not guess which.

#### Redirects

The two most common edge rules are one action each. Both belong on the
plaintext `:80` listener: a request that arrived over TLS and is sent back
to `https://` is a loop, and since the scheme is what the rule states
rather than what the hop was, only the config can keep the two apart.

```json
"request_filters": [
    { "match": { "host": "www.example.com" },
      "actions": [{ "redirect": { "status": 308, "scheme": "https",
                                  "host": "example.com" } }] },
    { "actions": [{ "redirect": { "status": 301, "scheme": "https" } }] }
]
```

The apex rule is written first because the rule under it matches
*everything*: reversed, `www.example.com` takes the catch-all's 301 to its
own name and never reaches the 308. A bare catch-all shadows every rule
beneath it, so a listener that redirects is usually a listener that does
nothing else. It still needs a `cluster` or `routes` the loader can check,
but filters run before routing, so nothing is ever dialed.

A composed target replaces the scheme, which is required because behind a
TLS terminator every hop zgix sees is plaintext, and optionally the host.
The request's own path and query are carried through. A fixed `location`
is the other form, sent verbatim. Statuses are `301`, `302`, `307`, `308`.
Redirects count as `zgix_l7_redirected` and log as `redirected`, separate
from rejects, so refused traffic and relocated traffic never blur.

#### Response filters

`response_filters` edits the origin's response on the way out: add
`Strict-Transport-Security`, strip `Server`, advertise a retry on 5xx.

```json
"response_filters": [
    { "actions": [
        { "header_remove": "Server" },
        { "header_set": { "name": "Strict-Transport-Security",
                          "value": "max-age=63072000" } }
    ] },
    { "match": { "status_class": "5xx" },
      "actions": [{ "header_set": { "name": "Retry-After", "value": "1" } }] }
]
```

A response rule matches on `status` (exact codes), `status_class`
(`"1xx"` through `"5xx"`), and response-header predicates with the same
`present`, `equals` and `contains` vocabulary. Its actions are the three
header verbs only. `reject`, `allow` and `rewrite_prefix` are request-side
ideas, and the loader says so by name if you reach for them here.

The same guardrails hold in both directions: filters may not touch the
headers zgix owns (`Content-Length`, `Transfer-Encoding`, `Connection` and
the hop-by-hop set, `X-Forwarded-For`), and a response head that no
longer fits after edits is answered `502`. Responses zgix generates itself
(`404`, `503`, filter rejects, a `respond` action's body) are not origin
responses and carry no edits.

### Response bodies

Every status zgix sends itself is empty by default. `bodies` names content
once, from a file read at startup or inline for one-liners, and anything
that serves content references it by name:

```json
"bodies": {
    "maintenance": { "file": "/etc/zgix/503.html", "content_type": "text/html; charset=utf-8" },
    "not-found":   { "file": "/etc/zgix/404.html", "content_type": "text/html; charset=utf-8" },
    "robots":      { "inline": "User-agent: *\nDisallow: /private\n",
                     "content_type": "text/plain" }
},
"error_pages": { "404": "not-found", "503": "maintenance" }
```

Each name is read once and rendered once, however many places serve it,
so the same maintenance page on `error_pages` and three filter rules is
one buffer. A name that does not exist is a startup error. `content_type`
is required; nothing is guessed from a filename. Files are read at
startup like the rest of the config, so **changing one needs a restart**.

`error_pages` accepts only the statuses zgix actually sends: `400`,
`403`, `404`, `408`, `413`, `414`, `429`, `431`, `501`, `502`, `503`,
`504`. A page for anything else is refused at load.

Every response zgix answers *itself* (those pages, the empty defaults, the
redirects) carries a `Date` and `Server: zgix`. Responses from an origin
are forwarded with the origin's own headers and gain neither, so
`Server: zgix` on a `503` tells you the proxy raised it and the backend
was never asked.

Bodies live in memory. A `503` is raised because something ran out, so an
error page whose delivery needed a resource would fail exactly when it is
needed. The cost is capped per body, counted in the startup banner, and
paid once per process.

**Listing a status is the opt-in, including for sheds.** Leave `503` out
and overload answers an empty `503` as before; put it in and the page is
served. There is no second switch.

#### Serving a body directly

```json
"request_filters": [
    { "match": { "path_prefix": "/robots.txt" },
      "actions": [{ "respond": { "status": 200, "body": "robots" } }] },
    { "match": { "host": "old.example.com" },
      "actions": [{ "respond": { "status": 503, "body": "maintenance" } }] }
]
```

`respond` answers from a body instead of forwarding: a `robots.txt`, a
maintenance window, a health target the balancer serves itself. It stops
the request like `reject` and `redirect` do, but counts as
`zgix_l7_responded` and logs as `responded`, since refusing traffic and
serving it are different facts. Statuses are `200` plus the error set.

#### Precompressed static answers

Every configured body — `respond` and `error_pages` alike — is gzipped
once at load. When the request's `Accept-Encoding` accepts gzip (an
explicit `gzip` or `*`; `q=0` declines; q-values are parsed), the answer
is sent with `Content-Encoding: gzip`, `Vary: Accept-Encoding` and the
compressed length; otherwise the plain body is sent unchanged. `HEAD`
gets the selected variant's headers without a body.

This is static-answer compression only; see the next section for the one
case where a proxied response is compressed.

#### Compressing proxied responses

A listener may opt in to gzip for proxied answers as well:

```json
"http": {
    "cluster": "api",
    "compress": { "min_bytes": 1024 }
}
```

- `min_bytes` (default 1024) is the floor; smaller bodies are sent
  unchanged, since the gzip framing alone would cost more than it saves.
- Compression applies only when the whole body arrived in the same read
  as the response head (a small response from a fast origin), status is
  `200`, `Content-Length` is known, `Content-Type` is text-like
  (`text/*`, JSON, JavaScript, XML, SVG, NDJSON), no `Content-Encoding`
  is already set, and `Cache-Control` does not say `no-transform`.
- The ceiling is 64 KiB. Anything larger, chunked, `until_close`, an
  interim response, a `HEAD`, or a body that took more than one read is
  streamed through untouched.
- A compressed answer carries a recomputed `Content-Length`,
  `Content-Encoding: gzip` and `Vary: Accept-Encoding`; a client that did
  not offer gzip gets the original bytes.

The compressor is one buffer allocated at startup and counted in the
banner, so there is no per-request allocation.

This is not full streaming compression: Zig's `std.compress.flate`
exposes no flush, so a pump that reads and writes one chunk at a time
cannot emit a valid gzip stream incrementally. Streaming responses (SSE,
large bodies, chunked) therefore pass through uncompressed — front zgix
with a CDN, or compress at the origin, when those need it.

### Timeouts

```json
"timeouts": {
    "connect_ms": 5000,
    "head_ms": 10000,
    "idle_ms": 60000,
    "drain_deadline_ms": 10000,
    "max_lifetime_ms": 0,
    "request_ms": 0,
    "h3_exchange_ms": 10000,
    "tunnel_ms": 3600000,
    "health_interval_ms": 2000
}
```

The whole block is optional, and so is every field in it; the values
above are the defaults. An explicit `0` disables the four caps. For
`connect_ms` and `idle_ms` it is rejected, since a zero-length dial or
idle budget is a mistake rather than a policy.

> [!WARNING]
> `connect_ms` must be **strictly below** `head_ms`, which must be at or
> below `idle_ms`, or the config is rejected at load. zgix keeps one timer
> per connection and never moves it earlier once armed. The first deadline
> is the dial budget and the dial's completion re-arms it to the idle one,
> so an idle budget that does not exceed the dial budget would reap late
> instead of taking effect. This bites when only one field is tuned:
> raising `connect_ms` past the default 60 s `idle_ms` is rejected just
> the same. `head_ms` sits between them for the same reason: it is
> re-based down from the idle deadline when the client's first byte
> lands, and down again to `connect_ms` at the dial.

| field | default | meaning |
|---|---|---|
| `connect_ms` | `5000` | per-try upstream connect budget |
| `head_ms` | derived | budget for reading one request head — what a slowloris meets, and is answered `408` for. A connection that has said nothing at all is not under it, so a monitoring probe that connects and leaves earns silence. 10 s, clamped between `connect_ms` and `idle_ms` so it never changes a config that predates it |
| `idle_ms` | `60000` | how long a connection may stay quiet — between requests, or before its first byte |
| `drain_deadline_ms` | `0` | how long a `SIGTERM` drain waits before reaping stragglers; `0` waits for the last connection |
| `max_lifetime_ms` | `0` | absolute connection-age cap regardless of activity; `0` disables |
| `request_ms` | `0` | cap on one L7 exchange, **not** refreshed by activity — bounds a request that is merely slow, where `idle_ms` only bounds one that has stalled; `0` disables |
| `h3_exchange_ms` | `10000` | cap on one HTTP/3 upstream exchange — the h3 listener's connect, send and receive window across the streamed response, which the TCP-side `request_ms` never reaches; absolute, not refreshed by progress, so streaming large bodies wants it raised; absent keeps the built-in 10 s, `0` disables |
| `h3_exchange_idle_ms` | `0` | idle cap on one HTTP/3 exchange: any progress in either direction (upload piece, response head, relayed chunk) resets it, so long-lived streams (SSE) survive the absolute cap; `0` disables. SSE wants 15000-30000 |
| `tunnel_ms` | `3600000` | whole life of a [tunnelled upgrade](#tunnelled-upgrades-websocket), replacing the idle, request and lifetime deadlines once one is established; 1 s to 1 day, and `0` is **not** legal |
| `health_interval_ms` | `2000` | pause between health-probe sweeps |
| `loop_watchdog_ms` | absent | kill this process if its event loop completes nothing for this long. Absent is off; 2 s minimum |

`loop_watchdog_ms` is the one deadline here that is not about a
connection. Every other row is a timer the event loop delivers, so none
of them can bound the loop itself: a loop parked in a blocking call
delivers nothing, including the timer that would have reported it, and
what you see is a process that is alive, passing health checks, holding
its listeners and answering nothing. Set this and the kernel gets a bound
the loop cannot silence: an `alarm(2)`, pushed out by a tick the loop has
to deliver, which fires only when the loop stops. The process writes one
line to stderr and exits **6**, so a supervisor replaces it.

It is off unless you name a number, because what counts as a stall
depends on the box (one that swaps has longer legitimate pauses) and a
false positive restarts a healthy proxy. Under `SO_REUSEPORT` it matters
most: the kernel keeps hashing new connections onto a stalled process, so
one that exits is replaced while one that hangs takes its share of the
group down with it.

`drain_deadline_ms` defaults to waiting indefinitely. nginx, HAProxy and
Caddy all wait forever by default, Traefik picks 10 s and Envoy 600 s.
Whatever sent the signal already owns the upper bound (systemd's
`TimeoutStopSec`, Kubernetes' `terminationGracePeriodSeconds`) and ends
the wait with `SIGKILL`. Set a number here when you want zgix to give up
before your platform does.

### Limits

Optional. The compiled constants are hard ceilings; this block sizes the
actual pools anywhere from 1 up to them, so a small deployment neither
reserves nor demands the ceiling's resources. The two conditional keys,
`tls_engines` and `tunnels`, are absent below: each is refused unless the
feature it sizes is configured. Both are described further down.

```json
"limits": {
    "conn_slots": 4096,
    "relay_buffers": 4096,
    "upstream_slots": 4096,
    "head_buffers": 1024,
    "upstream_head_buffers": 512,
    "head_buffer_bytes": 16384,
    "rate_limit_entries": 4096,
    "conn_limit_entries": 4096
}
```

The defaults are lean: 1386 connection slots, 1386 relay buffer pairs,
1311 upstream slots, roughly 34 MiB of pools, sized to start under a stock
4096 `RLIMIT_NOFILE`. The ceiling is 11457 of each. Raising the pools
raises the file-descriptor demand, which zgix asserts against
`RLIMIT_NOFILE` at startup rather than discovering as `EMFILE` later.

`head_buffers` and `upstream_head_buffers` bound *request heads in flight*
rather than open connections. Idle keep-alive connections and parked
origin connections hold no head buffer, so these default to their
never-shedding ceilings (`conn_slots` and `upstream_slots`) and are the
knobs a keep-alive-heavy deployment trades down for memory.
`head_buffer_bytes` sizes every head buffer and is therefore the largest
HTTP head accepted; oversize requests are answered `414` or `431`. Raise
it for big-cookie or JWT traffic. 1 KiB to 1 MiB, default 8 KiB.

`tls_engines` bounds *TLS sessions in flight*, handshaking or terminated,
and is zero unless some listener has a `tls` block. It decides what a TLS
deployment costs: an engine is by far the largest per-connection object
zgix holds, about 111 KiB plus a 32 KiB plaintext buffer, so 1024 of them
is roughly 170 MiB. It defaults to your connection slots capped at 1024,
and the startup banner prints the total. Lower it if that is more
concurrent TLS than you serve.

`tunnels` bounds concurrent
[tunnelled upgrades](#tunnelled-upgrades-websocket) and is zero unless
some listener names an `upgrades` allowlist, in which case it is
**required**, since no default can be derived for it. Each costs one
relay-buffer pair — 32,808 bytes at the 16 KiB default, 33,330 when a
`tls` cluster widens both halves — held for the tunnel's whole life,
which is why they are reserved apart from `relay_buffers`.

`rate_limit_entries` sizes the process-wide client-identity table used by
[rate limiting](#rate-limiting). It is **required** when any `http`
listener carries a `rate_limit` block and refused without one; 1 to
1,048,576 entries at 32 bytes each (32 KiB per thousand). One table
serves every listener, so two limits with different rates share a bucket
for the same client.

`conn_limit_entries` sizes the process-wide table used by
[connection limits](#connection-limits). It is **required** when any
`http` listener carries a `conn_limit` block and refused without one; 1
to 1,048,576 entries at 24 bytes each. The same table serves every
listener, so a client's count is shared: a connection accepted by one
listener consumes capacity against its cap on all of them, like the
rate limiter's bucket.

`keepalive_requests` lives on an `http` listener beside `max_body_bytes`,
not in `limits`, because it reserves nothing and states policy. It bounds
how many requests one client connection may serve: **1000 by default**,
nginx's figure, and `0` is unlimited. It is the one bound that reaches a
*busy* connection. `idle_ms` reaps one that stops speaking and
`max_lifetime_ms` one that has been open too long, but neither touches a
connection that keeps asking, which is the one holding a conn slot and,
on every request, a head buffer and an upstream lease. Past the cap the
next response announces `Connection: close`, never a silent reset, and the
client reconnects. `zgix_l7_keepalive_requests_capped` counts it, and only
where the cap is the *binding* reason, so a rising count is the cap
working rather than churn it coincided with.

A parked *upstream* connection is not capped, where nginx caps both. It
is shared across clients and carries the reuse the design rests on, and
the occupancy this bounds is a client's, not an origin's. An origin that
wants its own bound can announce it, and zgix honours what an origin says
about persistence.

`cq_fill_eighths` trades connection ceiling for `io_uring`
completion-queue burst headroom; `access_log_buffer_bytes` sizes the
access log's staging buffers. What zgix does when one of these pools runs
out is [Under load](#under-load).

## Observability

### Metrics

An optional listener serves Prometheus exposition text: every shed rung,
every lifecycle counter, and live pool-occupancy gauges. The experimental
HTTP/3 path renders there too: the global `zgix_h3_*` counter family
(requests, responses, the `bad_gateway`/`gateway_timeout`/`shed_busy`/
`no_route` verdicts, session opens and closes) plus, after the labeled
breakdown, one row per configured h3 listener — live sessions, cumulative
requests and relayed responses, and the parked keep-alive pool, each
labeled by the listener's bind. The exit tally carries the global family;
the per-listener rows are the scrape's alone.

Four inventory families follow, the `*_info` convention — a constant-1
gauge whose information lives in the labels — giving a control panel its
site/application 清单 view straight off the scrape:

```
zgix_info{version="0.9.0"} 1
zgix_listener_info{bind="0.0.0.0:443",kind="http",routes="12"} 1
zgix_route_info{listener="0.0.0.0:443",host="api.example",prefix="/api",header="x-canary",cluster="api"} 1
zgix_endpoint_info{cluster="api",endpoint="10.0.0.1:8080"} 1
```

`kind` is the listener's protocol (`http`, `l4`, `h3`; TLS termination
does not rename an http listener). A route's `host` and `header` labels
appear only when the route names them — an absent label means "any", the
Prometheus convention — and `header` carries the predicate's name. h3
listeners' routes share `route_info`, disambiguated by the `listener`
label; an l4 listener's synthetic admission route is not path routing and
stays out. Labels are prebuilt at startup and the render bound is priced
over the same walks, so the scrape stays zero-allocation like everything
else on this endpoint.

```json
"admin": { "bind": "127.0.0.1:9100" }
```

One scrape is served at a time from a slot reserved outside the data-path
pools, so a scrape and a request can never shed one another. This listener
is the only way to read live counters; no signal prints them, because a
second snapshot on one stream invalidates the first.

The gauges matter as much as the counters: a `shed_*` counter only moves
once a wall is hit, while `zgix_conn_slots_in_use` against
`zgix_conn_slots_capacity` shows the approach.

The scrape also says **which backend**, per cluster and endpoint:

```text
zgix_endpoint_responses{cluster="api",endpoint="10.0.0.1:8080"} 4182
zgix_endpoint_connect_failed{cluster="api",endpoint="10.0.0.2:8080"} 17
zgix_endpoint_health_down{cluster="api",endpoint="10.0.0.2:8080"} 2
zgix_endpoint_healthy{cluster="api",endpoint="10.0.0.2:8080"} 0
```

Dial failures, responses served and the health transitions
(`endpoint_health_down` and `_up`) carry both labels. The "every endpoint
was full" sheds carry only `cluster`, since no single endpoint was full.
Two gauges read live state: `zgix_endpoint_inflight` is the level the
balancer compares, and `zgix_endpoint_healthy` is the prober's current
verdict, rendered for health-checked clusters only. Each labeled family
sums to the bare process total it breaks down, an identity the simulator
asserts on every seed. Label cardinality is bounded by the config
(endpoints and cluster names, never request data), and the startup banner
prices what the labels and their render buffers cost.

#### Rate, Errors, Duration

Two families give a scrape the rest of the RED triad:

```text
zgix_cluster_responses{cluster="api",class="2xx"} 4182
zgix_cluster_responses{cluster="api",class="5xx"} 17
zgix_cluster_duration_seconds_bucket{cluster="api",le="0.005000000"} 3910
zgix_cluster_duration_seconds_bucket{cluster="api",le="+Inf"} 4199
zgix_cluster_duration_seconds_sum{cluster="api"} 12.884901888
zgix_cluster_duration_seconds_count{cluster="api"} 4199
```

`cluster_responses` is the status the client actually received, classed.
Without it, only statuses the proxy generated had counters (the `shed_`
ladder, `l7_bad_gateway`, `l7_gateway_timeout`), and an origin returning
`500` to every request showed up only in the access log.

`cluster_duration_seconds` is a standard Prometheus histogram, so
`histogram_quantile` works on it directly.

Both are labelled by **cluster**, not endpoint. The per-endpoint families
are what make a large deployment's exposition large, and per-endpoint
`5xx` is already acted on by [passive ejection](#passive-ejection).
Cluster is the granularity that answers "which backend got slow" without
multiplying the axis that already dominates.

The bucket ladder is compiled in: eighteen boundaries, 2.5× apart from
25 µs to 10 s, so every zgix's histogram is directly comparable to every
other's, and `_sum` and `_count` give an exact mean whatever the buckets
do.

Only **completed** exchanges are observed. An exchange the client cut off
mid-response is not in the histogram, so p99 measures how long serving
takes rather than how long clients wait before giving up. Those show as
`outcome: aborted` in the access log. `_count` therefore equals
`zgix_l7_responses` exactly, an identity the simulator asserts on every
seed.

### Access log

One JSON object per line: one per HTTP exchange (rejects, `503` sheds and
timeouts included) and one per L4 connection.

```json
"access_log": { "sink": "stdout" }
```

```json
{"time":"2026-07-31T09:14:22.481Z","kind":"http","outcome":"ok","client":"10.1.2.3:52344","method":"GET","host":"api.example.com","path":"/v1/items","status":200,"upstream_reused":true,"upstream_replayed":false,"duration_us":1873,"bytes_in":142,"bytes_out":4096,"cluster":"api","upstream":"10.0.0.7:8080"}
```

`outcome` is what `status` cannot tell you: an origin answering `503` and
zgix shedding a request with `503` are the same three digits and opposite
events. It reads `ok`, `rejected`, `shed`, `timed_out`, `upstream_failed`,
`aborted`, or `closed`. The last is for L4 connections and for
[tunnels](#tunnelled-upgrades-websocket), which end the way a relay ends
rather than the way an exchange does.

Logging never blocks the event loop, so a sink that stalls costs dropped
lines rather than latency. `zgix_access_log_dropped` counts them exactly.

#### The admin endpoint's log tail

The metrics scrape ends with a short access-log tail, whether or not a sink
is configured: a `# zgix_access_log` marker line, then the newest HTTP
lines as `# <json>` comments — one object per line, oldest first, in the
same `outcome` vocabulary as the sink's. It is a bounded ring (the newest
128 lines at 512 bytes each), so it answers without reading a file and
never blocks the loop; a fact that does not exist for a request (no
`upstream` chosen, an unparsed head) is an omitted key rather than a null.
The bundled control panel's *logs* view parses exactly this section.

#### Logging request headers

By default a zgix line and the backend's line for the same request share
no key, so a slow request cannot be attributed to a hop. Naming headers
fixes that without changing a byte on the wire:

```json
"access_log": {
    "sink": "stdout",
    "request_headers": ["X-Request-ID", "User-Agent"],
    "response_headers": ["X-Cache"]
}
```

```json
{"...":"...","status":200,"upstream_reused":true,"upstream_replayed":false,"request_headers":{"x-request-id":"7f3c…","user-agent":"curl/8.6.0"},"response_headers":{"x-cache":"HIT"},"duration_us":1873}
```

zgix does not mint an identifier. It is usually not the outermost hop: a
CDN, cloud LB or ingress in front almost always sets `X-Request-ID` or
`traceparent`, and that header reaches the origin untouched, so logging it
at both ends is the whole join. The same mechanism serves other purposes:
`User-Agent` for traffic analysis, a tenant header for multi-tenant
routing, the origin's `X-Cache` on the way out.

Names are matched case-insensitively and logged lowercased. A header that
did not arrive is omitted rather than logged as null. A repeated header
logs its first value, the one zgix itself read. Values are truncated at
256 bytes with a trailing `...`, and up to 8 headers may be named across
both lists. `response_headers` is ignored for L4 lines, which have no
response to read. Absent lists leave the line exactly as it was.

The values are held per connection for the life of a request, so naming
headers costs memory proportional to `conn_slots`, which the startup
banner prints. A wider line also needs a staging buffer that can hold
one; zgix refuses to start rather than dropping every line that carries
them.

`sink` is either `stdout`, the process's own standard output, inherited
rather than opened, so it costs no file descriptor and has no rotation
story of its own, or `file` with a `path`:

```json
"access_log": { "sink": "file", "path": "/var/log/zgix/access.log" }
```

The file is created if absent and opened append-only at startup, never
truncated, which is what makes copy-truncate rotation (logrotate) safe:
every write lands at the current end, wherever the rotation just put it.

Move-based rotation is served by `SIGHUP`, which reopens the configured
path. The new fd opens *first*: a reopen that cannot open its file keeps
the old one and counts `zgix_access_log_reopen_failed`, because a failed
rotation must not destroy a working log. The swap happens only between
writes, never under one, so every line accepted after the signal lands in
the new file. `zgix_access_log_reopened` counts the rotations that took.
A successful reopen also heals a sink that had broken, since what broke
was the fd the rotation just replaced. On a `stdout` sink, or with no log
configured, `SIGHUP` is a no-op.

### Proxy-Status

The access log answers you. This answers the client. A `503` from an
overloaded zgix and a `503` from a healthy zgix relaying an overloaded
backend are indistinguishable on the wire, and only one of them is your
problem. Setting `proxy_status` on an `http` listener makes the pages
zgix renders *itself* say so, in an RFC 9209 `Proxy-Status` field:

```json
{
    "bind": "0.0.0.0:80",
    "http": {
        "cluster": "web",
        "proxy_status": true
    }
}
```

```
HTTP/1.1 503 Service Unavailable
Content-Length: 0
Date: Wed, 01 Jan 2020 00:00:00 GMT
Server: zgix
Proxy-Status: zgix; error=connection_limit_reached
```

Four causes carry a token, and only those four:

| cause | status | `error=` |
|---|---|---|
| no route matched — zgix never dialed a backend, so the origin was not asked about this path | `404` | `destination_not_found` |
| a [filter](#filters) refused on policy — zgix's rule, not the origin's answer | the status the rule names (`400`/`403`/`404`/`429`) | `http_request_denied` |
| a zgix limit, any rung of the shed ladder — slots, buffers, tunnels, per-endpoint in-flight | `503` | `connection_limit_reached` |
| the backend was dialed and did not answer in time | `504` | `http_response_timeout` |

The token names the **cause, not the status**. A filter rejecting with
`404` and an empty routing table answering `404` are the same three
digits and different advice: one means "ask someone else", the other
means "you were refused".

Everything else is silent. A `400`, `413`, `414` or `431` that is the
request's own fault gets nothing, because 9209's only fitting token
(`http_request_error`) restates the status line. A `502` is skipped for
the opposite reason: a refused dial, a reset mid-response and a malformed
origin head are three different 9209 causes that zgix answers at one
place, so any single token would be right by accident. A `Proxy-Status`
from zgix therefore always carries something the status line did not.

What it does not do:

- **No `next-hop`.** 9209 allows naming the backend; that publishes your
  topology to every client that can provoke an error. The endpoint is in
  the access log.
- **An upstream proxy's field survives.** `Proxy-Status` is a List, and
  zgix sets it only on pages it renders itself. A relayed response carries
  whatever the hop before it wrote, unedited, so a chain reads back in
  order.
- **Configured error pages win.** A status you gave a body for in
  `error_pages` is sent exactly as you wrote it, header included or not.
- **Forwarded responses are untouched.** An origin's own `503` is relayed
  as the origin wrote it.

> [!IMPORTANT]
> Off by default, and per listener, on the same reasoning as
> [`forwarded`](#x-forwarded-for): the field states which of *this
> proxy's* limits a caller hit. Inside a mesh that is a diagnostic; at an
> untrusted edge it is a capacity disclosure, and zgix cannot tell from
> the inside which side of that line a listener is on.

## Under load

When a resource is exhausted, zgix degrades the newest work, keeps serving
admitted work, and never allocates, blocks or dies. Every limit has a
defined answer rather than an unbounded queue.

- **Exhaustion sheds at a defined point.** No connection slot: the socket
  is closed with an RST, so the client learns immediately instead of
  timing out. No relay buffer or upstream slot for an HTTP request: a
  static `503` from constant memory, and the connection is kept when the
  client's byte stream is still on a message boundary, because closing
  costs more than the work being shed.
- **A tunnel is refused before it costs anything.** No tunnel slot: the
  upgrade is answered `503` before the handshake is forwarded, so a
  refusal never spends an origin connection.
- **Watermarks before walls.** Each pool raises a pressure flag at 3/4
  occupancy and lowers it only once it has drained back to 1/2; the gap
  stops the flag flapping around a single threshold. While it is raised,
  idle timeouts are cut to a quarter, so quiet connections return their
  resources before the wall is reached.
- **Accept never pauses.** The kernel backlog stays drained even while
  shedding, so clients get an immediate signal rather than a timeout.
- **`SIGTERM` drains.** Listeners close, keep-alive stops being honoured,
  in-flight work finishes under `drain_deadline_ms`, then the process
  exits 0.
- **A stalled loop is a death, not a hang, if you ask for one.**
  `timeouts.loop_watchdog_ms` arms an `alarm(2)` that a tick the loop
  delivers keeps pushing out, so a loop that stops delivering is ended by
  the kernel with exit **6** and one line on stderr. Off unless
  configured.
- **The budget is printed, not hoped for.** Startup prints the closed-form
  memory, file-descriptor and ring-op totals it will never exceed, and
  asserts the fd count against `RLIMIT_NOFILE` before serving anything.

[DESIGN.md](DESIGN.md) §8 documents each rung and why it answers the way
it does.

## Further reading

- [DESIGN.md](DESIGN.md) — the settled design: what is shipped and how it
  works. The bare `§` references in this document, in the source and in commit
  messages all point here.
- [TIGER_STYLE.md](TIGER_STYLE.md) — the coding rules the tree is held to:
  static allocation only, bounded loops, assertion density, explicitly-sized
  integers.
- [IMPLEMENTATION_NOTES.md](IMPLEMENTATION_NOTES.md) — measured findings,
  shelved experiments and open technical questions.
- [zgix.io/config](https://zgix.io/config/) — every field, bound and default,
  rendered from the JSON Schema of the latest release.
