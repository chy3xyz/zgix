# HTTP/3 Support via ngtcp2 + nghttp3

> Status: Approved → Implementation

## Summary

Add HTTP/3 (RFC 9114) support by binding to ngtcp2 (QUIC) and nghttp3 (HTTP/3)
via translate-C. Reuse all existing httpz upper-layer types: Request, Response,
Router, Middleware, Cookie.

## Dependencies

- `libngtcp2` — QUIC transport (brew: `libngtcp2`)
- `libnghttp3` — HTTP/3 framing + QPACK (brew: `libnghttp3`)
- `openssl@3` — TLS 1.3 for QUIC (already required)

## Module Structure

```
src/h3/
├── root.zig       — public exports: quic, http3, Server, Client
├── ngtcp2.h       — translate-C header: <ngtcp2/ngtcp2.h> + crypto
├── nghttp3.h      — translate-C header: <nghttp3/nghttp3.h>
├── quic.zig       — QUIC connection wrapper (UDP socket, ngtcp2_conn, callbacks)
├── http3.zig      — HTTP/3 session wrapper (nghttp3_conn, request/response mapping)
├── Server.zig     — H3 server: UDP listener + CID routing + connection handling
└── Client.zig     — H3 client: UDP connect + handshake + request/response
```

## Build Integration

- `b.addTranslateC()` for both ngtcp2 and nghttp3 headers
- `linkSystemLibrary("ngtcp2")` and `linkSystemLibrary("nghttp3")`
- Add include path for OpenSSL headers
- Conditional: H3 module only linked when system has libngtcp2/nghttp3

## Architecture

### Server Flow
1. Bind UDP socket on configured port
2. On recvfrom: parse DCID, route to existing QUIC conn or create new one
3. ngtcp2_conn_read_pkt() processes incoming packets
4. On handshake complete: bind nghttp3 control + QPACK streams
5. On H3 stream data: nghttp3_conn_read_stream2() → callbacks yield headers/data
6. Build httpz.Request from pseudo-headers → invoke handler → httpz.Response
7. Submit response via nghttp3_conn_submit_response() → ngtcp2_conn_writev_stream()

### Client Flow
1. Create UDP socket, connect to server
2. ngtcp2_conn_client_new() → handshake via packet exchange loop
3. On handshake complete: open bidi stream → nghttp3_conn_submit_request()
4. Read responses via nghttp3 callbacks → build httpz-style Response
5. Return to caller

### Public API (unchanged signatures)
```zig
// Server — same API, detects h3 via ALPN or dedicated port
var server = httpz.Server.init(.{ .port = 443, .enable_h3 = true }, handler);

// Client — same API, negotiates h3 via ALPN
var client = httpz.Client.init(allocator, .{ .host = "...", .port = 443 });
```

## Implementation Phases

| # | Phase | Files |
|---|-------|-------|
| 1 | Build integration + translate-C headers | `build.zig`, `src/h3/ngtcp2.h`, `src/h3/nghttp3.h` |
| 2 | `quic.zig` — QUIC wrapper (UDP + callbacks) | `src/h3/quic.zig` |
| 3 | `http3.zig` — H3 session (request/response mapping) | `src/h3/http3.zig` |
| 4 | `Client.zig` — H3 client | `src/h3/Client.zig` |
| 5 | `Server.zig` — H3 server | `src/h3/Server.zig` |
| 6 | Integration + ALPN detection | `src/root.zig`, `src/server/Server.zig`, `src/client/Client.zig` |

Phases 4 and 5 can run in parallel after Phase 3.

## Testing Strategy

- Unit tests for QUIC connection state machine
- Integration test: H3 client ↔ H3 server (localhost, self-signed cert)
- Test vectors from RFC 9114 / RFC 9204

## Non-Goals (v1)

- 0-RTT early data
- Connection migration
- WebTransport
- Server push over H3 (deprecated)
