# H3 Client.get() + Server.run() Implementation

> Quick spec — design approved in evaluation phase.

## Client.get()

```
connect() → open_bidi_stream → submit_request → I/O loop → recv callbacks → return body
```

1. Callbacks: `recv_header` (accumulate status+headers), `recv_data` (accumulate body), `stream_close` (signal done)
2. `nghttp3_nv` array: `:method`, `:path`, `:authority`, `:scheme`, plus optional headers
3. I/O loop: write pending → read available → `nghttp3_conn_read_stream2()` until stream closes
4. Return `[]const u8` body (arena-allocated)

## Server.run()

```
UDP recvfrom → CID route → read_pkt → handshake → bind_h3 → read_stream → recv_header → handler → submit_response
```

1. CID routing: `[18]u8 → *Connection` map
2. ngtcp2 callbacks: `handshake_completed` → bind nghttp3 control+QPACK streams
3. nghttp3 callbacks: `recv_header` → build httpz.Request, invoke handler, submit response
4. Connection lifecycle: create on first packet, GC on close/idle timeout

## Files

| File | Change |
|------|--------|
| `src/h3/http3.zig` | Add callbacks, `submitRequest()`, `readStream()` |
| `src/h3/Client.zig` | Implement `get()` |
| `src/h3/Server.zig` | Implement `run()` |

## Non-goals
- QPACK stream binding (pass-through)
- Response body streaming
- Connection reuse
- 0-RTT
