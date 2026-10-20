---
title: Compression
sidebar_label: Compression
description: zgix gzips configured bodies once at load, and can gzip small, fast, text-like proxied responses. What it deliberately does not compress.
---

There are two compression features, both bounded by construction, and a
larger territory zgix deliberately leaves to a CDN or the origin.

# Precompressed static answers

Every configured body — a `respond` action's page, an `error_pages` entry —
is gzipped **once at load**. When the request's `Accept-Encoding` accepts
gzip (an explicit `gzip` or `*`; `q=0` declines; q-values are parsed), the
answer is sent with `Content-Encoding: gzip`, `Vary: Accept-Encoding` and
the compressed length; otherwise the plain body is sent unchanged. `HEAD`
gets the selected variant's headers without a body.

```json
"bodies": {
    "maintenance": { "file": "/etc/zgix/503.html", "content_type": "text/html; charset=utf-8" },
    "robots":      { "inline": "User-agent: *\nDisallow: /private\n",
                     "content_type": "text/plain" }
},
"error_pages": { "503": "maintenance" }
```

Bodies live in memory — a `503` is raised because something ran out, so an
error page whose delivery needed a resource would fail exactly when it is
needed. The cost is capped per body, counted in the startup banner, and paid
once per process. **Listing a status is the opt-in**, including for sheds:
leave `503` out and overload answers an empty `503` as before.

# Compressing proxied responses

A listener may opt in to gzip for proxied answers as well:

```json
"http": {
    "cluster": "api",
    "compress": { "min_bytes": 1024 }
}
```

- `min_bytes` (default 1024) is the floor; smaller bodies are sent
  unchanged, since the gzip framing alone would cost more than it saves.
- Compression applies only when the whole body arrived in the same read as
  the response head (a small response from a fast origin), the status is
  `200`, `Content-Length` is known, `Content-Type` is text-like (`text/*`,
  JSON, JavaScript, XML, SVG, NDJSON), no `Content-Encoding` is already set,
  and `Cache-Control` does not say `no-transform`.
- The ceiling is 64 KiB. Anything larger, chunked, `until_close`, an interim
  response, a `HEAD`, or a body that took more than one read is streamed
  through untouched.
- A compressed answer carries a recomputed `Content-Length`,
  `Content-Encoding: gzip` and `Vary: Accept-Encoding`; a client that did
  not offer gzip gets the original bytes.

The compressor is one buffer allocated at startup and counted in the banner
— there is no per-request allocation.

# What is not compressed

This is not full streaming compression: the deflate pump zgix ships cannot
emit a valid gzip stream incrementally, so streaming responses — SSE, large
bodies, chunked replies — pass through uncompressed. Front zgix with a CDN,
or compress at the origin, when those need it.
