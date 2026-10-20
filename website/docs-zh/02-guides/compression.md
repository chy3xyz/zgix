---
title: 压缩
sidebar_label: 压缩
description: zgix 在加载时把配置的应答体 gzip 一次；以及那条刻意收窄的代理响应压缩。它不压什么。
---

压缩有两处，都按构造有界；更大片的疆土刻意留给 CDN 或源站。

# 预压缩的静态应答

每个配置的应答体 —— `respond` 动作的页面、`error_pages` 条目 —— 在
**加载时 gzip 一次**。当请求的 `Accept-Encoding` 接受 gzip（显式
`gzip` 或 `*`；`q=0` 拒绝；解析 q 值），应答带 `Content-Encoding:
gzip`、`Vary: Accept-Encoding` 和压缩后的长度发出；否则原样发送明文。
`HEAD` 拿到所选变体的头部，不含正文。

```json
"bodies": {
    "maintenance": { "file": "/etc/zgix/503.html", "content_type": "text/html; charset=utf-8" },
    "robots":      { "inline": "User-agent: *\nDisallow: /private\n",
                     "content_type": "text/plain" }
},
"error_pages": { "503": "maintenance" }
```

正文活在内存里 —— `503` 是因为某种资源耗尽才抛出的，一个需要资源
才能送达的错误页会恰好在他最需要的时候失败。成本按正文封顶、计入
启动横幅、每进程只付一次。**列出状态码就是开启**，对甩掉类应答也
一样：不列 `503`，过载时照旧回答空 `503`。

# 压缩被代理的响应

监听也可以为代理应答开启 gzip：

```json
"http": {
    "cluster": "api",
    "compress": { "min_bytes": 1024 }
}
```

- `min_bytes`（默认 1024）是下限；更小的正文原样发送 —— gzip 框架
  本身的成本就比省下的多。
- 仅当整个正文与响应头同一次 read 到达（来自快源站的小响应）、状态
  `200`、`Content-Length` 已知、`Content-Type` 是文本类（`text/*`、
  JSON、JavaScript、XML、SVG、NDJSON）、未设置 `Content-Encoding`、且
  `Cache-Control` 没有 `no-transform` 时适用。
- 上限 64 KiB。更大的、chunked 的、`until_close` 的、 interim 响应、
  `HEAD`、或一次 read 没装完的正文，一律原样流过。
- 压缩后的应答带重算的 `Content-Length`、`Content-Encoding: gzip` 和
  `Vary: Accept-Encoding`；没提供 gzip 的客户端拿到原始字节。

压缩器是启动时分配的一个缓冲，计入横幅 —— 每请求零分配。

# 不压什么

这不是流式压缩：zgix 自带的 deflate 泵无法增量输出合法的 gzip 流，
因此流式响应 —— SSE、大正文、chunked 应答 —— 原样穿过。这些需要
压缩时，请在 zgix 前面接 CDN，或在源站压缩。
