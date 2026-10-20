---
title: HTTP/3（实验性）
sidebar_label: HTTP/3
description: 实验性 QUIC 监听 —— h3_listeners、QUIC 上的路由表、流式转发、超时、Alt-Svc 公告与互操作检查。
---

一个 `h3_listeners` 项绑定 UDP socket、终结 QUIC-TLS，并把每个请求经由
明文 HTTP/1.1 代理给路由表所选集群：

```json
"h3_listeners": [
    {
        "bind": "0.0.0.0:4443",
        "routes": [
            { "host": "api.example.com", "prefix": "/api", "cluster": "api" },
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

`"cluster": "name"` 依然是单条全 catch-all 路由的语法糖。路由表与
HTTP/1.1 监听完全一致：host 作用域、可选的 `header` 谓词（`equals` 或
`present`）、尊重段边界的最长路径前缀 —— 合取，按最具体者优先（host、
header、prefix）。没有路由命中的请求回答 `404`，即 `h3_no_route` 判定。
路由可以设 `access_log: false`，只把它的请求从日志里去掉 —— 计数器和
准入保留。

QUIC 没有明文模式，因此 `tls` 必填。整个进程只呈现一个身份：两个
HTTP/3 监听指向不同证书路径会在加载时被拒绝；`--check` 读同样的文件，
因此缺证书是启动错误并点名文件，而不是一次失败的首次握手。

# 上游这条腿

上游这条腿是 HTTP/1.1 —— 明文，或当所选集群带 `tls` 块时走 TLS ——
keep-alive 池化：完整成帧、未声明 `Connection: close` 的响应会把连接
停给该端点的下一个请求（每个端点一条闲置连接，30 秒不用即回收）。闲置
时被源站悄悄关掉的连接在下一次交换以 502 失败，且绝不重试 —— 请求
可能不幂等。TLS 拨号与 TCP 路径使用同一个客户端引擎，`verify`、CA
束、`server_name` 和可选客户端证书在两条协议上含义一致；停着的 TLS
连接带着会话检出，永远不付第二次握手。

请求和响应都是流式的：头一解析完就转发，正文块随到随转，`Content-Length`、
`chunked`（增量解码）和 close-delimited 正文都走同一条路径。交换是全
双工的 —— 提前应答的源站会在上传还在流的时候就开始回传。

# 上限与超时

每个响应正文有 `max_response_bytes` 上限（默认 64 KiB，可配置到
16 MiB）：超过上限的 `Content-Length` 在头发出前就被拒绝；chunked 或
close-delimited 正文在流中途越限则以流 reset 截断。

`max_connections` 是这个监听的内存旋钮 —— 每个会话槽内嵌固定 256 KiB
arena。默认 64（每监听约 16 MiB），加载器封顶 1024。

一个交换带两个超时，先到者生效：

- `timeouts.h3_exchange_ms`（默认 10 s，`0` 关闭）是从交换开始的绝对
  预算 —— 覆盖拨号、发送和流式响应的接收窗口。超时的腿回答 `504`，
  若头已发出则以流 reset 记录为 `bad_gateway`。
- `timeouts.h3_exchange_idle_ms`（默认 `0`，关）是空闲变体：任一方向有
  应用层进展即重置计时，因此持续有数据的流（SSE、 drip）不会被它
  长寿拖垮的绝对预算杀死。SSE 端点建议设 15000–30000。

# 它自己回答什么

监听自己写出的应答可以穿配置的页面：

```json
"h3_listeners": [
    {
        "bind": "0.0.0.0:4443",
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

每个值指向全局 `bodies` 表里的一个正文；缺键保留内置文本。h3 应答
自己写 HEADERS，因此只有页面正文跨过这条缝；家族所穿的状态码
（404/502/504）不变。

# 观测

这条路径刻意比 HTTP/1.1 监听窄 —— 没有过滤器、限流或连接数限制 ——
但观测与 TCP 路径一致。每个 h3 请求获得一行访问日志（与 TCP 监听
相同的 `kind:"http"` 记录），且每个请求恰好落进一个全局判定桶，
渲染为 `zgix_h3_*` 家族：

| 计数器 | 含义 |
|---|---|
| `zgix_h3_requests` | 监听接受的请求 |
| `zgix_h3_responses` | 从源站应答了 2xx–5xx 的交换 |
| `zgix_h3_bad_gateway` | 拨号失败、源站 reset 或源站数据畸形 |
| `zgix_h3_gateway_timeout` | 交换在头发出前超出 `h3_exchange_ms` |
| `zgix_h3_shed_busy` | 因 `max_connections` 已满而拒绝 |
| `zgix_h3_no_route` | 没有路由命中 —— 运维上识别拼错 host 的探针 |

外加会话开/关计数器；在带标签的分解之后，每个配置的 h3 监听还有一行
 —— 活跃会话、累计请求与转发响应、停驻的 keep-alive 池 —— 均以监听的
`bind` 为标签。

# 公告 UDP 端口

在客户端信任部署之前，`http` 监听可以按监听公告 UDP 端口：写出
`Alt-Svc` 值（RFC 7838），原样挂在每个被代理的 final 响应头上：

```json
{ "bind": "0.0.0.0:443", "http": { "cluster": "origin",
  "h3_advertise": "h3=\":4443\"; ma=3600" } }
```

值必须是 1–128 字节，且由运维写全字段内容（含 `ma=`），因为套接字
前面坐着什么，决定了这条公告是不是真的。

脚本化的互操作检查用 `scripts/h3-interop-client.py` —— 钉在 IPv4 socket
上的极简 aioquic 客户端（aioquic 默认的双栈路径在某些主机上看起来和
服务端挂死一模一样）：

```sh
pip install aioquic            # 任意 venv
python3 scripts/h3-interop-client.py 4443
# -> STATUS 200 / BODY ...
```

客户端侧见[验证](/01-getting-started/verify.md)，完整的
`zgix_h3_*` 清单见[指标](/03-reference/metrics.md)。
