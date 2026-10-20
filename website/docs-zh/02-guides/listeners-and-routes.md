---
title: 监听与路由
sidebar_label: 监听与路由
description: zgix 如何承接流量 —— l4 转发与 http 反向代理、host/header/prefix 路由表，以及多租户 SNI 路由。
---

一个监听绑定一个地址、只说一种协议，协议由配置键指明：`l4` 不检查字节
直接转发，`http` 运行 HTTP/1.1 反向代理。两者必须且只能取其一 —— 没有
默认值。

```json
"listeners": [
    { "bind": "0.0.0.0:80",   "http": { "cluster": "web" } },
    { "bind": "0.0.0.0:5432", "l4":   { "cluster": "postgres" } }
]
```

`bind` 和 `tls` 位于协议体之外，因为两者通用；其余键都放在协议体内部，
只对一种协议有意义的键写给另一种会被直接拒绝 —— 比如在 `l4` 监听上写
`max_body_bytes` 是配置错误，而不是一个静默无效的键。

每个监听都以 `SO_REUSEPORT` 绑定：同一端口跑多个进程是有支持的扩容方式，
也是[替换运行中实例](/04-deployment/systemd.md)的方式。每条连接
—— 无论接入还是上联 —— 都设置 `TCP_NODELAY`：Nagle 加 delayed ACK
会让一条复用的 keep-alive 连接白等 40 毫秒。`bind` 也可以是 `unix:`
socket 路径；见[配置参考](/03-reference/config.md)。

# HTTP 路由表

`"cluster": "name"` 是单条全 catch-all 路由的语法糖。`http` 监听也可以
携带路由表，在匹配到的 host 内按**最长前缀**匹配：

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

不写 `host` 的路由匹配任意 host；写了 host 的路由永远优先。匹配使用
**规范化**路径 —— 百分号转义已解码、点段已折叠 —— 源站收到的也是同一
个规范化路径，因此路由和后端不会对"请求的是哪个资源"产生分歧。改变
结构的转义（`%2F`、`%00`、截断的转义）以 `400` 拒绝。没有任何路由命中
的请求得到 `404`。

# 头部谓词

路由还可以匹配头部 —— `present` 匹配任意值，`equals` 匹配指定值。固定
金丝雀就是这么写的：百分比金丝雀是[端点权重](/03-reference/config.md)，
而给测试账号或内部网关的头部钉一个固定金丝雀，就是一条路由：

```json
"routes": [
    { "header": { "name": "X-Canary", "present": true },
      "prefix": "/", "cluster": "next" },
    { "prefix": "/", "cluster": "stable" }
]
```

**先 host，再 header，再 prefix。** 路由声明的每个键都必须成立；多条
路由同时匹配时，按这个顺序取最具体者。路由表在启动时排序一次，因此书写
顺序无所谓。只有一种情况由书写顺序决定：两条路由同 host 同 prefix、但
声明了*不同*的 header，此时携带两个头部的请求同时命中两者 —— 写在前面
的赢。

依赖头部路由之前，要知道两件事：

- 请求带上或失去该头部会**换到另一个集群**，因此 `hash` 选择在每个
  集群内部成立，跨变化不成立。
- 该头部既是路由键*又*被转发：源站看得到它，可以记录请求由哪一侧服务。

路由还可以带 `"access_log": false`，让它的请求不写访问日志 —— 相当于
nginx location 上的 `access_log off`。计数器、指标、准入和流量本身都不
变。

# 奇怪的请求

- `CONNECT` 和 `TRACE` 一律回答 `501`，永不到达后端 —— 前者是正向代理
  行为，后者是跨站追踪（XST）向量。
- `OPTIONS` 遵守 `Max-Forwards`：为 `0` 时 zgix 以 `200` 和一个描述自身
  的 `Allow` 应答，不拨后端；大于 `0` 时带着递减后的值转发。
- 绝对形式的请求目标（`GET http://api.example.com/v2/x`）按 RFC 9112
  接受，且目标里的 authority**优先于 `Host` 头** —— 路由、过滤、日志、
  源站收到的 Host，全都以它为准。只接受 `http` 和 `https` 目标；其它
  scheme 一律 `400`。

# 多租户 TLS：按 SNI 路由 l4 监听

一个 `:443` 可以在不终结任何 TLS 的前提下承接多个 TLS 服务。给 `l4`
体一个按服务器名路由的路由表，zgix 从 ClientHello 里读出名字，然后逐字
节原样转发：

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

zgix 不持有密钥材料、不参与握手：后端与客户端完成 TLS 会话，过程与没有
代理完全一致，zgix 看不到任何明文。这正是"代理绝对不能持有某服务证书"
场景的前置方式。

不带 `sni` 的路由是 catch-all —— 应答任何连接，包括 hello 里什么都没
写的连接。没有 catch-all 时，表外的名字会被直接关闭。匹配是精确匹配：
`api.example.com` 匹配它自己，不匹配 `x.api.example.com`；两张表都没有
通配符。

四个计数器报告这张表的行为 —— `zgix_l4_sni_routed`、`zgix_l4_sni_absent`
（客户端没写名字）、`zgix_l4_sni_no_route`（写了没有路由认领的名字）和
`zgix_l4_sni_invalid`（开头字节不是 ClientHello）。hello 必须在一个 TLS
记录内到达（真实客户端都这么做）；分片的首次 flight 计入
`zgix_l4_sni_invalid` 并被关闭，而不是在一个读取攻击者字节的解析器里做
重组。

两种组合在加载时就被拒绝：

| 配置 | 原因 |
|---|---|
| `routes` 与本监听的 `tls` 并存 | 终结 TLS 会消费掉这个路由要读的 hello；两者是不同的代理 |
| `limits.relay_buffer_bytes` 低于 16 KiB | hello 暂存在转发缓冲里，而带后量子密钥份额的现代 hello 会超过 2 KiB —— 缓冲太窄会按同一个配置放过短 hello、丢掉长 hello |

要改为终结 TLS —— 每个监听一组或多组证书 —— 见 [TLS 证书](tls-certificates.md)。
