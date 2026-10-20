---
title: WebSocket 与隧道化升级
sidebar_label: WebSocket
description: 让 WebSocket 升级穿过 zgix —— upgrades 白名单、独立的隧道池，以及约束隧道生命的超时。
---

默认情况下，任何带 `Upgrade` 的请求都得到 `501`，与 `CONNECT` 相同。
`http` 监听通过点名它愿意承载的协议来开启：

```json
"listeners": [
    { "bind": "0.0.0.0:80", "http": { "cluster": "web",
      "upgrades": { "websocket": true } } }
],
"limits": { "tunnels": 512 }
```

zgix 不会说 WebSocket。它转发握手、识别源站的 `101 Switching Protocols`，
从那一刻起双向转发字节直到一方关闭 —— 与 `l4` 监听相同的字节转发。
路由、过滤和健康检查像作用于任何请求一样作用于握手；`101` 之后连接
变成不透明字节流，过滤器、路由和头部规则随之停止适用。

每个协议一个开关，而不是一份 token 列表：词汇表活在 schema 里，编辑器
会在加载器之前拒绝 `"h2c"` —— `h2c` 会把 HTTP/2 带给一个 zgix 无法
解析的源站，因此在加载时按名字拒绝。省略块、写 `{}`、或全部置
`false` 都意味着*不允许任何升级，也不预留任何资源*。

# 隧道池

只要允许了任何升级，`limits.tunnels` 就是**必填**，且没有默认值：
源站应该承载多少长会话是 zgix 无法从连接数推断的容量决策。它不得
超过 `conn_slots`。

这个池与普通流量使用的缓冲是分开的。其它所有池按并发*活动*定容 ——
闲置的 keep-alive 连接不占用 head 缓冲 —— 但隧道会把转发缓冲钉住
整个生命期。独立的池意味着隧道挤不垮 HTTP。每条隧道占用一对转发
缓冲 —— 16 KiB 默认下为 32,808 字节，`tls` 集群加宽两半边时为
33,330 —— 启动横幅会打印。

池满时，升级在握手到达源站之前就被回答 `503`，因此一次拒绝不消耗
任何后端连接。`zgix_l7_shed_tunnels` 计数拒绝；`zgix_tunnels_established`
计数真正建立的会话。

池之上还挂着三个后果：

- `timeouts.tunnel_ms` 在连接成为隧道后取代其它超时 —— 默认一小时，
  下限一秒，上限一天，且没有 `0` 表示"不限"：隧道终生占着一个池槽。
  WebSocket 自带的保活是应用层 ping/pong，zgix 隔着不透明字节看不见。
- 升级后的上游连接离开 keep-alive 池，不再复用，但只要隧道活着仍计入
  集群的 `max_inflight`。
- 穿过 `tls` 集群时，隧道还终生占用该连接的 TLS 引擎：`upstream_slots`
  就是并发 TLS 隧道的上限，耗尽时甩掉新拨号，绝不会动已建立的隧道。

# 排空与访问日志

排空中的进程以 `503` 拒绝新升级，并在 `drain_deadline_ms` 切断活跃
隧道 —— 未设置时五秒，因为 WebSocket 没有"最后一个消息"的边界可等。
`zgix_tunnels_drained` 计数被切断的隧道。

访问日志在隧道关闭时写一行：`kind` 为 `http`、`status` 为 `101`、
打开它的请求事实，以及整个会话的 `bytes_in`/`bytes_out` —— WebSocket
的生命期成本因此与其它交换落在同一个汇里。
