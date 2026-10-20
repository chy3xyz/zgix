---
title: 访问日志与管理面板
sidebar_label: 访问日志与面板
description: JSON 访问日志 —— 汇、轮转、记录头部 —— 带日志尾的管理抓取，以及内置控制面板。
---

# 访问日志

每行一个 JSON 对象：每个 HTTP 交换一行（拒绝、`503` 甩掉和超时都
包括）、每条 L4 连接一行、每条隧道关闭时一行。

```json
"access_log": { "sink": "stdout" }
```

```json
{"time":"2026-10-20T09:14:22.481Z","kind":"http","outcome":"ok","client":"10.1.2.3:52344","method":"GET","host":"api.example.com","path":"/v1/items","status":200,"upstream_reused":true,"upstream_replayed":false,"duration_us":1873,"bytes_in":142,"bytes_out":4096,"cluster":"api","upstream":"10.0.0.7:8080"}
```

`outcome` 说的是 `status` 说不出来的事：源站回答 `503` 和 zgix 用
`503` 甩掉请求是同样的三个数字、相反的事件。取值有 `ok`、`rejected`、
`shed`、`timed_out`、`upstream_failed`、`aborted` 或 `closed` —— 最后
一个给 L4 连接和隧道，它们的结束方式更像转发而不是交换。

日志永远不会阻塞事件循环，因此汇卡住时付出的代价是丢行而不是延迟；
`zgix_access_log_dropped` 精确计数。

# 汇与轮转

`sink` 是 `stdout` —— 进程自己的标准输出，继承而非打开，不花 fd、
也没有自己的轮转故事 —— 或者是带 `path` 的 `file`：

```json
"access_log": { "sink": "file", "path": "/var/log/zgix/access.log" }
```

文件缺失时创建，启动时以 append-only 打开、永不截断 —— copy-truncate
式轮转（logrotate）因此安全：每次写都落在当前末尾。移动式轮转由
`SIGHUP` 服务：它重新打开路径 —— 新 fd *先*打开，打不开就保留旧 fd
并累加 `zgix_access_log_reopen_failed`，因为一次失败的轮转绝不能毁掉
一个能用的日志。`zgix_access_log_reopened` 计数成功的轮转，成功的
重开还会修好一个已经坏掉的汇。

# 记录请求与响应头部

默认情况下，同一个请求在 zgix 日志和后端日志之间没有任何公共键，
慢请求无法归因到某一跳。点名头部可以解决这个问题，线上一个字节
都不改：

```json
"access_log": {
    "sink": "stdout",
    "request_headers": ["X-Request-ID", "User-Agent"],
    "response_headers": ["X-Cache"]
}
```

zgix 不造 ID：前面的 CDN 或入口几乎总会设置 `X-Request-ID` 或
`traceparent`，这些头部原样到达源站，因此两端都记就是完整的串联。
名字大小写不敏感、记录为小写；没到的头部省略而不是置空；值在 256
字节处截断；两个列表合计最多 8 个。值按连接保存到请求结束，因此
点名头部的内存成本正比于 `conn_slots` —— 启动横幅会打印，暂存缓冲
太窄是启动拒绝而不是丢行。

# 管理端点

```json
"admin": { "bind": "127.0.0.1:9100" }
```

管理监听提供 Prometheus 抓取文本：每个甩掉阶梯、每个生命周期计数器、
清单家族、实时的池占用量表，以及一段有界的访问日志尾 —— 无论是否
配置了汇。同一时刻只服务一次抓取，使用数据路径池之外预留的槽位，
因此抓取和请求永远不会互相甩掉。它是读取实时计数器的唯一方式；
没有信号会打印计数器，因为同一条流上的第二份快照会使第一份失效。

抓取末尾是 `# zgix_access_log` 标记和最新 HTTP 行（以 `# <json>`
注释形式）—— 有界环形缓冲，最新 128 行、每行 512 字节、最旧在前
 —— 因此它不读文件即可回答，也永不阻塞事件循环。完整参考见
[指标](/03-reference/metrics.md)。

管理端点以 `Access-Control-Allow-Origin: *` 应答，因此任何静态服务器
都能托管面板。

# 内置面板

仓库里的 `panel/` 是运行中 zgix 的控制面板：纯静态文件，SolidJS
vendored 在 `panel/vendor/`，无构建步骤。ES module 不能经 `file://`
加载，因此要把目录伺服起来：

```sh
python3 -m http.server 8080 --directory panel
# 打开 http://127.0.0.1:8080/
```

在头部字段输入想观察的 zgix 管理端点（默认
`http://127.0.0.1:9100`，记在 localStorage），选择轮询间隔。四个
视图：

- **概览**：h3 监听表、逐 tick 速率迷你图、h3 判定分布、池量表、
  原始抓取。
- **站点**：监听及其路由表，来自 `zgix_listener_info` /
  `zgix_route_info` 清单家族。
- **应用**：集群的 avg/p50/p90/p99 延迟（`zgix_cluster_duration_seconds`
  直方图），per-endpoint 健康、响应数、连接失败数、inflight。
- **关于**：版本（`zgix_info`）与目标摘要。

带管理端点的最小配置就是[第一份配置](/01-getting-started/first-config.md)
里的那行 `"admin": { "bind": "127.0.0.1:9100" }`。
