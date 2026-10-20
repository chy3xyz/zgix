---
title: 配置导览
sidebar_label: 配置导览
description: zgix 配置能携带的每个块 —— 监听、集群、应答体、超时、上限、admin、access_log —— 以及权威的 JSON Schema。
---

配置在启动时解析一次，永不重载；改配置就是重启进程。未知字段会被
拒绝。

字段、枚举和数值边界的权威清单是 **JSON Schema** —— 它从解析器生成，
由 `zig build schema` 产出为 `zig-out/config.schema.json`，并作为
release 资产发布。最新 release 的逐字段渲染在
[zgix.click/config](https://zgix.click/config/)。本页是导览；schema
才是契约。

# 文件的形状

```json
{
    "listeners":      [],
    "h3_listeners":   [],
    "clusters":       {},
    "bodies":         {},
    "error_pages":    {},
    "timeouts":       {},
    "limits":         {},
    "admin":          {},
    "access_log":     {}
}
```

# `listeners` —— 谁承接流量

每个条目绑定一个地址、只说一种协议：

- `http` —— HTTP/1.1 反向代理：`cluster` 或 `routes` 路由表
  （host、可选 header 谓词、最长前缀）、`request_filters`、
  `response_filters`、`upgrades`、`forwarded`、`rate_limit`、
  `conn_limit`、`waf`、`compress`、`max_body_bytes`、
  `keepalive_requests`、`h3_advertise`、`proxy_status`、`error_pages`。
- `l4` —— 盲 TCP 转发：`cluster` 或 SNI `routes` 路由表、
  `proxy_protocol: { "mode": "require" }`。

`bind` 和 `tls` 位于协议体之外、两者通用；`bind` 也可以是
`unix:/abs/path.sock` 加 `mode`。每个条目都以 `SO_REUSEPORT` 绑定。

# `h3_listeners` —— 实验性 HTTP/3

一个终结 QUIC-TLS 并经 HTTP/1.1 代理的 UDP socket：`routes`（与
`http` 同维度）、`tls`（必填 —— 无 SNI 集合，进程一个身份）、
`max_connections`、`max_response_bytes`、`error_pages`。比 TCP 路径
窄：没有过滤器、没有限流。

# `clusters` —— 流量去哪里

具名的端点集合加选择方式：

- `endpoints`：`IP:port` 字符串或 `{ "address": …, "weight": … }`
  对象（权重至 256；`0` 表示排干），或 `unix:` socket 路径。
- `pick`：`"p2c"`（默认，按在飞工作量做二选一）、`"rr"`（平滑加权
  轮转）、或 `{ "policy": "hash", "key": "source_ip" | "header" | "cookie" }`
  做不维护任何表的粘性。
- `check`：主动探测，`tcp` 或 `http` 带 `path`、`expect_status`、
  `fall`/`rise` 计数。
- `passive_ejection`：`fall` 次连续失败请求后摘除端点，
  `recovery_ms` 后放回来重新接受流量审判。`5xx` **不算**失败。
- `max_inflight`：单端点并发工作上限 —— 唯一一个"关闭"而不是
  "打开"的限制（503）。
- `tls`：向源站发起 TLS 1.3（`server_name`、`ca_file`、`verify`、
  `client_cert`、`client_key`）。
- `proxy_protocol: { "send": "v1" | "v2" }` —— 向源站通告客户端；
  只有 `l4` 监听能路由到发送集群。

# `bodies` 与 `error_pages` —— 罐装应答

zgix 自己发送的每个状态默认是空正文。`bodies` 把内容命名一次 ——
`file` 或 `inline` 外加必填的 `content_type` —— `error_pages` 把
zgix 实际会发的状态码（`400`、`403`、`404`、`408`、`413`、`414`、
`429`、`431`、`501`、`502`、`503`、`504`）映射到某个正文。过滤器的
`respond` 动作引用同一张表。正文在启动时读取并 gzip 一次；改一个
需要重启。

# `timeouts` —— 超时阶梯

每个字段可选，整块也可选：

| 字段 | 默认 | 含义 |
|---|---|---|
| `connect_ms` | `5000` | 每次上游拨号预算 |
| `head_ms` | 派生 | 读取一个请求头的预算 —— slowloris 会遇到它（`408`） |
| `idle_ms` | `60000` | 连接可以安静多久 |
| `drain_deadline_ms` | `0` | SIGTERM 排空上限；`0` 等最后一条连接 |
| `max_lifetime_ms` | `0` | 绝对连接寿命上限；`0` 关闭 |
| `request_ms` | `0` | 单个 L7 交换的上限，不因活动刷新；`0` 关闭 |
| `h3_exchange_ms` | `10000` | 单个 h3 交换的绝对预算；`0` 关闭 |
| `h3_exchange_idle_ms` | `0` | 空闲变体，有进展即重置；SSE 设 15000–30000 |
| `tunnel_ms` | `3600000` | 隧道的整个生命，1 秒到 1 天；`0` 不合法 |
| `health_interval_ms` | `2000` | 健康探测扫掠之间的停顿 |
| `loop_watchdog_ms` | 缺省 | 事件循环停摆超过这么久就杀掉进程（退出码 6）；不设则关闭 |

`connect_ms` 必须严格小于 `head_ms`，后者必须小于或等于 `idle_ms`，
否则配置被拒 —— 每条连接只有一个计时器，沿阶梯向下重定但从不提前。

# `limits` —— 池的大小

编译期常量是硬顶；这个块把实际池子从 1 定容到硬顶：

```json
"limits": {
    "conn_slots": 4096,
    "relay_buffers": 4096,
    "upstream_slots": 4096,
    "head_buffers": 1024,
    "upstream_head_buffers": 512,
    "head_buffer_bytes": 16384,
    "rate_limit_entries": 4096,
    "conn_limit_entries": 4096,
    "tls_engines": 1024,
    "tunnels": 512
}
```

默认值很省（1386 连接槽、约 34 MiB 池），能在默认 4096 的
`RLIMIT_NOFILE` 下启动；硬顶为每池 11457。两个键是有条件的：
`tls_engines` 在某个监听终结 TLS 之前是被拒绝的；而只要任何监听
声明了 `upgrades` 白名单，`tunnels` 就是**必填**（没有可推导的
默认值）。`head_buffers`/`upstream_head_buffers` 限制在飞的请求头
 —— 闲置连接不占用，keep-alive 重的部署可以调小。`head_buffer_bytes`
 决定每个头缓冲的大小、也就是能接受的最大头（超限 `414`/`431`），
1 KiB 到 1 MiB，默认 8 KiB。

# `admin` 与 `access_log` —— 可观测性块

`admin` 绑定抓取端点（见[访问日志与面板](/02-guides/access-log-and-admin-panel.md)）；
`access_log` 接受 `stdout` 或 `file`+`path`，以及可选的
`request_headers` / `response_headers` 列表。

# 校验

`zgix --check config.json` 跑完整的加载器 —— 文件打开、池定价、
fd 需求测算 —— 退出码 `0`/`1`/`2`（合法 / 配置错 / 配置对但机器
太小）。把它接进 CI：普通 `RLIMIT_NOFILE` 的构建 agent 可以对
生产尺寸的配置接受 `2`，但绝不能接受 `1`。
