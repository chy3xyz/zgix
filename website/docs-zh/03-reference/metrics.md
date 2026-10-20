---
title: 指标参考
sidebar_label: 指标
description: 管理抓取上渲染的 zgix_* 指标家族 —— 清单、RED、per-endpoint、甩掉阶梯、策略计数器和池量表。
---

管理端点渲染 Prometheus 抓取文本：每个甩掉阶梯、每个生命周期计数器、
实时的池占用量表，以及一段有界的访问日志尾。所有名字带 `zgix_`
前缀。标签在启动时预建 —— 基数由配置限定（集群、端点、监听绑定、
证书名），绝不来自请求数据 —— 渲染零分配，与这个端点上的一切一致。

# 怎么读这份抓取

- **计数器在撞墙时动。** `shed_*`、`*_limited`、`*_blocked` 和判定
  计数器只在事情发生时才动。
- **量表显示墙的临近。** `zgix_conn_slots_in_use` 对照
  `zgix_conn_slots_capacity` 显示墙在逼近；甩掉计数器显示墙被
  撞上了。每个池在 3/4 占用时升起压力标志、回落到 1/2 才降下 ——
  标志升起期间闲置超时缩减为四分之一，让安静连接在撞墙前归还
  资源。
- **家族之间对得上账。** 每个带标签家族的合计等于它分解的进程
  总量 —— 确定性仿真器在每颗种子上断言这条恒等式。
  `zgix_cluster_duration_seconds_count` 精确等于
  `zgix_l7_responses`，因为只有完成的交换才被观测。

# 清单 —— `*_info` 约定

值为常量 1 的量表，信息全在标签里 —— 控制面板直接拿抓取画出
站点/应用清单视图：

```text
zgix_info{version="0.9.0"} 1
zgix_listener_info{bind="0.0.0.0:443",kind="http",routes="12"} 1
zgix_route_info{listener="0.0.0.0:443",host="api.example",prefix="/api",header="x-canary",cluster="api"} 1
zgix_endpoint_info{cluster="api",endpoint="10.0.0.1:8080"} 1
zgix_cert_info{name="edge.example",listener="127.0.0.1:8443",not_after="...",days_left="42"} 1
```

`kind` 取 `http`、`l4` 或 `h3` —— TLS 终结不改变 http 监听的名字。
路由的 `host` 和 `header` 标签只在路由点名时出现（缺省即"任意"，
Prometheus 惯例）；`header` 携带谓词的名字。h3 监听的路由共享
`zgix_route_info`，以 `listener` 标签区分。`zgix_cert_info` 每组
证书一行，带有效期窗口 —— 证书过期会在握手断掉之前先告警。

# Rate、Errors、Duration

```text
zgix_cluster_responses{cluster="api",class="2xx"} 4182
zgix_cluster_responses{cluster="api",class="5xx"} 17
zgix_cluster_duration_seconds_bucket{cluster="api",le="0.005000000"} 3910
zgix_cluster_duration_seconds_bucket{cluster="api",le="+Inf"} 4199
zgix_cluster_duration_seconds_sum{cluster="api"} 12.884901888
zgix_cluster_duration_seconds_count{cluster="api"} 4199
```

- `zgix_cluster_responses` 是**客户端实际收到**的状态码，按类分 —
  没有它，一个对每个请求都回 `500` 的源站只存在于访问日志里。
- `zgix_cluster_duration_seconds` 是标准直方图，阶梯编译期固化
 —— 十八条边界、2.5 倍一档、从 25 µs 到 10 s —— 因此任意 zgix
  的直方图互相可比，`histogram_quantile` 直接可用。
- 两者都按集群打标签而不是端点：per-endpoint 5xx 已经由被动摘除
  处理，而集群是"哪个后端变慢了"这个问题的粒度，不再乘法放大
  主导轴。

客户端在响应中途切断的交换不进直方图 —— p99 度量的是服务耗时，
不是客户端放弃前的等待时长。这些在访问日志里显示为
`outcome: aborted`。

# Per-endpoint

```text
zgix_endpoint_responses{cluster="api",endpoint="10.0.0.1:8080"} 4182
zgix_endpoint_connect_failed{cluster="api",endpoint="10.0.0.2:8080"} 17
zgix_endpoint_health_down{cluster="api",endpoint="10.0.0.2:8080"} 2
zgix_endpoint_healthy{cluster="api",endpoint="10.0.0.2:8080"} 0
zgix_endpoint_inflight{cluster="api",endpoint="10.0.0.1:8080"} 7
```

拨号失败、响应数和健康变迁带双标签；"所有端点都满"的甩掉只带
`cluster`，因为没有哪个单端点是"那个满的"。
`zgix_endpoint_inflight` 是均衡器比较的水位；
`zgix_endpoint_healthy` 是探测器的当前判定，只为带健康检查的集群
渲染。

# 甩掉阶梯

每一级耗尽都有定义好的应答和点名它的计数器：

| 计数器 | 何时累加 |
|---|---|
| `zgix_l7_shed_upstream_slots` | HTTP 请求拿不到上游槽位 —— 该加宽池子，而不是后端太忙 |
| `zgix_l4_shed_endpoint_inflight` / `zgix_l7_shed_endpoint_inflight` | 所有端点都到 `max_inflight` —— 唯一"关闭"的限制 |
| `zgix_l7_shed_tunnels` | 隧道池已满；升级在消耗后端连接之前被 `503` 拒绝 |
| `zgix_l7_shed_relay_buffers` | 被准入的交换拿不到转发缓冲对 |
| `zgix_l7_rate_limited` / `zgix_l7_rate_limit_full` | 客户端超出令牌桶（`429`）/ 身份表八探无空槽（放行 —— 该加宽 `rate_limit_entries`） |
| `zgix_l7_conn_limited` / `zgix_l7_conn_limit_full` | 客户端连接数越过 `conn_limit.max`（`503`）/ 表放不进该身份（放行） |
| `zgix_l7_body_over_limit` | 声明的 `Content-Length` 超过 `max_body_bytes`，在拨源站之前回答 `413` |
| `zgix_l7_body_cut_mid_stream` | chunked 正文在响应腿武装后越限 —— 剩下唯一能做的就是拆连接 |
| `zgix_l7_keepalive_requests_capped` | 连接越过 `keepalive_requests`；响应宣告 `Connection: close` |

`*_full` 上涨是加宽表的信号，不是事故；`*_limited`/`*_shed_*`
才是拒绝本身。

# 判定与策略

| 计数器 | 含义 |
|---|---|
| `zgix_l7_responses` | 以源站（或罐装）状态码完成的交换 |
| `zgix_l7_bad_gateway` / `zgix_l7_gateway_timeout` | 拨号失败或源站答得太慢（`502` / `504`） |
| `zgix_l7_request_timeout` | 单个交换超出 `request_ms` |
| `zgix_l7_head_budget_expired` | 连接在 `head_ms` 内什么都没说 —— slowloris 收割，能答时答 `408` |
| `zgix_l7_redirected` / `zgix_l7_responded` / `zgix_l7_rejected` | 过滤器终结动作：迁移、正文应答、拒绝 —— 永不相混 |
| `zgix_l7_waf_blocked` | 字面量黑名单命中 |
| `zgix_l7_sticky_followed` / `_assigned` / `_repicked` | cookie 粘性的三分支：遵循指派、铸发指派、摘除后重选。repick 率上涨意味着后端在粘性人群下抖动 |
| `zgix_forwarded_chain_dropped` | 超过 512 字节的 `X-Forwarded-For` 链，整条丢弃而不是截断 |
| `zgix_tunnels_established` / `zgix_tunnels_drained` | 升级成会话的数量 / 排空时被切断的隧道 |
| `zgix_l7_responses` ＋ 甩掉计数器 | 与访问日志行、直方图计数精确对账 |

# L4 两张表

| 计数器 | 含义 |
|---|---|
| `zgix_l4_sni_routed` / `_absent` / `_no_route` / `_invalid` | SNI 路由结局：已转发、没写服务器名、写了没人认领、开头字节不是 ClientHello |
| `zgix_l4_proxy_header_accepted` / `_invalid` | PROXY 协议 v1/v2 头解析成功 / 拒绝 —— `invalid` 上涨意味着配置之外的东西正在摸到监听 |
| `zgix_l4_proxy_header_sent` | 发往发送集群的头部，每条拨号连接一次 |

# TLS 与内核压力

- `zgix_tls_handshakes_completed`、`zgix_tls_resumed` —— 握手量与
  恢复占比；重启后这里会显示为恢复率在一个客户端代际内回落。
- `zgix_kernel_pressure_errors` 及按操作拆分
  （`zgix_kernel_pressure_accept`、`_connect`、`_recv`、`_send`、
  `_set_option`）和按原因拆分（`_out_of_buffers`、`_out_of_memory`、
  `_fd_limit`、`_address_unavailable`、`_other_cause`）—— 两个
  分区都等于总量，且在每个仿真种子上被断言。非零意味着内核拒绝
  了资源，这是第一个该查的，然后才怀疑 zgix。

# 池量表

每个池都有在用数对照容量：

```text
zgix_conn_slots_in_use 42
zgix_conn_slots_capacity 1386
zgix_relay_buffers_in_use 17
zgix_head_buffers_in_use 9
zgix_upstream_head_buffers_in_use 3
```

……TLS 集群拨号时还有 `zgix_upstream_slots_*`，以及压力标志
`zgix_conn_pressure_engaged`、`zgix_relay_pressure_engaged`、
`zgix_head_pressure_engaged`、`zgix_upstream_pressure_engaged`、
`zgix_upstream_head_pressure_engaged` —— 各在 3/4 占用时升起、
回落到 1/2 才降下。

# 访问日志

`zgix_access_log_dropped`（汇卡住付的是丢行，永不付延迟）、
`zgix_access_log_reopened`、`zgix_access_log_reopen_failed`。抓取
本身以 `# zgix_access_log` 标记和最新 128 行（`# <json>` 注释
形式）收尾。

# 退出统计

`SIGTERM` 在退出路上打印一次计数器 —— 那是它们到达 stderr 仅有的
另一处，外加卡死排空的诊断。Prometheus 展示始终是快照：同一条流上
的两份快照会互相失效。
