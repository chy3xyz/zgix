---
title: 限流与 WAF
sidebar_label: 限流与 WAF
description: 按客户端的令牌桶、连接数上限，以及监听级字面量黑名单 —— HTTP 路径上的三道准入控制。
---

HTTP 路径上跑着三道准入控制，全部按需开启，各有专属计数器，因此
"被拒绝"永远不会和源站的应答混淆。

# 限流

按客户端 IPv4 `/32` 或 IPv6 `/64`（与 `client` 过滤和 `source_ip`
哈希相同的身份） keyed 的令牌桶。超出速率时请求被回答 `429`，且连接
关闭 —— 正文可能还没读完：

```json
"listeners": [
    { "bind": "0.0.0.0:443", "http": {
        "cluster": "api",
        "rate_limit": { "requests": 100, "window_ms": 1000, "burst": 200 } } }
],
"limits": { "rate_limit_entries": 4096 }
```

| 字段 | 含义 |
|---|---|
| `requests` | 每个 `window_ms` 补充的令牌数 |
| `window_ms` | 补充窗口 |
| `burst` | 桶容量；可选，默认等于 `requests`，不得小于 `requests` |
| `limits.rate_limit_entries` | 进程级表槽数（每条 32 B），任何监听有限流时**必填** |

表在加载时定容，最多探测八个槽位 —— 每请求零分配，无无界扫描。key 是
按地址而非按监听，因此同一客户端打两个监听共享一只桶。探测八次找不到
空槽时**放行**并累加 `zgix_l7_rate_limit_full` —— 这个数上涨是"该加宽
`rate_limit_entries`"的信号，不是事故。`zgix_l7_rate_limited` 计数
`429`。

桶由任何被准入的请求消耗 —— 包括随后被 WAF 规则拒绝的请求 —— 而
畸形或超大的请求在此检查之前就被回答，因此攻击者无法用垃圾消耗令牌。

# 连接数上限

`conn_limit` 限制一个客户端身份同时持有的连接数。令牌桶回答"请求
太多"，它回答"socket 太多"，两者相互独立：

```json
"listeners": [
    { "bind": "0.0.0.0:443", "http": {
        "cluster": "api",
        "conn_limit": { "max": 256 } } }
],
"limits": { "conn_limit_entries": 4096 }
```

连接在**首个被准入的请求**处计数，而不是 accept 时 —— 解析完 PROXY
协议头才是监听知道真实客户端的第一个点。keep-alive 连接上的每个请求
共享这一个计数。越过 `max` 的请求回答 `503`；表内八次探测放不进该
身份时**放行**并累加 `zgix_l7_conn_limit_full`，而
`zgix_l7_conn_limited` 计数 `503`。

# WAF-lite：字面量黑名单

监听级的字面量黑名单，每请求一次、在过滤器遍历之前求值。命中按配置
的状态码回答，永不被路由或拨号；过滤器里的 `allow` 无法豁免它：

```json
"http": {
    "cluster": "api",
    "waf": { "deny": ["union select", "<script", "../"], "status": 403 }
}
```

- `deny` 为 1..64 个字面量，每个 1..256 字节，ASCII 大小写不敏感地
  匹配规范化路径、原始查询串和每个头部的**值**。
- `status` 默认 `403`，可为 `400`、`403`、`404` 或 `429`。
- `zgix_l7_waf_blocked` 计数命中。

它刻意只看头部：不做正文检查、不做百分号解码、没有正则、没有 Unicode
折叠、也没有子串的出处判定。这些既是绕过面也是误杀面 —— 查询参数里
一个无害的 `select` 会和注入一样被拒绝。把它当作严格请求解析、CIDR
规则和限流旁边的一层，而不是完整 WAF 的替代品。正文扫描未实现。

更丰富的规则 —— `allow` 白名单、CIDR 匹配、头部编辑、改写，以及
终结性的 `reject`/`redirect`/`respond` 动作 —— 用 `request_filters`；
见[配置参考](/03-reference/config.md)。
