---
title: 第一份配置
sidebar_label: 第一份配置
description: 一份完整的 zgix 最小配置 —— L4 监听、HTTP 监听、h3 监听、健康检查、管理端点和访问日志 —— 先用 --check 校验再启动。
---

这份配置是日常会碰到的每个块的最小集合：L4 转发、带 host 路由的 HTTP
反向代理、实验性 HTTP/3 监听、健康检查、管理抓取和 JSON 访问日志。存为
`config.json`：

```json
{
    "listeners": [
        {
            "bind": "0.0.0.0:80",
            "http": {
                "routes": [
                    { "host": "api.example.com", "prefix": "/", "cluster": "api" },
                    { "prefix": "/", "cluster": "web" }
                ]
            }
        },
        {
            "bind": "0.0.0.0:443",
            "l4": {
                "routes": [
                    { "sni": "db.example.com", "cluster": "postgres" },
                    { "cluster": "fallback" }
                ]
            }
        }
    ],
    "h3_listeners": [
        {
            "bind": "0.0.0.0:4443",
            "routes": [
                { "host": "api.example.com", "prefix": "/", "cluster": "api" },
                { "prefix": "/", "cluster": "web" }
            ],
            "tls": { "cert": "/etc/zgix/fullchain.pem", "key": "/etc/zgix/key.pem" }
        }
    ],
    "clusters": {
        "web": {
            "endpoints": ["127.0.0.1:9000"],
            "check": { "type": "tcp", "fall": 3, "rise": 2 }
        },
        "api": {
            "endpoints": ["127.0.0.1:9001", "127.0.0.1:9002"],
            "pick": "p2c",
            "check": { "type": "http", "path": "/healthz", "expect_status": 200 }
        },
        "postgres": { "endpoints": ["127.0.0.1:5432"] },
        "fallback": { "endpoints": ["127.0.0.1:8443"] }
    },
    "admin": { "bind": "127.0.0.1:9100" },
    "access_log": { "sink": "stdout" }
}
```

从上到下读一遍：

- `:80` 监听是 `http` 反向代理。路由表按 `host`、可选的 `header` 谓词、
  再按最长 `prefix` 匹配 —— `api.example.com` 走 `api` 集群，其余走
  `web`。
- `:443` 监听是按 TLS 服务器名（SNI）路由的 `l4` 转发，不终结 TLS ——
  后端与客户端直接完成握手，zgix 看不到任何明文。
- h3 监听在 UDP `:4443` 上终结 QUIC-TLS，经由同样的集群代理。QUIC 没有
  明文模式，因此 `tls` 必填。
- 每个集群都列出端点；除显而易见的本地集群外都带健康检查：`tcp`
  证明端口接受连接，`http` 证明应用真的会应答。
- `admin` 提供 Prometheus 抓取和一段有界的访问日志尾。
- `access_log` 每个交换写一行 JSON 到 stdout。

每个 TCP 监听必须且只能有一个协议键（`l4` 或 `http`）；`bind` 和
`tls` 位于协议体之外，因为两者通用。

# 先定价，再运行

```sh
zgix --check config.json
```

`--check` 加载配置、打开它点名的每个文件、为内存池定价、对照
`RLIMIT_NOFILE` 测算 fd 需求 —— 完成启动在横幅之前的一切 —— 然后退出，
不绑定端口：

```text
zgix 0.9.0
budgets:
  memory  total 47297 KiB = conn slots 1386 x 512 B + stream slots 1386 x 1552 B
          + relay buffers 1386 x 32808 B
          + ...
  fds     4093 required (asserted against RLIMIT_NOFILE)
  ring    4096 entries, completion queue 8192, in-flight ops <= 6869
  config  2 listener(s), 4 cluster(s), 0 error page(s), access log on
  rlimit  RLIMIT_NOFILE 1024 soft, 524288 hard (a start raises the soft limit to the fd budget)
  check   config.json: valid, and this box can start it
```

退出码可以直接给 CI 分支用：

| 退出码 | 含义 |
|---|---|
| `0` | 配置可加载，且本机可以启动它 |
| `1` | 配置错误 —— 不可读、不可解析、语义拒绝，或点名的文件无法加载 |
| `2` | 配置正确，但*本机*装不下：fd 预算超过 `RLIMIT_NOFILE` 硬上限 |

::: tip
`--check` 做的是完整加载，因此它需要代理运行时所需要的一切文件权限 ——
在生产证书机器上签发的配置，拿到没有证书的 agent 上是校验不过的。
另外 `access_log` 的 `file` 汇会在文件缺失时创建它，和真正启动时一样。
:::

# 启动

```sh
zgix config.json
```

启动横幅和退出统计走 stderr；stdout 属于访问日志。如果 fd 预算超过本机
`RLIMIT_NOFILE` 硬上限，合法的配置也会在横幅打印后被拒绝，屏幕上同时
给出数字和原因。

配置没有热重载：内存池、ring 和每张表都在启动时定容，永不增长。要改配置
就换进程 —— 监督式交接见 [systemd](/04-deployment/systemd.md)。
