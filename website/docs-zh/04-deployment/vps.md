---
title: 一次 VPS 部署实录
sidebar_label: VPS 实录
description: 一次有记录的单机 VPS 部署 —— 一张泛域名证书、三个应用、:443 上的 host 路由，以及同名上的 h3 监听。
---

一台小机器、三个应用、一个边缘。这份实录的要点：一张泛域名证书
覆盖所有应用，而把它们分开的是路由表 —— 不是额外的设施。

# 拓扑

```text
                        VPS（一个公网 IPv4）
┌──────────────────────────────────────────────────────────┐
│  zgix                                                    │
│    :80   http  → 重定向到 https，承接 acme http-01       │
│    :443  http+tls → host 路由：                          │
│           app.example.com     → 集群 app  （unix socket）│
│           api.example.com     → 集群 api  （127.0.0.1）  │
│           grafana.example.com → 集群 grafana             │
│           example.com、www    → 集群 web                 │
│    :443/udp h3（同一张证书、同一张路由表）               │
│    127.0.0.1:9100 admin（抓取 + 日志尾）                 │
└──────────────────────────────────────────────────────────┘
```

这个形状物有所值，三个原因：

- 一张泛域名为所有应用扛流量；续期只碰一对文件和一次 `SIGHUP`。
- 每个应用是一个集群，有自己的健康检查、均衡策略和 inflight 上限
  —— grafana 变慢不会借走 web 的上游租约。
- h3 监听用同一个名字、同一张路由表应答 HTTP/3 客户端，因此
  QUIC 的采用是客户端的决定，而不是配置的岔路。

# DNS

```text
example.com      A     <vps-ip>
*.example.com    A     <vps-ip>
```

泛域名就是后面一切无趣的前提：之后每加一个应用，就是加一行路由
和一个集群，而不是一次证书申请。

# 证书

签发一次（任意 ACME 客户端），放进 unit 预期的位置：

```sh
install -d -m 0755 /etc/zgix
install -m 0644 fullchain.pem /etc/zgix/fullchain.pem
install -m 0600 key.pem       /etc/zgix/key.pem
```

密钥必须是 ECDSA P-256 或 P-384 —— RSA 密钥在启动时被拒绝。续期
是两条命令，挂在 ACME 客户端的 deploy hook 上：

```sh
# deploy hook，每次续签成功后在小机上运行
install -m 0644 fullchain.pem /etc/zgix/fullchain.pem
install -m 0600 key.pem       /etc/zgix/key.pem
systemctl reload zgix        # SIGHUP：新一代上岗，老一代完成在飞握手
```

重载失败会保留老一代并点名坏文件 —— 坏掉的续期不可能把监听打挂。
抓取上的 `zgix_cert_info` 每组证书带 `not_after`/`days_left`，
过期会在握手断掉之前很久先告警。

# 配置

```json
{
    "listeners": [
        {
            "bind": "0.0.0.0:80",
            "http": {
                "cluster": "nowhere",
                "request_filters": [
                    { "match": { "path_prefix": "/.well-known/acme-challenge/" },
                      "actions": [{ "allow": true }] },
                    { "actions": [{ "redirect": { "status": 308, "scheme": "https" } }] }
                ]
            }
        },
        {
            "bind": "0.0.0.0:443",
            "http": {
                "routes": [
                    { "host": "app.example.com",     "prefix": "/", "cluster": "app" },
                    { "host": "api.example.com",     "prefix": "/", "cluster": "api" },
                    { "host": "grafana.example.com", "prefix": "/", "cluster": "grafana" },
                    { "host": "www.example.com",     "prefix": "/", "cluster": "web" },
                    { "prefix": "/", "cluster": "web" }
                ]
            },
            "tls": {
                "certificates": [
                    { "cert": "/etc/zgix/fullchain.pem", "key": "/etc/zgix/key.pem" }
                ]
            }
        }
    ],
    "h3_listeners": [
        {
            "bind": "0.0.0.0:443",
            "routes": [
                { "host": "app.example.com",     "prefix": "/", "cluster": "app" },
                { "host": "api.example.com",     "prefix": "/", "cluster": "api" },
                { "host": "grafana.example.com", "prefix": "/", "cluster": "grafana" },
                { "prefix": "/", "cluster": "web" }
            ],
            "tls": { "cert": "/etc/zgix/fullchain.pem", "key": "/etc/zgix/key.pem" },
            "error_pages": { "no_route": "friendly-404" }
        }
    ],
    "clusters": {
        "app": {
            "endpoints": ["unix:/run/app/app.sock"],
            "check": { "type": "http", "path": "/healthz", "expect_status": 200 },
            "passive_ejection": { "fall": 5, "recovery_ms": 30000 }
        },
        "api": {
            "endpoints": ["127.0.0.1:9001", "127.0.0.1:9002"],
            "pick": "p2c",
            "check": { "type": "http", "path": "/healthz", "expect_status": 200 }
        },
        "grafana": {
            "endpoints": ["127.0.0.1:3000"],
            "check": { "type": "tcp" }
        },
        "web": {
            "endpoints": ["127.0.0.1:8080"],
            "check": { "type": "tcp" }
        },
        "nowhere": { "endpoints": ["127.0.0.1:9"] }
    },
    "bodies": {
        "friendly-404": {
            "inline": "nothing here matches your request",
            "content_type": "text/plain"
        }
    },
    "admin": { "bind": "127.0.0.1:9100" },
    "access_log": { "sink": "file", "path": "/var/log/zgix/access.log" }
}
```

值得抄走的细节：

- `:80` 监听的存在意义是重定向和应答 ACME http-01。挑战路径在
  catch-all 308 之前被 `allow`，因此续期永远不依赖应用。`nowhere`
  集群是加载器的形式要求 —— 监听必须点名一个集群，但过滤器
  先回答，所以永远不会有东西被拨到。
- `app` 监听在 **unix socket** 上 —— 没有回环端口可撞，文件系统
  权限就是 ACL，最忙的那条腿上也没有临时端口耗尽。路径规矩
  （绝对、≤ 103 字节）见[配置参考](/03-reference/config.md)。
- `app` 上的 `passive_ejection`：`tcp` 检查在内核 accept 时就算
  通过，哪怕背后的应用已经卡死；连续 `fall` 次*失败请求*才摘除，
  30 秒后放回来由流量重新审判。
- h3 路由表是 TCP 表减去 `www` —— 同一张证书、同一批集群。盯一下
  `zgix_h3_no_route`：它是拼错 host 的探针的运维信号。

# 防火墙

```sh
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow 443/udp        # QUIC —— h3 监听
ufw deny 9100/tcp        # admin 反正只绑回环
```

漏掉 `443/udp` 是最经典的 h3 部署 bug：TCP 一切正常，QUIC 静悄悄
地不来，唯一的症状是 `zgix_h3_requests` 缺席。

# 拉起来

```sh
zgix --check /etc/zgix/config.json
systemctl enable --now zgix
curl -sI http://example.com/                       # 308 到 https
curl -s  https://api.example.com/healthz           # 走路由表
curl --http3-only -s https://app.example.com/      # QUIC 这条腿
ssh -L 9100:127.0.0.1:9100 vps 'sleep 3600' &      # 面板开在一个标签页：
#   python3 -m http.server 8080 --directory panel  → http://127.0.0.1:8080/
```

真实流量进来一分钟内，面板的概览视图就会显示出 h3 会话与 TCP 池
的对比；站点视图把 `zgix_listener_info`/`zgix_route_info` 读回来
 —— 你在配置里画的那张拓扑，从抓取里渲染出来。
