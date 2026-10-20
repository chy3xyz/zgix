---
title: 验证
sidebar_label: 验证
description: 用 curl 验证 TCP 与 TLS 链路、用 HTTP/3 客户端验证 QUIC、看管理抓取和访问日志。
---

在 `zgix config.json` 运行起来之后（见[第一份配置](first-config.md)），
四项检查可以确认每条腿都活着。

# 1. TCP 链路

```sh
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:80/
```

带上 `api` 的 Host 头发请求，走一遍路由表：

```sh
curl -s -H 'Host: api.example.com' http://127.0.0.1:80/healthz
```

# 2. L4 链路

任何指向 SNI 监听的 TLS 客户端都应该表现得像直连后端一样 —— zgix
逐字节转发握手：

```sh
psql 'host=db.example.com port=443 sslmode=require' -c 'select 1'
```

# 3. HTTP/3 链路

让支持 HTTP/3 的客户端直接指向 UDP 端口。用支持 HTTP/3 的 curl：

```sh
curl --http3-only -kv https://127.0.0.1:4443/
```

或者用仓库自带的互操作客户端 —— 一个钉在 IPv4 socket 上的极简 aioquic
客户端。aioquic 默认的双栈 IPv6 路径在某些主机上看起来和服务端挂死
一模一样：

```sh
pip install aioquic
python3 scripts/h3-interop-client.py 4443
# -> STATUS 200 / BODY ...
```

在客户端信任 `Alt-Svc` 提示之前，也可以选择从 `http` 监听里公告 UDP
端口；见 [HTTP/3](/02-guides/http3.md)。

# 4. 管理抓取

```sh
curl -s 127.0.0.1:9100/metrics | grep -E '^zgix_(info|h3_)'
```

应该能看到清单行和 h3 判定计数：

```text
zgix_info{version="0.9.0"} 1
zgix_h3_requests 2
zgix_h3_responses 2
```

抓取的末尾是一段 `# zgix_access_log` 标记和最新 128 行访问日志（以
`# <json>` 注释形式）——[控制面板](/02-guides/access-log-and-admin-panel.md)
的 *logs* 视图解析的正是这一段。

# 5. 访问日志

配置 `"access_log": { "sink": "stdout" }` 后，每个交换落一行 JSON：

```json
{"time":"2026-10-20T09:14:22.481Z","kind":"http","outcome":"ok","client":"10.1.2.3:52344","method":"GET","host":"api.example.com","path":"/v1/items","status":200,"upstream_reused":true,"upstream_replayed":false,"duration_us":1873,"bytes_in":142,"bytes_out":4096,"cluster":"api","upstream":"10.0.0.7:8080"}
```

每个请求恰好落进一个判定桶 —— 仿真器在每种子上断言日志行、计数器和
直方图计数之间的恒等关系 —— 因此 `zgix_l7_responses` 加上甩掉类计数器
永远能和日志行对上。
