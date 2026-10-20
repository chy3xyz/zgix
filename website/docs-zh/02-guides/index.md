---
title: 指南
sidebar_label: 指南
description: 面向任务的指南 —— 路由、TLS、HTTP/3、WebSocket、限流与 WAF、压缩、上游 TLS 和可观测性。
---

一篇一个主题：

- [监听与路由](listeners-and-routes.md) —— `l4` 与 `http`、host/header/prefix 路由表、多租户 SNI。
- [TLS 证书](tls-certificates.md) —— 终结 TLS 1.3、SNI 证书组、证书重载。
- [HTTP/3](http3.md) —— 实验性 QUIC 监听、它的上限与计数器。
- [WebSocket](websockets.md) —— 隧道化升级和独立的隧道池。
- [限流与 WAF](rate-limiting-and-waf.md) —— 令牌桶、连接数上限、字面量黑名单。
- [压缩](compression.md) —— 预压缩的静态应答，以及那条刻意收窄的代理响应压缩。
- [上游 TLS](upstream-tls.md) —— 向后端发起 TLS 1.3、mTLS、校验。
- [访问日志与管理面板](access-log-and-admin-panel.md) —— JSON 日志、汇与轮转、管理抓取和内置面板。
