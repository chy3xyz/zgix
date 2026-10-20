---
title: TLS 证书
sidebar_label: TLS 证书
description: 在 zgix 上终结 TLS 1.3 —— 单证书与 SNI 证书组、ECDSA 密钥、SIGHUP 重载、会话恢复。
---

给监听加上 `tls` 块，它就说 TLS 1.3 而不是明文。路由、集群和过滤器
都不变 —— 握手作为协议之前的一个阶段运行，因此路由、过滤、重定向和
访问日志与明文下完全一致。

```json
"listeners": [
    { "bind": "0.0.0.0:443", "http": { "cluster": "web" },
      "tls": { "cert": "/etc/zgix/site.crt", "key": "/etc/zgix/site.key" } }
]
```

两个文件在启动时读取一次，因此文件缺失或不可用会让进程带着点名文件的
错误直接退出 —— 绝不会拖到握手中途失败。`cert` 是 PEM 证书链，叶子
在前；`key` 是叶子的 PEM 私钥。

密钥必须是 **ECDSA P-256 或 P-384**。握手跑在事件循环上，一次 RSA 签名
的毫秒级耗时会卡住共享这条循环的其它所有连接；ECDSA 签名约 260 µs。
RSA 密钥在启动时被拒绝。

# 一个监听多个名字

`certificates` 是 SNI 形式：一组或多组 `cert`/`key` 对，按客户端所问
的名字选择。第一条是默认证书 —— 没有 SNI、或名字不被任何条目认领的
客户端拿到它。

```json
"tls": {
    "certificates": [
        { "cert": "/etc/zgix/api.crt", "key": "/etc/zgix/api.key",
          "names": ["api.example.com"] },
        { "cert": "/etc/zgix/www.crt", "key": "/etc/zgix/www.key" }
    ]
}
```

`names` 可选。缺省或为空时，名字取自叶子的 `subjectAltName` DNS 项，
回退到 common name。匹配为 ASCII 大小写不敏感，遵循 RFC 6125：精确
名字，或最左 `*.` 通配符且只匹配一个标签（`*.example.com` 匹配
`a.example.com`，不匹配 `example.com` 或 `a.b.example.com`）。尾部
句点被忽略。一个监听最多 16 组。

# 证书重载

`SIGHUP` 按配置的路径重载整个证书组。新一代服务新握手，老一代完成
已在空中的握手；重载失败会点名监听和证书并保留老一代 —— 一张坏证书
不可能把监听打挂。启动时预留四代（初始加载加三次轮转）—— 第四代之后
再重载会被拒绝，必须重启进程。

这个重载只管入站：集群上游的 `ca_file`、`client_cert` 和 `client_key`
在启动时读取一次，`SIGHUP` 不会重读。

# 会话恢复

恢复默认开启、没有开关。每次完成的握手发给客户端两张会话票，客户端
出示其中一张即可免签名恢复。票是无状态的 —— 每张开在 zgix 内存中的
密钥下 —— 因此恢复不消耗每会话内存，横幅里的预算也不动。两个推论：

- 重启会使所有未过期的票失效（封票密钥从不落盘），因此回访客户端各
  付一次完整握手，之后再次恢复。
- 票不在进程间共享，`SO_REUSEPORT` 交接期间客户端可能落在没有给它
  发票的那个进程上。

票飞行还捎带了客户端 `Finished` 的 ACK；没有它，先写 `Finished` 再写
请求的客户端会被自己的 Nagle 拖住约 45 毫秒。

# 终结不是什么

- 终结只发生在入站。`http` 监听到后端是明文，除非集群自己带 `tls`
  块（见[上游 TLS](upstream-tls.md)）；`l4` 监听永远不发起源于 TLS。
- `limits.tls_engines` 限制同时在飞的 TLS 会话数 —— 这是 zgix 持有
  的最大的单连接对象，约 111 KiB 外加 32 KiB 明文缓冲，因此 1024 个
  约为 170 MiB。默认取连接槽数 capped 在 1024，启动横幅会打印总量。
- 带 `proxy_protocol.send` 的集群无法从终结监听到达：该头在转发缓冲里
  暂存，而被终结的线上字节不经过那里。这个组合在加载时就被拒绝。

握手与恢复都有计数 —— `zgix_tls_handshakes_completed` 和
`zgix_tls_resumed` —— 因此重启之后的恢复率回退会在一个客户端代际之内
反映在抓取里。
