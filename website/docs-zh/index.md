---
layout: home
title: zgix 文档
description: 如何运行、配置和运维 zgix —— 一个零分配的 L4/L7 边缘代理，带实验性 HTTP/3。
hero:
  name: zgix
  text: 零分配 L4/L7 边缘代理，用 Zig 写成。
  tagline: 内存在启动时全部预留，每个上限都是编译期常量，资源耗尽时在既定的阶梯上甩掉负载。HTTP/3 over QUIC 为实验特性，但可观测性与其它路径一致。
  actions:
    - theme: brand
      text: 开始上手
      link: 01-getting-started/
    - theme: alt
      text: English docs
      link: https://zgix.click/docs/
features:
  - title: 零分配服务
    details: 请求路径上不做任何分配。各内存在启动时按编译期常量定容并打印在横幅里，并在绑定端口前对照 RLIMIT_NOFILE 断言。
  - title: HTTP/3 over QUIC
    details: 实验性的 h3_listeners 终结 QUIC-TLS，再通过池化的 HTTP/1.1 腿上联 —— 判定计数与访问日志一应俱全。
  - title: SNI 多租户 TLS
    details: 每个监听最多 16 组证书对终结 TLS 1.3，或按 SNI 盲转发。一个 :443 承接多个 TLS 服务。
  - title: WebSocket 隧道
    details: 按需开启的升级转发，使用独立的、有上限的隧道池，长连接永远不会挤占 HTTP 的缓冲。
  - title: 声明式 JSON 配置
    details: 一个文件，未知字段直接拒绝，--check 在绑定端口前为配置定价。配置不热更，用进程交接代替。
  - title: Prometheus 级可观测性
    details: zgix_* 计数家族、per-endpoint 健康度、RED 直方图、JSON 访问日志、抓取接口上的有界日志尾，以及内置控制面板。
---

# 快速开始

从源码构建（需要 Zig 0.17），然后用一个 JSON 配置启动二进制：

```sh
git clone https://github.com/chy3xyz/zgix
cd zgix
zig build -Doptimize=ReleaseSafe
```

二进制只接受一个参数：JSON 配置的路径。`--check` 会加载配置、为每个
内存池定价、测算 fd 需求 —— 完成启动前除绑定端口外的全部工作 —— 然后
退出：

```sh
zgix --check config.json   # 校验并定价，不绑定端口
zgix config.json           # 启动代理
```

最小配置 —— 一个 L4 监听转发到一个源站 —— 就是整个文件；其它所有块都有
默认值：

```json
{
    "listeners": [
        { "bind": "127.0.0.1:8080", "l4": { "cluster": "origin" } }
    ],
    "clusters": {
        "origin": { "endpoints": ["127.0.0.1:9000"] }
    }
}
```

从[快速上手](01-getting-started/)开始，浏览[指南](02-guides/)，或跳到[参考](03-reference/)。

::: warning
zgix 仍是实验性软件。HTTP/3 尤其是一条刻意收窄的路径 —— 没有过滤器、
没有限流 —— 它的计数器带 `h3_` 前缀，可以独立于 TCP 路径观察。
:::
