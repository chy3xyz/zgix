---
title: systemd
sidebar_label: systemd
description: 一个 zgix 的 systemd unit —— 启动前校验、fd 上限、停止时优雅排空，以及配置变更的 SO_REUSEPORT 交接。
---

一个把这些运维规矩固化下来的 unit：进程启动前先校验配置，给它
定价出来的 fd 预算，让 `SIGTERM` 完成排空。

```ini
[Unit]
Description=zgix L4/L7 edge proxy
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStartPre=/usr/local/bin/zgix --check /etc/zgix/config.json
ExecStart=/usr/local/bin/zgix /etc/zgix/config.json
ExecReload=/bin/kill -HUP $MAINPID

# 启动横幅会为 fd 需求定价并对照 RLIMIT_NOFILE 断言。
# 让 limit 匹配这台机器将要运行的最大配置。
LimitNOFILE=65536

# zgix 在 SIGTERM 时排空：监听关闭，keep-alive 不再被尊重，
# 在飞工作完成。把等待交给它，然后硬杀。
TimeoutStopSec=30
KillSignal=SIGTERM
SendSIGKILL=yes

Restart=on-failure
RestartSec=2

# stdout 属于访问日志
StandardOutput=append:/var/log/zgix/access.log
StandardError=journal

[Install]
WantedBy=multi-user.target
```

# 每一段为什么在那里

- **`ExecStartPre=zgix --check`** —— 一份被拒绝的配置永远到不了
  监听：预启动失败，老进程从未收到信号、继续服务。手册里的两条
  命令交接变成一次 `systemctl restart`。
- **`LimitNOFILE`** —— 启动时会把软上限提到横幅打印的 fd 预算；
  硬上限是 `--check` 以退出码 `2` 撞上的那堵墙。按最大配置定
  unit，让检查和启动达成一致。
- **`TimeoutStopSec` vs `drain_deadline_ms`** —— 默认排空会等最后
  一条连接（`drain_deadline_ms: 0`），而发送信号的一方拥有最终
  上限。当你想让 zgix 在 systemd 的 `TimeoutStopSec` 以 `SIGKILL`
  结束等待之前先放弃时，在配置里设 `drain_deadline_ms`。
- **`StandardOutput=append:...`** —— 配上 `"sink": "stdout"`，
  访问日志就是进程的 stdout，由 systemd 追加进文件。移动式轮转
  仍可通过 `ExecReload` 获得（`SIGHUP` 重开 `file` 汇；对 stdout
  汇是 no-op —— 那种请走 journal 轮转）。
- **`Restart=on-failure`** —— systemd 看不见事件循环停摆这种
  故障；在配置里武装 `timeouts.loop_watchdog_ms`，让进程自己
  退出（码 6）、由监督者换一个新。

# 改配置

没有重载 —— 池子在启动时定容、永不增长。`systemctl restart` 是
安全的，因为每个监听都以 `SO_REUSEPORT` 绑定：预启动的 `--check`
把住交接，新进程绑定同一端口、老进程排空，内核把新连接按 4-tuple
散列到组里的进程上。重叠窗口里两份配置都在应答，这不是切换。

::: warning
默认情况下交接不是无损的：老进程已 accept 但尚未服务的连接会在
它关闭监听时被 reset。Linux 5.14 加入的 `net.ipv4.tcp_migrate_req`
（默认关）会把它们迁移到组里另一条 socket —— 需要无损交接就打开
它。
:::

# 用满多核

一个进程拥有一个线程和一条事件循环；受支持的扩容是 N 个独立
进程挂在 `SO_REUSEPORT` 后面。同一端口跑 N 个实例，内核在它们
之间均衡 4-tuple：

```ini
# zgix@.service —— 用 systemctl enable --now zgix@1 zgix@2 实例化
[Unit]
Description=zgix instance %i
After=network-online.target

[Service]
Type=simple
ExecStartPre=/usr/local/bin/zgix --check /etc/zgix/config.json
ExecStart=/usr/local/bin/zgix /etc/zgix/config.json
LimitNOFILE=65536
TimeoutStopSec=30
Restart=on-failure
RestartSec=2
StandardOutput=append:/var/log/zgix/access.log
StandardError=journal

[Install]
WantedBy=multi-user.target
```

会话票不在进程间共享，因此客户端可能落在没有给它发票的进程上、
多付一次完整握手 —— 扩容后盯一下 `zgix_tls_resumed`，看实际拿到
的恢复占比。
