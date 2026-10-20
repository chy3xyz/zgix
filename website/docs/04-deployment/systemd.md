---
title: systemd
sidebar_label: systemd
description: A systemd unit for zgix — pre-start validation, fd limits, graceful drain on stop, and the SO_REUSEPORT handoff for config changes.
---

A unit that encodes the operational rules: validate the config before the
process starts, give it the fd budget it priced, and let `SIGTERM` drain.

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

# The startup banner prices the fd demand and asserts it against
# RLIMIT_NOFILE. Match the limit to the largest config this box will run.
LimitNOFILE=65536

# zgix drains on SIGTERM: listeners close, keep-alive stops being honoured,
# in-flight work finishes. Let it own the wait, then hard-kill.
TimeoutStopSec=30
KillSignal=SIGTERM
SendSIGKILL=yes

Restart=on-failure
RestartSec=2

# stdout belongs to the access log
StandardOutput=append:/var/log/zgix/access.log
StandardError=journal

[Install]
WantedBy=multi-user.target
```

# Why each piece is there

- **`ExecStartPre=zgix --check`** — a config zgix refuses never reaches a
  listener: the pre-start fails and the old process, never signalled, keeps
  serving. The manual's two-command handoff becomes one `systemctl restart`.
- **`LimitNOFILE`** — a start raises the soft limit to the fd budget the
  banner printed; the *hard* limit is the wall `--check` exits `2` against.
  Size the unit to your largest config so the check and the start agree.
- **`TimeoutStopSec` vs `drain_deadline_ms`** — by default a drain waits for
  its last connection (`drain_deadline_ms: 0`), and whatever sent the signal
  owns the upper bound. Set `drain_deadline_ms` in the config when you want
  zgix to give up before systemd's `TimeoutStopSec` ends the wait with
  `SIGKILL`.
- **`StandardOutput=append:...`** — with `"sink": "stdout"` the access log
  is the process's stdout; systemd appends it to the file. Move-based
  rotation stays available through `ExecReload` (`SIGHUP` reopens a `file`
  sink; on a stdout sink it is a no-op — rotate the journal instead).
- **`Restart=on-failure`** — a stalled event loop is a case systemd cannot
  see; arm `timeouts.loop_watchdog_ms` in the config so the process exits
  (code 6) and the supervisor replaces it.

# Changing the config

There is no reload — the pools are sized at startup and never grow.
`systemctl restart` is safe because every listener binds with
`SO_REUSEPORT`: the pre-start `--check` gates the handoff, the replacement
binds the same port while the old process drains, and the kernel hashes new
connections onto whichever process holds the group. The overlap is a window
where both configs answer, not a cutover.

::: warning
The handoff is not lossless by default: connections the old process accepted
but never served are reset when it closes its listener. Linux 5.14 added
`net.ipv4.tcp_migrate_req` (off by default), which migrates them to another
socket in the group — turn it on where the handoff must be clean.
:::

# Using more than one core

One process owns one thread and one event loop; the supported scale-out is
N independent processes behind `SO_REUSEPORT`. Run N units on the same port
and the kernel balances 4-tuples across them:

```ini
# zgix@.service — instantiate with: systemctl enable --now zgix@1 zgix@2
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

Session tickets are not shared between processes, so a client may land on
the process that did not issue its ticket and pay one full handshake —
watch `zgix_tls_resumed` across a scale-out for the share you actually get.
