---
title: 安装
sidebar_label: 安装
description: 用 Zig 0.17 从源码构建 zgix，或用 devenv 激活固定工具链。
---

# 环境要求

- **Zig 0.17**。整棵树以该版本为基准固定并通过 CI。

使用 [devenv](https://devenv.sh) 时，`.envrc` 会在 `cd` 时自动激活同一套
shell；也可以手动进入：

```sh
devenv shell        # zig 0.17、zls、kcov
```

# 构建

```sh
git clone https://github.com/chy3xyz/zgix
cd zgix
zig build -Doptimize=ReleaseSafe
```

二进制落在 `zig-out/bin/zgix`。直接用 `zig build` 产出的是 Debug
二进制 —— 开发 zgix 够用，但引用性能数字时请用 `-Doptimize=ReleaseFast`
或 `ReleaseSafe` 构建。

常用的构建目标：

```sh
zig build                 # zig-out/bin/zgix（Debug）
zig build ci              # 每次改动的门禁：测试 + lint + 仿真 + 冒烟
zig build test            # 单元测试
zig build sim -- 0 500    # 确定性仿真器：[种子] [迭代次数]
zig build smoke           # 实机门禁：真二进制对真实源站
zig build schema          # 生成 zig-out/config.schema.json
```

# 确认能跑

```sh
zgix --version      # 打印版本（-V）
zgix --help         # 用法摘要（-h）
```

Release 构建打印纯版本号，例如 `zgix 0.9.0`；发布之后从源码构建会加上
区分信息，如 `zgix 0.9.0 (v0.9.0-5-gabc1234)`；树有未提交改动时再追加
`-dirty` —— 因此 bug 报告里的版本号能精确对应到某次构建。

# 预编译二进制

目前还没有发布渠道：请从源码构建。一行安装脚本
（`curl -fsSL https://zgix.click/install.sh | sh`）将随首个 release
提供。
