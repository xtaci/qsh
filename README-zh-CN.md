qsh
------------

[![GoDoc][1]][2] [![Go Report Card][3]][4] [![CreatedAt][5]][6]

[1]: https://godoc.org/github.com/xtaci/qsh?status.svg
[2]: https://pkg.go.dev/github.com/xtaci/qsh
[3]: https://goreportcard.com/badge/github.com/xtaci/qsh
[4]: https://goreportcard.com/report/github.com/xtaci/qsh
[5]: https://img.shields.io/github/created-at/xtaci/qsh
[6]: https://img.shields.io/github/created-at/xtaci/qsh

[English](README.md) | 简体中文

状态：开发中

项目概述
--------
`qsh` 是一款使用 Go 语言编写的安全远程 Shell 工具，目标是提供与 SSH 一致的体验，同时在协议层面拥抱后量子密码学。核心加密能力由作者的两个项目提供：负责认证与密钥协商的 [HPPK](https://github.com/xtaci/hppk) 以及用于数据通道加密的 [QPP](https://github.com/xtaci/qpp)。单一可执行文件即可扮演客户端或服务器，并内置密钥对生成指令，部署与运维路径清晰。

核心特性
------------
- **可信身份验证**：服务器结合客户端白名单与 HPPK 签名校验，确保“谁在接入”始终可追溯、可审计。
- **量子安全通信**：双方通过 HKDF 派生独立的 QPP 会话密钥，并为每条连接随机协商 1024–2048 范围内的素数密码本参数，抵御长线重放与窃听。
- **结构化控制平面**：握手、质询、窗口调整、密文传输等全部消息都由 `protocol/` 中的 Protobuf 定义统一封装，便于演进与调试。
- **完整的终端语义**：服务器通过 `/bin/sh` 拉起 PTY，实时转发 stdout/stderr，支持窗口大小变更，交互体验与本地终端保持一致。
- **内建密钥管理**：使用 `qsh genkey -o <path>` 即可生成 JSON 形式的密钥对，私钥自动由口令加密并配合 `memguard` 做内存保护。
- **安全内存处理**：私钥与口令始终驻留在受保护的内存区，避免交换分区、core dump 等场景泄露敏感数据。

快速开始
-----------
1. **生成密钥对**（首次部署执行一次）：

	```bash
	# 生成服务器主机密钥
	qsh genkey -o ./server_hppk

	# 生成客户端密钥
	qsh genkey -o ./id_hppk
	```

	将 `id_hppk.pub` 拷贝到服务器，并在启动命令中通过 `-c client-1=/path/to/id_hppk.pub` 进行绑定。

2. **启动服务器**：

	```bash
	qsh server -l :2323 --host-key ./server_hppk -c client-1=/etc/qsh/id_hppk.pub
	```

	或改用 JSON 配置集中管理客户端：

	```bash
	qsh server -l :2323 --host-key ./server_hppk --clients-config /etc/qsh/clients.json
	```

3. **客户端连接**：

	```bash
	qsh -i ./id_hppk -P 2323 client-1@203.0.113.10
	```

	未显式指定 `-P` 时默认使用端口 `2222`。若目标地址缺失 `client-id@host` 格式，可通过 `-n/--id` 手动提供。

文件传输（copy）
-----------------
`copy` 子命令沿用交互式客户端的认证链路，实现 SCP 式文件同步。远程路径写法为 `client-id@host:/remote/path`，源与目的必须至少一端为远程。

- **上传**：

	```bash
	qsh copy -i ./id_hppk ./notes.txt client-1@example.com:/tmp/notes.txt
	```

- **下载**：

	```bash
	qsh copy -i ./id_hppk -P 4242 client-1@example.com:/var/log/qsh.log ./qsh.log
	```

命令会自动解析 `client-1` 身份（或使用 `-n/--id` 显式指定），并在建立的加密通道中完成双向校验与数据搬运。

客户端白名单
-------------------
除了多个 `--client` 参数，服务器亦支持通过 `--clients-config` 加载 JSON 格式白名单：

```json
{
	"clients": [
		{ "id": "xtaci", "public_key": "/home/xtaci/xtaci.pub" },
		{ "id": "ops-admin", "public_key": "/etc/qsh/ops-admin.pub" }
	]
}
```

- 每个条目需提供唯一 `id` 与对应 HPPK 公钥路径。
- JSON 配置与命令行 `--client` 可叠加使用，便于临时授权或灰度发布。
- 配置更新后发送 `SIGUSR1`（例如 `kill -USR1 <pid>`）即可热加载，无须重启。

协议流程概览
-----------------
1. **ClientHello**：客户端上送自身 ID，并附带随机 `ServerChallenge`，用于要求服务器证明身份。
2. **ServerHello**：服务器回传主机公钥及对 `ClientHello` 的签名，客户端可与 `known_hosts` 指纹比对（或首次信任后记录），确认对端合法。
3. **AuthChallenge**：服务器返回随机质询、KEM 封装的会话种子以及素数密码本参数。
4. **AuthResponse**：客户端用 HPPK 私钥对质询签名，证明控制权。
5. **AuthResult**：验证通过后，双方使用 HKDF 派生 `qsh-c2s`、`qsh-s2c`，并初始化各自的 QPP pad。
6. **SecureData**：所有 PTY 数据与窗口事件以 `PlainPayload` 表示，经加密后成为 `SecureData` 在通道中流转，直至会话结束。

开发者笔记
---------------
- **环境**：建议使用 Go 1.25.4 或更高版本，依赖定义详见 `go.mod`。
- **测试**：运行 `go test ./...` 可覆盖协议、密钥管理与文件传输的单元测试。
- **代码结构**：
  - `main.go`：CLI 入口与命令路由。
  - `cmd_client.go`、`cmd_server.go`、`cmd_copy.go`：对应三大子命令的业务实现。
  - `session.go`：握手与会话管理。
  - `tty.go`：PTY 生命周期与 I/O 转发。
  - `transfer.go`：上传、下载与结果回执。
  - `channel.go`：具备重放防护的加密通道实现。
  - `protocol/`：Protobuf 消息与长度前缀编解码。
  - `crypto/`：密钥装载、签名、HKDF 及 pad 管理。

许可证
-------
本项目遵循 MIT 许可证，详情见 `LICENSE`。
