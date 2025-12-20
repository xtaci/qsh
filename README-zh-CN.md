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
`qsh` 是一款基于 Go 语言开发的安全远程 Shell 工具，旨在提供类似 SSH 的使用体验。其核心安全机制基于作者研发的两个项目：用于后量子密码学认证的 [HPPK](https://github.com/xtaci/hppk) 和用于流加密的 [QPP](https://github.com/xtaci/qpp)。该程序为单二进制文件，同时支持服务器和客户端模式，并内置了密钥对生成工具。

主要特性
------------
- **强身份认证** – 服务器通过白名单机制验证客户端 ID，并校验握手阶段生成的 HPPK 签名，确保身份真实可靠。
- **量子安全加密隧道** – 通信双方通过 HKDF 派生唯一的加密密钥，用于 QPP 流加密，并为每个连接协商随机的素数密码本参数（1024 到 2048 之间）。
- **基于 Protobuf 的控制通道** – 所有的信令交互（如握手、质询、窗口调整、加密数据等）均封装在 `protocol/` 定义的 Protobuf 消息中传输，结构清晰且易于扩展。
- **完整的终端体验** – 服务器通过 `/bin/sh` 创建 PTY（伪终端），实时转发标准输出和标准错误，并完美支持窗口大小调整事件。
- **内置密钥管理工具** – 通过 `qsh genkey -o <路径>` 命令即可生成 JSON 格式的私钥/公钥文件（私钥部分使用密码短语加密保护）。
- **内存安全保护** – 使用 `memguard` 技术在内存中安全地处理私钥和密码短语，防止因内存交换或核心转储导致敏感信息泄露。

快速开始
-----------
1. **生成密钥对**（只需执行一次）：

	```bash
	# 生成服务器主机密钥
	qsh genkey -o ./server_hppk
	
	# 生成客户端密钥
	qsh genkey -o ./id_hppk
	```

	将生成的公钥 `id_hppk.pub` 复制到服务器端，并在启动服务器时通过 `-c client-1=/path/to/id_hppk.pub` 参数指定该公钥。

2. **启动服务器**：

	```bash
	qsh server -l :2323 --host-key ./server_hppk -c client-1=/etc/qsh/id_hppk.pub
	```
	
	或者使用 JSON 配置文件加载客户端列表：
	
	```bash
	qsh server -l :2323 --host-key ./server_hppk --clients-config /etc/qsh/clients.json
	```

3. **客户端连接**（默认模式）：

	```bash
	qsh -i ./id_hppk -P 2323 client-1@203.0.113.10
	```

	若省略 `-P` 参数，默认连接端口为 `2222`。如果目标地址中未包含客户端 ID（如 `client-id@host`），则需通过 `-n/--id` 参数手动指定。

文件传输 (Copy)
-------------
`copy` 子命令复用了交互式客户端的身份认证机制，支持类似 SCP 的文件传输操作。目标地址格式为 `client-id@host:/remote/path`。注意：源路径或目标路径中必须有一方为远程地址。

- **上传文件**：将本地文件上传到服务器（若未指定 `:port` 后缀，默认为 TCP 端口 2222）：

	```bash
	qsh copy -i ./id_hppk ./notes.txt client-1@example.com:/tmp/notes.txt
	```

- **下载文件**：将远程文件下载到当前目录，并使用 `-P` 指定端口：

	```bash
	qsh copy -i ./id_hppk -P 4242 client-1@example.com:/var/log/qsh.log ./qsh.log
	```

以上命令均使用 `client-1` 身份进行认证（从远程地址解析或通过 `-n/--id` 指定），并自动建立加密的文件传输通道。

客户端白名单配置
-----------------------------
除了在命令行使用 `--client` 逐个指定外，服务器还支持通过 `--clients-config` 参数从 JSON 文件加载客户端白名单：

```json
{
	"clients": [
        { "id": "xtaci", "public_key": "/home/xtaci/xtaci.pub" },
		{ "id": "ops-admin", "public_key": "/etc/qsh/ops-admin.pub" }
	]
}
```

- 每个条目必须包含唯一的 `id` 以及对应的 HPPK 公钥文件路径。
- 支持同时使用 JSON 配置文件和命令行 `--client` 参数，命令行参数可用于临时覆盖或补充配置。
- **热加载支持**：当配置文件发生变更时，向服务器进程发送 `SIGUSR1` 信号（例如 `kill -USR1 <pid>`）即可触发配置重载，无需重启服务。

协议流程摘要
-------------------
1. **ClientHello** – 客户端发送其 ID。
2. **AuthChallenge** – 服务器返回随机质询数据、经 KEM 封装的会话种子，以及协商确定的素数密码本参数。
3. **AuthResponse** – 客户端使用 HPPK 私钥对质询数据进行签名，以证明身份。
4. **AuthResult** – 服务器验证签名通过后，双方利用 HKDF 派生出会话密钥（`qsh-c2s`、`qsh-s2c`）并初始化 QPP 加密实例。
5. **安全流传输** – PTY 数据流和窗口调整事件被封装在 `PlainPayload` 中，经加密生成 `SecureData` 后进行传输，直至连接断开。

开发说明
-----------------
- **环境要求**：Go 1.25.4 及以上版本（详见 `go.mod`）。
- **测试**：运行 `go test ./...` 以验证 Protobuf 认证流程及其他功能。
- **核心代码结构**：
  - `main.go` – CLI 入口及命令定义。
  - `cmd_client.go`、`cmd_server.go`、`cmd_copy.go` – 客户端、服务器及文件传输的具体实现。
  - `session.go` – 客户端与服务器的握手协议实现。
  - `tty.go` – PTY 管理及终端 I/O 转发。
  - `transfer.go` – 文件上传/下载逻辑实现。
  - `channel.go` – 具备重放保护机制的加密通信通道。
  - `protocol/` – Protobuf 消息定义及长度前缀编解码工具。
  - `crypto/` – 密钥生成、加密密钥存储、HPPK 签名及 HKDF 派生逻辑。

许可证
-------
本项目遵循 MIT 许可证，详情请参阅 `LICENSE` 文件。
