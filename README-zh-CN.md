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

概述
--------
`qsh` 是一个基于 Go 的安全远程 Shell 工具，提供类似 SSH 的登录体验，同时依赖同一作者的两个研究项目：用于后量子友好认证的 [HPPK](https://github.com/xtaci/hppk) 和用于流加密的 [QPP](https://github.com/xtaci/qpp)。该二进制文件同时提供服务器和客户端模式，以及用于生成兼容密钥对的辅助工具。

主要特性
------------
- **强认证** – 服务器通过白名单验证客户端 ID，并验证握手期间生成的 HPPK 签名。
- **加密隧道** – 双向通信通过 HKDF 派生唯一密码本，输入到 QPP，并为每个连接协商随机素数密码本计数（1024 到 2048 之间）。
- **Proto 框架控制通道** – 所有信令（hello、质询、调整大小通知、加密数据）都通过在 `protocol/` 中定义的长度前缀 protobuf 封装传输。
- **真实终端体验** – 服务器通过 `/bin/sh` 生成 PTY，镜像 stdout/stderr，并处理窗口调整事件。
- **内置密钥管理** – 运行 `qsh genkey -o <路径>` 创建 JSON 编码的私钥/公钥文件（私钥部分使用密码短语加密）。

快速开始
-----------
1. 生成密钥（仅需运行一次）：

	```bash
	# 生成服务器主机密钥
	qsh genkey -o ./server_hppk
	
	# 生成客户端密钥
	qsh genkey -o ./id_hppk
	```

	将 `id_hppk.pub` 复制到服务器，并通过 `-c client-1=/path/to/id_hppk.pub` 引用它。

2. 启动服务器：

	```bash
	qsh server -l :2323 --host-key ./server_hppk -c client-1=/etc/qsh/id_hppk.pub
	```
	
	或使用客户端配置文件：
	
	```bash
	qsh server -l :2323 --host-key ./server_hppk --clients-config /etc/qsh/clients.json
	```

3. 从客户端连接（未提供子命令时，客户端模式为默认模式）：

	```bash
	qsh -i ./id_hppk -P 2323 client-1@203.0.113.10
	```

	省略 `-P` 将回退到默认端口 `2222`，或者提供 `-n/--id` 来覆盖客户端标识符（当它未嵌入 `client-id@host` 目标中时）。

文件复制
-------------
`copy` 子命令重用与交互式客户端相同的身份标志，同时接受 SCP 风格的目标，格式为 `client-id@host:/remote/path`。必须恰好有一个端点是远程的。

- 将本地文件上传到服务器（当不存在 `:port` 后缀时，默认为 TCP 端口 2222）：

	```bash
	qsh copy -i ./id_hppk ./notes.txt client-1@example.com:/tmp/notes.txt
	```

- 将远程文件下载到当前目录，使用 `-P` 覆盖端口：

	```bash
	qsh copy -i ./id_hppk -P 4242 client-1@example.com:/var/log/qsh.log ./qsh.log
	```

两个命令都以 `client-1` 身份进行认证（从远程规范或通过 `-n/--id` 获取），并自动派生加密的文件传输通道。

客户端注册表配置
-----------------------------
服务器可以通过 `--clients-config` 从 JSON 文件加载其允许列表，而不是在命令行上列出每个 `--client` 标志：

```json
{
	"clients": [
        { "id": "xtaci", "public_key": "/home/xtaci/xtaci.pub" },
		{ "id": "ops-admin", "public_key": "/etc/qsh/ops-admin.pub" }
	]
}
```

- 每个条目必须提供唯一的 `id` 以及相应 HPPK 公钥的文件系统路径。
- 将 JSON 文件与额外的 `--client id=/path` 标志结合使用，以分层临时覆盖。
- 每当文件更改时，向正在运行的服务器进程发送 `SIGUSR1`（例如，`kill -USR1 <pid>`）以触发注册表的就地重新加载。

协议要点
-------------------
1. **ClientHello** – 声明客户端 ID。
2. **AuthChallenge** – 服务器返回随机质询、KEM 包装的会话种子以及协商的素数密码本计数。
3. **AuthResponse** – 客户端使用其 HPPK 私钥签署质询并证明拥有权。
4. **AuthResult** – 服务器在验证签名后，双方通过 HKDF 派生方向种子（`qsh-c2s`、`qsh-s2c`）并实例化 QPP 密码本。
5. **安全流传输** – 明文 PTY 数据和调整大小事件被包装在 `PlainPayload` 中，加密到 `SecureData`，并交换直到任一方断开连接。

开发说明
-----------------
- 需要 Go 1.25.4+（请参阅 `go.mod`）。
- 使用 `go test ./...` 运行测试以验证 protobuf 认证流程。
- 关键实现文件：
  - `main.go` – CLI 入口点和命令定义。
  - `cmd_client.go`、`cmd_server.go`、`cmd_copy.go` – 客户端、服务器和复制操作的命令处理程序。
  - `session.go` – 客户端和服务器的握手协议实现。
  - `tty.go` – PTY 管理和终端 I/O 转发。
  - `transfer.go` – 文件上传/下载实现。
  - `channel.go` – 具有重放保护的加密通信通道。
  - `protocol/` – protobuf 定义以及长度前缀编解码器辅助工具。
  - `crypto/` – 密钥生成、加密密钥存储、HPPK 签名和 HKDF 派生。

许可证
-------
有关管理此项目的 MIT 条款，请参阅 `LICENSE`。
