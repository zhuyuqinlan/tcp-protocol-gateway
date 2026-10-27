# tcp-protocol-gateway

轻量级、高性能、可独立部署的 **Go TCP 多协议网关**。

单端口监听（默认 `0.0.0.0:25565`），根据客户端发送的首批数据自动识别协议：

| 协议 | 行为 |
| --- | --- |
| HTTP/1.x（GET/POST/PUT/DELETE/HEAD/OPTIONS/PATCH/CONNECT） | 透明 TCP 转发到配置的后端（默认 `127.0.0.1:8080`） |
| Minecraft Java Edition 握手（Next State = 1） | 本地模拟 SLP：返回 Status JSON、响应 Ping/Pong |
| Minecraft Java Edition 握手（Next State = 2） | 返回 Disconnect 消息，拒绝登录 |
| TLS ClientHello | 明确拒绝（网关不解密 TLS） |
| 其他 / 无法识别 | 安全关闭连接 |

本项目用于自有服务器的协议兼容性测试和网络开发学习，不实现任何风控绕过、探测欺骗或身份伪装功能。

## 特性

- **零第三方依赖**：仅使用 Go 标准库（`net`、`bufio`、`log/slog` 等），单二进制即可部署；配置解析使用内置的 YAML 子集解析器。
- **无损协议嗅探**：基于 `bufio.Reader.Peek` 窥探（不消费），嗅探数据随后被完整传递给后端，TCP 分片自动聚合。
- **严格 Minecraft 校验**：VarInt 长度 + Packet ID + 协议版本 + 地址 + 端口 + Next State 逐字段校验，拒绝无效 VarInt、超长包与非法结构；不会仅凭"首字节 < 0x80"误判。
- **完整 HTTP 代理语义**：支持 Keep-Alive、WebSocket Upgrade（101 后双向透传）、大文件流式上传、TCP 半关闭传递；后端不可用时返回 HTTP 502。
- **资源防护**：最大并发连接数限制、握手读取超时、空闲超时、Minecraft 包长度上限、嗅探缓冲上限；单连接 panic 不会击穿进程。
- **优雅退出**：SIGINT/SIGTERM 后停止接收新连接，等待活跃连接排空（最长 10 秒），超时强制清理。

## 快速开始

环境要求：Go 1.23+。

```bash
# 编译
go build -o tcp-protocol-gateway ./cmd/gateway

# 使用默认 config.yaml 启动
./tcp-protocol-gateway -config config.yaml

# 运行测试
go test ./...
```

## 配置

`config.yaml`（所有字段均有默认值，可按需裁剪）：

```yaml
server:
  listen: "0.0.0.0:25565"       # 监听地址
  max_connections: 1000          # 最大并发连接数
  handshake_timeout: 5s          # 协议嗅探阶段读取期限
  idle_timeout: 60s              # Minecraft 会话空闲超时

http:
  backend: "127.0.0.1:8080"      # HTTP 后端（固定，客户端不可指定）
  connect_timeout: 5s            # 连接后端超时

minecraft:
  enabled: true                  # 是否响应 Minecraft SLP
  version_name: "1.20.1"
  protocol_version: 763
  motd: "Go TCP Protocol Gateway"
  max_players: 100
  online_players: 0

logging:
  level: "info"                  # debug / info / warn / error
```

说明：配置解析器支持嵌套映射、双引号字符串、`#` 行注释，不支持列表/锚点/多行字符串等完整 YAML 语法。`go.sum` 不存在是因为项目零第三方依赖。

## 构建

```bash
# 当前平台
go build -o tcp-protocol-gateway ./cmd/gateway

# Linux amd64 / arm64（静态编译，可直接部署到无 Go 环境的服务器）
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w" \
    -o tcp-protocol-gateway-linux-amd64 ./cmd/gateway
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags "-s -w" \
    -o tcp-protocol-gateway-linux-arm64 ./cmd/gateway

# 或使用 Makefile
make build linux-amd64 linux-arm64
```

## systemd 部署

`deploy/tcp-protocol-gateway.service`：

```ini
[Unit]
Description=TCP Multi-Protocol Gateway
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=nobody
Group=nobody
ExecStart=/usr/local/bin/tcp-protocol-gateway -config /etc/tcp-protocol-gateway/config.yaml
Restart=on-failure
RestartSec=3
LimitNOFILE=65536

# 安全加固
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

安装步骤：

```bash
sudo cp tcp-protocol-gateway-linux-amd64 /usr/local/bin/tcp-protocol-gateway
sudo mkdir -p /etc/tcp-protocol-gateway
sudo cp config.yaml /etc/tcp-protocol-gateway/
sudo cp deploy/tcp-protocol-gateway.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now tcp-protocol-gateway
journalctl -u tcp-protocol-gateway -f   # 查看日志
```

## 测试

### HTTP 转发

```bash
# 先准备一个后端（例如）
python3 -m http.server 8080

# 通过网关访问
curl -v http://127.0.0.1:25565/
curl -X POST -d 'hello' http://127.0.0.1:25565/api

# 后端不可用时应返回 502
curl -i http://127.0.0.1:25565/
```

### Minecraft SLP

任选其一：

```bash
# 方法一：直接连接（使用 Minecraft 客户端添加服务器 127.0.0.1:25565，
# 服务器列表会显示 MOTD "Go TCP Protocol Gateway"；尝试登录会被踢出并显示提示语）

# 方法二：nmap
nmap -sV -Pn -p 25565 --script minecraft-serverinfo 127.0.0.1

# 方法三：python 脚本（Python 3）
python3 - <<'EOF'
import socket, struct

s = socket.create_connection(("127.0.0.1", 25565), timeout=5)

def varint(v):
    out = b""
    while True:
        b = v & 0x7F
        v >>= 7
        if v: out += bytes([b | 0x80])
        else: return out + bytes([b])

addr = b"127.0.0.1"
body = varint(0) + varint(763) + varint(len(addr)) + addr
body += struct.pack(">H", 25565) + varint(1)
s.sendall(varint(len(body)) + body)          # Handshake
s.sendall(varint(1) + b"\x00")               # Status Request

def read_varint(sock):
    n, result = 0, 0
    while True:
        b = sock.recv(1)[0]
        result |= (b & 0x7F) << (7 * n)
        if not b & 0x80: return result
        n += 1

length = read_varint(s)
data = b""
while len(data) < length:
    data += s.recv(length - len(data))
# data = varint(0x00) + ushort + json
print(data[3:].decode())

# Ping / Pong
payload = struct.pack(">q", 12345)
s.sendall(varint(9) + b"\x01" + payload)
length = read_varint(s)
pong = s.recv(length)
assert pong[1:9] == payload, "pong payload mismatch"
print("pong ok:", pong[1:9].hex())
s.close()
EOF
```

### 自动化测试

```bash
go test ./...            # 全部测试
go test -race ./...      # 竞态检测（需要 CGO 与 C 编译器）
go vet ./...
```

测试覆盖：HTTP GET/POST 转发、TCP 分片重组、请求体完整性、Handshake 解析、Status 响应、Ping/Pong、Login 拒绝、无效 VarInt 与异常包长、未知协议与嗅探超时、100 并发连接与优雅退出。

## 设计要点

### 协议嗅探的歧义消除

多协议复用一个端口的核心难点是"看起来像 A 协议的 B 协议数据"。本项目处理的几类冲突：

1. **Minecraft 握手长度是 0x47 ('G') / 0x50 ('P')**：长度 VarInt 首字节恰好是 HTTP 方法首字母，载荷又以 Packet ID `0x00` 开头。嗅探要求"方法 + 空格 + 全部可见 ASCII"才判定 HTTP，Minecraft 的 `0x00` 包 ID 不可见，从而可靠区分（有专门回归测试）。
2. **握手长度 0x16 与 TLS 记录层魔数相同**：典型 SLP 握手长度 17~30 字节，22 (0x16) 落在其中。TLS 判定使用 `0x16 0x03 0x0x` 三字节联合校验，与 Minecraft 的 `0x16 0x00 ...` 互斥。
3. **HTTP OPTIONS/CONNECT 恰好 8 字节**：`Peek` 窗口取 16 字节，避免最长方法占满窗口后无余量校验。

### 数据零丢失

嗅探全程只 `Peek` 不消费。识别为 HTTP 后，代理先把 bufio 缓冲区中已窥探的字节冲刷到后端，再双向 `io.Copy`；识别为 Minecraft 后，从同一 Reader 正式读取握手包并进入状态机。

### 与开放代理的区别

HTTP 后端地址仅来自配置文件，客户端无法通过请求行、Host 头或任何内容指定转发目标，因此不存在开放代理风险。网关不解析、不修改 HTTP 内容。

## 项目结构

```text
tcp-protocol-gateway/
├── cmd/gateway/main.go          # 入口：配置加载、日志、信号处理
├── internal/
│   ├── config/                  # 配置结构与内置 YAML 子集解析器
│   ├── detector/                # 协议嗅探（Peek、歧义消除）
│   ├── gateway/                 # TCP 服务：监听、并发控制、分发、优雅退出
│   ├── proxy/                   # HTTP 透明 TCP 代理
│   └── minecraft/               # VarInt/String 编解码、Handshake、SLP 状态机
├── deploy/                      # systemd 服务文件
├── config.yaml
├── go.mod
├── Makefile
└── README.md
```

## 常见故障排查

| 现象 | 可能原因 / 处理 |
| --- | --- |
| 启动报 `bind: address already in use` | 25565 被占用：`ss -ltnp \| grep 25565` 找到占用进程，或修改 `server.listen` |
| HTTP 请求返回 502 | 后端 `127.0.0.1:8080` 未启动或不可达；检查 `http.backend` 与后端服务 |
| Minecraft 客户端显示"无法连接" | 确认 `minecraft.enabled: true`；用 `logging.level: debug` 观察握手日志 |
| 客户端刚连上就被断开 | 握手数据 5 秒内未发全（慢连接超时）；或协议嗅探失败（日志有 `unknown protocol`） |
| Linux 上 `bind: permission denied` | 端口 < 1024 需要 `CAP_NET_BIND_SERVICE` 或改用高端口 |
| 大量连接被拒 | 触达 `max_connections` 上限，调大该值或排查上游连接泄漏 |
| 服务器列表 MOTD 显示异常字符 | 检查 `minecraft.motd` 是否为合法 UTF-8 文本 |

日志为 `log/slog` 文本格式输出到 stderr，包含来源 IP、识别协议、处理耗时与错误原因；不记录 HTTP 请求体或任何敏感数据。
