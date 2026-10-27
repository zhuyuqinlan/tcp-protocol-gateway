# tcp-protocol-gateway

轻量级、高性能、可独立部署的 **Go HTTP(S) 反向代理网关**。

网关直接监听一个端口（默认 `0.0.0.0:8000`），基于 `net/http` 标准库以标准
HTTP 服务器语义处理请求：按路径前缀路由表转发到对应后端，未命中任何前缀
的请求转发到默认后端 TCP 地址。同时配置 TLS 证书与私钥即启用 HTTPS
（TLS 在网关终止），且**同一端口可同时服务 HTTPS 与原始 TCP**：按连接
嗅探首字节，TLS 握手则终止 TLS，非 TLS 连接（如 Minecraft）照旧透传。

本项目仅依赖 Go 标准库（`net/http`、`httputil`、`log/slog` 等），单二进制即可部署。

## 特性

- **直接监听**：标准 `net/http` 服务器直接监听端口，无协议嗅探、无裸字节转发。
- **HTTPS + TCP 混合端口**：配置 `server.tls_cert` 与 `server.tls_key`
  即启用 TLS，按连接嗅探：TLS 客户端终止 TLS 后走 HTTP 分流，非 TLS
  连接（如 Minecraft）不受影响，原始透传。
- **前缀路由**：HTTP 路径前缀路由表，最长前缀优先，支持转发前剥掉前缀。
- **默认后端**：路由未命中时转发到配置的默认后端 TCP 地址（`backend`）。
- **完整代理语义**：基于 `httputil.ReverseProxy`，天然支持 Keep-Alive、
  流式请求/响应、WebSocket Upgrade（协议切换）、大文件上传；后端不可用返回 502。
- **零第三方依赖**：配置解析使用内置的 YAML 子集解析器。
- **优雅退出**：SIGINT/SIGTERM 后停止接收新连接，等待活跃请求排空。

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
  listen: "0.0.0.0:8000"       # 直接监听地址
  read_header_timeout: 10s     # 读取请求头的期限，防慢连接占用
  # 同时配置以下两项即启用 HTTPS（TLS 在网关终止）：
  # tls_cert: "cert.pem"
  # tls_key: "key.pem"

http:
  connect_timeout: 5s          # 连接后端超时

# 默认后端 TCP 地址：连接未命中任何前缀路由时，整条连接
# 原始透传到该地址。
backend: "127.0.0.1:8080"

# 可选的 HTTP 路径前缀路由（最长前缀优先）。
# 条目支持两种写法：
#   "/path": "127.0.0.1:8080"     # 简写：透明转发，前缀保留
#   "/path":                      # 完整：可配置剥掉前缀
#     backend: "127.0.0.1:8080"
#     strip_prefix: true         # /path/x → 后端收到 /x
routes:
  http:
    "/files":
      backend: "127.0.0.1:8080"
      strip_prefix: true

logging:
  level: "info"                # debug / info / warn / error
```

### 工作方式（混合分流）

网关只有一种工作方式，无需模式开关：

- **TLS 按连接嗅探（配置了证书时）**：每条连接先窥探前 5 字节，
  形如 TLS handshake record（`0x16 0x03 0x0[0-4]`）的连接完成 TLS
  握手（网关终止），之后的解密明文进入下述分流；其余连接不经过
  TLS，照旧按下面的规则处理——单端口同时服务 HTTPS 与原始 TCP。
- **未命中 → 原始 TCP 透传**：每条入站连接默认拨号一条到默认后端
  （`backend`）的连接并双向 `io.Copy`，不做任何协议解析。半关闭语义
  正确传递。
- **命中 → HTTP 反向代理**：配置了 `routes.http` 时，连接首行是合法
  HTTP 请求行且路径命中某条前缀路由的连接改走 HTTP 反向代理
  （Keep-Alive 后续请求逐条按前缀路由）；支持 `https://` 后端、
  `X-Forwarded-*`、流式响应与 502。
- **嗅探零开销**：首字节不是 HTTP 方法首字母的连接立即透传，非 HTTP
  协议零延迟；以 HTTP 方法开头但行迟迟不完整的连接最多等待
  `read_header_timeout` 后透传。未配置 `routes.http` 时完全不嗅探。
  嗅探阶段已读取的字节在透传/分流时均完整保留，数据零丢失。

### 路由语义

- **前缀匹配**：按请求路径做纯字符串前缀匹配，**最长前缀优先**。例：配置
  `"/api"` 与 `"/api/v1"` 时，`/api/v1/x` 命中后者。注意 `/apiweb` 会命中
  `/api`（纯前缀语义）；需要路径段边界时请使用更精确的前缀（如 `/api/`）。
- **strip_prefix**：只重写请求 URL 路径（`/api/users` → `/users`；剥完为空
  转发为 `/`；剥完不以 `/` 开头则补 `/`），查询串原样保留。
- **默认后端**：未命中任何前缀的请求转发到顶层 `backend` 配置的地址。
- **代理安全性**：后端地址全部来自配置文件，客户端无法通过请求行、Host 头
  或任何内容指定转发目标，不存在开放代理风险。网关不修改请求内容
  （除可选剥前缀外）。
- **转发头**：网关自动设置 `X-Forwarded-For` 与 `X-Forwarded-Proto`。

### HTTPS 与原始 TCP 混合端口

同时配置 `server.tls_cert` 与 `server.tls_key`（PEM 格式）即启用 TLS。
TLS **按连接嗅探**而非整体生效：客户端首字节是 TLS handshake record
（`0x16 0x03 0x0[0-4]`，第二字节必须为 `0x03`，可有效排除 Minecraft
等以 `0x16` 开头的非 TLS 协议被误判）时，网关终止 TLS，解密后的明文
按混合分流规则处理——命中路由的 HTTP 请求走反代，其余透传到后端；
非 TLS 连接的原始字节完全不受影响，照旧透传/分流。浏览器访问
`https://域名:端口/...` 即可，MC 客户端连接同一端口也不受影响。

生成自签证书（仅测试用）：

```bash
go run crypto/tls/generate_cert.go --host 127.0.0.1
# 生成 cert.pem 与 key.pem 到当前目录
```

说明：配置解析器支持嵌套映射、双引号键值、`#` 行注释，不支持列表/锚点/
多行字符串等完整 YAML 语法。`go.sum` 不存在是因为项目零第三方依赖。

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

`deploy/tcp-protocol-gateway.service`。安装步骤：

```bash
sudo cp tcp-protocol-gateway-linux-amd64 /usr/local/bin/tcp-protocol-gateway
sudo mkdir -p /etc/tcp-protocol-gateway
sudo cp config.yaml /etc/tcp-protocol-gateway/
# 启用 HTTPS 时，把证书放到服务账号可读的路径并更新配置
sudo cp deploy/tcp-protocol-gateway.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now tcp-protocol-gateway
journalctl -u tcp-protocol-gateway -f   # 查看日志
```

## 测试

```bash
# 先准备一个后端（对应默认配置里的 backend）
python3 -m http.server 8080

# 默认后端转发
curl -v http://127.0.0.1:8000/anything

# 命中 /files 前缀（剥前缀后转发为 /）
curl -v http://127.0.0.1:8000/files/

# 后端不可用时返回 502
curl -i http://127.0.0.1:8000/x
```

自动化测试：

```bash
go test ./...            # 全部测试
go test -race ./...      # 竞态检测（需要 CGO 与 C 编译器）
go vet ./...
```

测试覆盖：默认后端转发（路径保留、Host 重写、X-Forwarded-For）、前缀路由
最长前缀优先、strip_prefix（含剥完为空转发为 /）、POST 请求体完整性、
后端不可用 502、HTTPS 转发、TLS 与原始 TCP 混合端口（含伪 TLS 首字节
透传、无路由时 TLS 明文透传）、优雅退出、配置加载与校验。

## 项目结构

```text
tcp-protocol-gateway/
├── cmd/gateway/main.go          # 入口：配置加载、日志、信号处理
├── internal/
│   ├── config/                  # 配置结构与内置 YAML 子集解析器
│   ├── gateway/                 # 端口监听（HTTP/HTTPS）、优雅退出
│   └── proxy/                   # 前缀路由 + httputil.ReverseProxy 反向代理
├── deploy/                      # systemd 服务文件
├── config.yaml
├── go.mod
├── Makefile
└── README.md
```

## 常见故障排查

| 现象 | 可能原因 / 处理 |
| --- | --- |
| 启动报 `bind: address already in use` | 8000 被占用：`ss -ltnp \| grep 8000` 找到占用进程，或修改 `server.listen` |
| HTTP 请求返回 502 | 后端未启动或不可达；检查 `backend` 与 `routes.http` 中对应后端 |
| HTTPS 无法访问 | 确认 `tls_cert`/`tls_key` 已同时配置、文件存在且服务账号可读、证书未过期 |
| 浏览器提示证书不可信 | 自签证书属预期行为，正式环境使用 CA 签发证书 |
| Linux 上 `bind: permission denied` | 端口 < 1024 需要 `CAP_NET_BIND_SERVICE` 或改用高端口 |
| 请求路径带特殊字符转发异常 | 前缀匹配基于解码后的 `URL.Path`；如遇问题请检查后端日志中的实际路径 |

日志为 `log/slog` 文本格式输出到 stderr，包含监听地址、TLS 状态与后端错误；
不记录请求体或任何敏感数据。
