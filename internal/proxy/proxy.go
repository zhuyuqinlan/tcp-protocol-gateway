// Package proxy 实现 HTTP/1.x 流量的 TCP 透明转发与路由。
//
// 转发工作在原始 TCP 字节流层面：嗅探阶段已读取/缓冲的数据
// 会先完整写入后端，随后双向 io.Copy。这保证 HTTP 请求行、
// Keep-Alive 后续请求、WebSocket Upgrade、大文件流式上传
// 等所有场景天然可用，且网关不解析、不修改任何请求内容。
//
// Router 按请求行路径前缀选择后端（最长前缀优先）；
// 路由可配置转发前剥掉前缀（仅重写首个请求行的 request-target，
// 其余字节一律原样透传）。未匹配任何前缀时返回 nil，
// 由网关决定回退行为（当前策略是模拟真实 Minecraft 服务器的响应）。
package proxy

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

// BackendUnreachable 供上层区分"后端不可用"与其他错误。
var BackendUnreachable = errors.New("proxy: backend unreachable")

// ErrRequestLine 表示无法从连接中读取合法的 HTTP 请求行。
var ErrRequestLine = errors.New("proxy: cannot read request line")

// maxRequestLinePeek 是路由匹配时窥探请求行的上限，
// 不能超过网关侧 bufio.Reader 的缓冲区大小（见 gateway.sniffBufferSize）。
const maxRequestLinePeek = 4096

// badGatewayResponse 是后端不可用时返回给客户端的最小 HTTP 响应。
const badGatewayResponse = "HTTP/1.1 502 Bad Gateway\r\n" +
	"Content-Type: text/plain; charset=utf-8\r\n" +
	"Content-Length: 25\r\n" +
	"Connection: close\r\n" +
	"\r\n" +
	"502 Bad Gateway: backend\n"

// Proxy 将客户端连接透明转发到指定后端。
// 转发目标只来自配置的路由表，客户端无法通过任何请求内容
// 指定转发目标，因此不存在开放代理风险。
type Proxy struct {
	dialer *net.Dialer
	logger *slog.Logger
}

// New 创建代理处理器，connectTimeout 用于到后端的拨号。
func New(connectTimeout time.Duration, logger *slog.Logger) *Proxy {
	if logger == nil {
		logger = slog.Default()
	}
	return &Proxy{
		dialer: &net.Dialer{
			Timeout: connectTimeout,
		},
		logger: logger,
	}
}

// Handle 将客户端连接转发到 m 指定的后端。
// br 是嗅探阶段使用的同一个 bufio.Reader，其中可能仍缓冲着
// 已窥探但未消费的请求字节，必须先冲刷到后端。
// m.Strip 非空时，先重写请求行（剥掉该前缀）再转发；
// 请求行重写只作用于连接的第一个请求（透明代理语义，
// Keep-Alive 后续请求由客户端与后端直接协商）。
func (p *Proxy) Handle(client net.Conn, br *bufio.Reader, m *Match) error {
	backendConn, err := p.dialer.Dial("tcp", m.Backend)
	if err != nil {
		p.logger.Warn("proxy: backend dial failed",
			"backend", m.Backend, "error", err)
		// 后端不可用：返回合理的 HTTP 502 而不是静默断连。
		_ = client.SetWriteDeadline(time.Now().Add(3 * time.Second))
		_, _ = io.WriteString(client, badGatewayResponse)
		_ = client.Close()
		return fmt.Errorf("%w: %v", BackendUnreachable, err)
	}

	// 冲刷嗅探阶段缓冲的数据；需要剥前缀时重写请求行。
	if m.Strip != "" {
		err = p.forwardWithStrip(backendConn, br, m.Strip)
	} else if n := br.Buffered(); n > 0 {
		_, err = io.CopyN(backendConn, br, int64(n))
	}
	if err != nil {
		_ = backendConn.Close()
		_ = client.Close()
		return fmt.Errorf("proxy: forward head bytes: %w", err)
	}

	// 双向转发。任一方向结束即按 TCP 语义收尾：
	//   客户端 -> 后端读完（客户端半关闭）: 对后端 CloseWrite，
	//     后端可继续响应（覆盖客户端先发完请求再等响应的场景）。
	//   后端 -> 客户端读完: 直接关闭客户端连接。
	done := make(chan struct{}, 2)
	errs := &firstErr{}

	go func() {
		_, cerr := io.Copy(backendConn, client)
		if cerr != nil && !isExpectedConnError(cerr) {
			errs.set(fmt.Errorf("client->backend: %w", cerr))
		}
		if tc, ok := backendConn.(*net.TCPConn); ok {
			_ = tc.CloseWrite() // 传递客户端的半关闭。
		}
		done <- struct{}{}
	}()

	go func() {
		_, cerr := io.Copy(client, backendConn)
		if cerr != nil && !isExpectedConnError(cerr) {
			errs.set(fmt.Errorf("backend->client: %w", cerr))
		}
		_ = client.Close()
		done <- struct{}{}
	}()

	<-done
	<-done
	_ = backendConn.Close()
	_ = client.Close()
	return errs.get()
}

// Router 是 HTTP 路径前缀路由表（最长前缀优先）。
type Router struct {
	// routes 已按前缀长度降序排列。
	routes []Route
}

// Route 描述一条前缀路由。
type Route struct {
	// Prefix 是路径前缀，必须以 "/" 开头。
	Prefix string
	// Backend 是命中的请求转发目标。
	Backend string
	// StripPrefix 为 true 时，转发前把 Prefix 从请求行的
	// request-target 中剥掉。
	StripPrefix bool
}

// Match 是一次路由命中的结果。
type Match struct {
	// Backend 是命中的后端地址。
	Backend string
	// Strip 是需要从请求目标中剥掉的前缀；空串表示透明转发。
	Strip string
}

// NewRouter 构建路由表。
// 前缀必须以 "/" 开头（与配置校验一致，此处为纵深防御）。
func NewRouter(routes []Route) (*Router, error) {
	r := &Router{}
	for _, rt := range routes {
		if rt.Backend == "" {
			return nil, fmt.Errorf("proxy: route %q has empty backend", rt.Prefix)
		}
		if !bytes.HasPrefix([]byte(rt.Prefix), []byte("/")) {
			return nil, fmt.Errorf("proxy: route prefix %q must start with '/'", rt.Prefix)
		}
		r.routes = append(r.routes, rt)
	}
	// 最长前缀优先，保证 "/api/v1" 优先于 "/api" 命中。
	sort.Slice(r.routes, func(i, j int) bool {
		return len(r.routes[i].Prefix) > len(r.routes[j].Prefix)
	})
	return r, nil
}

// Match 窥探（不消费）请求行并返回命中的路由；未命中任何前缀
// 返回 nil（由网关决定回退行为，当前为 Minecraft 模拟）。
func (r *Router) Match(br *bufio.Reader) (*Match, error) {
	if len(r.routes) == 0 {
		return nil, nil
	}
	line, err := peekRequestLine(br)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRequestLine, err)
	}
	sp := bytes.IndexByte(line, ' ')
	if sp < 0 {
		return nil, fmt.Errorf("%w: malformed request line %q", ErrRequestLine, line)
	}
	target := line[sp+1:]
	if end := bytes.IndexByte(target, ' '); end >= 0 {
		target = target[:end]
	}
	for _, e := range r.routes {
		if bytes.HasPrefix(target, []byte(e.Prefix)) {
			m := &Match{Backend: e.Backend}
			if e.StripPrefix {
				m.Strip = e.Prefix
			}
			return m, nil
		}
	}
	return nil, nil
}

// forwardWithStrip 从 br 中消费完整请求行，剥掉 strip 前缀后
// 写入 backend，随后冲刷缓冲区中剩余的字节。
// 请求行已被 Router.Match 完整窥探过，必然已在缓冲区内。
func (p *Proxy) forwardWithStrip(backend net.Conn, br *bufio.Reader, strip string) error {
	line, err := br.ReadBytes('\n')
	if err != nil {
		return fmt.Errorf("read request line: %w", err)
	}
	rewritten, ok := rewriteRequestLine(line, strip)
	if !ok {
		// 请求行形态异常（非 "方法 目标 版本"）：保底原样转发，
		// 绝不因重写失败而丢失连接。
		rewritten = line
	}
	if _, err := backend.Write(rewritten); err != nil {
		return fmt.Errorf("write rewritten request line: %w", err)
	}
	// 请求行之后的头部与请求体仍按原样冲刷。
	if n := br.Buffered(); n > 0 {
		if _, err := io.CopyN(backend, br, int64(n)); err != nil {
			return fmt.Errorf("flush buffered bytes: %w", err)
		}
	}
	return nil
}

// rewriteRequestLine 把请求行 request-target 中的 strip 前缀剥掉，
// 返回重写后的完整请求行（含行结束符）。行不符合
// "方法 目标 版本" 形态或目标不含该前缀时返回 ok=false。
// 剥完为空的路径转发为 "/"；剥完不以 "/" 开头的路径补 "/"
// （如 /apiweb 剥掉 /api 后为 web → /web）。
func rewriteRequestLine(line []byte, strip string) (out []byte, ok bool) {
	s := string(line)
	eol := ""
	switch {
	case strings.HasSuffix(s, "\r\n"):
		s, eol = s[:len(s)-2], "\r\n"
	case strings.HasSuffix(s, "\n"):
		s, eol = s[:len(s)-1], "\n"
	}
	parts := strings.SplitN(s, " ", 3)
	if len(parts) != 3 {
		return nil, false
	}
	method, target, version := parts[0], parts[1], parts[2]
	if !strings.HasPrefix(target, strip) {
		return nil, false
	}
	rest := target[len(strip):]
	if rest == "" {
		rest = "/"
	}
	if rest[0] != '/' {
		rest = "/" + rest
	}
	return []byte(method + " " + rest + " " + version + eol), true
}

// peekRequestLine 窥探（不消费）请求行的第一行内容（不含 CRLF）。
// 请求行过长或连接在换行前超时/关闭均返回错误。
func peekRequestLine(br *bufio.Reader) ([]byte, error) {
	size := 16
	for {
		if size > maxRequestLinePeek {
			size = maxRequestLinePeek
		}
		p, err := br.Peek(size)
		if i := bytes.IndexByte(p, '\n'); i >= 0 {
			line := p[:i]
			if len(line) > 0 && line[len(line)-1] == '\r' {
				line = line[:len(line)-1]
			}
			return line, nil
		}
		if err != nil {
			return nil, err
		}
		if size >= maxRequestLinePeek {
			return nil, fmt.Errorf("request line exceeds %d bytes", maxRequestLinePeek)
		}
		size *= 2
	}
}

// isExpectedConnError 过滤连接关闭时的常见噪音错误。
func isExpectedConnError(err error) bool {
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return true
	}
	return errors.Is(err, net.ErrClosed)
}

// firstErr 只保留两个转发方向中第一个非预期错误。
// 两个方向分别运行在独立 goroutine 中，必须加锁。
type firstErr struct {
	mu  sync.Mutex
	err error
}

func (f *firstErr) set(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err == nil {
		f.err = err
	}
}

func (f *firstErr) get() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.err
}
