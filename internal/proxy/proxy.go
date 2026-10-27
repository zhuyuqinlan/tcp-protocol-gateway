// Package proxy 实现 HTTP/1.x 流量的 TCP 透明转发。
//
// 转发工作在原始 TCP 字节流层面：嗅探阶段已读取/缓冲的数据
// 会先完整写入后端，随后双向 io.Copy。这保证 HTTP 请求行、
// Keep-Alive 后续请求、WebSocket Upgrade、大文件流式上传
// 等所有场景天然可用，且网关不解析、不修改任何请求内容。
package proxy

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"
)

// BackendUnreachable 供上层区分"后端不可用"与其他错误。
var BackendUnreachable = errors.New("proxy: backend unreachable")

// Proxy 将 HTTP 连接透明转发到固定后端。
// 目标地址来自配置文件，客户端无法通过任何请求内容
// 指定转发目标，因此不存在开放代理风险。
type Proxy struct {
	backend string
	dialer  *net.Dialer
	logger  *slog.Logger
}

// New 创建 HTTP 代理处理器。
func New(backend string, connectTimeout time.Duration, logger *slog.Logger) *Proxy {
	if logger == nil {
		logger = slog.Default()
	}
	return &Proxy{
		backend: backend,
		dialer: &net.Dialer{
			Timeout: connectTimeout,
		},
		logger: logger,
	}
}

// Backend 返回后端地址（用于日志与诊断）。
func (p *Proxy) Backend() string { return p.backend }

// badGatewayResponse 是后端不可用时返回给客户端的最小 HTTP 响应。
const badGatewayResponse = "HTTP/1.1 502 Bad Gateway\r\n" +
	"Content-Type: text/plain; charset=utf-8\r\n" +
	"Content-Length: 25\r\n" +
	"Connection: close\r\n" +
	"\r\n" +
	"502 Bad Gateway: backend\n"

// Handle 将已识别为 HTTP 的客户端连接转发到后端。
// br 是嗅探阶段使用的同一个 bufio.Reader，其中可能仍缓冲着
// 已窥探但未消费的请求字节，必须先冲刷到后端。
func (p *Proxy) Handle(client net.Conn, br *bufio.Reader) error {
	backend, err := p.dialer.Dial("tcp", p.backend)
	if err != nil {
		p.logger.Warn("proxy: backend dial failed",
			"backend", p.backend, "error", err)
		// 后端不可用：返回合理的 HTTP 502 而不是静默断连。
		_ = client.SetWriteDeadline(time.Now().Add(3 * time.Second))
		_, _ = io.WriteString(client, badGatewayResponse)
		_ = client.Close()
		return fmt.Errorf("%w: %v", BackendUnreachable, err)
	}

	// 冲刷嗅探阶段缓冲的数据（Peek 过但未消费的部分）。
	if n := br.Buffered(); n > 0 {
		flushed, err := io.CopyN(backend, br, int64(n))
		if err != nil {
			_ = backend.Close()
			_ = client.Close()
			return fmt.Errorf("proxy: flush sniffed bytes: %w", err)
		}
		p.logger.Debug("proxy: flushed sniffed bytes", "count", flushed)
	}

	// 双向转发。任一方向结束即按 TCP 语义收尾：
	//   客户端 -> 后端读完（客户端半关闭）: 对后端 CloseWrite，
	//     后端可继续响应（覆盖客户端先发完请求再等响应的场景）。
	//   后端 -> 客户端读完: 直接关闭客户端连接。
	done := make(chan struct{}, 2)
	errs := &firstErr{}

	go func() {
		_, cerr := io.Copy(backend, client)
		if cerr != nil && !isExpectedConnError(cerr) {
			errs.set(fmt.Errorf("client->backend: %w", cerr))
		}
		if tc, ok := backend.(*net.TCPConn); ok {
			_ = tc.CloseWrite() // 传递客户端的半关闭。
		}
		done <- struct{}{}
	}()

	go func() {
		_, cerr := io.Copy(client, backend)
		if cerr != nil && !isExpectedConnError(cerr) {
			errs.set(fmt.Errorf("backend->client: %w", cerr))
		}
		_ = client.Close()
		done <- struct{}{}
	}()

	<-done
	<-done
	_ = backend.Close()
	_ = client.Close()
	return errs.get()
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
