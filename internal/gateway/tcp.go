// 原始字节透传 + 可选的 HTTP 前缀分流（混合模式）。
//
// 默认行为：每条入站连接拨号一条到默认后端的连接，双向 io.Copy，
// 不做任何协议解析。任一方向读完后按 TCP 语义收尾（客户端半关闭
// 时对后端 CloseWrite，让后端继续发响应）。
//
// 配置了 routes.http 时启用混合分流：先在只读缓冲区里窥探
// （不消费）首个请求行——是合法的 HTTP 请求行且路径命中某条
// 前缀路由时，该连接交给 net/http 服务器按 HTTP 反向代理处理
// （Keep-Alive 上的后续请求仍逐条按前缀路由）；否则连接照旧
// 原始透传到默认后端（已缓冲的字节会先冲刷给后端，零丢失）。
// 未配置路由时不嗅探，无任何额外开销。
//
// 配置了 TLS 证书时，网关终止 TLS 并把解密后的明文处理/转发；
// 未配置 TLS 时为纯透传（客户端的 TLS 握手字节原样到达后端，
// 由后端自己处理 TLS）。
package gateway

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"
)

// sniffBufferSize 是嗅探阶段 bufio.Reader 的缓冲区大小，
// 同时是请求行窥探上限（嗅探只 Peek 不消费，数据零丢失）。
const sniffBufferSize = 4096

func (s *Server) listenAndServe() error {
	ln, err := net.Listen("tcp", s.cfg.Server.Listen)
	if err != nil {
		return fmt.Errorf("gateway: listen on %s: %w", s.cfg.Server.Listen, err)
	}
	if s.cfg.Server.TLSEnabled() {
		cert, cerr := tls.LoadX509KeyPair(s.cfg.Server.TLSCertFile, s.cfg.Server.TLSKeyFile)
		if cerr != nil {
			_ = ln.Close()
			return fmt.Errorf("gateway: load tls cert: %w", cerr)
		}
		ln = tls.NewListener(ln, &tls.Config{ //nolint:gosec // MinVersion 显式设置
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		})
	}
	// 与 Shutdown 互斥：若关闭流程已开始，立即退出，避免监听器
	// 注册前被跳过关闭导致 Accept 永久阻塞。
	s.closeMu.Lock()
	if s.closed {
		s.closeMu.Unlock()
		_ = ln.Close()
		return ErrServerClosed
	}
	s.listener = ln
	s.closeMu.Unlock()

	s.logger.Info("gateway: listening",
		"addr", s.cfg.Server.Listen,
		"tls", s.cfg.Server.TLSEnabled(),
		"backend", s.cfg.Backend,
		"http_routes", len(s.cfg.Routes.HTTP))

	for {
		conn, err := ln.Accept()
		if err != nil {
			if s.isShuttingDown() {
				return ErrServerClosed
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			if isTemporaryAcceptError(err) {
				s.logger.Warn("gateway: temporary accept error", "error", err)
				time.Sleep(10 * time.Millisecond)
				continue
			}
			s.logger.Error("gateway: accept failed", "listen", s.cfg.Server.Listen, "error", err)
			return ErrServerClosed
		}

		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handleTCPConn(conn)
		}()
	}
}

// handleTCPConn 处理一条入站连接：嗅探命中 HTTP 路由则走 HTTP
// 反向代理，否则原始透传到默认后端。
// 单条连接的 panic 不允许击穿进程。
func (s *Server) handleTCPConn(client net.Conn) {
	defer func() {
		// 单条连接的 panic 不允许击穿进程。
		if r := recover(); r != nil {
			s.logger.Error("gateway: recovered from panic in tcp handler",
				"remote", client.RemoteAddr().String(), "panic", r)
		}
		_ = client.Close()
	}()
	s.trackConn(client, true)
	defer s.trackConn(client, false)

	// 未配置路由：纯透传，不嗅探。
	if s.httpSrv == nil {
		s.forwardRaw(client, nil, nil)
		return
	}

	// 嗅探阶段读取期限：请求行迟迟不来（如服务端先说话的协议）
	// 则按原始透传处理。
	_ = client.SetDeadline(time.Now().Add(s.cfg.Server.ReadHeaderTimeout))
	br := bufio.NewReaderSize(client, sniffBufferSize)
	route, prefix := s.sniffAndRoute(br)
	_ = client.SetDeadline(time.Time{})

	if !route {
		s.forwardRaw(client, br, prefix)
		return
	}

	// 命中 HTTP 路由：交给 http.Server 处理。已消费的请求行通过
	// bufConn 重放，缓冲区中其余字节完整续读，零丢失。
	l := newOneConnListener(&bufConn{Conn: client, prefix: prefix, r: br})
	_ = s.httpSrv.Serve(l) // 阻塞至连接结束或 Shutdown 关闭该监听
}

// sniffAndRoute 判断连接是否走 HTTP 反向代理。
//
// 快速路径：首字节不是大写字母（HTTP 方法首字母）时立即按原始
// 透传处理，非 HTTP 协议零延迟。否则读取首个请求行——是合法的
// "方法 目标 HTTP/x.y" 且路径命中前缀路由时返回 route=true
// （请求行已消费，由 bufConn 续读后续内容）；未命中前缀或行不
// 完整时返回 route=false 与已消费字节 prefix，供透传前冲刷，
// 保证数据零丢失。
func (s *Server) sniffAndRoute(br *bufio.Reader) (route bool, prefix []byte) {
	head, err := br.Peek(1)
	if err != nil || head[0] < 'A' || head[0] > 'Z' {
		return false, nil
	}

	line, err := br.ReadBytes('\n')
	if err != nil {
		// 行未读完（超时/关闭）：已收到的部分照旧透传。
		return false, line
	}
	trimmed := strings.TrimSuffix(strings.TrimSuffix(string(line), "\n"), "\r")
	_, target, isReq := parseRequestLine(trimmed)
	if !isReq || !strings.HasPrefix(target, "/") {
		return false, line
	}
	path := target
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path = path[:i]
	}
	if _, matched := s.router.Match(path); !matched {
		return false, line
	}
	return true, line
}

// parseRequestLine 判断 line 是否为 "方法 目标 HTTP/x.y" 形态的
// 请求行；是则返回方法与请求目标。
func parseRequestLine(line string) (method, target string, ok bool) {
	i := strings.IndexByte(line, ' ')
	if i <= 0 {
		return "", "", false
	}
	j := strings.LastIndexByte(line, ' ')
	if j <= i {
		return "", "", false
	}
	if !strings.HasPrefix(line[j+1:], "HTTP/") {
		return "", "", false
	}
	method = line[:i]
	if method != strings.ToUpper(method) {
		return "", "", false
	}
	return method, line[i+1:j], true
}

// forwardRaw 把连接原始透传到默认后端。br 非空时客户端读取经过
// 缓冲区；prefix 是嗅探阶段已消费、尚未发给后端的字节（透传前
// 先写入后端，保证数据零丢失）。
func (s *Server) forwardRaw(client net.Conn, br *bufio.Reader, prefix []byte) {
	start := time.Now()
	var src io.Reader = client
	if br != nil {
		src = br
	}

	backend, err := net.DialTimeout("tcp", s.cfg.Backend, s.cfg.HTTP.ConnectTimeout)
	if err != nil {
		s.logger.Warn("gateway: tcp backend dial failed",
			"backend", s.cfg.Backend,
			"remote", client.RemoteAddr().String(),
			"error", err)
		return
	}
	s.trackConn(backend, true)
	defer func() {
		_ = backend.Close()
		s.trackConn(backend, false)
	}()

	// 冲刷嗅探阶段已消费的字节（如未命中路由的请求行）。
	if len(prefix) > 0 {
		if _, err := backend.Write(prefix); err != nil {
			s.logger.Debug("gateway: flush sniffed bytes failed",
				"remote", client.RemoteAddr().String(), "error", err)
			return
		}
	}

	done := make(chan struct{}, 2)
	errs := &firstErr{}

	go func() {
		_, cerr := io.Copy(backend, src)
		if cerr != nil && !isExpectedConnError(cerr) {
			errs.set(fmt.Errorf("client->backend: %w", cerr))
		}
		// 传递客户端的半关闭，后端可继续发响应。
		if tc, ok := backend.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
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

	if e := errs.get(); e != nil {
		s.logger.Debug("gateway: tcp connection finished with error",
			"remote", client.RemoteAddr().String(),
			"elapsed", time.Since(start),
			"error", e)
	}
}

// bufConn 让 http.Server 从嗅探阶段的状态续读连接：先重放已消费
// 的字节（prefix，如命中的请求行），再继续读缓冲区与底层连接，
// 数据零丢失。
type bufConn struct {
	net.Conn
	prefix []byte
	r      *bufio.Reader
}

func (c *bufConn) Read(p []byte) (int, error) {
	if len(c.prefix) > 0 {
		n := copy(p, c.prefix)
		c.prefix = c.prefix[n:]
		return n, nil
	}
	return c.r.Read(p)
}

// oneConnListener 把单条已建立的连接包装成 net.Listener，
// 交给 http.Server.Serve 处理；Close 由 Server.Shutdown 触发。
type oneConnListener struct {
	conn net.Conn
	ch   chan net.Conn
	done chan struct{}
}

func newOneConnListener(conn net.Conn) *oneConnListener {
	l := &oneConnListener{
		conn: conn,
		ch:   make(chan net.Conn, 1),
		done: make(chan struct{}),
	}
	l.ch <- conn
	return l
}

func (l *oneConnListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.ch:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *oneConnListener) Close() error {
	select {
	case <-l.done:
	default:
		close(l.done)
	}
	return nil
}

func (l *oneConnListener) Addr() net.Addr { return l.conn.LocalAddr() }

// shutdown 优雅关闭：关闭监听与 HTTP 服务器，
// 等待活跃连接结束；超时后强制关闭全部剩余连接。
func (s *Server) shutdown(ctx context.Context) error {
	// 与 listenAndServe 互斥：listener 可能尚未注册（刚启动即关闭）。
	s.closeMu.Lock()
	if s.listener != nil {
		_ = s.listener.Close()
	}
	s.closeMu.Unlock()
	if s.httpSrv != nil {
		// 关闭全部 one-conn 监听并等待 HTTP 连接排空。
		_ = s.httpSrv.Shutdown(ctx)
	}

	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		s.logger.Info("gateway: all connections drained, shutdown complete")
		return nil
	case <-ctx.Done():
		s.connsMu.Lock()
		for conn := range s.conns {
			_ = conn.Close()
		}
		count := len(s.conns)
		s.connsMu.Unlock()
		s.logger.Warn("gateway: shutdown timeout, force-closed connections", "count", count)
		return ctx.Err()
	}
}

func (s *Server) isShuttingDown() bool {
	s.closeMu.Lock()
	defer s.closeMu.Unlock()
	return s.closed
}

func (s *Server) trackConn(conn net.Conn, add bool) {
	s.connsMu.Lock()
	if add {
		s.conns[conn] = struct{}{}
	} else {
		delete(s.conns, conn)
	}
	s.connsMu.Unlock()
}

// firstErr 只保留两个转发方向中第一个非预期错误。
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

// isTemporaryAcceptError 判断 Accept 错误是否值得重试。
func isTemporaryAcceptError(err error) bool {
	var ne net.Error
	if errors.As(err, &ne) {
		return ne.Temporary()
	}
	return false
}
