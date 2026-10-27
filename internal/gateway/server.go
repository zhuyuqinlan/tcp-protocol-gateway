// Package gateway 组合协议嗅探与各协议处理器，
// 提供 TCP 监听、多路由映射、并发控制与优雅退出。
package gateway

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"tcp-protocol-gateway/internal/config"
	"tcp-protocol-gateway/internal/detector"
	"tcp-protocol-gateway/internal/minecraft"
	"tcp-protocol-gateway/internal/proxy"
	"tcp-protocol-gateway/internal/relay"
)

// sniffBufferSize 是嗅探/读取阶段 bufio.Reader 的缓冲区大小。
// 它同时限制了单次 Peek 的上限：恶意客户端无法诱导网关
// 分配超过该尺寸的窥探缓冲。握手包上限为 1 KiB，
// HTTP 请求行远小于该值，4 KiB 足够。
const sniffBufferSize = 4096

// ErrServerClosed 在服务已关闭后调用 ListenAndServe 时返回。
var ErrServerClosed = errors.New("gateway: server closed")

// tcpRoute 是一条独立端口的原始 TCP 转发路由。
type tcpRoute struct {
	listener net.Listener
	backend  string
}

// Server 是多协议网关服务。
type Server struct {
	cfg    *config.Config
	logger *slog.Logger
	proxy  *proxy.Proxy
	router *proxy.Router
	mc     *minecraft.Handler

	// 主监听（协议嗅探端口）。
	listener net.Listener
	// tcpRoutes 是独立端口的原始 TCP 转发路由。
	tcpRoutes []tcpRoute
	// udpRelays 是独立端口的 UDP 转发中继。
	udpRelays []*relay.Relay
	// extraWG 等待 TCP/UDP 路由的 serve goroutine 结束。
	extraWG sync.WaitGroup

	// sem 限制最大并发连接数（跨全部监听端口共享预算）。
	sem chan struct{}
	// conns 跟踪全部活跃连接，供优雅退出强制清理。
	connsMu sync.Mutex
	conns   map[net.Conn]struct{}
	// wg 等待全部连接处理 goroutine 结束。
	wg sync.WaitGroup
	// closed 标记服务进入关闭流程，此后拒绝新连接。
	closed  bool
	closeMu sync.Mutex
}

// New 根据配置创建网关服务。
func New(cfg *config.Config, logger *slog.Logger) (*Server, error) {
	if logger == nil {
		logger = slog.Default()
	}
	router, err := buildRouter(cfg.Routes.HTTP)
	if err != nil {
		return nil, fmt.Errorf("gateway: build http router: %w", err)
	}
	s := &Server{
		cfg:    cfg,
		logger: logger,
		proxy:  proxy.New(cfg.HTTP.ConnectTimeout, logger),
		router: router,
		mc:     minecraft.NewHandler(&cfg.Minecraft, cfg.Server.IdleTimeout, logger),
		sem:    make(chan struct{}, cfg.Server.MaxConnections),
		conns:  make(map[net.Conn]struct{}),
	}
	return s, nil
}

// ListenAndServe 打开全部监听（主端口 + TCP/UDP 路由端口）并开始服务，
// 阻塞直到返回错误。通过 Shutdown 关闭时返回 ErrServerClosed。
// 任一路由端口打开失败时，关闭已打开的监听并返回错误。
func (s *Server) ListenAndServe() error {
	ln, err := net.Listen("tcp", s.cfg.Server.Listen)
	if err != nil {
		return fmt.Errorf("gateway: listen on %s: %w", s.cfg.Server.Listen, err)
	}
	s.listener = ln

	// 打开全部 TCP 路由监听；失败则回滚。
	for listen, backend := range s.cfg.Routes.TCP {
		rl, err := net.Listen("tcp", listen)
		if err != nil {
			s.closeAllListeners()
			return fmt.Errorf("gateway: open tcp route %s: %w", listen, err)
		}
		s.tcpRoutes = append(s.tcpRoutes, tcpRoute{listener: rl, backend: backend})
	}

	// 创建 UDP 路由中继（Run 在下方启动）。
	for listen, backend := range s.cfg.Routes.UDP {
		s.udpRelays = append(s.udpRelays,
			relay.New(listen, backend, s.cfg.Server.IdleTimeout, s.logger))
	}

	s.logger.Info("gateway: listening",
		"addr", s.cfg.Server.Listen,
		"http_routes", len(s.cfg.Routes.HTTP),
		"tcp_routes", len(s.tcpRoutes),
		"udp_routes", len(s.udpRelays),
		"max_connections", s.cfg.Server.MaxConnections)

	// 启动 TCP/UDP 路由的 serve goroutine。
	for _, rt := range s.tcpRoutes {
		s.extraWG.Add(1)
		go func(r tcpRoute) {
			defer s.extraWG.Done()
			s.serveTCPRoute(r)
		}(rt)
	}
	for _, r := range s.udpRelays {
		s.extraWG.Add(1)
		go func(rel *relay.Relay) {
			defer s.extraWG.Done()
			if err := rel.Run(); err != nil {
				s.logger.Error("gateway: udp relay failed", "error", err)
			}
		}(r)
	}

	s.serveMain(ln)
	s.extraWG.Wait()
	return ErrServerClosed
}

// serveMain 是主监听端口的 Accept 循环。
func (s *Server) serveMain(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if s.isShuttingDown() {
				return
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
			s.logger.Error("gateway: accept failed", "listen", ln.Addr().String(), "error", err)
			return
		}

		if !s.tryAcquire(conn) {
			continue
		}

		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer s.release(conn)
			s.handleMainConn(conn)
		}()
	}
}

// serveTCPRoute 是独立 TCP 路由端口的 Accept 循环：
// 不做协议嗅探，直接把字节流双向转发到配置的后端。
func (s *Server) serveTCPRoute(rt tcpRoute) {
	for {
		conn, err := rt.listener.Accept()
		if err != nil {
			if s.isShuttingDown() {
				return
			}
			if isTemporaryAcceptError(err) {
				time.Sleep(10 * time.Millisecond)
				continue
			}
			s.logger.Error("gateway: tcp route accept failed",
				"listen", rt.listener.Addr().String(), "error", err)
			return
		}

		if !s.tryAcquire(conn) {
			continue
		}

		s.wg.Add(1)
		go func(backend string) {
			defer s.wg.Done()
			defer s.release(conn)
			s.handleProxyConn(conn, backend)
		}(rt.backend)
	}
}

// tryAcquire 获取一个并发名额；服务已关闭时拒绝并关闭连接。
func (s *Server) tryAcquire(conn net.Conn) bool {
	s.closeMu.Lock()
	shutdown := s.closed
	s.closeMu.Unlock()
	if shutdown {
		_ = conn.Close()
		return false
	}
	select {
	case s.sem <- struct{}{}:
		s.connsMu.Lock()
		s.conns[conn] = struct{}{}
		s.connsMu.Unlock()
		return true
	default:
		// 超过最大并发连接数：立即拒绝，防止慢连接耗尽资源。
		s.logger.Warn("gateway: max connections reached, rejecting",
			"remote", conn.RemoteAddr().String())
		_ = conn.Close()
		return false
	}
}

func (s *Server) release(conn net.Conn) {
	<-s.sem
	s.connsMu.Lock()
	delete(s.conns, conn)
	s.connsMu.Unlock()
}

func (s *Server) isShuttingDown() bool {
	s.closeMu.Lock()
	defer s.closeMu.Unlock()
	return s.closed
}

// handleMainConn 处理主端口连接：嗅探协议并分发。
// 任何路径都必须关闭连接；任何单连接的异常都不允许影响进程。
func (s *Server) handleMainConn(conn net.Conn) {
	defer func() {
		// 单个连接的 panic 不允许击穿进程。
		if r := recover(); r != nil {
			s.logger.Error("gateway: recovered from panic in connection handler",
				"remote", conn.RemoteAddr().String(), "panic", r)
		}
		_ = conn.Close()
	}()

	remote := conn.RemoteAddr().String()
	start := time.Now()

	// 握手阶段读取期限：慢连接在此超时后被关闭，
	// 防止恶意客户端长期占用 goroutine。
	if err := conn.SetDeadline(start.Add(s.cfg.Server.HandshakeTimeout)); err != nil {
		s.logger.Debug("gateway: set handshake deadline failed", "remote", remote, "error", err)
		return
	}

	br := bufio.NewReaderSize(conn, sniffBufferSize)
	result, err := detector.Detect(br, s.cfg.Server.HandshakeTimeout)
	if err != nil {
		s.logger.Info("gateway: protocol detection failed",
			"remote", remote, "elapsed", time.Since(start), "error", err)
		return
	}

	switch result.Protocol {
	case detector.ProtocolHTTP:
		err = s.handleHTTP(conn, br, remote, start)

	case detector.ProtocolMinecraft:
		err = s.handleMinecraft(conn, br, remote, start)

	case detector.ProtocolTLS:
		// 网关不解密 TLS；按配置语义明确拒绝。
		s.logger.Info("gateway: tls connection rejected",
			"remote", remote, "elapsed", time.Since(start))
		return

	default: // ProtocolUnknown
		s.logger.Info("gateway: unknown protocol, closing",
			"remote", remote, "elapsed", time.Since(start))
		return
	}

	logLevel := slog.LevelDebug
	if err != nil {
		logLevel = slog.LevelWarn
	}
	s.logger.Log(context.Background(), logLevel, "gateway: connection finished",
		"remote", remote,
		"protocol", result.Protocol.String(),
		"elapsed", time.Since(start),
		"error", errMessage(err))
}

// handleHTTP 处理主端口上的 HTTP 连接：
// 按请求行路径前缀选择后端转发；未匹配任何前缀时，
// 模拟真实 Minecraft 服务器的行为——把字节当作 Minecraft
// 协议解析，合法的 SLP/Login 得到协议响应，非法数据直接断开
// （与原版服务器收到无效包的表现一致）。
func (s *Server) handleHTTP(conn net.Conn, br *bufio.Reader, remote string, start time.Time) error {
	// 识别完成，解除握手期限。后续路径各自管理超时。
	if err := conn.SetDeadline(time.Time{}); err != nil {
		s.logger.Debug("gateway: clear deadline failed", "remote", remote, "error", err)
		return nil
	}

	backend, err := s.router.Match(br)
	if err != nil {
		s.logger.Info("gateway: http route match failed",
			"remote", remote, "elapsed", time.Since(start), "error", err)
		return err
	}
	if backend != nil {
		s.logger.Debug("gateway: http connection",
			"remote", remote, "backend", backend.Backend, "strip", backend.Strip)
		return s.proxy.Handle(conn, br, backend)
	}

	// 未匹配任何 HTTP 前缀：回退到 Minecraft 模拟。
	return s.handleMinecraft(conn, br, remote, start)
}

// handleMinecraft 处理主端口上的 Minecraft 连接。
// 无论连接是嗅探直接识别为 Minecraft，还是 HTTP 未匹配后的回退，
// 都必须在此处从流中正式读取并校验握手包（嗅探阶段只 Peek 未消费）；
// 校验失败的表现与真实 Minecraft 服务器一致：直接断开连接。
func (s *Server) handleMinecraft(conn net.Conn, br *bufio.Reader, remote string, start time.Time) error {
	if !s.cfg.Minecraft.Enabled {
		s.logger.Info("gateway: minecraft disabled, closing",
			"remote", remote, "elapsed", time.Since(start))
		return nil
	}

	parsed, err := minecraft.ReadHandshake(br, minecraft.MaxHandshakePacketLen)
	if err != nil {
		// 与原版服务器收到无法解析的包时一致：断开连接。
		s.logger.Debug("gateway: not a valid minecraft handshake, closing",
			"remote", remote, "elapsed", time.Since(start), "error", err)
		return nil
	}

	if err := conn.SetDeadline(time.Time{}); err != nil {
		s.logger.Debug("gateway: clear deadline failed", "remote", remote, "error", err)
		return nil
	}
	return s.mc.Serve(conn, br, parsed)
}

// handleProxyConn 处理独立 TCP 路由端口的连接：纯字节转发。
func (s *Server) handleProxyConn(conn net.Conn, backend string) {
	defer func() {
		if r := recover(); r != nil {
			s.logger.Error("gateway: recovered from panic in tcp route handler",
				"remote", conn.RemoteAddr().String(), "panic", r)
		}
		_ = conn.Close()
	}()

	start := time.Now()
	br := bufio.NewReaderSize(conn, sniffBufferSize)
	err := s.proxy.Handle(conn, br, &proxy.Match{Backend: backend})

	logLevel := slog.LevelDebug
	if err != nil {
		logLevel = slog.LevelWarn
	}
	s.logger.Log(context.Background(), logLevel, "gateway: tcp route connection finished",
		"remote", conn.RemoteAddr().String(),
		"backend", backend,
		"elapsed", time.Since(start),
		"error", errMessage(err))
}

// Shutdown 优雅关闭：停止全部监听，等待活跃连接结束；
// 超过 ctx 期限后强制关闭剩余连接并返回。
func (s *Server) Shutdown(ctx context.Context) error {
	s.closeMu.Lock()
	s.closed = true
	s.closeMu.Unlock()

	s.closeAllListeners()
	for _, r := range s.udpRelays {
		r.Stop()
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
		// 强制关闭全部剩余连接，释放 goroutine。
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

// closeAllListeners 关闭主监听与全部 TCP 路由监听。
func (s *Server) closeAllListeners() {
	if s.listener != nil {
		_ = s.listener.Close()
	}
	for _, rt := range s.tcpRoutes {
		_ = rt.listener.Close()
	}
}

// buildRouter 把配置中的 HTTP 路由表转换为代理路由表。
func buildRouter(routes map[string]config.HTTPRoute) (*proxy.Router, error) {
	list := make([]proxy.Route, 0, len(routes))
	for prefix, r := range routes {
		list = append(list, proxy.Route{
			Prefix:      prefix,
			Backend:     r.Backend,
			StripPrefix: r.StripPrefix,
		})
	}
	return proxy.NewRouter(list)
}

// errMessage 返回用于日志的错误文本（nil 时为空串）。
func errMessage(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// isTemporaryAcceptError 判断 Accept 错误是否值得重试。
func isTemporaryAcceptError(err error) bool {
	var ne net.Error
	if errors.As(err, &ne) {
		return ne.Temporary()
	}
	return false
}
