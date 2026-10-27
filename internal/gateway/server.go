// Package gateway 组合协议嗅探与各协议处理器，
// 提供 TCP 监听、并发控制与优雅退出。
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
)

// sniffBufferSize 是嗅探/读取阶段 bufio.Reader 的缓冲区大小。
// 它同时限制了单次 Peek 的上限：恶意客户端无法诱导网关
// 分配超过该尺寸的窥探缓冲。握手包上限为 1 KiB，
// HTTP 请求行远小于该值，4 KiB 足够。
const sniffBufferSize = 4096

// ErrServerClosed 在服务已关闭后调用 ListenAndServe 时返回。
var ErrServerClosed = errors.New("gateway: server closed")

// Server 是多协议网关服务。
type Server struct {
	cfg    *config.Config
	logger *slog.Logger
	proxy  *proxy.Proxy
	mc     *minecraft.Handler

	listener net.Listener
	// sem 限制最大并发连接数（令牌桶信号量）。
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
	s := &Server{
		cfg:    cfg,
		logger: logger,
		proxy:  proxy.New(cfg.HTTP.Backend, cfg.HTTP.ConnectTimeout, logger),
		mc:     minecraft.NewHandler(&cfg.Minecraft, cfg.Server.IdleTimeout, logger),
		sem:    make(chan struct{}, cfg.Server.MaxConnections),
		conns:  make(map[net.Conn]struct{}),
	}
	return s, nil
}

// ListenAndServe 监听并开始服务，阻塞直到返回错误。
// 通过 Shutdown 关闭时返回 ErrServerClosed。
func (s *Server) ListenAndServe() error {
	ln, err := net.Listen("tcp", s.cfg.Server.Listen)
	if err != nil {
		return fmt.Errorf("gateway: listen on %s: %w", s.cfg.Server.Listen, err)
	}
	s.listener = ln
	s.logger.Info("gateway: listening",
		"addr", s.cfg.Server.Listen,
		"http_backend", s.cfg.HTTP.Backend,
		"max_connections", s.cfg.Server.MaxConnections)

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
			// 临时性错误（如 fd 暂时耗尽）不终止服务。
			if isTemporaryAcceptError(err) {
				s.logger.Warn("gateway: temporary accept error", "error", err)
				time.Sleep(10 * time.Millisecond)
				continue
			}
			return fmt.Errorf("gateway: accept: %w", err)
		}

		if !s.tryAcquire(conn) {
			continue
		}

		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer s.release(conn)
			s.handleConn(conn)
		}()
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

// handleConn 处理单个连接：嗅探协议并分发。
// 任何路径都必须关闭连接；任何单连接的异常都不允许影响进程。
func (s *Server) handleConn(conn net.Conn) {
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

	// 识别完成，解除握手期限。各处理器自行管理后续超时。
	if err := conn.SetDeadline(time.Time{}); err != nil {
		s.logger.Debug("gateway: clear deadline failed", "remote", remote, "error", err)
		return
	}

	switch result.Protocol {
	case detector.ProtocolHTTP:
		s.logger.Debug("gateway: http connection",
			"remote", remote, "backend", s.cfg.HTTP.Backend)
		err = s.proxy.Handle(conn, br)

	case detector.ProtocolMinecraft:
		if !s.cfg.Minecraft.Enabled {
			s.logger.Info("gateway: minecraft disabled, closing",
				"remote", remote, "elapsed", time.Since(start))
			return
		}
		// 嗅探阶段只窥探未消费握手包；这里正式从流中读取并校验，
		// 保证后续状态机从正确的流位置开始。
		hs, hsErr := minecraft.ReadHandshake(br, minecraft.MaxHandshakePacketLen)
		if hsErr != nil {
			s.logger.Warn("gateway: minecraft handshake read failed",
				"remote", remote, "elapsed", time.Since(start), "error", hsErr)
			return
		}
		err = s.mc.Serve(conn, br, hs)

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

// Shutdown 优雅关闭：停止接收新连接，等待活跃连接结束；
// 超过 ctx 期限后强制关闭剩余连接并返回。
func (s *Server) Shutdown(ctx context.Context) error {
	s.closeMu.Lock()
	s.closed = true
	s.closeMu.Unlock()

	if s.listener != nil {
		_ = s.listener.Close()
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
