// Package gateway 提供端口监听、混合分流（默认 TCP 透传 +
// routes.http 命中走 HTTP 反代）与优雅退出。
package gateway

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"

	"tcp-protocol-gateway/internal/config"
	"tcp-protocol-gateway/internal/proxy"
)

// ErrServerClosed 在服务已关闭后返回。
var ErrServerClosed = errors.New("gateway: server closed")

// Server 是网关服务，只有一种工作方式（混合模式）：
//
//   - 未命中：每条入站连接默认原始字节透传到默认后端（backend），
//     不做任何协议解析
//   - 命中：配置了 routes.http 时，对嗅探到 HTTP 请求行且路径命中
//     前缀的连接改走 HTTP 反向代理；未命中的连接照旧透传
//   - 配置了 TLS 证书时按连接嗅探：客户端发起 TLS 握手则网关终止
//     TLS 后按上述规则处理解密明文，非 TLS 连接（如 Minecraft 等
//     原始 TCP 协议）不受影响，单端口同时服务 HTTPS 与 TCP
//   - 未配置 routes 时不做 HTTP 嗅探，即纯 TCP 透传，零开销
type Server struct {
	cfg    *config.Config
	logger *slog.Logger

	// 配置了 routes.http 时创建：命中前缀的连接复用该服务器。
	httpSrv *http.Server
	router  *proxy.Router

	// 配置了 TLS 证书时创建：用于按连接嗅探（首字节为 TLS record
	// 时终止 TLS），使单端口同时服务 HTTPS 与原始 TCP。
	tlsConfig *tls.Config

	listener net.Listener

	// conns 跟踪活跃连接（含出站连接），供强制清理。
	connsMu sync.Mutex
	conns   map[net.Conn]struct{}
	// wg 等待全部连接处理 goroutine 结束。
	wg sync.WaitGroup
	// closed 标记服务进入关闭流程。
	closed  bool
	closeMu sync.Mutex
}

// New 根据配置创建网关服务。
func New(cfg *config.Config, logger *slog.Logger) (*Server, error) {
	if logger == nil {
		logger = slog.Default()
	}
	if cfg.Backend == "" {
		return nil, errors.New("gateway: backend must not be empty")
	}
	s := &Server{
		cfg:    cfg,
		logger: logger,
		conns:  make(map[net.Conn]struct{}),
	}

	// 配置了路由才需要嗅探与 HTTP 分流；未配置则纯透传，零嗅探开销。
	if len(cfg.Routes.HTTP) > 0 {
		router, err := proxy.NewRouter(routesFromConfig(cfg.Routes.HTTP))
		if err != nil {
			return nil, fmt.Errorf("gateway: build http router: %w", err)
		}
		p, err := proxy.New(cfg.Backend, router, cfg.HTTP.ConnectTimeout, cfg.HTTP.TLSSkipVerify, logger)
		if err != nil {
			return nil, fmt.Errorf("gateway: create proxy: %w", err)
		}
		s.router = router
		s.httpSrv = &http.Server{
			Handler:           p,
			ReadHeaderTimeout: cfg.Server.ReadHeaderTimeout,
		}
	}
	return s, nil
}

// ListenAndServe 直接监听配置端口并开始服务，阻塞直到返回错误。
// 通过 Shutdown 关闭时返回 ErrServerClosed。
func (s *Server) ListenAndServe() error {
	return s.listenAndServe()
}

// Shutdown 优雅关闭：停止接收新连接，等待活跃连接结束；
// 超过 ctx 期限后强制关闭并返回。
func (s *Server) Shutdown(ctx context.Context) error {
	s.closeMu.Lock()
	s.closed = true
	s.closeMu.Unlock()
	return s.shutdown(ctx)
}

// routesFromConfig 把配置中的 HTTP 路由表转换为代理路由表。
func routesFromConfig(routes map[string]config.HTTPRoute) []proxy.Route {
	list := make([]proxy.Route, 0, len(routes))
	for prefix, r := range routes {
		list = append(list, proxy.Route{
			Prefix:      prefix,
			Backend:     r.Backend,
			StripPrefix: r.StripPrefix,
		})
	}
	return list
}
