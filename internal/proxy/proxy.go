// Package proxy 基于 net/http/httputil 实现 HTTP 反向代理与路径前缀路由。
//
// 网关以标准 HTTP 服务器语义直接监听端口：请求被完整解析后，
// Router 按请求路径前缀（最长前缀优先）选择后端；未命中任何前缀时
// 转发到默认后端。转发使用 httputil.ReverseProxy，天然支持
// Keep-Alive、流式请求体、WebSocket Upgrade（协议切换）与 502 兜底。
//
// 后端地址只来自配置文件，客户端无法通过请求内容指定转发目标，
// 因此不存在开放代理风险。网关不修改（除可选剥前缀外）请求内容。
package proxy

import (
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sort"
	"strings"
	"time"
)

// Route 描述一条前缀路由。
type Route struct {
	// Prefix 是路径前缀，必须以 "/" 开头。
	Prefix string
	// Backend 是命中的请求转发目标（host:port）。
	Backend string
	// StripPrefix 为 true 时，转发前把 Prefix 从请求路径中剥掉。
	StripPrefix bool
}

// Router 是 HTTP 路径前缀路由表（最长前缀优先）。
type Router struct {
	// routes 已按前缀长度降序排列。
	routes []Route
}

// NewRouter 构建路由表。
// 前缀必须以 "/" 开头（与配置校验一致，此处为纵深防御）。
func NewRouter(routes []Route) (*Router, error) {
	r := &Router{}
	for _, rt := range routes {
		if rt.Backend == "" {
			return nil, fmt.Errorf("proxy: route %q has empty backend", rt.Prefix)
		}
		if !strings.HasPrefix(rt.Prefix, "/") {
			return nil, fmt.Errorf("proxy: route prefix %q must start with '/'", rt.Prefix)
		}
		r.routes = append(r.routes, rt)
	}
	// 最长前缀优先，保证 "/api/v1" 优先于 "/api" 命中。
	sort.SliceStable(r.routes, func(i, j int) bool {
		return len(r.routes[i].Prefix) > len(r.routes[j].Prefix)
	})
	return r, nil
}

// Match 按请求路径返回命中的路由；未命中任何前缀返回 false。
func (r *Router) Match(path string) (Route, bool) {
	for _, rt := range r.routes {
		if strings.HasPrefix(path, rt.Prefix) {
			return rt, true
		}
	}
	return Route{}, false
}

// Proxy 是 HTTP 反向代理处理器。
type Proxy struct {
	defaultBackend string
	router         *Router
	// transport 是全部后端共享的 HTTP 传输层。
	transport *http.Transport
	// backends 缓存每个后端地址对应的 ReverseProxy。
	backends map[string]*httputil.ReverseProxy
	logger   *slog.Logger
}

// New 创建代理处理器。
// defaultBackend 是路由未命中时的转发目标，支持两种形式：
//
//	"host:port"               明文 HTTP 转发
//	"https://host[:port]"     以 TLS 连接后端（SNI/Host 为 host）
//
// connectTimeout 用于到后端的拨号；tlsSkipVerify 为 true 时不校验
// HTTPS 后端的证书（自签名场景）。
func New(defaultBackend string, router *Router, connectTimeout time.Duration, tlsSkipVerify bool, logger *slog.Logger) (*Proxy, error) {
	if logger == nil {
		logger = slog.Default()
	}
	if defaultBackend == "" {
		return nil, errors.New("proxy: default backend must not be empty")
	}
	p := &Proxy{
		defaultBackend: defaultBackend,
		router:         router,
		backends:       make(map[string]*httputil.ReverseProxy),
		logger:         logger,
	}
	transport := &http.Transport{
		Proxy: nil, // 网关自身就是代理，不再使用上游代理。
		DialContext: (&net.Dialer{
			Timeout: connectTimeout,
		}).DialContext,
		// scheme 为 https 时由 http.Transport 自动完成 TLS 握手，
		// SNI 取自后端 URL 的主机名。
		TLSClientConfig: &tls.Config{
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: tlsSkipVerify, //nolint:gosec // 由配置显式开启
		},
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   20,
		IdleConnTimeout:       90 * time.Second,
		ResponseHeaderTimeout: 0, // 不限制后端响应时长（流式场景）。
	}
	p.transport = transport
	return p, nil
}

// ServeHTTP 实现 http.Handler：按路径前缀路由并转发。
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	backend := p.defaultBackend
	if rt, ok := p.router.Match(r.URL.Path); ok {
		backend = rt.Backend
		if rt.StripPrefix {
			r.URL.Path = stripPathPrefix(r.URL.Path, rt.Prefix)
			// Path 已重写，RawPath 不再与其一致，清空让
			// httputil 重新按 Path 生成合法的线格式目标。
			r.URL.RawPath = ""
		}
	}
	rp := p.backendProxy(backend)
	rp.ServeHTTP(w, r)
}

// stripPathPrefix 从 path 中剥掉 prefix；剥完为空时返回 "/"，
// 剥完不以 "/" 开头时补 "/"（如 /apiweb 剥掉 /api 后为 web → /web）。
func stripPathPrefix(path, prefix string) string {
	rest := strings.TrimPrefix(path, prefix)
	if rest == "" {
		return "/"
	}
	if !strings.HasPrefix(rest, "/") {
		rest = "/" + rest
	}
	return rest
}

// backendProxy 返回指定后端的 ReverseProxy（按需创建并缓存）。
func (p *Proxy) backendProxy(backend string) *httputil.ReverseProxy {
	if rp, ok := p.backends[backend]; ok {
		return rp
	}
	target := parseBackend(backend)
	rp := &httputil.ReverseProxy{
		// 流式响应（SSE、大文件）立即冲刷，与透明转发语义一致。
		FlushInterval: -1,
		Rewrite: func(pr *httputil.ProxyRequest) {
			// SetURL 会把出站请求路由到 target，并把 Host 重写为
			// 后端地址（Out.Host 置空）。
			pr.SetURL(target)
			// 设置标准 X-Forwarded-For / X-Forwarded-Proto。
			pr.SetXForwarded()
		},
		Transport: p.transport,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			p.logger.Warn("proxy: backend request failed",
				"backend", backend, "path", r.URL.Path, "error", err)
			w.WriteHeader(http.StatusBadGateway)
		},
	}
	p.backends[backend] = rp
	return rp
}

// parseBackend 把后端地址解析为转发目标 URL。
// 支持 "host:port"、"http://host:port" 与 "https://host:port"；
// 其他未知 scheme 回退为 http。
func parseBackend(b string) *url.URL {
	if i := strings.Index(b, "://"); i >= 0 {
		scheme := b[:i]
		if scheme != "http" && scheme != "https" {
			scheme = "http"
		}
		return &url.URL{Scheme: scheme, Host: b[i+3:]}
	}
	return &url.URL{Scheme: "http", Host: b}
}
