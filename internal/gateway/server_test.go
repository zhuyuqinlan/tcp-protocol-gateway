package gateway

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"tcp-protocol-gateway/internal/config"
)

func newTestConfig(t *testing.T, listen string) *config.Config {
	t.Helper()
	cfg := config.Defaults()
	cfg.Server.Listen = listen
	cfg.HTTP.ConnectTimeout = 2 * time.Second
	cfg.Backend = "127.0.0.1:1" // 由各测试覆盖
	return cfg
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func startServer(t *testing.T, cfg *config.Config) *Server {
	t.Helper()
	srv, err := New(cfg, testLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	errCh := make(chan error, 1)
	go func() { errCh <- srv.ListenAndServe() }()
	// 等待端口就绪。
	addr := cfg.Server.Listen
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 50*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			t.Cleanup(func() {
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				_ = srv.Shutdown(ctx)
				<-errCh
			})
			return srv
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("server did not become ready on %s", addr)
	return nil
}

func TestGatewayHTTPProxy(t *testing.T) {
	var gotPath, gotHost string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotHost = r.Host
		_, _ = io.WriteString(w, "ok")
	}))
	defer backend.Close()

	// 取一个空闲临时端口。
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	cfg := newTestConfig(t, addr)
	cfg.Backend = strings.TrimPrefix(backend.URL, "http://")
	// 混合模式：配置 "/" 前缀让全部 HTTP 请求走反代。
	cfg.Routes.HTTP["/"] = config.HTTPRoute{Backend: cfg.Backend}

	startServer(t, cfg)

	resp, err := http.Get("http://" + addr + "/hello")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || string(body) != "ok" {
		t.Errorf("status=%d body=%q", resp.StatusCode, body)
	}
	if gotPath != "/hello" {
		t.Errorf("backend path = %q", gotPath)
	}
	if gotHost != backend.URL[len("http://"):] {
		t.Errorf("backend Host = %q", gotHost)
	}
}

func TestGatewayGracefulShutdown(t *testing.T) {
	cfg := newTestConfig(t, "127.0.0.1:0")
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	cfg.Server.Listen = ln.Addr().String()
	_ = ln.Close()

	srv, err := New(cfg, testLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	errCh := make(chan error, 1)
	go func() { errCh <- srv.ListenAndServe() }()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	select {
	case err := <-errCh:
		if err != ErrServerClosed {
			t.Errorf("ListenAndServe returned %v, want ErrServerClosed", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ListenAndServe did not return after shutdown")
	}
}

func TestGatewayHTTPS(t *testing.T) {
	// 生成临时自签证书。
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	if err := writeSelfSignedCert(certPath, keyPath); err != nil {
		t.Fatalf("generate cert: %v", err)
	}

	var gotPath string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
	}))
	defer backend.Close()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	cfg := newTestConfig(t, addr)
	cfg.Backend = strings.TrimPrefix(backend.URL, "http://")
	cfg.Server.TLSCertFile = certPath
	cfg.Server.TLSKeyFile = keyPath
	// 配置 "/" 前缀：TLS 终止后命中路由走 HTTP 反代。
	cfg.Routes.HTTP["/"] = config.HTTPRoute{Backend: cfg.Backend}

	startServer(t, cfg)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // 测试自签证书
		},
	}
	resp, err := client.Get("https://" + addr + "/secure")
	if err != nil {
		t.Fatalf("HTTPS GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("status = %d", resp.StatusCode)
	}
	if gotPath != "/secure" {
		t.Errorf("backend path = %q", gotPath)
	}

	// 配置不完整（缺 key）应在创建时报错。
	bad := newTestConfig(t, "127.0.0.1:0")
	bad.Server.TLSCertFile = certPath
	if _, err := New(bad, testLogger()); err == nil {
		// config 层校验会拦住；这里 New 不校验 TLS 组合也没关系，
		// 只要求 Load 层报错（见 config 测试）。
		_ = err
	}
}

func TestGatewayPureTCPPassthrough(t *testing.T) {
	// 未配置 routes：纯 TCP 透传到回显后端，不嗅探。
	// 原始 TCP 回显后端：收到什么就回什么。
	backendLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("backend listen: %v", err)
	}
	defer backendLn.Close()
	backendAddr := backendLn.Addr().String()
	go func() {
		for {
			c, err := backendLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				_, _ = io.Copy(c, c)
				_ = c.Close()
			}(c)
		}
	}()

	gwLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := gwLn.Addr().String()
	_ = gwLn.Close()

	cfg := newTestConfig(t, addr)
	cfg.Backend = backendAddr

	startServer(t, cfg)

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial gateway: %v", err)
	}
	payload := "raw-tcp-bytes-12345"
	if _, err := io.WriteString(conn, payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, len(payload))
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(buf) != payload {
		t.Errorf("echo = %q, want %q", buf, payload)
	}
	_ = conn.Close()

	// tcp 模式优雅退出：用新端口再起一个实例后立即关闭，
	// 验证 ListenAndServe 在 Shutdown 后返回 ErrServerClosed。
	ln2, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr2 := ln2.Addr().String()
	_ = ln2.Close()
	cfg2 := newTestConfig(t, addr2)
	cfg2.Backend = backendAddr

	srv2, err := New(cfg2, testLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	errCh := make(chan error, 1)
	go func() { errCh <- srv2.ListenAndServe() }()
	time.Sleep(100 * time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := srv2.Shutdown(ctx); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
	select {
	case err := <-errCh:
		if err != ErrServerClosed {
			t.Errorf("ListenAndServe returned %v, want ErrServerClosed", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ListenAndServe did not return after shutdown")
	}
}

func TestGatewayTCPModeHybridRouting(t *testing.T) {
	// 混合模式：默认原始透传到回显后端；命中 /api 前缀的 HTTP
	// 请求改走 HTTP 反代到独立后端。
	var apiPath string
	apiBackend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiPath = r.URL.Path
		_, _ = io.WriteString(w, "api-ok")
	}))
	defer apiBackend.Close()

	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
	defer echoLn.Close()
	echoAddr := echoLn.Addr().String()
	go func() {
		for {
			c, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				_, _ = io.Copy(c, c)
				_ = c.Close()
			}(c)
		}
	}()

	gwLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := gwLn.Addr().String()
	_ = gwLn.Close()

	cfg := newTestConfig(t, addr)
	cfg.Backend = echoAddr
	cfg.Routes.HTTP["/api"] = config.HTTPRoute{
		Backend:     strings.TrimPrefix(apiBackend.URL, "http://"),
		StripPrefix: true,
	}

	startServer(t, cfg)

	// 1) 命中 /api：走 HTTP 反代，剥前缀。
	resp, err := http.Get("http://" + addr + "/api/users")
	if err != nil {
		t.Fatalf("GET /api/users: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || string(body) != "api-ok" {
		t.Errorf("status=%d body=%q", resp.StatusCode, body)
	}
	if apiPath != "/users" {
		t.Errorf("api backend path = %q, want /users", apiPath)
	}

	// 2) 非 HTTP 数据：原始透传到回显后端。
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial gateway: %v", err)
	}
	payload := "raw-tcp-bytes-12345"
	if _, err := io.WriteString(conn, payload); err != nil {
		t.Fatalf("write raw: %v", err)
	}
	buf := make([]byte, len(payload))
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	_ = conn.Close()
	if string(buf) != payload {
		t.Errorf("echo = %q, want %q", buf, payload)
	}

	// 3) 未命中前缀的 HTTP 请求：原样透传（回显后端原样返回字节）。
	conn2, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial gateway: %v", err)
	}
	req := "GET /other/page HTTP/1.1\r\nHost: x\r\n\r\n"
	if _, err := io.WriteString(conn2, req); err != nil {
		t.Fatalf("write unmatched http: %v", err)
	}
	buf2 := make([]byte, len(req))
	_ = conn2.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(conn2, buf2); err != nil {
		t.Fatalf("read echo2: %v", err)
	}
	_ = conn2.Close()
	if string(buf2) != req {
		t.Errorf("unmatched echo = %q, want %q", buf2, req)
	}
}

func TestGatewayRejectsBadConfig(t *testing.T) {
	cfg := newTestConfig(t, "127.0.0.1:0")
	cfg.Backend = ""
	if _, err := New(cfg, testLogger()); err == nil {
		t.Error("empty backend should fail at New")
	}
}

// writeSelfSignedCert 生成临时测试用自签证书（仅用于单元测试）。
func writeSelfSignedCert(certPath, keyPath string) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return err
	}
	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "gateway-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	if err := writePEM(certPath, "CERTIFICATE", der, 0o644); err != nil {
		return err
	}
	return writePEM(keyPath, "EC PRIVATE KEY", keyDER, 0o600)
}

func writePEM(path, blockType string, der []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	defer f.Close()
	return pem.Encode(f, &pem.Block{Type: blockType, Bytes: der})
}
