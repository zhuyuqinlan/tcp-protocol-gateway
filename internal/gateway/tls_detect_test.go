package gateway

import (
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"tcp-protocol-gateway/internal/config"
)

// startEchoBackend 启动一个原始 TCP 回显后端（收到什么回什么）。
func startEchoBackend(t *testing.T) (addr string, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				_, _ = io.Copy(c, c)
				_ = c.Close()
			}(c)
		}
	}()
	return ln.Addr().String(), func() {
		_ = ln.Close()
		<-done
	}
}

// TestGatewayMixedPortTLSAndTCP 验证单端口同时服务 HTTPS 与原始
// TCP：配置 TLS 证书 + routes 后，
//  1. TLS 客户端（HTTPS）终止 TLS 后按前缀路由反代；
//  2. 明文 HTTP 客户端照旧按前缀路由反代（不因 TLS 配置受影响）；
//  3. 非 HTTP 原始 TCP 连接透传到默认后端（如 Minecraft）；
//  4. 首字节 0x16 但不构成合法 TLS record 头的字节流原样透传
//     （防 Minecraft 等协议被误判为 TLS）。
func TestGatewayMixedPortTLSAndTCP(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	if err := writeSelfSignedCert(certPath, keyPath); err != nil {
		t.Fatalf("generate cert: %v", err)
	}

	var gotPath string
	httpBackend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_, _ = io.WriteString(w, "ok")
	}))
	defer httpBackend.Close()

	echoAddr, stopEcho := startEchoBackend(t)
	defer stopEcho()

	gwLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := gwLn.Addr().String()
	_ = gwLn.Close()

	cfg := newTestConfig(t, addr)
	cfg.Backend = echoAddr
	cfg.Server.TLSCertFile = certPath
	cfg.Server.TLSKeyFile = keyPath
	cfg.Routes.HTTP["/"] = config.HTTPRoute{
		Backend: strings.TrimPrefix(httpBackend.URL, "http://"),
	}
	startServer(t, cfg)

	// 1) HTTPS：TLS 握手成功，命中 "/" 路由。
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // 测试自签证书
		},
	}
	resp, err := client.Get("https://" + addr + "/secure")
	if err != nil {
		t.Fatalf("HTTPS GET: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || string(body) != "ok" {
		t.Errorf("https status=%d body=%q", resp.StatusCode, body)
	}
	if gotPath != "/secure" {
		t.Errorf("https backend path = %q", gotPath)
	}

	// 2) 明文 HTTP：同端口照旧按前缀路由反代。
	resp, err = http.Get("http://" + addr + "/plain")
	if err != nil {
		t.Fatalf("plain GET: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("plain status = %d", resp.StatusCode)
	}
	if gotPath != "/plain" {
		t.Errorf("plain backend path = %q", gotPath)
	}

	// 3) 原始 TCP：透传到回显后端。
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
		t.Errorf("raw echo = %q, want %q", buf, payload)
	}

	// 4) 首字节 0x16 但第二字节非 0x03：不是 TLS record，原样透传。
	conn, err = net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial gateway: %v", err)
	}
	fake := "\x16\x00\x00\x00mc-handshake-payload"
	if _, err := io.WriteString(conn, fake); err != nil {
		t.Fatalf("write fake tls: %v", err)
	}
	buf = make([]byte, len(fake))
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read fake echo: %v", err)
	}
	_ = conn.Close()
	if string(buf) != fake {
		t.Errorf("fake-tls echo = %q, want %q", buf, fake)
	}
}

// TestGatewayTLSWithoutRoutes 验证配置了 TLS 证书但未配置 routes
// 时：TLS 客户端的解密明文透传到默认后端，原始 TCP 连接不受影响。
func TestGatewayTLSWithoutRoutes(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	if err := writeSelfSignedCert(certPath, keyPath); err != nil {
		t.Fatalf("generate cert: %v", err)
	}

	// 明文回显后端：TLS 终止后的解密明文到这里应原样返回。
	echoAddr, stopEcho := startEchoBackend(t)
	defer stopEcho()

	gwLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := gwLn.Addr().String()
	_ = gwLn.Close()

	cfg := newTestConfig(t, addr)
	cfg.Backend = echoAddr
	cfg.Server.TLSCertFile = certPath
	cfg.Server.TLSKeyFile = keyPath
	// 不配置 routes.HTTP。
	startServer(t, cfg)

	// 1) TLS 客户端：解密后的明文透传。
	var conn net.Conn
	conn, err = tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // 测试自签证书
	if err != nil {
		t.Fatalf("tls dial: %v", err)
	}
	payload := "tls-plaintext-payload"
	if _, err := io.WriteString(conn, payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, len(payload))
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	_ = conn.Close()
	if string(buf) != payload {
		t.Errorf("tls plaintext echo = %q, want %q", buf, payload)
	}

	// 2) 原始 TCP 客户端：不受 TLS 配置影响，照旧透传。
	conn, err = net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial gateway: %v", err)
	}
	raw := "raw-minecraft-bytes"
	if _, err := io.WriteString(conn, raw); err != nil {
		t.Fatalf("write raw: %v", err)
	}
	buf = make([]byte, len(raw))
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read raw echo: %v", err)
	}
	_ = conn.Close()
	if string(buf) != raw {
		t.Errorf("raw echo = %q, want %q", buf, raw)
	}
}

// TestGatewayTLSHandshakeFailureNoCrash 回归测试：客户端发送合法
// TLS record 头但握手失败（如扫描器探测、畸形 ClientHello）时，
// 单条连接的处理不得 panic 击穿进程，且服务必须继续可用。
func TestGatewayTLSHandshakeFailureNoCrash(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	if err := writeSelfSignedCert(certPath, keyPath); err != nil {
		t.Fatalf("generate cert: %v", err)
	}

	echoAddr, stopEcho := startEchoBackend(t)
	defer stopEcho()

	gwLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := gwLn.Addr().String()
	_ = gwLn.Close()

	cfg := newTestConfig(t, addr)
	cfg.Backend = echoAddr
	cfg.Server.TLSCertFile = certPath
	cfg.Server.TLSKeyFile = keyPath
	startServer(t, cfg)

	// 构造握手必失败的连接：合法 TLS record 头（0x16 0x03 0x03）
	// 后紧跟垃圾数据，服务端完成 record 读取后在握手阶段报错。
	bad, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial gateway: %v", err)
	}
	if _, err := io.WriteString(bad, "\x16\x03\x03\x00\x05garbage"); err != nil {
		t.Fatalf("write bad tls: %v", err)
	}
	// 等待网关完成握手失败处理路径，再关闭客户端侧。
	_ = bad.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, _ = bad.Read(make([]byte, 16))
	_ = bad.Close()

	// 若网关因 defer 内二次 panic 崩溃，下方连接将失败。
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("gateway crashed after failed handshake: %v", err)
	}
	payload := "still-alive"
	if _, err := io.WriteString(conn, payload); err != nil {
		t.Fatalf("write after crash: %v", err)
	}
	buf := make([]byte, len(payload))
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read echo after failed handshake: %v", err)
	}
	_ = conn.Close()
	if string(buf) != payload {
		t.Errorf("echo = %q, want %q", buf, payload)
	}
}

// TestDetectTLSPartialRecord 验证只收到 1~4 字节（不足完整 TLS
// record 头）且随后 EOF 时按非 TLS 处理，不吞字节。
func TestDetectTLSPartialRecord(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	if err := writeSelfSignedCert(certPath, keyPath); err != nil {
		t.Fatalf("generate cert: %v", err)
	}
	cfg := newTestConfig(t, "127.0.0.1:0")
	cfg.Server.TLSCertFile = certPath
	cfg.Server.TLSKeyFile = keyPath
	cfg.Server.ReadHeaderTimeout = time.Second

	srv, err := New(cfg, testLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// 手动构造 tlsConfig（绕过 ListenAndServe）。
	srv.tlsConfig = &tls.Config{ //nolint:gosec // 测试
		MinVersion: tls.VersionTLS12,
	}

	c1, c2 := net.Pipe()
	defer func() { _ = c1.Close() }()
	go func() {
		_, _ = c2.Write([]byte{0x16})
		_ = c2.Close()
	}()

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, br := srv.detectTLS(c1)
		if conn == nil {
			t.Error("detectTLS returned nil for partial record, want non-TLS conn")
			return
		}
		b, err := br.ReadByte()
		if err != nil || b != 0x16 {
			t.Errorf("replay byte = %#v err = %v, want 0x16", b, err)
		}
	}()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("detectTLS blocked on partial record")
	}
}

// TestIsTLSRecordHead 单测 record 头判定。
func TestIsTLSRecordHead(t *testing.T) {
	cases := []struct {
		in   []byte
		want bool
	}{
		{[]byte{0x16, 0x03, 0x01, 0x00, 0x2f}, true},  // TLS 1.0
		{[]byte{0x16, 0x03, 0x03, 0x00, 0x2f}, true},  // TLS 1.2
		{[]byte{0x16, 0x03, 0x04, 0x00, 0x2f}, true},  // TLS 1.3
		{[]byte{0x16, 0x00, 0x03, 0x00, 0x2f}, false}, // 非 TLS（0x16 开头）
		{[]byte{0x16, 0x03, 0x05, 0x00, 0x2f}, false}, // 未知次版本
		{[]byte{0x17, 0x03, 0x03, 0x00, 0x2f}, false}, // application_data
	}
	for _, c := range cases {
		if got := isTLSRecordHead(c.in); got != c.want {
			t.Errorf("isTLSRecordHead(% x) = %v, want %v", c.in, got, c.want)
		}
	}
}
