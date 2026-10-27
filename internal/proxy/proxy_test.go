package proxy

import (
	"bufio"
	"bytes"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// tcpPair 建立一对真实 TCP 连接（支持半关闭语义）。
func tcpPair(t *testing.T) (client, server net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	type result struct {
		conn net.Conn
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		c, err := ln.Accept()
		ch <- result{c, err}
	}()

	client, err = net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	select {
	case r := <-ch:
		if r.err != nil {
			t.Fatalf("accept: %v", r.err)
		}
		server = r.conn
		t.Cleanup(func() { _ = server.Close() })
		return client, server
	case <-time.After(2 * time.Second):
		t.Fatal("accept timed out")
		return nil, nil
	}
}

// sniffedReader 模拟嗅探完成后的状态：sniffed 字节由客户端发出，
// 已在服务端 bufio 缓冲区中 Peek 过但仍未消费，等待代理冲刷。
func sniffedReader(t *testing.T, client, server net.Conn, sniffed []byte) *bufio.Reader {
	t.Helper()
	br := bufio.NewReaderSize(server, 4096)
	if len(sniffed) == 0 {
		return br
	}
	if _, err := client.Write(sniffed); err != nil {
		t.Fatalf("write sniffed: %v", err)
	}
	if _, err := br.Peek(len(sniffed)); err != nil {
		t.Fatalf("peek sniffed: %v", err)
	}
	return br
}

func TestProxyEndToEndHTTP(t *testing.T) {
	var gotPath, gotBody, gotHeader string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotHeader = r.Header.Get("X-Gateway-Test")
		body := make([]byte, r.ContentLength)
		_, _ = io.ReadFull(r.Body, body)
		gotBody = string(body)
		_, _ = w.Write([]byte("response-body"))
	}))
	defer backend.Close()

	p := New(2*time.Second, slog.Default())
	client, server := tcpPair(t)

	br := sniffedReader(t, client, server, nil)
	go func() { _ = p.Handle(server, br, &Match{Backend: backend.Listener.Addr().String()}) }()

	// POST 请求，含请求体，验证方法/路径/头/体都原样到达后端。
	// 使用 HTTP/1.0 让后端响应后主动关闭连接，读取到 EOF 即完成。
	req := "POST /api/submit HTTP/1.0\r\n" +
		"Host: gw.test\r\n" +
		"X-Gateway-Test: yes\r\n" +
		"Content-Type: text/plain\r\n" +
		"Content-Length: 11\r\n" +
		"\r\n" +
		"hello-world"
	if _, err := client.Write([]byte(req)); err != nil {
		t.Fatalf("write request: %v", err)
	}

	_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := io.ReadAll(client)
	if err != nil && err != io.EOF {
		t.Fatalf("read response: %v", err)
	}
	if !strings.Contains(string(resp), "response-body") {
		t.Fatalf("response missing body, got %q", resp)
	}
	if gotPath != "/api/submit" {
		t.Fatalf("backend got path %q, want /api/submit", gotPath)
	}
	if gotHeader != "yes" {
		t.Fatalf("backend missing header, got %q", gotHeader)
	}
	if gotBody != "hello-world" {
		t.Fatalf("backend got body %q, want hello-world", gotBody)
	}
}

func TestProxyGetRequest(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("hello from backend"))
	}))
	defer backend.Close()

	p := New(2*time.Second, slog.Default())
	client, server := tcpPair(t)
	br := sniffedReader(t, client, server, []byte("GET /sn"))

	// 已嗅探的 "GET /sn" 在缓冲区中，其余部分随后发送。
	go func() {
		_ = p.Handle(server, br, &Match{Backend: backend.Listener.Addr().String()})
		_ = server.Close()
	}()

	go func() {
		time.Sleep(20 * time.Millisecond)
		_, _ = client.Write([]byte("iffed HTTP/1.0\r\n\r\n"))
	}()

	_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := io.ReadAll(client)
	if err != nil && err != io.EOF {
		t.Fatalf("read: %v", err)
	}
	if !strings.Contains(string(resp), "hello from backend") {
		t.Fatalf("unexpected response %q", resp)
	}
}

func TestProxyRequestBodyIntegrity(t *testing.T) {
	// 1 MiB 请求体完整性：逐字节校验。
	const size = 1 << 20
	body := make([]byte, size)
	for i := range body {
		body[i] = byte(i)
	}

	received := make(chan int, 1)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, _ := io.ReadAll(r.Body)
		received <- len(got)
		for i := range got {
			if got[i] != byte(i) {
				t.Errorf("body mismatch at byte %d", i)
				break
			}
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	p := New(2*time.Second, slog.Default())
	client, server := tcpPair(t)
	go func() {
		_ = p.Handle(server, sniffedReader(t, client, server, nil), &Match{Backend: backend.Listener.Addr().String()})
	}()

	go func() {
		_, _ = client.Write([]byte("POST /upload HTTP/1.1\r\nHost: x\r\nContent-Length: " +
			strconv.Itoa(size) + "\r\n\r\n"))
		_, _ = client.Write(body)
	}()

	_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 4096)
	var resp []byte
	for {
		n, err := client.Read(buf)
		resp = append(resp, buf[:n]...)
		if err != nil || strings.Contains(string(resp), "200 OK") {
			break
		}
	}
	select {
	case n := <-received:
		if n != size {
			t.Fatalf("backend received %d bytes, want %d", n, size)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for backend")
	}
}

func TestProxySniffedBytesForwardedInOrder(t *testing.T) {
	// 嗅探缓冲字节与后续字节必须按原始顺序拼接到达后端。
	pathCh := make(chan string, 1)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pathCh <- r.URL.Path
	}))
	defer backend.Close()

	p := New(2*time.Second, slog.Default())
	client, server := tcpPair(t)

	// 缓冲区中已有 "GET /sn"，其余 "iffed HTTP/1.0\r\n\r\n" 稍后到达。
	br := sniffedReader(t, client, server, []byte("GET /sn"))
	go func() { _ = p.Handle(server, br, &Match{Backend: backend.Listener.Addr().String()}) }()

	go func() {
		time.Sleep(20 * time.Millisecond)
		_, _ = client.Write([]byte("iffed HTTP/1.0\r\n\r\n"))
	}()

	select {
	case path := <-pathCh:
		if path != "/sniffed" {
			t.Fatalf("backend got path %q, want /sniffed (order broken?)", path)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for backend request")
	}
}

func TestProxyBackendUnavailable502(t *testing.T) {
	// 端口 1 (tcpmux) 在测试环境几乎必然拒绝连接。
	p := New(500*time.Millisecond, slog.Default())
	client, server := tcpPair(t)

	done := make(chan error, 1)
	go func() {
		done <- p.Handle(server, sniffedReader(t, client, server, nil), &Match{Backend: "127.0.0.1:1"})
	}()

	_, err := client.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = client.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 512)
	n, err := client.Read(buf)
	if err != nil {
		t.Fatalf("read 502: %v", err)
	}
	resp := string(buf[:n])
	if !strings.HasPrefix(resp, "HTTP/1.1 502") {
		t.Fatalf("want 502 response, got %q", resp)
	}
	if err := <-done; err == nil {
		t.Fatal("expected BackendUnreachable error")
	}
}

func TestRouterLongestPrefixMatch(t *testing.T) {
	router, err := NewRouter([]Route{
		{Prefix: "/api", Backend: "backend-a:1"},
		{Prefix: "/api/v1", Backend: "backend-b:2"},
		{Prefix: "/web", Backend: "backend-c:3"},
		{Prefix: "/api/v12", Backend: "backend-d:4"},
	})
	if err != nil {
		t.Fatalf("NewRouter: %v", err)
	}

	cases := []struct {
		requestLine string
		wantBackend string
	}{
		{"GET /api/users HTTP/1.1", "backend-a:1"},
		{"GET /api/v1/items HTTP/1.1", "backend-b:2"}, // 最长前缀优先
		{"GET /api/v12/x HTTP/1.1", "backend-d:4"},    // 多前缀同源，长优先
		{"GET /web/index.html HTTP/1.1", "backend-c:3"},
		{"GET /api?q=1 HTTP/1.1", "backend-a:1"}, // 含查询串
		{"POST /other HTTP/1.1", ""},             // 未匹配
		// "/apiweb" 字面上以 "/api" 开头：按纯前缀语义命中 /api。
		// 这是刻意记录的行为——如需路径段边界匹配应在配置时规避。
		{"GET /apiweb HTTP/1.1", "backend-a:1"},
	}

	for _, c := range cases {
		br := bufio.NewReader(bytes.NewReader([]byte(c.requestLine + "\r\nHost: x\r\n\r\n")))
		got, err := router.Match(br)
		if err != nil {
			t.Fatalf("Match(%q): %v", c.requestLine, err)
		}
		if c.wantBackend == "" && got != nil {
			t.Errorf("Match(%q) = %+v, want nil", c.requestLine, got)
		}
		if c.wantBackend != "" && (got == nil || got.Backend != c.wantBackend) {
			t.Errorf("Match(%q) = %+v, want backend %q", c.requestLine, got, c.wantBackend)
		}
	}
}

func TestRouterNoMatch(t *testing.T) {
	router, err := NewRouter([]Route{
		{Prefix: "/api", Backend: "backend-a:1"},
	})
	if err != nil {
		t.Fatalf("NewRouter: %v", err)
	}
	// 请求行不完整（无换行）→ 请求行错误。
	br := bufio.NewReader(bytes.NewReader([]byte("GET /x HTTP/1.1")))
	if _, err := router.Match(br); err == nil {
		t.Fatal("expected error for incomplete request line")
	}
	// 空路由表 → 永远未命中。
	empty, err := NewRouter(nil)
	if err != nil {
		t.Fatalf("NewRouter(nil): %v", err)
	}
	br = bufio.NewReader(bytes.NewReader([]byte("GET / HTTP/1.1\r\n\r\n")))
	got, err := empty.Match(br)
	if err != nil || got != nil {
		t.Fatalf("empty router Match = %+v, %v", got, err)
	}
	// 非法前缀。
	if _, err := NewRouter([]Route{
		{Prefix: "api", Backend: "b:1"},
	}); err == nil {
		t.Fatal("expected error for prefix without leading slash")
	}
}

func TestRewriteRequestLine(t *testing.T) {
	cases := []struct {
		name  string
		line  string
		strip string
		want  string
		ok    bool
	}{
		{"normal", "GET /api/users HTTP/1.1\r\n", "/api", "GET /users HTTP/1.1\r\n", true},
		{"query preserved", "GET /api/search?q=1&x=2 HTTP/1.1\r\n", "/api", "GET /search?q=1&x=2 HTTP/1.1\r\n", true},
		{"empty path becomes slash", "POST /api HTTP/1.0\r\n", "/api", "POST / HTTP/1.0\r\n", true},
		{"non-boundary gets slash", "GET /apiweb HTTP/1.1\r\n", "/api", "GET /web HTTP/1.1\r\n", true},
		{"root prefix", "GET /users HTTP/1.1\r\n", "/", "GET /users HTTP/1.1\r\n", true},
		{"deep prefix", "GET /api/v1/items HTTP/1.1\r\n", "/api/v1", "GET /items HTTP/1.1\r\n", true},
		{"prefix missing passthrough", "GET /other HTTP/1.1\r\n", "/api", "", false},
		{"malformed line", "GARBAGE\r\n", "/api", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := rewriteRequestLine([]byte(c.line), c.strip)
			if ok != c.ok {
				t.Fatalf("ok = %v, want %v (got %q)", ok, c.ok, got)
			}
			if ok && string(got) != c.want {
				t.Fatalf("rewritten = %q, want %q", got, c.want)
			}
		})
	}
}

func TestProxyStripPrefixForward(t *testing.T) {
	var gotPath, gotRaw string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotRaw = r.URL.RawQuery
		_, _ = w.Write([]byte("strip-ok"))
	}))
	defer backend.Close()

	p := New(2*time.Second, slog.Default())

	t.Run("prefix stripped", func(t *testing.T) {
		client, server := tcpPair(t)
		br := sniffedReader(t, client, server, []byte("GET /api/us"))
		go func() { _ = p.Handle(server, br, &Match{Backend: backend.Listener.Addr().String(), Strip: "/api"}) }()
		// "ers HTTP/1.0\r\n\r\n" 分片稍后到达，验证拼接与重写共存。
		go func() {
			time.Sleep(20 * time.Millisecond)
			_, _ = client.Write([]byte("ers HTTP/1.0\r\nHost: x\r\n\r\n"))
		}()

		_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
		resp, _ := io.ReadAll(client)
		if !strings.Contains(string(resp), "strip-ok") {
			t.Fatalf("unexpected response %q", resp)
		}
		if gotPath != "/users" {
			t.Fatalf("backend got path %q, want /users (prefix not stripped?)", gotPath)
		}
	})

	t.Run("empty remainder becomes slash", func(t *testing.T) {
		client, server := tcpPair(t)
		go func() {
			_ = p.Handle(server, sniffedReader(t, client, server, nil),
				&Match{Backend: backend.Listener.Addr().String(), Strip: "/api"})
		}()
		if _, err := client.Write([]byte("GET /api HTTP/1.0\r\nHost: x\r\n\r\n")); err != nil {
			t.Fatalf("write: %v", err)
		}
		_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
		resp, _ := io.ReadAll(client)
		if !strings.Contains(string(resp), "strip-ok") || gotPath != "/" {
			t.Fatalf("backend got path %q resp %q, want / with response", gotPath, resp)
		}
	})

	t.Run("query string survives strip", func(t *testing.T) {
		client, server := tcpPair(t)
		go func() {
			_ = p.Handle(server, sniffedReader(t, client, server, nil),
				&Match{Backend: backend.Listener.Addr().String(), Strip: "/api"})
		}()
		if _, err := client.Write([]byte("GET /api/search?q=hello HTTP/1.0\r\nHost: x\r\n\r\n")); err != nil {
			t.Fatalf("write: %v", err)
		}
		_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
		resp, _ := io.ReadAll(client)
		if !strings.Contains(string(resp), "strip-ok") || gotPath != "/search" || gotRaw != "q=hello" {
			t.Fatalf("backend got path %q query %q, want /search?q=hello", gotPath, gotRaw)
		}
	})
}

func TestProxyHalfClose(t *testing.T) {
	// 客户端 CloseWrite（半关闭）后，代理必须把 FIN 传给后端，
	// 后端仍能继续响应——这是 HTTP/1.0 无 Content-Length 场景的基础。
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	backendDone := make(chan []byte, 1)
	go func() {
		bc, err := ln.Accept()
		if err != nil {
			backendDone <- nil
			return
		}
		defer bc.Close()
		buf := make([]byte, 1024)
		n, _ := io.ReadFull(bc, buf[:4]) // 读到 "PING"
		// 第二次读应收到 EOF（代理已传递客户端的半关闭）。
		_, err = bc.Read(buf)
		if err != io.EOF {
			backendDone <- nil
			return
		}
		_, _ = bc.Write([]byte("pong:" + string(buf[:n])))
		backendDone <- buf[:n]
	}()

	p := New(2*time.Second, slog.Default())
	client, server := tcpPair(t)
	go func() {
		_ = p.Handle(server, sniffedReader(t, client, server, nil), &Match{Backend: ln.Addr().String()})
	}()

	_, _ = client.Write([]byte("PING"))
	_ = client.(*net.TCPConn).CloseWrite()

	select {
	case got := <-backendDone:
		if string(got) != "PING" {
			t.Fatalf("backend got %q, want PING", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("backend never observed half close")
	}

	// 客户端应能收到后端的响应。
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 64)
	n, err := client.Read(buf)
	if err != nil {
		t.Fatalf("read pong: %v", err)
	}
	if string(buf[:n]) != "pong:PING" {
		t.Fatalf("client got %q, want pong:PING", buf[:n])
	}
}

func TestProxyWebSocketUpgradePassthrough(t *testing.T) {
	// WebSocket Upgrade 后连接变为原始双向字节流，
	// 代理的 io.Copy 双向转发天然支持：升级后互发原始终端数据。
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	go func() {
		bc, err := ln.Accept()
		if err != nil {
			return
		}
		defer bc.Close()
		buf := make([]byte, 4096)
		n, _ := bc.Read(buf) // 收到升级请求
		resp := "HTTP/1.1 101 Switching Protocols\r\n" +
			"Upgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
		_, _ = bc.Write([]byte(resp))
		_ = n
		// 升级后回显 3 条原始终端帧。
		for i := 0; i < 3; i++ {
			m, err := bc.Read(buf)
			if err != nil {
				return
			}
			_, _ = bc.Write(buf[:m])
		}
	}()

	p := New(2*time.Second, slog.Default())
	client, server := tcpPair(t)
	go func() {
		_ = p.Handle(server, sniffedReader(t, client, server, nil), &Match{Backend: ln.Addr().String()})
	}()

	req := "GET /ws HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
	if _, err := client.Write([]byte(req)); err != nil {
		t.Fatalf("write upgrade: %v", err)
	}
	_ = client.SetReadDeadline(time.Now().Add(3 * time.Second))

	// 读到 101。
	buf := make([]byte, 512)
	n, err := client.Read(buf)
	if err != nil || !strings.Contains(string(buf[:n]), "101 Switching Protocols") {
		t.Fatalf("want 101 response, got %q (err %v)", buf[:n], err)
	}

	// 升级后双向原始终端数据。
	for i := 0; i < 3; i++ {
		frame := []byte{byte(i), 0xAA}
		_, _ = client.Write(frame)
		echo := make([]byte, 2)
		if _, err := io.ReadFull(client, echo); err != nil {
			t.Fatalf("read echo frame %d: %v", i, err)
		}
		if echo[0] != byte(i) || echo[1] != 0xAA {
			t.Fatalf("frame %d echo mismatch: %x", i, echo)
		}
	}
}
