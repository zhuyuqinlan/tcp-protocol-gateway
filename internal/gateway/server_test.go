package gateway

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"tcp-protocol-gateway/internal/config"
	"tcp-protocol-gateway/internal/minecraft"
)

// testConfig 构造监听在随机端口的测试配置。
func testConfig(t *testing.T) *config.Config {
	t.Helper()
	cfg := config.Defaults()
	cfg.Server.Listen = "127.0.0.1:0"
	cfg.Server.HandshakeTimeout = 500 * time.Millisecond
	cfg.Server.IdleTimeout = 2 * time.Second
	cfg.HTTP.Backend = "127.0.0.1:1" // 由各测试按需覆盖
	return cfg
}

// silentLogger 返回丢弃全部输出的 logger，避免测试噪音。
// 设置 GATEWAY_TEST_LOG=1 时输出 debug 日志用于排查。
func silentLogger() *slog.Logger {
	if os.Getenv("GATEWAY_TEST_LOG") != "" {
		return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	}
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// startGateway 启动网关并返回其地址与优雅关闭函数。
func startGateway(t *testing.T, cfg *config.Config) (string, func() error) {
	t.Helper()
	srv, err := New(cfg, silentLogger())
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	done := make(chan error, 1)
	go func() { done <- srv.ListenAndServe() }()

	// 等待监听就绪（Listen 地址为 127.0.0.1:0，需要拿到实际端口）。
	addr := cfg.Server.Listen
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if srv.listener != nil {
			addr = srv.listener.Addr().String()
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if addr == cfg.Server.Listen {
		t.Fatal("listener not ready in time")
	}

	var once sync.Once
	var shutdownErr error
	shutdown := func() error {
		once.Do(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			shutdownErr = srv.Shutdown(ctx)
			if listenErr := <-done; listenErr != nil && listenErr != ErrServerClosed {
				shutdownErr = listenErr
			}
		})
		return shutdownErr
	}
	t.Cleanup(func() { _ = shutdown() })
	return addr, shutdown
}

func TestGatewayHTTPGetForwarded(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("backend-ok"))
	}))
	defer backend.Close()

	cfg := testConfig(t)
	cfg.HTTP.Backend = backend.Listener.Addr().String()
	addr, _ := startGateway(t, cfg)

	resp, err := http.Get("http://" + addr + "/test")
	if err != nil {
		t.Fatalf("GET through gateway: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "backend-ok" {
		t.Fatalf("body = %q, want backend-ok", body)
	}
}

func TestGatewayHTTPPostForwarded(t *testing.T) {
	var gotBody string
	var gotMethod string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.WriteHeader(http.StatusCreated)
	}))
	defer backend.Close()

	cfg := testConfig(t)
	cfg.HTTP.Backend = backend.Listener.Addr().String()
	addr, _ := startGateway(t, cfg)

	resp, err := http.Post("http://"+addr+"/submit",
		"application/json", strings.NewReader(`{"key":"value"}`))
	if err != nil {
		t.Fatalf("POST through gateway: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d, want 201", resp.StatusCode)
	}
	if gotMethod != "POST" {
		t.Errorf("method = %q", gotMethod)
	}
	if gotBody != `{"key":"value"}` {
		t.Errorf("body = %q", gotBody)
	}
}

func TestGatewayHTTPFragmentedHeader(t *testing.T) {
	// 请求头拆成多个 TCP 分片逐段发送，网关必须正确重组转发。
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("frag-ok"))
	}))
	defer backend.Close()

	cfg := testConfig(t)
	cfg.HTTP.Backend = backend.Listener.Addr().String()
	addr, _ := startGateway(t, cfg)

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial gateway: %v", err)
	}
	defer conn.Close()

	req := "GET /fragmented HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n"
	go func() {
		for i := 0; i < len(req); i += 2 {
			end := i + 2
			if end > len(req) {
				end = len(req)
			}
			_, _ = conn.Write([]byte(req[i:end]))
			time.Sleep(10 * time.Millisecond)
		}
	}()

	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	raw, err := io.ReadAll(conn)
	if err != nil && err != io.EOF {
		t.Fatalf("read: %v", err)
	}
	if !strings.Contains(string(raw), "frag-ok") {
		t.Fatalf("response = %q", raw)
	}
}

func TestGatewayHTTPBodyIntegrity(t *testing.T) {
	// 通过网关上传 512 KiB 请求体，后端逐字节校验。
	const size = 512 << 10
	body := make([]byte, size)
	for i := range body {
		body[i] = byte(i)
	}

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, _ := io.ReadAll(r.Body)
		if len(got) != size {
			t.Errorf("received %d bytes, want %d", len(got), size)
			return
		}
		for i := range got {
			if got[i] != byte(i) {
				t.Errorf("byte %d mismatch", i)
				break
			}
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	cfg := testConfig(t)
	cfg.HTTP.Backend = backend.Listener.Addr().String()
	addr, _ := startGateway(t, cfg)

	req, _ := http.NewRequest(http.MethodPut, "http://"+addr+"/upload", strings.NewReader(""))
	req.ContentLength = size
	req.Body = io.NopCloser(bufioReader(body))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("PUT through gateway: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
}

// bufioReader 把 []byte 包装成 io.Reader。
func bufioReader(b []byte) *byteSliceReader { return &byteSliceReader{b: b} }

type byteSliceReader struct {
	b []byte
	i int
}

func (r *byteSliceReader) Read(p []byte) (int, error) {
	if r.i >= len(r.b) {
		return 0, io.EOF
	}
	n := copy(p, r.b[r.i:])
	r.i += n
	return n, nil
}

func TestGatewayMinecraftStatusAndPing(t *testing.T) {
	cfg := testConfig(t)
	addr, _ := startGateway(t, cfg)

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	// Handshake (next state = status)。
	writeHandshake(t, conn, 763, "mc.example.com", 25565, minecraft.NextStateStatus)
	// Status Request。
	if err := minecraft.WritePacket(conn, minecraft.PacketIDStatusRequest, nil); err != nil {
		t.Fatalf("write status request: %v", err)
	}

	// Status Response。
	id, payload, err := minecraft.ReadPacket(bufio.NewReader(conn), 65536)
	if err != nil {
		t.Fatalf("read status response: %v", err)
	}
	if id != minecraft.PacketIDStatusResponse {
		t.Fatalf("packet id = %d", id)
	}
	br := newByteReader(payload)
	statusStr, err := minecraft.ReadString(br, 32767)
	if err != nil {
		t.Fatalf("read status string: %v", err)
	}
	var status struct {
		Version struct {
			Name     string `json:"name"`
			Protocol int32  `json:"protocol"`
		} `json:"version"`
		Players struct {
			Max    int `json:"max"`
			Online int `json:"online"`
		} `json:"players"`
		Description struct {
			Text string `json:"text"`
		} `json:"description"`
	}
	if err := json.Unmarshal([]byte(statusStr), &status); err != nil {
		t.Fatalf("status json invalid: %v (%s)", err, statusStr)
	}
	if status.Version.Protocol != 763 || status.Version.Name != "1.20.1" {
		t.Errorf("version = %+v", status.Version)
	}
	if status.Players.Max != 100 || status.Players.Online != 0 {
		t.Errorf("players = %+v", status.Players)
	}
	if status.Description.Text != "Go TCP Protocol Gateway" {
		t.Errorf("motd = %q", status.Description.Text)
	}

	// Ping。
	pongPayload := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	if err := minecraft.WritePacket(conn, minecraft.PacketIDPingRequest, pongPayload); err != nil {
		t.Fatalf("write ping: %v", err)
	}
	id, payload, err = minecraft.ReadPacket(bufio.NewReader(conn), 65536)
	if err != nil {
		t.Fatalf("read pong: %v", err)
	}
	if id != minecraft.PacketIDPongResponse {
		t.Fatalf("pong packet id = %d, want 1", id)
	}
	if string(payload) != string(pongPayload) {
		t.Fatalf("pong payload = %x, want %x", payload, pongPayload)
	}
}

func TestGatewayMinecraftLoginRejected(t *testing.T) {
	cfg := testConfig(t)
	addr, _ := startGateway(t, cfg)

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	writeHandshake(t, conn, 763, "mc.example.com", 25565, minecraft.NextStateLogin)
	// Login Start：用户名 "Tester"。
	username := "Tester"
	var payload []byte
	payload = append(payload, byte(len(username)>>8), byte(len(username)))
	payload = append(payload, username...)
	if err := minecraft.WritePacket(conn, minecraft.PacketIDLoginStart, payload); err != nil {
		t.Fatalf("write login start: %v", err)
	}

	id, resp, err := minecraft.ReadPacket(bufio.NewReader(conn), 65536)
	if err != nil {
		t.Fatalf("read disconnect: %v", err)
	}
	if id != minecraft.PacketIDLoginDisconnect {
		t.Fatalf("packet id = %d, want 0", id)
	}
	reason, err := minecraft.ReadString(newByteReader(resp), 32767)
	if err != nil {
		t.Fatalf("read disconnect reason: %v", err)
	}
	var msg struct {
		Text string `json:"text"`
	}
	if err := json.Unmarshal([]byte(reason), &msg); err != nil {
		t.Fatalf("disconnect reason invalid json: %v (%s)", err, reason)
	}
	if msg.Text == "" {
		t.Error("disconnect text must not be empty")
	}
}

func TestGatewayMinecraftDisabled(t *testing.T) {
	cfg := testConfig(t)
	cfg.Minecraft.Enabled = false
	addr, _ := startGateway(t, cfg)

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))

	writeHandshake(t, conn, 763, "mc", 25565, minecraft.NextStateStatus)

	// 网关应直接关闭连接：读取返回 EOF。
	_, _, err = minecraft.ReadPacket(bufio.NewReader(conn), 65536)
	if err == nil {
		t.Fatal("expected connection close when minecraft disabled")
	}
}

func TestGatewayUnknownProtocolClosed(t *testing.T) {
	cfg := testConfig(t)
	addr, _ := startGateway(t, cfg)

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))

	// 发送无法识别的数据。
	if _, err := conn.Write([]byte{0x00, 0x01, 0x02}); err != nil {
		t.Fatalf("write: %v", err)
	}
	// 网关应关闭连接（读返回 EOF）。
	buf := make([]byte, 16)
	if _, err := conn.Read(buf); err == nil {
		t.Fatal("expected connection to be closed for unknown protocol")
	}
}

func TestGatewaySlowClientTimeout(t *testing.T) {
	// 连接后不发送任何数据：应在握手期限内被关闭。
	cfg := testConfig(t)
	cfg.Server.HandshakeTimeout = 300 * time.Millisecond
	addr, _ := startGateway(t, cfg)

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	start := time.Now()
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 16)
	_, err = conn.Read(buf)
	if err == nil {
		t.Fatal("expected timeout close")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("connection closed after %v, want ~300ms", elapsed)
	}
}

func TestGatewayTLSRejected(t *testing.T) {
	cfg := testConfig(t)
	addr, _ := startGateway(t, cfg)

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))

	// TLS ClientHello 首字节。
	if _, err := conn.Write([]byte{0x16, 0x03, 0x01, 0x00, 0x50}); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 16)
	if _, err := conn.Read(buf); err == nil {
		t.Fatal("expected TLS connection to be rejected")
	}
}

func TestGatewayBackendDown502(t *testing.T) {
	cfg := testConfig(t)
	cfg.HTTP.Backend = "127.0.0.1:1" // 不可达
	addr, _ := startGateway(t, cfg)

	resp, err := http.Get("http://" + addr + "/x")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", resp.StatusCode)
	}
}

func TestGatewayHighConcurrencyAndGracefulShutdown(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer backend.Close()

	cfg := testConfig(t)
	cfg.HTTP.Backend = backend.Listener.Addr().String()
	cfg.Server.MaxConnections = 200
	addr, shutdown := startGateway(t, cfg)

	var okCount int64
	var wg sync.WaitGroup
	errCh := make(chan error, 100)
	// 禁用 keep-alive：请求结束后连接立即关闭，
	// 使 Shutdown 走"全部连接排空"的路径。
	client := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}}
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := client.Get("http://" + addr + "/concurrent")
			if err != nil {
				errCh <- err
				return
			}
			defer resp.Body.Close()
			b, _ := io.ReadAll(resp.Body)
			if string(b) == "ok" {
				atomic.AddInt64(&okCount, 1)
			}
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Errorf("concurrent request failed: %v", err)
	}
	if okCount != 100 {
		t.Fatalf("ok responses = %d, want 100", okCount)
	}

	// 优雅退出：所有连接处理完毕后 Shutdown 正常返回。
	if err := shutdown(); err != nil {
		t.Fatalf("graceful shutdown failed: %v", err)
	}
}

// --- 测试辅助 ---

func writeHandshake(t *testing.T, w io.Writer, protocol int32, address string, port uint16, nextState int32) {
	t.Helper()
	body := minecraft.EncodeVarInt(minecraft.PacketIDHandshake)
	body = append(body, minecraft.EncodeVarInt(protocol)...)
	body = append(body, byte(len(address)>>8), byte(len(address)))
	body = append(body, address...)
	body = append(body, byte(port>>8), byte(port))
	body = append(body, minecraft.EncodeVarInt(nextState)...)
	if err := minecraft.WritePacket(w, minecraft.PacketIDHandshake, body[1:]); err != nil {
		t.Fatalf("write handshake: %v", err)
	}
}

type byteReader struct {
	buf []byte
	pos int
}

func newByteReader(b []byte) *byteReader { return &byteReader{buf: b} }

func (b *byteReader) ReadByte() (byte, error) {
	if b.pos >= len(b.buf) {
		return 0, io.EOF
	}
	c := b.buf[b.pos]
	b.pos++
	return c, nil
}

func (b *byteReader) Read(p []byte) (int, error) {
	if b.pos >= len(b.buf) {
		return 0, io.EOF
	}
	n := copy(p, b.buf[b.pos:])
	b.pos += n
	return n, nil
}
