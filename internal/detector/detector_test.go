package detector

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"tcp-protocol-gateway/internal/minecraft"
)

// pair 建立 TCP 连接对，返回服务端连接（已按需设置读取期限）与客户端。
func pair(t *testing.T) (server, client net.Conn) {
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
		return server, client
	case <-time.After(2 * time.Second):
		t.Fatal("accept timed out")
		return nil, nil
	}
}

// buildHandshakeBytes 构造完整的 Minecraft 握手包字节流。
func buildHandshakeBytes(t *testing.T, protocol int32, address string, port uint16, nextState int32) []byte {
	t.Helper()
	body := minecraft.EncodeVarInt(minecraft.PacketIDHandshake)
	body = append(body, minecraft.EncodeVarInt(protocol)...)
	body = append(body, byte(len(address)>>8), byte(len(address)))
	body = append(body, address...)
	body = append(body, byte(port>>8), byte(port))
	body = append(body, minecraft.EncodeVarInt(nextState)...)

	var buf bytes.Buffer
	buf.Write(minecraft.EncodeVarInt(int32(len(body))))
	buf.Write(body)
	return buf.Bytes()
}

func TestDetectHTTPMethods(t *testing.T) {
	methods := []string{
		"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT",
	}
	for _, m := range methods {
		t.Run(m, func(t *testing.T) {
			server, client := pair(t)
			_ = server.SetDeadline(time.Now().Add(2 * time.Second))
			go func() {
				_, _ = client.Write([]byte(m + " /path HTTP/1.1\r\nHost: example.com\r\n\r\n"))
			}()
			br := bufio.NewReaderSize(server, 4096)
			res, err := Detect(br, time.Second)
			if err != nil {
				t.Fatalf("Detect: %v", err)
			}
			if res.Protocol != ProtocolHTTP {
				t.Fatalf("protocol = %v, want http", res.Protocol)
			}
		})
	}
}

func TestDetectHTTPFragmentedRequest(t *testing.T) {
	// 请求头被拆成多个 TCP 分片，嗅探必须等待补齐而不丢字节。
	server, client := pair(t)
	_ = server.SetDeadline(time.Now().Add(3 * time.Second))

	chunks := [][]byte{
		[]byte("GE"),
		[]byte("T /in"),
		[]byte("dex.html HT"),
		[]byte("TP/1.1\r"),
		[]byte("\nHost: exa"),
		[]byte("mple.com\r\n\r\n"),
	}
	go func() {
		for _, c := range chunks {
			_, _ = client.Write(c)
			time.Sleep(20 * time.Millisecond)
		}
	}()

	br := bufio.NewReaderSize(server, 4096)
	res, err := Detect(br, time.Second)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if res.Protocol != ProtocolHTTP {
		t.Fatalf("protocol = %v, want http", res.Protocol)
	}
	// 关键验证：Peek 不消费数据，已嗅探字节仍留在 bufio 缓冲区，
	// 后续由代理模块从同一 Reader 完整读取（此处验证可继续读出
	// 完整的请求行，且无丢失、无重复）。
	// 前 8 字节 "GET /ind" 是嗅探时 Peek 过但未消费的部分，
	// 仍应从 Reader 中首先读出。
	rest, err := io.ReadAll(io.LimitReader(br, 33))
	if err != nil {
		t.Fatalf("read rest: %v", err)
	}
	if string(rest) != "GET /index.html HTTP/1.1\r\nHost: e" {
		t.Fatalf("remaining stream = %q", rest)
	}
}

func TestDetectHTTPMinimalRequestLine(t *testing.T) {
	// 请求行在 Peek(8) 未凑满时也能通过部分数据识别。
	server, client := pair(t)
	_ = server.SetDeadline(time.Now().Add(2 * time.Second))
	go func() {
		// 故意先只发 5 字节（短于 8 字节窗口）。
		_, _ = client.Write([]byte("GET /"))
		time.Sleep(50 * time.Millisecond)
		_, _ = client.Write([]byte(" HTTP/1.1\r\n\r\n"))
	}()

	res, err := Detect(bufio.NewReaderSize(server, 4096), time.Second)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if res.Protocol != ProtocolHTTP {
		t.Fatalf("protocol = %v, want http", res.Protocol)
	}
}

func TestDetectMinecraftStatus(t *testing.T) {
	server, client := pair(t)
	_ = server.SetDeadline(time.Now().Add(2 * time.Second))
	raw := buildHandshakeBytes(t, 763, "mc.example.com", 25565, minecraft.NextStateStatus)
	go func() { _, _ = client.Write(raw) }()

	res, err := Detect(bufio.NewReaderSize(server, 4096), time.Second)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if res.Protocol != ProtocolMinecraft {
		t.Fatalf("protocol = %v, want minecraft", res.Protocol)
	}
	if res.Handshake == nil {
		t.Fatal("handshake must not be nil")
	}
	if res.Handshake.ProtocolVersion != 763 {
		t.Errorf("protocol version = %d, want 763", res.Handshake.ProtocolVersion)
	}
	if res.Handshake.ServerAddress != "mc.example.com" {
		t.Errorf("address = %q", res.Handshake.ServerAddress)
	}
	if res.Handshake.ServerPort != 25565 {
		t.Errorf("port = %d, want 25565", res.Handshake.ServerPort)
	}
	if res.Handshake.NextState != minecraft.NextStateStatus {
		t.Errorf("next state = %d, want status", res.Handshake.NextState)
	}
}

func TestDetectMinecraftLogin(t *testing.T) {
	server, client := pair(t)
	_ = server.SetDeadline(time.Now().Add(2 * time.Second))
	raw := buildHandshakeBytes(t, 763, "localhost", 25565, minecraft.NextStateLogin)
	go func() { _, _ = client.Write(raw) }()

	res, err := Detect(bufio.NewReaderSize(server, 4096), time.Second)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if res.Protocol != ProtocolMinecraft || res.Handshake.NextState != minecraft.NextStateLogin {
		t.Fatalf("want minecraft login, got %v", res.Protocol)
	}
}

func TestDetectMinecraftFragmented(t *testing.T) {
	// 握手包分片发送：验证 Peek 的跨分片聚合能力。
	server, client := pair(t)
	_ = server.SetDeadline(time.Now().Add(3 * time.Second))
	raw := buildHandshakeBytes(t, 763, "mc.frag.example.org", 25565, minecraft.NextStateStatus)
	go func() {
		for i := 0; i < len(raw); i += 3 {
			end := i + 3
			if end > len(raw) {
				end = len(raw)
			}
			_, _ = client.Write(raw[i:end])
			time.Sleep(10 * time.Millisecond)
		}
	}()

	res, err := Detect(bufio.NewReaderSize(server, 4096), time.Second)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if res.Protocol != ProtocolMinecraft {
		t.Fatalf("protocol = %v, want minecraft", res.Protocol)
	}
}

// TestDetectMinecraftTrickyHandshakeLength 是关键回归用例：
// 握手包长度为 71 (0x47) 时，首字节恰好是字母 'G'，
// 若嗅探只匹配 "GET " 前缀会把它误判为 HTTP。
func TestDetectMinecraftTrickyHandshakeLength(t *testing.T) {
	// 包体 = id(1) + protocol(2) + addrLen(2) + addr(N) + port(2) + state(1)
	// = 8 + N = 71 → 地址长度 63。
	addr := strings.Repeat("a", 63)
	if len(addr) != 63 {
		t.Fatalf("test setup: address length = %d, want 63", len(addr))
	}
	raw := buildHandshakeBytes(t, 763, addr, 25565, minecraft.NextStateStatus)
	if raw[0] != 71 && raw[0] != 'G' {
		t.Fatalf("test setup: first byte = 0x%02x, want 0x47 ('G')", raw[0])
	}
	server, client := pair(t)
	_ = server.SetDeadline(time.Now().Add(2 * time.Second))
	go func() { _, _ = client.Write(raw) }()

	res, err := Detect(bufio.NewReaderSize(server, 4096), time.Second)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if res.Protocol != ProtocolMinecraft {
		t.Fatalf("protocol = %v, want minecraft (misdetection as http!)", res.Protocol)
	}
}

func TestDetectTLS(t *testing.T) {
	server, client := pair(t)
	_ = server.SetDeadline(time.Now().Add(2 * time.Second))
	go func() {
		// TLS ClientHello 记录层: 0x16 0x03 0x01 ...
		_, _ = client.Write([]byte{0x16, 0x03, 0x01, 0x00, 0x50})
	}()
	res, err := Detect(bufio.NewReaderSize(server, 4096), time.Second)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if res.Protocol != ProtocolTLS {
		t.Fatalf("protocol = %v, want tls", res.Protocol)
	}
}

func TestDetectUnknownProtocol(t *testing.T) {
	payloads := [][]byte{
		{0x00, 0x01, 0x02}, // 长度 0 → 非法握手
		{0x05, 0x00, 0x00}, // 长度 5 < 7 → 非法握手
		{0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}, // 完整包但 Packet ID ≠ 0
		{0xFF, 0xFF, 0xFF, 0xFF, 0x7F},                         // VarInt 超范围
		{0xFF, 0xFF, 0x01, 0x00, 0x00},                         // 长度 32767 > 嗅探上限
	}
	for i, p := range payloads {
		server, client := pair(t)
		_ = server.SetDeadline(time.Now().Add(2 * time.Second))
		go func(pp []byte) { _, _ = client.Write(pp) }(p)

		res, err := Detect(bufio.NewReaderSize(server, 4096), time.Second)
		if err != nil {
			t.Fatalf("case %d: Detect: %v", i, err)
		}
		if res.Protocol != ProtocolUnknown {
			t.Fatalf("case %d: protocol = %v, want unknown", i, res.Protocol)
		}
	}
}

func TestDetectMinecraftInvalidHandshakeStructure(t *testing.T) {
	// 长度像握手包，但内容无法通过严格校验（NextState = 5）。
	body := minecraft.EncodeVarInt(minecraft.PacketIDHandshake)
	body = append(body, minecraft.EncodeVarInt(763)...)
	addr := "mc.example.com"
	body = append(body, byte(len(addr)>>8), byte(len(addr)))
	body = append(body, addr...)
	body = append(body, 0x63, 0xDD)
	body = append(body, minecraft.EncodeVarInt(5)...)

	var raw bytes.Buffer
	raw.Write(minecraft.EncodeVarInt(int32(len(body))))
	raw.Write(body)

	server, client := pair(t)
	_ = server.SetDeadline(time.Now().Add(2 * time.Second))
	go func() { _, _ = client.Write(raw.Bytes()) }()

	res, err := Detect(bufio.NewReaderSize(server, 4096), time.Second)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if res.Protocol != ProtocolUnknown {
		t.Fatalf("protocol = %v, want unknown", res.Protocol)
	}
}

func TestDetectTimeoutNoData(t *testing.T) {
	// 客户端不发任何数据：嗅探必须在期限内超时退出。
	server, _ := pair(t)
	_ = server.SetDeadline(time.Now().Add(100 * time.Millisecond))

	start := time.Now()
	_, err := Detect(bufio.NewReaderSize(server, 4096), time.Second)
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if !errors.Is(err, ErrDetectTimeout) {
		t.Fatalf("want ErrDetectTimeout, got %v", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("detection took %v, should have timed out promptly", elapsed)
	}
}

func TestDetectTimeoutPartialHandshake(t *testing.T) {
	// 声明了合法握手长度却永远不补齐数据：超时拒绝。
	server, client := pair(t)
	_ = server.SetDeadline(time.Now().Add(150 * time.Millisecond))
	go func() {
		// 长度 20，但只发 3 字节。
		_, _ = client.Write([]byte{20, 0x00, 0xFB})
	}()

	_, err := Detect(bufio.NewReaderSize(server, 4096), time.Second)
	if !errors.Is(err, ErrDetectTimeout) {
		t.Fatalf("want ErrDetectTimeout, got %v", err)
	}
}

func TestDetectInvalidHandshakeLengthTooLong(t *testing.T) {
	// 声明长度超过嗅探上限：直接按未知协议处理。
	server, client := pair(t)
	_ = server.SetDeadline(time.Now().Add(2 * time.Second))
	go func() {
		_, _ = client.Write([]byte{0xFF, 0xFF, 0x01, 0x00, 0x00})
	}()
	res, err := Detect(bufio.NewReaderSize(server, 4096), time.Second)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if res.Protocol != ProtocolUnknown {
		t.Fatalf("protocol = %v, want unknown", res.Protocol)
	}
}
