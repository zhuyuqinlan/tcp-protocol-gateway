package relay

import (
	"net"
	"strings"
	"testing"
	"time"
)

// TestUDPRelaySessionReuseAndIdleExpiry 验证：
// 同一客户端地址的数据报复用会话；会话空闲后被回收，
// 且回收后再次发包能建立新会话继续转发。
func TestUDPRelaySessionReuseAndIdleExpiry(t *testing.T) {
	backend, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("backend listen: %v", err)
	}
	defer backend.Close()

	// 后端回显：resp = "echo:" + payload。
	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, err := backend.ReadFrom(buf)
			if err != nil {
				return
			}
			resp := append([]byte("echo:"), buf[:n]...)
			_, _ = backend.WriteTo(resp, addr)
		}
	}()

	// 中继监听端口。
	tmp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("alloc port: %v", err)
	}
	listenAddr := tmp.LocalAddr().String()
	_ = tmp.Close()

	r := New(listenAddr, backend.LocalAddr().String(), 200*time.Millisecond, nil)
	done := make(chan error, 1)
	go func() { done <- r.Run() }()
	// 等待中继完成 socket 绑定，避免首个数据报发往未监听端口被丢弃。
	time.Sleep(100 * time.Millisecond)
	defer func() {
		r.Stop()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("relay run: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Error("relay did not stop in time")
		}
	}()

	client, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("client listen: %v", err)
	}
	defer client.Close()
	_ = client.SetReadDeadline(time.Now().Add(3 * time.Second))

	// 发送两个数据报，均应得到回显（会话复用）。
	for i := 0; i < 2; i++ {
		msg := []byte{byte(i), 0xAA}
		if _, err := client.WriteTo(msg, mustAddr(t, listenAddr)); err != nil {
			t.Fatalf("write datagram %d: %v", i, err)
		}
		buf := make([]byte, 2048)
		n, _, err := client.ReadFrom(buf)
		if err != nil {
			t.Fatalf("read echo %d: %v", i, err)
		}
		want := append([]byte("echo:"), msg...)
		if string(buf[:n]) != string(want) {
			t.Fatalf("echo %d = %q, want %q", i, buf[:n], want)
		}
	}

	// 空闲超过会话回收时间后再次发包：应建立新会话并继续转发。
	time.Sleep(400 * time.Millisecond)
	msg := []byte{0x09}
	if _, err := client.WriteTo(msg, mustAddr(t, listenAddr)); err != nil {
		t.Fatalf("write after idle: %v", err)
	}
	buf := make([]byte, 2048)
	n, _, err := client.ReadFrom(buf)
	if err != nil {
		t.Fatalf("read echo after idle: %v", err)
	}
	if !strings.HasPrefix(string(buf[:n]), "echo:") {
		t.Fatalf("echo after idle = %q", buf[:n])
	}
}

func mustAddr(t *testing.T, addr string) net.Addr {
	t.Helper()
	a, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		t.Fatalf("resolve %s: %v", addr, err)
	}
	return a
}
