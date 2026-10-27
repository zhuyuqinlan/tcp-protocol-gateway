// Package relay 提供端口级转发能力。当前实现 UDP 数据报中继：
// 按客户端地址维持"客户端 <-> 后端"会话，双向转发数据报，
// 空闲超时后回收会话。
package relay

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"
)

// Relay 将一个 UDP 监听地址的数据报转发到固定后端。
// 每个客户端地址对应一条到后端的 UDP 会话（connected socket），
// 会话在 server.idle_timeout 时间内无往来数据即被回收。
type Relay struct {
	listen  string
	backend string
	idle    time.Duration
	logger  *slog.Logger

	mu       sync.Mutex
	pc       net.PacketConn
	sessions map[string]*session
	closed   bool
}

// New 创建 UDP 中继。idle 为会话空闲回收时间。
func New(listen, backend string, idle time.Duration, logger *slog.Logger) *Relay {
	if logger == nil {
		logger = slog.Default()
	}
	if idle <= 0 {
		idle = 60 * time.Second
	}
	return &Relay{
		listen:   listen,
		backend:  backend,
		idle:     idle,
		logger:   logger,
		sessions: make(map[string]*session),
	}
}

// Run 监听并转发数据报，阻塞直到 Stop 被调用或致命错误发生。
// 主动 Stop 后返回 nil。
func (r *Relay) Run() error {
	pc, err := net.ListenPacket("udp", r.listen)
	if err != nil {
		return fmt.Errorf("relay: listen udp %s: %w", r.listen, err)
	}
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		_ = pc.Close()
		return nil
	}
	r.pc = pc
	r.mu.Unlock()
	r.logger.Info("relay: udp listening", "listen", r.listen, "backend", r.backend)

	buf := make([]byte, 65535)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("relay: read from %s: %w", r.listen, err)
		}
		if n == 0 {
			continue
		}
		r.forward(addr, buf[:n])
	}
}

// Stop 停止中继并回收全部会话。可安全地多次调用。
func (r *Relay) Stop() {
	r.mu.Lock()
	r.closed = true
	pc := r.pc
	sessions := make([]*session, 0, len(r.sessions))
	for _, s := range r.sessions {
		sessions = append(sessions, s)
	}
	r.sessions = make(map[string]*session)
	r.mu.Unlock()

	if pc != nil {
		_ = pc.Close()
	}
	for _, s := range sessions {
		_ = s.upstream.Close()
	}
	if pc != nil {
		r.logger.Info("relay: udp stopped", "listen", r.listen)
	}
}

// forward 将客户端数据报写入对应会话的后端 socket，
// 会话不存在时创建。
func (r *Relay) forward(client net.Addr, data []byte) {
	s := r.session(client)
	if s == nil {
		return
	}
	_ = s.upstream.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := s.upstream.Write(data); err != nil {
		r.logger.Debug("relay: write to backend failed",
			"backend", r.backend, "client", client.String(), "error", err)
	}
}

// session 取回或创建客户端地址对应的会话；服务已关闭时返回 nil。
func (r *Relay) session(client net.Addr) *session {
	key := client.String()
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil
	}
	if s, ok := r.sessions[key]; ok {
		return s
	}
	up, err := net.Dial("udp", r.backend)
	if err != nil {
		r.logger.Warn("relay: dial udp backend failed",
			"backend", r.backend, "error", err)
		return nil
	}
	s := &session{relay: r, client: client, key: key, upstream: up}
	r.sessions[key] = s
	r.logger.Debug("relay: udp session opened",
		"client", key, "backend", r.backend)
	go s.readLoop()
	return s
}

func (r *Relay) removeSession(s *session) {
	r.mu.Lock()
	delete(r.sessions, s.key)
	r.mu.Unlock()
	_ = s.upstream.Close()
	r.logger.Debug("relay: udp session closed", "client", s.key)
}

func (r *Relay) sendToClient(client net.Addr, data []byte) {
	r.mu.Lock()
	pc := r.pc
	r.mu.Unlock()
	if pc == nil {
		return
	}
	_, _ = pc.WriteTo(data, client)
}

// session 是单个客户端地址到后端的 UDP 转发通道。
type session struct {
	relay    *Relay
	client   net.Addr
	key      string
	upstream net.Conn // connected UDP socket
}

// readLoop 从后端读取响应并回传给客户端；
// 空闲超过 idle 时间后自动回收会话。
func (s *session) readLoop() {
	buf := make([]byte, 65535)
	for {
		_ = s.upstream.SetReadDeadline(time.Now().Add(s.relay.idle))
		n, err := s.upstream.Read(buf)
		if err != nil {
			s.relay.removeSession(s)
			return
		}
		s.relay.sendToClient(s.client, buf[:n])
	}
}
