package minecraft

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"time"

	"tcp-protocol-gateway/internal/config"
)

// DefaultLoginKickMessage 是 Login 被拒绝时下发给客户端的提示。
const DefaultLoginKickMessage = "This server is a protocol gateway and does not accept Minecraft logins."

// MaxStatusPacketLen 是 Status 阶段允许的最大入站包长度。
// Status Request 是空包（长度 2），Ping 固定 10 字节，
// 设为 512 已有充足余量，足以拦截恶意构造的超长包。
const MaxStatusPacketLen = 512

// Handler 在已识别的 Minecraft 连接上运行 SLP 最小状态机。
type Handler struct {
	cfg    *config.MinecraftConfig
	idle   time.Duration
	logger *slog.Logger
}

// NewHandler 创建 Minecraft 协议处理器。
func NewHandler(cfg *config.MinecraftConfig, idleTimeout time.Duration, logger *slog.Logger) *Handler {
	if logger == nil {
		logger = slog.Default()
	}
	return &Handler{cfg: cfg, idle: idleTimeout, logger: logger}
}

// Serve 处理一次完整的 Minecraft 会话。
// handshake 已由协议嗅探阶段解析完成；同一 bufio.Reader 继续使用，
// 保证已缓冲字节不被丢失或重复消费。
//
// Status 流程: Status Request -> Status Response -> Ping -> Pong。
// Login 流程:  Login Start    -> Disconnect -> 关闭连接。
func (h *Handler) Serve(conn net.Conn, br *bufio.Reader, hs *Handshake) error {
	defer func() {
		if err := conn.Close(); err != nil {
			h.logger.Debug("minecraft: close conn", "error", err)
		}
	}()

	if err := conn.SetDeadline(time.Now().Add(h.idle)); err != nil {
		return fmt.Errorf("set deadline: %w", err)
	}

	switch hs.NextState {
	case NextStateStatus:
		return h.serveStatus(conn, br)
	case NextStateLogin:
		return h.serveLogin(conn, br, hs)
	default:
		// 嗅探阶段已保证 NextState 只会是 1 或 2，这里是纵深防御。
		return fmt.Errorf("invalid next state %d", hs.NextState)
	}
}

// serveStatus 处理 Status Request 与 Ping/Pong。
func (h *Handler) serveStatus(conn net.Conn, br *bufio.Reader) error {
	// 1. Status Request: Packet ID 0x00，空载荷。
	id, payload, err := ReadPacket(br, MaxStatusPacketLen)
	if err != nil {
		return fmt.Errorf("read status request: %w", err)
	}
	if id != PacketIDStatusRequest {
		return fmt.Errorf("%w: status expects id 0x00, got 0x%02x", ErrBadPacketID, id)
	}
	if len(payload) != 0 {
		return fmt.Errorf("status request carries %d unexpected bytes", len(payload))
	}

	// 2. Status Response: Packet ID 0x00 + String(JSON)。
	status := NewStatus(h.cfg.VersionName, h.cfg.ProtocolVersion,
		h.cfg.MOTD, h.cfg.MaxPlayers, h.cfg.OnlinePlayers)
	body, err := status.JSON()
	if err != nil {
		return fmt.Errorf("build status json: %w", err)
	}
	if err := WriteStringPacket(conn, PacketIDStatusResponse, body); err != nil {
		return fmt.Errorf("write status response: %w", err)
	}
	h.logger.Debug("minecraft: status response sent", "bytes", len(body))

	// 3. Ping Request: Packet ID 0x01 + 8 字节载荷。
	//    客户端发出 Ping 后不再发送任何数据，若直接整包读取会在
	//    部分客户端实现上一直阻塞到超时；这里按字段解析。
	id, err = ReadPacketID(br, MaxStatusPacketLen)
	if err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			// 客户端拿到状态后直接关闭是合法行为。
			h.logger.Debug("minecraft: client closed before ping")
			return nil
		}
		return fmt.Errorf("read ping packet id: %w", err)
	}
	if id != PacketIDPingRequest {
		return fmt.Errorf("%w: ping expects id 0x01, got 0x%02x", ErrBadPacketID, id)
	}
	pongPayload, err := readPingPayload(br)
	if err != nil {
		return fmt.Errorf("read ping payload: %w", err)
	}

	// 4. Pong Response: Packet ID 0x01 + 原样返回的 8 字节载荷。
	if err := WritePacket(conn, PacketIDPongResponse, pongPayload); err != nil {
		return fmt.Errorf("write pong response: %w", err)
	}
	h.logger.Debug("minecraft: pong response sent")

	return nil
}

// readPingPayload 读取 Ping 包剩余的 8 字节时间戳载荷。
// 前置条件: 包 ID 已消费，包长度前缀已被 peek 方式读取，
// 因此这里读到的 8 字节就是完整载荷。
func readPingPayload(br *bufio.Reader) ([]byte, error) {
	payload := make([]byte, 8)
	if _, err := io.ReadFull(br, payload); err != nil {
		return nil, err
	}
	return payload, nil
}

// ReadPacketID 读取包长度前缀与 Packet ID，返回 Packet ID。
// 与 ReadPacket 不同，它不把整个包体读出来，适合"已知包体很小、
// 但希望按字段流式解析"的场景。
func ReadPacketID(r *bufio.Reader, maxLen int) (int32, error) {
	length, err := ReadVarInt(r)
	if err != nil {
		return 0, fmt.Errorf("read packet length: %w", err)
	}
	if length <= 0 || int(length) > maxLen {
		return 0, ErrPacketTooLarge
	}
	id, err := ReadVarInt(r)
	if err != nil {
		return 0, fmt.Errorf("read packet id: %w", err)
	}
	return id, nil
}

// serveLogin 处理 Login 阶段: 读取 Login Start 后发送 Disconnect。
func (h *Handler) serveLogin(conn net.Conn, br *bufio.Reader, hs *Handshake) error {
	// Login Start: Packet ID 0x00 + String 用户名。
	// 用户名最长 16 字符，包上限取 256 已足够。
	const maxLoginPacketLen = 256
	id, payload, err := ReadPacket(br, maxLoginPacketLen)
	if err != nil {
		return fmt.Errorf("read login start: %w", err)
	}
	if id != PacketIDLoginStart {
		return fmt.Errorf("%w: login expects id 0x00, got 0x%02x", ErrBadPacketID, id)
	}

	lbr := &byteReader{buf: payload}
	username, err := ReadString(lbr, 16)
	if err != nil {
		// 部分版本 Login Start 的字段顺序不同，这里尽力解析即可，
		// 解析失败不影响拒绝连接的正确性。
		h.logger.Debug("minecraft: parse login start fields", "error", err)
		username = "<unknown>"
	}

	reason := DisconnectReason(DefaultLoginKickMessage)
	if err := WriteStringPacket(conn, PacketIDLoginDisconnect, reason); err != nil {
		return fmt.Errorf("write login disconnect: %w", err)
	}
	h.logger.Info("minecraft: login rejected",
		"remote", conn.RemoteAddr().String(),
		"username", username,
		"protocol", hs.ProtocolVersion)
	return nil
}

// WriteStringPacket 写入一个载荷为单个协议 String 的数据包
// （Disconnect 消息即此格式）。
func WriteStringPacket(w io.Writer, packetID int32, s string) error {
	if len(s) > MaxStringLength {
		return fmt.Errorf("string length %d exceeds protocol limit %d", len(s), MaxStringLength)
	}
	payload := make([]byte, 2+len(s))
	payload[0] = byte(len(s) >> 8)
	payload[1] = byte(len(s))
	copy(payload[2:], s)
	return WritePacket(w, packetID, payload)
}
