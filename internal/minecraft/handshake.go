package minecraft

import (
	"fmt"
)

// Handshake 是 Minecraft 握手包的解码结果。
type Handshake struct {
	ProtocolVersion int32
	ServerAddress   string
	ServerPort      uint16
	NextState       int32
}

// MaxHandshakePacketLen 是握手包允许的最大长度（含 Packet ID）。
// 实际握手包通常在 260 字节以内；放宽到 1 KiB 以容纳较长的
// UTF-8 域名与 Forge 等客户端附加的标记信息，同时仍能有效
// 拦截恶意超长包。
const MaxHandshakePacketLen = 1024

// ReadHandshake 从 r 读取并严格校验一个 Handshake 包。
// 任何字段不符合协议约束都返回错误。
func ReadHandshake(r PacketReader, maxPacketLen int) (*Handshake, error) {
	id, payload, err := ReadPacket(r, maxPacketLen)
	if err != nil {
		return nil, fmt.Errorf("read handshake packet: %w", err)
	}
	if id != PacketIDHandshake {
		return nil, fmt.Errorf("%w: handshake expects id 0x00, got 0x%02x", ErrBadPacketID, id)
	}
	return ParseHandshakePayload(payload)
}

// ParseHandshakePayload 严格校验并解析 Handshake 包体
// （不含长度前缀与 Packet ID）。
func ParseHandshakePayload(payload []byte) (*Handshake, error) {
	br := &byteReader{buf: payload}

	protocol, err := ReadVarInt(br)
	if err != nil {
		return nil, fmt.Errorf("read protocol version: %w", err)
	}

	address, err := ReadString(br, 255)
	if err != nil {
		return nil, fmt.Errorf("read server address: %w", err)
	}

	port, err := ReadUnsignedShort(br)
	if err != nil {
		return nil, fmt.Errorf("read server port: %w", err)
	}

	nextState, err := ReadVarInt(br)
	if err != nil {
		return nil, fmt.Errorf("read next state: %w", err)
	}

	if br.Remaining() != 0 {
		return nil, fmt.Errorf("handshake packet has %d trailing bytes", br.Remaining())
	}
	if nextState != NextStateStatus && nextState != NextStateLogin {
		return nil, fmt.Errorf("invalid next state %d (must be %d or %d)",
			nextState, NextStateStatus, NextStateLogin)
	}

	return &Handshake{
		ProtocolVersion: protocol,
		ServerAddress:   address,
		ServerPort:      port,
		NextState:       nextState,
	}, nil
}
