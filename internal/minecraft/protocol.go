package minecraft

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// 协议常量（仅本项目用到的一部分）。
const (
	// PacketIDHandshake 是 Handshake 包的 Packet ID。
	PacketIDHandshake int32 = 0x00
	// PacketIDStatusRequest 是 Status Request 包的 Packet ID。
	PacketIDStatusRequest int32 = 0x00
	// PacketIDStatusResponse 是 Status Response 包的 Packet ID。
	PacketIDStatusResponse int32 = 0x00
	// PacketIDPingRequest 是 Ping Request 包的 Packet ID。
	PacketIDPingRequest int32 = 0x01
	// PacketIDPongResponse 是 Pong Response 包的 Packet ID。
	PacketIDPongResponse int32 = 0x01
	// PacketIDLoginDisconnect 是 Login 阶段 Disconnect 包的 Packet ID。
	PacketIDLoginDisconnect int32 = 0x00
	// PacketIDLoginStart 是 Login Start 包的 Packet ID。
	PacketIDLoginStart int32 = 0x00

	// NextStateStatus 表示进入状态机 Status 阶段。
	NextStateStatus int32 = 1
	// NextStateLogin 表示进入状态机 Login 阶段。
	NextStateLogin int32 = 2

	// MaxStringLength 是协议 String 的最大长度（ushort 上限）。
	MaxStringLength = 32767
)

// ErrPacketTooLarge 表示数据包长度超过上限。
var ErrPacketTooLarge = errors.New("minecraft: packet is too large")

// ErrBadPacketID 表示 Packet ID 与当前状态机期望不符。
var ErrBadPacketID = errors.New("minecraft: unexpected packet id")

// PacketReader 是数据包读取所需的 Reader 抽象：
// bufio.Reader、bytes.Reader 均满足。要求 io.ByteReader 以保证
// 多字节 VarInt 的中间字节不会丢失。
type PacketReader interface {
	io.Reader
	io.ByteReader
}

// ReadPacket 读取一个完整数据包：VarInt 长度前缀 + 包体。
// 返回 Packet ID 与去掉 ID 后的剩余载荷。
// maxLen 限制数据包总长度（含 Packet ID），防御恶意超长包。
func ReadPacket(r PacketReader, maxLen int) (packetID int32, payload []byte, err error) {
	length, err := ReadVarInt(r)
	if err != nil {
		return 0, nil, fmt.Errorf("read packet length: %w", err)
	}
	if length <= 0 {
		return 0, nil, fmt.Errorf("invalid packet length %d", length)
	}
	if int(length) > maxLen {
		return 0, nil, ErrPacketTooLarge
	}

	body := make([]byte, length)
	if _, err := io.ReadFull(r, body); err != nil {
		return 0, nil, fmt.Errorf("read packet body (%d bytes): %w", length, err)
	}

	br := &byteReader{buf: body}
	id, err := ReadVarInt(br)
	if err != nil {
		return 0, nil, fmt.Errorf("read packet id: %w", err)
	}
	return id, body[br.pos:], nil
}

// WritePacket 写入一个完整数据包：VarInt 长度前缀 + VarInt Packet ID + 载荷。
func WritePacket(w io.Writer, packetID int32, payload []byte) error {
	total := VarIntLen(packetID) + len(payload)
	buf := make([]byte, 0, VarIntLen(int32(total))+total)
	buf = append(buf, EncodeVarInt(int32(total))...)
	buf = append(buf, EncodeVarInt(packetID)...)
	buf = append(buf, payload...)
	_, err := w.Write(buf)
	return err
}

// ReadString 读取协议 String：Unsigned Short 长度 + UTF-8 字节。
// maxLen 限制字符串最大字节数（协议上限 32767，MOTD 场景用不到那么大）。
func ReadString(r io.Reader, maxLen int) (string, error) {
	var raw [2]byte
	if _, err := io.ReadFull(r, raw[:]); err != nil {
		return "", fmt.Errorf("read string length: %w", err)
	}
	n := int(binary.BigEndian.Uint16(raw[:]))
	if n > maxLen {
		return "", fmt.Errorf("string length %d exceeds limit %d", n, maxLen)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return "", fmt.Errorf("read string body: %w", err)
	}
	return string(buf), nil
}

// WriteString 写入协议 String。
func WriteString(w io.Writer, s string) error {
	if len(s) > MaxStringLength {
		return fmt.Errorf("string length %d exceeds protocol limit %d", len(s), MaxStringLength)
	}
	var raw [2]byte
	binary.BigEndian.PutUint16(raw[:], uint16(len(s)))
	if _, err := w.Write(raw[:]); err != nil {
		return err
	}
	_, err := io.WriteString(w, s)
	return err
}

// byteReader 是 []byte 上的 io.ByteReader，用于在包体上解码 VarInt
// 而不丢失后续字节。pos 记录已消费位置。
type byteReader struct {
	buf []byte
	pos int
}

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

// Remaining 返回尚未消费的字节数。
func (b *byteReader) Remaining() int { return len(b.buf) - b.pos }

// ReadUnsignedShort 读取 2 字节大端无符号整数（协议端口号等）。
func ReadUnsignedShort(r io.Reader) (uint16, error) {
	var raw [2]byte
	if _, err := io.ReadFull(r, raw[:]); err != nil {
		return 0, fmt.Errorf("read unsigned short: %w", err)
	}
	return binary.BigEndian.Uint16(raw[:]), nil
}

// ReadLong 读取 8 字节大端有符号整数（Ping 载荷等）。
func ReadLong(r io.Reader) (int64, error) {
	var raw [8]byte
	if _, err := io.ReadFull(r, raw[:]); err != nil {
		return 0, fmt.Errorf("read long: %w", err)
	}
	return int64(binary.BigEndian.Uint64(raw[:])), nil
}

// WriteLong 写入 8 字节大端整数。
func WriteLong(w io.Writer, v int64) error {
	var raw [8]byte
	binary.BigEndian.PutUint64(raw[:], uint64(v))
	_, err := w.Write(raw[:])
	return err
}
