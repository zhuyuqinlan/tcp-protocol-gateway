// Package minecraft 实现 Minecraft Java Edition 的协议编解码原语
// 与 Server List Ping / Login 拒绝的最小状态机。
//
// 参考协议文档: https://wiki.vg/Protocol
package minecraft

import (
	"errors"
	"fmt"
	"io"
)

// MaxVarIntLen 是 32 位 VarInt 的最大字节数。
const MaxVarIntLen = 5

// ErrVarIntTooLarge 表示 VarInt 超过 5 字节或数值超出 32 位范围。
var ErrVarIntTooLarge = errors.New("minecraft: varint is too large")

// ReadVarInt 从 r 读取一个 VarInt。
// 最多读取 5 字节；第 5 字节带有超出 32 位范围的位时返回 ErrVarIntTooLarge。
// r 必须实现 io.ByteReader（*bufio.Reader、*bytes.Reader 均满足），
// 否则会丢失多字节 VarInt 中间字节。
func ReadVarInt(r io.ByteReader) (int32, error) {
	var result uint32
	for i := 0; i < MaxVarIntLen; i++ {
		b, err := r.ReadByte()
		if err != nil {
			return 0, fmt.Errorf("read varint byte %d: %w", i, err)
		}
		result |= uint32(b&0x7F) << (7 * i)
		if b&0x80 == 0 {
			if i == MaxVarIntLen-1 && b > 0x0F {
				return 0, ErrVarIntTooLarge
			}
			return int32(result), nil
		}
	}
	return 0, ErrVarIntTooLarge
}

// WriteVarInt 将 v 以 VarInt 编码写入 w。
func WriteVarInt(w io.Writer, v int32) error {
	var buf [MaxVarIntLen]byte
	n := 0
	u := uint32(v)
	for {
		b := byte(u & 0x7F)
		u >>= 7
		if u != 0 {
			b |= 0x80
		}
		buf[n] = b
		n++
		if u == 0 {
			break
		}
	}
	_, err := w.Write(buf[:n])
	return err
}

// VarIntLen 返回 v 的 VarInt 编码字节数。
func VarIntLen(v int32) int {
	n := 1
	u := uint32(v)
	for u >= 0x80 {
		u >>= 7
		n++
	}
	return n
}

// EncodeVarInt 返回 v 的 VarInt 编码。
func EncodeVarInt(v int32) []byte {
	buf := make([]byte, 0, MaxVarIntLen)
	u := uint32(v)
	for {
		b := byte(u & 0x7F)
		u >>= 7
		if u != 0 {
			b |= 0x80
		}
		buf = append(buf, b)
		if u == 0 {
			return buf
		}
	}
}
