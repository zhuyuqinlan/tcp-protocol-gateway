// Package detector 基于 TCP 首批数据识别连接使用的协议。
//
// 识别完全基于 bufio.Reader.Peek：只窥探、不消费，
// 后续协议处理模块继续从同一个 Reader 读取，保证已嗅探的
// 字节既不丢失也不被重复消费。TCP 分片由 Peek 的阻塞语义天然处理。
package detector

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"time"

	"tcp-protocol-gateway/internal/minecraft"
)

// Protocol 是嗅探结果。
type Protocol int

const (
	// ProtocolUnknown 无法识别的协议，应安全关闭连接。
	ProtocolUnknown Protocol = iota
	// ProtocolHTTP HTTP/1.x 请求，应透明转发到后端。
	ProtocolHTTP
	// ProtocolMinecraft Minecraft Java Edition 现代协议（握手包校验通过）。
	ProtocolMinecraft
	// ProtocolTLS TLS ClientHello（首字节 0x16）。网关不解密 TLS，
	// 明确拒绝。
	ProtocolTLS
)

// String 返回协议的可读名称（用于日志）。
func (p Protocol) String() string {
	switch p {
	case ProtocolHTTP:
		return "http"
	case ProtocolMinecraft:
		return "minecraft"
	case ProtocolTLS:
		return "tls"
	default:
		return "unknown"
	}
}

// httpMethods 是需要识别的 HTTP/1.x 请求方法。
var httpMethods = []string{
	"OPTIONS", "CONNECT", "DELETE", "PATCH", "HEAD", "GET", "POST", "PUT",
}

// MaxDetectPacketLen 是嗅探阶段允许的 Minecraft 握手包最大长度。
// 与握手包自身的 1 KiB 上限对齐。
const MaxDetectPacketLen = minecraft.MaxHandshakePacketLen

// ErrDetectTimeout 表示嗅探阶段等待数据超时（调用方通常已设置
// 连接读取期限，这里是纵深防御）。
var ErrDetectTimeout = errors.New("detector: timed out waiting for protocol data")

// Result 是一次嗅探的结果。
type Result struct {
	Protocol  Protocol
	Handshake *minecraft.Handshake // 仅 Protocol == ProtocolMinecraft 时非 nil
}

// Detect 在 br 上识别协议。
//
// 调用方必须在进入本函数前为连接设置读取期限
// （deadline = now + handshakeTimeout），慢连接会因 Peek 超时返回
// 而被拒绝，不会无限等待。
func Detect(br *bufio.Reader, handshakeTimeout time.Duration) (*Result, error) {
	if handshakeTimeout <= 0 {
		handshakeTimeout = 5 * time.Second
	}

	// 1. 窥探第一个字节，判断协议大类。
	first, err := br.Peek(1)
	if err != nil {
		return nil, fmt.Errorf("%w: peek first byte: %v", ErrDetectTimeout, err)
	}

	// 1. TLS ClientHello 判定：记录层首字节 0x16 (Handshake) +
	//    版本号高字节 0x03。仅凭首字节判定不够——Minecraft 握手包
	//    的长度 VarInt 恰好可能是 22 (0x16)，必须联合校验版本字节。
	if p, _ := br.Peek(3); len(p) >= 3 && p[0] == 0x16 && p[1] == 0x03 && p[2] <= 0x04 {
		return &Result{Protocol: ProtocolTLS}, nil
	}

	// 2. HTTP：方法 + 空格 + 可见 ASCII 请求行。
	//    Peek(16) 覆盖最长的方法 "OPTIONS " 及其后的请求行内容；
	//    即使未凑满 16 字节（超时/EOF），已窥探到的字节仍然可用。
	if p, _ := br.Peek(16); matchHTTPRequestLine(p) {
		return &Result{Protocol: ProtocolHTTP}, nil
	}

	// 3. Minecraft：VarInt 长度 + Packet ID 0x00 + 握手字段严格校验。
	//    注意：不能用"首字节 < 0x80"来判断 Minecraft ——
	//    长度 7..127 的握手包首字节同样小于 0x80，必须完整校验。
	return detectMinecraft(br, first[0])
}

// matchHTTPRequestLine 检查 p 是否为 HTTP/1.x 请求行的开头：
// "METHOD 可见ASCII"（可见 ASCII = 0x20..0x7E，且至少含一个
// 非空格字符表示请求目标）。
//
// 之所以要求方法后的字节全部可见：Minecraft 握手包的长度 VarInt
// 首字节可能是 'G'(0x47)/'P'(0x50) 等字母，其载荷紧跟 Packet ID
// 0x00（不可见），该规则可将两者可靠区分。
// 允许 p 比 8 字节短（Peek 在超时或对端关闭时返回部分数据）。
func matchHTTPRequestLine(p []byte) bool {
	for _, m := range httpMethods {
		if len(p) < len(m)+2 {
			continue
		}
		if !bytes.HasPrefix(p, []byte(m)) || p[len(m)] != ' ' {
			continue
		}
		if isPrintableRequestTail(p[len(m)+1:]) {
			return true
		}
	}
	return false
}

// isPrintableRequestTail 检查请求行剩余部分（到行尾或数据末尾）
// 是否全部为可见 ASCII。
func isPrintableRequestTail(tail []byte) bool {
	seenNonSpace := false
	for _, b := range tail {
		if b == '\r' || b == '\n' {
			break
		}
		if b < 0x20 || b > 0x7E {
			return false
		}
		if b != ' ' {
			seenNonSpace = true
		}
	}
	return seenNonSpace
}

// detectMinecraft 尝试按 Minecraft 握手包解析窥探到的数据。
func detectMinecraft(br *bufio.Reader, first byte) (*Result, error) {
	// 3.1 窥探（不消费）包长度 VarInt，最多 3 字节。
	length, ok := peekVarInt(br, first, 3)
	if !ok {
		return &Result{Protocol: ProtocolUnknown}, nil
	}

	// 有效握手包最短 7 字节
	// (PacketID 1 + ProtocolVersion >= 1 + 地址长度 2 + 端口 2 + NextState 1)，
	// 上限与握手包解析限制一致。
	if length < 7 || length > MaxDetectPacketLen {
		return &Result{Protocol: ProtocolUnknown}, nil
	}

	// 3.2 窥探完整握手包体（长度前缀 + 包体）并严格校验。
	total := len(minecraft.EncodeVarInt(length)) + int(length)
	packet, err := br.Peek(total)
	if err != nil {
		// 数据不足：慢连接超时，或对端发送了看似长度前缀却
		// 迟迟不补齐的数据。统一按超时错误交给调用方安全关闭。
		return nil, fmt.Errorf("%w: peek minecraft handshake (%d bytes): %v",
			ErrDetectTimeout, total, err)
	}

	hs, err := parseHandshakeSnapshot(packet)
	if err != nil {
		// 结构不合法 → 不是 Minecraft。
		return &Result{Protocol: ProtocolUnknown}, nil
	}
	return &Result{Protocol: ProtocolMinecraft, Handshake: hs}, nil
}

// peekVarInt 从 br 窥探（不消费）一个最多 maxBytes 字节的 VarInt。
// first 是已窥探到的第一个字节。
func peekVarInt(br *bufio.Reader, first byte, maxBytes int) (int32, bool) {
	var result uint32
	b := first
	for i := 0; i < maxBytes; i++ {
		result |= uint32(b&0x7F) << (7 * i)
		if b&0x80 == 0 {
			return int32(result), true
		}
		need := i + 2
		p, err := br.Peek(need)
		if err != nil || len(p) < need {
			return 0, false
		}
		b = p[i+1]
	}
	return 0, false
}

// parseHandshakeSnapshot 对窥探到的完整握手包
// （长度前缀 + 包体）做严格解析校验，不消费 Reader。
// 复用协议层解析逻辑，保证嗅探与正式解析的规则完全一致。
func parseHandshakeSnapshot(packet []byte) (*minecraft.Handshake, error) {
	r := bytes.NewReader(packet)
	id, payload, err := minecraft.ReadPacket(r, MaxDetectPacketLen)
	if err != nil {
		return nil, err
	}
	if id != minecraft.PacketIDHandshake {
		return nil, fmt.Errorf("%w: handshake expects id 0x00, got 0x%02x",
			minecraft.ErrBadPacketID, id)
	}
	return minecraft.ParseHandshakePayload(payload)
}
