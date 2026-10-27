package minecraft

import (
	"bytes"
	"errors"
	"testing"
)

// buildHandshake 构造一个 Handshake 包体的原始字节
// （长度前缀 + Packet ID + 载荷）。
func buildHandshake(t *testing.T, protocol int32, address string, port uint16, nextState int32) []byte {
	t.Helper()

	body := EncodeVarInt(PacketIDHandshake)
	body = append(body, EncodeVarInt(protocol)...)
	addrLen := []byte{byte(len(address) >> 8), byte(len(address))}
	body = append(body, addrLen...)
	body = append(body, address...)
	body = append(body, byte(port>>8), byte(port))
	body = append(body, EncodeVarInt(nextState)...)

	var buf bytes.Buffer
	_ = WriteVarInt(&buf, int32(len(body)))
	buf.Write(body)
	return buf.Bytes()
}

func TestReadHandshakeValid(t *testing.T) {
	cases := []struct {
		name      string
		protocol  int32
		address   string
		port      uint16
		nextState int32
	}{
		{"status", 763, "mc.example.com", 25565, NextStateStatus},
		{"login", 763, "127.0.0.1", 25565, NextStateLogin},
		{"ipv4", 754, "10.0.0.5", 25566, NextStateStatus},
		{"empty address", 763, "", 25565, NextStateStatus},
		{"negative protocol", -1, "legacy", 25565, NextStateStatus},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			raw := buildHandshake(t, c.protocol, c.address, c.port, c.nextState)
			hs, err := ReadHandshake(bytes.NewReader(raw), MaxHandshakePacketLen)
			if err != nil {
				t.Fatalf("ReadHandshake: %v", err)
			}
			if hs.ProtocolVersion != c.protocol {
				t.Errorf("protocol = %d, want %d", hs.ProtocolVersion, c.protocol)
			}
			if hs.ServerAddress != c.address {
				t.Errorf("address = %q, want %q", hs.ServerAddress, c.address)
			}
			if hs.ServerPort != c.port {
				t.Errorf("port = %d, want %d", hs.ServerPort, c.port)
			}
			if hs.NextState != c.nextState {
				t.Errorf("next state = %d, want %d", hs.NextState, c.nextState)
			}
		})
	}
}

func TestReadHandshakeInvalidNextState(t *testing.T) {
	raw := buildHandshake(t, 763, "mc.example.com", 25565, 3)
	if _, err := ReadHandshake(bytes.NewReader(raw), MaxHandshakePacketLen); err == nil {
		t.Fatal("expected error for next state 3")
	}

	raw = buildHandshake(t, 763, "mc.example.com", 25565, 0)
	if _, err := ReadHandshake(bytes.NewReader(raw), MaxHandshakePacketLen); err == nil {
		t.Fatal("expected error for next state 0")
	}
}

func TestReadHandshakeWrongPacketID(t *testing.T) {
	// Packet ID 0x01 不是握手包。
	body := EncodeVarInt(0x01)
	body = append(body, EncodeVarInt(763)...)
	var buf bytes.Buffer
	_ = WriteVarInt(&buf, int32(len(body)))
	buf.Write(body)

	if _, err := ReadHandshake(bytes.NewReader(buf.Bytes()), MaxHandshakePacketLen); !errors.Is(err, ErrBadPacketID) {
		t.Fatalf("want ErrBadPacketID, got %v", err)
	}
}

func TestReadHandshakeTrailingBytes(t *testing.T) {
	// 包体在 NextState 字段后附加脏数据：解析必须报错。
	body := EncodeVarInt(PacketIDHandshake)
	body = append(body, EncodeVarInt(763)...)
	addr := "mc.example.com"
	body = append(body, byte(len(addr)>>8), byte(len(addr)))
	body = append(body, addr...)
	body = append(body, 0x63, 0xDD) // port 25565
	body = append(body, EncodeVarInt(NextStateStatus)...)
	body = append(body, 0xAA, 0xBB) // 包体内尾随字节

	var buf bytes.Buffer
	_ = WriteVarInt(&buf, int32(len(body)))
	buf.Write(body)

	if _, err := ReadHandshake(bytes.NewReader(buf.Bytes()), MaxHandshakePacketLen); err == nil {
		t.Fatal("expected error for trailing bytes inside packet body")
	}
}

func TestReadHandshakeTooLarge(t *testing.T) {
	// 超过 maxPacketLen 的包应被拒绝。
	raw := buildHandshake(t, 763, "mc.example.com", 25565, NextStateStatus)
	if _, err := ReadHandshake(bytes.NewReader(raw), 8); !errors.Is(err, ErrPacketTooLarge) {
		t.Fatalf("want ErrPacketTooLarge, got %v", err)
	}
}

func TestReadHandshakeTruncated(t *testing.T) {
	// 包体被截断（声明长度与实际不符）。
	raw := buildHandshake(t, 763, "mc.example.com", 25565, NextStateStatus)
	truncated := raw[:len(raw)-3]
	if _, err := ReadHandshake(bytes.NewReader(truncated), MaxHandshakePacketLen); err == nil {
		t.Fatal("expected error for truncated packet")
	}
}

func TestParseHandshakePayloadInvalidVarInt(t *testing.T) {
	// 载荷首字段是 5 字节超范围 VarInt。
	payload := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0x7F}
	if _, err := ParseHandshakePayload(payload); err == nil {
		t.Fatal("expected error for invalid varint in payload")
	}
}

func TestStatusJSON(t *testing.T) {
	s := NewStatus("1.20.1", 763, "Go TCP Protocol Gateway", 100, 0)
	js, err := s.JSON()
	if err != nil {
		t.Fatalf("JSON: %v", err)
	}
	want := `{"version":{"name":"1.20.1","protocol":763},` +
		`"players":{"max":100,"online":0},` +
		`"description":{"text":"Go TCP Protocol Gateway"}}`
	if js != want {
		t.Fatalf("status json =\n%s\nwant\n%s", js, want)
	}
}

func TestDisconnectReason(t *testing.T) {
	got := DisconnectReason("no login")
	want := `{"text":"no login"}`
	if got != want {
		t.Fatalf("disconnect reason = %s, want %s", got, want)
	}
}
