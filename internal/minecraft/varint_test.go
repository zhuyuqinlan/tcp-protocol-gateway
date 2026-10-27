package minecraft

import (
	"bytes"
	"errors"
	"math"
	"testing"
)

func TestWriteReadVarIntRoundTrip(t *testing.T) {
	cases := []int32{
		0, 1, 2, 127, 128, 255, 256, 16383, 16384,
		math.MaxInt32, -1, -2147483648,
	}
	for _, v := range cases {
		var buf bytes.Buffer
		if err := WriteVarInt(&buf, v); err != nil {
			t.Fatalf("WriteVarInt(%d): %v", v, err)
		}
		got, err := ReadVarInt(&buf)
		if err != nil {
			t.Fatalf("ReadVarInt(%d): %v", v, err)
		}
		if got != v {
			t.Fatalf("round trip: want %d, got %d", v, got)
		}
	}
}

func TestVarIntEncoding(t *testing.T) {
	// 与 wiki.vg 文档中的示例对齐。
	cases := []struct {
		value int32
		want  []byte
	}{
		{0, []byte{0x00}},
		{1, []byte{0x01}},
		{2, []byte{0x02}},
		{127, []byte{0x7F}},
		{128, []byte{0x80, 0x01}},
		{255, []byte{0xFF, 0x01}},
		{25565, []byte{0xDD, 0xC7, 0x01}},
		{2097151, []byte{0xFF, 0xFF, 0x7F}},
		{2147483647, []byte{0xFF, 0xFF, 0xFF, 0xFF, 0x07}},
		{-1, []byte{0xFF, 0xFF, 0xFF, 0xFF, 0x0F}},
		// -2147483648 = 0x80000000，最高 4 位 (bits 28-31) = 0b1000 = 0x08。
		{-2147483648, []byte{0x80, 0x80, 0x80, 0x80, 0x08}},
	}
	for _, c := range cases {
		got := EncodeVarInt(c.value)
		if !bytes.Equal(got, c.want) {
			t.Errorf("EncodeVarInt(%d) = %x, want %x", c.value, got, c.want)
		}
		if l := VarIntLen(c.value); l != len(c.want) {
			t.Errorf("VarIntLen(%d) = %d, want %d", c.value, l, len(c.want))
		}
	}
}

func TestReadVarIntTooLarge(t *testing.T) {
	// 5 字节且第 5 字节超出 32 位范围。
	data := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0x7F}
	_, err := ReadVarInt(bytes.NewReader(data))
	if !errors.Is(err, ErrVarIntTooLarge) {
		t.Fatalf("want ErrVarIntTooLarge, got %v", err)
	}

	// 6 字节（超过最大长度）。
	data = []byte{0x80, 0x80, 0x80, 0x80, 0x80, 0x01}
	_, err = ReadVarInt(bytes.NewReader(data))
	if !errors.Is(err, ErrVarIntTooLarge) {
		t.Fatalf("want ErrVarIntTooLarge for 6-byte varint, got %v", err)
	}
}

func TestReadVarIntEOF(t *testing.T) {
	// 截断的 VarInt 应返回错误而不是 panic。
	data := []byte{0x80, 0x80}
	if _, err := ReadVarInt(bytes.NewReader(data)); err == nil {
		t.Fatal("expected error for truncated varint")
	}
	if _, err := ReadVarInt(bytes.NewReader(nil)); err == nil {
		t.Fatal("expected error for empty input")
	}
}

func TestStringRoundTrip(t *testing.T) {
	for _, s := range []string{"", "hello", "Go TCP Protocol Gateway", "中文 MOTD ✅"} {
		var buf bytes.Buffer
		if err := WriteString(&buf, s); err != nil {
			t.Fatalf("WriteString: %v", err)
		}
		got, err := ReadString(&buf, MaxStringLength)
		if err != nil {
			t.Fatalf("ReadString: %v", err)
		}
		if got != s {
			t.Fatalf("string round trip: want %q, got %q", s, got)
		}
	}
}

func TestReadStringTooLong(t *testing.T) {
	var buf bytes.Buffer
	_ = buf.WriteByte(0x01) // 长度 258 > maxLen 8
	_ = buf.WriteByte(0x02)
	buf.WriteString("0123456789")
	if _, err := ReadString(&buf, 8); err == nil {
		t.Fatal("expected error for string exceeding limit")
	}
}

func TestPacketRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	payload := []byte("payload-bytes")
	if err := WritePacket(&buf, 0x01, payload); err != nil {
		t.Fatalf("WritePacket: %v", err)
	}
	id, got, err := ReadPacket(&buf, 1024)
	if err != nil {
		t.Fatalf("ReadPacket: %v", err)
	}
	if id != 0x01 {
		t.Fatalf("packet id = %d, want 1", id)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload = %q, want %q", got, payload)
	}
}

func TestReadPacketTooLarge(t *testing.T) {
	var buf bytes.Buffer
	// 声称包体长度 100，超过 maxLen 16。
	_ = WriteVarInt(&buf, 100)
	buf.Write(make([]byte, 10))
	if _, _, err := ReadPacket(&buf, 16); !errors.Is(err, ErrPacketTooLarge) {
		t.Fatalf("want ErrPacketTooLarge, got %v", err)
	}
}

func TestReadPacketInvalidLength(t *testing.T) {
	// 长度为 0 非法。
	var buf bytes.Buffer
	_ = WriteVarInt(&buf, 0)
	if _, _, err := ReadPacket(&buf, 16); err == nil {
		t.Fatal("expected error for zero packet length")
	}

	// 长度为负数非法。
	buf.Reset()
	_ = WriteVarInt(&buf, -1)
	if _, _, err := ReadPacket(&buf, 16); err == nil {
		t.Fatal("expected error for negative packet length")
	}
}

func TestLongRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	for _, v := range []int64{0, 1, -1, math.MaxInt64, math.MinInt64} {
		if err := WriteLong(&buf, v); err != nil {
			t.Fatalf("WriteLong: %v", err)
		}
		got, err := ReadLong(&buf)
		if err != nil {
			t.Fatalf("ReadLong: %v", err)
		}
		if got != v {
			t.Fatalf("long round trip: want %d, got %d", v, got)
		}
	}
}
