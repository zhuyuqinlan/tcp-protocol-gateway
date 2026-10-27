package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadDefaults(t *testing.T) {
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load(\"\"): %v", err)
	}
	if cfg.Server.Listen != "0.0.0.0:25565" {
		t.Errorf("listen = %q", cfg.Server.Listen)
	}
	if cfg.Server.MaxConnections != 1000 {
		t.Errorf("max_connections = %d", cfg.Server.MaxConnections)
	}
	if cfg.Server.HandshakeTimeout != 5*time.Second {
		t.Errorf("handshake_timeout = %v", cfg.Server.HandshakeTimeout)
	}
	if cfg.Server.IdleTimeout != 60*time.Second {
		t.Errorf("idle_timeout = %v", cfg.Server.IdleTimeout)
	}
	if cfg.HTTP.Backend != "127.0.0.1:8080" {
		t.Errorf("backend = %q", cfg.HTTP.Backend)
	}
	if !cfg.Minecraft.Enabled {
		t.Error("minecraft should be enabled by default")
	}
	if cfg.Minecraft.ProtocolVersion != 763 {
		t.Errorf("protocol_version = %d", cfg.Minecraft.ProtocolVersion)
	}
}

func TestLoadFromFile(t *testing.T) {
	content := `
# 网关配置示例
server:
  listen: "0.0.0.0:30000"  # 监听地址
  max_connections: 42
  handshake_timeout: 3s
  idle_timeout: 30s

http:
  backend: "127.0.0.1:9090"
  connect_timeout: 2s

minecraft:
  enabled: false
  version_name: "1.21.4"
  protocol_version: 769
  motd: "测试 MOTD # 带井号"
  max_players: 20
  online_players: 3

logging:
  level: "debug"
`
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.Server.Listen != "0.0.0.0:30000" {
		t.Errorf("listen = %q", cfg.Server.Listen)
	}
	if cfg.Server.MaxConnections != 42 {
		t.Errorf("max_connections = %d", cfg.Server.MaxConnections)
	}
	if cfg.Server.HandshakeTimeout != 3*time.Second {
		t.Errorf("handshake_timeout = %v", cfg.Server.HandshakeTimeout)
	}
	if cfg.Server.IdleTimeout != 30*time.Second {
		t.Errorf("idle_timeout = %v", cfg.Server.IdleTimeout)
	}
	if cfg.HTTP.Backend != "127.0.0.1:9090" {
		t.Errorf("backend = %q", cfg.HTTP.Backend)
	}
	if cfg.HTTP.ConnectTimeout != 2*time.Second {
		t.Errorf("connect_timeout = %v", cfg.HTTP.ConnectTimeout)
	}
	if cfg.Minecraft.Enabled {
		t.Error("enabled should be false")
	}
	if cfg.Minecraft.VersionName != "1.21.4" {
		t.Errorf("version_name = %q", cfg.Minecraft.VersionName)
	}
	if cfg.Minecraft.ProtocolVersion != 769 {
		t.Errorf("protocol_version = %d", cfg.Minecraft.ProtocolVersion)
	}
	// 行内注释与引号内的 '#' 都要正确处理。
	if cfg.Minecraft.MOTD != "测试 MOTD # 带井号" {
		t.Errorf("motd = %q", cfg.Minecraft.MOTD)
	}
	if cfg.Minecraft.MaxPlayers != 20 || cfg.Minecraft.OnlinePlayers != 3 {
		t.Errorf("players = %d/%d", cfg.Minecraft.OnlinePlayers, cfg.Minecraft.MaxPlayers)
	}
	if cfg.Logging.Level != "debug" {
		t.Errorf("level = %q", cfg.Logging.Level)
	}
}

func TestLoadPartialFileKeepsDefaults(t *testing.T) {
	content := `
server:
  listen: "127.0.0.1:12345"
`
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Server.Listen != "127.0.0.1:12345" {
		t.Errorf("listen = %q", cfg.Server.Listen)
	}
	// 未覆盖的字段保持默认值。
	if cfg.Server.MaxConnections != 1000 {
		t.Errorf("max_connections = %d, want default 1000", cfg.Server.MaxConnections)
	}
	if cfg.HTTP.Backend != "127.0.0.1:8080" {
		t.Errorf("backend = %q, want default", cfg.HTTP.Backend)
	}
}

func TestLoadMissingFile(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "nope.yaml")); err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoadInvalidValues(t *testing.T) {
	cases := []struct {
		name    string
		content string
	}{
		{"bad int", "server:\n  max_connections: abc\n"},
		{"bad duration", "server:\n  handshake_timeout: five\n"},
		{"bad bool", "minecraft:\n  enabled: yes-please\n"},
		{"bad level", "logging:\n  level: verbose\n"},
		{"zero max conn", "server:\n  max_connections: 0\n"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			if err := os.WriteFile(path, []byte(c.content), 0o644); err != nil {
				t.Fatalf("write config: %v", err)
			}
			if _, err := Load(path); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestParseYAMLStructure(t *testing.T) {
	root, err := parseYAML([]byte("a:\n  b: \"1\"\n  c: 2\nd: 3\n"))
	if err != nil {
		t.Fatalf("parseYAML: %v", err)
	}
	a, ok := root["a"].(map[string]any)
	if !ok {
		t.Fatalf("a should be a map, got %T", root["a"])
	}
	if a["b"] != "1" {
		t.Errorf("a.b = %v", a["b"])
	}
	if a["c"] != "2" {
		t.Errorf("a.c = %v (scalars are strings)", a["c"])
	}
	if root["d"] != "3" {
		t.Errorf("d = %v", root["d"])
	}
}
