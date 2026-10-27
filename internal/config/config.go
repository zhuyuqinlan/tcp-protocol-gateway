// Package config 加载并校验网关配置。
//
// 本项目仅依赖 Go 标准库，因此内置了一个只覆盖本项目所需语法子集的
// YAML 解析器（见 yaml.go）：两层以内的嵌套映射、标量值、双引号字符串、
// 行注释。完整 YAML 语法不在支持范围内。
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// ServerConfig TCP 监听相关配置。
type ServerConfig struct {
	Listen           string        `yaml:"listen"`
	MaxConnections   int           `yaml:"max_connections"`
	HandshakeTimeout time.Duration `yaml:"handshake_timeout"`
	IdleTimeout      time.Duration `yaml:"idle_timeout"`
}

// HTTPConfig HTTP 透明代理配置。
type HTTPConfig struct {
	Backend        string        `yaml:"backend"`
	ConnectTimeout time.Duration `yaml:"connect_timeout"`
}

// MinecraftConfig Minecraft SLP 模拟配置。
type MinecraftConfig struct {
	Enabled         bool   `yaml:"enabled"`
	VersionName     string `yaml:"version_name"`
	ProtocolVersion int32  `yaml:"protocol_version"`
	MOTD            string `yaml:"motd"`
	MaxPlayers      int    `yaml:"max_players"`
	OnlinePlayers   int    `yaml:"online_players"`
}

// LoggingConfig 日志配置。
type LoggingConfig struct {
	Level string `yaml:"level"`
}

// Config 顶层配置。
type Config struct {
	Server    ServerConfig    `yaml:"server"`
	HTTP      HTTPConfig      `yaml:"http"`
	Minecraft MinecraftConfig `yaml:"minecraft"`
	Logging   LoggingConfig   `yaml:"logging"`
}

// Defaults 返回一份带全部默认值的配置。未在配置文件中出现的字段
// 将保留这里的默认值。
func Defaults() *Config {
	return &Config{
		Server: ServerConfig{
			Listen:           "0.0.0.0:25565",
			MaxConnections:   1000,
			HandshakeTimeout: 5 * time.Second,
			IdleTimeout:      60 * time.Second,
		},
		HTTP: HTTPConfig{
			Backend:        "127.0.0.1:8080",
			ConnectTimeout: 5 * time.Second,
		},
		Minecraft: MinecraftConfig{
			Enabled:         true,
			VersionName:     "1.20.1",
			ProtocolVersion: 763,
			MOTD:            "Go TCP Protocol Gateway",
			MaxPlayers:      100,
			OnlinePlayers:   0,
		},
		Logging: LoggingConfig{
			Level: "info",
		},
	}
}

// Load 从 path 读取 YAML 配置并叠加到默认值上。
// path 为空字符串时直接返回默认配置。
func Load(path string) (*Config, error) {
	cfg := Defaults()
	if path == "" {
		return cfg, cfg.validate()
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config file: %w", err)
	}

	root, err := parseYAML(data)
	if err != nil {
		return nil, fmt.Errorf("parse config file %s: %w", path, err)
	}

	if err := applySection(root, "server", func(m map[string]any) error {
		if err := decodeString(m, "listen", &cfg.Server.Listen); err != nil {
			return err
		}
		if err := decodeInt(m, "max_connections", &cfg.Server.MaxConnections); err != nil {
			return err
		}
		if err := decodeDuration(m, "handshake_timeout", &cfg.Server.HandshakeTimeout); err != nil {
			return err
		}
		return decodeDuration(m, "idle_timeout", &cfg.Server.IdleTimeout)
	}); err != nil {
		return nil, fmt.Errorf("section server: %w", err)
	}

	if err := applySection(root, "http", func(m map[string]any) error {
		if err := decodeString(m, "backend", &cfg.HTTP.Backend); err != nil {
			return err
		}
		return decodeDuration(m, "connect_timeout", &cfg.HTTP.ConnectTimeout)
	}); err != nil {
		return nil, fmt.Errorf("section http: %w", err)
	}

	if err := applySection(root, "minecraft", func(m map[string]any) error {
		if v, ok := m["enabled"]; ok {
			b, err := parseBool(v)
			if err != nil {
				return fmt.Errorf("field enabled: %w", err)
			}
			cfg.Minecraft.Enabled = b
		}
		if err := decodeString(m, "version_name", &cfg.Minecraft.VersionName); err != nil {
			return err
		}
		if err := decodeString(m, "motd", &cfg.Minecraft.MOTD); err != nil {
			return err
		}
		if err := decodeInt32(m, "protocol_version", &cfg.Minecraft.ProtocolVersion); err != nil {
			return err
		}
		if err := decodeInt(m, "max_players", &cfg.Minecraft.MaxPlayers); err != nil {
			return err
		}
		return decodeInt(m, "online_players", &cfg.Minecraft.OnlinePlayers)
	}); err != nil {
		return nil, fmt.Errorf("section minecraft: %w", err)
	}

	if err := applySection(root, "logging", func(m map[string]any) error {
		return decodeString(m, "level", &cfg.Logging.Level)
	}); err != nil {
		return nil, fmt.Errorf("section logging: %w", err)
	}

	return cfg, cfg.validate()
}

func (c *Config) validate() error {
	if c.Server.Listen == "" {
		return fmt.Errorf("server.listen must not be empty")
	}
	if c.Server.MaxConnections <= 0 {
		return fmt.Errorf("server.max_connections must be > 0, got %d", c.Server.MaxConnections)
	}
	if c.Server.HandshakeTimeout <= 0 {
		return fmt.Errorf("server.handshake_timeout must be > 0")
	}
	if c.Server.IdleTimeout <= 0 {
		return fmt.Errorf("server.idle_timeout must be > 0")
	}
	if c.HTTP.Backend == "" {
		return fmt.Errorf("http.backend must not be empty")
	}
	if c.HTTP.ConnectTimeout <= 0 {
		return fmt.Errorf("http.connect_timeout must be > 0")
	}
	switch strings.ToLower(c.Logging.Level) {
	case "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("logging.level must be one of debug/info/warn/error, got %q", c.Logging.Level)
	}
	return nil
}

// applySection 取 root[section] 并在存在时调用 fn。
func applySection(root map[string]any, section string, fn func(map[string]any) error) error {
	v, ok := root[section]
	if !ok || v == nil {
		return nil
	}
	m, ok := v.(map[string]any)
	if !ok {
		return fmt.Errorf("expected a mapping")
	}
	return fn(m)
}

func decodeString(m map[string]any, key string, dst *string) error {
	v, ok := m[key]
	if !ok || v == nil {
		return nil
	}
	s, ok := v.(string)
	if !ok {
		return fmt.Errorf("field %s: expected string, got %T", key, v)
	}
	*dst = s
	return nil
}

func decodeInt(m map[string]any, key string, dst *int) error {
	v, ok := m[key]
	if !ok || v == nil {
		return nil
	}
	n, err := parseInt(v)
	if err != nil {
		return fmt.Errorf("field %s: %w", key, err)
	}
	*dst = n
	return nil
}

func decodeInt32(m map[string]any, key string, dst *int32) error {
	v, ok := m[key]
	if !ok || v == nil {
		return nil
	}
	n, err := parseInt(v)
	if err != nil {
		return fmt.Errorf("field %s: %w", key, err)
	}
	*dst = int32(n)
	return nil
}

func decodeDuration(m map[string]any, key string, dst *time.Duration) error {
	v, present := m[key]
	if !present || v == nil {
		return nil
	}
	s, ok := v.(string)
	if !ok {
		return fmt.Errorf("field %s: expected duration string, got %T", key, v)
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("field %s: invalid duration %q", key, s)
	}
	if d <= 0 {
		return fmt.Errorf("field %s: duration must be > 0", key)
	}
	*dst = d
	return nil
}

func parseInt(v any) (int, error) {
	switch t := v.(type) {
	case int:
		return t, nil
	case string:
		n, err := strconv.Atoi(strings.TrimSpace(t))
		if err != nil {
			return 0, fmt.Errorf("invalid integer %q", t)
		}
		return n, nil
	default:
		return 0, fmt.Errorf("expected integer, got %T", v)
	}
}

func parseBool(v any) (bool, error) {
	switch t := v.(type) {
	case bool:
		return t, nil
	case string:
		b, err := strconv.ParseBool(strings.TrimSpace(t))
		if err != nil {
			return false, fmt.Errorf("invalid bool %q", t)
		}
		return b, nil
	default:
		return false, fmt.Errorf("expected bool, got %T", v)
	}
}
