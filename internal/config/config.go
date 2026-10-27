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

// HTTPConfig HTTP 代理全局配置。
type HTTPConfig struct {
	ConnectTimeout time.Duration `yaml:"connect_timeout"`
}

// HTTPRoute 是一条 HTTP 路径前缀路由。
type HTTPRoute struct {
	// Backend 是该前缀命中的请求转发目标。
	Backend string `yaml:"backend"`
	// StripPrefix 为 true 时，转发前把命中的前缀从请求行
	// 的 request-target 中剥掉（如 /api/users → /users；
	// 剥完为空时转发为 /）。false 表示透明转发（保留前缀）。
	StripPrefix bool `yaml:"strip_prefix"`
}

// RoutesConfig 多路由映射表。
//
// 配置形式（键为前缀/监听地址）：
//
//	routes:
//	  http:                          # 路径前缀 -> HTTP 后端（最长前缀优先）
//	    "/api": "127.0.0.1:8080"     # 简写：仅后端，保留前缀
//	    "/web":                      # 完整形式：可配置前缀剥离
//	      backend: "127.0.0.1:8081"
//	      strip_prefix: true
//	  tcp:                       # 监听地址 -> TCP 后端（原始字节转发）
//	    "0.0.0.0:30000": "127.0.0.1:9000"
//	  udp:                       # 监听地址 -> UDP 后端（数据报转发）
//	    "0.0.0.0:5353": "8.8.8.8:53"
type RoutesConfig struct {
	// HTTP 是路径前缀到后端的映射，仅作用于主监听端口。
	HTTP map[string]HTTPRoute `yaml:"http"`
	// TCP 是监听地址到后端的映射，每个条目独立监听一个 TCP 端口，
	// 将连接的字节流原样转发到后端。
	TCP map[string]string `yaml:"tcp"`
	// UDP 是监听地址到后端的映射，每个条目独立监听一个 UDP 端口，
	// 按客户端地址维持会话转发数据报。
	UDP map[string]string `yaml:"udp"`
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
	Routes    RoutesConfig    `yaml:"routes"`
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
			ConnectTimeout: 5 * time.Second,
		},
		Routes: RoutesConfig{
			HTTP: map[string]HTTPRoute{},
			TCP:  map[string]string{},
			UDP:  map[string]string{},
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
		return decodeDuration(m, "connect_timeout", &cfg.HTTP.ConnectTimeout)
	}); err != nil {
		return nil, fmt.Errorf("section http: %w", err)
	}

	if err := applySection(root, "routes", func(m map[string]any) error {
		if err := decodeHTTPRoutes(m, "http", cfg.Routes.HTTP); err != nil {
			return err
		}
		if err := decodeStringMap(m, "tcp", cfg.Routes.TCP); err != nil {
			return err
		}
		return decodeStringMap(m, "udp", cfg.Routes.UDP)
	}); err != nil {
		return nil, fmt.Errorf("section routes: %w", err)
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
	if c.HTTP.ConnectTimeout <= 0 {
		return fmt.Errorf("http.connect_timeout must be > 0")
	}
	for prefix, route := range c.Routes.HTTP {
		if !strings.HasPrefix(prefix, "/") {
			return fmt.Errorf("routes.http prefix %q must start with '/'", prefix)
		}
		if route.Backend == "" {
			return fmt.Errorf("routes.http[%s]: backend must not be empty", prefix)
		}
	}
	for listen, backend := range c.Routes.TCP {
		if listen == "" {
			return fmt.Errorf("routes.tcp listen must not be empty")
		}
		if backend == "" {
			return fmt.Errorf("routes.tcp[%s]: backend must not be empty", listen)
		}
	}
	for listen, backend := range c.Routes.UDP {
		if listen == "" {
			return fmt.Errorf("routes.udp listen must not be empty")
		}
		if backend == "" {
			return fmt.Errorf("routes.udp[%s]: backend must not be empty", listen)
		}
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

// decodeStringMap 将 m[key]（"key: value" 形式的映射）解码到 dst，
// 仅保留字符串值。
func decodeStringMap(m map[string]any, key string, dst map[string]string) error {
	v, ok := m[key]
	if !ok || v == nil {
		return nil
	}
	sub, ok := v.(map[string]any)
	if !ok {
		return fmt.Errorf("field %s: expected a mapping", key)
	}
	for k, sv := range sub {
		if sv == nil {
			continue
		}
		s, ok := sv.(string)
		if !ok {
			return fmt.Errorf("field %s.%s: expected string value, got %T", key, k, sv)
		}
		dst[k] = s
	}
	return nil
}

// decodeHTTPRoutes 将 m[key] 解码为 HTTP 路由表。条目值支持两种形式：
//
//	"/api": "127.0.0.1:8080"        # 简写：仅后端地址，保留前缀
//	"/web":                         # 完整形式
//	  backend: "127.0.0.1:8081"
//	  strip_prefix: true
func decodeHTTPRoutes(m map[string]any, key string, dst map[string]HTTPRoute) error {
	v, ok := m[key]
	if !ok || v == nil {
		return nil
	}
	sub, ok := v.(map[string]any)
	if !ok {
		return fmt.Errorf("field %s: expected a mapping", key)
	}
	for prefix, sv := range sub {
		if sv == nil {
			continue
		}
		switch val := sv.(type) {
		case string:
			dst[prefix] = HTTPRoute{Backend: val}
		case map[string]any:
			var r HTTPRoute
			if err := decodeString(val, "backend", &r.Backend); err != nil {
				return fmt.Errorf("field %s.%s: %w", key, prefix, err)
			}
			if raw, present := val["strip_prefix"]; present && raw != nil {
				b, err := parseBool(raw)
				if err != nil {
					return fmt.Errorf("field %s.%s.strip_prefix: %w", key, prefix, err)
				}
				r.StripPrefix = b
			}
			dst[prefix] = r
		default:
			return fmt.Errorf("field %s.%s: expected backend string or mapping, got %T", key, prefix, sv)
		}
	}
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
