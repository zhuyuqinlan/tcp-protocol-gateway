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

// ServerConfig HTTP(S) 监听相关配置。
type ServerConfig struct {
	// Listen 是网关直接监听的地址（HTTP 或 HTTPS 由 TLS 配置决定）。
	Listen string `yaml:"listen"`
	// ReadHeaderTimeout 是读取请求头（含 TLS 握手后的首个请求）的期限，
	// 防止慢连接长期占用 goroutine。
	ReadHeaderTimeout time.Duration `yaml:"read_header_timeout"`
	// TLSCertFile / TLSKeyFile 均非空时启用 HTTPS（TLS 终止在本网关）。
	TLSCertFile string `yaml:"tls_cert"`
	TLSKeyFile  string `yaml:"tls_key"`
}

// TLSEnabled 返回是否启用 HTTPS。
func (s ServerConfig) TLSEnabled() bool {
	return s.TLSCertFile != "" || s.TLSKeyFile != ""
}

// HTTPConfig HTTP 代理全局配置。
type HTTPConfig struct {
	// ConnectTimeout 是连接后端的拨号超时。
	ConnectTimeout time.Duration `yaml:"connect_timeout"`
	// TLSSkipVerify 为 true 时，网关不校验 HTTPS 后端返回的证书
	// （自签名证书场景使用，仅建议测试环境开启）。
	TLSSkipVerify bool `yaml:"tls_skip_verify"`
}

// HTTPRoute 是一条 HTTP 路径前缀路由。
type HTTPRoute struct {
	// Backend 是该前缀命中的请求转发目标。
	Backend string `yaml:"backend"`
	// StripPrefix 为 true 时，转发前把命中的前缀从请求路径中
	// 剥掉（如 /api/users → /users；剥完为空时转发为 /）。
	// false 表示透明转发（保留前缀）。
	StripPrefix bool `yaml:"strip_prefix"`
}

// RoutesConfig HTTP 路径前缀路由表。
//
// 配置形式（键为路径前缀）：
//
//	routes:
//	  http:                          # 路径前缀 -> HTTP 后端（最长前缀优先）
//	    "/api": "127.0.0.1:8080"     # 简写：仅后端，保留前缀
//	    "/web":                      # 完整形式：可配置前缀剥离
//	      backend: "127.0.0.1:8081"
//	      strip_prefix: true
type RoutesConfig struct {
	// HTTP 是路径前缀到后端的映射，作用于监听端口。
	HTTP map[string]HTTPRoute `yaml:"http"`
}

// LoggingConfig 日志配置。
type LoggingConfig struct {
	Level string `yaml:"level"`
}

// Config 顶层配置。
type Config struct {
	Server  ServerConfig  `yaml:"server"`
	HTTP    HTTPConfig    `yaml:"http"`
	// Backend 是默认后端 TCP 地址：连接未命中任何 HTTP 前缀路由时，
	// 整条连接原始透传到该地址。
	Backend string       `yaml:"backend"`
	Routes  RoutesConfig `yaml:"routes"`
	Logging LoggingConfig `yaml:"logging"`
}

// Defaults 返回一份带全部默认值的配置。未在配置文件中出现的字段
// 将保留这里的默认值。
func Defaults() *Config {
	return &Config{
		Server: ServerConfig{
			Listen:            "0.0.0.0:8000",
			ReadHeaderTimeout: 10 * time.Second,
		},
		HTTP: HTTPConfig{
			ConnectTimeout: 5 * time.Second,
		},
		Backend: "127.0.0.1:8080",
		Routes: RoutesConfig{
			HTTP: map[string]HTTPRoute{},
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
		if err := decodeString(m, "tls_cert", &cfg.Server.TLSCertFile); err != nil {
			return err
		}
		if err := decodeString(m, "tls_key", &cfg.Server.TLSKeyFile); err != nil {
			return err
		}
		return decodeDuration(m, "read_header_timeout", &cfg.Server.ReadHeaderTimeout)
	}); err != nil {
		return nil, fmt.Errorf("section server: %w", err)
	}

	if err := applySection(root, "http", func(m map[string]any) error {
		if err := decodeDuration(m, "connect_timeout", &cfg.HTTP.ConnectTimeout); err != nil {
			return err
		}
		return decodeBool(m, "tls_skip_verify", &cfg.HTTP.TLSSkipVerify)
	}); err != nil {
		return nil, fmt.Errorf("section http: %w", err)
	}

	if err := applySection(root, "routes", func(m map[string]any) error {
		return decodeHTTPRoutes(m, "http", cfg.Routes.HTTP)
	}); err != nil {
		return nil, fmt.Errorf("section routes: %w", err)
	}

	if err := decodeString(root, "backend", &cfg.Backend); err != nil {
		return nil, fmt.Errorf("field backend: %w", err)
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
	if c.Server.ReadHeaderTimeout <= 0 {
		return fmt.Errorf("server.read_header_timeout must be > 0")
	}
	if c.HTTP.ConnectTimeout <= 0 {
		return fmt.Errorf("http.connect_timeout must be > 0")
	}
	if c.Backend == "" {
		return fmt.Errorf("backend must not be empty")
	}
	if c.Server.TLSEnabled() && (c.Server.TLSCertFile == "" || c.Server.TLSKeyFile == "") {
		return fmt.Errorf("server.tls_cert and server.tls_key must be configured together")
	}
	for prefix, route := range c.Routes.HTTP {
		if !strings.HasPrefix(prefix, "/") {
			return fmt.Errorf("routes.http prefix %q must start with '/'", prefix)
		}
		if route.Backend == "" {
			return fmt.Errorf("routes.http[%s]: backend must not be empty", prefix)
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

func decodeBool(m map[string]any, key string, dst *bool) error {
	v, ok := m[key]
	if !ok || v == nil {
		return nil
	}
	b, err := parseBool(v)
	if err != nil {
		return fmt.Errorf("field %s: %w", key, err)
	}
	*dst = b
	return nil
}
