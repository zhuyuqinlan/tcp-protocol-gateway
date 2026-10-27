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
	if cfg.Server.Listen != "0.0.0.0:8000" {
		t.Errorf("listen = %q", cfg.Server.Listen)
	}
	if cfg.Server.ReadHeaderTimeout != 10*time.Second {
		t.Errorf("read_header_timeout = %v", cfg.Server.ReadHeaderTimeout)
	}
	if cfg.Server.TLSEnabled() {
		t.Error("tls should be disabled by default")
	}
	if cfg.HTTP.ConnectTimeout != 5*time.Second {
		t.Errorf("connect_timeout = %v", cfg.HTTP.ConnectTimeout)
	}
	if cfg.Backend != "127.0.0.1:8080" {
		t.Errorf("backend = %q", cfg.Backend)
	}
	if len(cfg.Routes.HTTP) != 0 {
		t.Errorf("default routes should be empty, got %+v", cfg.Routes)
	}
}

func TestLoadFromFile(t *testing.T) {
	content := `
# 网关配置示例
server:
  listen: "0.0.0.0:30000"  # 监听地址
  read_header_timeout: 3s
  tls_cert: "cert.pem"
  tls_key: "key.pem"

http:
  connect_timeout: 2s

backend: "127.0.0.1:9000"

routes:
  http:
    "/api": "127.0.0.1:9090"
    "/web": "127.0.0.1:9091"
    "/static":
      backend: "127.0.0.1:9092"
      strip_prefix: true

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
	if cfg.Server.ReadHeaderTimeout != 3*time.Second {
		t.Errorf("read_header_timeout = %v", cfg.Server.ReadHeaderTimeout)
	}
	if !cfg.Server.TLSEnabled() {
		t.Error("tls should be enabled")
	}
	if cfg.Server.TLSCertFile != "cert.pem" || cfg.Server.TLSKeyFile != "key.pem" {
		t.Errorf("tls files = %q / %q", cfg.Server.TLSCertFile, cfg.Server.TLSKeyFile)
	}
	if cfg.HTTP.ConnectTimeout != 2*time.Second {
		t.Errorf("connect_timeout = %v", cfg.HTTP.ConnectTimeout)
	}
	if cfg.Backend != "127.0.0.1:9000" {
		t.Errorf("backend = %q", cfg.Backend)
	}
	if cfg.Routes.HTTP["/api"] != (HTTPRoute{Backend: "127.0.0.1:9090"}) {
		t.Errorf("routes.http[/api] = %+v", cfg.Routes.HTTP["/api"])
	}
	if cfg.Routes.HTTP["/web"] != (HTTPRoute{Backend: "127.0.0.1:9091"}) {
		t.Errorf("routes.http[/web] = %+v", cfg.Routes.HTTP["/web"])
	}
	if cfg.Routes.HTTP["/static"] != (HTTPRoute{Backend: "127.0.0.1:9092", StripPrefix: true}) {
		t.Errorf("routes.http[/static] = %+v", cfg.Routes.HTTP["/static"])
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
	if cfg.Backend != "127.0.0.1:8080" {
		t.Errorf("backend = %q, want default", cfg.Backend)
	}
	if cfg.Server.ReadHeaderTimeout != 10*time.Second {
		t.Errorf("read_header_timeout = %v, want default", cfg.Server.ReadHeaderTimeout)
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
		{"bad duration", "server:\n  read_header_timeout: five\n"},
		{"bad level", "logging:\n  level: verbose\n"},
		{"empty listen", "server:\n  listen: \"\"\n"},
		{"empty backend", "backend: \"\"\n"},
		{"tls cert without key", "server:\n  tls_cert: \"cert.pem\"\n"},
		{"tls key without cert", "server:\n  tls_key: \"key.pem\"\n"},
		{"http prefix without slash", "routes:\n  http:\n    \"api\": \"1.2.3.4:80\"\n"},
		{"empty http backend", "routes:\n  http:\n    \"/api\": \"\"\n"},
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
