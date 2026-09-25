package main

import (
	"testing"
)

func TestSplitList(t *testing.T) {
	got := splitList(" a, b ,,c ")
	want := []string{"a", "b", "c"}
	if len(got) != len(want) {
		t.Fatalf("splitList = %#v", got)
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("splitList = %#v", got)
		}
	}
}

func TestLoadConfigDefaults(t *testing.T) {
	t.Setenv("LAUNCH_ORIGIN", "https://example.test")
	t.Setenv("LAUNCH_FRONTEND", "")
	t.Setenv("LAUNCH_BACKEND", "")
	t.Setenv("LAUNCH_STATE_DIR", "")
	t.Setenv("LAUNCH_TRUSTED_PROXY", "")
	t.Setenv("LAUNCH_BYPASS_ROUTES", "")
	t.Setenv("LAUNCH_PAGE_DIR", "")
	cfg := loadConfig()
	if cfg.Frontend != "http://frontend:3000" || cfg.Backend != "http://backend:8080" ||
		cfg.StateDir != "/data/launch" || cfg.TrustedProxy != "" || len(cfg.BypassRoutes) != 0 || cfg.PageDir != "" {
		t.Fatalf("unexpected defaults: %+v", cfg)
	}
}

func TestLoadConfigReadsValues(t *testing.T) {
	t.Setenv("LAUNCH_ORIGIN", "https://example.test")
	t.Setenv("LAUNCH_FRONTEND", "http://frontend:3000")
	t.Setenv("LAUNCH_BACKEND", "http://backend:8080")
	t.Setenv("LAUNCH_STATE_DIR", "/tmp/launch")
	t.Setenv("LAUNCH_TRUSTED_PROXY", "192.0.2.1/32")
	t.Setenv("LAUNCH_BYPASS_ROUTES", "/api/webhooks, /api/callbacks")
	t.Setenv("LAUNCH_PAGE_DIR", "/tmp/page")
	cfg := loadConfig()
	if cfg.Origin != "https://example.test" || cfg.StateDir != "/tmp/launch" || cfg.TrustedProxy != "192.0.2.1/32" ||
		len(cfg.BypassRoutes) != 2 || cfg.BypassRoutes[0] != "/api/webhooks" || cfg.BypassRoutes[1] != "/api/callbacks" ||
		cfg.PageDir != "/tmp/page" {
		t.Fatalf("unexpected config: %+v", cfg)
	}
}

func TestNewGatewayValidation(t *testing.T) {
	dir := t.TempDir()
	if err := initializeStore(dir); err != nil {
		t.Fatal(err)
	}
	base := config{Origin: "https://example.test", Frontend: "http://127.0.0.1:1", Backend: "http://127.0.0.1:1", StateDir: dir}
	if _, err := newGateway(base); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	cases := []struct {
		name   string
		mutate func(*config)
	}{
		{"origin missing", func(c *config) { c.Origin = "" }},
		{"origin insecure", func(c *config) { c.Origin = "http://example.test" }},
		{"origin with path", func(c *config) { c.Origin = "https://example.test/app" }},
		{"origin with credentials", func(c *config) { c.Origin = "https://user@example.test" }},
		{"upstream invalid", func(c *config) { c.Backend = "ftp://example.test" }},
		{"trusted proxy range", func(c *config) { c.TrustedProxy = "10.0.0.0/8" }},
		{"trusted proxy invalid", func(c *config) { c.TrustedProxy = "not-a-cidr" }},
		{"bypass route relative", func(c *config) { c.BypassRoutes = []string{"webhook"} }},
	}
	for _, tc := range cases {
		cfg := base
		tc.mutate(&cfg)
		if _, err := newGateway(cfg); err == nil {
			t.Errorf("%s: expected error", tc.name)
		}
	}
	loopback := base
	loopback.Origin = "http://localhost:8090"
	if _, err := newGateway(loopback); err != nil {
		t.Fatalf("loopback origin rejected: %v", err)
	}
}
