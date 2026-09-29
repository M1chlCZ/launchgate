package main

import (
	"os"
	"strings"
)

type config struct {
	Origin       string
	Frontend     string
	Backend      string
	StateDir     string
	TrustedProxy string
	BypassRoutes []string
	PageDir      string
}

func loadConfig() config {
	return config{
		Origin:       strings.TrimSpace(os.Getenv("LAUNCH_ORIGIN")),
		Frontend:     env("LAUNCH_FRONTEND", "http://frontend:3000"),
		Backend:      env("LAUNCH_BACKEND", "http://backend:8080"),
		StateDir:     env("LAUNCH_STATE_DIR", "/data/launch"),
		TrustedProxy: strings.TrimSpace(os.Getenv("LAUNCH_TRUSTED_PROXY")),
		BypassRoutes: splitList(os.Getenv("LAUNCH_BYPASS_ROUTES")),
		PageDir:      strings.TrimSpace(os.Getenv("LAUNCH_PAGE_DIR")),
	}
}

func splitList(raw string) []string {
	items := []string{}
	for item := range strings.SplitSeq(raw, ",") {
		if item = strings.TrimSpace(item); item != "" {
			items = append(items, item)
		}
	}
	return items
}
