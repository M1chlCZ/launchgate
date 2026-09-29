package main

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writePageFiles(t *testing.T, dir, html, css, js string) {
	t.Helper()
	files := map[string]string{pageHTMLName: html}
	if css != "" {
		files[pageCSSName] = css
	}
	if js != "" {
		files[pageJSName] = js
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
}

func pageGateway(t *testing.T, pageDir string) (http.Handler, error) {
	t.Helper()
	store := t.TempDir()
	if err := initializeStore(store); err != nil {
		t.Fatal(err)
	}
	return newGateway(config{
		Origin: "https://example.test", Frontend: "http://127.0.0.1:1", Backend: "http://127.0.0.1:1",
		StateDir: store, PageDir: pageDir,
	})
}

func TestCustomPageFiles(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	writePageFiles(
		t,
		dir,
		`<html><head><style>{{.CSS}}</style></head><body><h1>Private</h1><script>{{.JS}}</script></body></html>`,
		"body{color:red}",
		"console.log(1)",
	)
	gate, err := pageGateway(t, dir)
	if err != nil {
		t.Fatal(err)
	}
	w := request(gate, "GET", "/", "", nil)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "Private") ||
		!strings.Contains(w.Body.String(), "body{color:red}") || !strings.Contains(w.Body.String(), "console.log(1)") {
		t.Fatalf("custom page = %d %q", w.Code, w.Body.String())
	}
	policy := w.Header().Get("Content-Security-Policy")
	if !strings.Contains(policy, cspHash("body{color:red}")) || !strings.Contains(policy, cspHash("console.log(1)")) {
		t.Fatalf("policy = %q", policy)
	}
	if request(gate, "HEAD", "/", "", nil).Code != 200 {
		t.Fatal("HEAD failed for custom page")
	}
}

func TestCustomPageWithoutStylesOrScripts(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	writePageFiles(t, dir, `<html><body><h1>Offline</h1></body></html>`, "", "")
	gate, err := pageGateway(t, dir)
	if err != nil {
		t.Fatal(err)
	}
	w := request(gate, "GET", "/", "", nil)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "Offline") {
		t.Fatalf("page = %d %q", w.Code, w.Body.String())
	}
	policy := w.Header().Get("Content-Security-Policy")
	if strings.Contains(policy, "style-src") || strings.Contains(policy, "script-src") {
		t.Fatalf("policy = %q", policy)
	}
}

func TestCustomPageRequiresHTML(t *testing.T) {
	t.Parallel()
	if _, err := pageGateway(t, t.TempDir()); err == nil {
		t.Fatal("missing page.html accepted")
	}
}

func TestCustomPageRejectsInvalidTemplate(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	writePageFiles(t, dir, `{{.Missing`, "", "")
	if _, err := pageGateway(t, dir); err == nil {
		t.Fatal("invalid template accepted")
	}
}
