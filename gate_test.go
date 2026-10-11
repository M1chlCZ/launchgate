package main

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func fixture(t *testing.T) (http.Handler, string, *atomic.Int32) {
	t.Helper()
	dir := t.TempDir()
	if err := initializeStore(dir); err != nil {
		t.Fatal(err)
	}
	if err := setMode(dir, "preview"); err != nil {
		t.Fatal(err)
	}
	hits := &atomic.Int32{}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if strings.Contains(r.Header.Get("Cookie"), "launchgate_preview") {
			t.Error("invitation cookie leaked upstream")
		}
		w.Header().Set("Cache-Control", "public, max-age=31536000")
		w.Header().Set("Cloudflare-Cdn-Cache-Control", "public,max-age=31536000")
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, r.URL.RequestURI()+"|"+r.Header.Get("X-Real-IP")+"|"+r.Header.Get("X-Forwarded-Proto"))
	}))
	t.Cleanup(upstream.Close)
	gate, err := newGateway(config{
		Origin: "https://example.test", Frontend: upstream.URL, Backend: upstream.URL,
		StateDir: dir, TrustedProxy: "127.0.0.1/32",
		BypassRoutes: []string{"/api/v1/webhooks/payments/provider"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return gate, dir, hits
}

func request(g http.Handler, method, path, body string, cookie *http.Cookie) *httptest.ResponseRecorder {
	return requestWithHost(g, method, "example.test", path, body, cookie)
}

func requestWithHost(g http.Handler, method, host, path, body string, cookie *http.Cookie) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "https://"+host+path, strings.NewReader(body))
	r.RemoteAddr = "127.0.0.1:54321"
	r.Header.Set("Origin", "https://example.test")
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Real-IP", "203.0.113.9")
	if cookie != nil {
		r.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	g.ServeHTTP(w, r)
	return w
}

func unlock(t *testing.T, g http.Handler, token string) *http.Cookie {
	t.Helper()
	w := request(g, "POST", accessPath, `{"token":"`+token+`"}`, nil)
	if w.Code != 204 {
		t.Fatalf("unlock status %d: %s", w.Code, w.Body.String())
	}
	cookies := w.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("cookies: %v", cookies)
	}
	c := cookies[0]
	if !c.Secure || !c.HttpOnly || c.Path != "/" || c.Domain != "" || c.SameSite != http.SameSiteLaxMode {
		t.Fatalf("unsafe cookie: %+v", c)
	}
	return c
}

func TestAnonymousCannotReachApplication(t *testing.T) {
	t.Parallel()
	g, _, hits := fixture(t)
	for _, p := range []string{"/", "/en", "/products/test", "/admin", "/api/v1/catalog", "/media/private.png", "/_next/static/app.js", "/_next/image?url=%2Fmedia%2Fprivate.png&w=640&q=75", "/sitemap.xml"} {
		w := request(g, "GET", p, "", nil)
		if w.Code != 200 && w.Code != 403 && w.Code != 404 {
			t.Errorf("%s: %d", p, w.Code)
		}
		if !strings.Contains(w.Header().Get("Cache-Control"), "no-store") {
			t.Errorf("cache enabled at %s", p)
		}
	}
	if hits.Load() != 0 {
		t.Fatalf("anonymous upstream requests: %d", hits.Load())
	}
	if !strings.Contains(request(g, "GET", "/", "", nil).Body.String(), "Coming soon") {
		t.Error("maintenance page missing")
	}
	if !strings.Contains(request(g, "GET", "/en", "", nil).Body.String(), "Coming soon") {
		t.Error("locale maintenance page missing")
	}
}

func TestCrawlerPolicyFollowsStoreMode(t *testing.T) {
	t.Parallel()
	g, dir, hits := fixture(t)
	previewRobots := request(g, "GET", "/robots.txt", "", nil)
	if previewRobots.Code != 200 || previewRobots.Body.String() != "User-agent: *\nDisallow: /\n" ||
		!strings.Contains(previewRobots.Header().Get("X-Robots-Tag"), "noindex") {
		t.Fatalf(
			"preview robots = %d %q %q",
			previewRobots.Code,
			previewRobots.Body.String(),
			previewRobots.Header().Get("X-Robots-Tag"),
		)
	}
	if !strings.Contains(request(g, "GET", "/products/test", "", nil).Header().Get("X-Robots-Tag"), "noindex") {
		t.Fatal("preview catalog page is indexable")
	}
	if hits.Load() != 0 {
		t.Fatalf("preview crawler policy reached upstream: %d", hits.Load())
	}
	if err := setMode(dir, "public"); err != nil {
		t.Fatal(err)
	}
	publicRobots := request(g, "GET", "/robots.txt", "", nil)
	if publicRobots.Code != 200 || !strings.HasPrefix(publicRobots.Body.String(), "/robots.txt|") {
		t.Fatalf("public robots = %d %q", publicRobots.Code, publicRobots.Body.String())
	}
	if publicRobots.Header().Get("X-Robots-Tag") != "" {
		t.Fatalf("public robots carries %q", publicRobots.Header().Get("X-Robots-Tag"))
	}
	for _, p := range []string{"/", "/en", "/products/test", "/en/products/test", "/sitemap.xml"} {
		w := request(g, "GET", p, "", nil)
		if w.Code != 200 || w.Header().Get("X-Robots-Tag") != "" {
			t.Fatalf("public %s = %d %q", p, w.Code, w.Header().Get("X-Robots-Tag"))
		}
		if !strings.Contains(w.Header().Get("Cache-Control"), "no-store") {
			t.Fatalf("public %s enabled caching", p)
		}
	}
	for _, p := range []string{
		"/admin", "/api/v1/catalog", "/media/private.png", "/account", "/en/account",
		"/cart", "/en/cart", "/checkout", "/en/checkout", "/orders", "/en/orders",
		"/login", "/en/login", "/register", "/en/register", "/healthz", entryPath, "/en" + entryPath,
	} {
		if request(g, "GET", p, "", nil).Header().Get("X-Robots-Tag") == "" {
			t.Fatalf("private %s is indexable in public mode", p)
		}
	}
}

func TestInviteCookieExpiryAndImmediateRevocation(t *testing.T) {
	t.Parallel()
	g, dir, hits := fixture(t)
	invite, token, err := issueInvitation(dir, "reviewer", time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	stored, err := os.ReadFile(filepath.Join(dir, "invitations.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(stored), token) {
		t.Fatal("plaintext invitation stored")
	}
	cookie := unlock(t, g, token)
	for _, p := range []string{"/products/test?color=red", "/api/v1/catalog", "/media/file.png", "/_next/static/chunk.js"} {
		w := request(g, "GET", p, "", cookie)
		if w.Code != 200 || !strings.HasPrefix(w.Body.String(), p+"|") {
			t.Fatalf("proxy %s: %d %s", p, w.Code, w.Body.String())
		}
		if w.Header().Get("Cloudflare-Cdn-Cache-Control") != "no-store" {
			t.Fatal("upstream re-enabled cache")
		}
	}
	if hits.Load() != 4 {
		t.Fatal("expected four authenticated requests")
	}
	if !strings.Contains(request(g, "GET", "/api/v1/catalog", "", cookie).Body.String(), "|203.0.113.9|https") {
		t.Fatal("trusted proxy identity not forwarded")
	}
	if revokeErr := revokeInvitation(dir, invite.ID); revokeErr != nil {
		t.Fatal(revokeErr)
	}
	request(g, "GET", "/api/v1/catalog", "", cookie)
	if hits.Load() != 5 {
		t.Fatal("revoked cookie still works")
	}
	if request(g, "POST", accessPath, `{"token":"`+token+`"}`, nil).Code != 403 {
		t.Fatal("revoked link still works")
	}
	_, expired, err := issueInvitation(dir, "expired", time.Second, time.Now().Add(-time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if request(g, "POST", accessPath, `{"token":"`+expired+`"}`, nil).Code != 403 {
		t.Fatal("expired link works")
	}
}

func TestOnlyExactBypassPOSTBypassesInvitation(t *testing.T) {
	t.Parallel()
	g, _, hits := fixture(t)
	p := "/api/v1/webhooks/payments/provider"
	w := request(g, "POST", p, `{"test":true}`, nil)
	if w.Code != 200 || hits.Load() != 1 {
		t.Fatal("webhook not forwarded")
	}
	for _, variant := range []string{p + "/", p + "/../orders", p + "%2f..%2forders", "/api/v1/webhooks/payments/%70rovider", p + "?x=1"} {
		request(g, "POST", variant, `{}`, nil)
	}
	request(g, "GET", p, "", nil)
	if hits.Load() != 1 {
		t.Fatalf("webhook exception too broad: %d", hits.Load())
	}
}

func TestInvalidStoreAndClosedModeFailClosed(t *testing.T) {
	t.Parallel()
	g, dir, hits := fixture(t)
	_, token, err := issueInvitation(dir, "test", time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	cookie := unlock(t, g, token)
	if modeErr := setMode(dir, "closed"); modeErr != nil {
		t.Fatal(modeErr)
	}
	request(g, "GET", "/api/v1/catalog", "", cookie)
	if hits.Load() != 0 {
		t.Fatal("closed mode grants access")
	}
	if writeErr := os.WriteFile(
		filepath.Join(dir, "invitations.json"),
		[]byte(`{"mode":"public","invitations":`),
		0600,
	); writeErr != nil {
		t.Fatal(writeErr)
	}
	request(g, "GET", "/api/v1/catalog", "", cookie)
	if hits.Load() != 0 {
		t.Fatal("corrupt store grants access")
	}
}

func TestOriginHostAndIdentityBoundaries(t *testing.T) {
	t.Parallel()
	g, dir, hits := fixture(t)
	_, token, err := issueInvitation(dir, "test", time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for _, origin := range []string{"", "https://evil.example", "null"} {
		r := httptest.NewRequest(
			http.MethodPost,
			"https://example.test"+accessPath,
			strings.NewReader(`{"token":"`+token+`"}`),
		)
		r.Header.Set("Origin", origin)
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		g.ServeHTTP(w, r)
		if w.Code != 403 {
			t.Errorf("origin %q accepted: %d", origin, w.Code)
		}
	}
	cookie := unlock(t, g, token)
	r := httptest.NewRequest(http.MethodGet, "https://evil.example/api/v1/catalog", nil)
	r.AddCookie(cookie)
	w := httptest.NewRecorder()
	g.ServeHTTP(w, r)
	if w.Code != 421 || hits.Load() != 0 {
		t.Fatal("unknown host accepted")
	}
	r = httptest.NewRequest(http.MethodGet, "https://example.test/api/v1/catalog", nil)
	r.AddCookie(cookie)
	r.RemoteAddr = "198.51.100.3:1234"
	r.Header.Set("X-Real-IP", "1.2.3.4")
	r.Header.Set("X-Forwarded-For", "1.2.3.4")
	r.Header.Set("Forwarded", "for=1.2.3.4")
	w = httptest.NewRecorder()
	g.ServeHTTP(w, r)
	if !strings.Contains(w.Body.String(), "|198.51.100.3|https") {
		t.Fatalf("spoofed identity: %s", w.Body.String())
	}
	if hits.Load() != 1 {
		t.Fatalf("authenticated request count: %d", hits.Load())
	}
	if getResponse := request(g, "GET", accessPath, "", cookie); getResponse.Code != 403 {
		t.Fatal("GET accepted for invitation exchange")
	}
}

func TestStoreRejectsInvalidAndConcurrentUpdates(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := initializeStore(dir); err != nil {
		t.Fatal(err)
	}
	if err := initializeStore(dir); err == nil {
		t.Fatal("overwrote existing store")
	}
	if err := setMode(dir, "typo"); err == nil {
		t.Fatal("invalid mode accepted")
	}
	if _, _, err := issueInvitation(dir, "test", 0, time.Now()); err == nil {
		t.Fatal("zero expiry accepted")
	}
	errors := make(chan error, 12)
	for range 12 {
		go func() { _, _, err := issueInvitation(dir, "parallel", time.Hour, time.Now()); errors <- err }()
	}
	for range 12 {
		if err := <-errors; err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(filepath.Join(dir, "invitations.json"))
	if err != nil {
		t.Fatal(err)
	}
	var saved struct {
		Invitations []json.RawMessage `json:"invitations"`
	}
	if decodeErr := json.Unmarshal(raw, &saved); decodeErr != nil {
		t.Fatal(decodeErr)
	}
	if len(saved.Invitations) != 12 {
		t.Fatalf("lost updates: %d", len(saved.Invitations))
	}
}

func TestUsageCountersIncrementAndPersist(t *testing.T) {
	t.Parallel()
	g, dir, _ := fixture(t)
	invite, token, err := issueInvitation(dir, "counter", time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(token) != encodedTokenLength {
		t.Fatalf("token length %d", len(token))
	}
	unlock(t, g, token)
	unlock(t, g, token)
	s, err := loadStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Invitations) != 1 || s.Invitations[0].ID != invite.ID || s.Invitations[0].Uses != 2 ||
		s.Invitations[0].LastUsedAt.IsZero() || s.Invitations[0].MaxUses != 0 {
		t.Fatalf("counters: %+v", s.Invitations)
	}
	firstUse := s.Invitations[0].LastUsedAt
	reloaded, err := newGateway(config{
		Origin: "https://example.test", Frontend: "http://127.0.0.1:1", Backend: "http://127.0.0.1:1",
		StateDir: dir,
	})
	if err != nil {
		t.Fatal(err)
	}
	if w := request(reloaded, "POST", accessPath, `{"token":"`+token+`"}`, nil); w.Code != 204 {
		t.Fatalf("admission after reload: %d %s", w.Code, w.Body.String())
	}
	s, err = loadStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if s.Invitations[0].Uses != 3 || s.Invitations[0].LastUsedAt.Before(firstUse) {
		t.Fatalf("counters after reload: %+v", s.Invitations)
	}
}

func TestListShowsUsageCounters(t *testing.T) {
	t.Parallel()
	g, dir, _ := fixture(t)
	_, limited, err := issueInvitationWithLimit(dir, "limited", time.Hour, 5, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	unlock(t, g, limited)
	s, err := loadStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	stamp := s.Invitations[0].LastUsedAt.Format(time.RFC3339)
	var out bytes.Buffer
	if err := listCommand(dir, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "limited\t1/5\t"+stamp) {
		t.Fatalf("list output: %q", out.String())
	}
	if _, _, err := issueInvitation(dir, "unlimited", time.Hour, time.Now()); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := listCommand(dir, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "unlimited\t0\t-") {
		t.Fatalf("list output: %q", out.String())
	}
}

func TestMaxUsesExhaustionRefusesAndKeepsInvitation(t *testing.T) {
	g, dir, _ := fixture(t)
	invite, token, err := issueInvitationWithLimit(dir, "limited", time.Hour, 2, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	log.SetOutput(&logs)
	defer log.SetOutput(os.Stderr)
	first := request(g, "POST", accessPath, `{"token":"`+token+`"}`, nil)
	if first.Code != 204 {
		t.Fatalf("first admission: %d", first.Code)
	}
	cookies := first.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("cookies: %v", cookies)
	}
	if second := request(g, "POST", accessPath, `{"token":"`+token+`"}`, nil); second.Code != 204 {
		t.Fatalf("second admission: %d", second.Code)
	}
	refused := request(g, "POST", accessPath, `{"token":"`+token+`"}`, nil)
	if refused.Code != 403 || !strings.Contains(refused.Body.String(), "Invalid or expired invitation") {
		t.Fatalf("exhausted: %d %q", refused.Code, refused.Body.String())
	}
	if !strings.Contains(logs.String(), "maximum uses reached") || !strings.Contains(logs.String(), invite.ID) {
		t.Fatalf("log: %q", logs.String())
	}
	s, err := loadStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Invitations) != 1 || s.Invitations[0].ID != invite.ID || s.Invitations[0].Uses != 2 {
		t.Fatalf("invitation state: %+v", s.Invitations)
	}
	if w := request(g, "GET", "/api/v1/catalog", "", cookies[0]); w.Code != 200 {
		t.Fatalf("cookie after exhaustion: %d", w.Code)
	}
}

func TestInvitationWithoutLimitAdmitsRepeatedly(t *testing.T) {
	t.Parallel()
	g, dir, _ := fixture(t)
	_, token, err := issueInvitation(dir, "plain", time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for range 4 {
		if w := request(g, "POST", accessPath, `{"token":"`+token+`"}`, nil); w.Code != 204 {
			t.Fatalf("admission: %d %s", w.Code, w.Body.String())
		}
	}
	s, err := loadStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if s.Invitations[0].Uses != 4 || s.Invitations[0].MaxUses != 0 || s.Invitations[0].LastUsedAt.IsZero() {
		t.Fatalf("counters: %+v", s.Invitations)
	}
}

func TestStoreRejectsInvalidCounters(t *testing.T) {
	t.Parallel()
	hash := strings.Repeat("ab", tokenBytes)
	expiry := "2030-01-01T00:00:00Z"
	cases := []string{
		`{"mode":"preview","invitations":[{"id":"a","label":"l","token_hash":"` + hash + `","expires_at":"` + expiry + `","uses":-1}]}`,
		`{"mode":"preview","invitations":[{"id":"a","label":"l","token_hash":"` + hash + `","expires_at":"` + expiry + `","max_uses":-1}]}`,
		`{"mode":"preview","invitations":[{"id":"a","label":"l","token_hash":"` + hash + `","expires_at":"` + expiry + `","max_uses":100001}]}`,
		`{"mode":"preview","invitations":[{"id":"a","label":"l","token_hash":"` + hash + `","expires_at":"` + expiry + `","uses":3,"max_uses":2}]}`,
	}
	for _, content := range cases {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "invitations.json"), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadStore(dir); err == nil {
			t.Errorf("invalid counters accepted: %s", content)
		}
	}
	dir := t.TempDir()
	legacy := `{"mode":"preview","invitations":[{"id":"a","label":"l","token_hash":"` + hash +
		`","expires_at":"` + expiry + `"}]}`
	if err := os.WriteFile(filepath.Join(dir, "invitations.json"), []byte(legacy), 0600); err != nil {
		t.Fatal(err)
	}
	s, err := loadStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if s.Invitations[0].Uses != 0 || s.Invitations[0].MaxUses != 0 || !s.Invitations[0].LastUsedAt.IsZero() {
		t.Fatalf("legacy record: %+v", s.Invitations[0])
	}
}

func TestIssueCommandMaxUsesFlag(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := initializeStore(dir); err != nil {
		t.Fatal(err)
	}
	cfg := config{Origin: "https://example.test", StateDir: dir}
	var out bytes.Buffer
	if err := issueCommand(cfg, []string{"-label", "limited", "-max-uses", "3"}, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "Max uses: 3") {
		t.Fatalf("issue output: %q", out.String())
	}
	s, err := loadStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Invitations) != 1 || s.Invitations[0].MaxUses != 3 {
		t.Fatalf("issued invitations: %+v", s.Invitations)
	}
	for _, value := range []string{"-1", "100001"} {
		if err := issueCommand(cfg, []string{"-label", "bad", "-max-uses", value}, &out); err == nil {
			t.Fatalf("max uses %s accepted", value)
		}
	}
}

func TestReplacementInvitationIsExchangedBeforeEntering(t *testing.T) {
	t.Parallel()
	g, dir, hits := fixture(t)
	first, token, err := issueInvitation(dir, "first", time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	cookie := unlock(t, g, token)
	w := request(g, "GET", entryPath, "", cookie)
	if w.Code != 200 || w.Header().Get("Location") != "" ||
		!strings.Contains(w.Body.String(), "history.replaceState") ||
		hits.Load() != 0 {
		t.Fatal("existing cookie bypassed invitation landing")
	}
	_, replacement, err := issueInvitation(dir, "replacement", time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	cookie = unlock(t, g, replacement)
	if revokeErr := revokeInvitation(dir, first.ID); revokeErr != nil {
		t.Fatal(revokeErr)
	}
	request(g, "GET", "/api/v1/catalog", "", cookie)
	if hits.Load() != 1 {
		t.Fatal("replacement invitation not active")
	}
}
