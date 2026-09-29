package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"path"
	"strings"
	"time"
)

const (
	accessPath         = "/_launch/access"
	logoutPath         = "/_launch/logout"
	entryPath          = "/_launch/enter"
	healthPath         = "/healthz"
	previewCookie      = "__Host-launchgate_preview"
	maxBypassBodyBytes = 64 << 10
	maxAccessBodyBytes = 1 << 10
	maxLocaleParts     = 2
	localePartLength   = 2

	dialTimeout           = 5 * time.Second
	dialKeepAlive         = 30 * time.Second
	maxIdleConns          = 50
	maxIdleConnsPerHost   = 25
	idleConnTimeout       = 90 * time.Second
	responseHeaderTimeout = 60 * time.Second
	tlsHandshakeTimeout   = 5 * time.Second
)

type gateway struct {
	config            config
	host              string
	trusted           netip.Prefix
	trustedSet        bool
	frontend, backend *httputil.ReverseProxy
	page              *pageRenderer
}

func newGateway(cfg config) (http.Handler, error) {
	origin, err := parseOrigin(cfg.Origin)
	if err != nil {
		return nil, err
	}
	var trusted netip.Prefix
	trustedSet := false
	if cfg.TrustedProxy != "" {
		trusted, err = netip.ParsePrefix(cfg.TrustedProxy)
		if err != nil || (trusted.Addr().Is4() && trusted.Bits() != 32) ||
			(!trusted.Addr().Is4() && trusted.Bits() != 128) {
			return nil, errors.New("LAUNCH_TRUSTED_PROXY must be one explicit host address")
		}
		trustedSet = true
	}
	for _, route := range cfg.BypassRoutes {
		if !strings.HasPrefix(route, "/") {
			return nil, errors.New("LAUNCH_BYPASS_ROUTES entries must start with /")
		}
	}
	g := &gateway{config: cfg, host: origin.Host, trusted: trusted, trustedSet: trustedSet}
	if g.frontend, err = g.proxy(cfg.Frontend); err != nil {
		return nil, err
	}
	if g.backend, err = g.proxy(cfg.Backend); err != nil {
		return nil, err
	}
	if g.page, err = loadPage(cfg.PageDir); err != nil {
		return nil, err
	}
	if _, err = loadStore(cfg.StateDir); err != nil {
		return nil, errors.New("initialize a valid invitation store before starting")
	}
	return g, nil
}

func parseOrigin(raw string) (*url.URL, error) {
	origin, err := url.Parse(raw)
	if err != nil || origin.Host == "" || origin.User != nil || origin.Path != "" || origin.RawQuery != "" ||
		origin.Fragment != "" {
		return nil, errors.New("LAUNCH_ORIGIN must be an origin without a path")
	}
	loopback := origin.Hostname() == "localhost" || origin.Hostname() == "127.0.0.1" || origin.Hostname() == "::1"
	if origin.Scheme != "https" && (origin.Scheme != "http" || !loopback) {
		return nil, errors.New("LAUNCH_ORIGIN must use HTTPS")
	}
	return origin, nil
}

// noCache keeps every gate response private and uncacheable.
func noCache(h http.Header) {
	h.Set("Cache-Control", "private, no-store")
	h.Set("CDN-Cache-Control", "no-store")
	h.Set("Cloudflare-Cdn-Cache-Control", "no-store")
	h.Set("Pragma", "no-cache")
}

// noIndex keeps a response out of search results. The gate applies this header
// to every response and removes it only for public paths in public mode.
func noIndex(h http.Header) {
	h.Set("X-Robots-Tag", "noindex, nofollow, noarchive")
}

// privatePath reports whether a path stays non-indexable in public mode. A
// locale prefix such as /en is removed before matching.
func privatePath(pathname string) bool {
	normalized := stripLocale(strings.ToLower(path.Clean(pathname)))
	switch firstSegment(normalized) {
	case "/account",
		"/admin",
		"/api",
		"/cart",
		"/checkout",
		"/healthz",
		"/login",
		"/media",
		"/orders",
		"/register",
		"/_launch",
		"/_next":
		return true
	default:
		return false
	}
}

// firstSegment returns the leading path segment of an absolute path. It
// returns an empty string for a path that does not start with a slash.
func firstSegment(pathname string) string {
	if !strings.HasPrefix(pathname, "/") {
		return ""
	}
	segment, _, _ := strings.Cut(strings.TrimPrefix(pathname, "/"), "/")
	return "/" + segment
}

func isEntryPath(pathname string) bool {
	return stripLocale(strings.ToLower(path.Clean(pathname))) == entryPath
}

func stripLocale(normalized string) string {
	rest := strings.TrimPrefix(normalized, "/")
	segment, tail, hasTail := strings.Cut(rest, "/")
	if !isLocale(segment) {
		return normalized
	}
	if !hasTail {
		return "/"
	}
	return "/" + tail
}

func isLocale(segment string) bool {
	parts := strings.Split(segment, "-")
	if len(parts) > maxLocaleParts {
		return false
	}
	for _, part := range parts {
		if len(part) != localePartLength {
			return false
		}
		for _, ch := range part {
			if (ch < 'a' || ch > 'z') && (ch < 'A' || ch > 'Z') {
				return false
			}
		}
	}
	return true
}

func (g *gateway) clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return ""
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return ""
	}
	if g.trustedSet && g.trusted.Contains(addr.Unmap()) {
		if forwarded, parseErr := netip.ParseAddr(r.Header.Get("X-Real-IP")); parseErr == nil {
			return forwarded.Unmap().String()
		}
	}
	return addr.Unmap().String()
}

func (g *gateway) proxy(raw string) (*httputil.ReverseProxy, error) {
	target, err := url.Parse(raw)
	if err != nil || (target.Scheme != "http" && target.Scheme != "https") || target.Host == "" || target.User != nil ||
		target.RawQuery != "" ||
		target.Fragment != "" ||
		(target.Path != "" && target.Path != "/") {
		return nil, errors.New("invalid upstream origin")
	}
	return &httputil.ReverseProxy{
		Rewrite: func(p *httputil.ProxyRequest) {
			p.SetURL(target)
			p.Out.Host = g.host
			for _, h := range []string{"Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "X-Real-IP", "CF-Connecting-IP", "CF-Access-Jwt-Assertion", "CF-Access-Client-Id", "CF-Access-Client-Secret"} {
				p.Out.Header.Del(h)
			}
			ip := g.clientIP(p.In)
			p.Out.Header.Set("X-Real-IP", ip)
			p.Out.Header.Set("X-Forwarded-For", ip)
			p.Out.Header.Set("X-Forwarded-Host", g.host)
			p.Out.Header.Set("X-Forwarded-Proto", "https")
			p.Out.Header.Del("Cookie")
			for _, c := range p.In.Cookies() {
				if c.Name != previewCookie {
					p.Out.AddCookie(c)
				}
			}
		},
		Transport: &http.Transport{
			Proxy:                 nil,
			DialContext:           (&net.Dialer{Timeout: dialTimeout, KeepAlive: dialKeepAlive}).DialContext,
			MaxIdleConns:          maxIdleConns,
			MaxIdleConnsPerHost:   maxIdleConnsPerHost,
			IdleConnTimeout:       idleConnTimeout,
			ResponseHeaderTimeout: responseHeaderTimeout,
			TLSHandshakeTimeout:   tlsHandshakeTimeout,
		},
		ModifyResponse: func(r *http.Response) error { noCache(r.Header); return nil },
		ErrorLog:       discardLogger(),
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) {
			noCache(w.Header())
			http.Error(w, "Service temporarily unavailable", http.StatusBadGateway)
		},
	}, nil
}

func validInvitation(s invitationStore, token string, now time.Time) (invitation, bool) {
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(raw) != tokenBytes || len(token) != encodedTokenLength ||
		base64.RawURLEncoding.EncodeToString(raw) != token {
		return invitation{}, false
	}
	sum := sha256.Sum256([]byte(token))
	for _, i := range s.Invitations {
		hash, _ := hex.DecodeString(i.TokenHash)
		if subtle.ConstantTimeCompare(sum[:], hash) == 1 && now.Before(i.ExpiresAt) {
			return i, true
		}
	}
	return invitation{}, false
}

func (g *gateway) bypassRoute(r *http.Request) bool {
	if r.URL.RawQuery != "" {
		return false
	}
	for _, route := range g.config.BypassRoutes {
		if r.URL.Path == route && r.URL.EscapedPath() == route {
			return true
		}
	}
	return false
}

func backendPath(pathname string) bool {
	switch firstSegment(pathname) {
	case "/api", "/media":
		return true
	default:
		return false
	}
}

func (g *gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	noCache(w.Header())
	noIndex(w.Header())
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	if r.URL.Path == healthPath && (r.Method == http.MethodGet || r.Method == http.MethodHead) {
		g.health(w)
		return
	}
	host := strings.ToLower(strings.TrimSuffix(r.Host, ":443"))
	if host != g.host {
		http.Error(w, "Unknown host", http.StatusMisdirectedRequest)
		return
	}
	if r.Method == http.MethodPost && g.bypassRoute(r) {
		r.Body = http.MaxBytesReader(w, r.Body, maxBypassBodyBytes)
		g.backend.ServeHTTP(w, r)
		return
	}
	s, err := loadStore(g.config.StateDir)
	if err != nil {
		http.Error(w, "Service temporarily unavailable", http.StatusServiceUnavailable)
		return
	}
	if s.Mode == modePublic && !privatePath(r.URL.Path) {
		w.Header().Del("X-Robots-Tag")
	}
	if g.serveSpecial(w, r, s) {
		return
	}
	if g.allowed(s, r) {
		g.forward(w, r)
		return
	}
	if (r.Method == http.MethodGet || r.Method == http.MethodHead) && !backendPath(r.URL.Path) &&
		!strings.HasPrefix(r.URL.Path, "/_next/") {
		g.page.serve(w, r)
		return
	}
	http.Error(w, "Invitation required", http.StatusForbidden)
}

func (g *gateway) health(w http.ResponseWriter) {
	if _, err := loadStore(g.config.StateDir); err != nil {
		http.Error(w, "Not ready", http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (g *gateway) serveSpecial(w http.ResponseWriter, r *http.Request, s invitationStore) bool {
	switch {
	case r.URL.Path == "/robots.txt":
		if s.Mode == modePublic {
			g.frontend.ServeHTTP(w, r)
			return true
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = io.WriteString(w, "User-agent: *\nDisallow: /\n")
		return true
	case r.URL.Path == accessPath:
		g.access(w, r, s)
		return true
	case r.URL.Path == logoutPath:
		g.logout(w, r)
		return true
	case isEntryPath(r.URL.Path) && (r.Method == http.MethodGet || r.Method == http.MethodHead):
		g.page.serve(w, r)
		return true
	case strings.HasPrefix(r.URL.Path, "/_launch/"):
		http.NotFound(w, r)
		return true
	default:
		return false
	}
}

func (g *gateway) logout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || r.Header.Get("Origin") != g.config.Origin {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	http.SetCookie(
		w,
		&http.Cookie{
			Name:     previewCookie,
			Value:    "",
			Path:     "/",
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
			MaxAge:   -1,
		},
	)
	w.WriteHeader(http.StatusNoContent)
}

func (g *gateway) allowed(s invitationStore, r *http.Request) bool {
	if s.Mode == modePublic {
		return true
	}
	if s.Mode == modePreview {
		if c, cookieErr := r.Cookie(previewCookie); cookieErr == nil {
			_, valid := validInvitation(s, c.Value, time.Now())
			return valid
		}
	}
	return false
}

func (g *gateway) forward(w http.ResponseWriter, r *http.Request) {
	if backendPath(r.URL.Path) {
		g.backend.ServeHTTP(w, r)
		return
	}
	g.frontend.ServeHTTP(w, r)
}

func (g *gateway) access(w http.ResponseWriter, r *http.Request, s invitationStore) {
	if r.Method != http.MethodPost || r.Header.Get("Origin") != g.config.Origin || s.Mode != modePreview {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	if r.Header.Get("Content-Type") != "application/json" {
		http.Error(w, "JSON required", http.StatusUnsupportedMediaType)
		return
	}
	var body struct {
		Token string `json:"token"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxAccessBodyBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&body); err != nil {
		http.Error(w, "Invalid invitation", http.StatusForbidden)
		return
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		http.Error(w, "Invalid invitation", http.StatusForbidden)
		return
	}
	now := time.Now()
	i, ok := validInvitation(s, body.Token, now)
	if !ok {
		http.Error(w, "Invalid or expired invitation", http.StatusForbidden)
		return
	}
	expiry := i.ExpiresAt
	if limit := now.Add(7 * 24 * time.Hour); expiry.After(limit) {
		expiry = limit
	}
	http.SetCookie(
		w,
		&http.Cookie{
			Name:     previewCookie,
			Value:    body.Token,
			Path:     "/",
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
			Expires:  expiry,
			MaxAge:   max(1, int(expiry.Sub(now).Seconds())),
		},
	)
	w.WriteHeader(http.StatusNoContent)
}
