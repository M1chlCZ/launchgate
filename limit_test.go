package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock(now time.Time) *fakeClock {
	return &fakeClock{now: now}
}

func (clock *fakeClock) Now() time.Time {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	return clock.now
}

func (clock *fakeClock) Advance(delta time.Duration) {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	clock.now = clock.now.Add(delta)
}

func useClock(g http.Handler, clock *fakeClock) {
	gate := g.(*gateway)
	gate.clock = clock.Now
	gate.clientFailures = newFailureLimiter(maxFailuresPerIP, failureWindow, limiterCapacity, clock.Now)
	gate.invitationFailures = newFailureLimiter(maxFailuresPerInvitation, failureWindow, limiterCapacity, clock.Now)
}

func accessFrom(t *testing.T, g http.Handler, ip, body string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, "https://example.test"+accessPath, strings.NewReader(body))
	request.RemoteAddr = "127.0.0.1:54321"
	request.Header.Set("Origin", "https://example.test")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Real-IP", ip)
	recorder := httptest.NewRecorder()
	g.ServeHTTP(recorder, request)
	return recorder
}

func TestTOTPBruteForceLockoutAndWindowExpiry(t *testing.T) {
	t.Parallel()
	g, dir, _ := fixture(t)
	clock := newFakeClock(time.Now())
	useClock(g, clock)
	invite, token, err := issueInvitationWithOptions(
		dir,
		issueOptions{Label: "locked", TTL: time.Hour, TOTP: true},
		clock.Now(),
	)
	if err != nil {
		t.Fatal(err)
	}
	for attempt := 1; attempt <= maxFailuresPerInvitation; attempt++ {
		wrong := request(g, "POST", accessPath, `{"token":"`+token+`","code":"000000"}`, nil)
		want := http.StatusUnauthorized
		if attempt == maxFailuresPerInvitation {
			want = http.StatusTooManyRequests
		}
		if wrong.Code != want {
			t.Fatalf("attempt %d: %d", attempt, wrong.Code)
		}
		if want == http.StatusTooManyRequests && wrong.Header().Get("Retry-After") == "" {
			t.Fatal("missing Retry-After header")
		}
	}
	code, err := totpCode(invite.TOTPSecret, clock.Now().Unix()/totpPeriod)
	if err != nil {
		t.Fatal(err)
	}
	locked := request(g, "POST", accessPath, `{"token":"`+token+`","code":"`+code+`"}`, nil)
	if locked.Code != http.StatusTooManyRequests {
		t.Fatalf("locked invitation admitted: %d", locked.Code)
	}
	clock.Advance(failureWindow + time.Second)
	code, err = totpCode(invite.TOTPSecret, clock.Now().Unix()/totpPeriod)
	if err != nil {
		t.Fatal(err)
	}
	if w := request(g, "POST", accessPath, `{"token":"`+token+`","code":"`+code+`"}`, nil); w.Code != http.StatusNoContent {
		t.Fatalf("code after window: %d %s", w.Code, w.Body.String())
	}
}

func TestSuccessfulAdmissionClearsInvitationFailures(t *testing.T) {
	t.Parallel()
	g, dir, _ := fixture(t)
	clock := newFakeClock(time.Now())
	useClock(g, clock)
	invite, token, err := issueInvitationWithOptions(
		dir,
		issueOptions{Label: "retry", TTL: time.Hour, TOTP: true},
		clock.Now(),
	)
	if err != nil {
		t.Fatal(err)
	}
	for range maxFailuresPerInvitation - 1 {
		if w := request(g, "POST", accessPath, `{"token":"`+token+`","code":"111111"}`, nil); w.Code != http.StatusUnauthorized {
			t.Fatalf("wrong code: %d", w.Code)
		}
	}
	code, err := totpCode(invite.TOTPSecret, clock.Now().Unix()/totpPeriod)
	if err != nil {
		t.Fatal(err)
	}
	if w := request(g, "POST", accessPath, `{"token":"`+token+`","code":"`+code+`"}`, nil); w.Code != http.StatusNoContent {
		t.Fatalf("valid code: %d %s", w.Code, w.Body.String())
	}
	for range maxFailuresPerInvitation - 1 {
		if w := request(g, "POST", accessPath, `{"token":"`+token+`","code":"111111"}`, nil); w.Code != http.StatusUnauthorized {
			t.Fatalf("wrong code after success: %d", w.Code)
		}
	}
}

func TestIPFailureLimitSpansInvitations(t *testing.T) {
	t.Parallel()
	g, dir, _ := fixture(t)
	clock := newFakeClock(time.Now())
	useClock(g, clock)
	_, token, err := issueInvitation(dir, "ip", time.Hour, clock.Now())
	if err != nil {
		t.Fatal(err)
	}
	for attempt := 1; attempt <= maxFailuresPerIP; attempt++ {
		wrong := accessFrom(t, g, "203.0.113.50", `{"token":"invalid-token"}`)
		want := http.StatusForbidden
		if attempt == maxFailuresPerIP {
			want = http.StatusTooManyRequests
		}
		if wrong.Code != want {
			t.Fatalf("attempt %d: %d", attempt, wrong.Code)
		}
	}
	if w := accessFrom(t, g, "203.0.113.50", `{"token":"`+token+`"}`); w.Code != http.StatusTooManyRequests {
		t.Fatalf("locked IP admitted: %d", w.Code)
	}
	if w := accessFrom(t, g, "203.0.113.51", `{"token":"`+token+`"}`); w.Code != http.StatusNoContent {
		t.Fatalf("other IP blocked: %d %s", w.Code, w.Body.String())
	}
	clock.Advance(failureWindow + time.Second)
	if w := accessFrom(t, g, "203.0.113.50", `{"token":"`+token+`"}`); w.Code != http.StatusNoContent {
		t.Fatalf("IP not released after window: %d", w.Code)
	}
}

func TestFailureLimiterEvictsOldestAtCapacity(t *testing.T) {
	t.Parallel()
	clock := newFakeClock(time.Now())
	limiter := newFailureLimiter(2, time.Minute, 2, clock.Now)
	limiter.fail("a")
	clock.Advance(time.Second)
	limiter.fail("b")
	clock.Advance(time.Second)
	limiter.fail("c")
	if _, blocked := limiter.locked("a"); blocked {
		t.Fatal("oldest entry was not evicted")
	}
	limiter.fail("b")
	if _, blocked := limiter.locked("b"); !blocked {
		t.Fatal("entry at the limit is not locked")
	}
	if retryAfter, blocked := limiter.locked("b"); blocked && retryAfter <= 0 {
		t.Fatal("locked entry has no retry window")
	}
	if _, blocked := limiter.locked("c"); blocked {
		t.Fatal("newest entry is locked too early")
	}
}
