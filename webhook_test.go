package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func webhookFixture(t *testing.T) (http.Handler, string, chan []byte) {
	t.Helper()
	dir := t.TempDir()
	if err := initializeStore(dir); err != nil {
		t.Fatal(err)
	}
	if err := setMode(dir, "preview"); err != nil {
		t.Fatal(err)
	}
	bodies := make(chan []byte, 8)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("webhook method %s", r.Method)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("webhook content type %q", r.Header.Get("Content-Type"))
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("webhook body: %v", err)
		}
		bodies <- body
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(server.Close)
	gate, err := newGateway(config{
		Origin: "https://example.test", Frontend: "http://127.0.0.1:1", Backend: "http://127.0.0.1:1",
		StateDir: dir, TrustedProxy: "127.0.0.1/32", WebhookURL: server.URL,
	})
	if err != nil {
		t.Fatal(err)
	}
	return gate, dir, bodies
}

func accessRequest(g http.Handler, userAgent, token string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "https://example.test"+accessPath, strings.NewReader(`{"token":"`+token+`"}`))
	r.RemoteAddr = "127.0.0.1:54321"
	r.Header.Set("Origin", "https://example.test")
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Real-IP", "203.0.113.9")
	if userAgent != "" {
		r.Header.Set("User-Agent", userAgent)
	}
	w := httptest.NewRecorder()
	g.ServeHTTP(w, r)
	return w
}

func receiveWebhook(t *testing.T, bodies chan []byte) webhookEvent {
	t.Helper()
	select {
	case body := <-bodies:
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(body, &fields); err != nil {
			t.Fatalf("webhook json: %v", err)
		}
		if len(fields) != 5 {
			t.Fatalf("webhook json keys: %s", body)
		}
		for _, key := range []string{"invitation_id", "result", "timestamp", "client_ip", "user_agent"} {
			if _, ok := fields[key]; !ok {
				t.Fatalf("webhook json missing %q: %s", key, body)
			}
		}
		var event webhookEvent
		if err := json.Unmarshal(body, &event); err != nil {
			t.Fatalf("webhook json: %v", err)
		}
		return event
	case <-time.After(3 * time.Second):
		t.Fatal("webhook event not received")
		return webhookEvent{}
	}
}

func TestWebhookReceivesAdmitAndRefuseEvents(t *testing.T) {
	t.Parallel()
	g, dir, bodies := webhookFixture(t)
	invite, token, err := issueInvitationWithLimit(dir, "hooked", time.Hour, 1, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	sent := time.Now().Add(-time.Second)
	if w := accessRequest(g, "launchgate-test/1.0", token); w.Code != 204 {
		t.Fatalf("admission: %d %s", w.Code, w.Body.String())
	}
	admit := receiveWebhook(t, bodies)
	if admit.InvitationID != invite.ID || admit.Result != "admit" || admit.ClientIP != "203.0.113.9" ||
		admit.UserAgent != "launchgate-test/1.0" || admit.Timestamp.Before(sent) ||
		admit.Timestamp.After(time.Now().Add(time.Second)) {
		t.Fatalf("admit event: %+v", admit)
	}
	if w := accessRequest(g, "launchgate-test/1.0", token); w.Code != 403 {
		t.Fatalf("exhausted admission: %d", w.Code)
	}
	refuse := receiveWebhook(t, bodies)
	if refuse.InvitationID != invite.ID || refuse.Result != "refuse" || refuse.ClientIP != "203.0.113.9" ||
		refuse.UserAgent != "launchgate-test/1.0" {
		t.Fatalf("refuse event: %+v", refuse)
	}
}

func TestWebhookRefusesInvalidToken(t *testing.T) {
	t.Parallel()
	g, _, bodies := webhookFixture(t)
	if w := accessRequest(g, "launchgate-test/1.0", "not-a-real-token"); w.Code != 403 {
		t.Fatalf("invalid token: %d", w.Code)
	}
	event := receiveWebhook(t, bodies)
	if event.Result != "refuse" || event.InvitationID != "" || event.ClientIP != "203.0.113.9" {
		t.Fatalf("refuse event: %+v", event)
	}
}

func TestWebhookFailureDoesNotChangeResponses(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		handler http.HandlerFunc
		timeout time.Duration
	}{
		{"server error", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}, time.Second},
		{"timeout", func(_ http.ResponseWriter, _ *http.Request) {
			time.Sleep(200 * time.Millisecond)
		}, 50 * time.Millisecond},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := initializeStore(dir); err != nil {
				t.Fatal(err)
			}
			if err := setMode(dir, "preview"); err != nil {
				t.Fatal(err)
			}
			server := httptest.NewServer(tc.handler)
			t.Cleanup(server.Close)
			gate, err := newGateway(config{
				Origin: "https://example.test", Frontend: "http://127.0.0.1:1", Backend: "http://127.0.0.1:1",
				StateDir: dir, TrustedProxy: "127.0.0.1/32",
			})
			if err != nil {
				t.Fatal(err)
			}
			gate.(*gateway).webhook, err = newWebhookNotifier(server.URL, tc.timeout)
			if err != nil {
				t.Fatal(err)
			}
			_, token, err := issueInvitationWithLimit(dir, "hooked", time.Hour, 1, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			if w := accessRequest(gate, "launchgate-test/1.0", token); w.Code != 204 {
				t.Fatalf("admission: %d %s", w.Code, w.Body.String())
			}
			refused := accessRequest(gate, "launchgate-test/1.0", token)
			if refused.Code != 403 || !strings.Contains(refused.Body.String(), "Invalid or expired invitation") {
				t.Fatalf("refused: %d %q", refused.Code, refused.Body.String())
			}
		})
	}
}

func TestWebhookDisabledWhenUnconfigured(t *testing.T) {
	t.Parallel()
	g, dir, _ := fixture(t)
	if gate := g.(*gateway); gate.webhook != nil {
		t.Fatal("webhook enabled without LAUNCH_WEBHOOK_URL")
	}
	_, token, err := issueInvitation(dir, "plain", time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if w := accessRequest(g, "launchgate-test/1.0", token); w.Code != 204 {
		t.Fatalf("admission: %d %s", w.Code, w.Body.String())
	}
	if w := accessRequest(g, "launchgate-test/1.0", "not-a-real-token"); w.Code != 403 {
		t.Fatalf("refusal: %d", w.Code)
	}
}
