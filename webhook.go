package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/url"
	"time"
)

const (
	webhookQueueSize         = 64
	webhookTimeout           = 3 * time.Second
	webhookMaxUserAgentBytes = 512
	webhookMaxResponseBytes  = 4 << 10
	webhookResultAdmit       = "admit"
	webhookResultRefuse      = "refuse"
)

type webhookEvent struct {
	InvitationID string    `json:"invitation_id"`
	Result       string    `json:"result"`
	Timestamp    time.Time `json:"timestamp"`
	ClientIP     string    `json:"client_ip"`
	UserAgent    string    `json:"user_agent"`
}

type webhookNotifier struct {
	url    string
	client *http.Client
	events chan webhookEvent
}

func newWebhookNotifier(rawURL string, timeout time.Duration) (*webhookNotifier, error) {
	if rawURL == "" {
		return nil, nil
	}
	target, err := url.Parse(rawURL)
	if err != nil || (target.Scheme != "http" && target.Scheme != "https") || target.Host == "" ||
		target.User != nil {
		return nil, errors.New("LAUNCH_WEBHOOK_URL must be an http or https URL")
	}
	if timeout <= 0 {
		timeout = webhookTimeout
	}
	n := &webhookNotifier{
		url:    rawURL,
		client: &http.Client{Timeout: timeout},
		events: make(chan webhookEvent, webhookQueueSize),
	}
	go n.run()
	return n, nil
}

func (n *webhookNotifier) notify(event webhookEvent) {
	select {
	case n.events <- event:
	default:
		log.Print("launchgate webhook queue full; event dropped")
	}
}

func (n *webhookNotifier) run() {
	for event := range n.events {
		n.deliver(event)
	}
}

func (n *webhookNotifier) deliver(event webhookEvent) {
	payload, err := json.Marshal(event)
	if err != nil {
		log.Printf("launchgate webhook payload failed: %v", err)
		return
	}
	request, err := http.NewRequest(http.MethodPost, n.url, bytes.NewReader(payload))
	if err != nil {
		log.Printf("launchgate webhook request failed: %v", err)
		return
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := n.client.Do(request)
	if err != nil {
		log.Printf("launchgate webhook delivery failed: %v", err)
		return
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, webhookMaxResponseBytes))
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		log.Printf("launchgate webhook rejected event: status %d", response.StatusCode)
	}
}

func (g *gateway) notifyWebhook(result, invitationID string, now time.Time, r *http.Request) {
	if g.webhook == nil {
		return
	}
	userAgent := r.UserAgent()
	if len(userAgent) > webhookMaxUserAgentBytes {
		userAgent = userAgent[:webhookMaxUserAgentBytes]
	}
	g.webhook.notify(webhookEvent{
		InvitationID: invitationID,
		Result:       result,
		Timestamp:    now.UTC(),
		ClientIP:     g.clientIP(r),
		UserAgent:    userAgent,
	})
}
