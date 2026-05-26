package events

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"math/rand"
	"net/http"
	"net/url"
	"time"

	"github.com/nokia/bgp-routing-security-monitor/internal/flowspec"
)

// Action is the unit of work executed when a rule fires.
type Action interface {
	// Name returns a human-readable identifier used in log output.
	Name() string
	// Execute performs the action. ctx carries a deadline from the engine.
	// The engine calls Execute in a separate goroutine per rule firing.
	Execute(ctx context.Context, event Event) error
}

// LogAction writes the event as structured key-value pairs to slog at a
// configured level. It is the fallback action and the default dead-letter sink.
type LogAction struct {
	level string // "info", "warn", or "error"
	log   *slog.Logger
}

// Name implements Action.
func (a *LogAction) Name() string { return "log" }

// Execute logs the event at the configured slog level.
func (a *LogAction) Execute(ctx context.Context, event Event) error {
	var prefix string
	if event.Route != nil {
		prefix = event.Route.Prefix.String()
	}
	args := []any{
		"id", event.ID,
		"type", event.Type,
		"prefix", prefix,
		"old_posture", event.OldPosture,
		"new_posture", event.NewPosture,
		"cache_name", event.CacheName,
		"router_id", event.RouterID,
	}
	switch a.level {
	case "warn":
		a.log.WarnContext(ctx, "raven event", args...)
	case "error":
		a.log.ErrorContext(ctx, "raven event", args...)
	default:
		a.log.InfoContext(ctx, "raven event", args...)
	}
	return nil
}

// webhookPayload is the JSON body posted to the configured endpoint.
type webhookPayload struct {
	ID            string   `json:"id"`
	Timestamp     string   `json:"timestamp"`
	Type          string   `json:"type"`
	RuleName      string   `json:"rule_name"`
	RouterID      string   `json:"router_id"`
	Prefix        string   `json:"prefix"`
	PeerAddr      string   `json:"peer_addr"`
	PeerASN       uint32   `json:"peer_asn"`
	OriginASN     uint32   `json:"origin_asn"`
	ProtectedASNs []uint32 `json:"protected_asns,omitempty"`
	OldPosture    string   `json:"old_posture"`
	NewPosture    string   `json:"new_posture"`
	ROVState      string   `json:"rov_state"`
	ASPAState     string   `json:"aspa_state"`
	CacheName     string   `json:"cache_name"`
}

// WebhookAction delivers the event payload to an HTTP endpoint.
// It retries on network errors and 5xx/429 responses, signs payloads
// with HMAC-SHA256 when a secret is configured, and dead-letters to slog
// after all attempts are exhausted.
type WebhookAction struct {
	url            string
	secret         string
	ruleName       string
	maxAttempts    int
	client         *http.Client
	headers        map[string]string
	log            *slog.Logger
	initialBackoff time.Duration // default 500ms; overridable in tests
}

func newWebhookAction(rawURL, secret, ruleName string, maxAttempts int, timeout time.Duration, headers map[string]string, log *slog.Logger) *WebhookAction {
	return &WebhookAction{
		url:            rawURL,
		secret:         secret,
		ruleName:       ruleName,
		maxAttempts:    maxAttempts,
		client:         &http.Client{Timeout: timeout},
		headers:        headers,
		log:            log,
		initialBackoff: 500 * time.Millisecond,
	}
}

// Name implements Action.
func (a *WebhookAction) Name() string { return "webhook" }

// Execute POSTs the event as JSON to the configured URL, retrying on transient
// failures. On exhaustion it dead-letters to slog and returns nil so the engine
// rule dispatcher does not treat the webhook as a hard failure.
func (a *WebhookAction) Execute(ctx context.Context, event Event) error {
	body, err := json.Marshal(a.buildPayload(event))
	if err != nil {
		// Marshal failure is non-retryable; dead-letter immediately.
		a.log.ErrorContext(ctx, "webhook dead-letter",
			"event_id", event.ID,
			"url", redactURL(a.url),
			"error", err,
			"attempts", 0,
		)
		return nil
	}

	var sig string
	if a.secret != "" {
		mac := hmac.New(sha256.New, []byte(a.secret))
		mac.Write(body)
		sig = "sha256=" + hex.EncodeToString(mac.Sum(nil))
	}

	backoff := a.initialBackoff
	var lastStatus int
	var lastErr error

	for attempt := 1; attempt <= a.maxAttempts; attempt++ {
		if attempt > 1 {
			// Exponential backoff with ±10% jitter; respect context cancellation.
			jitterRange := backoff / 10
			var jitter time.Duration
			if jitterRange > 0 {
				jitter = time.Duration(rand.Int63n(int64(2*jitterRange))) - jitterRange
			}
			sleep := backoff + jitter
			backoff *= 2

			t := time.NewTimer(sleep)
			select {
			case <-ctx.Done():
				t.Stop()
				a.deadLetter(ctx, event, lastErr, lastStatus, attempt-1)
				return nil
			case <-t.C:
			}
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.url, bytes.NewReader(body))
		if err != nil {
			// Request construction failure is non-retryable.
			a.deadLetter(ctx, event, err, 0, attempt)
			return nil
		}
		req.Header.Set("Content-Type", "application/json")
		if sig != "" {
			req.Header.Set("X-RAVEN-Signature", sig)
		}
		for k, v := range a.headers {
			req.Header.Set(k, v)
		}

		resp, err := a.client.Do(req)
		if err != nil {
			// Network error — retryable.
			lastErr = err
			lastStatus = 0
			if attempt == a.maxAttempts {
				a.deadLetter(ctx, event, lastErr, lastStatus, attempt)
			}
			continue
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return nil
		}

		lastStatus = resp.StatusCode
		lastErr = nil

		// 4xx other than 429 are non-retryable.
		if resp.StatusCode >= 400 && resp.StatusCode < 500 && resp.StatusCode != 429 {
			a.deadLetter(ctx, event, nil, lastStatus, attempt)
			return nil
		}

		// 5xx and 429 are retryable.
		if attempt == a.maxAttempts {
			a.deadLetter(ctx, event, nil, lastStatus, attempt)
		}
	}

	return nil
}

func (a *WebhookAction) buildPayload(event Event) webhookPayload {
	p := webhookPayload{
		ID:         event.ID,
		Timestamp:  event.Timestamp.Format(time.RFC3339Nano),
		Type:       string(event.Type),
		RuleName:   a.ruleName,
		RouterID:   event.RouterID,
		OldPosture: string(event.OldPosture),
		NewPosture: string(event.NewPosture),
		CacheName:  event.CacheName,
	}
	if event.Route != nil {
		p.Prefix = event.Route.Prefix.String()
		p.PeerAddr = event.Route.PeerAddr.String()
		p.PeerASN = event.Route.PeerASN
		p.OriginASN = event.Route.OriginASN()
		p.ROVState = event.Route.ROV.State.String()
		p.ASPAState = event.Route.ASPA.State.String()
		for _, vrp := range event.Route.ROV.MatchedVRPs {
			p.ProtectedASNs = append(p.ProtectedASNs, vrp.ASN)
		}
	}
	return p
}

func (a *WebhookAction) deadLetter(ctx context.Context, event Event, lastErr error, lastStatus, attempts int) {
	attrs := []any{
		"event_id", event.ID,
		"url", redactURL(a.url),
		"attempts", attempts,
	}
	if lastErr != nil {
		attrs = append(attrs, "error", lastErr)
	}
	if lastStatus != 0 {
		attrs = append(attrs, "http_status", lastStatus)
	}
	a.log.ErrorContext(ctx, "webhook dead-letter", attrs...)
}

func redactURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	u.RawQuery = ""
	return u.String()
}

// FlowspecAction injects a BGP Flowspec mitigation rule for the event's prefix
// via a flowspec.Manager. Events without a route (e.g. CacheUnhealthy) are skipped.
type FlowspecAction struct {
	manager *flowspec.Manager
	ttl     time.Duration
	action  flowspec.FlowspecRuleAction
}

// Name implements Action.
func (a *FlowspecAction) Name() string { return "flowspec" }

// Execute builds a FlowspecRule from the event and calls manager.Inject.
// ErrDuplicate is treated as steady-state and not propagated.
func (a *FlowspecAction) Execute(ctx context.Context, event Event) error {
	if event.Route == nil {
		return nil
	}

	rule := &flowspec.FlowspecRule{
		Prefix:     event.Route.Prefix,
		OriginASN:  event.Route.OriginASN(),
		PeerAddr:   event.Route.PeerAddr,
		Action:     a.action,
		InsertedAt: time.Now(),
		TTL:        a.ttl,
		EventID:    event.ID,
	}
	rule.Key = rule.CanonicalKey()

	if err := a.manager.Inject(ctx, rule); err != nil && err != flowspec.ErrDuplicate {
		return err
	}
	return nil
}
