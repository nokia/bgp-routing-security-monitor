package flowspec

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"

	api "github.com/osrg/gobgp/v4/api"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// Sentinel errors returned by Manager methods.
var (
	// ErrMaxRulesExceeded is returned when the active rule count is at capacity.
	ErrMaxRulesExceeded = errors.New("flowspec: max active rules exceeded")
	// ErrDuplicate is returned when a non-expired rule for the same key exists.
	ErrDuplicate = errors.New("flowspec: rule already active for this prefix")
	// ErrApprovalDenied is returned when the approval webhook rejects injection.
	ErrApprovalDenied = errors.New("flowspec: injection denied by approval webhook")
	// ErrNilClient is returned when InjectLive is called with no GoBGP client.
	ErrNilClient = errors.New("flowspec: no GoBGP client configured")
	// ErrNotFound is returned when a rule key is not in the registry.
	ErrNotFound = errors.New("flowspec: rule not found in registry")
)

// ManagerConfig configures a Flowspec Manager.
type ManagerConfig struct {
	// GoBGPAddress is the GoBGP gRPC management endpoint. When empty, no GoBGP
	// client is created and InjectLive returns ErrNilClient.
	GoBGPAddress string
	// MaxRules is the maximum number of concurrently active rules (default 100; 0 = unlimited).
	MaxRules int
	// DefaultTTL is the lifetime of each injected rule (default 1h).
	DefaultTTL time.Duration
	// DefaultAction is the Flowspec action applied when none is specified (default "drop").
	DefaultAction FlowspecRuleAction
	// DryRun logs rules without injecting them into GoBGP.
	DryRun bool
	// ReaperInterval is how often the reaper scans for expired rules (default 30s).
	ReaperInterval time.Duration
	// ApprovalWebhook is an optional URL to POST for injection approval; empty = no approval step.
	ApprovalWebhook string
	// ApprovalTimeout is the HTTP timeout for each approval webhook call (default 10s).
	ApprovalTimeout time.Duration
}

// Manager implements the Flowspec lifecycle: inject, track, reap expired rules.
// It is safe for concurrent use.
type Manager struct {
	cfg      ManagerConfig
	registry *Registry
	gobgp    api.GoBgpServiceClient // nil if GoBGPAddress was empty
	conn     *grpc.ClientConn       // nil if GoBGPAddress was empty
	logger   *slog.Logger
	mu       sync.Mutex // serialises the Len-check + registry.Add in Inject
}

// NewManager constructs a Manager from cfg. If cfg.GoBGPAddress is non-empty
// it dials the GoBGP gRPC endpoint regardless of cfg.DryRun, so that toggling
// dry-run live later succeeds.
func NewManager(cfg ManagerConfig, logger *slog.Logger) (*Manager, error) {
	if cfg.DefaultTTL == 0 {
		cfg.DefaultTTL = time.Hour
	}
	if cfg.MaxRules == 0 {
		cfg.MaxRules = 100
	}
	if cfg.DefaultAction == "" {
		cfg.DefaultAction = FlowspecActionDrop
	}
	if cfg.ReaperInterval == 0 {
		cfg.ReaperInterval = 30 * time.Second
	}
	if cfg.ApprovalTimeout == 0 {
		cfg.ApprovalTimeout = 10 * time.Second
	}

	m := &Manager{
		cfg:      cfg,
		registry: NewRegistry(),
		logger:   logger,
	}

	if cfg.GoBGPAddress != "" {
		conn, err := grpc.NewClient(cfg.GoBGPAddress,
			grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			return nil, fmt.Errorf("flowspec: dial GoBGP at %s: %w", cfg.GoBGPAddress, err)
		}
		m.conn = conn
		m.gobgp = api.NewGoBgpServiceClient(conn)
	}

	return m, nil
}

// Inject adds rule to the registry and injects it into GoBGP.
// Returns ErrMaxRulesExceeded, ErrDuplicate, ErrApprovalDenied, or nil.
// On GoBGP or approval errors the rule is removed from the registry before returning.
func (m *Manager) Inject(ctx context.Context, rule *FlowspecRule) error {
	// Reflect the manager's dry-run mode on the rule so the registry, API,
	// and CLI all see the true state. A per-rule rule.DryRun=true override
	// is preserved when cfg.DryRun is false.
	if m.cfg.DryRun {
		rule.DryRun = true
	}

	// Phase 1: atomic limit check + registry insertion.
	m.mu.Lock()
	if m.cfg.MaxRules > 0 && m.registry.Len() >= m.cfg.MaxRules {
		m.mu.Unlock()
		return ErrMaxRulesExceeded
	}
	if !m.registry.Add(rule) {
		m.mu.Unlock()
		return ErrDuplicate
	}
	m.mu.Unlock()

	// Phase 2: optional approval webhook (no lock held for I/O).
	if m.cfg.ApprovalWebhook != "" {
		if err := m.callApprovalWebhook(ctx, rule); err != nil {
			m.registry.Remove(rule.CanonicalKey())
			return ErrApprovalDenied
		}
	}

	// Phase 3: dry-run — rule stays in registry for Len/Active accounting.
	if m.cfg.DryRun || rule.DryRun {
		m.logger.InfoContext(ctx, "flowspec dry-run inject",
			"key", rule.CanonicalKey(),
			"prefix", rule.Prefix.String(),
			"action", string(rule.Action),
			"event_id", rule.EventID,
		)
		return nil
	}

	// Phase 4: build and inject via GoBGP AddPath.
	path, err := BuildFlowspecPath(rule)
	if err != nil {
		m.registry.Remove(rule.CanonicalKey())
		return fmt.Errorf("flowspec: build path: %w", err)
	}

	if _, err = m.gobgp.AddPath(ctx, &api.AddPathRequest{
		TableType: api.TableType_TABLE_TYPE_GLOBAL,
		Path:      path,
	}); err != nil {
		m.registry.Remove(rule.CanonicalKey())
		return fmt.Errorf("flowspec: AddPath: %w", err)
	}

	m.logger.InfoContext(ctx, "flowspec rule injected",
		"key", rule.CanonicalKey(),
		"prefix", rule.Prefix.String(),
		"action", string(rule.Action),
		"event_id", rule.EventID,
	)
	return nil
}

// Withdraw issues a GoBGP DeletePath for the rule identified by key. It does
// not mutate the registry — callers are responsible for removing the entry
// (reaper) or flipping it to dry-run (API toggle) as appropriate. No-op when
// no rule is registered for key or no GoBGP client is configured.
func (m *Manager) Withdraw(ctx context.Context, key string) error {
	rule := m.registry.Get(key)
	if rule == nil || m.gobgp == nil {
		return nil
	}

	path, err := BuildFlowspecWithdraw(rule)
	if err != nil {
		return fmt.Errorf("flowspec: build withdraw path: %w", err)
	}

	if _, err = m.gobgp.DeletePath(ctx, &api.DeletePathRequest{
		TableType: api.TableType_TABLE_TYPE_GLOBAL,
		Path:      path,
	}); err != nil {
		return fmt.Errorf("flowspec: DeletePath: %w", err)
	}

	return nil
}

// Run starts the reaper loop and blocks until ctx is done.
func (m *Manager) Run(ctx context.Context) {
	ticker := time.NewTicker(m.cfg.ReaperInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			m.runReaperTick(ctx)
		case <-ctx.Done():
			return
		}
	}
}

// runReaperTick performs one reaper scan: withdraws all expired rules.
// Extracted for testability.
func (m *Manager) runReaperTick(ctx context.Context) {
	expired := m.registry.Expired()
	for _, rule := range expired {
		key := rule.CanonicalKey()
		if err := m.Withdraw(ctx, key); err != nil {
			m.logger.WarnContext(ctx, "flowspec reaper withdraw failed",
				"key", key,
				"error", err,
			)
		}
		m.registry.Remove(key)
	}
	if len(expired) > 0 {
		m.logger.DebugContext(ctx, "flowspec reaper withdrawn", "count", len(expired))
	}
}

// ActiveRules returns a snapshot of all currently active (non-expired) rules.
func (m *Manager) ActiveRules() []*FlowspecRule {
	return m.registry.Active()
}

// GetRule returns the rule identified by key, or nil if not found.
func (m *Manager) GetRule(key string) *FlowspecRule {
	return m.registry.Get(key)
}

// SetDryRun updates the dry_run flag on an active rule in the registry.
// Thread-safe. Returns the updated rule and true, or nil and false if not found.
func (m *Manager) SetDryRun(key string, dryRun bool) (*FlowspecRule, bool) {
	return m.registry.SetDryRun(key, dryRun)
}

// InjectLive takes a rule that was previously dry-run and injects it live into
// GoBGP. Returns ErrNilClient if the manager has no GoBGP client configured,
// ErrNotFound if the rule is not in the registry.
func (m *Manager) InjectLive(ctx context.Context, rule *FlowspecRule) error {
	if m.gobgp == nil {
		return ErrNilClient
	}
	if m.registry.Get(rule.CanonicalKey()) == nil {
		return ErrNotFound
	}

	path, err := BuildFlowspecPath(rule)
	if err != nil {
		return fmt.Errorf("flowspec: build path: %w", err)
	}

	if _, err = m.gobgp.AddPath(ctx, &api.AddPathRequest{
		TableType: api.TableType_TABLE_TYPE_GLOBAL,
		Path:      path,
	}); err != nil {
		return fmt.Errorf("flowspec: AddPath: %w", err)
	}

	m.logger.InfoContext(ctx, "flowspec rule injected live",
		"key", rule.CanonicalKey(),
		"prefix", rule.Prefix.String(),
		"action", string(rule.Action),
		"event_id", rule.EventID,
	)
	return nil
}

// approvalBody is the JSON payload sent to the approval webhook.
type approvalBody struct {
	Key       string `json:"key"`
	Prefix    string `json:"prefix"`
	OriginASN uint32 `json:"origin_asn"`
	PeerAddr  string `json:"peer_addr"`
	Action    string `json:"action"`
	EventID   string `json:"event_id"`
}

func (m *Manager) callApprovalWebhook(ctx context.Context, rule *FlowspecRule) error {
	body, err := json.Marshal(approvalBody{
		Key:       rule.CanonicalKey(),
		Prefix:    rule.Prefix.String(),
		OriginASN: rule.OriginASN,
		PeerAddr:  rule.PeerAddr.String(),
		Action:    string(rule.Action),
		EventID:   rule.EventID,
	})
	if err != nil {
		return err
	}

	timeoutCtx, cancel := context.WithTimeout(ctx, m.cfg.ApprovalTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(timeoutCtx, http.MethodPost, m.cfg.ApprovalWebhook, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("approval webhook returned %d", resp.StatusCode)
	}
	return nil
}
