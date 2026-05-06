package flowspec

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"testing"
	"time"

	api "github.com/osrg/gobgp/v4/api"
)

// ─── helpers ───

func makeRule(prefix string, action FlowspecRuleAction, ttl time.Duration) *FlowspecRule {
	p := netip.MustParsePrefix(prefix)
	r := &FlowspecRule{
		Prefix:     p,
		Action:     action,
		InsertedAt: time.Now(),
		TTL:        ttl,
		EventID:    "test-event",
	}
	r.Key = r.CanonicalKey()
	return r
}

func dryRunManager(t *testing.T, maxRules int) *Manager {
	t.Helper()
	m, err := NewManager(ManagerConfig{
		DryRun:         true,
		MaxRules:       maxRules,
		DefaultTTL:     time.Hour,
		DefaultAction:  FlowspecActionDrop,
		ReaperInterval: time.Hour, // don't fire during tests
	}, slog.Default())
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	return m
}

// ─── Registry tests ───

func TestRegistry_AddDuplicate(t *testing.T) {
	reg := NewRegistry()
	rule := makeRule("10.0.0.0/8", FlowspecActionDrop, time.Hour)

	if !reg.Add(rule) {
		t.Fatal("first Add should return true")
	}
	if reg.Add(rule) {
		t.Error("second Add for same key should return false (duplicate)")
	}
	if reg.Len() != 1 {
		t.Errorf("Len: got %d, want 1", reg.Len())
	}
}

func TestRegistry_Expired(t *testing.T) {
	reg := NewRegistry()

	// Active rule: inserted now, TTL = 1h.
	active := makeRule("10.0.0.0/8", FlowspecActionDrop, time.Hour)
	reg.Add(active)

	// Expired rule: inserted 1 second in the past, TTL = 1ms.
	expired := makeRule("192.168.0.0/16", FlowspecActionDrop, time.Millisecond)
	expired.InsertedAt = time.Now().Add(-time.Second)
	reg.Add(expired)

	got := reg.Expired()
	if len(got) != 1 {
		t.Fatalf("Expired: got %d rules, want 1", len(got))
	}
	if got[0].CanonicalKey() != expired.CanonicalKey() {
		t.Errorf("Expired key: got %q, want %q", got[0].CanonicalKey(), expired.CanonicalKey())
	}
	if len(reg.Active()) != 1 {
		t.Errorf("Active: got %d rules, want 1", len(reg.Active()))
	}
}

// ─── Manager tests ───

func TestManager_DryRun(t *testing.T) {
	m := dryRunManager(t, 100)
	rule := makeRule("10.0.0.0/8", FlowspecActionDrop, time.Hour)

	if err := m.Inject(context.Background(), rule); err != nil {
		t.Fatalf("Inject: %v", err)
	}

	active := m.ActiveRules()
	if len(active) != 1 {
		t.Fatalf("ActiveRules: got %d, want 1", len(active))
	}
	if active[0].CanonicalKey() != rule.CanonicalKey() {
		t.Errorf("rule key: got %q, want %q", active[0].CanonicalKey(), rule.CanonicalKey())
	}
	if !active[0].DryRun {
		t.Error("rule.DryRun: got false, want true (manager is in dry-run mode)")
	}

	if _, ok := m.SetDryRun(rule.CanonicalKey(), false); !ok {
		t.Fatal("SetDryRun: rule not found")
	}
	if got := m.GetRule(rule.CanonicalKey()); got == nil || got.DryRun {
		t.Error("rule.DryRun: got true, want false after SetDryRun(false)")
	}
}

func TestManager_MaxRules(t *testing.T) {
	const max = 3
	m := dryRunManager(t, max)
	ctx := context.Background()

	prefixes := []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}
	for _, p := range prefixes {
		if err := m.Inject(ctx, makeRule(p, FlowspecActionDrop, time.Hour)); err != nil {
			t.Fatalf("Inject %s: %v", p, err)
		}
	}

	err := m.Inject(ctx, makeRule("203.0.113.0/24", FlowspecActionDrop, time.Hour))
	if err != ErrMaxRulesExceeded {
		t.Errorf("expected ErrMaxRulesExceeded, got %v", err)
	}
}

func TestManager_Duplicate(t *testing.T) {
	m := dryRunManager(t, 100)
	ctx := context.Background()
	rule := makeRule("10.0.0.0/8", FlowspecActionDrop, time.Hour)

	if err := m.Inject(ctx, rule); err != nil {
		t.Fatalf("first Inject: %v", err)
	}

	// Second inject for the same prefix+action must return ErrDuplicate.
	rule2 := makeRule("10.0.0.0/8", FlowspecActionDrop, time.Hour)
	if err := m.Inject(ctx, rule2); err != ErrDuplicate {
		t.Errorf("expected ErrDuplicate, got %v", err)
	}
}

func TestManager_Reaper(t *testing.T) {
	m := dryRunManager(t, 100)
	ctx := context.Background()

	rule := makeRule("10.0.0.0/8", FlowspecActionDrop, 10*time.Millisecond)
	if err := m.Inject(ctx, rule); err != nil {
		t.Fatalf("Inject: %v", err)
	}
	if len(m.ActiveRules()) != 1 {
		t.Fatal("rule should be active before TTL expires")
	}

	time.Sleep(20 * time.Millisecond)

	// Call reaper tick directly without waiting for the Run loop.
	m.runReaperTick(ctx)

	if got := m.ActiveRules(); len(got) != 0 {
		t.Errorf("ActiveRules after reaper: got %d, want 0", len(got))
	}
}

func TestManager_SetDryRun(t *testing.T) {
	m := dryRunManager(t, 100)
	ctx := context.Background()
	rule := makeRule("10.0.0.0/8", FlowspecActionDrop, time.Hour)

	if err := m.Inject(ctx, rule); err != nil {
		t.Fatalf("Inject: %v", err)
	}

	updated, ok := m.SetDryRun(rule.CanonicalKey(), false)
	if !ok {
		t.Fatal("SetDryRun: rule not found")
	}
	if updated.DryRun {
		t.Error("DryRun should be false after SetDryRun(false)")
	}

	got := m.GetRule(rule.CanonicalKey())
	if got == nil || got.DryRun {
		t.Error("GetRule: DryRun should be false after update")
	}
}

func TestManager_InjectLive_NilClient(t *testing.T) {
	m := dryRunManager(t, 100)
	ctx := context.Background()
	rule := makeRule("10.0.0.0/8", FlowspecActionDrop, time.Hour)

	if err := m.Inject(ctx, rule); err != nil {
		t.Fatalf("Inject: %v", err)
	}

	if err := m.InjectLive(ctx, rule); !errors.Is(err, ErrNilClient) {
		t.Errorf("InjectLive on dry-run manager: got %v, want ErrNilClient", err)
	}
}

func TestManager_DryRun_WithAddress(t *testing.T) {
	// grpc.NewClient is lazy, so a non-listening port does not error at dial
	// time. The Manager should create the client even though DryRun=true, so
	// that flipping DryRun off later allows InjectLive to reach gRPC.
	m, err := NewManager(ManagerConfig{
		DryRun:         true,
		GoBGPAddress:   "localhost:19999",
		MaxRules:       100,
		DefaultTTL:     time.Hour,
		DefaultAction:  FlowspecActionDrop,
		ReaperInterval: time.Hour,
	}, slog.Default())
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	if m.gobgp == nil {
		t.Fatal("m.gobgp: got nil, want non-nil (address was configured)")
	}

	ctx := context.Background()
	rule := makeRule("10.0.0.0/8", FlowspecActionDrop, time.Hour)
	if err := m.Inject(ctx, rule); err != nil {
		t.Fatalf("Inject (dry-run): %v", err)
	}
	if !rule.DryRun {
		t.Error("rule.DryRun: got false, want true")
	}

	if _, ok := m.SetDryRun(rule.CanonicalKey(), false); !ok {
		t.Fatal("SetDryRun: rule not found")
	}

	// Port 19999 is not listening, so AddPath must fail with a gRPC error
	// rather than ErrNilClient — the client exists, the server doesn't.
	liveCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	err = m.InjectLive(liveCtx, rule)
	if err == nil {
		t.Fatal("InjectLive: got nil, want gRPC connection error")
	}
	if errors.Is(err, ErrNilClient) {
		t.Errorf("InjectLive: got ErrNilClient, want gRPC connection error")
	}
}

func TestManager_GetRule(t *testing.T) {
	m := dryRunManager(t, 100)
	ctx := context.Background()
	rule := makeRule("10.0.0.0/8", FlowspecActionDrop, time.Hour)

	if m.GetRule(rule.CanonicalKey()) != nil {
		t.Error("GetRule: expected nil before inject")
	}

	if err := m.Inject(ctx, rule); err != nil {
		t.Fatalf("Inject: %v", err)
	}

	got := m.GetRule(rule.CanonicalKey())
	if got == nil {
		t.Fatal("GetRule: expected non-nil after inject")
	}
	if got.CanonicalKey() != rule.CanonicalKey() {
		t.Errorf("GetRule key: got %q, want %q", got.CanonicalKey(), rule.CanonicalKey())
	}
}

// ─── NLRI construction tests ───

// mpReachFromPath returns the MpReachNLRIAttribute from path.Pattrs, or nil.
func mpReachFromPath(path *api.Path) *api.MpReachNLRIAttribute {
	for _, attr := range path.Pattrs {
		if mp := attr.GetMpReach(); mp != nil {
			return mp
		}
	}
	return nil
}

// originFromPath returns the OriginAttribute from path.Pattrs, or nil.
func originFromPath(path *api.Path) *api.OriginAttribute {
	for _, attr := range path.Pattrs {
		if o := attr.GetOrigin(); o != nil {
			return o
		}
	}
	return nil
}

// extCommFromPath returns the ExtendedCommunitiesAttribute from path.Pattrs, or nil.
func extCommFromPath(path *api.Path) *api.ExtendedCommunitiesAttribute {
	for _, attr := range path.Pattrs {
		if ec := attr.GetExtendedCommunities(); ec != nil {
			return ec
		}
	}
	return nil
}

func TestBuildFlowspecPath_IPv4(t *testing.T) {
	rule := makeRule("10.0.0.0/8", FlowspecActionDrop, time.Hour)

	path, err := BuildFlowspecPath(rule)
	if err != nil {
		t.Fatalf("BuildFlowspecPath: %v", err)
	}

	// Real GoBGP requires the FlowSpec NLRI on path.Nlri (oneof-wrapped) AND
	// inside the MpReachNLRI attribute.
	if path.Nlri == nil {
		t.Fatal("path.Nlri: got nil, want FlowSpec NLRI")
	}
	fs := path.Nlri.GetFlowSpec()
	if fs == nil {
		t.Fatal("path.Nlri does not unmarshal to FlowSpecNLRI")
	}
	if len(fs.Rules) == 0 {
		t.Error("FlowSpecNLRI.Rules: got 0, want at least 1")
	}

	if path.Family == nil {
		t.Fatal("path.Family is nil")
	}
	if path.Family.Afi != api.Family_AFI_IP {
		t.Errorf("AFI: got %v, want AFI_IP", path.Family.Afi)
	}
	if path.Family.Safi != api.Family_SAFI_FLOW_SPEC_UNICAST {
		t.Errorf("SAFI: got %v, want SAFI_FLOW_SPEC_UNICAST", path.Family.Safi)
	}

	if got, want := len(path.Pattrs), 3; got != want {
		t.Errorf("len(path.Pattrs): got %d, want %d (Origin, MpReach, ExtComm)", got, want)
	}

	mp := mpReachFromPath(path)
	if mp == nil {
		t.Fatal("path is missing MpReachNLRI attribute")
	}
	if got := mp.NextHops; len(got) != 1 || got[0] != "0.0.0.0" {
		t.Errorf("MpReachNLRI.NextHops: got %v, want [0.0.0.0]", got)
	}

	if extCommFromPath(path) == nil {
		t.Error("path is missing ExtendedCommunities attribute")
	}

	origin := originFromPath(path)
	if origin == nil {
		t.Fatal("path is missing Origin attribute")
	}
	if origin.Origin != 2 {
		t.Errorf("Origin.Origin: got %d, want 2 (INCOMPLETE)", origin.Origin)
	}

	// Withdrawal must carry the same NLRI structure with IsWithdraw set.
	withdraw, err := BuildFlowspecWithdraw(rule)
	if err != nil {
		t.Fatalf("BuildFlowspecWithdraw: %v", err)
	}
	if !withdraw.IsWithdraw {
		t.Error("withdraw path should have IsWithdraw=true")
	}
	if withdraw.Nlri == nil {
		t.Error("withdraw.Nlri: got nil, want FlowSpec NLRI")
	}
}

func TestBuildFlowspecPath_IPv6(t *testing.T) {
	rule := makeRule("2001:db8::/32", FlowspecActionDrop, time.Hour)

	path, err := BuildFlowspecPath(rule)
	if err != nil {
		t.Fatalf("BuildFlowspecPath IPv6: %v", err)
	}

	if path.Nlri == nil {
		t.Fatal("path.Nlri: got nil, want FlowSpec NLRI")
	}
	fs := path.Nlri.GetFlowSpec()
	if fs == nil {
		t.Fatal("path.Nlri does not unmarshal to FlowSpecNLRI")
	}
	if len(fs.Rules) == 0 {
		t.Error("FlowSpecNLRI.Rules: got 0, want at least 1")
	}

	if path.Family == nil {
		t.Fatal("path.Family is nil")
	}
	if path.Family.Afi != api.Family_AFI_IP6 {
		t.Errorf("AFI: got %v, want AFI_IP6", path.Family.Afi)
	}
	if path.Family.Safi != api.Family_SAFI_FLOW_SPEC_UNICAST {
		t.Errorf("SAFI: got %v, want SAFI_FLOW_SPEC_UNICAST", path.Family.Safi)
	}

	mp := mpReachFromPath(path)
	if mp == nil {
		t.Fatal("path is missing MpReachNLRI attribute")
	}
	if got := mp.NextHops; len(got) != 1 || got[0] != "::" {
		t.Errorf("MpReachNLRI.NextHops: got %v, want [::]", got)
	}

	if extCommFromPath(path) == nil {
		t.Error("path is missing ExtendedCommunities attribute")
	}

	origin := originFromPath(path)
	if origin == nil {
		t.Fatal("path is missing Origin attribute")
	}
	if origin.Origin != 2 {
		t.Errorf("Origin.Origin: got %d, want 2 (INCOMPLETE)", origin.Origin)
	}
}
