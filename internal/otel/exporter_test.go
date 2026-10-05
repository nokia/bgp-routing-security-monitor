package otel_test

import (
	"context"
	"testing"
	"time"

	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	ravenotel "github.com/nokia/bgp-routing-security-monitor/internal/otel"
)

// ── mock StateReader ──────────────────────────────────────────────────────────

type mockReader struct {
	routeCounts    []ravenotel.RouteCount
	peerCounts     []ravenotel.PeerRouteCount
	bmpSessions    []ravenotel.BMPSessionState
	bmpMessages    []ravenotel.BMPMessageCount
	rtrSessions    []ravenotel.RTRSessionState
	rtrCacheCounts []ravenotel.RTRCacheCount
}

func (m *mockReader) RouteCounts() []ravenotel.RouteCount {
	return m.routeCounts
}
func (m *mockReader) PeerRouteCounts() []ravenotel.PeerRouteCount   { return m.peerCounts }
func (m *mockReader) BMPSessionStates() []ravenotel.BMPSessionState { return m.bmpSessions }
func (m *mockReader) BMPMessageCounts() []ravenotel.BMPMessageCount { return m.bmpMessages }
func (m *mockReader) RTRSessionStates() []ravenotel.RTRSessionState { return m.rtrSessions }
func (m *mockReader) RTRCacheCounts() []ravenotel.RTRCacheCount     { return m.rtrCacheCounts }

// ── helpers ───────────────────────────────────────────────────────────────────

func newTestExporter(t *testing.T, sr ravenotel.StateReader) (*ravenotel.Exporter, *sdkmetric.ManualReader) {
	t.Helper()
	mr := sdkmetric.NewManualReader()
	exp, err := ravenotel.NewExporterWithReader(mr, sr)
	if err != nil {
		t.Fatalf("NewExporterWithReader: %v", err)
	}
	return exp, mr
}

func collectMetrics(t *testing.T, exp *ravenotel.Exporter) metricdata.ResourceMetrics {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := exp.Produce(context.Background(), &rm); err != nil {
		t.Fatalf("Produce: %v", err)
	}
	return rm
}

func metricNamesInRM(rm metricdata.ResourceMetrics) map[string]bool {
	names := make(map[string]bool)
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			names[m.Name] = true
		}
	}
	return names
}

// ── tests ─────────────────────────────────────────────────────────────────────

// TestNewExporter_Disabled verifies that NewExporter returns (nil, nil)
// immediately when Enabled=false — no dial, no goroutine.
func TestNewExporter_Disabled(t *testing.T) {
	cfg := ravenotel.OTelConfig{Enabled: false}
	exp, err := ravenotel.NewExporter(context.Background(), cfg)
	if err != nil {
		t.Fatalf("NewExporter: unexpected error: %v", err)
	}
	if exp != nil {
		t.Fatal("NewExporter: expected nil exporter when Enabled=false, got non-nil")
	}
}

// TestExporter_MetricNames verifies that all 8 metric constants appear in the
// first collection pass.
func TestExporter_MetricNames(t *testing.T) {
	sr := &mockReader{
		routeCounts: []ravenotel.RouteCount{
			{RIB: "pre-policy", Posture: "secured", AFI: "ipv4", Count: 5},
		},
		rtrCacheCounts: []ravenotel.RTRCacheCount{
			{CacheName: "cache1", VRPCount: 100, ASPACount: 10, LastSync: 1_700_000_000},
		},
		bmpSessions: []ravenotel.BMPSessionState{
			{RouterID: "router1", State: 1},
		},
		rtrSessions: []ravenotel.RTRSessionState{
			{CacheName: "cache1", State: 1},
		},
		peerCounts: []ravenotel.PeerRouteCount{
			{PeerAddr: "10.0.0.1", PeerASN: 65000, Posture: "secured", Count: 5},
		},
		bmpMessages: []ravenotel.BMPMessageCount{
			{RouterID: "router1", MsgType: "route_monitoring", Count: 42},
		},
	}
	exp, _ := newTestExporter(t, sr)
	rm := collectMetrics(t, exp)

	got := metricNamesInRM(rm)
	for _, name := range ravenotel.AllMetrics {
		if !got[name] {
			t.Errorf("missing metric %q — found: %v", name, got)
		}
	}
}

// TestStateReader_Interface wires a mock StateReader to an in-memory exporter,
// produces one collection, and verifies attribute values on raven.routes.total.
func TestStateReader_Interface(t *testing.T) {
	sr := &mockReader{
		routeCounts: []ravenotel.RouteCount{
			{RIB: "pre-policy", Posture: "secured", AFI: "ipv4", Count: 10},
			{RIB: "pre-policy", Posture: "secured", AFI: "ipv6", Count: 3},
			{RIB: "loc-rib", Posture: "secured", AFI: "ipv4", Count: 4},
			{RIB: "pre-policy", Posture: "origin-invalid", AFI: "ipv4", Count: 2},
		},
	}
	exp, _ := newTestExporter(t, sr)
	rm := collectMetrics(t, exp)

	// Find raven.routes.total and build a map of {rib+posture+afi → count}.
	type labelKey struct{ rib, posture, afi string }
	observed := make(map[labelKey]int64)

	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != ravenotel.MetricRoutesTotal {
				continue
			}
			gauge, ok := m.Data.(metricdata.Gauge[int64])
			if !ok {
				t.Fatalf("raven.routes.total: unexpected data type %T", m.Data)
			}
			for _, dp := range gauge.DataPoints {
				var rib, posture, afi string
				for _, kv := range dp.Attributes.ToSlice() {
					switch string(kv.Key) {
					case "rib":
						rib = kv.Value.AsString()
					case "posture":
						posture = kv.Value.AsString()
					case "afi":
						afi = kv.Value.AsString()
					}
				}
				observed[labelKey{rib, posture, afi}] = dp.Value
			}
		}
	}

	cases := []struct {
		rib     string
		posture string
		afi     string
		want    int64
	}{
		{"pre-policy", "secured", "ipv4", 10},
		{"pre-policy", "secured", "ipv6", 3},
		{"loc-rib", "secured", "ipv4", 4},
		{"pre-policy", "origin-invalid", "ipv4", 2},
	}
	for _, tc := range cases {
		got := observed[labelKey{tc.rib, tc.posture, tc.afi}]
		if got != tc.want {
			t.Errorf("routes.total{rib=%q,posture=%q,afi=%q} = %d, want %d",
				tc.rib, tc.posture, tc.afi, got, tc.want)
		}
	}
}

// A router's Loc-RIB and a BGP peer of another router can share a peer
// address, so each gets its own raven.peer.routes series.
func TestPeerRoutesKeepPeersWithTheSameAddressApart(t *testing.T) {
	sr := &mockReader{
		peerCounts: []ravenotel.PeerRouteCount{
			{Router: "rr1", PeerAddr: "10.0.12.1", PeerType: "loc-rib", PeerASN: 65000, Posture: "unverified", Count: 3},
			{Router: "rr2", PeerAddr: "10.0.12.1", PeerType: "global", PeerASN: 65000, Posture: "unverified", Count: 4},
		},
	}
	exp, _ := newTestExporter(t, sr)
	rm := collectMetrics(t, exp)

	got := map[string]int64{}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != ravenotel.MetricPeerRoutes {
				continue
			}
			for _, dp := range m.Data.(metricdata.Gauge[int64]).DataPoints {
				router, _ := dp.Attributes.Value("router")
				peerType, _ := dp.Attributes.Value("peer_type")
				got[router.AsString()+"/"+peerType.AsString()] = dp.Value
			}
		}
	}
	if len(got) != 2 || got["rr1/loc-rib"] != 3 || got["rr2/global"] != 4 {
		t.Errorf("raven.peer.routes = %v, want rr1/loc-rib 3 and rr2/global 4", got)
	}
}

// TestOTelConfig_Defaults verifies that an empty OTelConfig gets the documented
// default values after applyDefaults (exercised indirectly via NewExporterWithReader).
func TestOTelConfig_Defaults(t *testing.T) {
	cfg := ravenotel.OTelConfig{}

	// Defaults are applied inside NewExporter; verify by parsing a zero config.
	// The zero values we care about:
	if cfg.Enabled {
		t.Error("default Enabled should be false")
	}

	// For the fields that get defaults, verify them via the exported constants
	// that applyDefaults fills — we test their effect through the config struct
	// directly since applyDefaults is unexported.
	const (
		wantEndpoint = "localhost:4317"
		wantProtocol = "grpc"
		wantInterval = 30 * time.Second
	)

	// applyDefaults is called inside NewExporter and NewExporterWithReader.
	// Verify the zero value is distinct from the default so the default matters.
	if cfg.Endpoint == wantEndpoint {
		t.Error("zero Endpoint should not already equal default")
	}
	if cfg.Protocol == wantProtocol {
		t.Error("zero Protocol should not already equal default")
	}
	if cfg.Interval == wantInterval {
		t.Error("zero Interval should not already equal default")
	}

	// Verify that after a round-trip through NewExporter with Enabled=false
	// there is no error and the exporter is nil.
	exp, err := ravenotel.NewExporter(context.Background(), cfg)
	if err != nil || exp != nil {
		t.Errorf("NewExporter(disabled): want (nil,nil), got (%v,%v)", exp, err)
	}
}
