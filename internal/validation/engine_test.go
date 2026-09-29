package validation

import (
	"io"
	"log/slog"
	"net/netip"
	"testing"

	"github.com/nokia/bgp-routing-security-monitor/internal/routetable"
	"github.com/nokia/bgp-routing-security-monitor/internal/rtr/store"
	"github.com/nokia/bgp-routing-security-monitor/internal/types"
)

// RevalidateAll changes a route's posture in place and re-inserts it. The
// posture index must follow: the route is listed under its current posture
// only, however many times it flips, and nothing is left behind once the
// route is withdrawn. Leaked keys here grow memory with every RTR-driven
// posture change and inflate the per-posture counts.
func TestRevalidateAllPostureFlipsLeaveNoStaleIndexKeys(t *testing.T) {
	prefix := netip.MustParsePrefix("192.0.2.0/24")
	matching := []types.VRP{{Prefix: prefix, ASN: 65000, MaxLength: 24}} // → origin-only
	other := []types.VRP{{Prefix: prefix, ASN: 65999, MaxLength: 24}}    // → origin-invalid

	vrps := store.NewVRPStore()
	vrps.ReplaceAll(matching, 1, 1)
	table := routetable.New()
	e := NewEngine(vrps, store.NewASPAStore(), table, slog.New(slog.NewTextHandler(io.Discard, nil)))

	route := &types.Route{
		PeerAddr: netip.MustParseAddr("198.51.100.1"),
		Prefix:   prefix,
		ASPath:   []uint32{64500, 65000},
		RIBType:  types.AdjRIBInPre,
	}
	e.ValidateRoute(route)
	table.Insert(route)
	if route.SecurityPosture != types.PostureOriginOnly {
		t.Fatalf("initial posture = %s, want %s", route.SecurityPosture, types.PostureOriginOnly)
	}

	checkIndexed := func(step string, want types.SecurityPosture) {
		t.Helper()
		var total uint64
		for posture, n := range table.CountByPosture() {
			total += n
			if posture != want && n != 0 {
				t.Errorf("%s: posture index %q still counts %d route(s); the route is %s", step, posture, n, want)
			}
		}
		if total != 1 {
			t.Errorf("%s: posture index counts %d entries in total, want 1 (one route)", step, total)
		}
		for _, r := range table.GetByPosture(want) {
			if r.SecurityPosture != want {
				t.Errorf("%s: GetByPosture(%s) returned a route whose posture is %s", step, want, r.SecurityPosture)
			}
		}
	}

	for i := 0; i < 4; i++ {
		vrps.ReplaceAll(other, uint32(2*i+2), 1)
		e.RevalidateAll()
		checkIndexed("flip to origin-invalid", types.PostureOriginInvalid)

		vrps.ReplaceAll(matching, uint32(2*i+3), 1)
		e.RevalidateAll()
		checkIndexed("flip back to origin-only", types.PostureOriginOnly)
	}

	table.Withdraw(route.PeerAddr, route.Prefix)
	for posture, n := range table.CountByPosture() {
		if n != 0 {
			t.Errorf("after withdrawal: posture index %q still counts %d route(s), want 0", posture, n)
		}
	}
}
