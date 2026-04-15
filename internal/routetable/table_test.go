package routetable

import (
	"net/netip"
	"testing"

	"github.com/nokia/bgp-routing-security-monitor/internal/types"
)

func makeRoute(peer string, prefix string, asPath []uint32) *types.Route {
	return &types.Route{
		PeerAddr: netip.MustParseAddr(peer),
		Prefix:   netip.MustParsePrefix(prefix),
		ASPath:   asPath,
		RIBType:  types.AdjRIBInPre,
	}
}

func TestInsertAndGetByPrefix(t *testing.T) {
	tbl := New()

	r := makeRoute("192.0.2.1", "1.0.0.0/24", []uint32{64501, 13335})
	tbl.Insert(r)

	if tbl.Count() != 1 {
		t.Fatalf("count = %d, want 1", tbl.Count())
	}

	routes := tbl.GetByPrefix(netip.MustParsePrefix("1.0.0.0/24"))
	if len(routes) != 1 {
		t.Fatalf("GetByPrefix returned %d routes, want 1", len(routes))
	}
	if routes[0].Prefix != r.Prefix {
		t.Errorf("prefix = %s, want %s", routes[0].Prefix, r.Prefix)
	}
}

func TestMultiplePeersSamePrefix(t *testing.T) {
	tbl := New()

	r1 := makeRoute("192.0.2.1", "1.0.0.0/24", []uint32{64501, 13335})
	r2 := makeRoute("192.0.2.2", "1.0.0.0/24", []uint32{64502, 13335})
	tbl.Insert(r1)
	tbl.Insert(r2)

	if tbl.Count() != 2 {
		t.Fatalf("count = %d, want 2", tbl.Count())
	}

	routes := tbl.GetByPrefix(netip.MustParsePrefix("1.0.0.0/24"))
	if len(routes) != 2 {
		t.Fatalf("GetByPrefix returned %d routes, want 2", len(routes))
	}
}

func TestGetByOriginASN(t *testing.T) {
	tbl := New()

	r1 := makeRoute("192.0.2.1", "1.0.0.0/24", []uint32{64501, 13335})
	r2 := makeRoute("192.0.2.1", "8.8.8.0/24", []uint32{64501, 15169})
	tbl.Insert(r1)
	tbl.Insert(r2)

	routes := tbl.GetByOriginASN(13335)
	if len(routes) != 1 {
		t.Fatalf("GetByOriginASN(13335) returned %d routes, want 1", len(routes))
	}
	if routes[0].Prefix.String() != "1.0.0.0/24" {
		t.Errorf("prefix = %s, want 1.0.0.0/24", routes[0].Prefix)
	}
}

func TestGetByPeer(t *testing.T) {
	tbl := New()

	r1 := makeRoute("192.0.2.1", "1.0.0.0/24", []uint32{64501, 13335})
	r2 := makeRoute("192.0.2.2", "8.8.8.0/24", []uint32{64502, 15169})
	tbl.Insert(r1)
	tbl.Insert(r2)

	routes := tbl.GetByPeer(netip.MustParseAddr("192.0.2.1"))
	if len(routes) != 1 {
		t.Fatalf("GetByPeer returned %d routes, want 1", len(routes))
	}
}

func TestWithdraw(t *testing.T) {
	tbl := New()

	r := makeRoute("192.0.2.1", "1.0.0.0/24", []uint32{64501, 13335})
	tbl.Insert(r)

	if tbl.Count() != 1 {
		t.Fatalf("count before withdraw = %d, want 1", tbl.Count())
	}

	tbl.Withdraw(netip.MustParseAddr("192.0.2.1"), netip.MustParsePrefix("1.0.0.0/24"))

	if tbl.Count() != 0 {
		t.Fatalf("count after withdraw = %d, want 0", tbl.Count())
	}

	routes := tbl.GetByPrefix(netip.MustParsePrefix("1.0.0.0/24"))
	if len(routes) != 0 {
		t.Errorf("GetByPrefix after withdraw returned %d routes, want 0", len(routes))
	}
}

func TestWithdrawAllFromPeer(t *testing.T) {
	tbl := New()

	tbl.Insert(makeRoute("192.0.2.1", "1.0.0.0/24", []uint32{64501, 13335}))
	tbl.Insert(makeRoute("192.0.2.1", "8.8.8.0/24", []uint32{64501, 15169}))
	tbl.Insert(makeRoute("192.0.2.2", "10.0.0.0/8", []uint32{64502, 3356}))

	if tbl.Count() != 3 {
		t.Fatalf("count = %d, want 3", tbl.Count())
	}

	removed := tbl.WithdrawAllFromPeer(netip.MustParseAddr("192.0.2.1"))
	if removed != 2 {
		t.Errorf("removed = %d, want 2", removed)
	}
	if tbl.Count() != 1 {
		t.Errorf("count after withdraw = %d, want 1", tbl.Count())
	}
}

func TestGetByPosture(t *testing.T) {
	tbl := New()

	r1 := makeRoute("192.0.2.1", "1.0.0.0/24", []uint32{64501, 13335})
	r1.SecurityPosture = types.PostureSecured
	tbl.Insert(r1)

	r2 := makeRoute("192.0.2.1", "10.0.0.0/8", []uint32{64501, 64666})
	r2.SecurityPosture = types.PostureOriginInvalid
	tbl.Insert(r2)

	secured := tbl.GetByPosture(types.PostureSecured)
	if len(secured) != 1 {
		t.Errorf("secured routes = %d, want 1", len(secured))
	}

	invalid := tbl.GetByPosture(types.PostureOriginInvalid)
	if len(invalid) != 1 {
		t.Errorf("origin-invalid routes = %d, want 1", len(invalid))
	}
}