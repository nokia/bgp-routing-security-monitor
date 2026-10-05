package routetable

import (
	"context"
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

	tbl.Withdraw(types.RouteKey{PeerAddr: netip.MustParseAddr("192.0.2.1"), Prefix: netip.MustParsePrefix("1.0.0.0/24")})

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

	removed := tbl.WithdrawAllFromPeer(netip.MustParseAddr("192.0.2.1"), types.PeerDistinguisher{}, types.AdjRIBInPre)
	if removed != 2 {
		t.Errorf("removed = %d, want 2", removed)
	}
	if tbl.Count() != 1 {
		t.Errorf("count after withdraw = %d, want 1", tbl.Count())
	}
}

// A peer going down must leave no trace of its routes anywhere: not in the
// primary map, and not in the prefix, origin-ASN or posture indexes. The
// public Get* queries skip index keys whose route is gone from the primary
// map, so a stale index entry would be invisible through them; this test
// inspects the indexes directly.
func TestWithdrawAllFromPeerCleansAllIndexes(t *testing.T) {
	tbl := New()
	down := netip.MustParseAddr("192.0.2.1")
	other := netip.MustParseAddr("192.0.2.2")

	const n = 50
	for i := 0; i < n; i++ {
		prefix := netip.PrefixFrom(netip.AddrFrom4([4]byte{10, 1, byte(i), 0}), 24).String()
		for _, rib := range []types.RIBType{types.AdjRIBInPre, types.AdjRIBInPost} {
			r := makeRoute(down.String(), prefix, []uint32{64501, 65000 + uint32(i%5)})
			r.RIBType = rib
			r.SecurityPosture = types.PostureOriginOnly
			if i%2 == 0 {
				r.SecurityPosture = types.PostureOriginInvalid
			}
			tbl.Insert(r)
		}
	}
	// The other peer shares one prefix and one origin ASN with the downed peer.
	shared := makeRoute(other.String(), "10.1.0.0/24", []uint32{64502, 65000})
	shared.SecurityPosture = types.PostureOriginInvalid
	tbl.Insert(shared)
	tbl.Insert(makeRoute(other.String(), "8.8.8.0/24", []uint32{64502, 15169}))

	if got := tbl.Count(); got != 2*n+2 {
		t.Fatalf("count before peer down = %d, want %d", got, 2*n+2)
	}

	if removed := tbl.WithdrawAllFromPeer(down, types.PeerDistinguisher{}, types.AdjRIBInPre, types.AdjRIBInPost); removed != 2*n {
		t.Errorf("removed = %d, want %d", removed, 2*n)
	}

	if got := tbl.Count(); got != 2 {
		t.Errorf("count after peer down = %d, want 2 (the other peer's routes)", got)
	}
	if got := tbl.GetByPeer(down); len(got) != 0 {
		t.Errorf("GetByPeer(down) returned %d routes, want 0", len(got))
	}

	// Prefix (BART) index: the downed peer's own prefixes are gone entirely;
	// the shared prefix keeps only the other peer's key.
	for i := 0; i < n; i++ {
		p := netip.PrefixFrom(netip.AddrFrom4([4]byte{10, 1, byte(i), 0}), 24)
		keys, ok := tbl.prefixIdx.Get(p)
		for _, k := range keys {
			if k.PeerAddr == down {
				t.Errorf("prefix index still holds %v", k)
			}
		}
		if i != 0 && ok {
			t.Errorf("prefix index still has an entry for %s, want it deleted", p)
		}
	}
	if keys, _ := tbl.prefixIdx.Get(netip.MustParsePrefix("10.1.0.0/24")); len(keys) != 1 || keys[0].PeerAddr != other {
		t.Errorf("shared prefix keys = %v, want only the other peer's", keys)
	}

	// Origin-ASN and posture indexes hold no key for the downed peer.
	for asn, keys := range tbl.asnIdx {
		for _, k := range keys {
			if k.PeerAddr == down {
				t.Errorf("ASN index AS%d still holds %v", asn, k)
			}
		}
	}
	for posture, keys := range tbl.postureIdx {
		for _, k := range keys {
			if k.PeerAddr == down {
				t.Errorf("posture index %q still holds %v", posture, k)
			}
		}
	}
	if got := tbl.CountByPosture()[types.PostureOriginInvalid]; got != 1 {
		t.Errorf("origin-invalid count after peer down = %d, want 1 (the other peer's shared route)", got)
	}
	if got := tbl.CountByPosture()[types.PostureOriginOnly]; got != 0 {
		t.Errorf("origin-only count after peer down = %d, want 0", got)
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

// The default view holds what the routers received (pre-policy Adj-RIB-In)
// and what they selected (Loc-RIB). Post-policy routes stay stored but out
// of the view.
func TestDefaultViewIncludesLocRIBButNotPostPolicy(t *testing.T) {
	tbl := New()
	prefix := "1.0.0.0/24"

	pre := makeRoute("192.0.2.1", prefix, []uint32{64501, 13335})
	pre.SecurityPosture = types.PostureOriginOnly
	post := makeRoute("192.0.2.1", prefix, []uint32{64501, 13335})
	post.RIBType = types.AdjRIBInPost
	post.SecurityPosture = types.PostureOriginOnly
	loc := makeRoute("192.0.2.55", prefix, []uint32{64501, 13335})
	loc.RIBType = types.LocRIB
	loc.SecurityPosture = types.PostureOriginOnly
	for _, r := range []*types.Route{pre, post, loc} {
		tbl.Insert(r)
	}

	wantRIBs := func(name string, routes []*types.Route) {
		t.Helper()
		got := map[types.RIBType]int{}
		for _, r := range routes {
			got[r.RIBType]++
		}
		if len(routes) != 2 || got[types.AdjRIBInPre] != 1 || got[types.LocRIB] != 1 {
			t.Errorf("%s returned RIB types %v, want one pre-policy and one Loc-RIB", name, got)
		}
	}
	wantRIBs("GetByPrefix", tbl.GetByPrefix(netip.MustParsePrefix(prefix)))
	wantRIBs("GetByOriginASN", tbl.GetByOriginASN(13335))
	wantRIBs("GetByPosture", tbl.GetByPosture(types.PostureOriginOnly))
	wantRIBs("AllDefaultView", tbl.AllDefaultView())

	if routes := tbl.GetByPeer(netip.MustParseAddr("192.0.2.55")); len(routes) != 1 || routes[0].RIBType != types.LocRIB {
		t.Errorf("GetByPeer on the Loc-RIB peer returned %d routes, want its Loc-RIB route", len(routes))
	}
}

// A router's BGP ID is often the address another router peers with, so a
// Loc-RIB and an Adj-RIB-In can share a peer address. A withdrawal must only
// touch the RIBs it was sent for.
func TestWithdrawIsScopedToRIBType(t *testing.T) {
	peer := netip.MustParseAddr("192.0.2.55")
	prefix := netip.MustParsePrefix("1.0.0.0/24")
	newTable := func() *Table {
		tbl := New()
		for _, rib := range []types.RIBType{types.AdjRIBInPre, types.AdjRIBInPost, types.LocRIB} {
			r := makeRoute(peer.String(), prefix.String(), []uint32{64501, 13335})
			r.RIBType = rib
			tbl.Insert(r)
		}
		return tbl
	}
	has := func(tbl *Table, rib types.RIBType) bool {
		return tbl.Get(types.RouteKey{PeerAddr: peer, Prefix: prefix, RIBType: rib}) != nil
	}

	tbl := newTable()
	tbl.Withdraw(types.RouteKey{PeerAddr: peer, Prefix: prefix, RIBType: types.AdjRIBInPre})
	if has(tbl, types.AdjRIBInPre) || !has(tbl, types.AdjRIBInPost) || !has(tbl, types.LocRIB) {
		t.Error("a pre-policy withdrawal must remove only the pre-policy route")
	}

	tbl = newTable()
	if removed := tbl.WithdrawAllFromPeer(peer, types.PeerDistinguisher{}, types.AdjRIBInPre, types.AdjRIBInPost); removed != 2 {
		t.Errorf("Adj-RIB-In withdraw-all removed %d routes, want 2", removed)
	}
	if !has(tbl, types.LocRIB) {
		t.Error("an Adj-RIB-In withdraw-all removed the Loc-RIB route")
	}

	tbl = newTable()
	if removed := tbl.WithdrawAllFromPeer(peer, types.PeerDistinguisher{}, types.LocRIB); removed != 1 {
		t.Errorf("Loc-RIB withdraw-all removed %d routes, want 1", removed)
	}
	if !has(tbl, types.AdjRIBInPre) || !has(tbl, types.AdjRIBInPost) {
		t.Error("a Loc-RIB withdraw-all removed an Adj-RIB-In route")
	}
}

// VRF Loc-RIBs of one router share its BGP ID, so routes and withdrawals are
// kept apart by the Peer Distinguisher.
func TestRoutesAreKeyedByDistinguisher(t *testing.T) {
	peer := netip.MustParseAddr("192.0.2.55")
	prefix := netip.MustParsePrefix("1.0.0.0/24")
	vrf := types.PeerDistinguisherFromUint64(64500<<32 | 100)
	tbl := New()
	for _, d := range []types.PeerDistinguisher{{}, vrf} {
		r := makeRoute(peer.String(), prefix.String(), []uint32{64510})
		r.RIBType = types.LocRIB
		r.PeerDistinguisher = d
		tbl.Insert(r)
	}
	if got := tbl.Count(); got != 2 {
		t.Fatalf("count = %d, want one route per instance", got)
	}

	if removed := tbl.WithdrawAllFromPeer(peer, vrf, types.LocRIB); removed != 1 {
		t.Errorf("VRF withdraw-all removed %d routes, want 1", removed)
	}
	if tbl.Get(types.RouteKey{PeerAddr: peer, Prefix: prefix, RIBType: types.LocRIB}) == nil {
		t.Error("the VRF withdraw-all removed the global Loc-RIB route")
	}
}

// The what-if simulator and the ASPA recommender count each route once, so
// ListRoutes returns one RIB, pre-policy by default.
func TestListRoutesReturnsOneRIB(t *testing.T) {
	tbl := New()
	peer := "192.0.2.1"
	prefix := "1.0.0.0/24"
	for _, rib := range types.RIBTypes {
		r := makeRoute(peer, prefix, []uint32{64501, 13335})
		r.RIBType = rib
		r.SecurityPosture = types.PostureOriginOnly
		tbl.Insert(r)
	}

	for name, f := range map[string]Filter{
		"no filter": {},
		"peer":      {PeerAddr: peer},
		"prefix":    {Prefix: prefix},
		"origin":    {OriginASN: 13335},
		"posture":   {Posture: string(types.PostureOriginOnly)},
	} {
		for _, rib := range types.RIBTypes {
			f.RIB = rib
			routes, err := tbl.ListRoutes(context.Background(), f)
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			if len(routes) != 1 || routes[0].RIBType != rib {
				t.Errorf("%s, RIB %s: got %d routes, want the %s route only", name, rib, len(routes), rib)
			}
		}
	}
}

// A withdraw-all without RIBs must not silently keep the routes of the peer.
func TestWithdrawAllFromPeerWithoutRIBsRemovesEveryRIB(t *testing.T) {
	tbl := New()
	peer := netip.MustParseAddr("192.0.2.1")
	for _, rib := range types.RIBTypes {
		r := makeRoute(peer.String(), "1.0.0.0/24", []uint32{64501, 13335})
		r.RIBType = rib
		tbl.Insert(r)
	}
	if removed := tbl.WithdrawAllFromPeer(peer, types.PeerDistinguisher{}); removed != len(types.RIBTypes) {
		t.Errorf("removed %d routes, want %d", removed, len(types.RIBTypes))
	}
}
