package cli

import "testing"

// A Loc-RIB route's peer is the monitored router, so the neighbor it was
// learned from is the first AS of its path.
func TestLocRIBRouteExpectsTheNeighborAS(t *testing.T) {
	loc := stealthyRoute{RIB: "loc-rib", PeerASN: 65000, OriginASN: 64500, ASPath: []uint32{64510, 64500}}
	if got := labelFor(64510, loc); got != "expected peer" {
		t.Errorf("label of the neighbor AS = %q, want expected peer", got)
	}
	if got := labelFor(65000, loc); got != "ATTACKER" {
		t.Errorf("label of the router's own AS = %q, want ATTACKER", got)
	}

	pre := stealthyRoute{RIB: "pre-policy", PeerASN: 64510, OriginASN: 64500, ASPath: []uint32{64510, 64500}}
	if got := pre.neighborASN(); got != 64510 {
		t.Errorf("neighbor AS of a pre-policy route = %d, want its peer AS 64510", got)
	}
}

// A Loc-RIB peer has the router's BGP ID as address, which can answer a
// probe, but it is not a BGP neighbor.
func TestLookupPeerSkipsLocRIBPeers(t *testing.T) {
	peers := []stealthyPeer{
		{Addr: "10.0.12.1", Type: "loc-rib", ASN: 65000},
		{Addr: "10.0.12.1", Type: "global", ASN: 65000},
	}
	if p := lookupPeer(peers, "10.0.12.1"); p == nil || p.Type != "global" {
		t.Errorf("lookupPeer = %+v, want the global peer", p)
	}
	if p := lookupPeer(peers[:1], "10.0.12.1"); p != nil {
		t.Errorf("lookupPeer returned the Loc-RIB peer %+v", p)
	}
}
