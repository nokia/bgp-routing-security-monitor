package api

import (
	"net/netip"
	"testing"

	"github.com/nokia/bgp-routing-security-monitor/internal/types"
)

// A Loc-RIB and an Adj-RIB-In can share a peer address, so each route in
// the API output says which RIB it comes from.
func TestRouteToResponseIncludesRIB(t *testing.T) {
	r := &types.Route{
		PeerAddr: netip.MustParseAddr("10.0.12.1"),
		Prefix:   netip.MustParsePrefix("203.0.113.0/24"),
		RIBType:  types.LocRIB,
	}
	if got := routeToResponse(r).RIB; got != "loc-rib" {
		t.Errorf("rib = %q, want loc-rib", got)
	}
}

// VRF Loc-RIBs can share a peer address, so each route says which instance
// it comes from.
func TestRouteToResponseIncludesDistinguisher(t *testing.T) {
	r := &types.Route{
		PeerAddr:          netip.MustParseAddr("10.0.12.1"),
		PeerDistinguisher: types.PeerDistinguisherFromUint64(64500<<32 | 100),
		Prefix:            netip.MustParsePrefix("203.0.113.0/24"),
		RIBType:           types.LocRIB,
	}
	if got := routeToResponse(r).PeerDistinguisher; got != "64500:100" {
		t.Errorf("peer_distinguisher = %q, want 64500:100", got)
	}
}
