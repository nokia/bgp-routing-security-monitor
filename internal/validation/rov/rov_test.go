package rov

import (
	"net/netip"
	"testing"

	"github.com/nokia/bgp-routing-security-monitor/internal/rtr/store"
	"github.com/nokia/bgp-routing-security-monitor/internal/types"
)

func TestROVValid(t *testing.T) {
	s := store.NewVRPStore()
	s.ReplaceAll([]types.VRP{
		{Prefix: netip.MustParsePrefix("198.51.100.0/24"), ASN: 13335, MaxLength: 24},
	}, 1, 1)

	a := NewAnnotator(s)
	route := &types.Route{
		Prefix: netip.MustParsePrefix("198.51.100.0/24"),
		ASPath: []uint32{64501, 13335},
	}

	result := a.Validate(route)
	if result.State != types.ROVValid {
		t.Errorf("expected Valid, got %s: %s", result.State, result.Reason)
	}
}

func TestROVInvalidOriginMismatch(t *testing.T) {
	s := store.NewVRPStore()
	s.ReplaceAll([]types.VRP{
		{Prefix: netip.MustParsePrefix("198.51.100.0/24"), ASN: 13335, MaxLength: 24},
	}, 1, 1)

	a := NewAnnotator(s)
	// Wrong origin ASN — hijack scenario
	route := &types.Route{
		Prefix: netip.MustParsePrefix("198.51.100.0/24"),
		ASPath: []uint32{64501, 64666},
	}

	result := a.Validate(route)
	if result.State != types.ROVInvalid {
		t.Errorf("expected Invalid, got %s: %s", result.State, result.Reason)
	}
}

func TestROVInvalidMoreSpecific(t *testing.T) {
	s := store.NewVRPStore()
	// ROA says /24 max, but route is /25 — more-specific hijack
	s.ReplaceAll([]types.VRP{
		{Prefix: netip.MustParsePrefix("198.51.100.0/24"), ASN: 13335, MaxLength: 24},
	}, 1, 1)

	a := NewAnnotator(s)
	route := &types.Route{
		Prefix: netip.MustParsePrefix("198.51.100.0/25"),
		ASPath: []uint32{64501, 13335},
	}

	result := a.Validate(route)
	if result.State != types.ROVInvalid {
		t.Errorf("expected Invalid (more-specific), got %s: %s", result.State, result.Reason)
	}
}

func TestROVValidWithMaxLength(t *testing.T) {
	s := store.NewVRPStore()
	// ROA allows up to /28
	s.ReplaceAll([]types.VRP{
		{Prefix: netip.MustParsePrefix("198.51.100.0/24"), ASN: 13335, MaxLength: 28},
	}, 1, 1)

	a := NewAnnotator(s)
	route := &types.Route{
		Prefix: netip.MustParsePrefix("198.51.100.0/25"),
		ASPath: []uint32{64501, 13335},
	}

	result := a.Validate(route)
	if result.State != types.ROVValid {
		t.Errorf("expected Valid (within maxLength), got %s: %s", result.State, result.Reason)
	}
}

func TestROVNotFound(t *testing.T) {
	s := store.NewVRPStore()
	// No VRPs at all
	a := NewAnnotator(s)
	route := &types.Route{
		Prefix: netip.MustParsePrefix("10.0.0.0/8"),
		ASPath: []uint32{64501, 64502},
	}

	result := a.Validate(route)
	if result.State != types.ROVNotFound {
		t.Errorf("expected NotFound, got %s: %s", result.State, result.Reason)
	}
}

func TestROVNoOriginASN(t *testing.T) {
	s := store.NewVRPStore()
	a := NewAnnotator(s)
	route := &types.Route{
		Prefix: netip.MustParsePrefix("10.0.0.0/8"),
		ASPath: nil, // empty AS_PATH
	}

	result := a.Validate(route)
	if result.State != types.ROVNotFound {
		t.Errorf("expected NotFound for empty AS_PATH, got %s", result.State)
	}
}

func TestROVValidIPv6(t *testing.T) {
	s := store.NewVRPStore()
	s.ReplaceAll([]types.VRP{
		{Prefix: netip.MustParsePrefix("2001:db8:2121::/48"), ASN: 2121, MaxLength: 48},
	}, 1, 1)

	a := NewAnnotator(s)
	route := &types.Route{
		Prefix: netip.MustParsePrefix("2001:db8:2121::/48"),
		ASPath: []uint32{65000, 2121},
	}

	result := a.Validate(route)
	if result.State != types.ROVValid {
		t.Errorf("expected Valid for IPv6 match, got %s: %s", result.State, result.Reason)
	}
}

func TestROVInvalidIPv6OriginMismatch(t *testing.T) {
	s := store.NewVRPStore()
	s.ReplaceAll([]types.VRP{
		{Prefix: netip.MustParsePrefix("2001:db8:2121::/48"), ASN: 2121, MaxLength: 48},
	}, 1, 1)

	a := NewAnnotator(s)
	// Wrong origin ASN — IPv6 hijack scenario
	route := &types.Route{
		Prefix: netip.MustParsePrefix("2001:db8:2121::/48"),
		ASPath: []uint32{65000, 65001},
	}

	result := a.Validate(route)
	if result.State != types.ROVInvalid {
		t.Errorf("expected Invalid for IPv6 origin mismatch, got %s: %s", result.State, result.Reason)
	}
}

func TestROVNotFoundIPv6(t *testing.T) {
	s := store.NewVRPStore()
	// VRPs for a different IPv6 prefix — should not cover this route
	s.ReplaceAll([]types.VRP{
		{Prefix: netip.MustParsePrefix("2001:db8:2121::/48"), ASN: 2121, MaxLength: 48},
	}, 1, 1)

	a := NewAnnotator(s)
	route := &types.Route{
		Prefix: netip.MustParsePrefix("2001:db8:dead::/48"),
		ASPath: []uint32{65000, 65001},
	}

	result := a.Validate(route)
	if result.State != types.ROVNotFound {
		t.Errorf("expected NotFound for uncovered IPv6, got %s: %s", result.State, result.Reason)
	}
}

// TestROVMixedFamilies confirms IPv4 validation still works when the store
// contains both IPv4 and IPv6 VRPs. Regression check for the IPv6 rollout.
func TestROVMixedFamilies(t *testing.T) {
	s := store.NewVRPStore()
	s.ReplaceAll([]types.VRP{
		{Prefix: netip.MustParsePrefix("2001:db8:2121::/48"), ASN: 2121, MaxLength: 48},
		{Prefix: netip.MustParsePrefix("198.51.100.0/24"), ASN: 13335, MaxLength: 24},
		{Prefix: netip.MustParsePrefix("2001:db8:6501::/48"), ASN: 65001, MaxLength: 48},
	}, 1, 1)

	a := NewAnnotator(s)

	v4 := &types.Route{
		Prefix: netip.MustParsePrefix("198.51.100.0/24"),
		ASPath: []uint32{64501, 13335},
	}
	if got := a.Validate(v4); got.State != types.ROVValid {
		t.Errorf("IPv4 with IPv6 VRPs in store: expected Valid, got %s: %s", got.State, got.Reason)
	}

	v6 := &types.Route{
		Prefix: netip.MustParsePrefix("2001:db8:6501::/48"),
		ASPath: []uint32{65000, 65001},
	}
	if got := a.Validate(v6); got.State != types.ROVValid {
		t.Errorf("IPv6 with IPv4 VRPs in store: expected Valid, got %s: %s", got.State, got.Reason)
	}
}

func TestROVMultipleVRPs(t *testing.T) {
	s := store.NewVRPStore()
	s.ReplaceAll([]types.VRP{
		{Prefix: netip.MustParsePrefix("198.51.100.0/24"), ASN: 13335, MaxLength: 24},
		{Prefix: netip.MustParsePrefix("198.51.100.0/24"), ASN: 64501, MaxLength: 24},
	}, 1, 1)

	a := NewAnnotator(s)
	// Origin is 64501 — second VRP should match
	route := &types.Route{
		Prefix: netip.MustParsePrefix("198.51.100.0/24"),
		ASPath: []uint32{3356, 64501},
	}

	result := a.Validate(route)
	if result.State != types.ROVValid {
		t.Errorf("expected Valid (second VRP matches), got %s: %s", result.State, result.Reason)
	}
}
