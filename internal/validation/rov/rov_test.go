package rov

import (
	"net/netip"
	"testing"

	"github.com/srl-labs/raven/internal/rtr/store"
	"github.com/srl-labs/raven/internal/types"
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
