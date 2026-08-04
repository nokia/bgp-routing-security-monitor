package aspa

import (
	"testing"

	"github.com/nokia/bgp-routing-security-monitor/internal/rtr/store"
	"github.com/nokia/bgp-routing-security-monitor/internal/types"
)

// TestValidate_RouteLeak_FirstHopCatchesIt reproduces the live route-leak
// scenario: sros-2 (AS64500) receives 198.51.100.0/24 via frr-attacker
// (AS64509) with AS-path [64509, 64501, 64502]. sros-1 (AS64501) has no
// ASPA record, so without the path[0]-vs-local-AS check the loop's last
// real hop (customer=64501) resolves to NoASPA and the route incorrectly
// comes back ASPAUnknown.
//
// The catch requires an ASPA record for AS64509 itself (path[0]) whose
// provider set does not include AS64500 (LocalASN) — i.e. AS64509 declares
// who its legitimate providers are, and sros-2 isn't one of them. That's
// exactly the "path[0]-vs-local-AS" edge the fix adds.
func TestValidate_RouteLeak_FirstHopCatchesIt(t *testing.T) {
	aspaStore := store.NewASPAStore()
	// AS64509's ASPA record does not list AS64500 (us) as an authorized provider.
	aspaStore.AddProvider(64509, 64510)

	annotator := NewAnnotator(aspaStore)

	route := &types.Route{
		ASPath:   []uint32{64509, 64501, 64502},
		LocalASN: 64500,
	}

	result := annotator.Validate(route)

	if result.State != types.ASPAInvalid {
		t.Fatalf("expected ASPAInvalid, got %s", result.State)
	}
	if result.FailingHop == nil {
		t.Fatal("expected a FailingHop, got nil")
	}
	if result.FailingHop.CustomerASN != 64509 || result.FailingHop.ProviderASN != 64500 {
		t.Fatalf("expected failing hop customer=64509 provider=64500, got customer=%d provider=%d",
			result.FailingHop.CustomerASN, result.FailingHop.ProviderASN)
	}
	if result.FailingHop.Authorization != types.HopNotAuthorized {
		t.Fatalf("expected failing hop Authorization=HopNotAuthorized, got %v", result.FailingHop.Authorization)
	}
}

// TestValidate_NoLocalASN_PreservesOldBehavior ensures that when LocalASN is
// unknown (e.g. a session where the Peer Up OPEN couldn't be parsed), the
// final hop check is skipped and existing behavior is unchanged.
func TestValidate_NoLocalASN_PreservesOldBehavior(t *testing.T) {
	aspaStore := store.NewASPAStore()
	// No ASPA record for AS64501 (the last real hop) — same shape as before
	// LocalASN existed.

	annotator := NewAnnotator(aspaStore)

	route := &types.Route{
		ASPath: []uint32{64509, 64501, 64502},
		// LocalASN left as zero value — unknown.
	}

	result := annotator.Validate(route)

	if result.State != types.ASPAUnknown {
		t.Fatalf("expected ASPAUnknown when LocalASN is unset, got %s", result.State)
	}
	if result.FailingHop != nil {
		t.Fatalf("expected no FailingHop, got %+v", result.FailingHop)
	}
}

// TestValidate_ValidPath_WithLocalASNAuthorized confirms a fully legitimate
// path (every hop, including the final path[0]-vs-local-AS edge) validates
// as ASPAValid rather than being penalized by the new check.
func TestValidate_ValidPath_WithLocalASNAuthorized(t *testing.T) {
	aspaStore := store.NewASPAStore()
	aspaStore.AddProvider(64502, 64501) // AS64502's provider is AS64501
	aspaStore.AddProvider(64501, 64500) // AS64501's provider is AS64500 (us)

	annotator := NewAnnotator(aspaStore)

	route := &types.Route{
		ASPath:   []uint32{64501, 64502},
		LocalASN: 64500,
	}

	result := annotator.Validate(route)

	if result.State != types.ASPAValid {
		t.Fatalf("expected ASPAValid, got %s", result.State)
	}
	if result.FailingHop != nil {
		t.Fatalf("expected no FailingHop, got %+v", result.FailingHop)
	}
}

// TestValidate_SingleASPath_LocalASNKnown ensures a single-AS path (route
// learned directly from its originator) still gets the final hop checked
// against LocalASN, rather than short-circuiting to Unknown as before.
func TestValidate_SingleASPath_LocalASNKnown(t *testing.T) {
	aspaStore := store.NewASPAStore()
	aspaStore.AddProvider(64501, 64509) // AS64501's authorized provider is NOT us

	annotator := NewAnnotator(aspaStore)

	route := &types.Route{
		ASPath:   []uint32{64501},
		LocalASN: 64500,
	}

	result := annotator.Validate(route)

	if result.State != types.ASPAInvalid {
		t.Fatalf("expected ASPAInvalid, got %s", result.State)
	}
	if result.FailingHop == nil || result.FailingHop.CustomerASN != 64501 || result.FailingHop.ProviderASN != 64500 {
		t.Fatalf("unexpected failing hop: %+v", result.FailingHop)
	}
}
