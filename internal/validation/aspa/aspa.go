// Package aspa implements AS_PATH verification per
// draft-ietf-sidrops-aspa-verification-24.
package aspa

import (
	"github.com/nokia/bgp-routing-security-monitor/internal/rtr/store"
	"github.com/nokia/bgp-routing-security-monitor/internal/types"
)

// Annotator performs ASPA AS_PATH verification.
type Annotator struct {
	aspaStore *store.ASPAStore
}

// NewAnnotator creates an ASPA annotator backed by the given store.
func NewAnnotator(aspaStore *store.ASPAStore) *Annotator {
	return &Annotator{aspaStore: aspaStore}
}

// Validate performs upstream AS_PATH verification on a route.
// Returns an ASPAResult with State, per-hop details, and failing hop if any.
//
// Algorithm per draft-ietf-sidrops-aspa-verification-24 §6.1 (upstream):
//
//  1. If AS_PATH contains an AS_SET → Unverifiable
//  2. Walk pairs (AS[i], AS[i-1]) from origin toward verifying AS:
//     - If ASPA exists for AS[i] and AS[i-1] is in provider set → Authorized
//     - If ASPA exists for AS[i] and AS[i-1] is NOT in provider set → Invalid
//     - If no ASPA for AS[i] → NoASPA (unknown for this hop)
//  3. Result:
//     - Any hop Invalid → ASPAInvalid
//     - All hops Authorized → ASPAValid
//     - Mix of Authorized + NoASPA → ASPAUnknown
//     - No hops (path length 0 or 1) → ASPAUnknown
func (a *Annotator) Validate(route *types.Route) types.ASPAResult {
	// Check for AS_SET segments — unverifiable per the draft
	for _, seg := range route.ASPathRaw {
		if seg.Type == types.ASSegmentSet {
			return types.ASPAResult{
				State:     types.ASPAUnverifiable,
				Procedure: types.ASPAUpstream,
			}
		}
	}

	path := route.ASPath
	if len(path) == 0 {
		// Self-originated route — no path to verify
		return types.ASPAResult{
			State:     types.ASPAUnknown,
			Procedure: types.ASPAUpstream,
		}
	}

	if len(path) == 1 {
		// Single-hop path — no pairs to verify
		return types.ASPAResult{
			State:     types.ASPAUnknown,
			Procedure: types.ASPAUpstream,
		}
	}

	// Walk pairs from origin (path[len-1]) toward verifying AS (path[0])
	// AS_PATH is stored as [neighbor, ..., origin] so we walk right to left
	hops := make([]types.ASPAHop, 0, len(path)-1)
	hasInvalid := false
	hasNoASPA := false

	for i := len(path) - 1; i > 0; i-- {
		customerASN := path[i]
		providerASN := path[i-1]

		hop := types.ASPAHop{
			CustomerASN: customerASN,
			ProviderASN: providerASN,
		}

		if !a.aspaStore.HasRecord(customerASN) {
			// No ASPA object for this customer — unknown
			hop.Authorization = types.HopNoASPA
			hasNoASPA = true
		} else if a.aspaStore.HasProvider(customerASN, providerASN) {
			// Provider is authorized
			hop.Authorization = types.HopAuthorized
		} else {
			// ASPA exists but provider not in set — invalid
			hop.Authorization = types.HopNotAuthorized
			hasInvalid = true
		}
		hops = append(hops, hop)
	}

	result := types.ASPAResult{
		HopDetails: hops,
		Procedure:  types.ASPAUpstream,
	}

	switch {
	case hasInvalid:
		result.State = types.ASPAInvalid
		// Find the first failing hop
		for i := range hops {
			if hops[i].Authorization == types.HopNotAuthorized {
				h := hops[i]
				result.FailingHop = &h
				break
			}
		}
	case hasNoASPA:
		// Mix of authorized and unknown hops — can't confirm validity
		result.State = types.ASPAUnknown
	default:
		// All hops authorized
		result.State = types.ASPAValid
	}

	return result
}
