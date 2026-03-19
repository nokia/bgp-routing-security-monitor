package rov

import (
	"fmt"

	"github.com/srl-labs/raven/internal/rtr/store"
	"github.com/srl-labs/raven/internal/types"
)

// Annotator performs Route Origin Validation per RFC 6811.
type Annotator struct {
	vrpStore *store.VRPStore
}

// NewAnnotator creates a ROV annotator backed by the given VRP store.
func NewAnnotator(vrpStore *store.VRPStore) *Annotator {
	return &Annotator{vrpStore: vrpStore}
}

// Validate performs ROV on a single route and returns the result.
//
// Algorithm (RFC 6811 §2):
//  1. Find all VRPs whose prefix covers the route's prefix.
//  2. If no covering VRPs exist → NotFound.
//  3. If any covering VRP matches the origin ASN AND the route's
//     prefix length ≤ VRP's maxLength → Valid.
//  4. Otherwise → Invalid.
func (a *Annotator) Validate(route *types.Route) types.ROVResult {
	originASN := route.OriginASN()
	if originASN == 0 {
		return types.ROVResult{
			State:  types.ROVNotFound,
			Reason: "no origin ASN in AS_PATH",
		}
	}

	covering := a.vrpStore.FindCovering(route.Prefix)

	if len(covering) == 0 {
		return types.ROVResult{
			State:  types.ROVNotFound,
			Reason: "no covering VRPs found",
		}
	}

	routePrefixLen := route.Prefix.Bits()

	for _, vrp := range covering {
		if vrp.ASN == originASN && routePrefixLen <= int(vrp.MaxLength) {
			return types.ROVResult{
				State:       types.ROVValid,
				MatchedVRPs: covering,
				Reason:      fmt.Sprintf("matches VRP {%s, AS%d, /%d}", vrp.Prefix, vrp.ASN, vrp.MaxLength),
			}
		}
	}

	return types.ROVResult{
		State:       types.ROVInvalid,
		MatchedVRPs: covering,
		Reason:      fmt.Sprintf("origin AS%d not authorized by any covering VRP", originASN),
	}
}
