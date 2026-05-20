package events

import (
	"net/netip"
	"slices"

	"github.com/nokia/bgp-routing-security-monitor/internal/types"
)

// Trigger evaluates an Event and reports whether the associated rule should fire.
type Trigger interface {
	Matches(event Event) bool
}

// PostureTrigger fires when NewPosture matches any of the configured postures.
// It evaluates current steady state, not transitions.
type PostureTrigger struct {
	Postures []types.SecurityPosture
}

// Matches returns true if event.NewPosture is in the configured posture list.
func (t *PostureTrigger) Matches(event Event) bool {
	return slices.Contains(t.Postures, event.NewPosture)
}

// PostureChangeTrigger fires when OldPosture != NewPosture and NewPosture
// matches any of the configured postures. It catches transitions, not steady state.
type PostureChangeTrigger struct {
	Postures []types.SecurityPosture
}

// Matches returns true when the event represents a posture transition to one of the
// configured postures.
func (t *PostureChangeTrigger) Matches(event Event) bool {
	return event.OldPosture != event.NewPosture && slices.Contains(t.Postures, event.NewPosture)
}

// PrefixTrigger fires when the event's route prefix falls within the configured
// supernet (the route prefix is equal to or more specific than the supernet).
type PrefixTrigger struct {
	// Supernet is the covering prefix; any contained or identical prefix matches.
	Supernet netip.Prefix
}

// Matches returns true if the event's route prefix is covered by the supernet.
func (t *PrefixTrigger) Matches(event Event) bool {
	if event.Route == nil {
		return false
	}
	p := event.Route.Prefix
	return t.Supernet.Bits() <= p.Bits() && t.Supernet.Contains(p.Addr())
}

// ASNTrigger fires when the event's route involves one of the configured ASNs.
// Match controls the scope: "origin" (default) checks only route.OriginASN();
// "path" checks every ASN in the full AS path.
type ASNTrigger struct {
	ASNs  []uint32
	Match string
}

// Matches returns true when the route involves one of the configured ASNs.
func (t *ASNTrigger) Matches(event Event) bool {
	if event.Route == nil {
		return false
	}
	if t.Match == "path" {
		for _, asn := range event.Route.ASPath {
			if slices.Contains(t.ASNs, asn) {
				return true
			}
		}
		return false
	}
	// default: "origin"
	return slices.Contains(t.ASNs, event.Route.OriginASN())
}

// ProtectedASNTrigger fires when a route's origin violates a VRP that names one
// of the configured ASNs as the authorized originator. This detects prefix
// hijacks: the hijacking route does not contain the protected ASN in its path,
// but the covering VRP names it as the only authorized origin.
//
// It relies on ROV.MatchedVRPs populated by the validation engine before the
// event is emitted — no VRP store access is needed at match time.
type ProtectedASNTrigger struct {
	ASNs []uint32
}

// Matches returns true when the route is origin-invalid and a covering VRP
// authorises one of the protected ASNs for the route's prefix.
func (t *ProtectedASNTrigger) Matches(event Event) bool {
	if event.Route == nil {
		return false
	}
	if event.NewPosture != types.PostureOriginInvalid {
		return false
	}
	for _, vrp := range event.Route.ROV.MatchedVRPs {
		if slices.Contains(t.ASNs, vrp.ASN) {
			return true
		}
	}
	return false
}

// CacheUnhealthyTrigger fires on EventTypeCacheUnhealthy events.
type CacheUnhealthyTrigger struct{}

// Matches returns true for any cache-unhealthy event.
func (t *CacheUnhealthyTrigger) Matches(event Event) bool {
	return event.Type == EventTypeCacheUnhealthy
}

// CompoundTrigger combines multiple sub-triggers with AND or OR logic.
type CompoundTrigger struct {
	// Op is "and" (all must match) or "or" (any must match). Defaults to "and".
	Op       string
	Triggers []Trigger
}

// Matches evaluates sub-triggers according to the configured operator.
func (t *CompoundTrigger) Matches(event Event) bool {
	if t.Op == "or" {
		for _, sub := range t.Triggers {
			if sub.Matches(event) {
				return true
			}
		}
		return false
	}
	// default: "and"
	for _, sub := range t.Triggers {
		if !sub.Matches(event) {
			return false
		}
	}
	return true
}
