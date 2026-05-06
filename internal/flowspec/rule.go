// Package flowspec implements the RAVEN Flowspec lifecycle manager.
// It generates BGP Flowspec NLRI rules, injects them via GoBGP's gRPC
// management API, tracks active rules in a registry with TTL, and
// withdraws expired rules via a periodic reaper goroutine.
package flowspec

import (
	"fmt"
	"net/netip"
	"time"
)

// FlowspecRuleAction specifies the BGP Flowspec traffic action.
type FlowspecRuleAction string

const (
	// FlowspecActionDrop sets traffic-rate 0 (discard all matching traffic).
	FlowspecActionDrop FlowspecRuleAction = "drop"
	// FlowspecActionRateLimit sets traffic-rate to RateLimit bps.
	FlowspecActionRateLimit FlowspecRuleAction = "rate-limit"
)

// FlowspecRule represents a single active Flowspec injection.
type FlowspecRule struct {
	// Key is the canonical identifier: "prefix|action", e.g. "10.0.0.0/8|drop".
	Key string
	// Prefix is the destination prefix to match (Type 1 Flowspec component).
	Prefix netip.Prefix
	// OriginASN is the origin AS of the affected route (0 if unknown).
	OriginASN uint32
	// PeerAddr is the peer that announced the affected route.
	PeerAddr netip.Addr
	// Action specifies the Flowspec traffic-action extended community.
	Action FlowspecRuleAction
	// RateLimit is the rate in bps used when Action == FlowspecActionRateLimit.
	RateLimit float32
	// InsertedAt is when this rule was first injected.
	InsertedAt time.Time
	// TTL is the maximum lifetime of the rule; 0 means the rule never expires.
	TTL time.Duration
	// EventID is the ID of the event that triggered this rule.
	EventID string
	// DryRun marks rules that should be logged but not sent to GoBGP.
	DryRun bool
}

// Expired reports whether the rule's TTL has elapsed since InsertedAt.
// Rules with TTL == 0 never expire.
func (r *FlowspecRule) Expired() bool {
	if r.TTL == 0 {
		return false
	}
	return time.Since(r.InsertedAt) >= r.TTL
}

// CanonicalKey returns the stable identifier for this rule: "prefix|action".
func (r *FlowspecRule) CanonicalKey() string {
	return fmt.Sprintf("%s|%s", r.Prefix.String(), string(r.Action))
}
