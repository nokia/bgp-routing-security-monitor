// Package events implements the RAVEN Phase 3 active-response event engine.
// It defines event types, triggers, actions, rules, and the engine that
// evaluates them in response to BGP security state changes.
package events

import (
	"crypto/rand"
	"fmt"
	"time"

	"github.com/nokia/bgp-routing-security-monitor/internal/types"
)

// EventType distinguishes what triggered the event.
type EventType string

const (
	// EventTypeNewRoute fires when a route is seen for the first time.
	EventTypeNewRoute EventType = "new_route"
	// EventTypePostureChange fires when an existing route changes security posture.
	EventTypePostureChange EventType = "posture_change"
	// EventTypeRouteWithdraw fires when a route is withdrawn via BMP.
	EventTypeRouteWithdraw EventType = "route_withdraw"
	// EventTypeCacheUnhealthy fires when an RTR cache goes stale or unreachable.
	EventTypeCacheUnhealthy EventType = "cache_unhealthy"
)

// Event is the payload passed to every trigger and action.
type Event struct {
	// ID is a UUID v4 generated at event creation.
	ID        string
	Timestamp time.Time
	Type      EventType
	// Route is the BGP route associated with this event. Nil for CacheUnhealthy events.
	Route *types.Route
	// OldPosture is the security posture before the change; empty for EventTypeNewRoute.
	OldPosture types.SecurityPosture
	// NewPosture is the current security posture after validation.
	NewPosture types.SecurityPosture
	// CacheName is populated for EventTypeCacheUnhealthy events.
	CacheName string
	// RouterID is the router that sourced this event.
	RouterID string
}

// NewID returns a random UUID v4 string suitable for use as an event identifier.
func NewID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "00000000-0000-0000-0000-000000000000"
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant RFC 4122
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}
