package otel

// StateReader provides read-only access to RAVEN's current runtime state.
// It is implemented by internal/server.Server and defined here so that
// internal/otel never imports internal/server (which would be circular).
type StateReader interface {
	// RouteCountsByPosture returns the current route count broken down by
	// security posture and address family.
	// map[posture]map[afi]count — e.g. map["secured"]["ipv4"]42
	RouteCountsByPosture() map[string]map[string]int64

	// PeerRouteCounts returns per-peer route counts.
	PeerRouteCounts() []PeerRouteCount

	// BMPSessionStates returns the up/down state for each connected router.
	BMPSessionStates() []BMPSessionState

	// BMPMessageCounts returns cumulative BMP message counts per router and
	// message type.
	BMPMessageCounts() []BMPMessageCount

	// RTRSessionStates returns the connection state of each RTR cache.
	RTRSessionStates() []RTRSessionState

	// RTRCacheCounts returns VRP/ASPA counts and last-sync time per cache.
	RTRCacheCounts() []RTRCacheCount
}

// PeerRouteCount holds the route count for a single BGP peer.
type PeerRouteCount struct {
	PeerAddr string
	PeerASN  uint32
	Posture  string
	Count    int64
}

// BMPSessionState holds the up/down state for one router's BMP session.
type BMPSessionState struct {
	RouterID string
	State    int64 // 1 = up, 0 = down
}

// BMPMessageCount holds a cumulative message count for one router+type pair.
type BMPMessageCount struct {
	RouterID string
	MsgType  string
	Count    int64
}

// RTRSessionState holds the connection state for one RTR cache.
type RTRSessionState struct {
	CacheName string
	State     int64 // 1 = connected, 0 = disconnected
}

// RTRCacheCount holds VRP/ASPA counts and last-sync timestamp for one cache.
type RTRCacheCount struct {
	CacheName string
	VRPCount  int64
	ASPACount int64
	LastSync  int64 // unix seconds; 0 if never synced
}
