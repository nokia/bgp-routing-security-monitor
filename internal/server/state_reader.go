package server

import (
	ravenotel "github.com/nokia/bgp-routing-security-monitor/internal/otel"
)

// Verify at compile time that *Server implements ravenotel.StateReader.
var _ ravenotel.StateReader = (*Server)(nil)

// RouteCountsByPosture returns the current pre-policy route count broken down
// by security posture and address family.
func (s *Server) RouteCountsByPosture() map[string]map[string]int64 {
	routes := s.table.AllPrePolicy()
	result := make(map[string]map[string]int64)
	for _, r := range routes {
		posture := string(r.SecurityPosture)
		if posture == "" {
			posture = "unverified"
		}
		afi := "ipv4"
		if r.Prefix.Addr().Is6() {
			afi = "ipv6"
		}
		if result[posture] == nil {
			result[posture] = make(map[string]int64)
		}
		result[posture][afi]++
	}
	return result
}

// PeerRouteCounts returns per-peer route counts derived from the BMP listener's
// peer state map.
func (s *Server) PeerRouteCounts() []ravenotel.PeerRouteCount {
	peers := s.bmpListen.GetPeers()
	result := make([]ravenotel.PeerRouteCount, 0, len(peers))
	for _, p := range peers {
		result = append(result, ravenotel.PeerRouteCount{
			PeerAddr: p.Addr.String(),
			PeerASN:  p.ASN,
			Posture:  "unverified", // per-peer posture not tracked; use "unverified"
			Count:    int64(p.RouteCount),
		})
	}
	return result
}

// BMPSessionStates returns the up/down state for each known BMP router session.
func (s *Server) BMPSessionStates() []ravenotel.BMPSessionState {
	states := s.bmpListen.GetRouterStates()
	result := make([]ravenotel.BMPSessionState, 0, len(states))
	for routerID, state := range states {
		result = append(result, ravenotel.BMPSessionState{
			RouterID: routerID,
			State:    state,
		})
	}
	return result
}

// BMPMessageCounts returns BMP message counts.
// Currently returns nil — message counts are tracked only in Prometheus counters
// and are not re-exported to OTel to avoid double-counting.
func (s *Server) BMPMessageCounts() []ravenotel.BMPMessageCount {
	return nil
}

// RTRSessionStates returns the connection state of each configured RTR cache.
func (s *Server) RTRSessionStates() []ravenotel.RTRSessionState {
	s.rtrMu.RLock()
	defer s.rtrMu.RUnlock()

	result := make([]ravenotel.RTRSessionState, 0, len(s.rtrStates))
	for cache, state := range s.rtrStates {
		result = append(result, ravenotel.RTRSessionState{
			CacheName: cache,
			State:     state,
		})
	}
	return result
}

// RTRCacheCounts returns VRP/ASPA counts and last-sync timestamps.
// VRP and ASPA stores are shared across all caches; each cache entry
// reports the same totals.
func (s *Server) RTRCacheCounts() []ravenotel.RTRCacheCount {
	vrpCount := int64(s.vrpStore.Count())
	aspaCount := int64(s.aspaStore.Count())

	s.rtrMu.RLock()
	lastSync := make(map[string]int64, len(s.rtrLastSync))
	for k, v := range s.rtrLastSync {
		lastSync[k] = v
	}
	s.rtrMu.RUnlock()

	result := make([]ravenotel.RTRCacheCount, 0, len(s.cfg.RTR.Caches))
	for _, cache := range s.cfg.RTR.Caches {
		result = append(result, ravenotel.RTRCacheCount{
			CacheName: cache.Address,
			VRPCount:  vrpCount,
			ASPACount: aspaCount,
			LastSync:  lastSync[cache.Address],
		})
	}
	return result
}
