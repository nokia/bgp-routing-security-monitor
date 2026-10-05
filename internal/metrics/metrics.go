package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// BMP session state: 1=up 0=down. Label: router (sysName or addr).
	BMPSessionState = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "raven_bmp_session_state",
		Help: "BMP session state (1=up, 0=down).",
	}, []string{"router"})

	// BMP messages processed. Labels: router, msg_type.
	BMPMessagesTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "raven_bmp_messages_total",
		Help: "Total BMP messages processed.",
	}, []string{"router", "msg_type"})

	// BGP peer state via BMP (1=established, 0=down), by router, peer and distinguisher (empty for a global peer).
	BMPPeerState = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "raven_bmp_peer_state",
		Help: "BGP peer state as seen via BMP (1=established, 0=down).",
	}, []string{"router", "peer", "distinguisher"})

	// RTR session state: 1=connected 0=down. Label: cache.
	RTRSessionState = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "raven_rtr_session_state",
		Help: "RTR session state (1=connected, 0=disconnected).",
	}, []string{"cache"})

	// VRPs loaded from RTR cache. Label: cache.
	RTRVRPCount = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "raven_rtr_vrp_count",
		Help: "Number of VRPs loaded from RTR cache.",
	}, []string{"cache"})

	// ASPA records loaded from RTR cache. Label: cache.
	RTRASPACount = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "raven_rtr_aspa_count",
		Help: "Number of ASPA records loaded from RTR cache.",
	}, []string{"cache"})

	// Unix timestamp of last successful RTR sync. Label: cache.
	RTRLastSync = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "raven_rtr_last_sync_seconds",
		Help: "Unix timestamp of last successful RTR sync.",
	}, []string{"cache"})

	// RTR anomalies detected by the adaptive detector. Labels: cache, severity.
	RTRAnomalyTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "raven_rtr_anomaly_total",
		Help: "Total RTR anomalies detected, by severity.",
	}, []string{"cache", "severity"})

	// Unix timestamp of the most recent RTR anomaly detected. Label: cache.
	RTRAnomalyLastTimestamp = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "raven_rtr_anomaly_last_timestamp",
		Help: "Unix timestamp of the most recent RTR anomaly detected.",
	}, []string{"cache"})

	// Route counts by security posture, AFI and RIB.
	RoutesTotal = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "raven_routes_total",
		Help: "Number of routes by security posture, address family and RIB.",
	}, []string{"posture", "afi", "rib"})

	// Routes in the route table, by RIB.
	RouteTableSize = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "raven_route_table_size",
		Help: "Number of routes in the route table, by RIB.",
	}, []string{"rib"})

	// External global-visibility correlations. Labels: source (e.g.
	// "ripestat"), result (match, divergent, local_only, inconclusive).
	GlobalCheckTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "raven_global_check_total",
		Help: "Total external global-visibility correlations, by source and consensus result.",
	}, []string{"source", "result"})

	// Global-visibility lookups suppressed by the local rate limiter before
	// any provider was contacted. Label: source (e.g. "ripestat").
	//
	// Separate from raven_global_check_total on purpose: a rate-limit
	// rejection is a policy decision costing no network call, and folding it
	// into the inconclusive result label made it indistinguishable from a
	// provider RAVEN genuinely could not reach.
	GlobalCheckRateLimited = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "raven_global_check_rate_limited_total",
		Help: "Total external global-visibility lookups suppressed by the local rate limiter, by source.",
	}, []string{"source"})

	// Global-visibility lookups the provider served from its in-process cache
	// without a network round-trip. Label: source (e.g. "ripestat").
	//
	// Like the rate-limited counter, this keeps a non-network event off
	// raven_global_check_latency_seconds while leaving cache activity
	// visible: rate(cache_hits) / rate(check_total) is the cache hit ratio.
	GlobalCheckCacheHits = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "raven_global_check_cache_hits_total",
		Help: "Total global-visibility lookups served from the in-process cache, by source.",
	}, []string{"source"})

	// Latency of a global-visibility correlation that actually went to the
	// provider, successful or not.
	//
	// Cache hits and rate-limited lookups are both excluded: neither made a
	// network round-trip, and their near-zero timings would pull p50/p95
	// toward zero whenever the cache is warm, masking exactly the provider
	// latency degradation an operator alerts on.
	GlobalCheckLatency = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "raven_global_check_latency_seconds",
		Help:    "Latency of external global-visibility correlations in seconds.",
		Buckets: []float64{.001, .005, .025, .1, .25, .5, 1, 2.5, 5, 10},
	})
)
