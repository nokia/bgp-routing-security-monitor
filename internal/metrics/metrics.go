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

	// BGP peer state via BMP: 1=established 0=down. Labels: router, peer.
	BMPPeerState = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "raven_bmp_peer_state",
		Help: "BGP peer state as seen via BMP (1=established, 0=down).",
	}, []string{"router", "peer"})

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

	// Unix timestamp of last successful RTR sync. Label: cache.
	RTRLastSync = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "raven_rtr_last_sync_seconds",
		Help: "Unix timestamp of last successful RTR sync.",
	}, []string{"cache"})

	// Route counts by security posture and AFI. Labels: posture, afi.
	RoutesTotal = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "raven_routes_total",
		Help: "Number of routes by security posture and address family.",
	}, []string{"posture", "afi"})

	// Total pre-policy routes in the route table.
	RouteTableSize = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "raven_route_table_size",
		Help: "Total number of pre-policy routes in the route table.",
	})
)