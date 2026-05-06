package otel

// OTLP metric names exported by RAVEN.
// These mirror the existing Prometheus metric names (with dots instead
// of underscores as the OTel convention requires).
const (
	MetricRoutesTotal        = "raven.routes.total"
	MetricPeerRoutes         = "raven.peer.routes"
	MetricBMPSessionState    = "raven.bmp.session.state"
	MetricBMPMessagesTotal   = "raven.bmp.messages.total"
	MetricRTRSessionState    = "raven.rtr.session.state"
	MetricRTRVRPCount        = "raven.rtr.vrp.count"
	MetricRTRASPACount       = "raven.rtr.aspa.count"
	MetricRTRLastSyncSeconds = "raven.rtr.last_sync.seconds"
)

// AllMetrics lists every metric name in declaration order.
var AllMetrics = []string{
	MetricRoutesTotal,
	MetricPeerRoutes,
	MetricBMPSessionState,
	MetricBMPMessagesTotal,
	MetricRTRSessionState,
	MetricRTRVRPCount,
	MetricRTRASPACount,
	MetricRTRLastSyncSeconds,
}
