package otel

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel/attribute"
	otelmetric "go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"go.opentelemetry.io/otel/sdk/resource"

	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
)

// Exporter wraps the OTel MeterProvider and registers observable-gauge
// callbacks for all RAVEN metrics. The server calls SetReader once to
// inject its state, after which the SDK drives collection automatically.
type Exporter struct {
	provider     *metric.MeterProvider
	meter        otelmetric.Meter
	reader       StateReader          // injected via SetReader; nil-safe in callbacks
	manualReader *metric.ManualReader // non-nil only when created via NewExporterWithReader

	// Observable gauge handles — one per metric constant.
	routesTotal        otelmetric.Int64ObservableGauge
	peerRoutes         otelmetric.Int64ObservableGauge
	bmpSessionState    otelmetric.Int64ObservableGauge
	bmpMessagesTotal   otelmetric.Int64ObservableGauge
	rtrSessionState    otelmetric.Int64ObservableGauge
	rtrVRPCount        otelmetric.Int64ObservableGauge
	rtrASPACount       otelmetric.Int64ObservableGauge
	rtrLastSyncSeconds otelmetric.Int64ObservableGauge
}

// NewExporter constructs and starts the Exporter against a live OTLP collector.
//
//   - protocol: "grpc" (default) | "http"
//   - endpoint: collector address e.g. "localhost:4317" (grpc) or "localhost:4318" (http)
//   - interval: push interval, default 30 s
//   - headers:  optional metadata for auth
//   - insecure: disable TLS (default true for local collector)
//
// Returns (nil, nil) when cfg.Enabled is false — callers must check for nil.
// Non-fatal if the collector is unreachable at startup; the SDK logs warnings
// on each failed export attempt and retries automatically.
func NewExporter(ctx context.Context, cfg OTelConfig) (*Exporter, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	cfg.applyDefaults()

	// Build the OTLP wire exporter (gRPC or HTTP).
	sdkExp, err := buildSDKExporter(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("otel: build exporter: %w", err)
	}

	// Wrap in a periodic reader that pushes on the configured interval.
	periodicReader := metric.NewPeriodicReader(sdkExp,
		metric.WithInterval(cfg.Interval),
	)

	provider, err := buildProvider(periodicReader, cfg)
	if err != nil {
		return nil, err
	}
	return newExporterFromProvider(provider, nil)
}

// NewExporterWithReader creates an Exporter backed by a ManualReader for testing.
// Call Produce to trigger one synchronous collection.
func NewExporterWithReader(mr *metric.ManualReader, sr StateReader) (*Exporter, error) {
	provider, err := buildProvider(mr, OTelConfig{})
	if err != nil {
		return nil, err
	}
	exp, err := newExporterFromProvider(provider, mr)
	if err != nil {
		return nil, err
	}
	exp.reader = sr
	return exp, nil
}

// SetReader injects the StateReader that callbacks will read from.
// Must be called before the first metric collection.
func (e *Exporter) SetReader(r StateReader) {
	e.reader = r
}

// Produce triggers one synchronous collection and returns the snapshot.
// Only meaningful when the Exporter was created via NewExporterWithReader.
func (e *Exporter) Produce(ctx context.Context, rm *metricdata.ResourceMetrics) error {
	if e.manualReader == nil {
		return fmt.Errorf("otel: Produce requires a ManualReader (use NewExporterWithReader)")
	}
	return e.manualReader.Collect(ctx, rm)
}

// Shutdown flushes pending exports and stops the MeterProvider.
// Call during graceful shutdown.
func (e *Exporter) Shutdown(ctx context.Context) error {
	return e.provider.Shutdown(ctx)
}

// ── internal constructors ────────────────────────────────────────────────────

func buildSDKExporter(ctx context.Context, cfg OTelConfig) (metric.Exporter, error) {
	switch cfg.Protocol {
	case "http":
		opts := []otlpmetrichttp.Option{
			otlpmetrichttp.WithEndpoint(cfg.Endpoint),
		}
		if cfg.Insecure {
			opts = append(opts, otlpmetrichttp.WithInsecure())
		}
		if len(cfg.Headers) > 0 {
			opts = append(opts, otlpmetrichttp.WithHeaders(cfg.Headers))
		}
		return otlpmetrichttp.New(ctx, opts...)
	default: // grpc
		opts := []otlpmetricgrpc.Option{
			otlpmetricgrpc.WithEndpoint(cfg.Endpoint),
		}
		if cfg.Insecure {
			opts = append(opts, otlpmetricgrpc.WithInsecure())
		}
		if len(cfg.Headers) > 0 {
			opts = append(opts, otlpmetricgrpc.WithHeaders(cfg.Headers))
		}
		return otlpmetricgrpc.New(ctx, opts...)
	}
}

func buildProvider(r metric.Reader, cfg OTelConfig) (*metric.MeterProvider, error) {
	var resOpts []resource.Option
	if len(cfg.ResourceAttributes) > 0 {
		attrs := make([]attribute.KeyValue, 0, len(cfg.ResourceAttributes))
		for k, v := range cfg.ResourceAttributes {
			attrs = append(attrs, attribute.String(k, v))
		}
		resOpts = append(resOpts, resource.WithAttributes(attrs...))
	}
	res, err := resource.New(context.Background(), resOpts...)
	if err != nil {
		// resource.New may return a partial resource with a non-nil error
		// when some detectors fail; use the partial resource rather than aborting.
		_ = err
	}
	opts := []metric.Option{metric.WithReader(r)}
	if res != nil {
		opts = append(opts, metric.WithResource(res))
	}
	return metric.NewMeterProvider(opts...), nil
}

func newExporterFromProvider(provider *metric.MeterProvider, mr *metric.ManualReader) (*Exporter, error) {
	m := provider.Meter("raven",
		otelmetric.WithInstrumentationVersion("0.1.0"),
	)

	e := &Exporter{
		provider:     provider,
		meter:        m,
		manualReader: mr,
	}
	if err := e.initInstruments(); err != nil {
		return nil, fmt.Errorf("otel: init instruments: %w", err)
	}
	return e, nil
}

// initInstruments creates all observable gauges and registers a single
// batch callback that reads from e.reader.
func (e *Exporter) initInstruments() error {
	var err error

	e.routesTotal, err = e.meter.Int64ObservableGauge(MetricRoutesTotal,
		otelmetric.WithDescription("Number of routes by security posture and address family."))
	if err != nil {
		return err
	}
	e.peerRoutes, err = e.meter.Int64ObservableGauge(MetricPeerRoutes,
		otelmetric.WithDescription("Number of routes per BGP peer."))
	if err != nil {
		return err
	}
	e.bmpSessionState, err = e.meter.Int64ObservableGauge(MetricBMPSessionState,
		otelmetric.WithDescription("BMP session state (1=up, 0=down)."))
	if err != nil {
		return err
	}
	e.bmpMessagesTotal, err = e.meter.Int64ObservableGauge(MetricBMPMessagesTotal,
		otelmetric.WithDescription("Cumulative BMP messages processed."))
	if err != nil {
		return err
	}
	e.rtrSessionState, err = e.meter.Int64ObservableGauge(MetricRTRSessionState,
		otelmetric.WithDescription("RTR session state (1=connected, 0=disconnected)."))
	if err != nil {
		return err
	}
	e.rtrVRPCount, err = e.meter.Int64ObservableGauge(MetricRTRVRPCount,
		otelmetric.WithDescription("Number of VRPs loaded from RTR cache."))
	if err != nil {
		return err
	}
	e.rtrASPACount, err = e.meter.Int64ObservableGauge(MetricRTRASPACount,
		otelmetric.WithDescription("Number of ASPA records loaded from RTR cache."))
	if err != nil {
		return err
	}
	e.rtrLastSyncSeconds, err = e.meter.Int64ObservableGauge(MetricRTRLastSyncSeconds,
		otelmetric.WithDescription("Unix timestamp of last successful RTR sync."))
	if err != nil {
		return err
	}

	_, err = e.meter.RegisterCallback(e.collect,
		e.routesTotal,
		e.peerRoutes,
		e.bmpSessionState,
		e.bmpMessagesTotal,
		e.rtrSessionState,
		e.rtrVRPCount,
		e.rtrASPACount,
		e.rtrLastSyncSeconds,
	)
	return err
}

// collect is the OTel observable callback. Called by the SDK on each export.
func (e *Exporter) collect(_ context.Context, o otelmetric.Observer) error {
	r := e.reader
	if r == nil {
		return nil
	}

	// raven.routes.total — labels: posture, afi
	for posture, afis := range r.RouteCountsByPosture() {
		for afi, count := range afis {
			o.ObserveInt64(e.routesTotal, count,
				otelmetric.WithAttributes(
					attribute.String("posture", posture),
					attribute.String("afi", afi),
				))
		}
	}

	// raven.peer.routes — labels: peer_addr, peer_asn, posture
	for _, p := range r.PeerRouteCounts() {
		o.ObserveInt64(e.peerRoutes, p.Count,
			otelmetric.WithAttributes(
				attribute.String("peer_addr", p.PeerAddr),
				attribute.Int64("peer_asn", int64(p.PeerASN)),
				attribute.String("posture", p.Posture),
			))
	}

	// raven.bmp.session.state — label: router
	for _, s := range r.BMPSessionStates() {
		o.ObserveInt64(e.bmpSessionState, s.State,
			otelmetric.WithAttributes(
				attribute.String("router", s.RouterID),
			))
	}

	// raven.bmp.messages.total — labels: router, msg_type
	for _, m := range r.BMPMessageCounts() {
		o.ObserveInt64(e.bmpMessagesTotal, m.Count,
			otelmetric.WithAttributes(
				attribute.String("router", m.RouterID),
				attribute.String("msg_type", m.MsgType),
			))
	}

	// raven.rtr.session.state — label: cache
	for _, s := range r.RTRSessionStates() {
		o.ObserveInt64(e.rtrSessionState, s.State,
			otelmetric.WithAttributes(
				attribute.String("cache", s.CacheName),
			))
	}

	// raven.rtr.vrp.count, raven.rtr.aspa.count, raven.rtr.last_sync.seconds
	for _, c := range r.RTRCacheCounts() {
		cacheAttr := otelmetric.WithAttributes(attribute.String("cache", c.CacheName))
		o.ObserveInt64(e.rtrVRPCount, c.VRPCount, cacheAttr)
		o.ObserveInt64(e.rtrASPACount, c.ASPACount, cacheAttr)
		o.ObserveInt64(e.rtrLastSyncSeconds, c.LastSync, cacheAttr)
	}

	return nil
}
