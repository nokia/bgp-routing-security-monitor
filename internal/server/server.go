package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/nokia/bgp-routing-security-monitor/internal/api"
	"github.com/nokia/bgp-routing-security-monitor/internal/aspa/recommender"
	"github.com/nokia/bgp-routing-security-monitor/internal/bmp"
	"github.com/nokia/bgp-routing-security-monitor/internal/config"
	"github.com/nokia/bgp-routing-security-monitor/internal/events"
	"github.com/nokia/bgp-routing-security-monitor/internal/flowspec"
	"github.com/nokia/bgp-routing-security-monitor/internal/metrics"
	otelexporter "github.com/nokia/bgp-routing-security-monitor/internal/otel"
	"github.com/nokia/bgp-routing-security-monitor/internal/routetable"
	"github.com/nokia/bgp-routing-security-monitor/internal/rtr"
	"github.com/nokia/bgp-routing-security-monitor/internal/rtr/store"
	"github.com/nokia/bgp-routing-security-monitor/internal/snapshot"
	"github.com/nokia/bgp-routing-security-monitor/internal/types"
	"github.com/nokia/bgp-routing-security-monitor/internal/validation"
	"github.com/nokia/bgp-routing-security-monitor/internal/whatif"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Version is the RAVEN build version embedded in snapshots for compatibility
// checking. Set at build time via -ldflags "-X ...server.Version=v1.2.3".
var Version = "dev"

// DefaultAPIListen is the address the JSON API server binds to.
const DefaultAPIListen = ":11020"

// Server is the top-level RAVEN daemon that owns all subsystems.
type Server struct {
	cfg         *config.Config
	log         *slog.Logger
	table       *routetable.Table
	bmpListen   *bmp.Listener
	vrpStore    *store.VRPStore
	aspaStore   *store.ASPAStore
	engine      *validation.Engine
	eventEngine *events.Engine
	routeCh     chan types.Route
	demoMode    bool
	apiSrv      *api.Server
	rtrReady    chan struct{}
	withdrawCh  chan types.Withdrawal

	// fsManagers holds the active flowspec lifecycle managers.
	fsManagers []*flowspec.Manager

	// rtrMu guards rtrStates and rtrLastSync for StateReader.
	rtrMu       sync.RWMutex
	rtrStates   map[string]int64 // cache address → 1 connected, 0 disconnected
	rtrLastSync map[string]int64 // cache address → unix seconds of last sync
}

// New creates a new RAVEN server from the given config.
func New(cfg *config.Config, log *slog.Logger) *Server {
	routeCh := make(chan types.Route, 100_000)
	vrpStore := store.NewVRPStore()
	aspaStore := store.NewASPAStore() // ADD
	table := routetable.New()
	engine := validation.NewEngine(vrpStore, aspaStore, table, log)
	withdrawCh := make(chan types.Withdrawal, 10_000)

	srv := &Server{
		cfg:         cfg,
		log:         log,
		table:       table,
		bmpListen:   bmp.NewListener(cfg.BMP.Listen, routeCh, withdrawCh, log),
		vrpStore:    vrpStore,
		aspaStore:   aspaStore, // ADD
		engine:      engine,
		routeCh:     routeCh,
		rtrReady:    make(chan struct{}),
		withdrawCh:  withdrawCh,
		rtrStates:   make(map[string]int64),
		rtrLastSync: make(map[string]int64),
	}

	// Existing API server
	srv.apiSrv = api.NewServer(table, srv.bmpListen, vrpStore, log, "dev")

	// Phase 2b: what-if + recommender
	sim := whatif.NewSimulator(table)
	rec := recommender.NewRecommender(table, aspaStore)
	whatifHandler := api.NewWhatIfHandler(sim, rec, aspaStore)
	whatifHandler.RegisterRoutes(srv.apiSrv.Mux())

	// Audit endpoint
	auditHandler := api.NewAuditHandler(table)
	auditHandler.RegisterRoutes(srv.apiSrv.Mux())

	return srv
}

// SetDemoMode enables demo mode with test VRPs instead of live RTR.
func (s *Server) SetDemoMode(enabled bool) {
	s.demoMode = enabled
}

// Run starts all subsystems and blocks until interrupted.
func (s *Server) Run() error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// Build event engine before starting any goroutines so that routeIngestLoop
	// sees a non-nil s.eventEngine from the start.
	if len(s.cfg.Events.Rules) > 0 {
		eng, mgrs, err := events.BuildEngine(s.cfg.Events, s.log)
		if err != nil {
			return fmt.Errorf("event engine: %w", err)
		}
		s.eventEngine = eng
		s.fsManagers = mgrs
	}

	// Flowspec API endpoint — registered here so managers are available.
	fsHandler := api.NewFlowspecHandler(s.fsManagers)
	fsHandler.RegisterRoutes(s.apiSrv.Mux())

	// ── Warm-start restore (before BMP/RTR sessions open) ─────────────────
	if s.cfg.Persistence.Enabled {
		reader := snapshot.NewReader(s.cfg.Persistence.SnapshotDir, Version)

		if routes, err := reader.ReadRoutes(); err != nil {
			if !errors.Is(err, snapshot.ErrVersionMismatch) {
				s.log.Warn("failed to read route snapshot", "err", err)
			} else {
				s.log.Warn("route snapshot version mismatch, starting cold")
			}
		} else if routes != nil {
			s.table.Restore(routes)
			s.log.Info("restored route snapshot", "routes", len(routes))
		}

		if vrps, aspas, serial, err := reader.ReadRPKI(); err != nil {
			if !errors.Is(err, snapshot.ErrVersionMismatch) {
				s.log.Warn("failed to read RPKI snapshot", "err", err)
			} else {
				s.log.Warn("RPKI snapshot version mismatch, starting cold")
			}
		} else if vrps != nil {
			s.vrpStore.Restore(vrps)
			s.aspaStore.Restore(aspas)
			s.log.Info("restored RPKI snapshot",
				"vrps", len(vrps), "aspas", len(aspas), "serial", serial)
		}
	}

	var wg sync.WaitGroup

	// Route ingestion pipeline
	wg.Add(1)
	go func() {
		defer wg.Done()
		s.routeIngestLoop(ctx)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		s.withdrawIngestLoop(ctx)
	}()

	// BMP listener
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := s.bmpListen.Start(ctx); err != nil {
			s.log.Error("BMP listener failed", "error", err)
			cancel()
		}
	}()

	// RTR clients or demo mode
	if s.demoMode {
		rtr.LoadTestVRPs(s.vrpStore, s.log)
		close(s.rtrReady)
	} else {
		s.log.Info("starting RTR clients", "count", len(s.cfg.RTR.Caches))
		for _, cache := range s.cfg.RTR.Caches {
			wg.Add(1)
			go func() {
				defer wg.Done()
				addr := cache.Address
				client := rtr.NewClient(addr, s.vrpStore, s.aspaStore, s.log)
				client.SetOnUpdate(func() {
					s.engine.RevalidateAll()
					// Record last-sync time for StateReader/OTel.
					s.rtrMu.Lock()
					s.rtrLastSync[addr] = time.Now().Unix()
					s.rtrStates[addr] = 1
					s.rtrMu.Unlock()
				})
				// Signal server when first RTR sync completes
				go func() {
					<-client.Ready()
					select {
					case <-s.rtrReady:
						// already closed
					default:
						close(s.rtrReady)
					}
				}()
				s.rtrMu.Lock()
				s.rtrStates[addr] = 0
				s.rtrMu.Unlock()
				client.Start(ctx)
				// Mark disconnected when Start returns (session ended).
				s.rtrMu.Lock()
				s.rtrStates[addr] = 0
				s.rtrMu.Unlock()
			}()
		}
	}

	// ── Stale eviction — fires once after stale_eviction_timeout ───────────
	if s.cfg.Persistence.Enabled {
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case <-time.After(s.cfg.Persistence.StaleEvictionTimeout):
				evicted := s.table.EvictStale()
				s.log.Info("evicted unconfirmed stale routes", "count", evicted)
			case <-ctx.Done():
			}
		}()
	}

	// Prometheus metrics endpoint
	if s.cfg.Outputs.Prometheus != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.runPrometheus(ctx)
		}()
	}

	// OTel metrics exporter — non-fatal if collector is unreachable.
	if s.cfg.Outputs.OTel.Enabled {
		otelCfg := otelexporter.OTelConfig{
			Enabled:            true,
			Endpoint:           s.cfg.Outputs.OTel.Endpoint,
			Protocol:           s.cfg.Outputs.OTel.Protocol,
			Interval:           s.cfg.Outputs.OTel.Interval,
			Headers:            s.cfg.Outputs.OTel.Headers,
			Insecure:           s.cfg.Outputs.OTel.Insecure,
			ResourceAttributes: s.cfg.Outputs.OTel.ResourceAttributes,
		}
		otelExp, otelErr := otelexporter.NewExporter(ctx, otelCfg)
		if otelErr != nil {
			s.log.Error("failed to start OTel exporter", "err", otelErr)
		} else if otelExp != nil {
			otelExp.SetReader(s)
			defer otelExp.Shutdown(context.Background())
			s.log.Info("OTel exporter started",
				"endpoint", s.cfg.Outputs.OTel.Endpoint,
				"protocol", s.cfg.Outputs.OTel.Protocol,
				"interval", s.cfg.Outputs.OTel.Interval,
			)
		}
	}

	// Periodically update route table metrics
	wg.Add(1)
	go func() {
		defer wg.Done()
		t := time.NewTicker(15 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				s.updateRouteMetrics()
			case <-ctx.Done():
				return
			}
		}
	}()

	// Event engine (Phase 3 active response)
	if s.eventEngine != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.eventEngine.Run(ctx, nil)
		}()
	}

	// Flowspec manager reapers — one goroutine per flowspec action config block.
	for _, mgr := range s.fsManagers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			mgr.Run(ctx)
		}()
	}

	// API server for CLI queries and watch streaming
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := s.apiSrv.Start(ctx, DefaultAPIListen); err != nil {
			s.log.Error("API server failed", "error", err)
		}
	}()

	s.log.Info("RAVEN started",
		"bmp_listen", s.cfg.BMP.Listen,
		"rtr_caches", len(s.cfg.RTR.Caches),
		"rov_enabled", s.cfg.Validation.ROV,
	)

	<-ctx.Done()
	s.log.Info("shutting down...")
	wg.Wait()

	// ── Snapshot on shutdown (after all sessions drained) ──────────────────
	if s.cfg.Persistence.Enabled {
		writer, wErr := snapshot.NewWriter(s.cfg.Persistence.SnapshotDir, Version)
		if wErr != nil {
			s.log.Error("failed to create snapshot writer", "err", wErr)
		} else {
			routes := s.table.Snapshot()
			if err := writer.WriteRoutes(routes); err != nil {
				s.log.Error("failed to write route snapshot", "err", err)
			} else {
				s.log.Info("wrote route snapshot", "routes", len(routes))
			}

			vrps := s.vrpStore.Snapshot()
			aspas := s.aspaStore.Snapshot()
			serial := s.vrpStore.Serial()
			if err := writer.WriteRPKI(vrps, aspas, serial); err != nil {
				s.log.Error("failed to write RPKI snapshot", "err", err)
			} else {
				s.log.Info("wrote RPKI snapshot", "vrps", len(vrps), "aspas", len(aspas))
			}
		}
	}

	s.log.Info("RAVEN stopped")
	return nil
}

func (s *Server) withdrawIngestLoop(ctx context.Context) {
	for {
		select {
		case w := <-s.withdrawCh:
			if w.WithdrawAll {
				s.table.WithdrawAllFromPeer(w.PeerAddr)
			} else {
				// Capture route before removal so the event carries prefix/posture context.
				var withdrawn *types.Route
				if s.eventEngine != nil {
					key := types.RouteKey{PeerAddr: w.PeerAddr, Prefix: w.Prefix, RIBType: types.AdjRIBInPre}
					withdrawn = s.table.Get(key)
				}
				s.table.Withdraw(w.PeerAddr, w.Prefix)
				if s.eventEngine != nil && withdrawn != nil {
					s.eventEngine.Emit(events.Event{
						ID:         events.NewID(),
						Timestamp:  time.Now(),
						Type:       events.EventTypeRouteWithdraw,
						Route:      withdrawn,
						OldPosture: withdrawn.SecurityPosture,
						RouterID:   w.PeerAddr.String(),
					})
				}
			}
		case <-ctx.Done():
			return
		}
	}
}

// GetTable returns the route table.
func (s *Server) GetTable() *routetable.Table {
	return s.table
}

// FlowspecManagers returns the active flowspec lifecycle managers.
func (s *Server) FlowspecManagers() []*flowspec.Manager {
	return s.fsManagers
}

// GetBMPListener returns the BMP listener.
func (s *Server) GetBMPListener() *bmp.Listener {
	return s.bmpListen
}

// routeIngestLoop reads parsed routes from the BMP subsystem,
// runs validation, and inserts into the Route Table.
func (s *Server) routeIngestLoop(ctx context.Context) {
	s.log.Info("route ingest pipeline started")
	// Wait for first RTR sync before annotating routes.
	// This ensures VRP store is populated before any ROV happens.
	s.log.Info("waiting for RTR sync before annotating routes...")
	select {
	case <-s.rtrReady:
		s.log.Info("RTR ready — starting route annotation")
	case <-ctx.Done():
		return
	}

	var count uint64

	for {
		select {
		case route := <-s.routeCh:
			r := route

			// Capture old posture before overwriting so we can classify the event.
			// If the existing route is Stale (snapshot artefact), treat the
			// incoming live BMP message as a fresh insert → EventTypeNewRoute.
			var oldPosture types.SecurityPosture
			if s.eventEngine != nil {
				key := types.RouteKey{PeerAddr: r.PeerAddr, Prefix: r.Prefix, RIBType: r.RIBType}
				if old := s.table.Get(key); old != nil && !old.Stale {
					oldPosture = old.SecurityPosture
				}
			}

			// Run ROV validation before inserting
			if s.cfg.Validation.ROV {
				s.engine.ValidateRoute(&r)
			}

			s.table.Insert(&r)
			count++

			// Notify watch subscribers
			s.apiSrv.NotifyRoute(&r)

			// Emit to the event engine for active-response rule evaluation.
			if s.eventEngine != nil {
				eventType := events.EventTypeNewRoute
				if oldPosture != "" {
					eventType = events.EventTypePostureChange
				}
				s.eventEngine.Emit(events.Event{
					ID:         events.NewID(),
					Timestamp:  r.Timestamp,
					Type:       eventType,
					Route:      &r,
					OldPosture: oldPosture,
					NewPosture: r.SecurityPosture,
					RouterID:   r.RouterID.String(),
				})
			}

			// Log first few routes so the user sees it working
			if count <= 20 {
				s.log.Info("route received",
					"prefix", r.Prefix.String(),
					"peer", r.PeerAddr.String(),
					"origin_asn", r.OriginASN(),
					"rov", r.ROV.State.String(),
					"posture", r.SecurityPosture,
				)
			}
			if count%10000 == 0 {
				s.log.Info("routes ingested", "count", count, "table_size", s.table.Count())
			}
		case <-ctx.Done():
			s.log.Info("route ingest pipeline stopped", "total_ingested", count)
			return
		}
	}
}

// updateRouteMetrics refreshes Prometheus gauges for route counts.
func (s *Server) updateRouteMetrics() {
	routes := s.table.AllPrePolicy()
	metrics.RouteTableSize.Set(float64(len(routes)))

	// Explicitly zero all known posture/AFI combinations before repopulating.
	// Using Reset() removes the series entirely, which causes Grafana
	// lastNotNull panels to show stale values. Set(0) keeps the series at 0.
	for _, posture := range []string{
		"secured", "origin-only", "path-suspect", "path-only",
		"unverified", "origin-invalid",
	} {
		for _, afi := range []string{"ipv4", "ipv6"} {
			metrics.RoutesTotal.WithLabelValues(posture, afi).Set(0)
		}
	}

	// Count by posture and AFI
	counts := make(map[string]map[string]int)
	for _, r := range routes {
		posture := string(r.SecurityPosture)
		if posture == "" {
			posture = "unverified"
		}
		afi := "ipv4"
		if r.Prefix.Addr().Is6() {
			afi = "ipv6"
		}
		if counts[posture] == nil {
			counts[posture] = make(map[string]int)
		}
		counts[posture][afi]++
	}
	for posture, afis := range counts {
		for afi, n := range afis {
			metrics.RoutesTotal.WithLabelValues(posture, afi).Set(float64(n))
		}
	}
}

// runPrometheus starts the Prometheus metrics HTTP server.
func (s *Server) runPrometheus(ctx context.Context) {
	addr := s.cfg.Outputs.Prometheus.Listen
	path := s.cfg.Outputs.Prometheus.Path

	mux := http.NewServeMux()
	mux.Handle(path, promhttp.Handler())
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "ok")
	})

	srv := &http.Server{Addr: addr, Handler: mux}
	go func() {
		<-ctx.Done()
		srv.Close()
	}()

	s.log.Info("Prometheus metrics endpoint started", "addr", addr, "path", path)
	if err := srv.ListenAndServe(); err != http.ErrServerClosed {
		s.log.Error("Prometheus server error", "error", err)
	}
}
