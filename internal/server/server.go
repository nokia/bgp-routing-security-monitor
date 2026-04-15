package server

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/nokia/bgp-routing-security-monitor/internal/api"
	"github.com/nokia/bgp-routing-security-monitor/internal/aspa/recommender"
	"github.com/nokia/bgp-routing-security-monitor/internal/bmp"
	"github.com/nokia/bgp-routing-security-monitor/internal/config"
	"github.com/nokia/bgp-routing-security-monitor/internal/metrics"
	"github.com/nokia/bgp-routing-security-monitor/internal/routetable"
	"github.com/nokia/bgp-routing-security-monitor/internal/rtr"
	"github.com/nokia/bgp-routing-security-monitor/internal/rtr/store"
	"github.com/nokia/bgp-routing-security-monitor/internal/types"
	"github.com/nokia/bgp-routing-security-monitor/internal/validation"
	"github.com/nokia/bgp-routing-security-monitor/internal/whatif"
)

// Server is the top-level RAVEN daemon that owns all subsystems.
type Server struct {
	cfg        *config.Config
	log        *slog.Logger
	table      *routetable.Table
	bmpListen  *bmp.Listener
	vrpStore   *store.VRPStore
	aspaStore  *store.ASPAStore
	engine     *validation.Engine
	routeCh    chan types.Route
	demoMode   bool
	apiSrv     *api.Server
	rtrReady   chan struct{}
	withdrawCh chan types.Withdrawal
}

// New creates a new RAVEN server from the given config.
func New(cfg *config.Config, log *slog.Logger) *Server {
    routeCh    := make(chan types.Route, 100_000)
    vrpStore   := store.NewVRPStore()
    aspaStore  := store.NewASPAStore()          // ADD
    table      := routetable.New()
    engine     := validation.NewEngine(vrpStore, aspaStore, table, log)
    withdrawCh := make(chan types.Withdrawal, 10_000)

    srv := &Server{
        cfg:        cfg,
        log:        log,
        table:      table,
        bmpListen:  bmp.NewListener(cfg.BMP.Listen, routeCh, withdrawCh, log),
        vrpStore:   vrpStore,
        aspaStore:  aspaStore,              // ADD
        engine:     engine,
        routeCh:    routeCh,
        rtrReady:   make(chan struct{}),
        withdrawCh: withdrawCh,
    }

    // Existing API server
    srv.apiSrv = api.NewServer(table, srv.bmpListen, vrpStore, log, "dev")

    // Phase 2b: what-if + recommender
    sim := whatif.NewSimulator(table)
    rec := recommender.NewRecommender(table, aspaStore)
    whatifHandler := api.NewWhatIfHandler(sim, rec, aspaStore)
    whatifHandler.RegisterRoutes(srv.apiSrv.Mux())

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
			cache := cache
			wg.Add(1)
			go func() {
				defer wg.Done()
				client := rtr.NewClient(cache.Address, s.vrpStore, s.aspaStore, s.log)
				client.SetOnUpdate(func() {
					s.engine.RevalidateAll()
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
				client.Start(ctx)
			}()
		}
	}

	// Prometheus metrics endpoint
	if s.cfg.Outputs.Prometheus != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.runPrometheus(ctx)
		}()
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

	// API server for CLI queries and watch streaming
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := s.apiSrv.Start(ctx, ":11020"); err != nil {
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
				s.table.Withdraw(w.PeerAddr, w.Prefix)
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

			// Run ROV validation before inserting
			if s.cfg.Validation.ROV {
				s.engine.ValidateRoute(&r)
			}

			s.table.Insert(&r)
			count++

			// Notify watch subscribers
			s.apiSrv.NotifyRoute(&r)

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