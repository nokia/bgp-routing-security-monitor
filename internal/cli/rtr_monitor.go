package cli

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/cobra"

	"github.com/nokia/bgp-routing-security-monitor/internal/rtr"
	"github.com/nokia/bgp-routing-security-monitor/internal/rtr/store"
	"github.com/nokia/bgp-routing-security-monitor/internal/telemetry"
)

// rtrMonitorProtoVersion is the RTR protocol version the monitor starts with.
// v2 exercises ASPA PDUs (which telemetry records); the client automatically
// falls back to v1/v0 if the cache rejects it.
const rtrMonitorProtoVersion uint8 = 2

// rtrMonitorShutdownGrace bounds how long we wait for the RTR client goroutine
// to unwind after a signal before closing the recorder. It is deliberately
// longer than the client's rtrReadTimeout (65s): a parked read unblocks within
// that window and returns cleanly on a cancelled context, so the goroutine
// always exits before this grace fires. The bound only guards against an
// unforeseen hang. See the shutdown note in RunE.
const rtrMonitorShutdownGrace = 70 * time.Second

// newRTRMonitorCmd builds "raven rtr monitor": a standalone RTR session
// observer that streams telemetry events to an NDJSON file. It needs no
// config file — every setting comes from flags.
func newRTRMonitorCmd() *cobra.Command {
	var (
		cache      string
		logFile    string
		transport  string
		prometheus string
	)

	cmd := &cobra.Command{
		Use:   "monitor",
		Short: "Observe an RTR cache session and log telemetry to NDJSON",
		Long: `monitor connects to a single RPKI-to-Router (RTR) cache, records session
lifecycle and sync events as NDJSON, and (optionally) exposes Prometheus
metrics. It maintains in-memory VRP/ASPA stores solely to drive the RTR
client; no validation or BMP ingestion happens here.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			log := initLogger()

			if transport != "tcp" && transport != "tls" {
				return fmt.Errorf("invalid --transport %q: must be \"tcp\" or \"tls\"", transport)
			}

			// Open the NDJSON sink for append, creating it if absent.
			f, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
			if err != nil {
				return fmt.Errorf("open log file %q: %w", logFile, err)
			}

			rec := telemetry.NewRecorder(f, 64, log)

			// Minimal in-memory stores: NewClient requires them, but this
			// command performs no validation, so they are never queried.
			vrpStore := store.NewVRPStore()
			aspaStore := store.NewASPAStore()

			// tlsCfg is nil: NewClient only consults it when transport == "tls",
			// and a nil config falls back to the system root CA pool.
			client, err := rtr.NewClient(cache, transport, nil, vrpStore, aspaStore, rtrMonitorProtoVersion, log)
			if err != nil {
				f.Close()
				return fmt.Errorf("create RTR client: %w", err)
			}
			client.SetTelemetry(rec)

			ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()

			if prometheus != "" {
				startRTRMonitorMetrics(ctx, prometheus, log)
			}

			done := make(chan struct{})
			go func() {
				client.Start(ctx)
				close(done)
			}()

			log.Info("RTR monitor started", "cache", cache, "transport", transport, "log_file", logFile)

			<-ctx.Done()
			log.Info("shutting down RTR monitor")

			// Wait for the client goroutine to stop before closing the recorder:
			// Recorder.Record must not run after Close. The wait is bounded
			// because the client's read loop can park in a blocking socket read
			// (no read deadline) that ctx cancellation cannot interrupt until
			// the cache sends more bytes. On the rare timeout path the process
			// exits immediately anyway.
			select {
			case <-done:
			case <-time.After(rtrMonitorShutdownGrace):
				log.Warn("RTR client did not stop within grace period", "grace", rtrMonitorShutdownGrace)
			}

			rec.Close()
			if err := f.Close(); err != nil {
				return fmt.Errorf("close log file: %w", err)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&cache, "cache", "localhost:3323", "RTR cache address")
	cmd.Flags().StringVar(&logFile, "log-file", "rtr-telemetry.ndjson", "path to NDJSON telemetry output file")
	cmd.Flags().StringVar(&transport, "transport", "tcp", "RTR transport: tcp or tls")
	cmd.Flags().StringVar(&prometheus, "prometheus", "", "Prometheus listen address (e.g. :9595); empty disables metrics")

	return cmd
}

// startRTRMonitorMetrics serves Prometheus metrics on addr until ctx is
// cancelled. Mirrors the server package's runPrometheus handler wiring.
func startRTRMonitorMetrics(ctx context.Context, addr string, log *slog.Logger) {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "ok")
	})

	srv := &http.Server{Addr: addr, Handler: mux}
	go func() {
		<-ctx.Done()
		srv.Close()
	}()

	go func() {
		log.Info("Prometheus metrics endpoint started", "addr", addr, "path", "/metrics")
		if err := srv.ListenAndServe(); err != http.ErrServerClosed {
			log.Error("Prometheus server error", "error", err)
		}
	}()
}
