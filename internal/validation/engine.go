package validation

import (
	"github.com/nokia/bgp-routing-security-monitor/internal/routetable"
	"github.com/nokia/bgp-routing-security-monitor/internal/rtr/store"
	"github.com/nokia/bgp-routing-security-monitor/internal/types"
	"github.com/nokia/bgp-routing-security-monitor/internal/validation/aspa"
	"github.com/nokia/bgp-routing-security-monitor/internal/validation/rov"
	"log/slog"
)

// Engine annotates routes with ROV (and later ASPA) validation results.
type Engine struct {
	rovAnnotator  *rov.Annotator
	aspaAnnotator *aspa.Annotator
	vrpStore      *store.VRPStore
	table         *routetable.Table
	log           *slog.Logger
}

// NewEngine creates a validation engine.
func NewEngine(vrpStore *store.VRPStore, aspaStore *store.ASPAStore, table *routetable.Table, log *slog.Logger) *Engine {
	return &Engine{
		rovAnnotator:  rov.NewAnnotator(vrpStore),
		aspaAnnotator: aspa.NewAnnotator(aspaStore),
		vrpStore:      vrpStore,
		table:         table,
		log:           log.With("subsystem", "validation"),
	}
}

// ValidateRoute performs ROV on a single route and updates its annotations.
// Called by the ingest pipeline for each new route.
func (e *Engine) ValidateRoute(route *types.Route) {
	// ROV
	route.ROV = e.rovAnnotator.Validate(route)
	// ASPA
	route.ASPA = e.aspaAnnotator.Validate(route)
	// Combined posture
	route.SecurityPosture = types.ComputePosture(route.ROV.State, route.ASPA.State)
}

// RevalidateAll re-runs validation on every route in the table.
// Called when the VRP store is updated (RTR cache sync).
func (e *Engine) RevalidateAll() {
	routes := e.table.All()
	e.log.Info("re-validating all routes", "count", len(routes))

	var changed int
	for _, route := range routes {
		oldPosture := route.SecurityPosture
		e.ValidateRoute(route)

		if route.SecurityPosture != oldPosture {
			changed++
			// Update posture index in the route table
			e.table.Insert(route)
		}
	}

	e.log.Info("re-validation complete", "total", len(routes), "posture_changes", changed)
}
