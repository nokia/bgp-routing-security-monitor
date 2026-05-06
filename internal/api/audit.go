package api

import (
	"fmt"
	"net/http"

	"github.com/nokia/bgp-routing-security-monitor/internal/audit"
	"github.com/nokia/bgp-routing-security-monitor/internal/routetable"
)

// AuditHandler serves the router security posture audit endpoint.
type AuditHandler struct {
	table *routetable.Table
}

// NewAuditHandler creates a new AuditHandler backed by the given route table.
func NewAuditHandler(table *routetable.Table) *AuditHandler {
	return &AuditHandler{table: table}
}

// RegisterRoutes registers the audit endpoint on the given mux.
func (h *AuditHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/v1/audit", h.handleAudit)
}

func (h *AuditHandler) handleAudit(w http.ResponseWriter, r *http.Request) {
	routerID := r.URL.Query().Get("router")
	if routerID == "" {
		httpError(w, fmt.Errorf("router query parameter required"), http.StatusBadRequest)
		return
	}
	routes := h.table.AllPrePolicy()
	report := audit.Analyze(routerID, routes)
	writeJSON(w, report)
}
