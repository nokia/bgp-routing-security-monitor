package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/nokia/bgp-routing-security-monitor/internal/routetable"
)

func TestAuditRejectsUnknownRIB(t *testing.T) {
	mux := http.NewServeMux()
	NewAuditHandler(routetable.New()).RegisterRoutes(mux)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/audit?router=192.0.2.1&rib=adj-rib-out", nil))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}
