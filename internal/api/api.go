package api

import (
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/nokia/bgp-routing-security-monitor/internal/bmp"
	"github.com/nokia/bgp-routing-security-monitor/internal/routetable"
	"github.com/nokia/bgp-routing-security-monitor/internal/rtr/store"
	"github.com/nokia/bgp-routing-security-monitor/internal/types"
)

// RouteResponse is a single route in API output.
type RouteResponse struct {
	Prefix    string   `json:"prefix"`
	PeerAddr  string   `json:"peer"`
	PeerASN   uint32   `json:"peer_asn"`
	OriginASN uint32   `json:"origin_asn"`
	ASPath    []uint32 `json:"as_path"`
	NextHop   string   `json:"next_hop"`
	ROV       string   `json:"rov"`
	ROVReason string   `json:"rov_reason,omitempty"`
	ASPA      string   `json:"aspa"`
	Posture   string   `json:"posture"`
	Timestamp string   `json:"timestamp"`
}

// PeerResponse is a BMP peer in API output.
type PeerResponse struct {
	Addr       string `json:"addr"`
	ASN        uint32 `json:"asn"`
	RouterID   string `json:"router_id"`
	State      string `json:"state"`
	RouteCount uint64 `json:"route_count"`
	UpSince    string `json:"up_since"`
	LastMsg    string `json:"last_msg"`
}

// StatusResponse is the system health API output.
type StatusResponse struct {
	Version    string                    `json:"version"`
	Uptime     string                    `json:"uptime"`
	BMP        []PeerResponse            `json:"bmp_peers"`
	RTR        RTRStatusResponse         `json:"rtr"`
	RouteTable RouteTableStatusResponse  `json:"route_table"`
}

// RTRStatusResponse is RTR cache health.
type RTRStatusResponse struct {
	VRPCount  uint64 `json:"vrp_count"`
	Serial    uint32 `json:"serial"`
	SessionID uint16 `json:"session_id"`
}

// RouteTableStatusResponse is route table summary.
type RouteTableStatusResponse struct {
	TotalRoutes    uint64            `json:"total_routes"`
	ByPosture      map[string]uint64 `json:"by_posture"`
}

// WatchEvent is a streaming event for raven watch.
type WatchEvent struct {
	Type  string        `json:"type"` // "route"
	Route RouteResponse `json:"route"`
}

// Server is the HTTP/JSON API server.
type Server struct {
	table     *routetable.Table
	bmpListen *bmp.Listener
	vrpStore  *store.VRPStore
	log       *slog.Logger
	version   string
	startTime time.Time
	mux       *http.ServeMux

	// Watch subscribers
	watchMu   sync.RWMutex
	watchSubs map[chan RouteResponse]struct{}
}

// NewServer creates an API server.
func NewServer(table *routetable.Table, bmpListen *bmp.Listener, vrpStore *store.VRPStore, log *slog.Logger, version string) *Server {
	s := &Server{
		table:     table,
		bmpListen: bmpListen,
		vrpStore:  vrpStore,
		log:       log.With("subsystem", "api"),
		version:   version,
		startTime: time.Now(),
		watchSubs: make(map[chan RouteResponse]struct{}),
		mux:       http.NewServeMux(),
	}
	s.mux.HandleFunc("/api/v1/routes", s.handleRoutes)
	s.mux.HandleFunc("/api/v1/peers", s.handlePeers)
	s.mux.HandleFunc("/api/v1/status", s.handleStatus)
	s.mux.HandleFunc("/api/v1/watch", s.handleWatch)
	return s
}

// NotifyRoute sends a route to all watch subscribers.
func (s *Server) NotifyRoute(route *types.Route) {
	rr := routeToResponse(route)
	s.watchMu.RLock()
	defer s.watchMu.RUnlock()
	for ch := range s.watchSubs {
		select {
		case ch <- rr:
		default:
			// subscriber too slow, skip
		}
	}
}

func (s *Server) Mux() *http.ServeMux { return s.mux }

// Start runs the API server. Blocks until ctx is cancelled.
func (s *Server) Start(ctx context.Context, addr string) error {
	srv := &http.Server{
		Addr:    addr,
		Handler: s.mux,
		BaseContext: func(l net.Listener) context.Context {
			return ctx
		},
	}

	go func() {
		<-ctx.Done()
		srv.Close()
	}()

	s.log.Info("API server started", "addr", addr)
	if err := srv.ListenAndServe(); err != http.ErrServerClosed {
		return err
	}
	return nil
}

func (s *Server) handleRoutes(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	var routes []*types.Route

	if prefix := q.Get("prefix"); prefix != "" {
		p, err := netip.ParsePrefix(prefix)
		if err != nil {
			http.Error(w, "invalid prefix: "+err.Error(), http.StatusBadRequest)
			return
		}
		routes = s.table.GetByPrefix(p)
	} else if asnStr := q.Get("origin-asn"); asnStr != "" {
		asn, err := strconv.ParseUint(asnStr, 10, 32)
		if err != nil {
			http.Error(w, "invalid ASN: "+err.Error(), http.StatusBadRequest)
			return
		}
		routes = s.table.GetByOriginASN(uint32(asn))
	} else if peer := q.Get("peer"); peer != "" {
		addr, err := netip.ParseAddr(peer)
		if err != nil {
			http.Error(w, "invalid peer address: "+err.Error(), http.StatusBadRequest)
			return
		}
		routes = s.table.GetByPeer(addr)
	} else if posture := q.Get("posture"); posture != "" {
		routes = s.table.GetByPosture(types.SecurityPosture(posture))
	} else {
		routes = s.table.AllPrePolicy()
	}

	resp := make([]RouteResponse, 0, len(routes))
	for _, route := range routes {
		resp = append(resp, routeToResponse(route))
	}

	writeJSON(w, resp)
}

func (s *Server) handlePeers(w http.ResponseWriter, r *http.Request) {
	peers := s.bmpListen.GetPeers()
	resp := make([]PeerResponse, 0, len(peers))
	for _, p := range peers {
		resp = append(resp, PeerResponse{
			Addr:       p.Addr.String(),
			ASN:        p.ASN,
			RouterID:   p.RouterID.String(),
			State:      p.State,
			RouteCount: p.RouteCount,
			UpSince:    p.UpSince.Format(time.RFC3339),
			LastMsg:    p.LastMsg.Format(time.RFC3339),
		})
	}
	writeJSON(w, resp)
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	postureCounts := s.table.CountByPosture()
	byPosture := make(map[string]uint64)
	for k, v := range postureCounts {
		byPosture[string(k)] = v
	}

	resp := StatusResponse{
		Version: s.version,
		Uptime:  time.Since(s.startTime).Round(time.Second).String(),
		RTR: RTRStatusResponse{
			VRPCount:  s.vrpStore.Count(),
			Serial:    s.vrpStore.Serial(),
			SessionID: s.vrpStore.SessionID(),
		},
		RouteTable: RouteTableStatusResponse{
			TotalRoutes: s.table.Count(),
			ByPosture:   byPosture,
		},
	}

	peers := s.bmpListen.GetPeers()
	for _, p := range peers {
		resp.BMP = append(resp.BMP, PeerResponse{
			Addr:       p.Addr.String(),
			ASN:        p.ASN,
			RouterID:   p.RouterID.String(),
			State:      p.State,
			RouteCount: p.RouteCount,
			UpSince:    p.UpSince.Format(time.RFC3339),
			LastMsg:    p.LastMsg.Format(time.RFC3339),
		})
	}

	writeJSON(w, resp)
}

// handleWatch streams route events via Server-Sent Events (SSE).
func (s *Server) handleWatch(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	postureFilter := r.URL.Query().Get("posture")

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	ch := make(chan RouteResponse, 100)
	s.watchMu.Lock()
	s.watchSubs[ch] = struct{}{}
	s.watchMu.Unlock()

	defer func() {
		s.watchMu.Lock()
		delete(s.watchSubs, ch)
		s.watchMu.Unlock()
	}()

	ctx := r.Context()
	for {
		select {
		case rr := <-ch:
			if postureFilter != "" && rr.Posture != postureFilter {
				continue
			}
			data, _ := json.Marshal(rr)
			w.Write([]byte("data: "))
			w.Write(data)
			w.Write([]byte("\n\n"))
			flusher.Flush()
		case <-ctx.Done():
			return
		}
	}
}

func routeToResponse(r *types.Route) RouteResponse {
	return RouteResponse{
		Prefix:    r.Prefix.String(),
		PeerAddr:  r.PeerAddr.String(),
		PeerASN:   r.PeerASN,
		OriginASN: r.OriginASN(),
		ASPath:    r.ASPath,
		NextHop:   r.NextHop.String(),
		ROV:       r.ROV.State.String(),
		ROVReason: r.ROV.Reason,
		ASPA:      r.ASPA.State.String(),
		Posture:   string(r.SecurityPosture),
	}
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(v) //nolint:errcheck
}

func httpError(w http.ResponseWriter, err error, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": err.Error()}) //nolint:errcheck
}
