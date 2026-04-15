package whatif

import (
	"context"
	"fmt"
	"sort"

	"github.com/nokia/bgp-routing-security-monitor/internal/routetable"
	"github.com/nokia/bgp-routing-security-monitor/internal/types"
)

// Simulator runs what-if policy simulations against the live Route Table.
type Simulator struct {
	table *routetable.Table
}

func NewSimulator(table *routetable.Table) *Simulator {
	return &Simulator{table: table}
}

// ─── Result types ─────────────────────────────────────────────────────────────

type RejectInvalidResult struct {
	TotalRoutes       int            `json:"total_routes"`
	RejectedRoutes    int            `json:"rejected_routes"`
	AffectedPrefixes  int            `json:"affected_prefixes"`
	AffectedOrigins   int            `json:"affected_origins"`
	TopOrigins        []OriginImpact `json:"top_origins"`
	ByPeer            []PeerImpact   `json:"by_peer"`
	RejectedRouteList []types.Route  `json:"rejected_route_list,omitempty"`
}

type OriginImpact struct {
	OriginASN   uint32 `json:"origin_asn"`
	RouteCount  int    `json:"route_count"`
	PrefixCount int    `json:"prefix_count"`
	Reason      string `json:"reason"`
}

type PeerImpact struct {
	PeerAddr string `json:"peer_addr"`
	PeerASN  uint32 `json:"peer_asn"`
	Rejected int    `json:"rejected"`
	Total    int    `json:"total"`
}

type ASPAEnforceResult struct {
	TotalRoutes        int         `json:"total_routes"`
	RejectedRoutes     int         `json:"rejected_routes"`
	UnverifiableRoutes int         `json:"unverifiable_routes"`
	AffectedPrefixes   int         `json:"affected_prefixes"`
	AffectedOrigins    int         `json:"affected_origins"`
	TopFailingHops     []HopImpact `json:"top_failing_hops"`
	RejectedRouteList  []types.Route `json:"rejected_route_list,omitempty"`
}

type HopImpact struct {
	CustomerASN uint32 `json:"customer_asn"`
	ProviderASN uint32 `json:"provider_asn"`
	RouteCount  int    `json:"route_count"`
}

type Options struct {
	MaxRouteList int
	TopN         int
	FilterPeer   string
	FilterAFI    string
}

func defaultOptions(o *Options) *Options {
	if o == nil {
		o = &Options{}
	}
	if o.MaxRouteList == 0 {
		o.MaxRouteList = 500
	}
	if o.TopN == 0 {
		o.TopN = 10
	}
	return o
}

// SimulateRejectInvalid computes what would be rejected under reject-invalid policy.
func (s *Simulator) SimulateRejectInvalid(ctx context.Context, opts *Options) (*RejectInvalidResult, error) {
	opts = defaultOptions(opts)

	routes, err := s.fetchRoutes(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("whatif: fetch routes: %w", err)
	}

	res := &RejectInvalidResult{TotalRoutes: len(routes)}

	prefixSet := make(map[string]struct{})
	originSet := make(map[uint32]struct{})
	originCount := make(map[uint32]*OriginImpact)
	peerCount := make(map[string]*PeerImpact)

	for i := range routes {
		r := &routes[i]
		peerKey := r.PeerAddr.String()

		if _, ok := peerCount[peerKey]; !ok {
			peerCount[peerKey] = &PeerImpact{PeerAddr: peerKey, PeerASN: r.PeerASN}
		}
		peerCount[peerKey].Total++

		if r.ROV.State != types.ROVInvalid {
			continue
		}

		res.RejectedRoutes++
		peerCount[peerKey].Rejected++
		prefixSet[r.Prefix.String()] = struct{}{}

		originASN := r.OriginASN()
		originSet[originASN] = struct{}{}

		if _, ok := originCount[originASN]; !ok {
			originCount[originASN] = &OriginImpact{OriginASN: originASN, Reason: r.ROV.Reason}
		}
		originCount[originASN].RouteCount++
		originCount[originASN].PrefixCount++

		if len(res.RejectedRouteList) < opts.MaxRouteList {
			res.RejectedRouteList = append(res.RejectedRouteList, *r)
		}
	}

	res.AffectedPrefixes = len(prefixSet)
	res.AffectedOrigins = len(originSet)

	origins := make([]OriginImpact, 0, len(originCount))
	for _, o := range originCount {
		origins = append(origins, *o)
	}
	sort.Slice(origins, func(i, j int) bool { return origins[i].RouteCount > origins[j].RouteCount })
	if len(origins) > opts.TopN {
		origins = origins[:opts.TopN]
	}
	res.TopOrigins = origins

	peers := make([]PeerImpact, 0, len(peerCount))
	for _, p := range peerCount {
		peers = append(peers, *p)
	}
	sort.Slice(peers, func(i, j int) bool { return peers[i].Rejected > peers[j].Rejected })
	res.ByPeer = peers

	return res, nil
}

// SimulateASPAEnforce computes impact of dropping path-suspect routes.
func (s *Simulator) SimulateASPAEnforce(ctx context.Context, opts *Options) (*ASPAEnforceResult, error) {
	opts = defaultOptions(opts)

	routes, err := s.fetchRoutes(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("whatif: fetch routes: %w", err)
	}

	res := &ASPAEnforceResult{TotalRoutes: len(routes)}

	prefixSet := make(map[string]struct{})
	originSet := make(map[uint32]struct{})
	hopCount := make(map[[2]uint32]*HopImpact)

	for i := range routes {
		r := &routes[i]

		switch r.SecurityPosture {
		case types.PostureOriginOnly, types.PostureUnverified, types.PosturePathOnly:
			res.UnverifiableRoutes++
		}

		if r.SecurityPosture != types.PosturePathSuspect {
			continue
		}

		res.RejectedRoutes++
		prefixSet[r.Prefix.String()] = struct{}{}
		originSet[r.OriginASN()] = struct{}{}

		if r.ASPA.FailingHop != nil {
			key := [2]uint32{r.ASPA.FailingHop.CustomerASN, r.ASPA.FailingHop.ProviderASN}
			if _, ok := hopCount[key]; !ok {
				hopCount[key] = &HopImpact{
					CustomerASN: r.ASPA.FailingHop.CustomerASN,
					ProviderASN: r.ASPA.FailingHop.ProviderASN,
				}
			}
			hopCount[key].RouteCount++
		}

		if len(res.RejectedRouteList) < opts.MaxRouteList {
			res.RejectedRouteList = append(res.RejectedRouteList, *r)
		}
	}

	res.AffectedPrefixes = len(prefixSet)
	res.AffectedOrigins = len(originSet)

	hops := make([]HopImpact, 0, len(hopCount))
	for _, h := range hopCount {
		hops = append(hops, *h)
	}
	sort.Slice(hops, func(i, j int) bool { return hops[i].RouteCount > hops[j].RouteCount })
	if len(hops) > opts.TopN {
		hops = hops[:opts.TopN]
	}
	res.TopFailingHops = hops

	return res, nil
}

func (s *Simulator) fetchRoutes(ctx context.Context, opts *Options) ([]types.Route, error) {
	filter := routetable.Filter{}
	if opts.FilterPeer != "" {
		filter.PeerAddr = opts.FilterPeer
	}
	if opts.FilterAFI != "" {
		filter.AFI = opts.FilterAFI
	}
	return s.table.ListRoutes(ctx, filter)
}
