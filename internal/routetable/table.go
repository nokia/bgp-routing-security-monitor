package routetable

import (
	"context"
	"fmt"
	"hash/fnv"
	"net/netip"
	"slices"
	"sync"

	"github.com/gaissmai/bart"
	"github.com/nokia/bgp-routing-security-monitor/internal/types"
)

const defaultShards = 256

// Table is RAVEN's internal route table: the Adj-RIB-In and Loc-RIB routes of
// every monitored router, with validation annotations.
//
// Architecture: hybrid BART prefix index + sharded flat map (see ARCHITECTURE.md §2.3).
type Table struct {
	// Primary store: sharded flat map keyed by types.RouteKey
	shards []shard

	// Prefix index: BART trie mapping prefix -> set of route keys
	prefixMu  sync.RWMutex
	prefixIdx bart.Table[[]types.RouteKey]

	// Secondary index: origin ASN -> route keys
	asnMu  sync.RWMutex
	asnIdx map[uint32][]types.RouteKey

	// Secondary index: security posture -> route keys
	postureMu  sync.RWMutex
	postureIdx map[types.SecurityPosture][]types.RouteKey
}

type shard struct {
	mu     sync.RWMutex
	routes map[types.RouteKey]*types.Route
}

// Filter holds query parameters for ListRoutes.
type Filter struct {
	PeerAddr  string
	Prefix    string
	OriginASN uint32
	Posture   string
	AFI       string // "ipv4" | "ipv6" | ""
	// RIB keeps each route once when routers send several RIBs; the zero value is pre-policy.
	RIB types.RIBType
}

// ListRoutes returns routes matching the given filter.
// Used by the what-if simulator and ASPA recommender.
func (t *Table) ListRoutes(ctx context.Context, f Filter) ([]types.Route, error) {
	var ptrs []*types.Route
	inRIB := func(rib types.RIBType) bool { return rib == f.RIB }

	switch {
	case f.PeerAddr != "":
		addr, err := netip.ParseAddr(f.PeerAddr)
		if err != nil {
			return nil, fmt.Errorf("invalid peer addr: %w", err)
		}
		ptrs = t.byPeer(addr, inRIB)
	case f.Prefix != "":
		p, err := netip.ParsePrefix(f.Prefix)
		if err != nil {
			return nil, fmt.Errorf("invalid prefix: %w", err)
		}
		ptrs = t.resolveKeys(t.prefixKeys(p), inRIB)
	case f.OriginASN != 0:
		ptrs = t.resolveKeys(t.originASNKeys(f.OriginASN), inRIB)
	case f.Posture != "":
		ptrs = t.resolveKeys(t.postureKeys(types.SecurityPosture(f.Posture)), inRIB)
	default:
		ptrs = t.all(inRIB)
	}

	// Apply AFI filter
	routes := make([]types.Route, 0, len(ptrs))
	for _, r := range ptrs {
		if f.AFI == "ipv4" && !r.Prefix.Addr().Is4() {
			continue
		}
		if f.AFI == "ipv6" && !r.Prefix.Addr().Is6() {
			continue
		}
		routes = append(routes, *r)
	}
	return routes, nil
}

// New creates a new Route Table.
func New() *Table {
	t := &Table{
		shards:     make([]shard, defaultShards),
		asnIdx:     make(map[uint32][]types.RouteKey),
		postureIdx: make(map[types.SecurityPosture][]types.RouteKey),
	}
	for i := range t.shards {
		t.shards[i].routes = make(map[types.RouteKey]*types.Route)
	}
	return t
}

// Insert adds or updates a route in the table.
func (t *Table) Insert(route *types.Route) {
	key := route.Key()

	// Write to primary store
	s := t.getShard(key)
	s.mu.Lock()
	old := s.routes[key]
	s.routes[key] = route
	s.mu.Unlock()

	// Update prefix index
	t.prefixMu.Lock()
	existing, _ := t.prefixIdx.Get(route.Prefix)
	if !containsKey(existing, key) {
		t.prefixIdx.Insert(route.Prefix, append(existing, key))
	}
	t.prefixMu.Unlock()

	// Update ASN index
	originASN := route.OriginASN()
	if originASN != 0 {
		t.asnMu.Lock()
		if !containsKey(t.asnIdx[originASN], key) {
			t.asnIdx[originASN] = append(t.asnIdx[originASN], key)
		}
		t.asnMu.Unlock()
	}

	// Update posture index
	if route.SecurityPosture != "" {
		t.postureMu.Lock()
		// Remove from old posture if changed
		if old != nil && old.SecurityPosture != route.SecurityPosture {
			t.postureIdx[old.SecurityPosture] = removeKey(t.postureIdx[old.SecurityPosture], key)
		}
		if !containsKey(t.postureIdx[route.SecurityPosture], key) {
			t.postureIdx[route.SecurityPosture] = append(t.postureIdx[route.SecurityPosture], key)
		}
		t.postureMu.Unlock()
	}
}

// Withdraw removes the route stored under the given key.
func (t *Table) Withdraw(key types.RouteKey) {
	s := t.getShard(key)
	s.mu.Lock()
	route, exists := s.routes[key]
	delete(s.routes, key)
	s.mu.Unlock()

	if !exists {
		return
	}

	// Clean up prefix index
	t.prefixMu.Lock()
	existing, _ := t.prefixIdx.Get(key.Prefix)
	updated := removeKey(existing, key)
	if len(updated) == 0 {
		t.prefixIdx.Delete(key.Prefix)
	} else {
		t.prefixIdx.Insert(key.Prefix, updated)
	}
	t.prefixMu.Unlock()

	// Clean up ASN index
	originASN := route.OriginASN()
	if originASN != 0 {
		t.asnMu.Lock()
		t.asnIdx[originASN] = removeKey(t.asnIdx[originASN], key)
		t.asnMu.Unlock()
	}

	// Clean up posture index
	if route.SecurityPosture != "" {
		t.postureMu.Lock()
		t.postureIdx[route.SecurityPosture] = removeKey(t.postureIdx[route.SecurityPosture], key)
		t.postureMu.Unlock()
	}
}

// WithdrawAllFromPeer removes every route a peer holds in the given RIBs, or
// in every RIB when none is given.
func (t *Table) WithdrawAllFromPeer(peerAddr netip.Addr, distinguisher types.PeerDistinguisher, ribs ...types.RIBType) int {
	if len(ribs) == 0 {
		ribs = types.RIBTypes
	}
	count := 0
	for i := range t.shards {
		s := &t.shards[i]
		s.mu.RLock()
		var toRemove []types.RouteKey
		for key := range s.routes {
			if key.PeerAddr == peerAddr && key.PeerDistinguisher == distinguisher && slices.Contains(ribs, key.RIBType) {
				toRemove = append(toRemove, key)
			}
		}
		s.mu.RUnlock()

		for _, key := range toRemove {
			t.Withdraw(key)
			count++
		}
	}
	return count
}

// ─── Query Methods ───

// Get returns the route stored under the given key, or nil if not found.
func (t *Table) Get(key types.RouteKey) *types.Route {
	s := t.getShard(key)
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.routes[key]
}

func (t *Table) GetByPrefix(prefix netip.Prefix) []*types.Route {
	return t.resolveKeys(t.prefixKeys(prefix), inDefaultView)
}

func (t *Table) GetByOriginASN(asn uint32) []*types.Route {
	return t.resolveKeys(t.originASNKeys(asn), inDefaultView)
}

func (t *Table) GetByPosture(posture types.SecurityPosture) []*types.Route {
	return t.resolveKeys(t.postureKeys(posture), inDefaultView)
}

func (t *Table) GetByPeer(peerAddr netip.Addr) []*types.Route {
	return t.byPeer(peerAddr, inDefaultView)
}

// All returns every route in the table regardless of RIB type.
func (t *Table) All() []*types.Route {
	return t.all(func(types.RIBType) bool { return true })
}

// AllDefaultView returns the routes of the default operator view: what the
// routers received before import filtering (Adj-RIB-In Pre-Policy) and what
// they selected (Loc-RIB).
func (t *Table) AllDefaultView() []*types.Route {
	return t.all(inDefaultView)
}

// Count returns the total number of routes.
func (t *Table) Count() uint64 {
	var total uint64
	for i := range t.shards {
		s := &t.shards[i]
		s.mu.RLock()
		total += uint64(len(s.routes))
		s.mu.RUnlock()
	}
	return total
}

// Snapshot returns all routes currently in the table.
// Called by the serve shutdown sequence to persist state.
func (t *Table) Snapshot() []*types.Route {
	return t.All()
}

// Restore populates the table from a snapshot.
// All restored routes have Stale=true so that the Event Engine
// ignores them until a live BMP message confirms each one.
func (t *Table) Restore(routes []*types.Route) {
	for _, r := range routes {
		cp := *r
		cp.Stale = true
		t.Insert(&cp)
	}
}

// EvictStale removes all routes still marked Stale from the table.
// Returns the number of routes evicted. Called once after
// stale_eviction_timeout to purge unconfirmed snapshot entries.
func (t *Table) EvictStale() int {
	var toEvict []types.RouteKey
	for i := range t.shards {
		s := &t.shards[i]
		s.mu.RLock()
		for key, route := range s.routes {
			if route.Stale {
				toEvict = append(toEvict, key)
			}
		}
		s.mu.RUnlock()
	}
	for _, key := range toEvict {
		t.Withdraw(key)
	}
	return len(toEvict)
}

// CountByPosture returns route counts grouped by security posture.
func (t *Table) CountByPosture() map[types.SecurityPosture]uint64 {
	t.postureMu.RLock()
	defer t.postureMu.RUnlock()

	result := make(map[types.SecurityPosture]uint64)
	for posture, keys := range t.postureIdx {
		result[posture] = uint64(len(keys))
	}
	return result
}

// ─── Internal helpers ───

// inDefaultView leaves Post-Policy out because a router that sends it also sends the same routes Pre-Policy.
func inDefaultView(rib types.RIBType) bool {
	return rib == types.AdjRIBInPre || rib == types.LocRIB
}

func (t *Table) getShard(key types.RouteKey) *shard {
	h := fnv.New32a()
	b := key.PeerAddr.As16()
	h.Write(b[:])
	pb, _ := key.Prefix.MarshalBinary()
	h.Write(pb)
	return &t.shards[h.Sum32()%uint32(len(t.shards))]
}

func (t *Table) prefixKeys(prefix netip.Prefix) []types.RouteKey {
	t.prefixMu.RLock()
	defer t.prefixMu.RUnlock()
	keys, _ := t.prefixIdx.Get(prefix)
	return keys
}

func (t *Table) originASNKeys(asn uint32) []types.RouteKey {
	t.asnMu.RLock()
	defer t.asnMu.RUnlock()
	return t.asnIdx[asn]
}

func (t *Table) postureKeys(posture types.SecurityPosture) []types.RouteKey {
	t.postureMu.RLock()
	defer t.postureMu.RUnlock()
	return t.postureIdx[posture]
}

func (t *Table) byPeer(peerAddr netip.Addr, keep func(types.RIBType) bool) []*types.Route {
	var routes []*types.Route
	for i := range t.shards {
		s := &t.shards[i]
		s.mu.RLock()
		for key, route := range s.routes {
			if key.PeerAddr == peerAddr && keep(key.RIBType) {
				routes = append(routes, route)
			}
		}
		s.mu.RUnlock()
	}
	return routes
}

func (t *Table) all(keep func(types.RIBType) bool) []*types.Route {
	var routes []*types.Route
	for i := range t.shards {
		s := &t.shards[i]
		s.mu.RLock()
		for key, route := range s.routes {
			if keep(key.RIBType) {
				routes = append(routes, route)
			}
		}
		s.mu.RUnlock()
	}
	return routes
}

func (t *Table) resolveKeys(keys []types.RouteKey, keep func(types.RIBType) bool) []*types.Route {
	routes := make([]*types.Route, 0, len(keys))
	for _, key := range keys {
		if !keep(key.RIBType) {
			continue
		}
		s := t.getShard(key)
		s.mu.RLock()
		if r, ok := s.routes[key]; ok {
			routes = append(routes, r)
		}
		s.mu.RUnlock()
	}
	return routes
}

func containsKey(keys []types.RouteKey, key types.RouteKey) bool {
	for _, k := range keys {
		if k == key {
			return true
		}
	}
	return false
}

func removeKey(keys []types.RouteKey, key types.RouteKey) []types.RouteKey {
	for i, k := range keys {
		if k == key {
			return append(keys[:i], keys[i+1:]...)
		}
	}
	return keys
}
