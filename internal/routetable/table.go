package routetable

import (
	"context"
	"fmt"
	"hash/fnv"
	"net/netip"
	"sync"

	"github.com/gaissmai/bart"
	"github.com/nokia/bgp-routing-security-monitor/internal/types"
)

const defaultShards = 256

// Table is RAVEN's internal route table — an annotated Adj-RIB-In.
// It stores every route from every peer with validation annotations.
//
// Architecture: hybrid BART prefix index + sharded flat map (see ARCHITECTURE.md §2.3).
type Table struct {
	// Primary store: sharded flat map keyed by (PeerAddr, Prefix)
	shards []shard

	// Prefix index: BART trie mapping prefix -> route keys. A prefix's list
	// holds at most one key per peer carrying it, so it stays short and a
	// linear scan is cheap; a map per prefix would roughly triple the index's
	// memory when most prefixes have a single route.
	prefixMu  sync.RWMutex
	prefixIdx bart.Table[[]types.RouteKey]

	// Secondary index: origin ASN -> route keys
	asnMu  sync.RWMutex
	asnIdx map[uint32]keySet

	// Secondary index: security posture -> route keys
	postureMu  sync.RWMutex
	postureIdx map[types.SecurityPosture]keySet
}

// keySet is the set of route keys under one ASN or posture index entry.
// These entries used to be slices, scanned linearly on every insert and
// removal; with about a million keys under a single posture that made index
// maintenance quadratic.
type keySet map[types.RouteKey]struct{}

// keys copies the set's members. Callers hold the index's lock: a map must
// not be read while another goroutine writes it.
func (s keySet) keys() []types.RouteKey {
	out := make([]types.RouteKey, 0, len(s))
	for k := range s {
		out = append(out, k)
	}
	return out
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
}

// ListRoutes returns routes matching the given filter.
// Used by the what-if simulator and ASPA recommender.
func (t *Table) ListRoutes(ctx context.Context, f Filter) ([]types.Route, error) {
	var ptrs []*types.Route

	switch {
	case f.PeerAddr != "":
		addr, err := netip.ParseAddr(f.PeerAddr)
		if err != nil {
			return nil, fmt.Errorf("invalid peer addr: %w", err)
		}
		ptrs = t.GetByPeer(addr)
	case f.Prefix != "":
		p, err := netip.ParsePrefix(f.Prefix)
		if err != nil {
			return nil, fmt.Errorf("invalid prefix: %w", err)
		}
		ptrs = t.GetByPrefix(p)
	case f.OriginASN != 0:
		ptrs = t.GetByOriginASN(f.OriginASN)
	case f.Posture != "":
		ptrs = t.GetByPosture(types.SecurityPosture(f.Posture))
	default:
		ptrs = t.All()
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
		asnIdx:     make(map[uint32]keySet),
		postureIdx: make(map[types.SecurityPosture]keySet),
	}
	for i := range t.shards {
		t.shards[i].routes = make(map[types.RouteKey]*types.Route)
	}
	return t
}

// Insert adds or updates a route in the table.
func (t *Table) Insert(route *types.Route) {
	key := types.RouteKey{
		PeerAddr: route.PeerAddr,
		Prefix:   route.Prefix,
		RIBType:  route.RIBType,
	}

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

	// Update ASN index. A re-announcement with a new origin arrives as a new
	// route for the same key, so the old origin's entry must be dropped.
	originASN := route.OriginASN()
	t.asnMu.Lock()
	if old != nil {
		if oldASN := old.OriginASN(); oldASN != 0 && oldASN != originASN {
			t.unindexASN(oldASN, key)
		}
	}
	if originASN != 0 {
		addKey(t.asnIdx, originASN, key)
	}
	t.asnMu.Unlock()

	// Update posture index
	t.postureMu.Lock()
	t.unindexPostureExcept(key, route.SecurityPosture)
	if route.SecurityPosture != "" {
		addKey(t.postureIdx, route.SecurityPosture, key)
	}
	t.postureMu.Unlock()
}

// unindexPostureExcept removes key from every posture index entry other than
// keep. The caller holds postureMu.
//
// The old posture cannot be read off the stored route: RevalidateAll changes
// a route's posture in place and re-inserts the same pointer, so by the time
// Insert runs the stored route already carries the new posture. Checking the
// old route's posture left the key listed under every posture it had ever
// had. There are only a handful of postures, so clear them all.
func (t *Table) unindexPostureExcept(key types.RouteKey, keep types.SecurityPosture) {
	for posture, set := range t.postureIdx {
		if posture != keep {
			delete(set, key)
			if len(set) == 0 {
				delete(t.postureIdx, posture)
			}
		}
	}
}

// unindexASN removes key from asn's index entry, dropping the entry once it
// is empty so the map does not keep one per origin ever seen. The caller
// holds asnMu.
func (t *Table) unindexASN(asn uint32, key types.RouteKey) {
	if set, ok := t.asnIdx[asn]; ok {
		delete(set, key)
		if len(set) == 0 {
			delete(t.asnIdx, asn)
		}
	}
}

// addKey adds key to idx[k], creating the entry if needed.
func addKey[K comparable](idx map[K]keySet, k K, key types.RouteKey) {
	set, ok := idx[k]
	if !ok {
		set = keySet{}
		idx[k] = set
	}
	set[key] = struct{}{}
}

// Withdraw removes a route from the table.
func (t *Table) Withdraw(peerAddr netip.Addr, prefix netip.Prefix) {
	// Withdraw across all RIB types
	for _, rib := range []types.RIBType{types.AdjRIBInPre, types.AdjRIBInPost, types.LocRIB} {
		t.withdrawOne(types.RouteKey{PeerAddr: peerAddr, Prefix: prefix, RIBType: rib})
	}
}

func (t *Table) withdrawOne(key types.RouteKey) {
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
		t.unindexASN(originASN, key)
		t.asnMu.Unlock()
	}

	// Clean up posture index. Every entry, not just route.SecurityPosture's:
	// a revalidation may have changed the posture in place before this ran.
	t.postureMu.Lock()
	t.unindexPostureExcept(key, "")
	t.postureMu.Unlock()
}

// WithdrawAllFromPeer removes all routes from a specific peer.
func (t *Table) WithdrawAllFromPeer(peerAddr netip.Addr) int {
	count := 0
	// Scan all shards for routes from this peer
	for i := range t.shards {
		s := &t.shards[i]
		s.mu.RLock()
		var toRemove []netip.Prefix
		for key := range s.routes {
			if key.PeerAddr == peerAddr {
				toRemove = append(toRemove, key.Prefix)
			}
		}
		s.mu.RUnlock()

		for _, prefix := range toRemove {
			t.Withdraw(peerAddr, prefix)
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
	t.prefixMu.RLock()
	keys, _ := t.prefixIdx.Get(prefix)
	t.prefixMu.RUnlock()
	return t.resolveKeys(keys)
}

func (t *Table) GetByOriginASN(asn uint32) []*types.Route {
	t.asnMu.RLock()
	keys := t.asnIdx[asn].keys()
	t.asnMu.RUnlock()
	return t.resolveKeys(keys)
}

func (t *Table) GetByPosture(posture types.SecurityPosture) []*types.Route {
	t.postureMu.RLock()
	keys := t.postureIdx[posture].keys()
	t.postureMu.RUnlock()
	return t.resolveKeys(keys)
}

func (t *Table) GetByPeer(peerAddr netip.Addr) []*types.Route {
	var routes []*types.Route
	for i := range t.shards {
		s := &t.shards[i]
		s.mu.RLock()
		for key, route := range s.routes {
			if key.PeerAddr == peerAddr && route.RIBType == types.AdjRIBInPre {
				routes = append(routes, route)
			}
		}
		s.mu.RUnlock()
	}
	return routes
}

// All returns every route in the table regardless of RIB type.
func (t *Table) All() []*types.Route {
	var routes []*types.Route
	for i := range t.shards {
		s := &t.shards[i]
		s.mu.RLock()
		for _, route := range s.routes {
			routes = append(routes, route)
		}
		s.mu.RUnlock()
	}
	return routes
}

// AllPrePolicy returns only Adj-RIB-In Pre-Policy routes — the default
// operator view showing what routers received before import filtering.
func (t *Table) AllPrePolicy() []*types.Route {
	var routes []*types.Route
	for i := range t.shards {
		s := &t.shards[i]
		s.mu.RLock()
		for _, route := range s.routes {
			if route.RIBType == types.AdjRIBInPre {
				routes = append(routes, route)
			}
		}
		s.mu.RUnlock()
	}
	return routes
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
		t.withdrawOne(key)
	}
	return len(toEvict)
}

// CountByPosture returns route counts grouped by security posture.
func (t *Table) CountByPosture() map[types.SecurityPosture]uint64 {
	t.postureMu.RLock()
	defer t.postureMu.RUnlock()

	result := make(map[types.SecurityPosture]uint64)
	for posture, set := range t.postureIdx {
		result[posture] = uint64(len(set))
	}
	return result
}

// ─── Internal helpers ───

func (t *Table) getShard(key types.RouteKey) *shard {
	h := fnv.New32a()
	b := key.PeerAddr.As16()
	h.Write(b[:])
	pb, _ := key.Prefix.MarshalBinary()
	h.Write(pb)
	return &t.shards[h.Sum32()%uint32(len(t.shards))]
}

func (t *Table) resolveKeys(keys []types.RouteKey) []*types.Route {
	routes := make([]*types.Route, 0, len(keys))
	for _, key := range keys {
		if key.RIBType != types.AdjRIBInPre {
			continue // only return pre-policy routes by default
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

// containsKey and removeKey maintain a prefix's key list. It holds at most
// one key per peer, so a linear scan is bounded by the peer count, not the
// table size.
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
