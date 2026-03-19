package routetable

import (
	"hash/fnv"
	"net/netip"
	"sync"

	"github.com/gaissmai/bart"
	"github.com/srl-labs/raven/internal/types"
)

const defaultShards = 256

// Table is RAVEN's internal route table — an annotated Adj-RIB-In.
// It stores every route from every peer with validation annotations.
//
// Architecture: hybrid BART prefix index + sharded flat map (see ARCHITECTURE.md §2.3).
type Table struct {
	// Primary store: sharded flat map keyed by (PeerAddr, Prefix)
	shards []shard

	// Prefix index: BART trie mapping prefix -> set of route keys
	prefixMu sync.RWMutex
	prefixIdx bart.Table[[]types.RouteKey]

	// Secondary index: origin ASN -> route keys
	asnMu  sync.RWMutex
	asnIdx map[uint32][]types.RouteKey

	// Secondary index: security posture -> route keys
	postureMu sync.RWMutex
	postureIdx map[types.SecurityPosture][]types.RouteKey
}

type shard struct {
	mu     sync.RWMutex
	routes map[types.RouteKey]*types.Route
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

func (t *Table) GetByPrefix(prefix netip.Prefix) []*types.Route {
	t.prefixMu.RLock()
	keys, _ := t.prefixIdx.Get(prefix)
	t.prefixMu.RUnlock()
	return t.resolveKeys(keys)
}

func (t *Table) GetByOriginASN(asn uint32) []*types.Route {
	t.asnMu.RLock()
	keys := t.asnIdx[asn]
	t.asnMu.RUnlock()
	return t.resolveKeys(keys)
}

func (t *Table) GetByPosture(posture types.SecurityPosture) []*types.Route {
	t.postureMu.RLock()
	keys := t.postureIdx[posture]
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