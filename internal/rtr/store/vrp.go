package store

import (
	"net/netip"
	"sync"

	"github.com/srl-labs/raven/internal/types"
)

// VRPStore holds Validated ROA Payloads indexed for efficient
// Route Origin Validation lookups (RFC 6811).
//
// Thread-safe for concurrent reads from validation workers
// while the RTR client writes updates.
type VRPStore struct {
	mu   sync.RWMutex
	vrps []types.VRP

	// Indexed by prefix for covering-prefix lookups.
	// Key: prefix string, Value: slice of VRPs covering that prefix.
	// We rebuild the index on each update (RTR updates are infrequent).
	byPrefix map[string][]types.VRP

	serial    uint32
	sessionID uint16
	count     uint64
}

// NewVRPStore creates an empty VRP store.
func NewVRPStore() *VRPStore {
	return &VRPStore{
		byPrefix: make(map[string][]types.VRP),
	}
}

// Count returns the number of VRPs in the store.
func (s *VRPStore) Count() uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.count
}

// Serial returns the current RTR serial number.
func (s *VRPStore) Serial() uint32 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.serial
}

// SessionID returns the current RTR session ID.
func (s *VRPStore) SessionID() uint16 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.sessionID
}

// SetSerial updates the serial and session ID after an RTR sync.
func (s *VRPStore) SetSerial(serial uint32, sessionID uint16) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.serial = serial
	s.sessionID = sessionID
}

// ReplaceAll atomically replaces the entire VRP set (used on RTR cache reset).
func (s *VRPStore) ReplaceAll(vrps []types.VRP, serial uint32, sessionID uint16) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.vrps = vrps
	s.serial = serial
	s.sessionID = sessionID
	s.count = uint64(len(vrps))
	s.rebuildIndex()
}

// AddVRP adds a single VRP (used during incremental RTR updates).
func (s *VRPStore) AddVRP(vrp types.VRP) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.vrps = append(s.vrps, vrp)
	s.count = uint64(len(s.vrps))
	// Index rebuilt lazily on EndOfData via RebuildIndex()
}

// RemoveVRP removes a single VRP (used during incremental RTR updates).
func (s *VRPStore) RemoveVRP(vrp types.VRP) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i, v := range s.vrps {
		if v.Prefix == vrp.Prefix && v.ASN == vrp.ASN && v.MaxLength == vrp.MaxLength {
			s.vrps = append(s.vrps[:i], s.vrps[i+1:]...)
			break
		}
	}
	s.count = uint64(len(s.vrps))
	s.rebuildIndex()
}

// FindCovering returns all VRPs that cover the given prefix.
// A VRP covers a route prefix if the VRP prefix is equal to or
// less specific than the route prefix (RFC 6811 §2).
func (s *VRPStore) FindCovering(prefix netip.Prefix) []types.VRP {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []types.VRP

	// Check all prefix lengths from /0 up to the route's prefix length
	// to find covering VRPs.
	addr := prefix.Addr()
	for pl := 0; pl <= prefix.Bits(); pl++ {
		// Compute the network address at this prefix length
		candidate, err := addr.Prefix(pl)
		if err != nil {
			continue
		}
		key := candidate.String()
		if vrps, ok := s.byPrefix[key]; ok {
			result = append(result, vrps...)
		}
	}

	return result
}

// All returns a copy of all VRPs. Used for diagnostics.
func (s *VRPStore) All() []types.VRP {
	s.mu.RLock()
	defer s.mu.RUnlock()

	cp := make([]types.VRP, len(s.vrps))
	copy(cp, s.vrps)
	return cp
}

// rebuildIndex rebuilds the prefix lookup index. Must be called with mu held.
func (s *VRPStore) rebuildIndex() {
	s.byPrefix = make(map[string][]types.VRP, len(s.vrps))
	for _, vrp := range s.vrps {
		key := vrp.Prefix.String()
		s.byPrefix[key] = append(s.byPrefix[key], vrp)
	}
}

// RebuildIndex rebuilds the prefix lookup index.
// Call once after a bulk load (e.g. after RTR EndOfData).
func (s *VRPStore) RebuildIndex() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rebuildIndex()
}
