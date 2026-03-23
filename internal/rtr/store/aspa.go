package store

import (
	"sync"
)

// ASPARecord holds the validated provider set for a single customer ASN.
// Per RTR v2 semantics, the provider set is the union of all valid ASPA
// objects for that customer ASN.
type ASPARecord struct {
	CustomerASN uint32
	Providers   map[uint32]struct{} // set of authorized provider ASNs
}

// ASPAStore holds ASPA Validated Payloads received via RTR v2.
// Indexed by customer ASN for O(1) lookup during AS_PATH verification.
type ASPAStore struct {
	mu      sync.RWMutex
	records map[uint32]*ASPARecord // customer ASN -> record
}

// NewASPAStore creates an empty ASPA store.
func NewASPAStore() *ASPAStore {
	return &ASPAStore{
		records: make(map[uint32]*ASPARecord),
	}
}

// AddProvider adds a provider ASN to a customer's provider set.
// Creates the record if it doesn't exist.
func (s *ASPAStore) AddProvider(customerASN, providerASN uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.records[customerASN]
	if !ok {
		r = &ASPARecord{
			CustomerASN: customerASN,
			Providers:   make(map[uint32]struct{}),
		}
		s.records[customerASN] = r
	}
	r.Providers[providerASN] = struct{}{}
}

// RemoveProvider removes a provider ASN from a customer's provider set.
// Removes the record entirely if the provider set becomes empty.
func (s *ASPAStore) RemoveProvider(customerASN, providerASN uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.records[customerASN]
	if !ok {
		return
	}
	delete(r.Providers, providerASN)
	if len(r.Providers) == 0 {
		delete(s.records, customerASN)
	}
}

// GetRecord returns a copy of the ASPA record for a customer ASN.
// Returns nil if no record exists.
func (s *ASPAStore) GetRecord(customerASN uint32) *ASPARecord {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.records[customerASN]
	if !ok {
		return nil
	}
	// Return a copy to avoid races
	copy := &ASPARecord{
		CustomerASN: r.CustomerASN,
		Providers:   make(map[uint32]struct{}, len(r.Providers)),
	}
	for p := range r.Providers {
		copy.Providers[p] = struct{}{}
	}
	return copy
}

// HasProvider returns true if providerASN is in customerASN's provider set.
func (s *ASPAStore) HasProvider(customerASN, providerASN uint32) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.records[customerASN]
	if !ok {
		return false
	}
	_, ok = r.Providers[providerASN]
	return ok
}

// HasRecord returns true if the store has any ASPA record for customerASN.
func (s *ASPAStore) HasRecord(customerASN uint32) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.records[customerASN]
	return ok
}

// Count returns the number of customer ASNs with ASPA records.
func (s *ASPAStore) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.records)
}

// AffectedASNs returns all customer ASNs in the store.
// Used to compute dirty sets for re-validation after ASPA updates.
func (s *ASPAStore) AffectedASNs() []uint32 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	asns := make([]uint32, 0, len(s.records))
	for asn := range s.records {
		asns = append(asns, asn)
	}
	return asns
}