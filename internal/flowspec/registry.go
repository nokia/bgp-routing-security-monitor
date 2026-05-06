package flowspec

import "sync"

// Registry tracks active Flowspec rules and prevents duplicate injections.
// All methods are safe for concurrent use.
type Registry struct {
	mu    sync.RWMutex
	rules map[string]*FlowspecRule
}

// NewRegistry returns an empty Registry.
func NewRegistry() *Registry {
	return &Registry{rules: make(map[string]*FlowspecRule)}
}

// Add inserts rule into the registry. It returns false (no-op) if a
// non-expired rule for the same CanonicalKey already exists.
func (r *Registry) Add(rule *FlowspecRule) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	key := rule.CanonicalKey()
	if existing, ok := r.rules[key]; ok && !existing.Expired() {
		return false
	}
	r.rules[key] = rule
	return true
}

// Remove deletes the rule with the given key from the registry. It is a
// no-op if no rule with that key exists.
func (r *Registry) Remove(key string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.rules, key)
}

// Get returns the rule stored under key, or nil if none is present.
func (r *Registry) Get(key string) *FlowspecRule {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.rules[key]
}

// Expired returns a snapshot of all rules whose TTL has elapsed.
func (r *Registry) Expired() []*FlowspecRule {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []*FlowspecRule
	for _, rule := range r.rules {
		if rule.Expired() {
			out = append(out, rule)
		}
	}
	return out
}

// Active returns a snapshot of all rules whose TTL has not elapsed.
func (r *Registry) Active() []*FlowspecRule {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []*FlowspecRule
	for _, rule := range r.rules {
		if !rule.Expired() {
			out = append(out, rule)
		}
	}
	return out
}

// SetDryRun updates the DryRun flag on the rule identified by key.
// Returns the updated rule and true, or nil and false if not found.
func (r *Registry) SetDryRun(key string, dryRun bool) (*FlowspecRule, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	rule, ok := r.rules[key]
	if !ok {
		return nil, false
	}
	rule.DryRun = dryRun
	return rule, true
}

// Len returns the number of non-expired (active) rules in the registry.
func (r *Registry) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	n := 0
	for _, rule := range r.rules {
		if !rule.Expired() {
			n++
		}
	}
	return n
}
