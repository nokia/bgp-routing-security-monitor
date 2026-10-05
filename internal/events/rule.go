package events

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// Rule pairs a Trigger with one or more Actions and optional per-prefix rate-limiting.
type Rule struct {
	// Name is a human-readable identifier used in logs.
	Name string
	// Trigger decides whether this rule fires for a given event.
	Trigger Trigger
	// Actions are executed concurrently when the trigger matches.
	Actions []Action
	// Enrichers annotate the event before Actions run. They are populated
	// from the same YAML actions list; buildRule partitions them out.
	Enrichers []Enricher
	// Cooldown prevents the same rule from firing more than once per route
	// (prefix, peer, Peer Distinguisher and RIB) within this duration. Zero
	// means no cooldown.
	Cooldown    time.Duration
	log         *slog.Logger
	cooldownMu  sync.Mutex
	cooldownMap map[string]time.Time // key: "prefix|peer|distinguisher|rib" or event type
}

// Evaluate checks the trigger, enforces the cooldown, runs any enrichers,
// then calls every action concurrently in its own goroutine. Action errors
// are logged but do not interrupt other actions.
//
// The engine calls Evaluate from its own goroutine, so everything here —
// including an enricher's outbound HTTP call — is already off the BMP ingest
// and validation path.
func (r *Rule) Evaluate(ctx context.Context, event Event) {
	if !r.Trigger.Matches(event) {
		return
	}
	if !r.checkCooldown(event) {
		return
	}

	// Enrichers run to completion before the actions so that every action
	// sees the same fully annotated event. They mutate a local copy; the
	// event the engine holds is untouched, so one rule's enrichment cannot
	// leak into another rule's evaluation of the same event.
	for _, enricher := range r.Enrichers {
		enricher.Enrich(ctx, &event)
	}

	var wg sync.WaitGroup
	for _, action := range r.Actions {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := action.Execute(ctx, event); err != nil {
				r.log.Error("action failed",
					"rule", r.Name,
					"action", action.Name(),
					"error", err,
				)
			}
		}()
	}
	wg.Wait()
}

// checkCooldown returns false when the event falls within the active cooldown
// window for its route key. On a pass it records the current time.
func (r *Rule) checkCooldown(event Event) bool {
	if r.Cooldown == 0 {
		return true
	}
	key := cooldownKey(event)
	now := time.Now()
	r.cooldownMu.Lock()
	defer r.cooldownMu.Unlock()
	if last, ok := r.cooldownMap[key]; ok && now.Sub(last) < r.Cooldown {
		return false
	}
	r.cooldownMap[key] = now
	return true
}

func cooldownKey(event Event) string {
	if event.Type == EventTypeCacheUnhealthy {
		return "cache|" + event.CacheName
	}
	if event.Route == nil {
		return string(event.Type)
	}
	k := event.Route.Key()
	return fmt.Sprintf("%s|%s|%s|%s", k.Prefix, k.PeerAddr, k.PeerDistinguisher, k.RIBType)
}
