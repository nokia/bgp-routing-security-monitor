package events

import (
	"context"
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
	// Cooldown prevents the same rule from firing more than once per
	// prefix+peer pair within this duration. Zero means no cooldown.
	Cooldown    time.Duration
	log         *slog.Logger
	cooldownMu  sync.Mutex
	cooldownMap map[string]time.Time // key: "prefix|peerAddr" or event type
}

// Evaluate checks the trigger, enforces the cooldown, then calls every action
// concurrently in its own goroutine. Action errors are logged but do not
// interrupt other actions.
func (r *Rule) Evaluate(ctx context.Context, event Event) {
	if !r.Trigger.Matches(event) {
		return
	}
	if !r.checkCooldown(event) {
		return
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
// window for its prefix+peer key. On a pass it records the current time.
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
	return event.Route.Prefix.String() + "|" + event.Route.PeerAddr.String()
}
