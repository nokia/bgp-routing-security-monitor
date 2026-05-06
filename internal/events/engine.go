package events

import (
	"context"
	"log/slog"
	"sync"
)

const internalChannelSize = 1000

// Engine evaluates all configured rules for every event it receives.
// It owns an internal buffered channel so that callers using Emit are
// decoupled from action execution latency.
type Engine struct {
	rules   []*Rule
	logger  *slog.Logger
	eventCh chan Event
}

// NewEngine creates an Engine backed by a 1000-event internal buffer.
func NewEngine(rules []*Rule, logger *slog.Logger) *Engine {
	return &Engine{
		rules:   rules,
		logger:  logger,
		eventCh: make(chan Event, internalChannelSize),
	}
}

// Run reads events from eventCh and the engine's internal channel, evaluating
// all rules concurrently for each event. It blocks until ctx is done and all
// in-flight evaluations complete.
//
// eventCh may be nil; in that case only events sent via Emit are processed.
func (e *Engine) Run(ctx context.Context, eventCh <-chan Event) {
	var wg sync.WaitGroup
	for {
		var event Event
		select {
		case ev, ok := <-eventCh:
			if !ok {
				eventCh = nil // disable closed channel; keep draining internal
				continue
			}
			event = ev
		case ev := <-e.eventCh:
			event = ev
		case <-ctx.Done():
			wg.Wait()
			return
		}
		// Stale routes have not been confirmed by a live BMP message yet —
		// skip them so snapshot artefacts never trigger active-response rules.
		if event.Route != nil && event.Route.Stale {
			continue
		}
		for _, rule := range e.rules {
			wg.Add(1)
			go func() {
				defer wg.Done()
				rule.Evaluate(ctx, event)
			}()
		}
	}
}

// Emit sends an event to the engine's internal channel for processing by Run.
// It is non-blocking: if the channel is full the event is dropped with a warning.
func (e *Engine) Emit(event Event) {
	select {
	case e.eventCh <- event:
	default:
		e.logger.Warn("event channel full, dropping event",
			"type", event.Type,
			"id", event.ID,
		)
	}
}
