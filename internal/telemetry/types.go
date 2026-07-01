package telemetry

import "time"

// SyncType indicates whether a sync cycle was triggered by a Reset Query
// (full table dump) or a Serial Query (incremental update).
type SyncType string

const (
	SyncTypeFull        SyncType = "full"
	SyncTypeIncremental SyncType = "incremental"
)

// ResetReason classifies why an RTR session was reset or reconnected.
type ResetReason string

const (
	ResetReasonCacheResetPDU      ResetReason = "cache_reset_pdu"     // cache sent PDUCacheReset mid-session
	ResetReasonReconnectError     ResetReason = "reconnect_error"     // session failed and reconnected
	ResetReasonReconnectTimeout   ResetReason = "reconnect_timeout"   // TCP stall or read deadline
	ResetReasonVersionNegotiation ResetReason = "version_negotiation" // fell back to lower RTR version
)

// EventType classifies a SessionEvent.
type EventType string

const (
	EventConnected    EventType = "connected"
	EventDisconnected EventType = "disconnected"
	EventSync         EventType = "sync"
	EventReset        EventType = "reset"
	EventError        EventType = "error"
)

// SessionEvent captures a single RTR session lifecycle or sync event.
// It is the atomic unit written to the NDJSON log and emitted on the
// event channel consumed by the anomaly detector.
type SessionEvent struct {
	Timestamp time.Time `json:"timestamp"`
	Cache     string    `json:"cache"`
	EventType EventType `json:"event_type"`

	// Sync fields — populated when EventType == EventSync.
	Serial        uint32        `json:"serial,omitempty"`
	VRPTotal      int           `json:"vrp_total,omitempty"`
	VRPAnnounced  int           `json:"vrp_announced,omitempty"`
	VRPWithdrawn  int           `json:"vrp_withdrawn,omitempty"`
	ASPATotal     int           `json:"aspa_total,omitempty"`
	ASPAAnnounced int           `json:"aspa_announced,omitempty"`
	ASPAWithdrawn int           `json:"aspa_withdrawn,omitempty"`
	SyncDuration  time.Duration `json:"sync_duration_ns,omitempty"`
	IntervalSince time.Duration `json:"interval_since_ns,omitempty"`
	SyncType      SyncType      `json:"sync_type,omitempty"`

	// Reset fields — populated when EventType == EventReset.
	ResetReason ResetReason `json:"reset_reason,omitempty"`

	// Error fields — populated when EventType == EventError.
	ErrorText    string `json:"error_text,omitempty"`
	ProtoVersion uint8  `json:"proto_version,omitempty"`

	// Disconnect fields — populated when EventType == EventDisconnected.
	DisconnectReason string `json:"disconnect_reason,omitempty"`
}
