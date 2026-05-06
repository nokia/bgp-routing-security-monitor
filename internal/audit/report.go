package audit

import "time"

// RouterAuditReport is the top-level result of a security posture audit for one router.
type RouterAuditReport struct {
	RouterID        string            `json:"router_id"`
	GeneratedAt     time.Time         `json:"generated_at"`
	TotalRoutes     int               `json:"total_routes"`
	ROVCoverage     float64           `json:"rov_coverage"`    // fraction 0–1
	ASPACoverage    float64           `json:"aspa_coverage"`   // fraction 0–1
	PostureSummary  map[string]int    `json:"posture_summary"` // posture → count
	Peers           []PeerAuditReport `json:"peers"`
	TopOffenders    []OffenderEntry   `json:"top_offenders"`
	Recommendations []string          `json:"recommendations"`
}

// PeerAuditReport summarises a single BGP peer's contribution to the router's route table.
type PeerAuditReport struct {
	PeerAddr       string         `json:"peer_addr"`
	PeerASN        uint32         `json:"peer_asn"`
	TotalRoutes    int            `json:"total_routes"`
	PostureSummary map[string]int `json:"posture_summary"`
	ROVCoverage    float64        `json:"rov_coverage"`
	ASPACoverage   float64        `json:"aspa_coverage"`
}

// OffenderEntry describes an origin ASN contributing origin-invalid or path-suspect routes.
type OffenderEntry struct {
	OriginASN uint32   `json:"origin_asn"`
	Count     int      `json:"count"`
	Posture   string   `json:"posture"`            // worst posture seen for this ASN
	Prefixes  []string `json:"prefixes,omitempty"` // up to 5 example prefixes
}
