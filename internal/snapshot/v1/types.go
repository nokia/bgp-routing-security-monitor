// Package snapshotv1 defines the on-disk serialisation types for RAVEN
// snapshots. The canonical schema lives in
// internal/proto/snapshot/v1/snapshot.proto; once buf is configured
// (run: buf generate), replace this file with the generated
// snapshot.pb.go — the field names and package path are identical.
package snapshotv1

// RouteSnapshot is the JSON envelope written to routes.snap.
type RouteSnapshot struct {
	SnapshotTimeUnix int64         `json:"snapshot_time_unix"`
	RavenVersion     string        `json:"raven_version"`
	Routes           []RouteRecord `json:"routes"`
}

// RouteRecord is a single route entry in a RouteSnapshot.
type RouteRecord struct {
	Prefix        string   `json:"prefix"`
	PeerAddr      string   `json:"peer_addr"`
	PeerASN       uint32   `json:"peer_asn"`
	RouterID      string   `json:"router_id,omitempty"`
	ASPath        []uint32 `json:"as_path,omitempty"`
	OriginASN     uint32   `json:"origin_asn"`
	NextHop       string   `json:"next_hop,omitempty"`
	TimestampUnix int64    `json:"timestamp_unix"`
	RIBType       string   `json:"rib_type"`
	ROVState      string   `json:"rov_state"`
	ASPAState     string   `json:"aspa_state"`
	Posture       string   `json:"posture"`
	Stale         bool     `json:"stale"`
}

// RPKISnapshot is the JSON envelope written to rpki.snap.
type RPKISnapshot struct {
	SnapshotTimeUnix int64        `json:"snapshot_time_unix"`
	RavenVersion     string       `json:"raven_version"`
	RTRSerial        uint32       `json:"rtr_serial"`
	VRPs             []VRPRecord  `json:"vrps,omitempty"`
	ASPAs            []ASPARecord `json:"aspas,omitempty"`
}

// VRPRecord is a single VRP entry in an RPKISnapshot.
type VRPRecord struct {
	Prefix    string `json:"prefix"`
	ASN       uint32 `json:"asn"`
	MaxLength uint32 `json:"max_length"`
}

// ASPARecord is a single ASPA entry in an RPKISnapshot.
type ASPARecord struct {
	CustomerASN  uint32   `json:"customer_asn"`
	ProviderASNs []uint32 `json:"provider_asns,omitempty"`
}
