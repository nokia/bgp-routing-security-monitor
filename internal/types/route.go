package types

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"time"
)

// ─── Route ───
// The central data object flowing through RAVEN's pipeline.
// Created by BMP Ingest, annotated by Validation Engine, stored in Route Table.

type Route struct {
	// Populated by BMP Ingest
	Timestamp         time.Time
	PeerAddr          netip.Addr
	PeerDistinguisher PeerDistinguisher
	PeerASN           uint32
	// LocalASN is the monitoring router's own AS on the BMP session this
	// route was learned over (from the Peer Up message's Sent OPEN). Zero
	// if unknown. Used by ASPA validation for the path[0]-vs-local-AS hop.
	LocalASN uint32

	RouterID         netip.Addr
	Prefix           netip.Prefix
	ASPath           []uint32    // flattened (AS_SETs expanded)
	ASPathRaw        []ASSegment // preserving segment types for ASPA
	Origin           OriginType  // IGP/EGP/Incomplete
	NextHop          netip.Addr
	Communities      []Community
	LargeCommunities []LargeCommunity
	RIBType          RIBType

	// Populated by Validation Engine
	ROV             ROVResult
	ASPA            ASPAResult
	SecurityPosture SecurityPosture

	// Stale is set on routes restored from a snapshot. It is cleared
	// when a live BMP Route Monitoring message confirms the route is
	// still active. Stale routes are excluded from Event Engine
	// evaluation.
	Stale bool
}

// Withdrawal represents a BGP route withdrawal received via BMP.
type Withdrawal struct {
	PeerAddr          netip.Addr
	PeerDistinguisher PeerDistinguisher
	Prefix            netip.Prefix
	RIBType           RIBType
	// WithdrawAll removes every route of the peer in RIBs (every RIB when
	// empty), and Prefix and RIBType are then unused.
	WithdrawAll bool
	RIBs        []RIBType
}

// Key returns the Route Table key of the one route this withdrawal removes.
func (w *Withdrawal) Key() RouteKey {
	return RouteKey{PeerAddr: w.PeerAddr, PeerDistinguisher: w.PeerDistinguisher, Prefix: w.Prefix, RIBType: w.RIBType}
}

// IngestEvent is one item on the BMP ingest stream. Exactly one of Route or
// Withdrawal is set.
//
// Routes and withdrawals share one channel so the Route Table applies them in
// the order the router sent them. On separate channels a peer-down could be
// applied while that peer's routes were still queued, and those routes were
// then re-inserted after the wipe and never removed.
type IngestEvent struct {
	Route      *Route
	Withdrawal *Withdrawal
}

// OriginASN returns the last ASN in the AS_PATH (the route originator).
func (r *Route) OriginASN() uint32 {
	if len(r.ASPath) == 0 {
		return 0
	}
	return r.ASPath[len(r.ASPath)-1]
}

// Key returns the Route Table key of the route.
func (r *Route) Key() RouteKey {
	return RouteKey{PeerAddr: r.PeerAddr, PeerDistinguisher: r.PeerDistinguisher, Prefix: r.Prefix, RIBType: r.RIBType}
}

// RouteKey uniquely identifies a route in the Route Table.
type RouteKey struct {
	PeerAddr          netip.Addr
	PeerDistinguisher PeerDistinguisher
	Prefix            netip.Prefix
	RIBType           RIBType
}

// PeerDistinguisher is the BMP Peer Distinguisher (RFC 7854 §4.2): the RD
// or instance ID of a non-global peer, zero for a global one.
type PeerDistinguisher [8]byte

// PeerDistinguisherFromUint64 builds a distinguisher from its big-endian integer form.
func PeerDistinguisherFromUint64(v uint64) PeerDistinguisher {
	var d PeerDistinguisher
	binary.BigEndian.PutUint64(d[:], v)
	return d
}

func (d PeerDistinguisher) Uint64() uint64 {
	return binary.BigEndian.Uint64(d[:])
}

// String formats the distinguisher as a route distinguisher (RFC 4364 §4.2),
// with an L after a type 2 AS number so that types 0 and 2 stay apart, or
// returns "" for a global peer.
func (d PeerDistinguisher) String() string {
	if d == (PeerDistinguisher{}) {
		return ""
	}
	switch binary.BigEndian.Uint16(d[0:2]) {
	case 0:
		return fmt.Sprintf("%d:%d", binary.BigEndian.Uint16(d[2:4]), binary.BigEndian.Uint32(d[4:8]))
	case 1:
		return fmt.Sprintf("%s:%d", netip.AddrFrom4([4]byte(d[2:6])), binary.BigEndian.Uint16(d[6:8]))
	case 2:
		return fmt.Sprintf("%dL:%d", binary.BigEndian.Uint32(d[2:6]), binary.BigEndian.Uint16(d[6:8]))
	default:
		return fmt.Sprintf("0x%016x", d.Uint64())
	}
}

// ─── AS_PATH types ───

type ASSegmentType uint8

const (
	ASSegmentSequence ASSegmentType = 2 // AS_SEQUENCE
	ASSegmentSet      ASSegmentType = 1 // AS_SET
)

type ASSegment struct {
	Type ASSegmentType
	ASNs []uint32
}

// HasASSet returns true if the AS_PATH contains any AS_SET segments.
func (r *Route) HasASSet() bool {
	for _, seg := range r.ASPathRaw {
		if seg.Type == ASSegmentSet {
			return true
		}
	}
	return false
}

// ─── BGP Origin ───

type OriginType uint8

const (
	OriginIGP        OriginType = 0
	OriginEGP        OriginType = 1
	OriginIncomplete OriginType = 2
)

// ─── Communities ───

type Community struct {
	High uint16
	Low  uint16
}

type LargeCommunity struct {
	GlobalAdmin uint32
	LocalData1  uint32
	LocalData2  uint32
}

// ─── BMP RIB types ───

type RIBType uint8

const (
	AdjRIBInPre  RIBType = 0
	AdjRIBInPost RIBType = 1
	LocRIB       RIBType = 2
)

// RIBTypes lists every RIB type.
var RIBTypes = []RIBType{AdjRIBInPre, AdjRIBInPost, LocRIB}

func (r RIBType) String() string {
	switch r {
	case AdjRIBInPost:
		return "post-policy"
	case LocRIB:
		return "loc-rib"
	default:
		return "pre-policy"
	}
}

// ParseRIBType parses the name of a RIB type.
func ParseRIBType(s string) (RIBType, error) {
	for _, r := range RIBTypes {
		if r.String() == s {
			return r, nil
		}
	}
	return 0, fmt.Errorf("unknown RIB type %q (want pre-policy, post-policy or loc-rib)", s)
}

// ─── ROV (RFC 6811) ───

type ROVState uint8

const (
	ROVValid    ROVState = 0
	ROVInvalid  ROVState = 1
	ROVNotFound ROVState = 2
)

func (s ROVState) String() string {
	switch s {
	case ROVValid:
		return "Valid"
	case ROVInvalid:
		return "Invalid"
	case ROVNotFound:
		return "NotFound"
	default:
		return "Unknown"
	}
}

type ROVResult struct {
	State       ROVState
	MatchedVRPs []VRP
	Reason      string
}

type VRP struct {
	Prefix    netip.Prefix
	ASN       uint32
	MaxLength uint8
}

// ─── ASPA (draft-ietf-sidrops-aspa-verification) ───

type ASPAState uint8

const (
	ASPAValid        ASPAState = 0
	ASPAInvalid      ASPAState = 1
	ASPAUnknown      ASPAState = 2
	ASPAUnverifiable ASPAState = 3
)

func (s ASPAState) String() string {
	switch s {
	case ASPAValid:
		return "Valid"
	case ASPAInvalid:
		return "Invalid"
	case ASPAUnknown:
		return "Unknown"
	case ASPAUnverifiable:
		return "Unverifiable"
	default:
		return "Unknown"
	}
}

type ASPAProcedure uint8

const (
	ASPAUpstream   ASPAProcedure = 0
	ASPADownstream ASPAProcedure = 1
)

type HopAuth uint8

const (
	HopAuthorized    HopAuth = 0
	HopNotAuthorized HopAuth = 1
	HopNoASPA        HopAuth = 2
	HopSkipped       HopAuth = 3 // AS_SET segment in best-effort mode
)

type ASPAHop struct {
	CustomerASN   uint32
	ProviderASN   uint32
	Authorization HopAuth
	Reason        string // human-readable (e.g., "AS_SET segment skipped")
}

type ASPAResult struct {
	State      ASPAState
	FailingHop *ASPAHop  // non-nil if State == Invalid
	HopDetails []ASPAHop // per-hop breakdown
	Procedure  ASPAProcedure
}

// ASPARecord is a snapshot-friendly representation of a validated ASPA object.
// ProviderASNs is a sorted slice (not a map) for deterministic serialisation.
type ASPARecord struct {
	CustomerASN  uint32
	ProviderASNs []uint32
}

// ─── Security Posture (§2.4.3) ───
// Combined ROV × ASPA result

type SecurityPosture string

const (
	PostureSecured       SecurityPosture = "secured"
	PostureOriginOnly    SecurityPosture = "origin-only"
	PosturePathSuspect   SecurityPosture = "path-suspect"
	PosturePathOnly      SecurityPosture = "path-only"
	PostureUnverified    SecurityPosture = "unverified"
	PostureOriginInvalid SecurityPosture = "origin-invalid"
)

// ComputePosture derives the combined security posture from ROV and ASPA states.
// This implements the matrix from Architecture doc §2.4.3.
func ComputePosture(rov ROVState, aspa ASPAState) SecurityPosture {
	if rov == ROVInvalid {
		return PostureOriginInvalid
	}
	switch {
	case rov == ROVValid && aspa == ASPAValid:
		return PostureSecured
	case rov == ROVValid && (aspa == ASPAUnknown || aspa == ASPAUnverifiable):
		return PostureOriginOnly
	case rov == ROVValid && aspa == ASPAInvalid:
		return PosturePathSuspect
	case rov == ROVNotFound && aspa == ASPAValid:
		return PosturePathOnly
	case rov == ROVNotFound && aspa == ASPAInvalid:
		return PosturePathSuspect
	default:
		// ROVNotFound + ASPAUnknown/Unverifiable
		return PostureUnverified
	}
}
