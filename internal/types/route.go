package types

import (
	"net/netip"
	"time"
)

// ─── Route ───
// The central data object flowing through RAVEN's pipeline.
// Created by BMP Ingest, annotated by Validation Engine, stored in Route Table.

type Route struct {
	// Populated by BMP Ingest
	Timestamp        time.Time
	PeerAddr         netip.Addr
	PeerASN          uint32
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
}

// Withdrawal represents a BGP route withdrawal received via BMP.
type Withdrawal struct {
	PeerAddr    netip.Addr
	Prefix      netip.Prefix
	RIBType     RIBType
	WithdrawAll bool // if true, withdraw all routes from PeerAddr
}

// OriginASN returns the last ASN in the AS_PATH (the route originator).
func (r *Route) OriginASN() uint32 {
	if len(r.ASPath) == 0 {
		return 0
	}
	return r.ASPath[len(r.ASPath)-1]
}

// RouteKey uniquely identifies a route in the Route Table.
type RouteKey struct {
	PeerAddr netip.Addr
	Prefix   netip.Prefix
	RIBType  RIBType
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
