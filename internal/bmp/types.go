package bmp

import (
	"net/netip"
	"time"

	"github.com/nokia/bgp-routing-security-monitor/internal/types"
)

// BMP Message Types (RFC 7854 §4.1)
const (
	MsgTypeRouteMonitoring  uint8 = 0
	MsgTypeStatisticsReport uint8 = 1
	MsgTypePeerDown         uint8 = 2
	MsgTypePeerUp           uint8 = 3
	MsgTypeInitiation       uint8 = 4
	MsgTypeTermination      uint8 = 5
	MsgTypeRouteMirroring   uint8 = 6
)

// BMP Peer Types (RFC 7854 §4.2, RFC 9069)
const (
	PeerTypeGlobal  uint8 = 0
	PeerTypeRDLocal uint8 = 1
	PeerTypeLocal   uint8 = 2
	PeerTypeLocRIB  uint8 = 3
)

// PeerTypeName returns the name RAVEN reports for a BMP peer type.
func PeerTypeName(peerType uint8) string {
	switch peerType {
	case PeerTypeGlobal:
		return "global"
	case PeerTypeRDLocal:
		return "rd"
	case PeerTypeLocal:
		return "local"
	case PeerTypeLocRIB:
		return "loc-rib"
	default:
		return "unknown"
	}
}

// BMP Peer Flags (RFC 7854 §4.2)
const (
	PeerFlagIPv6       uint8 = 0x80 // Bit 0: 1 = IPv6, 0 = IPv4
	PeerFlagPostPolicy uint8 = 0x40 // Bit 1: 1 = Post-Policy, 0 = Pre-Policy
	PeerFlagAS2        uint8 = 0x20 // Bit 2: 1 = AS_PATH uses 2-byte ASNs
	PeerFlagAdjRIBOut  uint8 = 0x10 // Bit 3: 1 = Adj-RIB-Out (RFC 8671)
)

// BMP Initiation TLV Types (RFC 7854 §4.3)
const (
	InitTLVString   uint16 = 0 // Free-form string
	InitTLVSysDescr uint16 = 1 // sysDescr
	InitTLVSysName  uint16 = 2 // sysName
)

// BMP Common Header length: 5 bytes (Version + MsgLength + MsgType)
const CommonHeaderLen = 6 // 1 (version) + 4 (length) + 1 (type)

// BMP Per-Peer Header length: 42 bytes
const PerPeerHeaderLen = 42

// BMPCommonHeader represents the 6-byte common header on every BMP message.
type BMPCommonHeader struct {
	Version uint8
	Length  uint32
	MsgType uint8
}

// BMPPerPeerHeader represents the 42-byte per-peer header (RFC 7854 §4.2).
type BMPPerPeerHeader struct {
	PeerType          uint8
	Flags             uint8
	PeerDistinguisher types.PeerDistinguisher
	PeerAddr          netip.Addr
	PeerASN           uint32
	PeerBGPID         netip.Addr // Router ID as IPv4
	Timestamp         time.Time
}

// Key returns the key of the peer this header describes on the given router.
func (h *BMPPerPeerHeader) Key(routerAddr netip.Addr) PeerKey {
	return PeerKey{RouterAddr: routerAddr, PeerAddr: h.PeerAddr, PeerDistinguisher: h.PeerDistinguisher}
}

// IsLocRIB returns true if this header describes the router's own Loc-RIB
// (RFC 9069) rather than one of its BGP peers.
func (h *BMPPerPeerHeader) IsLocRIB() bool {
	return h.PeerType == PeerTypeLocRIB
}

// IsIPv6 returns true if the peer address is IPv6.
func (h *BMPPerPeerHeader) IsIPv6() bool {
	return !h.IsLocRIB() && h.Flags&PeerFlagIPv6 != 0
}

// IsPostPolicy returns true if this is Post-Policy Adj-RIB-In.
func (h *BMPPerPeerHeader) IsPostPolicy() bool {
	return !h.IsLocRIB() && h.Flags&PeerFlagPostPolicy != 0
}

// IsAdjRIBOut returns true if this is Adj-RIB-Out (RFC 8671).
func (h *BMPPerPeerHeader) IsAdjRIBOut() bool {
	return !h.IsLocRIB() && h.Flags&PeerFlagAdjRIBOut != 0
}

// BMPInitiation represents a BMP Initiation message (Type 4).
type BMPInitiation struct {
	SysName  string
	SysDescr string
	Info     string // free-form string TLV
}

// BMPPeerUp represents a BMP Peer Up message (Type 3).
type BMPPeerUp struct {
	PerPeer    BMPPerPeerHeader
	LocalAddr  netip.Addr
	LocalPort  uint16
	RemotePort uint16
	// LocalASN is the monitored router's own AS on this session, taken from
	// the Sent OPEN message's My Autonomous System field (overridden by the
	// 4-octet AS Number capability, RFC 6793, when present). Zero if the
	// embedded OPEN message could not be parsed.
	LocalASN uint32
}

// BMPPeerDown represents a BMP Peer Down message (Type 2).
type BMPPeerDown struct {
	PerPeer BMPPerPeerHeader
	Reason  uint8
}

// BMPRouteMonitoring represents a BMP Route Monitoring message (Type 0).
// The BGP UPDATE is parsed separately using GoBGP.
type BMPRouteMonitoring struct {
	PerPeer       BMPPerPeerHeader
	BGPUpdateData []byte // raw BGP UPDATE PDU for GoBGP to parse
}

// BMPStatsReport represents a BMP Statistics Report (Type 1).
type BMPStatsReport struct {
	PerPeer  BMPPerPeerHeader
	Counters map[uint16]uint64
}

// Peer is the runtime state RAVEN maintains per BMP peer session.
type Peer struct {
	Addr          netip.Addr
	Distinguisher types.PeerDistinguisher
	PeerType      uint8
	ASN           uint32
	LocalASN      uint32 // monitoring router's own AS on this session (from Peer Up's Sent OPEN); 0 if unknown
	RouterID      netip.Addr
	SysName       string
	SysDescr      string
	State         string // "up" or "down"
	RouteCount    uint64
	UpSince       time.Time
	LastMsg       time.Time
}

// PeerKey uniquely identifies a BMP peer.
type PeerKey struct {
	RouterAddr        netip.Addr // the BMP session source (router)
	PeerAddr          netip.Addr // the BGP peer on that router
	PeerDistinguisher types.PeerDistinguisher
}
