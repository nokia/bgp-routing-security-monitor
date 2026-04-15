package bmp

import (
	"net/netip"
	"time"
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

// BMP Peer Types (RFC 7854 §4.2)
const (
	PeerTypeGlobal  uint8 = 0
	PeerTypeRDLocal uint8 = 1
	PeerTypeLocal   uint8 = 2
)

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
	PeerDistinguisher [8]byte
	PeerAddr          netip.Addr
	PeerASN           uint32
	PeerBGPID         netip.Addr // Router ID as IPv4
	Timestamp         time.Time
}

// IsIPv6 returns true if the peer address is IPv6.
func (h *BMPPerPeerHeader) IsIPv6() bool {
	return h.Flags&PeerFlagIPv6 != 0
}

// IsPostPolicy returns true if this is Post-Policy Adj-RIB-In.
func (h *BMPPerPeerHeader) IsPostPolicy() bool {
	return h.Flags&PeerFlagPostPolicy != 0
}

// IsAdjRIBOut returns true if this is Adj-RIB-Out (RFC 8671).
func (h *BMPPerPeerHeader) IsAdjRIBOut() bool {
	return h.Flags&PeerFlagAdjRIBOut != 0
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
	// Sent and Received OPEN messages are parsed but we primarily
	// extract capabilities from them (BGP Role, ADD-PATH, etc.)
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
	Addr       netip.Addr
	ASN        uint32
	RouterID   netip.Addr
	SysName    string
	SysDescr   string
	State      string // "up" or "down"
	RouteCount uint64
	UpSince    time.Time
	LastMsg    time.Time
}

// PeerKey uniquely identifies a BMP peer.
type PeerKey struct {
	RouterAddr netip.Addr // the BMP session source (router)
	PeerAddr   netip.Addr // the BGP peer on that router
}
