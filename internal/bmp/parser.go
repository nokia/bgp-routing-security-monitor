package bmp

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"time"
)

const bmpVersion = 3

// ParseCommonHeader parses the 6-byte BMP common header.
// Returns the header and any error.
func ParseCommonHeader(data []byte) (BMPCommonHeader, error) {
	if len(data) < CommonHeaderLen {
		return BMPCommonHeader{}, fmt.Errorf("BMP common header too short: %d bytes", len(data))
	}

	h := BMPCommonHeader{
		Version: data[0],
		Length:  binary.BigEndian.Uint32(data[1:5]),
		MsgType: data[5],
	}

	if h.Version != bmpVersion {
		return h, fmt.Errorf("unsupported BMP version %d (expected %d)", h.Version, bmpVersion)
	}

	if h.Length < CommonHeaderLen {
		return h, fmt.Errorf("BMP message length %d is less than common header size", h.Length)
	}

	return h, nil
}

// ParsePerPeerHeader parses the 42-byte per-peer header from the given data.
func ParsePerPeerHeader(data []byte) (BMPPerPeerHeader, error) {
	if len(data) < PerPeerHeaderLen {
		return BMPPerPeerHeader{}, fmt.Errorf("per-peer header too short: %d bytes", len(data))
	}

	h := BMPPerPeerHeader{
		PeerType: data[0],
		Flags:    data[1],
	}

	copy(h.PeerDistinguisher[:], data[2:10])

	// Peer address: 16 bytes (10..25). IPv4 is in the last 4 bytes.
	var addrBytes [16]byte
	copy(addrBytes[:], data[10:26])

	if h.IsIPv6() {
		addr, ok := netip.AddrFromSlice(addrBytes[:])
		if !ok {
			return h, fmt.Errorf("invalid IPv6 peer address")
		}
		h.PeerAddr = addr
	} else {
		// IPv4 is stored in the last 4 bytes of the 16-byte field
		addr, ok := netip.AddrFromSlice(addrBytes[12:16])
		if !ok {
			return h, fmt.Errorf("invalid IPv4 peer address")
		}
		h.PeerAddr = addr
	}

	// Peer AS: bytes 26..29
	h.PeerASN = binary.BigEndian.Uint32(data[26:30])

	// Peer BGP ID: bytes 30..33 (IPv4 router ID)
	bgpID, ok := netip.AddrFromSlice(data[30:34])
	if !ok {
		return h, fmt.Errorf("invalid BGP ID")
	}
	h.PeerBGPID = bgpID

	// Timestamp: bytes 34..37 (seconds) + 38..41 (microseconds)
	sec := binary.BigEndian.Uint32(data[34:38])
	usec := binary.BigEndian.Uint32(data[38:42])
	h.Timestamp = time.Unix(int64(sec), int64(usec)*1000)

	return h, nil
}

// ParseInitiation parses a BMP Initiation message body (after common header).
func ParseInitiation(data []byte) (BMPInitiation, error) {
	init := BMPInitiation{}
	offset := 0

	for offset+4 <= len(data) {
		tlvType := binary.BigEndian.Uint16(data[offset : offset+2])
		tlvLen := binary.BigEndian.Uint16(data[offset+2 : offset+4])
		offset += 4

		if offset+int(tlvLen) > len(data) {
			return init, fmt.Errorf("initiation TLV overflows message: type=%d len=%d", tlvType, tlvLen)
		}

		val := string(data[offset : offset+int(tlvLen)])
		offset += int(tlvLen)

		switch tlvType {
		case InitTLVString:
			init.Info = val
		case InitTLVSysDescr:
			init.SysDescr = val
		case InitTLVSysName:
			init.SysName = val
		}
	}

	return init, nil
}

// ParseRouteMonitoring parses a BMP Route Monitoring message body.
// It extracts the per-peer header and returns the raw BGP UPDATE PDU
// for GoBGP to parse.
func ParseRouteMonitoring(data []byte) (BMPRouteMonitoring, error) {
	pph, err := ParsePerPeerHeader(data)
	if err != nil {
		return BMPRouteMonitoring{}, fmt.Errorf("route monitoring per-peer header: %w", err)
	}

	bgpData := data[PerPeerHeaderLen:]

	// BGP message has a 19-byte header (16 marker + 2 length + 1 type)
	// We pass the entire BGP message to GoBGP for parsing
	if len(bgpData) < 19 {
		return BMPRouteMonitoring{}, fmt.Errorf("BGP message too short: %d bytes", len(bgpData))
	}

	return BMPRouteMonitoring{
		PerPeer:       pph,
		BGPUpdateData: bgpData,
	}, nil
}

// ParsePeerUp parses a BMP Peer Up message body.
func ParsePeerUp(data []byte) (BMPPeerUp, error) {
	pph, err := ParsePerPeerHeader(data)
	if err != nil {
		return BMPPeerUp{}, fmt.Errorf("peer up per-peer header: %w", err)
	}

	body := data[PerPeerHeaderLen:]
	if len(body) < 20 {
		return BMPPeerUp{}, fmt.Errorf("peer up body too short: %d bytes", len(body))
	}

	pu := BMPPeerUp{PerPeer: pph}

	// Local address: 16 bytes
	if pph.IsIPv6() {
		addr, ok := netip.AddrFromSlice(body[0:16])
		if !ok {
			return pu, fmt.Errorf("invalid IPv6 local address")
		}
		pu.LocalAddr = addr
	} else {
		addr, ok := netip.AddrFromSlice(body[12:16])
		if !ok {
			return pu, fmt.Errorf("invalid IPv4 local address")
		}
		pu.LocalAddr = addr
	}

	// Local port: bytes 16..17, Remote port: bytes 18..19
	pu.LocalPort = binary.BigEndian.Uint16(body[16:18])
	pu.RemotePort = binary.BigEndian.Uint16(body[18:20])

	return pu, nil
}

// ParsePeerDown parses a BMP Peer Down message body.
func ParsePeerDown(data []byte) (BMPPeerDown, error) {
	pph, err := ParsePerPeerHeader(data)
	if err != nil {
		return BMPPeerDown{}, fmt.Errorf("peer down per-peer header: %w", err)
	}

	body := data[PerPeerHeaderLen:]
	if len(body) < 1 {
		return BMPPeerDown{}, fmt.Errorf("peer down body too short")
	}

	return BMPPeerDown{
		PerPeer: pph,
		Reason:  body[0],
	}, nil
}

// ParseStatsReport parses a BMP Statistics Report message body.
func ParseStatsReport(data []byte) (BMPStatsReport, error) {
	pph, err := ParsePerPeerHeader(data)
	if err != nil {
		return BMPStatsReport{}, fmt.Errorf("stats report per-peer header: %w", err)
	}

	body := data[PerPeerHeaderLen:]
	if len(body) < 4 {
		return BMPStatsReport{}, fmt.Errorf("stats report body too short")
	}

	count := binary.BigEndian.Uint32(body[0:4])
	counters := make(map[uint16]uint64, count)
	offset := 4

	for i := uint32(0); i < count; i++ {
		if offset+4 > len(body) {
			break
		}
		statType := binary.BigEndian.Uint16(body[offset : offset+2])
		statLen := binary.BigEndian.Uint16(body[offset+2 : offset+4])
		offset += 4

		if offset+int(statLen) > len(body) {
			break
		}

		switch statLen {
		case 4:
			counters[statType] = uint64(binary.BigEndian.Uint32(body[offset : offset+4]))
		case 8:
			counters[statType] = binary.BigEndian.Uint64(body[offset : offset+8])
		}
		offset += int(statLen)
	}

	return BMPStatsReport{
		PerPeer:  pph,
		Counters: counters,
	}, nil
}
