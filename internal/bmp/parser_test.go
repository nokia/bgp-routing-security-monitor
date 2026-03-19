package bmp

import (
	"encoding/binary"
	"testing"
)

func TestParseCommonHeader(t *testing.T) {
	// Build a valid BMP common header: version=3, length=42, type=4 (Initiation)
	data := make([]byte, CommonHeaderLen)
	data[0] = 3 // version
	binary.BigEndian.PutUint32(data[1:5], 42) // length
	data[5] = MsgTypeInitiation // type

	hdr, err := ParseCommonHeader(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hdr.Version != 3 {
		t.Errorf("version = %d, want 3", hdr.Version)
	}
	if hdr.Length != 42 {
		t.Errorf("length = %d, want 42", hdr.Length)
	}
	if hdr.MsgType != MsgTypeInitiation {
		t.Errorf("type = %d, want %d", hdr.MsgType, MsgTypeInitiation)
	}
}

func TestParseCommonHeaderBadVersion(t *testing.T) {
	data := make([]byte, CommonHeaderLen)
	data[0] = 2 // wrong version
	binary.BigEndian.PutUint32(data[1:5], 6)
	data[5] = 0

	_, err := ParseCommonHeader(data)
	if err == nil {
		t.Fatal("expected error for bad version, got nil")
	}
}

func TestParseCommonHeaderTooShort(t *testing.T) {
	_, err := ParseCommonHeader([]byte{3, 0})
	if err == nil {
		t.Fatal("expected error for short data, got nil")
	}
}

func TestParseInitiation(t *testing.T) {
	// Build initiation TLVs: sysName="test-router", sysDescr="FRR 9.1"
	sysName := "test-router"
	sysDescr := "FRR 9.1"

	var data []byte

	// TLV: sysName (type 2)
	data = appendTLV(data, InitTLVSysName, sysName)
	// TLV: sysDescr (type 1)
	data = appendTLV(data, InitTLVSysDescr, sysDescr)

	init, err := ParseInitiation(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if init.SysName != sysName {
		t.Errorf("sysName = %q, want %q", init.SysName, sysName)
	}
	if init.SysDescr != sysDescr {
		t.Errorf("sysDescr = %q, want %q", init.SysDescr, sysDescr)
	}
}

func TestParsePerPeerHeader(t *testing.T) {
	data := make([]byte, PerPeerHeaderLen)

	data[0] = PeerTypeGlobal // peer type
	data[1] = 0              // flags: IPv4, pre-policy

	// Peer address: IPv4 192.0.2.1 in last 4 bytes of 16-byte field
	data[22] = 192
	data[23] = 0
	data[24] = 2
	data[25] = 1

	// Peer ASN: 64501
	binary.BigEndian.PutUint32(data[26:30], 64501)

	// BGP ID: 10.0.0.1
	data[30] = 10
	data[31] = 0
	data[32] = 0
	data[33] = 1

	// Timestamp: 1710000000 seconds, 0 microseconds
	binary.BigEndian.PutUint32(data[34:38], 1710000000)
	binary.BigEndian.PutUint32(data[38:42], 0)

	pph, err := ParsePerPeerHeader(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if pph.PeerAddr.String() != "192.0.2.1" {
		t.Errorf("peer addr = %s, want 192.0.2.1", pph.PeerAddr)
	}
	if pph.PeerASN != 64501 {
		t.Errorf("peer ASN = %d, want 64501", pph.PeerASN)
	}
	if pph.PeerBGPID.String() != "10.0.0.1" {
		t.Errorf("BGP ID = %s, want 10.0.0.1", pph.PeerBGPID)
	}
	if pph.IsIPv6() {
		t.Error("expected IPv4 peer, got IPv6")
	}
	if pph.IsPostPolicy() {
		t.Error("expected pre-policy, got post-policy")
	}
}

func TestParseASPath(t *testing.T) {
	// AS_PATH: AS_SEQUENCE [64501, 13335]
	var data []byte
	data = append(data, 2) // AS_SEQUENCE
	data = append(data, 2) // 2 ASNs

	asn1 := make([]byte, 4)
	binary.BigEndian.PutUint32(asn1, 64501)
	data = append(data, asn1...)

	asn2 := make([]byte, 4)
	binary.BigEndian.PutUint32(asn2, 13335)
	data = append(data, asn2...)

	flat, raw := parseASPath(data)

	if len(flat) != 2 {
		t.Fatalf("flat AS_PATH length = %d, want 2", len(flat))
	}
	if flat[0] != 64501 || flat[1] != 13335 {
		t.Errorf("flat = %v, want [64501 13335]", flat)
	}
	if len(raw) != 1 {
		t.Fatalf("raw segments = %d, want 1", len(raw))
	}
	if raw[0].Type != 2 {
		t.Errorf("segment type = %d, want 2 (AS_SEQUENCE)", raw[0].Type)
	}
}

// appendTLV appends a BMP Initiation TLV to the data.
func appendTLV(data []byte, tlvType uint16, val string) []byte {
	t := make([]byte, 2)
	binary.BigEndian.PutUint16(t, tlvType)
	data = append(data, t...)

	l := make([]byte, 2)
	binary.BigEndian.PutUint16(l, uint16(len(val)))
	data = append(data, l...)

	data = append(data, []byte(val)...)
	return data
}
