package types

import "testing"

func TestComputePosture(t *testing.T) {
	tests := []struct {
		rov  ROVState
		aspa ASPAState
		want SecurityPosture
	}{
		{ROVValid, ASPAValid, PostureSecured},
		{ROVValid, ASPAUnknown, PostureOriginOnly},
		{ROVValid, ASPAUnverifiable, PostureOriginOnly},
		{ROVValid, ASPAInvalid, PosturePathSuspect},
		{ROVNotFound, ASPAValid, PosturePathOnly},
		{ROVNotFound, ASPAUnknown, PostureUnverified},
		{ROVNotFound, ASPAUnverifiable, PostureUnverified},
		{ROVNotFound, ASPAInvalid, PosturePathSuspect},
		{ROVInvalid, ASPAValid, PostureOriginInvalid},
		{ROVInvalid, ASPAInvalid, PostureOriginInvalid},
		{ROVInvalid, ASPAUnknown, PostureOriginInvalid},
	}
	for _, tt := range tests {
		got := ComputePosture(tt.rov, tt.aspa)
		if got != tt.want {
			t.Errorf("ComputePosture(%v, %v) = %v, want %v",
				tt.rov, tt.aspa, got, tt.want)
		}
	}
}

func TestRIBTypeString(t *testing.T) {
	for rib, want := range map[RIBType]string{
		AdjRIBInPre:  "pre-policy",
		AdjRIBInPost: "post-policy",
		LocRIB:       "loc-rib",
	} {
		if got := rib.String(); got != want {
			t.Errorf("RIBType(%d).String() = %q, want %q", rib, got, want)
		}
	}
}

func TestParseRIBType(t *testing.T) {
	for _, rib := range RIBTypes {
		if got, err := ParseRIBType(rib.String()); err != nil || got != rib {
			t.Errorf("ParseRIBType(%q) = %v, %v, want %v", rib.String(), got, err, rib)
		}
	}
	if _, err := ParseRIBType("adj-rib-out"); err == nil {
		t.Error("ParseRIBType accepted an unknown RIB type")
	}
}

func TestPeerDistinguisherString(t *testing.T) {
	for v, want := range map[uint64]string{
		0:                          "",
		64500<<32 | 100:            "64500:100",
		1<<48 | 0xc0000201<<16 | 7: "192.0.2.1:7",
		2<<48 | 4200000000<<16 | 9: "4200000000L:9",
		65000<<32 | 1:              "65000:1",
		2<<48 | 65000<<16 | 1:      "65000L:1",
		3<<48 | 1:                  "0x0003000000000001",
	} {
		d := PeerDistinguisherFromUint64(v)
		if got := d.String(); got != want {
			t.Errorf("PeerDistinguisher(%#x).String() = %q, want %q", v, got, want)
		}
		if d.Uint64() != v {
			t.Errorf("PeerDistinguisher(%#x).Uint64() = %#x", v, d.Uint64())
		}
	}
}
