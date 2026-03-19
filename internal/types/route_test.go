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
