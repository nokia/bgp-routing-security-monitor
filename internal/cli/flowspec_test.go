package cli

import (
	"strings"
	"testing"
)

func TestDryRunLabel(t *testing.T) {
	yes := dryRunLabel(true)
	if !strings.Contains(yes, "yes") {
		t.Errorf("dryRunLabel(true): want %q, got %q", "yes", yes)
	}
	if strings.Contains(yes, "LIVE") {
		t.Errorf("dryRunLabel(true) must not display LIVE; got %q", yes)
	}

	live := dryRunLabel(false)
	if !strings.Contains(live, "LIVE") {
		t.Errorf("dryRunLabel(false): want %q, got %q", "LIVE", live)
	}
	if strings.Contains(live, "yes") {
		t.Errorf("dryRunLabel(false) must not display yes; got %q", live)
	}
}
