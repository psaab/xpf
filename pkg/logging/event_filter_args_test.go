package logging

import (
	"strings"
	"testing"
)

// TestParseEventFilterArgs pins the shared `show security log` grammar (#3547)
// — the single source of truth the local CLI and the remote `cli` gRPC text
// path both consume. The unknown/none/0 sentinels select zone 0 (#3338)
// without an apply result; a named zone needs one; parsing fails closed.
func TestParseEventFilterArgs(t *testing.T) {
	zoneIDs := map[string]uint32{"trust": 1, "untrust": 2}

	t.Run("zone-0 sentinels select the unknown zone", func(t *testing.T) {
		for _, s := range []string{"unknown", "none", "0", "UNKNOWN", "None"} {
			n, f, err := ParseEventFilterArgs([]string{"zone", s}, zoneIDs, true)
			if err != nil {
				t.Fatalf("sentinel %q: unexpected error %v", s, err)
			}
			if n != 50 {
				t.Errorf("sentinel %q: count = %d, want default 50", s, n)
			}
			if !f.HasZone || f.Zone != 0 {
				t.Errorf("sentinel %q: filter = %+v, want {Zone:0, HasZone:true}", s, f)
			}
		}
	})

	t.Run("zone-0 sentinel works without an apply result", func(t *testing.T) {
		_, f, err := ParseEventFilterArgs([]string{"zone", "unknown"}, nil, false)
		if err != nil {
			t.Fatalf("unexpected error %v", err)
		}
		if !f.HasZone || f.Zone != 0 {
			t.Errorf("filter = %+v, want {Zone:0, HasZone:true}", f)
		}
	})

	t.Run("named zone resolves through the apply result", func(t *testing.T) {
		_, f, err := ParseEventFilterArgs([]string{"zone", "untrust"}, zoneIDs, true)
		if err != nil {
			t.Fatalf("unexpected error %v", err)
		}
		if !f.HasZone || f.Zone != 2 {
			t.Errorf("filter = %+v, want {Zone:2, HasZone:true}", f)
		}
	})

	t.Run("count plus protocol plus action", func(t *testing.T) {
		n, f, err := ParseEventFilterArgs([]string{"5", "protocol", "tcp", "action", "permit"}, zoneIDs, true)
		if err != nil {
			t.Fatalf("unexpected error %v", err)
		}
		if n != 5 || f.Protocol != "tcp" || f.ProtocolNum != 6 || !f.HasProtocol || f.Action != "permit" || f.HasZone {
			t.Errorf("got n=%d filter=%+v; want n=5 protocol=tcp/6 action=permit no-zone", n, f)
		}
	})

	failClosed := []struct {
		name      string
		args      []string
		haveApply bool
		wantErr   string
	}{
		{"unknown token", []string{"zon", "trust"}, true, "unknown argument"},
		{"missing zone value", []string{"zone"}, true, "missing value"},
		{"missing protocol value", []string{"protocol"}, true, "missing value"},
		{"missing action value", []string{"action"}, true, "missing value"},
		{"unknown named zone", []string{"zone", "nope"}, true, "not found"},
		{"named zone without apply result", []string{"zone", "trust"}, false, "apply result"},
		{"non-positive count", []string{"0"}, true, "positive integer"},
		{"negative count", []string{"-3"}, true, "positive integer"},
	}
	for _, tc := range failClosed {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := ParseEventFilterArgs(tc.args, zoneIDs, tc.haveApply)
			if err == nil {
				t.Fatalf("args %v: got nil error, want one containing %q", tc.args, tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("args %v: error = %q, want substring %q", tc.args, err.Error(), tc.wantErr)
			}
		})
	}
}
