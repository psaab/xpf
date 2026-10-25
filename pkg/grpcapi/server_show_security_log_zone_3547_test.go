package grpcapi

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
	"github.com/psaab/xpf/pkg/logging"
)

// zoneApplyGRPCDP exposes a fixed ZoneIDs map so the security-log text
// renderer can resolve a named zone filter (zone <name> -> ID).
type zoneApplyGRPCDP struct {
	*dataplane.Manager
	result *dataplane.ApplyResult
}

func (d *zoneApplyGRPCDP) IsLoaded() bool { return true }

func (d *zoneApplyGRPCDP) LastApplyResult() *dataplane.ApplyResult {
	return d.result.Clone()
}

// TestShowSecurityLogZoneFilterRemotePath pins the #3547 fix on the remote
// `cli` text path (the ShowText "security-log" topic). Before #3547 the
// server-side renderer treated the filter string as a bare count and dropped
// any zone/protocol/action selector, so `show security log zone <name>` on
// the remote client silently dumped every event instead of isolating the
// requested zone — including the unknown/none/0 zone-0 selector (#3338).
//
// FAIL-ON-REVERT: reverting showSecurityLog to Latest(n) (ignoring the
// filter) makes every subtest below render all three events, so the
// "must NOT contain" assertions fail.
func TestShowSecurityLogZoneFilterRemotePath(t *testing.T) {
	eb := logging.NewEventBuffer(16)
	// Distinct SrcAddr per zone so the rendered "src -> dst" line is an
	// unambiguous presence marker. Zone 0 is the unknown/unassigned zone.
	eb.Add(logging.EventRecord{Type: "POLICY_DENY", SrcAddr: "z0", DstAddr: "d", Protocol: "tcp", InZone: 0, OutZone: 0})
	eb.Add(logging.EventRecord{Type: "SESSION_OPEN", SrcAddr: "z1", DstAddr: "d", Protocol: "tcp", InZone: 1, OutZone: 2})
	eb.Add(logging.EventRecord{Type: "SESSION_OPEN", SrcAddr: "z2", DstAddr: "d", Protocol: "udp", InZone: 2, OutZone: 1})

	dp := &zoneApplyGRPCDP{result: &dataplane.ApplyResult{
		ZoneIDs: map[string]uint32{"trust": 1, "untrust": 2},
	}}
	s := &Server{eventBuf: eb, dp: dp}

	render := func(filter string) string {
		var buf strings.Builder
		s.showSecurityLog(filter, &buf)
		return buf.String()
	}

	// Unknown-zone (zone 0) selector — only the z0 event.
	for _, sentinel := range []string{"zone unknown", "zone none", "zone 0"} {
		out := render(sentinel)
		if !strings.Contains(out, "z0") {
			t.Errorf("%q output missing the zone-0 event:\n%s", sentinel, out)
		}
		if strings.Contains(out, "z1") || strings.Contains(out, "z2") {
			t.Errorf("%q leaked non-zone-0 events (silent show-all regression):\n%s", sentinel, out)
		}
	}

	// Control: a VALID named zone filter still returns exactly that zone's
	// events. zone trust (ID 1) appears as ingress on z1 and egress on z2.
	out := render("zone trust")
	if !strings.Contains(out, "z1") || !strings.Contains(out, "z2") {
		t.Errorf("zone trust output missing a zone-1 (trust) event:\n%s", out)
	}
	if strings.Contains(out, "z0") {
		t.Errorf("zone trust leaked the zone-0 event:\n%s", out)
	}

	// Control: protocol filter still narrows.
	out = render("protocol udp")
	if !strings.Contains(out, "z2") {
		t.Errorf("protocol udp output missing the udp event:\n%s", out)
	}
	if strings.Contains(out, "z0") || strings.Contains(out, "z1") {
		t.Errorf("protocol udp leaked tcp events:\n%s", out)
	}

	// Control: unfiltered query still includes every event, zone 0 included.
	out = render("")
	for _, want := range []string{"z0", "z1", "z2"} {
		if !strings.Contains(out, want) {
			t.Errorf("unfiltered output missing %q:\n%s", want, out)
		}
	}

	// Fail-closed: an unknown named zone is a clear message, not show-all.
	out = render("zone bogus")
	if !strings.Contains(out, "not found") {
		t.Errorf("unknown zone should report a clear message, got:\n%s", out)
	}
	if strings.Contains(out, "z0") || strings.Contains(out, "z1") || strings.Contains(out, "z2") {
		t.Errorf("unknown zone must not dump events (silent show-all):\n%s", out)
	}

	// Fail-closed: an unknown token is rejected, not silently ignored.
	out = render("zon trust")
	if !strings.Contains(out, "unknown argument") {
		t.Errorf("unknown token should be rejected, got:\n%s", out)
	}
}
