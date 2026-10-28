package cli

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// sentinelCLI17193DP drives the real LegacyDataPlaneAdapter sentinel for
// the four #13274 unsourced indexes and healthy values elsewhere.
type sentinelCLI17193DP struct {
	dataplane.DataPlane
	adapter *dpuserspace.LegacyDataPlaneAdapter
}

func (d *sentinelCLI17193DP) IsLoaded() bool           { return true }
func (d *sentinelCLI17193DP) SessionCount() (int, int) { return 7, 5 }
func (d *sentinelCLI17193DP) ReadGlobalCounter(idx uint32) (uint64, error) {
	switch idx {
	case dataplane.GlobalCtrFlowCacheFlush, dataplane.GlobalCtrFlowCacheInvalidate,
		dataplane.GlobalCtrTCEgressPackets, dataplane.GlobalCtrFabricRedirect:
		return d.adapter.ReadGlobalCounter(idx)
	default:
		return uint64(idx) + 1, nil
	}
}

func newSentinelCLI17193() *CLI {
	adapter := dpuserspace.NewLegacyDataPlaneAdapter(dpuserspace.New())
	return &CLI{dp: &sentinelCLI17193DP{adapter: adapter}}
}

// TestShowStatisticsUnavailableNotZero17193: `show security statistics`
// must print "unavailable" for TC egress, never a fabricated 0, and must
// not cry "read failed" for known-unsourced counters (#17193).
//
// FAIL-ON-REVERT: restoring the first-error closure in showStatistics
// prints "TC egress packets: 0" plus the warning and both assertions RED.
func TestShowStatisticsUnavailableNotZero17193(t *testing.T) {
	c := newSentinelCLI17193()
	out := captureStdout(t, func() {
		if err := c.showStatistics(false); err != nil {
			t.Fatalf("showStatistics: %v", err)
		}
	})
	if !strings.Contains(out, "TC egress packets:") || !strings.Contains(out, "unavailable") {
		t.Errorf("TC egress must render unavailable:\n%s", out)
	}
	if strings.Contains(out, "read failed") {
		t.Errorf("false read-failed warning on unavailable counters:\n%s", out)
	}
}

// TestShowFlowStatisticsUnavailableNotZero17193 covers the second pkg/cli
// loop (`show security flow statistics`): TC egress and fabric redirects
// unavailable, flush/invalidate unavailable in the flow-cache section, no
// fabricated zeros, no false warning.
func TestShowFlowStatisticsUnavailableNotZero17193(t *testing.T) {
	c := newSentinelCLI17193()
	out := captureStdout(t, func() {
		if err := c.showFlowStatistics(); err != nil {
			t.Fatalf("showFlowStatistics: %v", err)
		}
	})
	for _, label := range []string{"TC egress packets:", "Fabric redirects:", "Flow cache flushes:", "Flow cache invalidations:"} {
		found := false
		for _, line := range strings.Split(out, "\n") {
			if strings.Contains(line, label) {
				found = true
				if !strings.Contains(line, "unavailable") {
					t.Errorf("%s must render unavailable, got line %q\nfull:\n%s", label, line, out)
				}
			}
		}
		if !found {
			t.Errorf("missing %s line:\n%s", label, out)
		}
	}
	if strings.Contains(out, "read failed") {
		t.Errorf("false read-failed warning on unavailable counters:\n%s", out)
	}
}
