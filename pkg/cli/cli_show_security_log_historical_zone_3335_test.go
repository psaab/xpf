package cli

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
	"github.com/psaab/xpf/pkg/logging"
)

// #3335: `show security log` must render a historical event's zone names from
// the resolved-at-event-time EventRecord.InZoneName/OutZoneName, NOT recompute
// them from the current config. After a zone rename / delete / ID reuse
// (#3075), an old event whose ID 1 mapped to "trust" must keep printing
// source-zone-name="trust", even though the live config now maps ID 1 to a
// different name.
//
// FAIL-ON-REVERT: restoring `zoneName(id)` (current-map only) renders the
// renamed name "marketing"/"sales" and the assertions below fail.
func TestShowSecurityLogPrefersStoredZoneName(t *testing.T) {
	buf := logging.NewEventBuffer(16)
	buf.Add(logging.EventRecord{
		Type:         "SESSION_OPEN",
		InZone:       1,
		OutZone:      2,
		InZoneName:   "trust",
		OutZoneName:  "untrust",
		IngressIface: "ge-0-0-0",
	})
	c := &CLI{
		eventBuf: buf,
		dp: &applyCLIDP{
			Manager: dataplane.New(),
			// Current config reuses IDs 1/2 for renamed zones.
			apply: &dataplane.ApplyResult{ZoneIDs: map[string]uint32{
				"marketing": 1, "sales": 2,
			}},
		},
	}

	var callErr error
	out := captureStdout(t, func() { callErr = c.showSecurityLog(nil) })
	if callErr != nil {
		t.Fatalf("showSecurityLog = %v; want nil", callErr)
	}
	if !strings.Contains(out, `source-zone-name="trust"`) {
		t.Errorf("output missing source-zone-name=\"trust\" (as-of-event name); got:\n%s", out)
	}
	if !strings.Contains(out, `destination-zone-name="untrust"`) {
		t.Errorf("output missing destination-zone-name=\"untrust\" (as-of-event name); got:\n%s", out)
	}
	if strings.Contains(out, "marketing") || strings.Contains(out, "sales") {
		t.Errorf("output recomputed zone names from current config (found renamed names); got:\n%s", out)
	}
}

// TestShowSecurityLogFallsBackToCurrentMapForLegacyRecord pins the fallback
// half of #3335: a legacy record with no stored names still resolves through
// the current-config map, so the fix does not regress legacy display.
func TestShowSecurityLogFallsBackToCurrentMapForLegacyRecord(t *testing.T) {
	buf := logging.NewEventBuffer(16)
	// No InZoneName/OutZoneName, and no IngressIface (so the in-zone fallback
	// is exercised for the packet-incoming-interface field too).
	buf.Add(logging.EventRecord{Type: "SESSION_OPEN", InZone: 1, OutZone: 2})
	c := &CLI{
		eventBuf: buf,
		dp: &applyCLIDP{
			Manager: dataplane.New(),
			apply: &dataplane.ApplyResult{ZoneIDs: map[string]uint32{
				"trust": 1, "untrust": 2,
			}},
		},
	}

	var callErr error
	out := captureStdout(t, func() { callErr = c.showSecurityLog(nil) })
	if callErr != nil {
		t.Fatalf("showSecurityLog = %v; want nil", callErr)
	}
	if !strings.Contains(out, `source-zone-name="trust"`) {
		t.Errorf("legacy record: output missing current-map source-zone-name=\"trust\"; got:\n%s", out)
	}
	if !strings.Contains(out, `destination-zone-name="untrust"`) {
		t.Errorf("legacy record: output missing current-map destination-zone-name=\"untrust\"; got:\n%s", out)
	}
}
