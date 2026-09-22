package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

const toleratedTypedLeafAlarm10515 = `class-of-service {
    schedulers be transmit-rate asd;
}`

func TestTypedLeafWarningReachesLocalAlarmSurfaces10515(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if _, err := store.SyncApply(toleratedTypedLeafAlarm10515, nil); err != nil {
		t.Fatalf("Store.SyncApply: %v", err)
	}
	cfg := store.ActiveConfig()
	warnings := config.ToleratedTypedLeafWarnings(cfg)
	if len(warnings) != 1 {
		t.Fatalf("active typed-leaf warnings = %v, want one marker", warnings)
	}
	marker := warnings[0]

	c := &CLI{store: store}
	system := captureStdout(t, func() {
		if err := c.handleShowSystem([]string{"alarms"}); err != nil {
			t.Fatalf("show system alarms: %v", err)
		}
	})
	if !strings.Contains(system, marker) {
		t.Fatalf("show system alarms omitted persisted typed-leaf warning %q:\n%s", marker, system)
	}
	if !strings.Contains(system, "1 active alarm(s):") {
		t.Fatalf("show system alarms count does not include typed-leaf warning:\n%s", system)
	}

	securityDetail := captureStdout(t, func() {
		if err := c.handleShowSecurity([]string{"alarms", "detail"}); err != nil {
			t.Fatalf("show security alarms detail: %v", err)
		}
	})
	if !strings.Contains(securityDetail, marker) {
		t.Fatalf("show security alarms detail omitted persisted typed-leaf warning %q:\n%s", marker, securityDetail)
	}

	securityBrief := captureStdout(t, func() {
		if err := c.handleShowSecurity([]string{"alarms"}); err != nil {
			t.Fatalf("show security alarms: %v", err)
		}
	})
	if strings.Contains(securityBrief, marker) {
		t.Fatalf("non-detail security alarms leaked detail text:\n%s", securityBrief)
	}
	if !strings.Contains(securityBrief, "1 security alarm(s) currently active") {
		t.Fatalf("non-detail security alarms omitted typed-leaf count:\n%s", securityBrief)
	}

	// Alarm surfaces intentionally expose only the dedicated tolerant marker,
	// not unrelated compiler advisories stored on the config.
	cfg.Warnings = []string{"ordinary compiler advisory"}
	ordinarySystem := captureStdout(t, func() {
		if err := c.handleShowSystem([]string{"alarms"}); err != nil {
			t.Fatalf("show system alarms with ordinary warning: %v", err)
		}
	})
	if strings.Contains(ordinarySystem, "ordinary compiler advisory") {
		t.Fatalf("show system alarms promoted an ordinary compiler warning:\n%s", ordinarySystem)
	}
	ordinarySecurity := captureStdout(t, func() {
		if err := c.handleShowSecurity([]string{"alarms", "detail"}); err != nil {
			t.Fatalf("show security alarms detail with ordinary warning: %v", err)
		}
	})
	if strings.Contains(ordinarySecurity, "ordinary compiler advisory") {
		t.Fatalf("show security alarms promoted an ordinary compiler warning:\n%s", ordinarySecurity)
	}
}
