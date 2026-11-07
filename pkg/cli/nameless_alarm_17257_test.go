package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestPackedNamelessTermAlarmReachesLocalAlarmSurfaces17257(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "nameless.conf"))
	src := `firewall { filter { F term { then discard; } } }`
	if _, err := store.SyncApply(src, nil); err != nil {
		t.Fatalf("tolerant SyncApply: %v", err)
	}
	cfg := store.ActiveConfig()
	alarms := config.NamelessTermAlarmWarnings17257(cfg)
	if len(alarms) != 1 || !strings.Contains(alarms[0], `filter "F"`) {
		t.Fatalf("active nameless alarms = %q, want one marker-derived F alarm", alarms)
	}
	marker := alarms[0]
	cfg.Warnings = nil // show commands must re-derive the alarm from retained markers.
	c := &CLI{store: store}

	system := captureStdout(t, func() {
		if err := c.handleShowSystem([]string{"alarms"}); err != nil {
			t.Fatalf("show system alarms: %v", err)
		}
	})
	if !strings.Contains(system, marker) {
		t.Fatalf("show system alarms omitted marker-derived alarm %q:\n%s", marker, system)
	}

	detail := captureStdout(t, func() {
		if err := c.handleShowSecurity([]string{"alarms", "detail"}); err != nil {
			t.Fatalf("show security alarms detail: %v", err)
		}
	})
	if !strings.Contains(detail, marker) {
		t.Fatalf("show security alarms detail omitted marker-derived alarm %q:\n%s", marker, detail)
	}
	brief := captureStdout(t, func() {
		if err := c.handleShowSecurity([]string{"alarms"}); err != nil {
			t.Fatalf("show security alarms: %v", err)
		}
	})
	if !strings.Contains(brief, "security alarm(s) currently active") ||
		strings.Contains(brief, "No security alarms currently active") {
		t.Fatalf("show security alarms omitted the marker-derived alarm count:\n%s", brief)
	}
}
