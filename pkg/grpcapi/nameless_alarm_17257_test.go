package grpcapi

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestPackedNamelessTermAlarmReachesGRPCAlarmSurfaces17257(t *testing.T) {
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
	s := &Server{store: store}

	var system strings.Builder
	s.showAlarms(&system)
	if !strings.Contains(system.String(), marker) {
		t.Fatalf("gRPC show system alarms omitted marker-derived alarm %q:\n%s", marker, system.String())
	}

	var detail strings.Builder
	s.showSecurityAlarms(cfg, "security-alarms-detail", &detail)
	if !strings.Contains(detail.String(), marker) {
		t.Fatalf("gRPC show security alarms detail omitted marker-derived alarm %q:\n%s", marker, detail.String())
	}
	var brief strings.Builder
	s.showSecurityAlarms(cfg, "security-alarms", &brief)
	if !strings.Contains(brief.String(), "security alarm(s) currently active") ||
		strings.Contains(brief.String(), "No security alarms currently active") {
		t.Fatalf("gRPC show security alarms omitted the marker-derived alarm count:\n%s", brief.String())
	}
}
