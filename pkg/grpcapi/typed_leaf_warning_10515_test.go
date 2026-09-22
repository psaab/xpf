package grpcapi

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

const toleratedTypedLeafAlarm10515 = `class-of-service {
    schedulers be transmit-rate asd;
}`

func TestTypedLeafWarningReachesGRPCAlarmSurfaces10515(t *testing.T) {
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

	s := &Server{store: store}
	var system strings.Builder
	s.showAlarms(&system)
	if !strings.Contains(system.String(), marker) {
		t.Fatalf("gRPC show system alarms omitted persisted typed-leaf warning %q:\n%s", marker, system.String())
	}
	if !strings.Contains(system.String(), "1 active alarm(s):") {
		t.Fatalf("gRPC show system alarms count does not include typed-leaf warning:\n%s", system.String())
	}

	var securityDetail strings.Builder
	s.showSecurityAlarms(cfg, "security-alarms-detail", &securityDetail)
	if !strings.Contains(securityDetail.String(), marker) {
		t.Fatalf("gRPC show security alarms detail omitted persisted typed-leaf warning %q:\n%s", marker, securityDetail.String())
	}

	var securityBrief strings.Builder
	s.showSecurityAlarms(cfg, "security-alarms", &securityBrief)
	if strings.Contains(securityBrief.String(), marker) {
		t.Fatalf("gRPC non-detail security alarms leaked detail text:\n%s", securityBrief.String())
	}
	if !strings.Contains(securityBrief.String(), "1 security alarm(s) currently active") {
		t.Fatalf("gRPC non-detail security alarms omitted typed-leaf count:\n%s", securityBrief.String())
	}

	// Alarm surfaces intentionally expose only the dedicated tolerant marker,
	// not unrelated compiler advisories stored on the config.
	cfg.Warnings = []string{"ordinary compiler advisory"}
	var ordinarySystem strings.Builder
	s.showAlarms(&ordinarySystem)
	if strings.Contains(ordinarySystem.String(), "ordinary compiler advisory") {
		t.Fatalf("gRPC show system alarms promoted an ordinary compiler warning:\n%s", ordinarySystem.String())
	}
	var ordinarySecurity strings.Builder
	s.showSecurityAlarms(cfg, "security-alarms-detail", &ordinarySecurity)
	if strings.Contains(ordinarySecurity.String(), "ordinary compiler advisory") {
		t.Fatalf("gRPC show security alarms promoted an ordinary compiler warning:\n%s", ordinarySecurity.String())
	}
}
