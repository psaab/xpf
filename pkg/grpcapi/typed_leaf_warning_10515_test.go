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
	// not unrelated compiler advisories stored on the config. Exercise the
	// latter through a real lenient compiler warning instead of mutating the
	// already-published active snapshot.
	ordinaryStore := newConfigStore(t, filepath.Join(t.TempDir(), "ordinary.conf"))
	ordinaryCfg, err := ordinaryStore.SyncApply(
		"system host-name "+strings.Repeat("x", 256)+";", nil)
	if err != nil {
		t.Fatalf("ordinary-warning SyncApply: %v", err)
	}
	if len(ordinaryCfg.Warnings) == 0 {
		t.Fatal("ordinary-warning fixture produced no compiler advisory")
	}
	if got := config.ToleratedTypedLeafWarnings(ordinaryCfg); len(got) != 0 {
		t.Fatalf("ordinary compiler advisory was classified as typed-leaf: %v", got)
	}
	ordinaryServer := &Server{store: ordinaryStore}
	var ordinarySystem strings.Builder
	ordinaryServer.showAlarms(&ordinarySystem)
	var ordinarySecurity strings.Builder
	ordinaryServer.showSecurityAlarms(ordinaryCfg, "security-alarms-detail", &ordinarySecurity)
	for _, warning := range ordinaryCfg.Warnings {
		if strings.Contains(ordinarySystem.String(), warning) ||
			strings.Contains(ordinarySecurity.String(), warning) {
			t.Fatalf("alarm surfaces promoted an ordinary compiler warning %q:\n%s\n%s",
				warning, ordinarySystem.String(), ordinarySecurity.String())
		}
	}
}

const secretTypedLeafAlarm10515 = `system {
    root-authentication {
        encrypted-password "typed-leaf-secret-10515";
    }
}`

func TestTypedLeafSecretWarningRedactsGRPCAlarmSurfaces10515(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "secret.conf"))
	if _, err := store.SyncApply(secretTypedLeafAlarm10515, nil); err != nil {
		t.Fatalf("Store.SyncApply: %v", err)
	}
	cfg := store.ActiveConfig()
	warnings := config.ToleratedTypedLeafWarnings(cfg)
	if len(warnings) != 1 {
		t.Fatalf("secret typed-leaf warnings = %v, want one marker", warnings)
	}
	marker := warnings[0]
	if !strings.Contains(marker, "<redacted>") {
		t.Fatalf("secret typed-leaf marker lacks redaction: %q", marker)
	}
	if strings.Contains(marker, "typed-leaf-secret-10515") {
		t.Fatalf("secret typed-leaf marker leaked plaintext: %q", marker)
	}

	s := &Server{store: store}
	var system strings.Builder
	s.showAlarms(&system)
	var securityDetail strings.Builder
	s.showSecurityAlarms(cfg, "security-alarms-detail", &securityDetail)
	for name, output := range map[string]string{
		"gRPC system alarms":          system.String(),
		"gRPC security alarms detail": securityDetail.String(),
	} {
		if !strings.Contains(output, "<redacted>") {
			t.Fatalf("%s omitted redacted secret warning %q:\n%s", name, marker, output)
		}
		if strings.Contains(output, "typed-leaf-secret-10515") {
			t.Fatalf("%s leaked secret plaintext:\n%s", name, output)
		}
	}
}
