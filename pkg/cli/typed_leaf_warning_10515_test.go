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
	ordinaryCLI := &CLI{store: ordinaryStore}
	ordinarySystem := captureStdout(t, func() {
		if err := ordinaryCLI.handleShowSystem([]string{"alarms"}); err != nil {
			t.Fatalf("show system alarms with ordinary warning: %v", err)
		}
	})
	ordinarySecurity := captureStdout(t, func() {
		if err := ordinaryCLI.handleShowSecurity([]string{"alarms", "detail"}); err != nil {
			t.Fatalf("show security alarms detail with ordinary warning: %v", err)
		}
	})
	for _, warning := range ordinaryCfg.Warnings {
		if strings.Contains(ordinarySystem, warning) || strings.Contains(ordinarySecurity, warning) {
			t.Fatalf("alarm surfaces promoted an ordinary compiler warning %q:\n%s\n%s",
				warning, ordinarySystem, ordinarySecurity)
		}
	}
}

const secretTypedLeafAlarm10515 = `system {
    root-authentication {
        encrypted-password "typed-leaf-secret-10515";
    }
}`

func TestTypedLeafSecretWarningRedactsLocalAlarmSurfaces10515(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "secret.conf"))
	if _, err := store.SyncApply(secretTypedLeafAlarm10515, nil); err != nil {
		t.Fatalf("Store.SyncApply: %v", err)
	}
	cfg := store.ActiveConfig()
	for _, warning := range cfg.Warnings {
		if strings.Contains(warning, "typed-leaf-secret-10515") {
			t.Fatalf("cfg.Warnings leaked secret plaintext: %q", warning)
		}
	}
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

	c := &CLI{store: store}
	system := captureStdout(t, func() {
		if err := c.handleShowSystem([]string{"alarms"}); err != nil {
			t.Fatalf("show system alarms with secret warning: %v", err)
		}
	})
	securityDetail := captureStdout(t, func() {
		if err := c.handleShowSecurity([]string{"alarms", "detail"}); err != nil {
			t.Fatalf("show security alarms detail with secret warning: %v", err)
		}
	})
	for name, output := range map[string]string{
		"local system alarms":          system,
		"local security alarms detail": securityDetail,
	} {
		if !strings.Contains(output, "<redacted>") {
			t.Fatalf("%s omitted redacted secret warning %q:\n%s", name, marker, output)
		}
		if strings.Contains(output, "typed-leaf-secret-10515") {
			t.Fatalf("%s leaked secret plaintext:\n%s", name, output)
		}
	}
}
