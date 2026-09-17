package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/clockskew"
	"github.com/psaab/xpf/pkg/cluster"
)

// TestShowSystemAlarmsListsClockSkew10025: the local `show system alarms`
// lists an active fabric-clock-skew alarm as CRITICAL with its summary,
// counted in the aggregate. Mirrors alarms_config_divergence_9530_test.go.
func TestShowSystemAlarmsListsClockSkew10025(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := store.SetFromInput("system host-name skewtest"); err != nil {
		t.Fatalf("SetFromInput: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	c := &CLI{store: store}
	c.SetClockSkewAlarmsFn(func() []clockskew.ActiveAlarm {
		return []clockskew.ActiveAlarm{{Kind: clockskew.KindOffset, OffsetSecs: 20.5}}
	})
	var runErr error
	out := captureStdout(t, func() { runErr = c.handleShowSystem([]string{"alarms"}) })
	if runErr != nil {
		t.Fatalf("show system alarms: %v", runErr)
	}
	if !strings.Contains(out, "1 active alarm(s):") {
		t.Errorf("skew alarm must be counted in the aggregate:\n%s", out)
	}
	if !strings.Contains(out, "CRITICAL: node clock is 20.5s ahead of its NTP reference") {
		t.Errorf("skew alarm must render as CRITICAL with its summary:\n%s", out)
	}
}

// TestShowSecurityAlarmsListsClockSkew10025 exercises the console
// `show security alarms detail` renderer, which has a separate path from
// `show system alarms`.
func TestShowSecurityAlarmsListsClockSkew10025(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := store.SetFromInput("system host-name skewtest"); err != nil {
		t.Fatalf("SetFromInput: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	c := &CLI{store: store}
	c.SetClockSkewAlarmsFn(func() []clockskew.ActiveAlarm {
		return []clockskew.ActiveAlarm{{Kind: clockskew.KindOffset, OffsetSecs: 20.5}}
	})
	var runErr error
	out := captureStdout(t, func() {
		runErr = c.showSecurityAlarms([]string{"detail"})
	})
	if runErr != nil {
		t.Fatalf("show security alarms detail: %v", runErr)
	}
	for _, want := range []string{
		"Alarm 1:",
		"Class: System",
		"Severity: Critical",
		"Description: node clock is 20.5s ahead of its NTP reference",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("console show security alarms lacks %q:\n%s", want, out)
		}
	}
}

// TestShowChassisClusterStatusListsClockSkew10025 exercises the console
// cluster-status path, separate from gRPC's renderer.
func TestShowChassisClusterStatusListsClockSkew10025(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	for _, line := range []string{
		"system host-name skewtest",
		"chassis cluster cluster-id 1",
		"chassis cluster authentication-key test-only-clockskew-01",
	} {
		if err := store.SetFromInput(line); err != nil {
			t.Fatalf("SetFromInput(%q): %v", line, err)
		}
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	c := &CLI{store: store, cluster: cluster.NewManager(0, 1)}
	c.SetClockSkewAlarmsFn(func() []clockskew.ActiveAlarm {
		return []clockskew.ActiveAlarm{{Kind: clockskew.KindNoSource}}
	})
	var runErr error
	out := captureStdout(t, func() {
		runErr = c.showChassisClusterStatus()
	})
	if runErr != nil {
		t.Fatalf("show chassis cluster status: %v", runErr)
	}
	if !strings.Contains(out, "Warning: cluster clock has no `system ntp server` time source") {
		t.Fatalf("console cluster status lacks the clock warning:\n%s", out)
	}
}

// TestShowSystemAlarmsSilentWithoutSkew10025: with no monitor wired (nil fn)
// or no active alarm, the alarms output is byte-identical to before —
// no skew text, no count inflation.
func TestShowSystemAlarmsSilentWithoutSkew10025(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := store.SetFromInput("system host-name skewtest"); err != nil {
		t.Fatalf("SetFromInput: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	for _, tc := range []struct {
		name string
		fn   func() []clockskew.ActiveAlarm
	}{
		{"nil fn (no monitor wired)", nil},
		{"empty (monitor healthy)", func() []clockskew.ActiveAlarm { return nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := &CLI{store: store}
			if tc.fn != nil {
				c.SetClockSkewAlarmsFn(tc.fn)
			}
			var runErr error
			out := captureStdout(t, func() { runErr = c.handleShowSystem([]string{"alarms"}) })
			if runErr != nil {
				t.Fatalf("show system alarms: %v", runErr)
			}
			if strings.Contains(out, "NTP reference") || strings.Contains(out, "system ntp server") {
				t.Errorf("healthy/unwired path must not mention clock skew:\n%s", out)
			}
		})
	}
}

// TestShowSystemAlarmsListsClockSkewWithoutConfig10025 keeps a daemon-resident
// alarm visible during bootstrap/rollback, when the active config is nil.
func TestShowSystemAlarmsListsClockSkewWithoutConfig10025(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	c := &CLI{store: store}
	c.SetClockSkewAlarmsFn(func() []clockskew.ActiveAlarm {
		return []clockskew.ActiveAlarm{{Kind: clockskew.KindUnsynced}}
	})
	var runErr error
	out := captureStdout(t, func() {
		runErr = c.handleShowSystem([]string{"alarms"})
	})
	if runErr != nil {
		t.Fatalf("show system alarms: %v", runErr)
	}
	for _, want := range []string{
		"1 active alarm(s):",
		"CRITICAL: node clock is not synchronized to its NTP reference",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("clock alarm must remain visible without active config; missing %q:\n%s", want, out)
		}
	}
}
