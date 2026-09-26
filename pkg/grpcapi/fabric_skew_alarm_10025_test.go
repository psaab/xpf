package grpcapi

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/clockskew"
)

// TestClockSkewAlarmBound10025 pins the documented bound against the fabric
// auth window it cites, so the two cannot drift apart silently:
//
//   - The verifier accepts the current 30s window ±1. |skew| <= 30s always
//     verifies (windows differ by at most 1); |skew| >= 60s always rejects
//     (windows differ by at least 2); 30-60s is alignment-dependent.
//   - The 15s per-node alarm threshold gives the guarantee: both nodes within
//     15s of the same reference => inter-node skew <= 30s => always verifies.
//     Margin: 2x under the minimum break (>30s), 4x under guaranteed break.
func TestClockSkewAlarmBound10025(t *testing.T) {
	if clockskew.AuthWindowSecs != fabricAuthWindowSeconds {
		t.Fatalf("clockskew.AuthWindowSecs = %d, want fabricAuthWindowSeconds = %d; the bound cites this window",
			clockskew.AuthWindowSecs, fabricAuthWindowSeconds)
	}
	if clockskew.RaiseAtSecs*2 != float64(fabricAuthWindowSeconds) {
		t.Fatalf("2*RaiseAtSecs = %g, want one auth window (%d): both nodes under the alarm must imply inter-node skew within the always-verifies band",
			clockskew.RaiseAtSecs*2, fabricAuthWindowSeconds)
	}
	if clockskew.AuthBreakSkewSecs != 2*fabricAuthWindowSeconds {
		t.Fatalf("AuthBreakSkewSecs = %d, want 2 windows (%d): the guaranteed-break bound",
			clockskew.AuthBreakSkewSecs, 2*fabricAuthWindowSeconds)
	}
}

// TestAppendClockSkewAlarm10025: `show chassis cluster status` carries the
// pre-break alarm as a Warning line next to the #6708 post-break diagnosis,
// and stays byte-identical when no alarm is active.
func TestAppendClockSkewAlarm10025(t *testing.T) {
	t.Run("nil fn appends nothing", func(t *testing.T) {
		s := &Server{}
		var buf strings.Builder
		s.appendClockSkewAlarm(&buf)
		if buf.String() != "" {
			t.Fatalf("status appended %q with no monitor wired; every healthy cluster would carry a warning", buf.String())
		}
	})
	t.Run("empty appends nothing", func(t *testing.T) {
		s := &Server{clockSkewAlarmsFn: func() []clockskew.ActiveAlarm { return nil }}
		var buf strings.Builder
		s.appendClockSkewAlarm(&buf)
		if buf.String() != "" {
			t.Fatalf("status appended %q with no active alarm", buf.String())
		}
	})
	t.Run("active alarm warns", func(t *testing.T) {
		s := &Server{clockSkewAlarmsFn: func() []clockskew.ActiveAlarm {
			return []clockskew.ActiveAlarm{{Kind: clockskew.KindOffset, OffsetSecs: -45}}
		}}
		var buf strings.Builder
		s.appendClockSkewAlarm(&buf)
		out := buf.String()
		for _, want := range []string{"Warning:", "45s behind its NTP reference", "NTP"} {
			if !strings.Contains(out, want) {
				t.Errorf("status lacks %q:\n%s", want, out)
			}
		}
	})
	t.Run("no-source alarm warns", func(t *testing.T) {
		s := &Server{clockSkewAlarmsFn: func() []clockskew.ActiveAlarm {
			return []clockskew.ActiveAlarm{{Kind: clockskew.KindNoSource}}
		}}
		var buf strings.Builder
		s.appendClockSkewAlarm(&buf)
		if out := buf.String(); !strings.Contains(out, "no `system ntp server`") {
			t.Errorf("status lacks the no-source alarm:\n%s", out)
		}
	})
}

// TestShowSystemAlarmsListsClockSkew10025 exercises the remote gRPC
// `show system alarms` renderer, not only the shared callback binding.
func TestShowSystemAlarmsListsClockSkew10025(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	s := &Server{
		store: store,
		clockSkewAlarmsFn: func() []clockskew.ActiveAlarm {
			return []clockskew.ActiveAlarm{{Kind: clockskew.KindOffset, OffsetSecs: 20.5}}
		},
	}
	var buf strings.Builder
	s.showAlarms(&buf)
	out := buf.String()
	for _, want := range []string{
		"1 active alarm(s):",
		"CRITICAL: node clock is 20.5s ahead of its NTP reference",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("remote show system alarms lacks %q:\n%s", want, out)
		}
	}
}

// TestShowSecurityAlarmsListsClockSkew10025 exercises the remote gRPC
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
	s := &Server{
		store: store,
		clockSkewAlarmsFn: func() []clockskew.ActiveAlarm {
			return []clockskew.ActiveAlarm{{Kind: clockskew.KindOffset, OffsetSecs: 20.5}}
		},
	}
	var buf strings.Builder
	s.showSecurityAlarms(store.ActiveConfig(), "security-alarms-detail", &buf)
	out := buf.String()
	for _, want := range []string{
		"Alarm 1:",
		"Class: System",
		"Severity: Critical",
		"Description: node clock is 20.5s ahead of its NTP reference",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("remote show security alarms lacks %q:\n%s", want, out)
		}
	}
}

// TestClockSkewAlarmWiring10025 pins by source that the status renderer calls
// the alarm appender and that the server binds the daemon's hook: no test
// crosses those lines, so a deletion would otherwise stay green (#9452).
func TestClockSkewAlarmWiring10025(t *testing.T) {
	read := func(path string) string {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		return strings.Join(strings.Fields(string(b)), " ")
	}
	if src := read("server_show_cluster_text.go"); !strings.Contains(src, "s.appendClockSkewAlarm(buf)") {
		t.Error("showChassisClusterStatus must call appendClockSkewAlarm")
	}
	if src := read("server.go"); !strings.Contains(src, "clockSkewAlarmsFn: cfg.ClockSkewAlarmsFn,") {
		t.Error("NewServer must bind cfg.ClockSkewAlarmsFn")
	}
}
