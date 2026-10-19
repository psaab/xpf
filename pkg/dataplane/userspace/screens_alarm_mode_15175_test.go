package userspace

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #15175 (B18-04): ScreenAlarmModeLine is the shared operator-facing mode
// line for the profile-wide alarm-without-drop modifier. Before the fix no
// show renderer read AlarmWithoutDrop, so a profile whose every check is
// log-only rendered identically to a drop-enforcing one.
//
// RED on base: this file does not build (ScreenAlarmModeLine /
// ScreenAlarmModeLine undefined). After the fix the two arms differ and the
// non-audit arm stays silent.
func alarmModeCfg15175(audit bool) *config.Config {
	return &config.Config{Security: config.SecurityConfig{
		Screen: map[string]*config.ScreenProfile{
			"p": {Name: "p", AlarmWithoutDrop: audit,
				TCP: config.TCPScreen{Land: true}},
		},
		Zones: map[string]*config.ZoneConfig{
			"untrust": {Name: "untrust", ScreenProfile: "p"},
		},
	}}
}

func TestScreenAlarmModeLines15175(t *testing.T) {
	audit, drop := alarmModeCfg15175(true), alarmModeCfg15175(false)
	if got := ScreenAlarmModeLine(audit.Security.Screen["p"]); !strings.Contains(got, "Mode: alarm-without-drop") ||
		!strings.Contains(got, "nothing is dropped") {
		t.Fatalf("audit profile must render the alarm-without-drop mode line, got %q", got)
	}
	if got := ScreenAlarmModeLine(drop.Security.Screen["p"]); got != "" {
		t.Fatalf("drop-enforcing profile must render no mode line, got %q", got)
	}
	if got := ScreenAlarmModeLine(nil); got != "" {
		t.Fatalf("nil profile must render empty, got %q", got)
	}
	if got := ScreenCheckValue(audit.Security.Screen["p"]); got != "alarm-only" {
		t.Fatalf("audit Value token = %q, want alarm-only", got)
	}
	if got := ScreenCheckValue(drop.Security.Screen["p"]); got != "enabled" {
		t.Fatalf("drop Value token = %q, want enabled", got)
	}
	if got := ScreenCheckValue(nil); got != "enabled" {
		t.Fatalf("nil Value token = %q, want enabled", got)
	}
}
