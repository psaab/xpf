package cli

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #16568: `show security zones [detail]` must qualify a zone whose screen
// profile is undefined (lenient) or inert (strict-clean) instead of
// printing `Screen: <profile>` verbatim. Enforcing control unchanged;
// detail must not list alarm-without-drop as an enabled check.

func zonesScreenCfg16568() *config.Config {
	return &config.Config{Security: config.SecurityConfig{
		Screen: map[string]*config.ScreenProfile{
			"corp":  {Name: "corp", TCP: config.TCPScreen{SynFlood: &config.SynFloodConfig{AttackThreshold: 500}}},
			"audit": {Name: "audit", AlarmWithoutDrop: true},
		},
		Zones: map[string]*config.ZoneConfig{
			"trust": {Name: "trust", ScreenProfile: "corp"},
			"inert": {Name: "inert", ScreenProfile: "audit"},
			"ghost": {Name: "ghost", ScreenProfile: "missing"},
		},
	}}
}

func TestShowZonesScreenQualifier16568(t *testing.T) {
	cfg := zonesScreenCfg16568()
	for _, detail := range []bool{false, true} {
		out := captureStdout(t, func() {
			if err := (&CLI{}).showZonesDisplay(cfg, detail, ""); err != nil {
				t.Fatalf("showZonesDisplay(detail=%v): %v", detail, err)
			}
		})
		if !strings.Contains(out, "  Screen: corp\n") {
			t.Errorf("detail=%v: enforcing control must stay bare:\n%s", detail, out)
		}
		if !strings.Contains(out, "  Screen: audit [ENFORCES NOTHING — conservative default applies]\n") {
			t.Errorf("detail=%v: inert zone not qualified:\n%s", detail, out)
		}
		if !strings.Contains(out, "  Screen: missing [UNDEFINED — conservative default applies]\n") {
			t.Errorf("detail=%v: undefined zone not qualified:\n%s", detail, out)
		}
		if strings.Contains(out, "Enabled checks: alarm-without-drop") {
			t.Errorf("detail=%v: inert detail lists modifier as enabled check:\n%s", detail, out)
		}
		if detail && !strings.Contains(out, "Enabled checks: syn-flood(threshold:500)") {
			t.Errorf("detail: enforcing inventory changed:\n%s", out)
		}
		if detail && !strings.Contains(out, "Enabled checks: (none) —") {
			t.Errorf("detail: inert detail must say (none) with disposition:\n%s", out)
		}
	}
}
