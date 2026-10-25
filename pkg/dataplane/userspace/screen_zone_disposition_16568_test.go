package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #16568: ScreenZoneDispositionFor is the SSOT the zone renderers use to
// qualify `Screen: <profile>`. Rows mirror the issue probe: enforcing
// control unchanged, inert and undefined qualified, plus the UNKNOWN
// guards (nil profile value, no screen, quarantined zone).

func dispositionCfg16568() *config.Config {
	return &config.Config{Security: config.SecurityConfig{
		Screen: map[string]*config.ScreenProfile{
			"corp":  {Name: "corp", TCP: config.TCPScreen{SynFlood: &config.SynFloodConfig{AttackThreshold: 500}}},
			"audit": {Name: "audit", AlarmWithoutDrop: true},
			"empty": {Name: "empty"},
			"nilp":  nil,
		},
		Zones: map[string]*config.ZoneConfig{
			"trust":   {Name: "trust", ScreenProfile: "corp"},
			"inert":   {Name: "inert", ScreenProfile: "audit"},
			"emptyz":  {Name: "emptyz", ScreenProfile: "empty"},
			"ghost":   {Name: "ghost", ScreenProfile: "missing"},
			"nilzone": {Name: "nilzone", ScreenProfile: "nilp"},
			"plain":   {Name: "plain"},
		},
	}}
}

func TestScreenZoneDispositionFor16568(t *testing.T) {
	cfg := dispositionCfg16568()
	cases := []struct {
		zone string
		want ScreenZoneDisposition
		qual string
	}{
		{"trust", ScreenZoneDispositionEnforcing, ""},
		{"inert", ScreenZoneDispositionInert, "[ENFORCES NOTHING — conservative default applies]"},
		{"emptyz", ScreenZoneDispositionInert, "[ENFORCES NOTHING — conservative default applies]"},
		{"ghost", ScreenZoneDispositionUndefined, "[UNDEFINED — conservative default applies]"},
		{"nilzone", ScreenZoneDispositionUnknown, ""},
		{"plain", ScreenZoneDispositionUnknown, ""},
		{"absent", ScreenZoneDispositionUnknown, ""},
	}
	for _, tc := range cases {
		got := ScreenZoneDispositionFor(cfg, tc.zone)
		if got != tc.want {
			t.Errorf("%s: disposition = %v, want %v", tc.zone, got, tc.want)
		}
		if q := got.Qualifier(); q != tc.qual {
			t.Errorf("%s: qualifier = %q, want %q", tc.zone, q, tc.qual)
		}
	}
	if got := ScreenZoneDispositionFor(nil, "trust"); got != ScreenZoneDispositionUnknown {
		t.Errorf("nil cfg: disposition = %v, want Unknown", got)
	}
}
