package configstore

import (
	"strings"
	"testing"
)

// #9814 end-to-end at the REAL commit gate. The unit gates live in pkg/config
// (the `instance-type` schema enum + validateRoutingInstanceTypeStrict9814),
// but binding the WIRING matters separately from binding the functions:
// CheckText is what `commit check` and `commit` actually run
// (compileTreeStrict = SchemaValidate, then CompileConfig), and the issue's
// acceptance is phrased as "strict commit refuses". Green-on-arrival: base
// RED was proven per-member by the pkg/config cells, and both rejection legs
// are new code, so this cell would fail on base by construction.
func TestRoutingInstanceTypeCommitRefusesUnknown9814(t *testing.T) {
	for _, typ := range []string{"forwardng", "bogus", "no-forwarding", "l2vpn", "vpls"} {
		text := "routing-instances { V9814 { instance-type " + typ + "; } }\n"
		cfg, err := CheckText(text, 0)
		if err == nil {
			t.Errorf("commit ACCEPTED instance-type %q (%d warning(s)) — this is the #9814 defect", typ, len(cfg.Warnings))
			continue
		}
		if !strings.Contains(err.Error(), typ) {
			t.Errorf("commit diagnostic omits the value %q: %v", typ, err)
		}
	}
	for _, typ := range []string{"forwarding", "virtual-router", "vrf"} {
		text := "routing-instances { V9814 { instance-type " + typ + "; } }\n"
		if _, err := CheckText(text, 0); err != nil {
			t.Errorf("commit rejected supported instance-type %q: %v", typ, err)
		}
	}
	if _, err := CheckText("routing-instances { V9814 { interface ge-0/0/0.0; } }\n", 0); err != nil {
		t.Errorf("commit rejected omitted instance-type (established VRF default): %v", err)
	}
	if _, err := CheckText("routing-instances { V9814 instance-type bogus; }\n", 0); err == nil {
		t.Errorf("commit ACCEPTED elided instance-type bogus — the elided shape must reject")
	} else if !strings.Contains(err.Error(), "#9814") {
		t.Errorf("elided-bogus commit rejection lacks #9814 marker (wrong gate?): %v", err)
	}
	for _, tc := range []struct{ name, text, want string }{
		{"nested-empty-overwrites-forwarding", "routing-instances { V9814 { instance-type forwarding; description x { instance-type \"\"; } } }\n", "#9814"},
		{"direct-empty", "routing-instances { V9814 { instance-type \"\"; } }\n", "#9814"},
		// Valueless fires the schema ARITY gate ("missing value"), which runs
		// before any value validator — so no #9814 marker by construction.
		// Pinning the measured gate, not weakening the assert.
		{"valueless", "routing-instances { V9814 { instance-type; } }\n", "missing value"},
	} {
		cfg, err := CheckText(tc.text, 0)
		if err == nil {
			t.Errorf("commit ACCEPTED %s (%d warning(s)) — explicitly-empty must reject", tc.name, len(cfg.Warnings))
			continue
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("commit rejection of %s lacks %q (wrong gate?): %v", tc.name, tc.want, err)
		}
	}
}

// The #9814 VPN-statement warnings must reach the commit-warnings channel:
// each keyword still commits (never rejected per #9323) but warns.
func TestRoutingInstanceVpnStatementWarnsAtCommit9814(t *testing.T) {
	for _, tc := range []struct{ kw, body string }{
		{"vrf-target", "vrf-target target:65001:100;"},
		{"vrf-table-label", "vrf-table-label;"},
		{"route-distinguisher", "route-distinguisher 65001:100;"},
	} {
		cfg, err := CheckText("routing-instances { V9814 { instance-type vrf; "+tc.body+" } }\n", 0)
		if err != nil {
			t.Fatalf("commit rejected %s (must stay accepted per #9323): %v", tc.kw, err)
		}
		joined := strings.Join(cfg.Warnings, "\n")
		if !strings.Contains(joined, tc.kw) || !strings.Contains(joined, "ACCEPTED but NOT APPLIED") || !strings.Contains(joined, "#9814") {
			t.Errorf("commit warnings lack the #9374-style %s warning; warnings=%v", tc.kw, cfg.Warnings)
		}
	}
}
