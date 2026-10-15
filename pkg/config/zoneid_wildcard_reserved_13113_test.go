package config

import (
	"strings"
	"testing"
)

// #13113 (D1-09): the collision gate must only consider concrete, non-reserved
// zone names — the same view QuarantinedZoneNames uses. Group wildcard
// templates (<*>, <ge-*>) are patterns, not zones, and reserved tokens
// (any/junos-global/junos-host) never claim a StableZoneID, so neither may
// collide with (and reject/quarantine) a real zone folding to the same id.
// z65162 folds to StableZoneID("<*>")==15527; z63256 folds to
// StableZoneID("any")==29700.
func TestZoneIDCollisionIgnoresWildcardAndReserved13113(t *testing.T) {
	if StableZoneID("z65162") != StableZoneID("<*>") {
		t.Fatalf("test premise broken: z65162 no longer folds to StableZoneID(\"<*>\")")
	}
	if StableZoneID("z63256") != StableZoneID("any") {
		t.Fatalf("test premise broken: z63256 no longer folds to StableZoneID(\"any\")")
	}
	cases := []struct {
		name            string
		lines           []string
		strictErrReason string
	}{
		{"group wildcard template", []string{
			"set groups G security zones security-zone <*> tcp-rst",
			"set security zones security-zone z65162",
		}, ""},
		{"group wildcard glob template", []string{
			"set groups G security zones security-zone <z*> tcp-rst",
			"set security zones security-zone z65162",
		}, ""},
		{"reserved any defined in group", []string{
			"set groups G security zones security-zone any",
			"set security zones security-zone z63256",
		}, ""},
		{"reserved junos-host defined directly", []string{
			"set security zones security-zone junos-host",
			"set security zones security-zone z63256",
		}, "reserved"},
	}
	for _, c := range cases {
		t.Run(c.name+"/strict", func(t *testing.T) {
			tree := buildTree(t, c.lines)
			_, err := CompileConfig(tree)
			if c.strictErrReason != "" {
				if err == nil || !strings.Contains(err.Error(), c.strictErrReason) ||
					strings.Contains(err.Error(), "collision") {
					t.Fatalf("strict compile error = %v, want non-collision %q error (#13113)", err, c.strictErrReason)
				}
				return
			}
			if err != nil {
				t.Fatalf("strict compile rejected on non-concrete/reserved token: %v (#13113)", err)
			}
		})
		t.Run(c.name+"/lenient", func(t *testing.T) {
			tree := buildTree(t, c.lines)
			cfg, err := CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("lenient compile errored: %v", err)
			}
			for _, w := range cfg.Warnings {
				if strings.Contains(w, "zone id collision") {
					t.Fatalf("lenient compile emitted false collision warning: %q (#13113)", w)
				}
			}
			for _, n := range []string{"z65162", "z63256"} {
				if _, ok := ZoneQuarantineExclusionsForConfig(cfg)[n]; ok {
					t.Fatalf("non-colliding runtime zone %q was quarantined (#13113)", n)
				}
			}
		})
	}
	// Positive control: a genuine concrete collision must still be rejected.
	t.Run("concrete collision still rejected", func(t *testing.T) {
		tree := buildTree(t, []string{
			"set security zones security-zone z174",
			"set security zones security-zone z214",
		})
		if _, err := CompileConfig(tree); err == nil ||
			!strings.Contains(err.Error(), "collision") {
			t.Fatalf("strict compile error = %v, want genuine concrete collision (#13113 control)", err)
		}
	})
}
