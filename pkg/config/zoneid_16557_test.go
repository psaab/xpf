package config

import (
	"fmt"
	"strings"
	"testing"
)

// #16557 acceptance: the former u16 collision pairs commit under the u32 fold.
func TestZoneID16557FormerCollisionPairsCommit(t *testing.T) {
	for _, pair := range [][2]string{{"vlan163", "vlan364"}, {"zone109", "zone237"}} {
		if StableZoneID(pair[0]) == StableZoneID(pair[1]) {
			t.Fatalf("premise: %q/%q still collide under u32 fold", pair[0], pair[1])
		}
		tree := buildTree(t, []string{
			"set security zones security-zone " + pair[0],
			"set security zones security-zone " + pair[1],
		})
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("pair %v strict commit rejected: %v", pair, err)
		}
		if len(cfg.Security.Zones) != 2 {
			t.Fatalf("pair %v zones = %d, want 2", pair, len(cfg.Security.Zones))
		}
	}
}

// #16557: ids are stable across unrelated add/remove.
func TestZoneID16557StableAcrossUnrelatedAddRemove(t *testing.T) {
	before := StableZoneID("vlan163")
	tree := buildTree(t, []string{
		"set security zones security-zone aaa-unrelated",
		"set security zones security-zone vlan163",
		"set security zones security-zone vlan364",
		"set security zones security-zone zzz-unrelated",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if cfg.Security.Zones["vlan163"] == nil {
		t.Fatal("vlan163 missing")
	}
	if got := StableZoneID("vlan163"); got != before {
		t.Fatalf("StableZoneID changed with unrelated zones: %d != %d", got, before)
	}
}

// #16557 residual: a single-fold u32 collision is still strict-rejected and
// lenient-quarantined (zzq17760/zzq8100 both fold to 1679679597).
func TestZoneID16557ResidualCollisionGate(t *testing.T) {
	if StableZoneID("zzq17760") != 1679679597 || StableZoneID("zzq8100") != 1679679597 {
		t.Fatalf("premise: residual pair no longer collides: %d/%d", StableZoneID("zzq17760"), StableZoneID("zzq8100"))
	}
	tree := buildTree(t, []string{
		"set security zones security-zone zzq17760",
		"set security zones security-zone zzq8100",
	})
	if _, err := CompileConfig(tree); err == nil || !strings.Contains(err.Error(), "collision") {
		t.Fatalf("strict residual collision not rejected: %v", err)
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient residual collision bricked: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "QUARANTINED") {
			found = true
		}
	}
	if !found {
		t.Fatalf("lenient warning missing QUARANTINED: %v", cfg.Warnings)
	}
	q := QuarantinedZoneNames([]string{"zzq8100", "zzq17760"})
	if _, ok := q["zzq8100"]; !ok {
		t.Fatalf("later-sorting zzq8100 not quarantined: %v", q)
	}
	_ = fmt.Sprintf
}
