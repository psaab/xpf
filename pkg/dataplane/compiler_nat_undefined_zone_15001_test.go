package dataplane

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #15001: leniently-compiled config with undefined NAT zone must pass the
// dataplane pre-pass (validateBeforeMutate) by skipping the bad rule-set,
// while a hand-built / JSON-round-tripped config reaching compileNAT
// directly still fails closed on missing stamp (existing #12525/#14679).

func natUndefinedZoneLenientCfg15001(t *testing.T, cmds ...string) *config.Config {
	t.Helper()
	tree := &config.ConfigTree{}
	for _, cmd := range cmds {
		path, err := config.ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	return cfg
}

func TestCompileNATLenientUndefinedZonePrePass15001(t *testing.T) {
	cases := []struct {
		name string
		cmds []string
	}{
		{
			name: "source from-zone",
			cmds: []string{
				"set security zones security-zone trust",
				"set security zones security-zone untrust",
				"set security nat source pool pool1 address 192.0.2.10",
				"set security nat source rule-set snat-bad from zone untrsut",
				"set security nat source rule-set snat-bad to zone untrust",
				"set security nat source rule-set snat-bad rule r1 match source-address 10.0.0.0/8",
				"set security nat source rule-set snat-bad rule r1 then source-nat pool pool1",
				// healthy sibling must still compile
				"set security nat source rule-set snat-good from zone trust",
				"set security nat source rule-set snat-good to zone untrust",
				"set security nat source rule-set snat-good rule r1 match source-address 10.1.0.0/16",
				"set security nat source rule-set snat-good rule r1 then source-nat pool pool1",
			},
		},
		{
			name: "source to-zone",
			cmds: []string{
				"set security zones security-zone trust",
				"set security zones security-zone untrust",
				"set security nat source pool pool1 address 192.0.2.10",
				"set security nat source rule-set snat-bad from zone trust",
				"set security nat source rule-set snat-bad to zone untrsut",
				"set security nat source rule-set snat-bad rule r1 match source-address 10.0.0.0/8",
				"set security nat source rule-set snat-bad rule r1 then source-nat pool pool1",
			},
		},
		{
			name: "destination from-zone",
			cmds: []string{
				"set security zones security-zone trust",
				"set security nat destination pool P1 address 10.0.30.100",
				"set security nat destination rule-set dnat-bad from zone untrsut",
				"set security nat destination rule-set dnat-bad rule R1 match destination-address 198.51.100.5/32",
				"set security nat destination rule-set dnat-bad rule R1 then destination-nat pool P1",
				"set security nat destination rule-set dnat-good from zone trust",
				"set security nat destination rule-set dnat-good rule R1 match destination-address 198.51.100.6/32",
				"set security nat destination rule-set dnat-good rule R1 then destination-nat pool P1",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := natUndefinedZoneLenientCfg15001(t, tc.cmds...)
			if !strings.Contains(strings.Join(cfg.Warnings, "\n"), "untrsut") {
				t.Fatalf("precondition: lenient cfg should warn on untrsut, warnings=%v", cfg.Warnings)
			}
			result := newValidationResult()
			if err := validateBeforeMutateWithResult(discardingDataPlane{}, cfg, result); err != nil {
				t.Fatalf("pre-pass rejected lenient undefined-zone config (must skip rule-set): %v", err)
			}
		})
	}
}

func TestCompileNATDefinedZonePrePassControl15001(t *testing.T) {
	cfg := natUndefinedZoneLenientCfg15001(t,
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security nat source pool pool1 address 192.0.2.10",
		"set security nat source rule-set snat-good from zone trust",
		"set security nat source rule-set snat-good to zone untrust",
		"set security nat source rule-set snat-good rule r1 match source-address 10.0.0.0/8",
		"set security nat source rule-set snat-good rule r1 then source-nat pool pool1",
	)
	result := newValidationResult()
	if err := validateBeforeMutateWithResult(discardingDataPlane{}, cfg, result); err != nil {
		t.Fatalf("pre-pass rejected defined-zone control: %v", err)
	}
	if _, ok := result.PoolIDs["pool1"]; !ok {
		t.Fatalf("defined-zone control did not compile pool1: PoolIDs=%v", result.PoolIDs)
	}
}
