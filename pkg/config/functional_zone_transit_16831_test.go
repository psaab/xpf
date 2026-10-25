package config

import (
	"strings"
	"testing"
)

// #16831: `security zones functional-zone management` compiled into an
// ordinary transit zone indistinguishable from `security-zone
// management`, so global and zone-pair permit policies forwarded traffic
// into and out of the management interface. Junos: "Traffic entering
// management zones does not match policies; therefore, traffic cannot
// transit out of any other interface if it was received in the
// management interface."
//
// RED-on-revert: dropping the Functional stamp in compileZones (or the
// functional gates in validatePolicyZoneReferencesStrict) makes the
// strict-reject subtests compile clean and the Functional assertions
// fail. The security-zone twin control must stay an ordinary transit
// zone throughout.

func functionalBase16831() []string {
	return []string{
		"set security zones functional-zone management interfaces ge-0/0/1.0",
		"set security zones functional-zone management host-inbound-traffic system-services ssh",
		"set security zones security-zone trust interfaces ge-0/0/0.0",
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.1.1/24",
	}
}

func TestFunctionalZoneMarkedAndTwinControl16831(t *testing.T) {
	cfg, err := CompileConfig(buildTree(t, functionalBase16831()))
	if err != nil {
		t.Fatalf("strict CompileConfig (functional, no policy): %v", err)
	}
	mgmt := cfg.Security.Zones["management"]
	if mgmt == nil {
		t.Fatal("functional-zone management did not compile into zone \"management\"")
	}
	if !mgmt.Functional {
		t.Fatal("functional-zone management zone is not marked Functional (#16831)")
	}
	if svc, _, _ := mgmt.InterfaceHostInboundEffective("ge-0/0/1.0"); len(svc) != 1 || svc[0] != "ssh" {
		t.Fatalf("management host-inbound services = %v, want [ssh] (host-inbound must survive)", svc)
	}
	// Control: the twin `security-zone management` stays ordinary.
	twin := buildTree(t, []string{
		"set security zones security-zone management interfaces ge-0/0/1.0",
		"set security zones security-zone trust interfaces ge-0/0/0.0",
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.1.1/24",
	})
	cfgTwin, err := CompileConfig(twin)
	if err != nil {
		t.Fatalf("strict CompileConfig (security-zone twin): %v", err)
	}
	if z := cfgTwin.Security.Zones["management"]; z == nil || z.Functional {
		t.Fatalf("security-zone management Functional = %v, want false (ordinary transit zone)", z)
	}
	// Merged spelling: functional + literal security-zone management
	// keeps the functional (host-only) semantics for the one zone.
	merged := append(append([]string{}, functionalBase16831()...),
		"set security zones security-zone management description literal")
	cfgM, err := CompileConfig(buildTree(t, merged))
	if err != nil {
		t.Fatalf("strict CompileConfig (merged spellings): %v", err)
	}
	if z := cfgM.Security.Zones["management"]; z == nil || !z.Functional {
		t.Fatalf("merged management zone = %+v, want Functional=true", z)
	}
}

func TestFunctionalZonePairPolicyRejected16831(t *testing.T) {
	cases := []struct{ name, from, to string }{
		{"management_to_trust", "management", "trust"},
		{"trust_to_management", "trust", "management"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cmds := append(append([]string{}, functionalBase16831()...),
				"set security policies from-zone "+tc.from+" to-zone "+tc.to+" policy p1 match source-address any",
				"set security policies from-zone "+tc.from+" to-zone "+tc.to+" policy p1 match destination-address any",
				"set security policies from-zone "+tc.from+" to-zone "+tc.to+" policy p1 match application any",
				"set security policies from-zone "+tc.from+" to-zone "+tc.to+" policy p1 then permit",
			)
			if _, err := CompileConfig(buildTree(t, cmds)); err == nil {
				t.Fatalf("CompileConfig accepted %s->%s permit naming the functional zone; want strict reject (#16831)", tc.from, tc.to)
			} else if !strings.Contains(err.Error(), "functional zone") {
				t.Fatalf("reject = %v, want it to name the functional zone", err)
			}
			// Tolerant path boots with a warning and keeps the stamp.
			cfgL, err := CompileConfigLenient(buildTree(t, cmds))
			if err != nil {
				t.Fatalf("lenient CompileConfig: %v", err)
			}
			found := false
			for _, w := range cfgL.Warnings {
				if strings.Contains(w, "functional zone") {
					found = true
				}
			}
			if !found {
				t.Fatalf("lenient warnings = %v, want a functional-zone warning", cfgL.Warnings)
			}
			if z := cfgL.Security.Zones["management"]; z == nil || !z.Functional {
				t.Fatalf("lenient management zone = %+v, want Functional=true", z)
			}
		})
	}
	// Control: the same zone-pair permit on the security-zone twin commits.
	twinCmds := []string{
		"set security zones security-zone management interfaces ge-0/0/1.0",
		"set security zones security-zone trust interfaces ge-0/0/0.0",
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.1.1/24",
		"set security policies from-zone management to-zone trust policy p1 match source-address any",
		"set security policies from-zone management to-zone trust policy p1 match destination-address any",
		"set security policies from-zone management to-zone trust policy p1 match application any",
		"set security policies from-zone management to-zone trust policy p1 then permit",
	}
	if _, err := CompileConfig(buildTree(t, twinCmds)); err != nil {
		t.Fatalf("security-zone twin management->trust permit must commit, got: %v", err)
	}
}

func TestFunctionalGlobalScopeRejectedUnscopedCommits16831(t *testing.T) {
	scoped := append(append([]string{}, functionalBase16831()...),
		"set security policies global policy g1 match from-zone management",
		"set security policies global policy g1 match source-address any",
		"set security policies global policy g1 match destination-address any",
		"set security policies global policy g1 match application any",
		"set security policies global policy g1 then permit",
	)
	if _, err := CompileConfig(buildTree(t, scoped)); err == nil {
		t.Fatal("CompileConfig accepted global policy scoped to functional management; want strict reject (#16831)")
	}
	// An unscoped global permit stays legal: the dataplane excludes the
	// functional zone from global matching instead of rejecting the rule.
	unscoped := append(append([]string{}, functionalBase16831()...),
		"set security policies global policy g1 match source-address any",
		"set security policies global policy g1 match destination-address any",
		"set security policies global policy g1 match application any",
		"set security policies global policy g1 then permit",
	)
	cfg, err := CompileConfig(buildTree(t, unscoped))
	if err != nil {
		t.Fatalf("unscoped global permit with functional zone must commit, got: %v", err)
	}
	if len(cfg.Security.GlobalPolicies) != 1 {
		t.Fatalf("GlobalPolicies = %v, want the one unscoped permit", cfg.Security.GlobalPolicies)
	}
}
