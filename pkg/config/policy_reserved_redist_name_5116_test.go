package config

import (
	"strings"
	"testing"
)

// #5116/#12065: the FRR renderer derives per-source protocol route-map names
// `<policy>-<protocol>-xpf-redist` into FRR's GLOBAL name-keyed route-map
// namespace. An operator policy-statement with that generated name can collide
// and merge route-map sequences, silently changing redistribution policy.
// validatePolicyReservedRedistNameStrict reserves the suffix: hard-reject at
// commit / commit-check (strict), lenient-warn on load / peer-sync (#1960).
//
// These tests drive the real CompileConfig (strict) / CompileConfigLenient
// (tolerant) paths via buildTreeFromSet. They FAIL if the reserve gate is
// reverted (the reserved-suffix name is then silently accepted at commit).

func TestPolicyReservedRedistSuffixRejected(t *testing.T) {
	tree := buildTreeFromSet(t, []string{
		"set policy-options policy-statement SHARED term t1 from protocol static",
		"set policy-options policy-statement SHARED term t1 then accept",
		"set policy-options policy-statement SHARED-static-xpf-redist term t1 from protocol connected",
		"set policy-options policy-statement SHARED-static-xpf-redist term t1 then accept",
		"set protocols ospf area 0.0.0.0 interface ge-0-0-0",
		"set protocols ospf export SHARED",
	})
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("CompileConfig accepted a policy-statement ending in the reserved " +
			"\"-xpf-redist\" suffix; expected rejection (#12065)")
	}
	for _, want := range []string{"SHARED-static-xpf-redist", "-xpf-redist", "reserved"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q missing %q", err.Error(), want)
		}
	}
}

func TestPolicyNormalNameAccepted(t *testing.T) {
	tree := buildTreeFromSet(t, []string{
		"set policy-options policy-statement SHARED term t1 from protocol direct",
		"set policy-options policy-statement SHARED term t1 then accept",
		"set protocols ospf area 0.0.0.0 interface ge-0-0-0",
		"set protocols ospf export SHARED",
	})
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("CompileConfig rejected a normal (non-reserved) policy-statement name: %v", err)
	}
}

func TestPolicyReservedRedistSuffixLenientWarns(t *testing.T) {
	tree := buildTreeFromSet(t, []string{
		"set policy-options policy-statement SHARED term t1 from protocol static",
		"set policy-options policy-statement SHARED term t1 then accept",
		"set policy-options policy-statement SHARED-static-xpf-redist term t1 from protocol connected",
		"set policy-options policy-statement SHARED-static-xpf-redist term t1 then accept",
		"set protocols ospf area 0.0.0.0 interface ge-0-0-0",
		"set protocols ospf export SHARED",
	})
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient must not hard-fail on a reserved-suffix name; must downgrade to warning: %v", err)
	}
	found := false
	for _, warning := range cfg.Warnings {
		if strings.Contains(warning, "SHARED-static-xpf-redist") && strings.Contains(warning, "reserved") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected a downgraded reserved-suffix warning naming the policy; warnings=%v", cfg.Warnings)
	}
}
