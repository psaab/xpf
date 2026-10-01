package config

import (
	"strings"
	"testing"
)

// #5442: the FRR renderer composes an ordered BGP import/export policy chain of
// length >= 2 into a SINGLE route-map named `join(chain, "-") + ReservedChainSuffix`
// ("-xpf-chain") in FRR's GLOBAL name-keyed route-map namespace (composedChainName,
// pkg/frr, #5277). An operator policy-statement literally named `<X>-xpf-chain`
// lands in that reserved suffix namespace and can collide with a generated
// composed route-map; FRR MERGES two same-named route-map definitions, silently
// altering the operator's BGP filtering. validatePolicyReservedChainNameStrict
// reserves the suffix: hard-reject at commit / commit-check (strict),
// lenient-warn on load / peer-sync (#1960). This makes the composed-name
// namespace injective against operator policy-statements by construction — the
// commit-time parity for the `-xpf-redist` reservation (#5116) whose render-side
// guard bgpComposedChainCollision (pkg/frr) already fails the apply CLOSED.
//
// These tests drive the real CompileConfig (strict) / CompileConfigLenient
// (tolerant) paths via buildTreeFromSet (the shared flat-set helper). They FAIL
// if the reserve gate is reverted (the reserved-suffix name is then silently
// accepted at commit).

// TestPolicyReservedChainSuffixRejected is the core: an operator
// policy-statement whose name ends in the reserved suffix is hard-rejected at
// commit, naming the policy, the suffix, and that it is reserved.
func TestPolicyReservedChainSuffixRejected(t *testing.T) {
	tree := buildTreeFromSet(t, []string{
		"set policy-options policy-statement A-B-xpf-chain term t1 from protocol direct",
		"set policy-options policy-statement A-B-xpf-chain term t1 then accept",
	})
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("CompileConfig accepted a policy-statement ending in the reserved " +
			"\"-xpf-chain\" suffix; expected rejection (#5442)")
	}
	for _, want := range []string{"A-B-xpf-chain", "-xpf-chain", "reserved"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q missing %q", err.Error(), want)
		}
	}
}

// TestPolicyReservedChainNormalNameAccepted is the negative control: a normal
// policy-statement name (no reserved suffix), even when composed into a BGP
// export chain of >= 2, still compiles — so the gate is SURGICAL and does not
// reject the common case. It also proves the collision trigger requires the
// exact suffix — a name merely CONTAINING "chain" is fine.
func TestPolicyReservedChainNormalNameAccepted(t *testing.T) {
	tree := buildTreeFromSet(t, []string{
		"set routing-options autonomous-system 65000",
		"set policy-options policy-statement BLOCK-PRIVATE term t1 from protocol direct",
		"set policy-options policy-statement BLOCK-PRIVATE term t1 then reject",
		"set policy-options policy-statement ALLOW-CUSTOMER term t1 then accept",
		"set protocols bgp group g type external",
		"set protocols bgp group g peer-as 65001",
		"set protocols bgp group g neighbor 10.0.0.2 export BLOCK-PRIVATE",
		"set protocols bgp group g neighbor 10.0.0.2 export ALLOW-CUSTOMER",
	})
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("CompileConfig rejected a normal (non-reserved) policy-statement chain: %v", err)
	}
}

// TestPolicyReservedChainSuffixLenientWarns pins the #1960 fail-closed-on-load
// doctrine: an already-persisted or peer-synced config an older binary accepted
// (before this gate) must still BOOT through CompileConfigLenient — the reserved
// name is downgraded to a warning, not a hard failure. The render-side
// bgpComposedChainCollision guard (pkg/frr) fails the actual apply closed, so
// the leniently-loaded name still cannot leak.
func TestPolicyReservedChainSuffixLenientWarns(t *testing.T) {
	tree := buildTreeFromSet(t, []string{
		"set policy-options policy-statement A-B-xpf-chain term t1 from protocol direct",
		"set policy-options policy-statement A-B-xpf-chain term t1 then accept",
	})
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient must not hard-fail on a reserved-suffix name; must downgrade to warning: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "A-B-xpf-chain") && strings.Contains(w, "reserved") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected a downgraded reserved-suffix warning naming the policy; warnings=%v", cfg.Warnings)
	}
}
