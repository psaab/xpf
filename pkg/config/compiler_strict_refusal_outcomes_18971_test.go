package config

import (
	"strings"
	"testing"
)

// The outcome pins are deliberately independent literals. They must not be
// derived from production output: swapping a builder's strict and tolerant
// outcomes has to red these tests rather than move their expectations.
const strictCommitOutcome18971 = "the commit is refused"

func requireCompileOutcomes18971(t *testing.T, tree *ConfigTree, head, lenientOutcome string) {
	t.Helper()
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatalf("strict compile accepted the invalid fixture; want refusal containing %q", head)
	}
	strict := err.Error()
	if !strings.Contains(strict, head) || !strings.Contains(strict, strictCommitOutcome18971) {
		t.Errorf("strict error %q lacks literal head %q or outcome %q", strict, head, strictCommitOutcome18971)
	}
	if strings.Contains(strict, lenientOutcome) {
		t.Errorf("strict error %q incorrectly carries tolerant outcome %q", strict, lenientOutcome)
	}

	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("tolerant compile must warn and continue, got %v", err)
	}
	for _, warning := range cfg.Warnings {
		if !strings.Contains(warning, head) {
			continue
		}
		if !strings.Contains(warning, lenientOutcome) {
			t.Fatalf("tolerant warning %q lacks literal outcome %q", warning, lenientOutcome)
		}
		if strings.Contains(warning, strictCommitOutcome18971) {
			t.Fatalf("tolerant warning %q incorrectly carries strict outcome %q", warning, strictCommitOutcome18971)
		}
		return
	}
	t.Fatalf("tolerant warnings %v contain no diagnostic with literal head %q", cfg.Warnings, head)
}

func requireBuilderOutcomes18971(t *testing.T, head, lenientOutcome string, build func(bool) error) {
	t.Helper()
	for _, lenient := range []bool{false, true} {
		err := build(lenient)
		if err == nil {
			t.Fatalf("builder returned nil for invalid fixture (lenient=%t)", lenient)
		}
		message := err.Error()
		if !strings.Contains(message, head) {
			t.Errorf("builder error %q lacks literal head %q (lenient=%t)", message, head, lenient)
		}
		if lenient {
			if !strings.Contains(message, lenientOutcome) || strings.Contains(message, strictCommitOutcome18971) {
				t.Errorf("tolerant builder error %q lacks outcome %q or carries strict refusal", message, lenientOutcome)
			}
		} else {
			if !strings.Contains(message, strictCommitOutcome18971) || strings.Contains(message, lenientOutcome) {
				t.Errorf("strict builder error %q lacks refusal or carries tolerant outcome %q", message, lenientOutcome)
			}
		}
	}
}

func TestPolicyMatchApplicationOutcome18971(t *testing.T) {
	tree := buildAppMatchTree(t, append(append([]string{}, zoneBoilerplate...),
		"set security policies from-zone trust to-zone untrust policy p match source-address any",
		"set security policies from-zone trust to-zone untrust policy p match destination-address any",
		"set security policies from-zone trust to-zone untrust policy p match application NO_SUCH_APP",
		"set security policies from-zone trust to-zone untrust policy p then permit",
	)...)
	requireCompileOutcomes18971(t, tree,
		`security policies from-zone trust to-zone untrust policy "p" match application "NO_SUCH_APP" is not defined`,
		"an undefined application reference commits but the userspace dataplane then REFUSES to arm security policies (commit/apply split, fail-open)")
}

func TestPolicyMatchEmptyAppSetOutcome18971(t *testing.T) {
	tree := buildAppMatchTree(t, append(append([]string{}, zoneBoilerplate...),
		"set applications application-set EMPTYSET description foo",
		"set security policies from-zone trust to-zone untrust policy p match source-address any",
		"set security policies from-zone trust to-zone untrust policy p match destination-address any",
		"set security policies from-zone trust to-zone untrust policy p match application EMPTYSET",
		"set security policies from-zone trust to-zone untrust policy p then permit",
	)...)
	requireCompileOutcomes18971(t, tree,
		`security policies from-zone trust to-zone untrust policy "p" match application "EMPTYSET" is a defined but EMPTY application-set (it expands to zero applications)`,
		"the policy commits but the userspace dataplane then REFUSES to arm security policies (commit/apply split, fail-open)")
}

func TestPolicyMatchAddressSetOutcome18971(t *testing.T) {
	tree := buildAppMatchTree(t, append(append([]string{}, zoneBoilerplate...),
		"set security address-book global address-set BAD address MISSING",
		"set security policies from-zone trust to-zone untrust policy p match source-address BAD",
		"set security policies from-zone trust to-zone untrust policy p match destination-address any",
		"set security policies from-zone trust to-zone untrust policy p match application any",
		"set security policies from-zone trust to-zone untrust policy p then permit",
	)...)
	requireCompileOutcomes18971(t, tree,
		`security policies from-zone trust to-zone untrust policy "p" match source-address "BAD" does not fully resolve: member "MISSING" is not a defined address or address-set`,
		"the policy commits but the userspace dataplane then REFUSES to arm security policies (commit/apply split, fail-open)")
}

func TestNATMatchEmptyAppSetOutcome18971(t *testing.T) {
	tree := flatTreeFromSets(t,
		"set applications application-set EMPTYSET description foo",
		"set security nat source rule-set rs1 from zone trust",
		"set security nat source rule-set rs1 to zone untrust",
		"set security nat source rule-set rs1 rule r1 match source-address 10.0.0.0/8",
		"set security nat source rule-set rs1 rule r1 match application EMPTYSET",
		"set security nat source rule-set rs1 rule r1 then source-nat interface",
	)
	requireCompileOutcomes18971(t, tree,
		`source NAT rule-set "rs1" rule "r1" match application "EMPTYSET" is a defined but EMPTY application-set (it expands to zero applications)`,
		"the rule commits but the dataplane installs a never-match term so the translation never fires")
}

func TestNATPoolReferenceOutcome18971(t *testing.T) {
	tree := flatTreeFromSets(t,
		"set security nat source rule-set rs1 from zone trust",
		"set security nat source rule-set rs1 to zone untrust",
		"set security nat source rule-set rs1 rule r1 match source-address 10.0.0.0/24",
		"set security nat source rule-set rs1 rule r1 then source-nat pool ghost-pool",
	)
	requireCompileOutcomes18971(t, tree,
		`source-nat rule-set "rs1" rule "r1" references undefined pool "ghost-pool"`,
		"otherwise the rule commits but the dataplane fails the translation closed (the pool lookup misses, so the rule is dropped / marked unusable) and matching traffic is silently left untranslated, falling through to a later rule or the no-NAT default")
}

func TestSourceNATPoolAddressGrammarOutcomes18971(t *testing.T) {
	cases := []struct {
		name           string
		pool           []string
		head           string
		lenientOutcome string
	}{
		{
			name:           "empty-pool",
			pool:           []string{"set security nat source pool p1 port range 5000 to 6000"},
			head:           `source-nat pool "p1" (referenced by rule-set "RS" rule "R1") has no pool addresses`,
			lenientOutcome: "the rule commits but the dataplane marks the pool unusable (EmptyPool) and drops it at runtime, silently stopping translation",
		},
		{
			name:           "invalid-member",
			pool:           []string{"set security nat source pool p1 address not-an-ip"},
			head:           `source-nat pool "p1" (referenced by rule-set "RS" rule "R1"): address "not-an-ip" is not a valid IP address`,
			lenientOutcome: "the rule commits but the dataplane marks the pool unusable (InvalidPool) and drops it at runtime, silently stopping translation",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			requireCompileOutcomes18971(t, snat5627Tree(t, tc.pool...), tc.head, tc.lenientOutcome)
		})
	}
}

func TestSourceNATPoolAddressScopeOutcome18971(t *testing.T) {
	tree := snat5875Tree(t, "set security nat source pool p1 address fe80::1%eth0")
	requireCompileOutcomes18971(t, tree,
		`source-nat pool "p1" (referenced by rule-set "RS" rule "R1"): address "fe80::1%eth0" carries an IPv6 zone/scope qualifier (%zone)`,
		"the rule commits but the dataplane marks the pool unusable (InvalidPool) and drops it at runtime, silently stopping translation")
}

func TestNATPeerEffectiveStrictOutcomes18971(t *testing.T) {
	cases := []struct {
		name           string
		cmds           []string
		head           string
		lenientOutcome string
	}{
		{
			name: "empty-application-set",
			cmds: []string{
				"set security nat source rule-set RS from zone trust",
				"set security nat source rule-set RS to zone untrust",
				"set security nat source rule-set RS rule R1 match source-address 10.0.0.0/24",
				"set security nat source rule-set RS rule R1 match application AppSet",
				"set security nat source rule-set RS rule R1 then source-nat interface",
				"set groups node0 applications application App protocol tcp destination-port 80",
				"set groups node0 applications application-set AppSet application App",
				"set groups node1 applications application-set AppSet description empty",
				`set apply-groups "${node}"`,
			},
			head:           `source NAT rule-set "RS" rule "R1" match application "AppSet" is a defined but EMPTY application-set`,
			lenientOutcome: "the rule commits but the dataplane installs a never-match term so the translation never fires",
		},
		{
			name: "undefined-pool",
			cmds: []string{
				"set security nat source rule-set RS from zone trust",
				"set security nat source rule-set RS to zone untrust",
				"set security nat source rule-set RS rule R1 match source-address 10.0.0.0/24",
				"set security nat source rule-set RS rule R1 then source-nat pool OnlyNode0",
				"set groups node0 security nat source pool OnlyNode0 address 203.0.113.9/32",
				"set groups node1 system host-name fw1",
				`set apply-groups "${node}"`,
			},
			head:           `source-nat rule-set "RS" rule "R1" references undefined pool "OnlyNode0"`,
			lenientOutcome: "otherwise the rule commits but the dataplane fails the translation closed",
		},
		{
			name: "invalid-pool-member",
			cmds: []string{
				"set security nat source rule-set RS from zone trust",
				"set security nat source rule-set RS to zone untrust",
				"set security nat source rule-set RS rule R1 match source-address 10.0.0.0/24",
				"set security nat source rule-set RS rule R1 then source-nat pool Q",
				"set groups node0 security nat source pool Q address 203.0.113.5/32",
				"set groups node1 security nat source pool Q address not-an-ip",
				`set apply-groups "${node}"`,
			},
			head:           `source-nat pool "Q" (referenced by rule-set "RS" rule "R1"): address "not-an-ip" is not a valid IP address`,
			lenientOutcome: "the rule commits but the dataplane marks the pool unusable (InvalidPool)",
		},
		{
			name: "scoped-pool-address",
			cmds: []string{
				"set security nat source rule-set RS from zone trust",
				"set security nat source rule-set RS to zone untrust",
				"set security nat source rule-set RS rule R1 match source-address 10.0.0.0/24",
				"set security nat source rule-set RS rule R1 then source-nat pool P",
				"set groups node0 security nat source pool P address 203.0.113.5/32",
				"set groups node1 security nat source pool P address fe80::1%eth0",
				`set apply-groups "${node}"`,
			},
			head:           `source-nat pool "P" (referenced by rule-set "RS" rule "R1"): address "fe80::1%eth0" carries an IPv6 zone/scope qualifier (%zone)`,
			lenientOutcome: "the rule commits but the dataplane marks the pool unusable (InvalidPool)",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := buildTreeFromSet(t, tc.cmds)
			if _, err := CompileConfigForNode(tree, 0); err != nil {
				t.Fatalf("node0 local compile must be clean, got %v", err)
			}
			err := ValidatePeerEffectiveStrict(tree, 0)
			if err == nil {
				t.Fatal("peer-effective strict gate accepted the peer-only invalid fixture")
			}
			message := err.Error()
			if !strings.Contains(message, tc.head) || !strings.Contains(message, strictCommitOutcome18971) {
				t.Fatalf("peer-effective error %q lacks literal head %q or strict outcome", message, tc.head)
			}
			if strings.Contains(message, tc.lenientOutcome) {
				t.Fatalf("peer-effective strict error %q carries tolerant outcome %q", message, tc.lenientOutcome)
			}
		})
	}
}

func TestHostInboundTokenOutcomes18971(t *testing.T) {
	const lenientOutcome = "an unknown token commits but enforces inconsistently (kernel nft path vs Rust dataplane disagree)"
	cases := []struct {
		name string
		hib  *HostInboundTraffic
		head string
	}{
		{
			name: "retained-noncanonical-service",
			hib:  &HostInboundTraffic{nonCanonicalSystemServices: []string{"SSH"}},
			head: `security zone "trust" host-inbound-traffic system-services "SSH" is not a recognized system-service`,
		},
		{
			name: "retained-noncanonical-protocol",
			hib:  &HostInboundTraffic{nonCanonicalProtocols: []string{"OSPF"}},
			head: `security zone "trust" host-inbound-traffic protocols "OSPF" is not a recognized protocol`,
		},
		{
			name: "compiled-service-token",
			hib:  &HostInboundTraffic{SystemServices: []string{"sssh"}},
			head: `security zone "trust" host-inbound-traffic system-services "sssh" is not a recognized system-service`,
		},
		{
			name: "compiled-protocol-token",
			hib:  &HostInboundTraffic{Protocols: []string{"ospff"}},
			head: `security zone "trust" host-inbound-traffic protocols "ospff" is not a recognized protocol`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			requireBuilderOutcomes18971(t, tc.head, lenientOutcome, func(lenient bool) error {
				return validateHostInboundStanzaStrict("trust", "", tc.hib, lenient)
			})
		})
	}

	// The direct branch pins above identify each producer; this public-pipeline
	// case separately proves that the dispatcher threads its actual arm flag.
	t.Run("dispatcher-arm-threading", func(t *testing.T) {
		tree := buildTree(t, []string{
			"set security zones security-zone trust host-inbound-traffic system-services sssh",
		})
		requireCompileOutcomes18971(t, tree,
			`security zone "trust" host-inbound-traffic system-services "sssh" is not a recognized system-service`,
			lenientOutcome)
	})
}
