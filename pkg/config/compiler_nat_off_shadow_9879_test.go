package config

import (
	"strings"
	"testing"
)

// #9879: a broad `then destination-nat off` exemption configured BEFORE a
// narrower later translate rule loses for the overlapping subspace — the
// dataplane resolves DNAT by most-specific match, not rule order — so the
// "exempted" traffic is translated anyway (fail-open). The commit gate rejects
// the losing shape on the strict path and warns on the lenient path.
//
// RED-on-revert: delete validateDNATOffShadowStrict (or its runUniformGatesNAT
// registration) and every reject case below compiles clean.

func offShadowTree9879(t *testing.T, ruleCmds ...string) *ConfigTree {
	t.Helper()
	cmds := []string{
		"set security nat destination pool p1 address 192.168.1.10",
		"set security nat destination rule-set rs1 from zone untrust",
	}
	return buildTree(t, append(cmds, ruleCmds...))
}

func TestDNATOffShadowPortTierRejected_9879(t *testing.T) {
	tree := offShadowTree9879(t,
		"set security nat destination rule-set rs1 rule r-exempt match destination-address 192.0.2.10/32",
		"set security nat destination rule-set rs1 rule r-exempt then destination-nat off",
		"set security nat destination rule-set rs1 rule r-dnat match destination-address 192.0.2.10/32",
		"set security nat destination rule-set rs1 rule r-dnat match destination-port 80",
		"set security nat destination rule-set rs1 rule r-dnat then destination-nat pool p1",
	)
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatalf("CompileConfig accepted a broad off shadowed by a narrower later translate (want reject)")
	}
	for _, want := range []string{"rs1", "r-exempt", "r-dnat", "shadowed", "9879"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("reject does not name %q: %v", want, err)
		}
	}
}

func TestDNATOffShadowProtoTierRejected_9879(t *testing.T) {
	tree := offShadowTree9879(t,
		"set security nat destination rule-set rs1 rule r-exempt match destination-address 192.0.2.10/32",
		"set security nat destination rule-set rs1 rule r-exempt then destination-nat off",
		"set security nat destination rule-set rs1 rule r-dnat match destination-address 192.0.2.10/32",
		"set security nat destination rule-set rs1 rule r-dnat match protocol tcp",
		"set security nat destination rule-set rs1 rule r-dnat then destination-nat pool p1",
	)
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatalf("CompileConfig accepted an any-protocol off shadowed by a TCP-pinned later translate (want reject)")
	}
	if !strings.Contains(err.Error(), "r-dnat") || !strings.Contains(err.Error(), "9879") {
		t.Errorf("reject does not name the re-entering rule and issue: %v", err)
	}
}

func TestDNATOffShadowPrefixTierRejected_9879(t *testing.T) {
	tree := offShadowTree9879(t,
		"set security nat destination rule-set rs1 rule r-exempt match destination-address 203.0.113.0/24",
		"set security nat destination rule-set rs1 rule r-exempt then destination-nat off",
		"set security nat destination rule-set rs1 rule r-dnat match destination-address 203.0.113.50/32",
		"set security nat destination rule-set rs1 rule r-dnat then destination-nat pool p1",
	)
	if _, err := CompileConfig(tree); err == nil {
		t.Fatalf("CompileConfig accepted a /24 off shadowed by a host translate inside it (want reject)")
	}
}

func TestDNATOffShadowLongerPrefixRejected_9879(t *testing.T) {
	tree := offShadowTree9879(t,
		"set security nat destination rule-set rs1 rule r-exempt match destination-address 203.0.113.0/24",
		"set security nat destination rule-set rs1 rule r-exempt match protocol tcp",
		"set security nat destination rule-set rs1 rule r-exempt then destination-nat off",
		"set security nat destination rule-set rs1 rule r-dnat match destination-address 203.0.113.64/26",
		"set security nat destination rule-set rs1 rule r-dnat match protocol tcp",
		"set security nat destination rule-set rs1 rule r-dnat then destination-nat pool p1",
	)
	if _, err := CompileConfig(tree); err == nil {
		t.Fatalf("CompileConfig accepted a /24 off shadowed by a /26 translate inside it (want reject)")
	}
}

func TestDNATOffShadowLenientWarns_9879(t *testing.T) {
	tree := offShadowTree9879(t,
		"set security nat destination rule-set rs1 rule r-exempt match destination-address 192.0.2.10/32",
		"set security nat destination rule-set rs1 rule r-exempt then destination-nat off",
		"set security nat destination rule-set rs1 rule r-dnat match destination-address 192.0.2.10/32",
		"set security nat destination rule-set rs1 rule r-dnat match destination-port 80",
		"set security nat destination rule-set rs1 rule r-dnat then destination-nat pool p1",
	)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient rejected the losing shape (want warn-and-compile): %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "shadowed") && strings.Contains(w, "r-dnat") {
			found = true
		}
	}
	if !found {
		t.Fatalf("lenient path produced no off-shadow warning (warnings=%q)", cfg.Warnings)
	}
}

// TestDNATOffShadowControlsCommitClean_9879 pins the shapes the gate must NOT
// fire on: same-tier ties (config order wins — the off holds), reversed order
// (no inversion under either semantic), disjoint matches, and the documented
// out-of-scope shapes (application, cross-rule-set).
func TestDNATOffShadowControlsCommitClean_9879(t *testing.T) {
	cases := []struct {
		name string
		cmds []string
	}{
		{
			// Same specificity, off first: one tier, config order wins, the
			// off holds (the #3844 shape — must keep committing).
			"same-specificity-off-first",
			[]string{
				"set security nat destination rule-set rs1 rule r-exempt match destination-address 192.0.2.10/32",
				"set security nat destination rule-set rs1 rule r-exempt then destination-nat off",
				"set security nat destination rule-set rs1 rule r-dnat match destination-address 192.0.2.10/32",
				"set security nat destination rule-set rs1 rule r-dnat then destination-nat pool p1",
			},
		},
		{
			// Translate first, broader off later: the translate wins under
			// both Junos first-match and xpf specificity — no inversion.
			"translate-first",
			[]string{
				"set security nat destination rule-set rs1 rule r-dnat match destination-address 192.0.2.10/32",
				"set security nat destination rule-set rs1 rule r-dnat match destination-port 80",
				"set security nat destination rule-set rs1 rule r-dnat then destination-nat pool p1",
				"set security nat destination rule-set rs1 rule r-exempt match destination-address 192.0.2.10/32",
				"set security nat destination rule-set rs1 rule r-exempt then destination-nat off",
			},
		},
		{
			// Disjoint destinations: no shared space, nothing re-entered.
			"disjoint-destinations",
			[]string{
				"set security nat destination rule-set rs1 rule r-exempt match destination-address 192.0.2.10/32",
				"set security nat destination rule-set rs1 rule r-exempt then destination-nat off",
				"set security nat destination rule-set rs1 rule r-dnat match destination-address 192.0.2.20/32",
				"set security nat destination rule-set rs1 rule r-dnat match destination-port 80",
				"set security nat destination rule-set rs1 rule r-dnat then destination-nat pool p1",
			},
		},
		{
			// Disjoint protocols: the off exempts TCP only; the UDP
			// translate cannot re-enter it.
			"disjoint-protocols",
			[]string{
				"set security nat destination rule-set rs1 rule r-exempt match destination-address 192.0.2.10/32",
				"set security nat destination rule-set rs1 rule r-exempt match protocol tcp",
				"set security nat destination rule-set rs1 rule r-exempt then destination-nat off",
				"set security nat destination rule-set rs1 rule r-dnat match destination-address 192.0.2.10/32",
				"set security nat destination rule-set rs1 rule r-dnat match protocol udp",
				"set security nat destination rule-set rs1 rule r-dnat match destination-port 80",
				"set security nat destination rule-set rs1 rule r-dnat then destination-nat pool p1",
			},
		},
		{
			// A ranged translate installs a wildcard-keyed row (#3449): the
			// SAME tier as the off wildcard, so config order wins and the
			// off holds.
			"range-translate-same-tier",
			[]string{
				"set security nat destination rule-set rs1 rule r-exempt match destination-address 192.0.2.10/32",
				"set security nat destination rule-set rs1 rule r-exempt match protocol tcp",
				"set security nat destination rule-set rs1 rule r-exempt then destination-nat off",
				"set security nat destination rule-set rs1 rule r-dnat match destination-address 192.0.2.10/32",
				"set security nat destination rule-set rs1 rule r-dnat match protocol tcp",
				"set security nat destination rule-set rs1 rule r-dnat match destination-port 1000 to 2000",
				"set security nat destination rule-set rs1 rule r-dnat then destination-nat pool p1",
			},
		},
		{
			// An any-protocol off WITH an exact port installs TCP+UDP exact
			// rows (#6462): the same tier as the TCP translate, so the off
			// holds.
			"anyproto-port-off-same-tier",
			[]string{
				"set security nat destination rule-set rs1 rule r-exempt match destination-address 192.0.2.10/32",
				"set security nat destination rule-set rs1 rule r-exempt match destination-port 80",
				"set security nat destination rule-set rs1 rule r-exempt then destination-nat off",
				"set security nat destination rule-set rs1 rule r-dnat match destination-address 192.0.2.10/32",
				"set security nat destination rule-set rs1 rule r-dnat match protocol tcp",
				"set security nat destination rule-set rs1 rule r-dnat match destination-port 80",
				"set security nat destination rule-set rs1 rule r-dnat then destination-nat pool p1",
			},
		},
		{
			// Equal prefixes: an LPM length tie the off wins by order.
			"equal-prefixes",
			[]string{
				"set security nat destination rule-set rs1 rule r-exempt match destination-address 203.0.113.0/24",
				"set security nat destination rule-set rs1 rule r-exempt then destination-nat off",
				"set security nat destination rule-set rs1 rule r-dnat match destination-address 203.0.113.0/24",
				"set security nat destination rule-set rs1 rule r-dnat then destination-nat pool p1",
			},
		},
		{
			// An off host beats a translate prefix for their shared address
			// (exact map precedes LPM).
			"off-host-beats-translate-prefix",
			[]string{
				"set security nat destination rule-set rs1 rule r-exempt match destination-address 203.0.113.50/32",
				"set security nat destination rule-set rs1 rule r-exempt then destination-nat off",
				"set security nat destination rule-set rs1 rule r-dnat match destination-address 203.0.113.0/24",
				"set security nat destination rule-set rs1 rule r-dnat then destination-nat pool p1",
			},
		},
		{
			// `match application` is out of scope (builder expansion too
			// complex to mirror): skipped, never fired on.
			"application-match-skipped",
			[]string{
				"set security nat destination rule-set rs1 rule r-exempt match destination-address 192.0.2.10/32",
				"set security nat destination rule-set rs1 rule r-exempt then destination-nat off",
				"set security nat destination rule-set rs1 rule r-dnat match destination-address 192.0.2.10/32",
				"set security nat destination rule-set rs1 rule r-dnat match application junos-http",
				"set security nat destination rule-set rs1 rule r-dnat then destination-nat pool p1",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := offShadowTree9879(t, tc.cmds...)
			cfg, err := CompileConfig(tree)
			if err != nil {
				t.Fatalf("CompileConfig rejected control %q (want clean): %v", tc.name, err)
			}
			for _, w := range cfg.Warnings {
				if strings.Contains(w, "shadowed") {
					t.Fatalf("control %q produced an off-shadow warning: %q", tc.name, w)
				}
			}
		})
	}
}

// TestDNATOffShadowCrossRuleSetSkipped_9879 pins the documented scope: pairs
// across rule-sets are not analyzed (from-scope overlap modeling is a
// follow-up), so a broad off in one rule-set and a narrower translate in
// another commits clean.
func TestDNATOffShadowCrossRuleSetSkipped_9879(t *testing.T) {
	tree := buildTree(t, []string{
		"set security nat destination pool p1 address 192.168.1.10",
		"set security nat destination rule-set rs1 from zone untrust",
		"set security nat destination rule-set rs1 rule r-exempt match destination-address 192.0.2.10/32",
		"set security nat destination rule-set rs1 rule r-exempt then destination-nat off",
		"set security nat destination rule-set rs2 from zone untrust",
		"set security nat destination rule-set rs2 rule r-dnat match destination-address 192.0.2.10/32",
		"set security nat destination rule-set rs2 rule r-dnat match destination-port 80",
		"set security nat destination rule-set rs2 rule r-dnat then destination-nat pool p1",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig rejected the cross-rule-set pair (out of scope, want clean): %v", err)
	}
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "shadowed") {
			t.Fatalf("cross-rule-set pair produced an off-shadow warning: %q", w)
		}
	}
}

// TestDNATOffShadowReasonTiers_9879 exercises the shared predicate directly on
// tier shapes awkward to spell in set syntax: an off exact port holding
// against a translate wildcard (off wins its tier), a translate range tying an
// off range (same wildcard key), and numeric-vs-name protocol spellings (a
// documented miss, never a fire).
func TestDNATOffShadowReasonTiers_9879(t *testing.T) {
	mkRule := func(name, dst string, ports []int, protos []string, then NATThen) *NATRule {
		return &NATRule{
			Name: name,
			Match: NATMatch{
				DestinationAddress: dst,
				DestinationPorts:   ports,
				Protocols:          protos,
			},
			Then: then,
		}
	}
	off := func(name, dst string, ports []int, protos []string) *NATRule {
		return mkRule(name, dst, ports, protos, NATThen{Type: NATDestination, Off: true})
	}
	tr := func(name, dst string, ports []int, protos []string) *NATRule {
		return mkRule(name, dst, ports, protos, NATThen{Type: NATDestination, PoolName: "p1"})
	}
	cases := []struct {
		name    string
		offRule *NATRule
		trRule  *NATRule
		wantHit bool
	}{
		{"off-exact-holds-vs-translate-wild", off("o", "192.0.2.10", []int{80}, []string{"tcp"}), tr("t", "192.0.2.10", nil, []string{"tcp"}), false},
		{"off-wild-loses-vs-translate-exact", off("o", "192.0.2.10", nil, []string{"tcp"}), tr("t", "192.0.2.10", []int{80}, []string{"tcp"}), true},
		{"range-ties-range", off("o", "192.0.2.10", []int{1000, 1001, 1002}, []string{"tcp"}), tr("t", "192.0.2.10", []int{1001, 1002, 1003}, []string{"tcp"}), false},
		{"off-range-loses-vs-translate-exact-in-range", off("o", "192.0.2.10", []int{1000, 1001, 1002}, []string{"tcp"}), tr("t", "192.0.2.10", []int{1001}, []string{"tcp"}), true},
		{"numeric-proto-spelling-miss", off("o", "192.0.2.10", nil, []string{"tcp"}), tr("t", "192.0.2.10", []int{80}, []string{"6"}), false},
		{"numeric-proto-spelling-hit", off("o", "192.0.2.10", nil, []string{"6"}), tr("t", "192.0.2.10", []int{80}, []string{"6"}), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rs := &NATRuleSet{Name: "rs1", Rules: []*NATRule{tc.offRule, tc.trRule}}
			// The translate pool must be DEFINED: an undefined pool leaves
			// the translate NOT INSTALLED, which correctly yields no shadow
			// (GPT-3) — fixtures that omit it conceal the disposition.
			dnat := &DestinationNATConfig{
				Pools:    map[string]*NATPool{"p1": {Name: "p1", Address: "192.168.1.10"}},
				RuleSets: []*NATRuleSet{rs},
			}
			got := DNATOffShadowReason(dnat, rs, tc.offRule)
			if tc.wantHit && got == "" {
				t.Fatalf("predicate missed a shadowing pair (want reason)")
			}
			if !tc.wantHit && got != "" {
				t.Fatalf("predicate fired on a non-shadowing pair: %q", got)
			}
			if tc.wantHit && !strings.Contains(got, `"t"`) {
				t.Fatalf("reason does not name the translate rule: %q", got)
			}
		})
	}
}

// SPARK-§6 + parent-review (1a): a prefix-prefix port-tier mismatch must NOT
// fire. An exact-port bucket is probed before the wildcard-port bucket even
// when the wildcard side has the longer prefix: the /24 exact-port `off`
// HOLDS against the /26 wildcard-port translate for port 80 (the pairwise
// model falsely rejected this via destNarrower => outerDecides).
func TestDNATOffShadowPrefixPortMismatchClean_9879(t *testing.T) {
	tree := offShadowTree9879(t,
		"set security nat destination rule-set rs1 rule r-exempt match destination-address 203.0.113.0/24",
		"set security nat destination rule-set rs1 rule r-exempt match protocol tcp",
		"set security nat destination rule-set rs1 rule r-exempt match destination-port 80",
		"set security nat destination rule-set rs1 rule r-exempt then destination-nat off",
		"set security nat destination rule-set rs1 rule r-dnat match destination-address 203.0.113.64/26",
		"set security nat destination rule-set rs1 rule r-dnat match protocol tcp",
		"set security nat destination rule-set rs1 rule r-dnat then destination-nat pool p1",
	)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig rejected a held exemption (want clean): %v", err)
	}
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "shadowed") {
			t.Fatalf("held exemption produced an off-shadow warning: %q", w)
		}
	}
}

// Parent-review (1a): a translate RANGE installs a wildcard-keyed row, which
// never outranks an off EXACT port it contains: the off wins the shared port
// (exact bucket first), and the range's other ports are outside the exemption.
// Must commit clean.
func TestDNATOffShadowExactHoldsVsRangeClean_9879(t *testing.T) {
	tree := offShadowTree9879(t,
		"set security nat destination rule-set rs1 rule r-exempt match destination-address 192.0.2.10/32",
		"set security nat destination rule-set rs1 rule r-exempt match protocol tcp",
		"set security nat destination rule-set rs1 rule r-exempt match destination-port 80",
		"set security nat destination rule-set rs1 rule r-exempt then destination-nat off",
		"set security nat destination rule-set rs1 rule r-dnat match destination-address 192.0.2.10/32",
		"set security nat destination rule-set rs1 rule r-dnat match protocol tcp",
		"set security nat destination rule-set rs1 rule r-dnat match destination-port 80 to 90",
		"set security nat destination rule-set rs1 rule r-dnat then destination-nat pool p1",
	)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig rejected a held exemption (want clean): %v", err)
	}
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "shadowed") {
			t.Fatalf("held exemption produced an off-shadow warning: %q", w)
		}
	}
}

// Parent-review (1b): EVERY host tier precedes EVERY prefix tier, so an
// any-protocol HOST translate beats a pinned-protocol PREFIX `off` despite
// losing the protocol tier in isolation (the pairwise model skipped
// pinned-vs-ANY and missed the shadow). Must reject.
func TestDNATOffShadowHostBeatsPrefixAnyProtoRejected_9879(t *testing.T) {
	tree := offShadowTree9879(t,
		"set security nat destination rule-set rs1 rule r-exempt match destination-address 203.0.113.0/24",
		"set security nat destination rule-set rs1 rule r-exempt match protocol tcp",
		"set security nat destination rule-set rs1 rule r-exempt then destination-nat off",
		"set security nat destination rule-set rs1 rule r-dnat match destination-address 203.0.113.50/32",
		"set security nat destination rule-set rs1 rule r-dnat then destination-nat pool p1",
	)
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatalf("CompileConfig accepted an any-protocol host translate re-entering a pinned prefix off (want reject)")
	}
	if !strings.Contains(err.Error(), "r-dnat") || !strings.Contains(err.Error(), "shadowed") {
		t.Fatalf("reject does not name the shadow: %v", err)
	}
}

// GPT-2: a multi-address exemption carrying BOTH a prefix and its contained
// host holds for the host via its exact-host entry (same-tier order win),
// even though the prefix cell alone looks weaker than the same-host
// translate. The witness search evaluates the exemption's BEST entry, never
// its weakest cell. Must commit clean.
func TestDNATOffShadowMultiAddressExemptionClean_9879(t *testing.T) {
	tree := offShadowTree9879(t,
		"set security nat destination rule-set rs1 rule r-exempt match destination-address [ 203.0.113.0/24 203.0.113.50/32 ]",
		"set security nat destination rule-set rs1 rule r-exempt then destination-nat off",
		"set security nat destination rule-set rs1 rule r-dnat match destination-address 203.0.113.50/32",
		"set security nat destination rule-set rs1 rule r-dnat then destination-nat pool p1",
	)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig rejected a held multi-address exemption (want clean): %v", err)
	}
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "shadowed") {
			t.Fatalf("held exemption produced an off-shadow warning: %q", w)
		}
	}
}

// GPT-3/SPARK-§3: a translate rule that installs NOTHING (undefined pool,
// invalid pool, unknown #9877 leaves) cannot re-enter anything: no shadow
// warning on the lenient path (which tolerates the exclusion), and the
// exclusion warning — not a TRANSLATED claim — is what the operator sees.
func TestDNATOffShadowExcludedTranslateSkipped_9879(t *testing.T) {
	t.Run("undefined-pool", func(t *testing.T) {
		tree := buildTree(t, []string{
			"set security nat destination pool p1 address 192.168.1.10",
			"set security nat destination rule-set rs1 from zone untrust",
			"set security nat destination rule-set rs1 rule r-exempt match destination-address 192.0.2.10/32",
			"set security nat destination rule-set rs1 rule r-exempt then destination-nat off",
			"set security nat destination rule-set rs1 rule r-dnat match destination-address 192.0.2.10/32",
			"set security nat destination rule-set rs1 rule r-dnat match destination-port 80",
			"set security nat destination rule-set rs1 rule r-dnat then destination-nat pool p-missing",
		})
		cfg, err := CompileConfigLenient(tree)
		if err != nil {
			t.Fatalf("CompileConfigLenient rejected (want warn-and-compile): %v", err)
		}
		poolWarn, shadowWarn := false, false
		for _, w := range cfg.Warnings {
			if strings.Contains(w, "p-missing") {
				poolWarn = true
			}
			if strings.Contains(w, "shadowed") {
				shadowWarn = true
			}
		}
		if !poolWarn {
			t.Fatalf("no pool-reference warning for the undefined pool (warnings=%q)", cfg.Warnings)
		}
		if shadowWarn {
			t.Fatalf("excluded translate yielded a shadow warning (it installs nothing): %q", cfg.Warnings)
		}
	})
	t.Run("invalid-pool", func(t *testing.T) {
		tree := buildTree(t, []string{
			"set security nat destination pool p1 address 10.0.0.0/24",
			"set security nat destination rule-set rs1 from zone untrust",
			"set security nat destination rule-set rs1 rule r-exempt match destination-address 192.0.2.10/32",
			"set security nat destination rule-set rs1 rule r-exempt then destination-nat off",
			"set security nat destination rule-set rs1 rule r-dnat match destination-address 192.0.2.10/32",
			"set security nat destination rule-set rs1 rule r-dnat match destination-port 80",
			"set security nat destination rule-set rs1 rule r-dnat then destination-nat pool p1",
		})
		cfg, err := CompileConfigLenient(tree)
		if err != nil {
			t.Fatalf("CompileConfigLenient rejected (want warn-and-compile): %v", err)
		}
		poolWarn, shadowWarn := false, false
		for _, w := range cfg.Warnings {
			if strings.Contains(w, "p1") && strings.Contains(w, "pool") {
				poolWarn = true
			}
			if strings.Contains(w, "shadowed") {
				shadowWarn = true
			}
		}
		if !poolWarn {
			t.Fatalf("no pool warning for the non-host pool address (warnings=%q)", cfg.Warnings)
		}
		if shadowWarn {
			t.Fatalf("excluded translate yielded a shadow warning (it installs nothing): %q", cfg.Warnings)
		}
	})
	t.Run("unknown-leaf", func(t *testing.T) {
		tree := buildTree(t, []string{
			"set security nat destination pool p1 address 192.168.1.10",
			"set security nat destination rule-set rs1 from zone untrust",
			"set security nat destination rule-set rs1 rule r-exempt match destination-address 192.0.2.10/32",
			"set security nat destination rule-set rs1 rule r-exempt then destination-nat off",
			"set security nat destination rule-set rs1 rule r-dnat match destination-address 192.0.2.10/32",
			"set security nat destination rule-set rs1 rule r-dnat match soruce-address 10.0.0.0/8",
			"set security nat destination rule-set rs1 rule r-dnat match destination-port 80",
			"set security nat destination rule-set rs1 rule r-dnat then destination-nat pool p1",
		})
		cfg, err := CompileConfigLenient(tree)
		if err != nil {
			t.Fatalf("CompileConfigLenient rejected (want warn-and-compile): %v", err)
		}
		unknownWarn, shadowWarn := false, false
		for _, w := range cfg.Warnings {
			if strings.Contains(w, "soruce-address") {
				unknownWarn = true
			}
			if strings.Contains(w, "shadowed") {
				shadowWarn = true
			}
		}
		if !unknownWarn {
			t.Fatalf("no unknown-leaf warning for the typo (warnings=%q)", cfg.Warnings)
		}
		if shadowWarn {
			t.Fatalf("excluded translate yielded a shadow warning (it installs nothing): %q", cfg.Warnings)
		}
	})
}

// GPT-4/SPARK-§2: the #9879 gate runs last in the NAT uniform segment, BEFORE
// later uniform domains (DHCPApp, Filter, ...) and tailgates — so a config
// tripping both #9879 and a later-domain gate reports #9879 first, by design.
// Pinned here with an undefined-policer Filter trip after a losing DNAT shape.
func TestDNATOffShadowWinsOverLaterDomain_9879(t *testing.T) {
	tree := buildTree(t, []string{
		"set security nat destination pool p1 address 192.168.1.10",
		"set security nat destination rule-set rs1 from zone untrust",
		"set security nat destination rule-set rs1 rule r-exempt match destination-address 192.0.2.10/32",
		"set security nat destination rule-set rs1 rule r-exempt then destination-nat off",
		"set security nat destination rule-set rs1 rule r-dnat match destination-address 192.0.2.10/32",
		"set security nat destination rule-set rs1 rule r-dnat match destination-port 80",
		"set security nat destination rule-set rs1 rule r-dnat then destination-nat pool p1",
		"set firewall family inet filter f1 term t1 then policer no-such-policer",
		"set firewall family inet filter f1 term t1 then accept",
	})
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatalf("CompileConfig accepted (want #9879 reject winning over the later Filter trip)")
	}
	if !strings.Contains(err.Error(), "shadowed") {
		t.Fatalf("first error is not the #9879 shadow (want #9879 winning): %v", err)
	}
	if strings.Contains(err.Error(), "no-such-policer") {
		t.Fatalf("later-domain error won over #9879 (want #9879 first): %v", err)
	}
}

// Non-vacuity companion: the review cells above assert dispositions (clean /
// reject / no-shadow-warning) that would also hold if a fixture mis-parsed
// into a weaker shape. This pins the compiled shapes themselves.
func TestDNATOffShadowReviewCellsParseAsIntended_9879(t *testing.T) {
	shapeOf := func(t *testing.T, cmds ...string) *NATRuleSet {
		t.Helper()
		tree := offShadowTree9879(t, cmds...)
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("CompileConfig: %v", err)
		}
		for _, rs := range cfg.Security.NAT.Destination.RuleSets {
			if rs.Name == "rs1" {
				return rs
			}
		}
		t.Fatalf("rule-set rs1 missing")
		return nil
	}
	t.Run("prefix-port-mismatch-shapes", func(t *testing.T) {
		rs := shapeOf(t,
			"set security nat destination rule-set rs1 rule r-exempt match destination-address 203.0.113.0/24",
			"set security nat destination rule-set rs1 rule r-exempt match protocol tcp",
			"set security nat destination rule-set rs1 rule r-exempt match destination-port 80",
			"set security nat destination rule-set rs1 rule r-exempt then destination-nat off",
			"set security nat destination rule-set rs1 rule r-dnat match destination-address 203.0.113.64/26",
			"set security nat destination rule-set rs1 rule r-dnat match protocol tcp",
			"set security nat destination rule-set rs1 rule r-dnat then destination-nat pool p1",
		)
		if got := rs.Rules[0].Match.DestinationPorts; len(got) != 1 || got[0] != 80 {
			t.Fatalf("off ports = %v, want [80] (exact)", got)
		}
		if got := rs.Rules[1].Match.DestinationPorts; len(got) != 0 {
			t.Fatalf("translate ports = %v, want wild", got)
		}
	})
	t.Run("multi-address-exemption-has-two-dests", func(t *testing.T) {
		rs := shapeOf(t,
			"set security nat destination rule-set rs1 rule r-exempt match destination-address [ 203.0.113.0/24 203.0.113.50/32 ]",
			"set security nat destination rule-set rs1 rule r-exempt then destination-nat off",
			"set security nat destination rule-set rs1 rule r-dnat match destination-address 203.0.113.50/32",
			"set security nat destination rule-set rs1 rule r-dnat then destination-nat pool p1",
		)
		if got := len(rs.Rules[0].Match.DestinationAddresses); got != 2 {
			t.Fatalf("off dests = %d, want 2 (prefix+host)", got)
		}
	})
	t.Run("later-domain-trips-alone", func(t *testing.T) {
		tree := buildTree(t, []string{
			"set security nat destination pool p1 address 192.168.1.10",
			"set security nat destination rule-set rs1 from zone untrust",
			"set security nat destination rule-set rs1 rule r-exempt match destination-address 192.0.2.10/32",
			"set security nat destination rule-set rs1 rule r-exempt then destination-nat off",
			"set security nat destination rule-set rs1 rule r-dnat match destination-address 192.0.2.10/32",
			"set security nat destination rule-set rs1 rule r-dnat then destination-nat pool p1",
			"set firewall family inet filter f1 term t1 then policer no-such-policer",
			"set firewall family inet filter f1 term t1 then accept",
		})
		_, err := CompileConfig(tree)
		if err == nil || !strings.Contains(err.Error(), "no-such-policer") {
			t.Fatalf("Filter trip alone = %v, want undefined-policer error (ordering pin would be vacuous)", err)
		}
	})
}
