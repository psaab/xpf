package config

import (
	"strings"
	"testing"
)

// #8447/#8573: the commit-time advisory that persistent-NAT on a cluster stops
// forwarding — and its removal, because the thing it warned about no longer
// happens.
//
// #8447 WAS: adding persistent-nat to a rule-referenced source pool on a
// clustered node DISARMED FORWARDING entirely — rx went to 0 while the
// interfaces stayed up and the config committed cleanly. The disarm was the
// deliberate #1449 contract (leases held to be helper-local and not
// HA-synchronized), so #8447 fixed the SILENCE by adding this advisory in front
// of it.
//
// #8573 removed the disarm, having measured its premise false on the loss
// userspace cluster: a persistent lease created on the active node reaches the
// standby (three sync routes — #7360, #8132, #8121), survives an RG0 failover,
// and is HONOURED after failback, the new active translating the same source
// identity to the same translated identity the other node allocated. With the
// disarm gone the advisory describes nothing: it would tell an operator that a
// working configuration stops traffic, which is worse than silence.
//
// So the advisory is gone and this file guards the ABSENCE. That is a weaker
// claim than the one it replaces, so it is paired with a positive control on
// the same helper — otherwise a helper that compiles the wrong tree, or a
// ValidateConfig that returns nothing at all, reads as a clean pass.
//
// The PREDICATE stays. UsesPersistentSourceNATPool has a second live consumer
// (ensurePersistentSourceNATProtocolLocked, the MinProtocolPersistentSourceNAT
// floor), so its contract is still load-bearing and is still bound below.

// warningsFor compiles set-lines through the production path and returns every
// commit warning. Returning ALL of them, rather than filtering to the phrase
// this file used to look for, is deliberate: a phrase filter cannot see the
// advisory come back under a rewording.
func warningsFor8573(t *testing.T, setLines []string) []string {
	t.Helper()
	setLines = prependNATZoneDefs15001(setLines)
	tree := &ConfigTree{}
	for _, line := range setLines {
		toks, err := ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := tree.SetPath(toks); err != nil {
			t.Fatalf("SetPath(%q): %v", line, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	return ValidateConfig(cfg)
}

var natBase8447 = []string{
	`set security nat source pool p1 address 172.16.80.200/32`,
	`set security nat source pool p1 port range 51400 to 51499`,
	`set security nat source rule-set rs1 from zone lan`,
	`set security nat source rule-set rs1 to zone wan`,
	`set security nat source rule-set rs1 rule r1 then source-nat pool p1`,
}

var clusterLines8447 = []string{
	`set chassis cluster cluster-id 1`,
	`set chassis cluster node 0`,
	`set chassis cluster authentication-key "s3cr3t-probe-key"`,
}

// #8573: the clustered persistent-NAT config that #8447 warned about must now
// commit with NO warning about forwarding, persistent-nat, or HA.
//
// RED ON REVERT: restore persistentNATClusterForwardingWarnings and its
// registration in ValidateConfig and this fails on the first substring.
func TestClusteredPersistentNATNoLongerWarns8573(t *testing.T) {
	lines := append([]string{}, natBase8447...)
	lines = append(lines, `set security nat source pool p1 persistent-nat permit any-remote-host`)
	lines = append(lines, clusterLines8447...)

	got := warningsFor8573(t, lines)
	for _, w := range got {
		low := strings.ToLower(w)
		if !strings.Contains(low, "persistent-nat") {
			continue
		}
		// Any warning naming persistent-nat AND a forwarding/HA consequence is
		// the retired advisory, however it is worded.
		for _, banned := range []string{"forward", "ha-synchronized", "ha synchron", "transit", "disarm"} {
			if strings.Contains(low, banned) {
				t.Errorf("a persistent-nat forwarding advisory is back (%q): %q\n\n"+
					"#8573 measured that clustered persistent-NAT leases DO reach the "+
					"standby and ARE honoured after failover, and removed the disarm. "+
					"Warning here tells an operator a working config stops traffic.",
					banned, w)
				break
			}
		}
	}

	// POSITIVE CONTROL on the same helper. Without it, a helper that silently
	// compiled an empty tree — or a ValidateConfig that lost its warning list —
	// would satisfy the loop above by returning nothing at all.
	ctrl := append([]string{}, lines...)
	ctrl = append(ctrl,
		`set security nat source pool addr-only address 172.16.80.210/32`,
		`set security nat source pool addr-only port no-translation`,
		`set security nat source rule-set rs1 rule r2 then source-nat pool addr-only`,
		`set security nat source pool-utilization-alarm raise-threshold 80 clear-threshold 70`,
	)
	var sawControl bool
	for _, w := range warningsFor8573(t, ctrl) {
		if strings.Contains(w, "pool-utilization-alarm") {
			sawControl = true
			break
		}
	}
	if !sawControl {
		t.Fatal("the positive control produced no #7361 pool-utilization-alarm warning, " +
			"so this helper cannot observe a warning at all and the absence " +
			"assertion above proves nothing")
	}
}

// The predicate contract, kept. UsesPersistentSourceNATPool no longer gates
// forwarding, but ensurePersistentSourceNATProtocolLocked reads it to raise the
// helper protocol floor to MinProtocolPersistentSourceNAT — so a wrong answer
// still ships persistent-NAT config to a helper that cannot honour it.
//
// It is keyed on the RULE, not the pool table: a pool no rule references
// translates nothing.
func TestTheAdvisoryPredicateIsTheGatePredicate8447(t *testing.T) {
	build := func(lines []string) *Config {
		t.Helper()
		tree := &ConfigTree{}
		for _, line := range lines {
			toks, err := ParseSetCommand(line)
			if err != nil {
				t.Fatalf("ParseSetCommand(%q): %v", line, err)
			}
			if err := tree.SetPath(toks); err != nil {
				t.Fatalf("SetPath(%q): %v", line, err)
			}
		}
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("CompileConfig: %v", err)
		}
		return cfg
	}

	referenced := append([]string{}, natBase8447...)
	referenced = append(referenced, `set security nat source pool p1 persistent-nat permit any-remote-host`)
	if !UsesPersistentSourceNATPool(build(referenced)) {
		t.Error("a rule-referenced persistent-nat pool must be reported — this is the " +
			"condition that raises the helper protocol floor")
	}

	plain := build(natBase8447)
	if UsesPersistentSourceNATPool(plain) {
		t.Error("a plain pool must NOT be reported; reporting it would demand a " +
			"protocol floor from helpers that need none")
	}

	orphan := build([]string{
		`set security nat source pool orphan address 172.16.80.201/32`,
		`set security nat source pool orphan persistent-nat permit any-remote-host`,
	})
	if UsesPersistentSourceNATPool(orphan) {
		t.Error("an UNREFERENCED persistent-nat pool translates nothing and must not " +
			"be reported")
	}

	if UsesPersistentSourceNATPool(nil) {
		t.Error("a nil config must not be reported")
	}
}
