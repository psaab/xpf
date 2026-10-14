package cli

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #12901: the local CLI `show security policies` STANDARD view (the
// non-brief/non-detail dispatcher branch) rendered a policy's match addresses
// without the source/destination-address-excluded inversion, printed
// ", log" for an EMPTY PolicyLog block (a leniently-loaded bare `then log`,
// #3060 — logging that emits no session records), and the BRIEF view read
// counters for quarantined rules, showing "n/a" plus the "not yet published
// by the dataplane" note for counters the quarantine scrub guarantees will
// never arrive. These are the fail-on-revert guards: revert any leg and the
// assertions below go RED.

// standardViewCLI12901 builds a committed store whose active config carries
// the #12901 shapes: an inverted (excluded) source list, a plain control
// rule, a real session-init log, a bare (empty) log block, and a global with
// an inverted destination list and its own bare log. Post-commit mutation is
// the established fixture pattern (see quarantinePolicyCLI10530) and mirrors
// what the tolerant-load / peer-sync path leaves in an active config.
func standardViewCLI12901(t *testing.T) *CLI {
	t.Helper()
	store := newPolicyHitCountCLIStore(t, false)
	cfg := store.ActiveConfig()
	cfg.Security.Policies = []*config.ZonePairPolicies{
		{
			FromZone: "trust",
			ToZone:   "untrust",
			Policies: []*config.Policy{
				{
					Name:   "except-src",
					Action: config.PolicyDeny,
					Match: config.PolicyMatch{
						SourceAddresses:       []string{"bad-net"},
						SourceAddressExcluded: true,
						DestinationAddresses:  []string{"any"},
					},
				},
				{
					Name:   "plain-rule",
					Action: config.PolicyPermit,
					Match: config.PolicyMatch{
						SourceAddresses:      []string{"any"},
						DestinationAddresses: []string{"any"},
					},
				},
				{
					Name:   "logged-rule",
					Action: config.PolicyPermit,
					Match: config.PolicyMatch{
						SourceAddresses:      []string{"any"},
						DestinationAddresses: []string{"any"},
					},
					Log: &config.PolicyLog{SessionInit: true},
				},
				{
					Name:   "bare-log-rule",
					Action: config.PolicyPermit,
					Match: config.PolicyMatch{
						SourceAddresses:      []string{"any"},
						DestinationAddresses: []string{"any"},
					},
					Log: &config.PolicyLog{},
				},
			},
		},
	}
	cfg.Security.GlobalPolicies = []*config.Policy{
		{
			Name:   "global-except-dst",
			Action: config.PolicyDeny,
			Match: config.PolicyMatch{
				SourceAddresses:            []string{"any"},
				DestinationAddresses:       []string{"mgmt-net"},
				DestinationAddressExcluded: true,
			},
		},
		{
			Name:   "global-bare-log",
			Action: config.PolicyPermit,
			Match: config.PolicyMatch{
				SourceAddresses:      []string{"any"},
				DestinationAddresses: []string{"any"},
			},
			Log: &config.PolicyLog{},
		},
	}
	return &CLI{store: store}
}

// stdActionLine returns the block's "Action:" line, so a ", log" suffix (or
// its absence) is asserted on the exact rendered token.
func stdActionLine(t *testing.T, block string) string {
	t.Helper()
	for _, line := range strings.Split(block, "\n") {
		if strings.Contains(line, "Action:") {
			return line
		}
	}
	t.Fatalf("no Action line in block:\n%s", block)
	return ""
}

func Test_12901_StandardViewRendersAddressExclusion(t *testing.T) {
	c := standardViewCLI12901(t)
	out := captureStdout(t, func() {
		if err := c.handleShowSecurity([]string{"policies"}); err != nil {
			t.Fatalf("handleShowSecurity(policies): %v", err)
		}
	})

	// Zone-pair rule: source inverted, destination not.
	block := flatPolicyBlock(t, out, "except-src")
	if !strings.Contains(block, "Source addresses: bad-net (except)") {
		t.Fatalf("except-src block = %q, want \"Source addresses: bad-net (except)\" "+
			"(standard view dropped the source-address-excluded inversion — #12901 regression)", block)
	}
	if strings.Contains(block, "Destination addresses: any (except)") {
		t.Fatalf("except-src block = %q, destination is NOT excluded but rendered (except)", block)
	}

	// Plain control: no inversion, bit-identical to the old render.
	plain := flatPolicyBlock(t, out, "plain-rule")
	if strings.Contains(plain, "(except)") {
		t.Fatalf("plain-rule block = %q, want no (except) annotation for an un-inverted policy", plain)
	}

	// Global rule: destination inverted, source not.
	g := flatPolicyBlock(t, out, "global-except-dst")
	if !strings.Contains(g, "Destination addresses: mgmt-net (except)") {
		t.Fatalf("global-except-dst block = %q, want \"Destination addresses: mgmt-net (except)\" "+
			"(standard view dropped the destination-address-excluded inversion — #12901 regression)", g)
	}
	if strings.Contains(g, "Source addresses: any (except)") {
		t.Fatalf("global-except-dst block = %q, source is NOT excluded but rendered (except)", g)
	}
}

func Test_12901_StandardViewLogTokenGatesOnRealModes(t *testing.T) {
	c := standardViewCLI12901(t)
	out := captureStdout(t, func() {
		if err := c.handleShowSecurity([]string{"policies"}); err != nil {
			t.Fatalf("handleShowSecurity(policies): %v", err)
		}
	})

	// A real session-init log still renders the token (control).
	if act := stdActionLine(t, flatPolicyBlock(t, out, "logged-rule")); act != "    Action: permit, log" {
		t.Fatalf("logged-rule Action line = %q, want \"    Action: permit, log\"", act)
	}

	// An EMPTY PolicyLog block must NOT read as logging — it emits no
	// session records (#3060). Zone-pair and global branches alike.
	if act := stdActionLine(t, flatPolicyBlock(t, out, "bare-log-rule")); act != "    Action: permit" {
		t.Fatalf("bare-log-rule Action line = %q, want \"    Action: permit\" "+
			"(an empty log block described the policy as logging — #12901 regression)", act)
	}
	if act := stdActionLine(t, flatPolicyBlock(t, out, "global-bare-log")); act != "    Action: permit" {
		t.Fatalf("global-bare-log Action line = %q, want \"    Action: permit\" "+
			"(an empty log block described the global policy as logging — #12901 regression)", act)
	}
}

// briefQuarantineCLI12901 builds the #10530 collision fixture (z174/z214
// fold to one StableZoneID, z214 loses and is quarantined) on a loaded
// dataplane whose bulk snapshot is EMPTY (warmupPolicyCLIDP — the measured
// warm-up state of the real userspace Manager): every read-eligible rule
// returns ErrPolicyCounterUnpublished, which is exactly the signal the brief
// view used to misattribute as "not yet published" for rules the quarantine
// scrub dropped (their counters are not late — they are never coming).
func briefQuarantineCLI12901(t *testing.T) *CLI {
	t.Helper()
	store := newPolicyHitCountCLIStore(t, true)
	cfg := store.ActiveConfig()
	if config.StableZoneID("z174") != config.StableZoneID("z214") {
		t.Fatal("test premise broken: z174/z214 no longer collide under the frozen fold")
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust": {Name: "trust"},
		"z174":  {Name: "z174"},
		"z214":  {Name: "z214"},
	}
	cfg.Security.Policies = []*config.ZonePairPolicies{
		{FromZone: "trust", ToZone: "z214", Policies: []*config.Policy{{
			Name: "loser-rule", Action: config.PolicyPermit, Count: true,
		}}},
		{FromZone: "trust", ToZone: "trust", Policies: []*config.Policy{{
			Name: "ordinary-rule", Action: config.PolicyPermit, Count: true,
		}}},
	}
	cfg.Security.GlobalPolicies = []*config.Policy{
		{Name: "dropped-global", Action: config.PolicyDeny,
			Match: config.PolicyMatch{ToZones: []string{"z214"}}},
		{Name: "live-global", Action: config.PolicyDeny},
	}
	return &CLI{store: store, dp: &warmupPolicyCLIDP{}}
}

func Test_12901_BriefGuardsQuarantinedRulesBeforeCounterRead(t *testing.T) {
	c := briefQuarantineCLI12901(t)
	out := captureStdout(t, func() {
		if err := c.handleShowSecurity([]string{"policies", "brief"}); err != nil {
			t.Fatalf("handleShowSecurity(policies brief): %v", err)
		}
	})

	// Quarantined zone-pair row: the quarantine disposition, not "n/a" —
	// and the losing zone is qualified so the row cannot read as an
	// ordinary hit.
	loser := briefRow(t, out, "loser-rule")
	if !strings.Contains(loser, config.ZoneQuarantineLiveCountersUnavailable) {
		t.Fatalf("loser-rule brief row = %q, want the live-counter-unavailable disposition "+
			"(brief read a quarantined rule's counter — #12901 regression)", loser)
	}
	if !strings.Contains(loser, "z214 "+config.ZoneQuarantinePoliciesQualifier) {
		t.Fatalf("loser-rule brief row = %q, want the quarantined to-zone qualifier", loser)
	}

	// Quarantined scoped global (its configured to-zone side is entirely
	// quarantined, so the scrub drops the whole rule — #12897).
	if dropped := briefRow(t, out, "dropped-global"); !strings.Contains(dropped, config.ZoneQuarantineLiveCountersUnavailable) {
		t.Fatalf("dropped-global brief row = %q, want the live-counter-unavailable disposition "+
			"(brief read a quarantine-dropped global's counter — #12901 regression)", dropped)
	}

	// The live rows still read their counters (unpublished here, honestly
	// reported as n/a) and ONLY they feed the "not yet published" note: 2,
	// not 4 — the quarantined rows must not be counted as merely late.
	if row := briefRow(t, out, "ordinary-rule"); !strings.Contains(row, "n/a") {
		t.Fatalf("ordinary-rule brief row = %q, want n/a (live rule, helper published nothing)", row)
	}
	if row := briefRow(t, out, "live-global"); !strings.Contains(row, "n/a") {
		t.Fatalf("live-global brief row = %q, want n/a (live rule, helper published nothing)", row)
	}
	if !strings.Contains(out, "note: 2 policy counter(s) not yet published by the dataplane") {
		t.Fatalf("brief output's unpublished-note count includes quarantined rules "+
			"(misattributing scrubbed counters as \"not yet published\"):\n%s", out)
	}
	if strings.Contains(out, "note: 4 policy counter(s)") {
		t.Fatalf("brief output counts quarantined rules in the unpublished note:\n%s", out)
	}
}
