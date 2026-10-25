package config

import (
	"strings"
	"testing"
)

// #16554: the reserved `zone-local/<zone>/<name>` key was usable as an
// authored policy, global-policy, NAT, NAT64, static-NAT prefix-name, or
// address-set-member token. trust's zone-local `web` folds to the global
// key `zone-local/trust/web`; an untrust->dmz policy spelling that key was
// not rewritten, found it in the post-fold global book, and committed —
// binding trust's object on a rule whose zones never defined `web`.
//
// These tests pin: every authored reserved-prefix row rejects at strict
// commit, the own-zone authored-name control still commits and rewrites,
// and the tolerant path warns AND poisons (never enforces the other zone's
// object). All use the production ParseSetCommand + SetPath path (buildTree).

func zonelocalRefBase16554() []string {
	return []string{
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.1.1/24",
		"set interfaces ge-0/0/2 unit 0 family inet address 10.0.2.1/24",
		"set security zones security-zone trust interfaces ge-0/0/0.0",
		"set security zones security-zone untrust interfaces ge-0/0/1.0",
		"set security zones security-zone dmz interfaces ge-0/0/2.0",
		"set security zones security-zone trust address-book address web 10.1.0.0/24",
		"set security zones security-zone trust address-book address web6 2001:db8:1::/48",
		"set security zones security-zone trust address-book address host32 10.1.0.5/32",
	}
}

func withExtra16554(extra ...string) []string {
	return append(zonelocalRefBase16554(), extra...)
}

func policyLines16554(from, to, src string) []string {
	return []string{
		"set security policies from-zone " + from + " to-zone " + to + " policy p1 match source-address " + src,
		"set security policies from-zone " + from + " to-zone " + to + " policy p1 match destination-address any",
		"set security policies from-zone " + from + " to-zone " + to + " policy p1 match application any",
		"set security policies from-zone " + from + " to-zone " + to + " policy p1 then permit",
	}
}

func assertReservedReject16554(t *testing.T, lines []string) {
	t.Helper()
	_, err := CompileConfig(buildTree(t, lines))
	if err == nil {
		t.Fatalf("strict commit accepted a reserved zone-local/ reference token")
	}
	if !strings.Contains(err.Error(), "reserved") || !strings.Contains(err.Error(), "zone-local/") || !strings.Contains(err.Error(), "#16554") {
		t.Fatalf("error %q does not explain the reserved zone-local/ restriction", err.Error())
	}
}

func TestReservedZoneLocalRefPolicyCrossZoneRejected16554(t *testing.T) {
	// a04 PROBE row: untrust->dmz policy binds trust's zone-local entry.
	assertReservedReject16554(t, withExtra16554(policyLines16554("untrust", "dmz", "zone-local/trust/web")...))
	// Destination side, same back door.
	lines := withExtra16554(
		"set security policies from-zone untrust to-zone dmz policy p1 match source-address any",
		"set security policies from-zone untrust to-zone dmz policy p1 match destination-address zone-local/trust/web",
		"set security policies from-zone untrust to-zone dmz policy p1 match application any",
		"set security policies from-zone untrust to-zone dmz policy p1 then permit",
	)
	assertReservedReject16554(t, lines)
}

func TestReservedZoneLocalRefGlobalPolicyRejected16554(t *testing.T) {
	// a04 global row.
	lines := withExtra16554(
		"set security policies global policy g1 match source-address zone-local/trust/web",
		"set security policies global policy g1 match destination-address any",
		"set security policies global policy g1 match application any",
		"set security policies global policy g1 then permit",
	)
	assertReservedReject16554(t, lines)
}

func TestReservedZoneLocalRefSNATRejected16554(t *testing.T) {
	// a04 SNAT row, plus the DNAT source/destination twins.
	assertReservedReject16554(t, withExtra16554(
		"set security nat source rule-set rs1 from zone trust",
		"set security nat source rule-set rs1 to zone untrust",
		"set security nat source rule-set rs1 rule r1 match source-address-name zone-local/trust/web",
		"set security nat source rule-set rs1 rule r1 then source-nat interface",
	))
	assertReservedReject16554(t, withExtra16554(
		"set security nat source rule-set rs1 from zone trust",
		"set security nat source rule-set rs1 to zone untrust",
		"set security nat source rule-set rs1 rule r1 match destination-address-name zone-local/trust/web",
		"set security nat source rule-set rs1 rule r1 then source-nat interface",
	))
	assertReservedReject16554(t, withExtra16554(
		"set security nat destination pool dp address 10.0.0.5",
		"set security nat destination rule-set rs1 from zone untrust",
		"set security nat destination rule-set rs1 rule r1 match destination-address 203.0.113.10",
		"set security nat destination rule-set rs1 rule r1 match source-address-name zone-local/trust/web",
		"set security nat destination rule-set rs1 rule r1 then destination-nat pool dp",
	))
	assertReservedReject16554(t, withExtra16554(
		"set security nat destination pool dp address 10.0.0.5",
		"set security nat destination rule-set rs1 from zone untrust",
		"set security nat destination rule-set rs1 rule r1 match destination-address 203.0.113.10",
		"set security nat destination rule-set rs1 rule r1 match destination-address-name zone-local/trust/web",
		"set security nat destination rule-set rs1 rule r1 then destination-nat pool dp",
	))
}

func TestReservedZoneLocalRefAddressSetMemberRejected16554(t *testing.T) {
	// Global set member, zone-local set member, and nested set member.
	assertReservedReject16554(t, withExtra16554(
		"set security address-book global address-set grp address zone-local/trust/web",
	))
	assertReservedReject16554(t, withExtra16554(
		"set security zones security-zone dmz address-book address-set grp address zone-local/trust/web",
	))
	assertReservedReject16554(t, withExtra16554(
		"set security address-book global address-set outer address-set zone-local/trust/web",
	))
	assertReservedReject16554(t, withExtra16554(
		"set security address-book global address grp 10.2.0.0/24",
		"set security address-book book1 address-set grp address zone-local/trust/web",
	))
}

func TestReservedZoneLocalRefNAT64AndStaticRejected16554(t *testing.T) {
	assertReservedReject16554(t, withExtra16554(
		"set security nat source pool p64 address 100.64.0.7/32",
		"set security nat nat64 rule-set n64 prefix 64:ff9b::/96",
		"set security nat nat64 rule-set n64 source-pool p64",
		"set security nat nat64 rule-set n64 match source-address-name zone-local/trust/web6",
	))
	// A /32 zone-local entry so the static host-mask gate cannot mask the
	// reserved-prefix verdict on the strict path.
	assertReservedReject16554(t, withExtra16554(
		"set security nat static rule-set srs from zone untrust",
		"set security nat static rule-set srs rule sr1 match destination-address 203.0.113.10",
		"set security nat static rule-set srs rule sr1 then static-nat prefix-name zone-local/trust/host32",
	))
}

func TestReservedZoneLocalRefEvenWhenUndefinedRejected16554(t *testing.T) {
	// The prefix itself is reserved, not merely a defined cross-zone key:
	// spelling a synthetic key for a zone/name that does not exist rejects
	// with the reserved diagnostic, not an undefined-name error.
	lines := withExtra16554(policyLines16554("untrust", "dmz", "zone-local/trust/nope")...)
	_, err := CompileConfig(buildTree(t, lines))
	if err == nil || !strings.Contains(err.Error(), "#16554") {
		t.Fatalf("undefined reserved token: err=%v, want #16554 reserved reject", err)
	}
}

func TestOwnZoneAuthoredNameStillCommitsAndRewrites16554(t *testing.T) {
	lines := withExtra16554(policyLines16554("trust", "untrust", "web")...)
	cfg, err := CompileConfig(buildTree(t, lines))
	if err != nil {
		t.Fatalf("own-zone authored name must still commit: %v", err)
	}
	pol := findPolicy(t, cfg, "trust", "untrust", "p1")
	assertContains(t, "source-address", pol.Match.SourceAddresses, "zone-local/trust/web")
	if pol.LenientContentDropped {
		t.Fatalf("own-zone control policy must not be poisoned")
	}
	if _, ok := cfg.Security.AddressBook.CollidingNames["zone-local/trust/web"]; ok {
		t.Fatalf("own-zone control must not quarantine the folded key: %v", cfg.Security.AddressBook.CollidingNames)
	}
}

func TestReservedZoneLocalRefLenientWarnsAndPoisons16554(t *testing.T) {
	lines := withExtra16554(policyLines16554("untrust", "dmz", "zone-local/trust/web")...)
	cfg, err := CompileConfigLenient(buildTree(t, lines))
	if err != nil {
		t.Fatalf("tolerant load must boot (#1960), got: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "#16554") || (strings.Contains(w, "reserved zone-local reference") && strings.Contains(w, "zone-local/trust/web")) {
			found = true
		}
	}
	if !found {
		t.Fatalf("tolerant load must warn naming the reserved token, warnings: %v", cfg.Warnings)
	}
	pol := findPolicy(t, cfg, "untrust", "dmz", "p1")
	if !pol.LenientContentDropped {
		t.Fatalf("tolerant cross-zone policy must be poisoned (LenientContentDropped), token would otherwise enforce trust's web")
	}
	if _, ok := cfg.Security.AddressBook.CollidingNames["zone-local/trust/web"]; !ok {
		t.Fatalf("tolerant load must quarantine the reserved token in CollidingNames: %v", cfg.Security.AddressBook.CollidingNames)
	}
}

func TestReservedZoneLocalRefLenientNATPoisons16554(t *testing.T) {
	lines := withExtra16554(
		"set security nat source rule-set rs1 from zone trust",
		"set security nat source rule-set rs1 to zone untrust",
		"set security nat source rule-set rs1 rule r1 match source-address-name zone-local/trust/web",
		"set security nat source rule-set rs1 rule r1 then source-nat interface",
	)
	cfg, err := CompileConfigLenient(buildTree(t, lines))
	if err != nil {
		t.Fatalf("tolerant load must boot (#1960), got: %v", err)
	}
	rule := cfg.Security.NAT.Source[0].Rules[0]
	if !rule.LenientMatchDropped {
		t.Fatalf("tolerant SNAT rule with a reserved token must be poisoned (LenientMatchDropped)")
	}
	if _, ok := cfg.Security.AddressBook.CollidingNames["zone-local/trust/web"]; !ok {
		t.Fatalf("tolerant SNAT load must quarantine the reserved token: %v", cfg.Security.AddressBook.CollidingNames)
	}
}

func TestReservedZoneLocalRefLenientSetMemberQuarantined16554(t *testing.T) {
	lines := withExtra16554(
		"set security address-book global address-set grp address zone-local/trust/web",
	)
	lines = append(lines, policyLines16554("untrust", "dmz", "grp")...)
	cfg, err := CompileConfigLenient(buildTree(t, lines))
	if err != nil {
		t.Fatalf("tolerant load must boot (#1960), got: %v", err)
	}
	if _, ok := cfg.Security.AddressBook.CollidingNames["zone-local/trust/web"]; !ok {
		t.Fatalf("tolerant set-member load must quarantine the reserved member token: %v", cfg.Security.AddressBook.CollidingNames)
	}
	// The policy that references the set carries a poisoned member closure,
	// so it must itself be poisoned rather than arming the set.
	if pol := findPolicy(t, cfg, "untrust", "dmz", "p1"); !pol.LenientContentDropped {
		t.Fatalf("policy referencing a set with a reserved member must be poisoned on the tolerant path")
	}
	// The authored set keeps its member spelling; quarantine, not rewriting,
	// is what refuses it at every resolver.
	set := cfg.Security.AddressBook.AddressSets["grp"]
	if set == nil || len(set.Addresses) != 1 || set.Addresses[0] != "zone-local/trust/web" {
		t.Fatalf("authored set membership must be preserved, got %+v", set)
	}
}
