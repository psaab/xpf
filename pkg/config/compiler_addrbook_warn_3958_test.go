package config

import (
	"strings"
	"testing"
)

// buildTree3958 compiles a flat set-command list into a ConfigTree via the
// ParseSetCommand + SetPath loop the CLI uses (NewParser merges newline-
// separated set lines into one node and must not be used for set syntax — see
// CLAUDE.md "Testing flat set syntax").
func buildTree3958(t *testing.T, cmds []string) *ConfigTree {
	t.Helper()
	tree := &ConfigTree{}
	for _, cmd := range cmds {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	return tree
}

// policyAddrBookWarnings returns the "not in address-book" warnings emitted by
// ValidateConfig for a POLICY source/destination-address reference. It excludes
// the distinct address-set MEMBER warning ("address-set %q: member ...") which
// also carries the "not in address-book" phrase but is a different check.
func policyAddrBookWarnings(cfg *Config) []string {
	var out []string
	for _, w := range ValidateConfig(cfg) {
		if strings.Contains(w, "not in address-book") && strings.HasPrefix(w, "policy ") {
			out = append(out, w)
		}
	}
	return out
}

// TestValidateWarnAddressRefFormsNoFalsePositive is the #3958 RED-on-revert
// guard. The ValidateConfig warn pass must NOT emit a spurious "not in
// address-book" warning for any legitimate policy source/destination-address
// reference form that is not a plain address-book name:
//
//   - a literal IPv4/IPv6 address or CIDR,
//   - the any / any-ipv4 / any-ipv6 wildcards (kept as keywords in the compiled
//     config since #9574; the snapshot builder writes 0.0.0.0/0 / ::/0),
//   - a dynamic-address feed binding name (a direct #2049/#3294 feed reference),
//   - an address-book address-set name.
//
// RED-on-revert: restore the old `addr != "any" && !addrs[addr]` check in
// compiler_validate_warn.go and every literal / any-ipv4 / any-ipv6 / feed
// reference below draws a false warning, turning this test RED. (The address-set
// form was already covered by the folded book set, so it is asserted here as a
// contract but is not by itself the reverting signal.)
func TestValidateWarnAddressRefFormsNoFalsePositive(t *testing.T) {
	cmds := []string{
		// dynamic-address feed binding
		"set security dynamic-address feed-server threat url https://feeds.example/list.txt",
		"set security dynamic-address feed-server threat feed-name malware path /malware.txt",
		"set security dynamic-address address-name bad-actors profile feed-name malware",
		// address-book entry + address-set
		"set security address-book global address good-host 10.0.0.0/8",
		"set security address-book global address-set trusted address good-host",
		"set interfaces ge-0-0-1 unit 0 family inet address 10.0.1.1/24",
		"set interfaces ge-0-0-2 unit 0 family inet address 10.0.2.1/24",
		"set security zones security-zone lan interfaces ge-0-0-1.0",
		"set security zones security-zone wan interfaces ge-0-0-2.0",

		// literal IPv4 CIDR + bare IPv6 literal
		"set security policies from-zone lan to-zone wan policy lit match source-address 10.0.0.0/8",
		"set security policies from-zone lan to-zone wan policy lit match destination-address 2001:db8::/32",
		"set security policies from-zone lan to-zone wan policy lit match application any",
		"set security policies from-zone lan to-zone wan policy lit then permit",

		// any / any-ipv4 / any-ipv6 wildcards
		"set security policies from-zone lan to-zone wan policy wild match source-address any-ipv4",
		"set security policies from-zone lan to-zone wan policy wild match destination-address any-ipv6",
		"set security policies from-zone lan to-zone wan policy wild match application any",
		"set security policies from-zone lan to-zone wan policy wild then permit",

		// feed binding name (direct) + address-set name
		"set security policies from-zone lan to-zone wan policy named match source-address bad-actors",
		"set security policies from-zone lan to-zone wan policy named match destination-address trusted",
		"set security policies from-zone lan to-zone wan policy named match application any",
		"set security policies from-zone lan to-zone wan policy named then deny",
	}
	tree := buildTree3958(t, cmds)
	cfg, err := CompileConfig(tree)
	if err != nil {
		// The strict gate accepts every one of these forms; a failure here would
		// mean the warn/strict paths disagree, which is exactly what #3958 fixes.
		t.Fatalf("CompileConfig rejected a legitimate policy address form: %v", err)
	}
	if got := policyAddrBookWarnings(cfg); len(got) != 0 {
		t.Fatalf("expected NO policy 'not in address-book' warning for legitimate "+
			"literal/any/feed/address-set references, got: %v", got)
	}
}

// TestValidateWarnAddressRefUndefinedStillWarns pins the other half of the
// contract: a genuinely undefined policy address name (none of literal / any /
// feed / address-set / address-book entry) must STILL warn. Compiled on the
// lenient path so the strict #2008 gate does not hard-reject it before the warn
// pass runs (an already-persisted / peer-synced config an older binary
// accepted).
func TestValidateWarnAddressRefUndefinedStillWarns(t *testing.T) {
	cmds := []string{
		"set security zones security-zone lan interfaces ge-0-0-1.0",
		"set security zones security-zone wan interfaces ge-0-0-2.0",
		"set security policies from-zone lan to-zone wan policy p match source-address totally-bogus",
		"set security policies from-zone lan to-zone wan policy p match destination-address any",
		"set security policies from-zone lan to-zone wan policy p match application any",
		"set security policies from-zone lan to-zone wan policy p then permit",
	}
	tree := buildTree3958(t, cmds)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile must not fail on a typo'd policy address: %v", err)
	}
	found := false
	for _, w := range policyAddrBookWarnings(cfg) {
		if strings.Contains(w, "totally-bogus") && strings.Contains(w, "source-address") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected a 'not in address-book' warning for the undefined token "+
			"totally-bogus, got: %v", ValidateConfig(cfg))
	}
}
