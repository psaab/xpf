package config

import (
	"strings"
	"testing"
)

// #2396(c): a destination-NAT rule whose `match destination-address` resolves
// to NO parseable host IP (every configured token is malformed) compiles and
// commits, but the snapshot builder skips each bad destination and the Rust
// DNAT table drops the rule — so it silently translates NOTHING with no
// operator feedback. validateDestinationNATAddressesStrict hard-rejects it at
// commit / commit-check, and the tolerant load / peer-sync path downgrades the
// error to a warning (#1960 no-brick).
//
// All tests use the production ParseSetCommand + SetPath path (buildTree),
// never NewParser (the flat-set gotcha in CLAUDE.md).

// dnatSet builds a minimal DNAT rule-set with one rule matching the given
// destination-address (raw token) and a valid pool. The from-zone is defined
// to avoid unrelated undefined-zone warnings.
func dnatSet(matchDest string) []string {
	poolAddress := "10.0.0.5"
	if strings.Contains(matchDest, ":") {
		poolAddress = "2001:db8::5"
	}
	return []string{
		"set security zones security-zone untrust",
		"set security nat destination pool dp address " + poolAddress,
		"set security nat destination rule-set rs1 from zone untrust",
		"set security nat destination rule-set rs1 rule r1 match destination-address " + matchDest,
		"set security nat destination rule-set rs1 rule r1 then destination-nat pool dp",
	}
}

func TestDNATValidDestinationCompiles(t *testing.T) {
	tree := buildTree(t, dnatSet("203.0.113.10"))
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("a DNAT rule with a valid destination must compile, got: %v", err)
	}
}

func TestDNATValidDestinationCIDRCompiles(t *testing.T) {
	// A /32 host CIDR is a valid destination (the builder keys it as an
	// exact host, DestinationPrefix empty).
	tree := buildTree(t, dnatSet("203.0.113.10/32"))
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("a DNAT rule with a /32 destination must compile, got: %v", err)
	}
}

func TestDNATAllInvalidDestinationRejected(t *testing.T) {
	// The only destination is a typo (not an IP) — reject at commit so the
	// operator sees the rule would never translate anything.
	tree := buildTree(t, dnatSet("not-an-ip"))
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("a DNAT rule whose only destination-address is malformed must be rejected at commit")
	}
	msg := err.Error()
	if !strings.Contains(msg, "destination-nat") ||
		!strings.Contains(msg, "r1") ||
		!strings.Contains(msg, "not-an-ip") {
		t.Fatalf("error must name the rule-set/rule + the malformed token, got: %v", err)
	}
}

// #3228: a bracket list with one valid + one malformed destination (e.g.
// `[ 203.0.113.10 web-server ]`) used to pass the gate (the old anyGood break
// required only ONE good entry). The snapshot builder then silently `continue`s
// past the typo, so traffic to it never translates — a partial, silent drop of
// a forwarding-relevant config. The gate must now reject the rule, naming the
// bad entry, so validator and builder agree (anything the builder would skip,
// the validator rejects). Reverting the per-entry check to the anyGood break
// makes this RED (the partial-valid rule compiles).
//
// Constructed at the struct level (not via flat-set syntax) because the
// flat-set parser collapses a `[ a b ]` destination-address list to its first
// token; the builder/gate operate on DestinationAddresses, which the
// hierarchical parser and the dataplane snapshot path populate fully.
func TestDNATPartialValidDestinationRejected(t *testing.T) {
	cfg := &Config{}
	cfg.Security.NAT.Destination = &DestinationNATConfig{
		Pools: map[string]*NATPool{"dp": {Name: "dp", Address: "10.0.0.5"}},
		RuleSets: []*NATRuleSet{
			{Name: "rs1", FromZone: "untrust", Rules: []*NATRule{
				{
					Name: "r1",
					Match: NATMatch{
						DestinationAddresses: []string{"203.0.113.10", "web-server"},
						DestinationAddress:   "203.0.113.10",
					},
					Then: NATThen{Type: NATDestination, PoolName: "dp"},
				},
			}},
		},
	}
	err := validateDestinationNATAddressesStrict(cfg)
	if err == nil {
		t.Fatal("a DNAT rule with a malformed destination in an otherwise-valid " +
			"list must be rejected at commit (the builder silently drops it)")
	}
	msg := err.Error()
	if !strings.Contains(msg, "destination-nat") ||
		!strings.Contains(msg, "r1") ||
		!strings.Contains(msg, "web-server") {
		t.Fatalf("error must name the rule-set/rule + the malformed token, got: %v", err)
	}
}

// #3228 (positive half): an all-valid bracket list must still pass the gate
// unchanged — the per-entry rejection must not regress a list where every
// entry parses. The builder's all-entries-installed behavior is covered by
// userspace.TestBuildDestinationNATSnapshotsMultiDestination.
func TestDNATAllValidDestinationListAccepted(t *testing.T) {
	cfg := &Config{}
	cfg.Security.NAT.Destination = &DestinationNATConfig{
		Pools: map[string]*NATPool{"dp": {Name: "dp", Address: "10.0.0.5"}},
		RuleSets: []*NATRuleSet{
			{Name: "rs1", FromZone: "untrust", Rules: []*NATRule{
				{
					Name: "r1",
					Match: NATMatch{
						DestinationAddresses: []string{"203.0.113.10", "203.0.113.11/32", "203.0.113.12"},
						DestinationAddress:   "203.0.113.10",
					},
					Then: NATThen{Type: NATDestination, PoolName: "dp"},
				},
			}},
		},
	}
	if err := validateDestinationNATAddressesStrict(cfg); err != nil {
		t.Fatalf("a DNAT rule whose destination list is entirely valid must pass the gate, got: %v", err)
	}
}

// #3164: a DNAT match destination-address that is a MULTI-HOST prefix
// (e.g. 198.51.100.0/24) is now HONORED — the snapshot builder carries the
// canonical prefix to the wire and the Rust DnatTable installs a
// longest-prefix-match entry that translates every host in the block to the
// rule's pool. The #3029 reject that previously fired at commit is gone, so the
// rule must compile cleanly. Reverting the feature (restoring the #3029 gate)
// makes this RED (the prefix rule is rejected again).
func TestDNATPrefixDestinationCompiles(t *testing.T) {
	tree := buildTree(t, dnatSet("198.51.100.0/24"))
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("a DNAT rule whose destination-address is a multi-host prefix must compile (#3164), got: %v", err)
	}
}

// #3164: an IPv6 multi-host prefix destination is honored the same way.
func TestDNATPrefixDestinationV6Compiles(t *testing.T) {
	tree := buildTree(t, dnatSet("2001:db8::/64"))
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("a DNAT rule whose destination-address is an IPv6 multi-host prefix must compile (#3164), got: %v", err)
	}
}

// #3164: a single-host destination written as an explicit host mask (/32 or
// /128) or a bare IP still compiles and keys the Rust exact-host fast path.
func TestDNATHostMaskDestinationCompiles(t *testing.T) {
	for _, dst := range []string{"203.0.113.10/32", "2001:db8::5/128", "203.0.113.10"} {
		tree := buildTree(t, dnatSet(dst))
		if _, err := CompileConfig(tree); err != nil {
			t.Fatalf("a single-host DNAT destination %q must compile, got: %v", dst, err)
		}
	}
}

// #3164: a prefix DNAT destination must NOT emit the old destination-nat
// multi-host-prefix warning on the tolerant load / peer-sync path — it is now a
// fully-valid config, not a degraded one. (A genuinely malformed destination
// still warns; see TestDNATAllInvalidDestinationLenientWarns.)
func TestDNATPrefixDestinationLenientCompilesNoWarn(t *testing.T) {
	cfg, err := CompileConfigLenient(buildTree(t, dnatSet("198.51.100.0/24")))
	if err != nil {
		t.Fatalf("lenient load of a prefix DNAT destination must NOT fail, got: %v", err)
	}
	if hasWarningContaining(cfg.Warnings, "destination-nat address") {
		t.Fatalf("a prefix DNAT destination must not emit a destination-nat warning (#3164), warnings=%v", cfg.Warnings)
	}
}

func TestDNATAllInvalidDestinationLenientWarns(t *testing.T) {
	// Tolerant load / peer-sync must NOT brick on a config that committed
	// before this gate existed — downgrade to a warning instead.
	cfg, err := CompileConfigLenient(buildTree(t, dnatSet("not-an-ip")))
	if err != nil {
		t.Fatalf("lenient load must NOT fail (brick-on-restart), got: %v", err)
	}
	if !hasWarningContaining(cfg.Warnings, "destination-nat address") {
		t.Fatalf("lenient load must emit a destination-nat warning, warnings=%v", cfg.Warnings)
	}
}
