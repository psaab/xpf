package userspace

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func hierTree6673(t *testing.T, text string) *config.ConfigTree {
	t.Helper()
	tree, perrs := config.NewParser(text).Parse()
	if len(perrs) != 0 {
		t.Fatalf("parse: %v", perrs)
	}
	return tree
}

// TestNPTv6MultiValueMatch6673ReachesTheWireAsTheSelectedPrefix closes the
// round-9 finding that no test observed an NPTv6 rule end to end: the strict
// gate and the compiler were asserted, the SNAPSHOT that crosses to the Rust
// dataplane was not.
//
// `destination-address [ 2001:db8:1::/48 2001:db8:1:2::/48 ]` is rejected at
// strict commit (the second prefix has host bits, which the NPTv6 consumer fails
// closed on rather than masking). But it can still arrive on the tolerant load /
// peer-sync path from a config an older binary persisted, and there it must
// lower EXACTLY as origin/master lowered it — one rule carrying the SELECTED
// external prefix, with the widened tail nowhere on the wire.
func TestNPTv6MultiValueMatch6673ReachesTheWireAsTheSelectedPrefix(t *testing.T) {
	tree := hierTree6673(t, `
security { zones { security-zone untrust; }
nat { static { rule-set rs1 { from zone untrust;
    rule r1 { match { destination-address [ 2001:db8:1::/48 2001:db8:1:2::/48 ]; }
              then { static-nat { nptv6-prefix 2001:db8:2::/48; } } } } } } }`)

	if _, err := config.CompileConfig(tree); err == nil {
		t.Fatal("strict commit accepted an NPTv6 rule whose non-selected " +
			"`match destination-address` carries host bits; the cardinality " +
			"gate must see the two prefixes as distinct because the NPTv6 " +
			"consumer does not mask them together")
	}

	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("tolerant compile must not brick: %v", err)
	}
	snaps := buildNptv6Snapshots(cfg)
	if len(snaps) != 1 {
		t.Fatalf("buildNptv6Snapshots produced %d rules, want 1: %+v", len(snaps), snaps)
	}
	if snaps[0].ExternalPrefix != "2001:db8:1::/48" {
		t.Fatalf("ExternalPrefix on the wire = %q, want the SELECTED value "+
			"2001:db8:1::/48 — the value origin/master lowered. The widened "+
			"read must not change what crosses to the dataplane.",
			snaps[0].ExternalPrefix)
	}
	if snaps[0].InternalPrefix != "2001:db8:2::/48" {
		t.Fatalf("InternalPrefix = %q, want 2001:db8:2::/48", snaps[0].InternalPrefix)
	}

	// The whole point of the host-bits rule: what reaches the wire is a prefix
	// userspace-dp/src/nptv6.rs parse_prefix ACCEPTS. It returns None for a
	// prefix with bits set beyond its length ("#4519 — fail closed, do NOT
	// mask"), so a snapshot carrying the tail would install nothing at all.
	for _, p := range []string{snaps[0].ExternalPrefix, snaps[0].InternalPrefix} {
		pfx, perr := netip.ParsePrefix(p)
		if perr != nil {
			t.Fatalf("prefix %q on the wire does not parse: %v", p, perr)
		}
		if pfx.Masked() != pfx {
			t.Fatalf("prefix %q on the wire carries host bits; "+
				"userspace-dp/src/nptv6.rs parse_prefix returns None for it and "+
				"the rule installs NOTHING", p)
		}
	}
}

// TestNPTv6RepeatedMatch6673LowersOnceAndUnchanged is the control: a REPEATED
// identical prefix is one prefix, commits, and lowers to exactly the rule
// origin/master lowered. The dedupe that spares it must not also change the
// wire.
func TestNPTv6RepeatedMatch6673LowersOnceAndUnchanged(t *testing.T) {
	tree := hierTree6673(t, `
security { zones { security-zone untrust; }
nat { static { rule-set rs1 { from zone untrust;
    rule r1 { match { destination-address [ 2001:db8:1::/48 2001:db8:1::/48 ]; }
              then { static-nat { nptv6-prefix 2001:db8:2::/48; } } } } } } }`)
	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("strict commit rejected a repeated identical NPTv6 prefix: %v", err)
	}
	snaps := buildNptv6Snapshots(cfg)
	if len(snaps) != 1 || snaps[0].ExternalPrefix != "2001:db8:1::/48" {
		t.Fatalf("snapshots = %+v, want exactly one rule with "+
			"ExternalPrefix 2001:db8:1::/48", snaps)
	}
}

// TestStaticNATDropCauses6673AreVisibleInTheSnapshot is the other half of the
// round-9 finding: the verdict table in pkg/config compares WARNING TEXT and
// nothing else, so "the dataplane drops this rule" was an assertion about a
// string. Here each dropping cause is observed on the SNAPSHOT that crosses to
// Rust — the artefact the claim is actually about.
//
// The Rust-side verdict for each shape is pinned by tests in
// userspace-dp/src/nat/tests_static.rs (cited per case); what this adds is the
// Go half: that the snapshot really does carry the input those tests reject.
func TestStaticNATDropCauses6673AreVisibleInTheSnapshot(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  string
		// check inspects the lowered snapshot and returns "" when the snapshot
		// carries the input the Rust consumer refuses to install.
		check func(t *testing.T, snaps []StaticNATRuleSnapshot) string
	}{
		{
			// parse_nat_prefix does `parts.next()?.parse().ok()?` on the
			// address, so an unparseable internal prefix returns None and
			// from_snapshots records a parse error and installs nothing.
			name: "then prefix does not parse",
			cfg: `
security { zones { security-zone untrust; }
nat { static { rule-set rs1 { from zone untrust;
    rule r1 { match { destination-address 198.51.100.0/24; destination-address 192.0.2.1/32; }
              then { static-nat prefix not-an-addr; } } } } } }`,
			check: func(t *testing.T, snaps []StaticNATRuleSnapshot) string {
				if len(snaps) != 1 {
					return "expected exactly one lowered rule"
				}
				if _, err := parseNATPrefix6673(snaps[0].InternalIP); err == nil {
					return "InternalIP " + snaps[0].InternalIP +
						" parses; the rule would install, contradicting the " +
						"compiler warning that says the dataplane drops it"
				}
				return ""
			},
		},
		{
			// from_snapshots' block branch `continue`s when
			// match_destination_port != 0 || mapped_port != 0 (#3202) —
			// static_nat_block_with_port_is_dropped.
			name: "block pair with a port",
			cfg: `
security { zones { security-zone untrust; }
nat { static { rule-set rs1 { from zone untrust;
    rule r1 { match { destination-address [ 10.1.1.0/24 198.51.100.0/25 ];
                      destination-port 80; }
              then { static-nat { prefix 10.0.0.0/24; mapped-port 8080; } } } } } } }`,
			check: func(t *testing.T, snaps []StaticNATRuleSnapshot) string {
				if len(snaps) != 1 {
					return "expected exactly one lowered rule"
				}
				s := snaps[0]
				ext, err := parseNATPrefix6673(s.ExternalIP)
				if err != nil {
					return "ExternalIP does not parse: " + err.Error()
				}
				if ext.Bits() == ext.Addr().BitLen() {
					return "ExternalIP " + s.ExternalIP +
						" is a HOST route, so Rust takes the 1:1 branch, not " +
						"the block branch this case is about"
				}
				if s.MatchDestinationPort == 0 && s.MappedPort == 0 {
					return "neither port survived lowering, so the block " +
						"branch would NOT continue and the rule would install"
				}
				return ""
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := config.CompileConfigLenient(hierTree6673(t, tc.cfg))
			if err != nil {
				t.Fatalf("tolerant compile: %v", err)
			}
			if why := tc.check(t, buildStaticNATSnapshots(cfg, nil)); why != "" {
				t.Fatalf("the snapshot does not carry the input the dataplane "+
					"refuses: %s\n"+
					"pkg/config's verdict table says this rule is dropped; that "+
					"claim is about the SNAPSHOT, so it has to be checked here "+
					"and not only in the warning text.", why)
			}
			// And the compiler must be saying the same thing about it.
			if !warningsMention6673(cfg.Warnings, "rule dropped by dataplane until corrected") {
				t.Fatal("no compiler warning claims the rule is dropped, but " +
					"the snapshot shows it cannot install — the two halves of " +
					"the verdict have drifted")
			}
		})
	}
}

// parseNATPrefix6673 mirrors the ACCEPTANCE half of userspace-dp's
// parse_nat_prefix: a bare address is a host route, a "/len" is a prefix, and
// anything else is unparseable. It deliberately does NOT mirror the masking —
// the tests above only ask whether the value parses at all.
func parseNATPrefix6673(v string) (netip.Prefix, error) {
	if !strings.Contains(v, "/") {
		a, err := netip.ParseAddr(v)
		if err != nil {
			return netip.Prefix{}, err
		}
		return netip.PrefixFrom(a, a.BitLen()), nil
	}
	return netip.ParsePrefix(v)
}

func warningsMention6673(warnings []string, sub string) bool {
	for _, w := range warnings {
		if strings.Contains(w, sub) {
			return true
		}
	}
	return false
}
