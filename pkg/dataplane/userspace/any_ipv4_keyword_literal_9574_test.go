package userspace

import (
	"reflect"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #9574 — the snapshot builder, not compilePolicy, turns `any-ipv4` / `any-ipv6`
// into the CIDR the dataplane parses, AFTER classifying the token as a keyword.
// Channel: config.CompileConfig (strict); every fixture is a legal config.

func compileStrictSet9574(t *testing.T, lines []string) *config.Config {
	t.Helper()
	tree := &config.ConfigTree{}
	for _, l := range lines {
		p, err := config.ParseSetCommand(l)
		if err != nil {
			t.Fatalf("parse %q: %v", l, err)
		}
		if err := tree.SetPath(p); err != nil {
			t.Fatalf("setpath %q: %v", l, err)
		}
	}
	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("fixture must commit: %v", err)
	}
	return cfg
}

func policyLines9574(scope, name, src string) []string {
	p := "set security policies " + scope + " policy " + name + " "
	return []string{p + "match source-address " + src, p + "match destination-address any", p + "match application any", p + "then deny"}
}

var zones9574 = []string{"set security zones security-zone trust", "set security zones security-zone untrust"}

// The wire is byte-identical to before #9574 for a config with no object named
// after a match-all CIDR: the rewrite moved, its output did not.
func TestAnyIPv4KeywordReachesTheWireAsCIDR9574(t *testing.T) {
	p := "set security policies from-zone trust to-zone untrust policy fam "
	cfg := compileStrictSet9574(t, append(append([]string{}, zones9574...),
		p+"match source-address any-ipv4", p+"match destination-address any-ipv6",
		p+"match application any", p+"then permit"))
	rules, err := buildPolicySnapshotsWithSchedulerStateAndFeeds(cfg, nil, nil)
	if err != nil || len(rules) != 1 {
		t.Fatalf("build: rules=%d err=%v", len(rules), err)
	}
	r := rules[0]
	if !reflect.DeepEqual(r.SourceLiterals, []string{"0.0.0.0/0"}) || !reflect.DeepEqual(r.DestinationLiterals, []string{"::/0"}) {
		t.Errorf("v3 literals = %v / %v, want [0.0.0.0/0] / [::/0]", r.SourceLiterals, r.DestinationLiterals)
	}
	if !reflect.DeepEqual(r.SourceAddresses, []string{"0.0.0.0/0"}) || !reflect.DeepEqual(r.DestinationAddresses, []string{"::/0"}) {
		t.Errorf("legacy addresses = %v / %v, want [0.0.0.0/0] / [::/0]", r.SourceAddresses, r.DestinationAddresses)
	}
	if len(r.SourceBookIDs) != 0 || len(r.DestinationBookIDs) != 0 {
		t.Errorf("a keyword must not become a book reference: %v / %v", r.SourceBookIDs, r.DestinationBookIDs)
	}
}

func TestObjectNamedAMatchAllCIDRDoesNotCaptureTheKeyword9574(t *testing.T) {
	for _, tc := range []struct {
		name    string
		lines   []string
		wantLit string
	}{
		{"address 0.0.0.0/0 + any-ipv4", append([]string{"set security address-book global address 0.0.0.0/0 10.99.0.0/16"},
			policyLines9574("from-zone trust to-zone untrust", "d1", "any-ipv4")...), "0.0.0.0/0"},
		{"address ::/0 + any-ipv6", append([]string{"set security address-book global address ::/0 2001:db8:99::/48"},
			policyLines9574("from-zone trust to-zone untrust", "d1", "any-ipv6")...), "::/0"},
		{"address-set 0.0.0.0/0 + any-ipv4", append([]string{
			"set security address-book global address a1 10.99.0.0/16",
			"set security address-book global address-set 0.0.0.0/0 address a1",
		}, policyLines9574("from-zone trust to-zone untrust", "d1", "any-ipv4")...), "0.0.0.0/0"},
		{"zone-local 0.0.0.0/0 + any-ipv4", append([]string{
			"set security zones security-zone trust address-book address 0.0.0.0/0 10.99.0.0/16",
		}, policyLines9574("from-zone trust to-zone untrust", "d1", "any-ipv4")...), "0.0.0.0/0"},
		{"global policy + any-ipv4", append([]string{"set security address-book global address 0.0.0.0/0 10.99.0.0/16"},
			policyLines9574("global", "g1", "any-ipv4")...), "0.0.0.0/0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := compileStrictSet9574(t, append(append([]string{}, zones9574...), tc.lines...))
			_, nameToID, err := buildAddressBookTable(cfg)
			if err != nil {
				t.Fatal(err)
			}
			captured := false
			for name := range nameToID {
				if name == tc.wantLit || name == "zone-local/trust/"+tc.wantLit {
					captured = true
				}
			}
			if !captured {
				t.Fatalf("fixture premise broken: no object named %q reached the book table", tc.wantLit)
			}
			rules, err := buildPolicySnapshotsWithSchedulerStateAndFeeds(cfg, nil, nil)
			if err != nil || len(rules) != 1 {
				t.Fatalf("build: rules=%d err=%v", len(rules), err)
			}
			r := rules[0]
			if len(r.SourceBookIDs) != 0 || !reflect.DeepEqual(r.SourceLiterals, []string{tc.wantLit}) {
				t.Errorf("#9574: the keyword was captured: SourceBookIDs=%v SourceLiterals=%v", r.SourceBookIDs, r.SourceLiterals)
			}
			if reasons := PolicyContentRejectionReasons(cfg, nil); len(reasons) != 0 {
				t.Errorf("a match-all keyword must be enforced, not refused: %v", reasons)
			}
		})
	}
}

// Name-before-literal is documented and matches Junos, and #9574 must not break
// it: a literal `0.0.0.0/0` TYPED in a policy names the object of that name.
func TestTypedMatchAllCIDRStillNamesTheObject9574(t *testing.T) {
	cfg := compileStrictSet9574(t, append(append(append([]string{}, zones9574...),
		"set security address-book global address 0.0.0.0/0 10.99.0.0/16"),
		policyLines9574("from-zone trust to-zone untrust", "d1", "0.0.0.0/0")...))
	_, nameToID, err := buildAddressBookTable(cfg)
	if err != nil {
		t.Fatal(err)
	}
	rules, err := buildPolicySnapshotsWithSchedulerStateAndFeeds(cfg, nil, nil)
	if err != nil || len(rules) != 1 {
		t.Fatalf("build: rules=%d err=%v", len(rules), err)
	}
	if !reflect.DeepEqual(rules[0].SourceBookIDs, []uint32{nameToID["0.0.0.0/0"]}) || len(rules[0].SourceLiterals) != 0 {
		t.Errorf("name-before-literal broke: SourceBookIDs=%v SourceLiterals=%v", rules[0].SourceBookIDs, rules[0].SourceLiterals)
	}
}
