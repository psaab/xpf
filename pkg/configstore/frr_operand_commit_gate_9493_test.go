package configstore

import (
	"fmt"
	"strings"
	"testing"
)

// #9493: six operand classes reached the managed frr.conf with no commit-time
// validator, so a malformed value committed GREEN and the rejected line failed
// the whole FRR reload. CheckText is the operator commit channel. Each bad row
// must be refused naming its leaf, and each good row, the same text with a
// valid value, must commit, so a refusal cannot come from an unrelated gap in
// the fixture.
func TestFRROperandsAreValidatedAtCommit9493(t *testing.T) {
	const base = `routing-options { autonomous-system 65000; router-id 10.0.0.1; } `
	for _, tc := range []struct {
		name, tmpl, good, leaf string
		bad                    []string
	}{
		{"bgp neighbor local-address",
			`protocols { bgp { group g1 { type external; peer-as 65001; neighbor 10.0.0.1 { local-address %s; } } } }`,
			"10.0.0.2", "local-address", []string{`"10.0.0.2 POISON"`, "not-an-address"}},
		{"bgp group local-address",
			`protocols { bgp { group g1 { type external; peer-as 65001; local-address %s; neighbor 10.0.0.1; } } }`,
			"10.0.0.2", "local-address", []string{`"10.0.0.2 POISON"`}},
		{"bgp neighbor multihop",
			`protocols { bgp { group g1 { type external; peer-as 65001; neighbor 10.0.0.1 { multihop %s; } } } }`,
			"5", "multihop", []string{"256", "99999999", "0"}},
		{"bgp group multihop",
			`protocols { bgp { group g1 { type external; peer-as 65001; multihop %s; neighbor 10.0.0.1; } } }`,
			"5", "multihop", []string{"256"}},
		{"ospf interface cost",
			`protocols { ospf { area 0.0.0.0 { interface ge-0/0/0.0 { cost %s; } } } }`,
			"10", "cost", []string{"70000", "0"}},
		{"ospf3 interface cost",
			`protocols { ospf3 { area 0.0.0.0 { interface ge-0/0/0.0 { cost %s; } } } }`,
			"10", "cost", []string{"70000"}},
		{"ospf virtual-link neighbor",
			`protocols { ospf { area 0.0.0.1 { virtual-link %s { transit-area 0.0.0.1; } } } }`,
			"1.1.1.1", "virtual-link", []string{`"1.1.1.1 POISON"`, "2001:db8::1"}},
		{"ospf virtual-link transit-area",
			`protocols { ospf { area 0.0.0.1 { virtual-link 1.1.1.1 { transit-area %s; } } } }`,
			"0.0.0.1", "transit-area", []string{`"0.0.0.1 POISON"`}},
		{"isis net",
			`protocols { isis { net %s; } }`,
			"49.0001.1921.6800.1001.00", "net", []string{`"49.0001.0000.0000.0001.00 POISON"`, "49.0001", "49.0001.zzzz.6800.1001.00"}},
		{"policy-statement name",
			`policy-options { policy-statement %s { term t1 { then accept; } } }`,
			"EXPORT", "policy-statement", []string{`"POI SON"`}},
		{"term name",
			`policy-options { policy-statement p1 { term %s { then accept; } } }`,
			"t1", "term", []string{`"t 1"`}},
		{"prefix-list name",
			`policy-options { prefix-list %s { 10.0.0.0/8; } }`,
			"PL1", "prefix-list", []string{`"P L1"`}},
		{"as-path name",
			`policy-options { as-path %s "^65000 .*$"; }`,
			"AP1", "as-path", []string{`"A P1"`}},
		{"community name",
			`policy-options { community %s { members 65000:1; } }`,
			"C1", "community", []string{`"C 1"`}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := CheckText(base+fmt.Sprintf(tc.tmpl, tc.good), 0); err != nil {
				t.Fatalf("good value %q was refused, so the bad rows prove nothing: %v", tc.good, err)
			}
			for _, bad := range tc.bad {
				_, err := CheckText(base+fmt.Sprintf(tc.tmpl, bad), 0)
				if err == nil {
					t.Errorf("%s %s committed; it renders into frr.conf as a line FRR rejects", tc.leaf, bad)
					continue
				}
				if !strings.Contains(err.Error(), tc.leaf) {
					t.Errorf("%s %s was refused without naming the leaf: %v", tc.leaf, bad, err)
				}
			}
		})
	}
}
