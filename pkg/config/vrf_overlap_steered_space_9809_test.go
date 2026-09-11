package config

import (
	"reflect"
	"strings"
	"testing"
)

func vrfTree9809(t *testing.T, lines []string) *ConfigTree {
	t.Helper()
	tree := &ConfigTree{}
	for _, l := range lines {
		path, err := ParseSetCommand(l)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", l, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", l, err)
		}
	}
	return tree
}

// vrfVerdict9809 compiles lines on the strict path and the tolerant path and
// reports whether strict refused with the #7924 message, how many overlap
// warnings strict produced, and how many admissions the tolerant path records.
func vrfVerdict9809(t *testing.T, lines []string) (refused bool, warnings, admissions int) {
	t.Helper()
	cfg, err := CompileConfig(vrfTree9809(t, lines))
	if err != nil {
		if !strings.Contains(err.Error(), "#7924") {
			t.Fatalf("strict compile failed for a reason other than #7924: %v", err)
		}
		refused = true
	} else {
		for _, w := range cfg.Warnings {
			if strings.Contains(w, "NOT session-isolated") {
				warnings++
			}
		}
	}
	lcfg, lerr := CompileConfigLenient(vrfTree9809(t, lines))
	if lerr != nil {
		t.Fatalf("tolerant compile: %v", lerr)
	}
	return refused, warnings, len(TolerantVRFOverlapAdmissions(lcfg))
}

// steeredPair9809 is #9809's steered fixture: two forwarding instances with no
// member interfaces, each steered by its own input filter on a different
// default-instance interface. fa and fb are the `from` statements of each term.
func steeredPair9809(fa, fb []string) []string {
	lines := []string{
		"set interfaces ge-0/0/1 unit 0 family inet address 192.168.1.1/24",
		"set interfaces ge-0/0/2 unit 0 family inet address 192.168.2.1/24",
		"set routing-instances FA instance-type forwarding",
		"set routing-instances FB instance-type forwarding",
		"set policy-options prefix-list PL1 10.1.0.0/16",
		"set policy-options prefix-list PL2 10.2.0.0/16",
		"set firewall family inet filter fa term t then routing-instance FA",
		"set firewall family inet filter fa term d then accept",
		"set firewall family inet filter fb term t then routing-instance FB",
		"set firewall family inet filter fb term d then accept",
		"set interfaces ge-0/0/1 unit 0 family inet filter input fa",
		"set interfaces ge-0/0/2 unit 0 family inet filter input fb",
	}
	for _, f := range fa {
		lines = append(lines, "set firewall family inet filter fa term t from "+f)
	}
	for _, f := range fb {
		lines = append(lines, "set firewall family inet filter fb term t from "+f)
	}
	return lines
}

// TestSteeredSpellingsReachTheOverlapGate9809 is #9809's steered-spelling
// table. The detector learned a steering term's space only from literal
// prefixes, so the same overlap written as a prefix-list, a bare host, `any` or
// no `from` committed clean, with no warning and no tolerant admission.
func TestSteeredSpellingsReachTheOverlapGate9809(t *testing.T) {
	cases := []struct {
		name   string
		fa, fb []string
		refuse bool
	}{
		{"control: literal prefix in both", []string{"source-address 10.1.0.0/16"}, []string{"source-address 10.1.0.0/16"}, true},
		{"control: literal /32 in both", []string{"source-address 10.1.0.5/32"}, []string{"source-address 10.1.0.5/32"}, true},
		{"control: literal 0.0.0.0/0 in both", []string{"source-address 0.0.0.0/0"}, []string{"source-address 0.0.0.0/0"}, true},
		{"prefix-list in both", []string{"source-prefix-list PL1"}, []string{"source-prefix-list PL1"}, true},
		{"literal in one, prefix-list in the other", []string{"source-address 10.1.0.0/16"}, []string{"source-prefix-list PL1"}, true},
		{"bare host in both", []string{"source-address 10.1.0.5"}, []string{"source-address 10.1.0.5"}, true},
		{"any in both", []string{"source-address any"}, []string{"source-address any"}, true},
		{"no from in either", nil, nil, true},
		{"control: disjoint prefix-lists", []string{"source-prefix-list PL1"}, []string{"source-prefix-list PL2"}, false},
		{"a non-empty pure except steers nothing", []string{"source-prefix-list PL1 except"}, []string{"source-prefix-list PL1 except"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			refused, _, admissions := vrfVerdict9809(t, steeredPair9809(tc.fa, tc.fb))
			if refused != tc.refuse {
				t.Fatalf("strict refused=%v, want %v", refused, tc.refuse)
			}
			if tc.refuse && admissions == 0 {
				t.Errorf("the tolerant path records no admission for a config strict refuses, so the metric stays silent")
			}
			if !tc.refuse && admissions != 0 {
				t.Errorf("the tolerant path records %d admissions for a config strict accepts", admissions)
			}
		})
	}
}

// fbfOverMemberInstance9809 is the shape the lab loads: test-fbf-steering.sh
// applies fbf-two-upstream-config.set, which steers into ISP-B, on top of
// docs/ha-cluster-userspace.conf, whose sfmix virtual-router has an addressed
// member interface.
func fbfOverMemberInstance9809(from []string) []string {
	lines := []string{
		"set interfaces gr-0/0/0 tunnel source 2001:db8::8",
		"set interfaces gr-0/0/0 tunnel destination 2001:db8::7",
		"set interfaces gr-0/0/0 unit 0 family inet address 10.255.192.42/30",
		"set interfaces reth1 unit 0 family inet address 10.0.61.1/24",
		"set routing-instances sfmix instance-type virtual-router",
		"set routing-instances sfmix interface gr-0/0/0.0",
		"set routing-instances ISP-B instance-type forwarding",
		"set routing-instances ISP-B routing-options static route 0.0.0.0/0 next-hop 172.16.80.1",
		"set firewall family inet filter fbf-steer term to-isp-b then routing-instance ISP-B",
		"set firewall family inet filter fbf-steer term default then accept",
		"set interfaces reth1 unit 0 family inet filter input fbf-steer",
	}
	for _, f := range from {
		lines = append(lines, "set firewall family inet filter fbf-steer term to-isp-b from "+f)
	}
	return lines
}

// TestMatchAllSteerAgainstAMemberInstance9809 pins the pairing rule #9809
// chose: match-all steered space pairs only with other steered space. Read
// literally, "no from is match-all" would have refused the shipped FBF lab
// overlay, a member-interface prefix against default-instance steering, which
// #7160 already separates by routing domain. A literal 0.0.0.0/0 keeps its
// pre-#9809 refusal.
func TestMatchAllSteerAgainstAMemberInstance9809(t *testing.T) {
	cases := []struct {
		name   string
		from   []string
		refuse bool
	}{
		{"the shipped DSCP-only steer", []string{"dscp af31"}, false},
		{"an `any` steer", []string{"dscp af31", "source-address any"}, false},
		{"control: a literal 0.0.0.0/0 steer is still refused", []string{"dscp af31", "source-address 0.0.0.0/0"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			refused, warnings, _ := vrfVerdict9809(t, fbfOverMemberInstance9809(tc.from))
			if refused != tc.refuse {
				t.Fatalf("strict refused=%v, want %v", refused, tc.refuse)
			}
			if !tc.refuse && warnings != 0 {
				t.Errorf("want no overlap warning for match-all steering against a member prefix, got %d", warnings)
			}
		})
	}
}

// bareMember9809 is #9809's bare-member fixture: ge-0/0/1 has unit 0 at
// 192.168.0.1/24 and unit 10 at 10.0.0.1/24, and RI-B's member overlaps unit 10.
func bareMember9809(member string) []string {
	return []string{
		"set interfaces ge-0/0/1 vlan-tagging",
		"set interfaces ge-0/0/1 unit 0 vlan-id 5",
		"set interfaces ge-0/0/1 unit 0 family inet address 192.168.0.1/24",
		"set interfaces ge-0/0/1 unit 10 vlan-id 10",
		"set interfaces ge-0/0/1 unit 10 family inet address 10.0.0.1/24",
		"set interfaces ge-0/0/2 unit 0 family inet address 10.0.0.2/24",
		"set routing-instances RI-A instance-type virtual-router",
		"set routing-instances RI-A interface " + member,
		"set routing-instances RI-B instance-type virtual-router",
		"set routing-instances RI-B interface ge-0/0/2.0",
		"set firewall family inet filter fbf term t1 then routing-instance RI-B",
	}
}

// TestBareMemberIsEveryUnitInTheOverlapGate9809: a bare routing-instance member
// binds every configured unit in the FIB (#9132), so an overlap on unit 10 must
// reach the gate. It used to be read as unit 0 alone.
func TestBareMemberIsEveryUnitInTheOverlapGate9809(t *testing.T) {
	cases := []struct {
		member string
		refuse bool
	}{
		{"ge-0/0/1", true},
		{"ge-0/0/1.10", true},
		{"ge-0/0/1.0", false},
	}
	for _, tc := range cases {
		t.Run(tc.member, func(t *testing.T) {
			refused, _, _ := vrfVerdict9809(t, bareMember9809(tc.member))
			if refused != tc.refuse {
				t.Fatalf("member %s: strict refused=%v, want %v", tc.member, refused, tc.refuse)
			}
		})
	}
}

func TestRoutingInstanceMemberUnits9809(t *testing.T) {
	cfg, err := CompileConfig(vrfTree9809(t, bareMember9809("ge-0/0/1.0")))
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	refs := func(member string) []string {
		var out []string
		for _, mu := range RoutingInstanceMemberUnits(cfg, member) {
			out = append(out, mu.Ref)
		}
		return out
	}
	if got, want := refs("ge-0/0/1"), []string{"ge-0/0/1.0", "ge-0/0/1.10"}; !reflect.DeepEqual(got, want) {
		t.Errorf("bare member: got %v, want %v", got, want)
	}
	if got, want := refs("ge-0/0/1.10"), []string{"ge-0/0/1.10"}; !reflect.DeepEqual(got, want) {
		t.Errorf("unit member: got %v, want %v", got, want)
	}
	if got := refs("ge-0/0/9"); len(got) != 0 {
		t.Errorf("unknown member: got %v, want none", got)
	}
}

// TestPBRDirectionSteers9809 pins the classifier against the builder's rules
// (pkg/routing resolvePBRDirection), with its one recorded difference: a
// literal /0 stays a prefix.
func TestPBRDirectionSteers9809(t *testing.T) {
	pls := map[string]*PrefixList{
		"PL":    {Prefixes: []string{"10.1.0.0/16", "not-an-address"}},
		"EMPTY": {},
	}
	cases := []struct {
		name     string
		literal  []string
		refs     []PrefixListRef
		prefixes []string
		all      bool
		none     bool
	}{
		{"no match is all", nil, nil, nil, true, false},
		{"any is all", []string{"any"}, nil, nil, true, false},
		{"bare v4 host is /32", []string{"10.1.0.5"}, nil, []string{"10.1.0.5/32"}, false, false},
		{"bare v6 host is /128", []string{"2001:db8::5"}, nil, []string{"2001:db8::5/128"}, false, false},
		{"literal /0 stays a prefix", []string{"0.0.0.0/0"}, nil, []string{"0.0.0.0/0"}, false, false},
		{"unparseable literal drops the term", []string{"bogus"}, nil, nil, false, true},
		{"prefix-list expands, skipping a bad entry", nil, []PrefixListRef{{Name: "PL"}}, []string{"10.1.0.0/16"}, false, false},
		{"unresolved positive list steers nothing", nil, []PrefixListRef{{Name: "MISSING"}}, nil, false, true},
		{"non-empty pure except drops the term", nil, []PrefixListRef{{Name: "PL", Except: true}}, nil, false, true},
		{"empty pure except is all", nil, []PrefixListRef{{Name: "EMPTY", Except: true}}, nil, true, false},
		{"positive beside except keeps the positive set", []string{"10.9.0.0/16"}, []PrefixListRef{{Name: "PL", Except: true}}, []string{"10.9.0.0/16"}, false, false},
		{"any beside a prefix reports both", []string{"10.9.0.0/16", "any"}, nil, []string{"10.9.0.0/16"}, true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, all, none := PBRDirectionSteers(tc.literal, tc.refs, pls)
			if !reflect.DeepEqual(p, tc.prefixes) || all != tc.all || none != tc.none {
				t.Fatalf("got prefixes=%v all=%v none=%v, want %v %v %v", p, all, none, tc.prefixes, tc.all, tc.none)
			}
		})
	}
}

// TestRibGroupLeakCoversEveryUnitOfABareMember9809: an interface-routes
// rib-group for an instance with a bare member must leak every addressed
// unit's connected prefix, which is what the FIB installs for that member
// (#9132). It used to read unit 0 alone: with unit 0 unaddressed the leak set
// was empty and the warning blamed a DHCP-only member.
func TestRibGroupLeakCoversEveryUnitOfABareMember9809(t *testing.T) {
	build := func(member string) *Config {
		cfg := &Config{}
		cfg.Interfaces.Interfaces = map[string]*InterfaceConfig{
			"ge-0/0/1": {Name: "ge-0/0/1", Units: map[int]*InterfaceUnit{
				0:  {Number: 0},
				10: {Number: 10, Addresses: []string{"10.0.0.1/24"}},
			}},
		}
		cfg.RoutingOptions.RibGroups = map[string]*RibGroup{
			"leak": {Name: "leak", ImportRibs: []string{"dmz-vr.inet.0", "inet.0"}},
		}
		cfg.RoutingInstances = []*RoutingInstanceConfig{{
			Name: "dmz-vr", TableID: 101, Interfaces: []string{member}, InterfaceRoutesRibGroup: "leak",
		}}
		return cfg
	}
	for _, member := range []string{"ge-0/0/1", "ge-0/0/1.10"} {
		cfg := build(member)
		if got, want := RibGroupConnectedPrefixes(cfg)["dmz-vr"], []string{"10.0.0.0/24"}; !reflect.DeepEqual(got, want) {
			t.Errorf("member %s: leak set %v, want %v", member, got, want)
		}
		for _, w := range validateRibGroupLeakWarnings(cfg) {
			if strings.Contains(w, "no enumerable static connected prefix") {
				t.Errorf("member %s: the leak warning blames an unaddressed member while unit 10 is addressed: %s", member, w)
			}
		}
	}
}

// oneOrTwoFilters9809 builds a multi-WAN steer: an address term into RI-A and
// a DSCP-only catch-all into RI-B, either as two ordered terms of ONE filter
// or as one term in each of two filters on two interfaces.
func oneOrTwoFilters9809(twoFilters bool) []string {
	lines := []string{
		"set interfaces ge-0/0/1 unit 0 family inet address 192.168.1.1/24",
		"set interfaces ge-0/0/2 unit 0 family inet address 192.168.2.1/24",
		"set routing-instances RI-A instance-type forwarding",
		"set routing-instances RI-B instance-type forwarding",
	}
	if !twoFilters {
		return append(lines,
			"set firewall family inet filter wan term to-a from source-address 172.16.80.198/32",
			"set firewall family inet filter wan term to-a then routing-instance RI-A",
			"set firewall family inet filter wan term to-b from dscp af31",
			"set firewall family inet filter wan term to-b then routing-instance RI-B",
			"set firewall family inet filter wan term rest then accept",
			"set interfaces ge-0/0/1 unit 0 family inet filter input wan",
		)
	}
	return append(lines,
		"set firewall family inet filter wa term to-a from source-address 172.16.80.198/32",
		"set firewall family inet filter wa term to-a then routing-instance RI-A",
		"set firewall family inet filter wa term rest then accept",
		"set firewall family inet filter wb term to-b from dscp af31",
		"set firewall family inet filter wb term to-b then routing-instance RI-B",
		"set firewall family inet filter wb term rest then accept",
		"set interfaces ge-0/0/1 unit 0 family inet filter input wa",
		"set interfaces ge-0/0/2 unit 0 family inet filter input wb",
	)
}

// TestOneFilterOrderedTermsAreNotACollision9809 pins why match-all steered
// space pairs only with ANOTHER filter's steered space. Within one filter the
// first matching term wins, so an address term followed by a DSCP catch-all
// into another WAN never steers one 5-tuple into both. That is
// TestFirewallFilter's multi-WAN filter, and the first cut of #9809 refused
// it. The same terms in two filters on two interfaces can steer one 5-tuple
// both ways, and are refused.
func TestOneFilterOrderedTermsAreNotACollision9809(t *testing.T) {
	if refused, _, _ := vrfVerdict9809(t, oneOrTwoFilters9809(false)); refused {
		t.Fatal("one filter: an address term and a DSCP catch-all into two WANs were refused; the first matching term decides, so this is not a collision")
	}
	if refused, _, admissions := vrfVerdict9809(t, oneOrTwoFilters9809(true)); !refused || admissions == 0 {
		t.Fatalf("two filters: want the overlap refused and metered, got refused=%v admissions=%d", refused, admissions)
	}
}
