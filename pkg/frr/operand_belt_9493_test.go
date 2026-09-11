package frr

import (
	"regexp"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #9493 render belts. The commit gate refuses these values, but a value
// persisted or peer-synced before the gate existed still reaches the renderer,
// and one rejected line fails the whole managed reload.

func TestFRRNameIsOneTokenAndStable9493(t *testing.T) {
	for _, safe := range []string{"EXPORT", "export-v4", "p.1", "a_b"} {
		if got := frrName(safe); got != safe {
			t.Errorf("frrName(%q) = %q; a name FRR can carry must render byte-identically", safe, got)
		}
	}
	for _, bad := range []string{"POI SON", "a\tb", "x\nrouter bgp 65000", ""} {
		got := frrName(bad)
		if !config.FRRSingleToken(got) {
			t.Errorf("frrName(%q) = %q is not one token", bad, got)
		}
		if got != frrName(bad) {
			t.Errorf("frrName(%q) is not deterministic", bad)
		}
	}
	// Two UNSAFE names with the same sanitized fragment are the collision the
	// hash exists for: "a b" and "a\tb" both sanitize to "a_b". Without the hash
	// they would render as ONE route-map, merging two policies. (A safe name
	// such as "a_b" is returned unchanged, so it can never reach this.)
	if frrName("a b") == frrName("a\tb") {
		t.Errorf("frrName collides for two unsafe names with one fragment: %q", frrName("a b"))
	}
	if frrName("a b") == frrName("a_b") || frrName("a b") == frrName("a.b") {
		t.Errorf("frrName collides with a safe name: %q %q %q", frrName("a b"), frrName("a_b"), frrName("a.b"))
	}
}

func TestScalarOperandBelts9493(t *testing.T) {
	m := &Manager{}
	ospf := func(neighbor, transit string, cost int) *config.OSPFConfig {
		return &config.OSPFConfig{Areas: []*config.OSPFArea{{
			ID:           "0.0.0.1",
			VirtualLinks: []*config.OSPFVirtualLink{{NeighborID: neighbor, TransitArea: transit}},
			Interfaces:   []*config.OSPFInterface{{Name: "ge-0-0-0", Cost: cost}},
		}}}
	}
	good := m.generateProtocols(ospf("1.1.1.1", "0.0.0.1", 10), nil, nil, nil, nil, "", 0, nil, nil)
	for _, want := range []string{" area 0.0.0.1 virtual-link 1.1.1.1\n", " ip ospf cost 10\n"} {
		if !strings.Contains(good, want) {
			t.Fatalf("control: a valid OSPF config must render %q, got:\n%s", want, good)
		}
	}
	for _, tc := range []struct{ neighbor, transit string }{
		{"1.1.1.1 POISON", "0.0.0.1"}, {"2001:db8::1", "0.0.0.1"}, {"1.1.1.1", "0.0.0.1 POISON"}, {"1.1.1.1", "not-an-area"},
	} {
		if out := m.generateProtocols(ospf(tc.neighbor, tc.transit, 10), nil, nil, nil, nil, "", 0, nil, nil); strings.Contains(out, "virtual-link") {
			t.Errorf("virtual-link neighbor=%q transit=%q rendered:\n%s", tc.neighbor, tc.transit, out)
		}
	}
	if out := m.generateProtocols(ospf("1.1.1.1", "0.0.0.1", 99999999), nil, nil, nil, nil, "", 0, nil, nil); !strings.Contains(out, " ip ospf cost 65535\n") {
		t.Errorf("an out-of-range OSPF cost must clamp to 65535, got:\n%s", out)
	}
	v3 := &config.OSPFv3Config{Areas: []*config.OSPFv3Area{{ID: "0.0.0.0", Interfaces: []*config.OSPFv3Interface{{Name: "ge-0-0-0", Cost: 70000}}}}}
	if out := m.generateProtocols(nil, v3, nil, nil, nil, "", 0, nil, nil); !strings.Contains(out, " ipv6 ospf6 cost 65535\n") {
		t.Errorf("an out-of-range OSPFv3 cost must clamp to 65535, got:\n%s", out)
	}

	bgp := func(local string, ttl int) *config.BGPConfig {
		return &config.BGPConfig{LocalAS: 65000, Neighbors: []*config.BGPNeighbor{{Address: "10.0.0.1", PeerAS: 65001, LocalAddress: local, MultihopTTL: ttl}}}
	}
	out := m.generateProtocols(nil, nil, bgp("10.0.0.2", 5), nil, nil, "", 0, nil, nil)
	for _, want := range []string{" neighbor 10.0.0.1 update-source 10.0.0.2\n", " neighbor 10.0.0.1 ebgp-multihop 5\n"} {
		if !strings.Contains(out, want) {
			t.Fatalf("control: a valid neighbor must render %q, got:\n%s", want, out)
		}
	}
	out = m.generateProtocols(nil, nil, bgp("10.0.0.2 POISON", 999), nil, nil, "", 0, nil, nil)
	if strings.Contains(out, "update-source") || strings.Contains(out, "POISON") {
		t.Errorf("a multi-token update-source must be omitted, got:\n%s", out)
	}
	if !strings.Contains(out, " neighbor 10.0.0.1 ebgp-multihop 255\n") {
		t.Errorf("an out-of-range multihop TTL must clamp to 255, got:\n%s", out)
	}

	isis := func(net string) string {
		return m.generateProtocols(nil, nil, nil, nil, &config.ISISConfig{NET: net, Level: "level-2"}, "", 0, nil, nil)
	}
	if out := isis("49.0001.1921.6800.1001.00"); !strings.Contains(out, " net 49.0001.1921.6800.1001.00\n") {
		t.Fatalf("control: a valid NET must render, got:\n%s", out)
	}
	for _, bad := range []string{"49.0001.0000.0000.0001.00 POISON", "49.0001", "49.0001.zzzz.6800.1001.00"} {
		if out := isis(bad); strings.Contains(out, " net ") {
			t.Errorf("NET %q rendered:\n%s", bad, out)
		}
	}
}

// Every route-map, prefix-list, community-list and as-path name reaches the
// managed section through several definition AND reference sites. This census
// is behavioural rather than a list of sites: it renders a config whose every
// name carries a space. It asserts that no line carries a raw name, and that
// every reference resolves to a definition. A site that was missed shows up as
// either a raw name or a dangling reference.
func TestEveryRenderedObjectNameIsOneTokenAndResolves9493(t *testing.T) {
	names := map[string]string{"PL": "P L", "CM": "C M", "AP": "A P", "EX": "E X", "SE": "S E", "T1": "T 1", "T2": "T 2"}
	render := func(n map[string]string) string {
		cmds := []string{
			"set routing-options autonomous-system 65000",
			"set routing-options router-id 10.0.0.1",
			`set policy-options prefix-list "` + n["PL"] + `" 10.0.0.0/8`,
			`set policy-options community "` + n["CM"] + `" members 65000:1`,
			`set policy-options as-path "` + n["AP"] + `" "^65000$"`,
			`set policy-options policy-statement "` + n["EX"] + `" term "` + n["T1"] + `" from prefix-list "` + n["PL"] + `"`,
			`set policy-options policy-statement "` + n["EX"] + `" term "` + n["T1"] + `" from community "` + n["CM"] + `"`,
			`set policy-options policy-statement "` + n["EX"] + `" term "` + n["T1"] + `" from as-path "` + n["AP"] + `"`,
			`set policy-options policy-statement "` + n["EX"] + `" term "` + n["T1"] + `" then community delete "` + n["CM"] + `"`,
			`set policy-options policy-statement "` + n["EX"] + `" term "` + n["T1"] + `" then accept`,
			`set policy-options policy-statement "` + n["EX"] + `" term "` + n["T2"] + `" from route-filter 10.1.0.0/16 orlonger`,
			`set policy-options policy-statement "` + n["EX"] + `" term "` + n["T2"] + `" from prefix-list "` + n["PL"] + `"`,
			`set policy-options policy-statement "` + n["EX"] + `" term "` + n["T2"] + `" then accept`,
			`set policy-options policy-statement "` + n["SE"] + `" term t from protocol static`,
			`set policy-options policy-statement "` + n["SE"] + `" term t then accept`,
			"set protocols bgp group g1 type external",
			"set protocols bgp group g1 peer-as 65001",
			`set protocols bgp group g1 neighbor 10.0.0.2 export "` + n["EX"] + `"`,
			`set protocols bgp group g1 neighbor 10.0.0.2 export "` + n["SE"] + `"`,
			`set protocols bgp group g1 neighbor 10.0.0.3 export "` + n["EX"] + `"`,
			`set protocols bgp group g1 neighbor 10.0.0.3 import "` + n["SE"] + `"`,
			`set protocols ospf export "` + n["SE"] + `"`,
			"set protocols ospf area 0.0.0.0 interface ge-0/0/0.0",
		}
		tree := &config.ConfigTree{}
		for _, c := range cmds {
			path, err := config.ParseSetCommand(c)
			if err != nil {
				t.Fatalf("ParseSetCommand(%q): %v", c, err)
			}
			if err := tree.SetPath(path); err != nil {
				t.Fatalf("SetPath(%q): %v", c, err)
			}
		}
		cfg, err := config.CompileConfigLenient(tree)
		if err != nil {
			t.Fatalf("lenient compile: %v", err)
		}
		m := New()
		fc := &FullConfig{BGP: cfg.Protocols.BGP, OSPF: cfg.Protocols.OSPF, PolicyOptions: &cfg.PolicyOptions}
		return m.buildManagedSection(fc)
	}

	defs := map[string]*regexp.Regexp{
		"route-map":   regexp.MustCompile(`(?m)^route-map (\S+) (?:permit|deny) \d+$`),
		"prefix-list": regexp.MustCompile(`(?m)^(?:ip|ipv6) prefix-list (\S+) seq `),
		"community":   regexp.MustCompile(`(?m)^bgp community-list (?:standard|expanded) (\S+) permit `),
		"as-path":     regexp.MustCompile(`(?m)^bgp as-path access-list (\S+) permit `),
		"access-list": regexp.MustCompile(`(?m)^(?:ipv6 )?access-list (\S+) seq `),
	}
	refs := []struct {
		kind string
		re   *regexp.Regexp
	}{
		{"route-map", regexp.MustCompile(`(?m)^\s*neighbor \S+ route-map (\S+) (?:in|out)$`)},
		{"route-map", regexp.MustCompile(`(?m)^\s*redistribute \S+ route-map (\S+)$`)},
		{"prefix-list", regexp.MustCompile(`(?m)^\s*match (?:ip|ipv6) address prefix-list (\S+)$`)},
		{"access-list", regexp.MustCompile(`(?m)^\s*match (?:ip|ipv6) address (\S+)$`)},
		{"community", regexp.MustCompile(`(?m)^\s*match community (\S+)$`)},
		{"community", regexp.MustCompile(`(?m)^\s*set comm-list (\S+) delete$`)},
		{"as-path", regexp.MustCompile(`(?m)^\s*match as-path (\S+)$`)},
	}
	check := func(label, out string) {
		defined := map[string]map[string]bool{}
		for kind, re := range defs {
			defined[kind] = map[string]bool{}
			for _, mm := range re.FindAllStringSubmatch(out, -1) {
				defined[kind][mm[1]] = true
			}
		}
		for _, r := range refs {
			found := r.re.FindAllStringSubmatch(out, -1)
			// Positive control: the fixture must exercise every reference
			// shape, or a missed site could hide in a shape that never renders.
			if len(found) == 0 {
				t.Errorf("%s: no %s reference matched %s; the census is not exercising it:\n%s", label, r.kind, r.re, out)
			}
			for _, mm := range found {
				if !defined[r.kind][mm[1]] {
					t.Errorf("%s: %s reference %q has no definition:\n%s", label, r.kind, mm[1], out)
				}
			}
		}
	}

	unsafe := render(names)
	for _, raw := range names {
		for _, line := range strings.Split(unsafe, "\n") {
			if strings.Contains(line, raw) {
				t.Errorf("a raw name %q reached frr.conf: %q", raw, line)
			}
		}
	}
	check("spaced names", unsafe)

	safe := map[string]string{}
	for k := range names {
		safe[k] = k
	}
	safeOut := render(safe)
	check("safe names", safeOut)
	for _, want := range []string{"ip prefix-list PL seq", "bgp as-path access-list AP permit", " match community CM\n"} {
		if !strings.Contains(safeOut, want) {
			t.Errorf("control: a safe name must render verbatim (%q), got:\n%s", want, safeOut)
		}
	}
}
