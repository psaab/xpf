package config

import (
	"strings"
	"testing"
)

// #9624: two IPsec VPNs that render the same swanctl SA name fail commit, naming the VPNs and
// the name; the tolerant load / peer-sync path warns and keeps both. Distinct names commit, and
// so does a collision WITHIN one VPN, which the renderer disambiguates (#5122).

func setTree9624(t *testing.T, lines ...string) *ConfigTree {
	t.Helper()
	tree := &ConfigTree{}
	for _, cmd := range append([]string{"set security ike gateway gw1 address 198.51.100.1"}, lines...) {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("FIXTURE: ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("FIXTURE: SetPath(%q): %v", cmd, err)
		}
	}
	return tree
}

func vpn9624(name string, selectors ...string) []string {
	lines := []string{"set security ipsec vpn " + name + " ike gateway gw1"}
	for i, sel := range selectors {
		lines = append(lines,
			"set security ipsec vpn "+name+" traffic-selector "+sel+" local-ip 10.0."+string(rune('1'+i))+".0/24",
			"set security ipsec vpn "+name+" traffic-selector "+sel+" remote-ip 10.9."+string(rune('1'+i))+".0/24")
	}
	return lines
}

func TestIPsecSANameCollisionsFailCommit9624(t *testing.T) {
	for _, tc := range []struct {
		name    string
		lines   []string
		vpns    []string // VPNs that must stay configured
		reject  bool
		saName  string
		vpnList string
	}{
		{"child/child: a+b-c vs a-b+c", append(vpn9624("a", "b-c"), vpn9624("a-b", "c")...),
			[]string{"a", "a-b"}, true, "a-b-c", `"a", "a-b"`},
		{"connection/child: blue+red vs blue-red", append(vpn9624("blue", "red"), vpn9624("blue-red")...),
			[]string{"blue", "blue-red"}, true, "blue-red", `"blue", "blue-red"`},
		{"distinct names", append(vpn9624("east", "lan"), vpn9624("west", "lan")...),
			[]string{"east", "west"}, false, "", ""},
		{"within-VPN #5122 collision is disambiguated, not rejected", vpn9624("site", "x/a", "x:a"),
			[]string{"site"}, false, "", ""},
	} {
		cfg, err := CompileConfig(setTree9624(t, tc.lines...))
		if tc.reject {
			if err == nil {
				t.Errorf("%s: commit must reject the colliding SA name", tc.name)
			} else if msg := err.Error(); !strings.Contains(msg, `"`+tc.saName+`"`) || !strings.Contains(msg, tc.vpnList) {
				t.Errorf("%s: the message must name SA %q and VPNs %s, got: %v", tc.name, tc.saName, tc.vpnList, err)
			}
		} else {
			if err != nil {
				t.Errorf("%s: commit must accept, got %v", tc.name, err)
				continue
			}
			for _, v := range tc.vpns {
				if cfg.Security.IPsec.VPNs[v] == nil {
					t.Errorf("%s: FIXTURE: VPN %q must compile", tc.name, v)
				}
			}
		}

		lenient, lerr := CompileConfigLenient(setTree9624(t, tc.lines...))
		if lerr != nil {
			t.Errorf("%s: the tolerant path must not fail: %v", tc.name, lerr)
			continue
		}
		warned := false
		for _, w := range lenient.Warnings {
			if strings.Contains(w, "ipsec SA name collision") {
				warned = true
			}
		}
		if warned != tc.reject {
			t.Errorf("%s: tolerant-path warning = %v, want %v (warnings %q)", tc.name, warned, tc.reject, lenient.Warnings)
		}
		for _, v := range tc.vpns {
			if lenient.Security.IPsec.VPNs[v] == nil {
				t.Errorf("%s: FIXTURE: the tolerant path must keep VPN %q", tc.name, v)
			}
		}
	}
}
