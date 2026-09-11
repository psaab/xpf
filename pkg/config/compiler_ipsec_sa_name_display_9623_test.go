package config

import (
	"strings"
	"testing"
)

// #9623: an IPsec VPN name that is not display-safe renders raw into swanctl but is published
// over HA IPsec SA sync display-escaped, so failover never re-initiates that tunnel. Commit
// rejects it; the tolerant load / peer-sync path warns and keeps the VPN. The rune rows are the
// issue's measured probe (a C1 control and U+2028 diverge; U+202E and a plain name do not).

func setTree9623(t *testing.T, vpnName string) *ConfigTree {
	t.Helper()
	tree := &ConfigTree{}
	for _, cmd := range []string{
		"set security ike gateway gw1 address 198.51.100.1",
		`set security ipsec vpn "` + vpnName + `" ike gateway gw1`,
	} {
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

func TestIPsecVPNNameMustBeDisplaySafe9623(t *testing.T) {
	// reject is whether COMMIT refuses the name; displayUnsafe is whether the #9623 gate
	// itself fires. They agreed for every row until #9495. U+202E is display-safe, so the #9623
	// property holds and #9623 stays silent. But the #9495 measurement (docs/log/9495.md) found
	// strongSwan refuses a non-ASCII VPN name (exit 22), and the #9495 section-name allowlist now
	// refuses it at commit.
	for _, tc := range []struct {
		name          string
		vpn           string
		reject        bool
		displayUnsafe bool
	}{
		{"C1 control (CSI)", "vpn\u009bx", true, true},
		{"line separator", "vpn\u2028x", true, true},
		{"paragraph separator", "vpn\u2029x", true, true},
		{"invalid UTF-8", "vpn\xffx", true, true},
		{"bidi override (display-safe; refused at commit by #9495, not #9623)", "vpn\u202ex", true, false},
		{"plain", "vpnplain", false, false},
	} {
		cfg, err := CompileConfig(setTree9623(t, tc.vpn))
		if tc.reject {
			if err == nil || !strings.Contains(err.Error(), "security ipsec vpn") {
				t.Errorf("%s: commit must reject the VPN name with a message naming it, got err %v", tc.name, err)
			}
		} else {
			if err != nil {
				t.Errorf("%s: commit must accept the VPN name, got %v", tc.name, err)
				continue
			}
			if cfg.Security.IPsec.VPNs[tc.vpn] == nil {
				t.Errorf("%s: FIXTURE: the VPN must compile under its exact name", tc.name)
			}
		}

		lenient, lerr := CompileConfigLenient(setTree9623(t, tc.vpn))
		if lerr != nil {
			t.Errorf("%s: the tolerant path must not fail: %v", tc.name, lerr)
			continue
		}
		warned := false
		for _, w := range lenient.Warnings {
			if strings.Contains(w, "ipsec SA name display safety") {
				warned = true
			}
		}
		if warned != tc.displayUnsafe {
			t.Errorf("%s: tolerant-path display-safety warning = %v, want %v (warnings %q)", tc.name, warned, tc.displayUnsafe, lenient.Warnings)
		}
		if lenient.Security.IPsec.VPNs[tc.vpn] == nil {
			t.Errorf("%s: FIXTURE: the tolerant path must keep the VPN under its exact name, or the "+
				"rows below it test a different name", tc.name)
		}
	}
}
