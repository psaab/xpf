package config

import (
	"strings"
	"testing"
)

// #9495: an IPsec VPN name outside letters, digits, '-' and '_' is refused at commit, naming the
// VPN; the tolerant load / peer-sync path warns and keeps it. (A name containing '"' cannot be
// spelled as a set command; ipsecname's predicate cell and the render cell cover it.)
func TestIPsecVPNNameMustBeSectionSafe9495(t *testing.T) {
	for _, tc := range []struct {
		name   string
		vpn    string
		reject bool
	}{
		{"structure characters", "evil } # {", true},
		{"hash", "x # y", true},
		{"equals", "a=b", true},
		{"comma", "a,b", true},
		{"space", "a b", true},
		{"dot", "a.b", true},
		{"percent", "a%b", true},
		{"colon renames", "a:b", true},
		{"non-ASCII", "vpné", true},
		{"injected child", "x { children { p { mode = transport } } } y", true},
		{"slash (loads today, outside the allowlist)", "a/b", true},
		{"plain", "vpnplain", false},
		{"dash and underscore", "vpn-1_a", false},
	} {
		cfg, err := CompileConfig(setTree9623(t, tc.vpn))
		if tc.reject {
			if err == nil || !strings.Contains(err.Error(), "security ipsec vpn") {
				t.Errorf("%s: commit must refuse VPN name %q with a message naming it, got %v", tc.name, tc.vpn, err)
			}
		} else if err != nil {
			t.Errorf("%s: commit must accept VPN name %q, got %v", tc.name, tc.vpn, err)
		} else if cfg.Security.IPsec.VPNs[tc.vpn] == nil {
			t.Errorf("%s: FIXTURE: VPN %q must compile under its exact name", tc.name, tc.vpn)
		}

		lenient, lerr := CompileConfigLenient(setTree9623(t, tc.vpn))
		if lerr != nil {
			t.Errorf("%s: the tolerant path must not refuse %q: %v", tc.name, tc.vpn, lerr)
			continue
		}
		warned := false
		for _, w := range lenient.Warnings {
			if strings.Contains(w, "ipsec VPN section name") {
				warned = true
			}
		}
		if warned != tc.reject {
			t.Errorf("%s: tolerant-path section-name warning = %v, want %v (warnings %v)", tc.name, warned, tc.reject, lenient.Warnings)
		}
		if tc.reject && lenient.Security.IPsec.VPNs[tc.vpn] == nil {
			t.Errorf("%s: the tolerant path must keep VPN %q (the render belt decides whether it renders)", tc.name, tc.vpn)
		}
	}
}
