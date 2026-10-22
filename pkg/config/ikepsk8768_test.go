package config

import (
	"fmt"
	"testing"
)

func TestIkePskDiff8768(t *testing.T) {
	const prop = `proposal pr1 { authentication-method pre-shared-keys; dh-group group14; authentication-algorithm sha1; encryption-algorithm aes-128-cbc; }`
	packed := "security { ike { " + prop + " policy p1 pre-shared-key ascii-text SEKRIT mode main; } }"
	braced := "security { ike { " + prop + " policy p1 { pre-shared-key ascii-text SEKRIT; mode main; } } }"
	get := func(txt string) string {
		tr, perrs := NewParser(txt).Parse()
		if len(perrs) > 0 {
			return "<parse err>"
		}
		cfg, err := compileTree(tr, lenientCompileOpts(), nil)
		if err != nil || cfg == nil {
			return fmt.Sprintf("<err %v>", err)
		}
		out := ""
		for _, p := range cfg.Security.IPsec.IKEPolicies {
			out += fmt.Sprintf("psk=%q mode=%q", p.PSK, p.Mode)
		}
		return out
	}
	p, b := get(packed), get(braced)
	t.Logf("PACKED %s", p)
	t.Logf("BRACED %s", b)
	if p != b {
		t.Errorf("the two spellings must compile identically (#8768)")
	}
}
