package config

import "testing"

// #9561: three brace-elided spellings of an SNMPv3 USM user passed every config
// channel and compiled to ZERO users, with no warning. The braced spelling and
// the #7653 spelling compiled the user. The operator's user did not exist, so
// SNMPv3 management silently failed closed.
//
// Each cell pins what the elided spelling must COMPILE TO: the user, its
// protocol and a non-empty password, on the strict AND the tolerant path. An
// equivalence check alone is satisfied when every spelling is broken (#7653's
// lesson), so the braced and #7653 spellings run in the same test as controls
// rather than as the assertion.
func TestElidedUSMSpellingsCompileTheUser9561(t *testing.T) {
	const body = `{ authentication-sha256 { authentication-password "xpfpass9561"; } privacy-aes128 { privacy-password "xpfpriv9561"; } }`
	for _, sp := range []struct {
		label, src string
	}{
		{"control: braced", `snmp { v3 { usm { local-engine { user u1 ` + body + ` } } } }`},
		{"control: #7653 usm local-engine", `snmp { v3 { usm local-engine { user u1 ` + body + ` } } }`},
		{"elided v3 usm", `snmp { v3 usm { local-engine { user u1 ` + body + ` } } }`},
		{"elided v3 usm local-engine", `snmp { v3 usm local-engine { user u1 ` + body + ` } }`},
		{"elided v3 usm local-engine user", `snmp { v3 usm local-engine user u1 ` + body + ` }`},
	} {
		sp := sp
		t.Run(sp.label, func(t *testing.T) {
			tree, errs := NewParser(sp.src).Parse()
			if len(errs) > 0 {
				t.Fatalf("parse: %v", errs[0])
			}
			for _, path := range []struct {
				name    string
				compile func(*ConfigTree) (*Config, error)
			}{{"strict", CompileConfig}, {"lenient", CompileConfigLenient}} {
				cfg, err := path.compile(tree)
				if err != nil {
					t.Fatalf("%s compile: %v", path.name, err)
				}
				if cfg.System.SNMP == nil {
					t.Fatalf("%s: no SNMP config compiled", path.name)
				}
				u := cfg.System.SNMP.V3Users["u1"]
				if u == nil {
					t.Fatalf("%s: user u1 not compiled (users=%d); the elided spelling "+
						"silently drops every SNMPv3 user (#9561)", path.name, len(cfg.System.SNMP.V3Users))
				}
				if u.AuthProtocol != "sha256" || string(u.AuthPassword) != "xpfpass9561" ||
					u.PrivProtocol != "aes128" || string(u.PrivPassword) != "xpfpriv9561" {
					t.Errorf("%s: user u1 compiled auth=%q/%t priv=%q/%t, want sha256 and aes128 with "+
						"their passwords", path.name, u.AuthProtocol, u.AuthPassword != "",
						u.PrivProtocol, u.PrivPassword != "")
				}
			}
		})
	}
}
