package configstore

import (
	"strings"
	"testing"
)

func hasPrefixCT9414(ws []string, prefix string) bool {
	for _, w := range ws {
		if strings.HasPrefix(w, prefix) {
			return true
		}
	}
	return false
}

// TestSNMPSyslogInertStatementsAreLoudAtCheckText9414 is #9414 on the operator
// channel. The pkg/config cells cover both compile channels and every spelling;
// this proves the advisory reaches `commit check`, that the config is still
// ACCEPTED there, and that the two advisories this family already had are
// unchanged.
func TestSNMPSyslogInertStatementsAreLoudAtCheckText9414(t *testing.T) {
	for _, tc := range []struct{ name, text, prefix string }{
		{"v3 vacm", "snmp { v3 { vacm { security-to-group { security-model usm; } } } }", "snmp v3 vacm:"},
		{"v3 usm remote-engine", "snmp { v3 { usm { remote-engine 800007e580 { user u1 { authentication-sha { authentication-password xpfpass123; } } } } } }", "snmp v3 usm remote-engine:"},
		{"engine-id", "snmp { engine-id { local 8000abcd; } }", "snmp engine-id:"},
		{"name", "snmp { name fw1; }", "snmp name:"},
		{"syslog host routing-instance", "system { syslog { host 10.0.0.9 { any any; routing-instance mgmt; } } }", "system syslog host routing-instance:"},
		{"syslog file match", "system { syslog { file messages { any any; match foo; } } }", "system syslog file match:"},
		{"syslog user match-strings", "system { syslog { user * { any emergency; match-strings foo; } } }", "system syslog user match-strings:"},
	} {
		t.Run("loud/"+tc.name, func(t *testing.T) {
			cfg, err := CheckText(tc.text, -1)
			if err != nil {
				t.Fatalf("CheckText REJECTED an operator-valid config; the remedy is an advisory, never a refusal: %v", err)
			}
			if !hasPrefixCT9414(cfg.Warnings, tc.prefix) {
				t.Errorf("#9414: commit check raised no advisory starting %q; warnings: %q", tc.prefix, cfg.Warnings)
			}
		})
	}
	for _, tc := range []struct{ name, text, keep string }{
		{"v3 local-engine user (implemented)", "snmp { v3 { usm { local-engine { user u1 { authentication-sha { authentication-password xpfpass123; } } } } } }", ""},
		{"syslog host modifiers xpf applies", "system { syslog { host 10.0.0.9 { any any; source-address 10.0.0.1; port 5514; } } }", ""},
		{"snmp view advisory unchanged", "snmp { view v1 { oid 1.3.6.1.2.1 include; } }", "snmp view:"},
		{"syslog file archive advisory unchanged", "system { syslog { file messages { any any; archive size 1m; } } }", `system syslog file "messages" archive`},
	} {
		t.Run("quiet/"+tc.name, func(t *testing.T) {
			cfg, err := CheckText(tc.text, -1)
			if err != nil {
				t.Fatalf("CheckText REJECTED: %v", err)
			}
			for _, w := range cfg.Warnings {
				if strings.Contains(w, "(#9414)") {
					t.Errorf("#9414: an advisory on a config whose #9414-family statements compile: %q", w)
				}
			}
			if tc.keep != "" && !hasPrefixCT9414(cfg.Warnings, tc.keep) {
				t.Errorf("the pre-existing advisory %q is gone; warnings: %q", tc.keep, cfg.Warnings)
			}
		})
	}
}
