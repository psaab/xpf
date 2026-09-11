package config

import (
	"strings"
	"testing"
)

// #9494: strict commit-check must reject a bridge-domain name carrying a path
// separator, and still accept a plain one.
func TestBridgeDomainNameRejectsPathSeparators_9494(t *testing.T) {
	build := func(cmds ...string) *ConfigTree {
		t.Helper()
		tr := &ConfigTree{}
		for _, c := range cmds {
			p, err := ParseSetCommand(c)
			if err != nil {
				t.Fatalf("parse %q: %v", c, err)
			}
			if err := tr.SetPath(p); err != nil {
				t.Fatalf("setpath %q: %v", c, err)
			}
		}
		return tr
	}
	for _, bad := range []string{`x/../../pwnbd`, `x/../../../../../../etc/cron.d/pwn`, `a\\b`} {
		err := SchemaValidate(build(`set bridge-domains "`+bad+`" vlan-id-list 10`), nil)
		if err == nil || !strings.Contains(err.Error(), "path separator") {
			t.Fatalf("#9494: bridge-domain %q must be rejected at commit, got %v", bad, err)
		}
	}
	if err := SchemaValidate(build(`set bridge-domains bd0 vlan-id-list 10`), nil); err != nil {
		t.Fatalf("control: a plain bridge-domain name must commit, got %v", err)
	}
}
