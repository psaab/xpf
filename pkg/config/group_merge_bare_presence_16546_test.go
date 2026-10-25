package config

import (
	"slices"
	"testing"
)

// #16546: a bare presence statement inline (`ssh;`, `syslog;`, `rip;`)
// is the empty braced spelling (`ssh { }`), so a group's container for
// the same keyword must merge into it instead of being discarded by the
// #4325 cross-shape guard. The `def-bare-*` rows below must equal their
// braced controls; a valued inline leaf keeps suppressing the group, and
// the #4325/#4070 leaf-list cells still yield exactly one node.

func compile16546(t *testing.T, text string) *Config {
	t.Helper()
	tree := parseHierText(t, text)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if err := SchemaValidate(tree); err != nil {
		t.Fatalf("SchemaValidate rejected the fixture: %v", err)
	}
	return cfg
}

func sshOf16546(t *testing.T, cfg *Config) *SSHServiceConfig {
	t.Helper()
	if cfg.System.Services == nil || cfg.System.Services.SSH == nil {
		t.Fatalf("no SSH compiled: %+v", cfg.System.Services)
	}
	return cfg.System.Services.SSH
}

const groupSSH16546 = `groups { G { system { services { ssh { root-login deny; ciphers [ aes256-ctr aes192-ctr ]; connection-limit 10; } } } } } apply-groups G; `

func TestGroupBareSSHInheritsHardening16546(t *testing.T) {
	bare := compile16546(t, groupSSH16546+`system { services { ssh; } }`)
	braced := compile16546(t, groupSSH16546+`system { services { ssh { } } }`)
	for name, cfg := range map[string]*Config{"bare": bare, "braced": braced} {
		ssh := sshOf16546(t, cfg)
		if ssh.RootLogin != "deny" {
			t.Errorf("%s: RootLogin=%q want deny", name, ssh.RootLogin)
		}
		if !slices.Equal(ssh.Ciphers, []string{"aes256-ctr", "aes192-ctr"}) {
			t.Errorf("%s: Ciphers=%v want [aes256-ctr aes192-ctr]", name, ssh.Ciphers)
		}
		if ssh.ConnectionLimit != 10 {
			t.Errorf("%s: ConnectionLimit=%d want 10", name, ssh.ConnectionLimit)
		}
	}
	// Inline precedence inside the promoted container: an inline value
	// for the same scalar still wins over the group's.
	both := compile16546(t, groupSSH16546+`system { services { ssh { root-login allow; } } }`)
	if got := sshOf16546(t, both).RootLogin; got != "allow" {
		t.Errorf("braced inline root-login must still win, got %q", got)
	}
}

func TestGroupBareSyslogInheritsHost16546(t *testing.T) {
	group := `groups { G { system { syslog { host 10.0.0.9 { any warning; } } } } } apply-groups G; `
	bare := compile16546(t, group+`system { syslog; }`)
	braced := compile16546(t, group+`system { syslog { } }`)
	for name, cfg := range map[string]*Config{"bare": bare, "braced": braced} {
		if cfg.System.Syslog == nil || len(cfg.System.Syslog.Hosts) != 1 {
			t.Fatalf("%s: Syslog hosts = %+v want 1 host", name, cfg.System.Syslog)
		}
		h := cfg.System.Syslog.Hosts[0]
		if h.Address != "10.0.0.9" || len(h.Facilities) != 1 ||
			h.Facilities[0].Facility != "any" || h.Facilities[0].Severity != "warning" {
			t.Errorf("%s: host = %+v want 10.0.0.9 any/warning", name, h)
		}
	}
}
func TestGroupBareSNMPInherits16546(t *testing.T) {
	// `snmp` is a top-level container in the schema, so the bare peer is
	// a top-level `snmp;` beside a top-level group `snmp { ... }`.
	text := `groups { G { snmp { description GROUPDESC; } } } apply-groups G; snmp;`
	tree := parseHierText(t, text)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig snmp: %v", err)
	}
	if cfg.System.SNMP == nil || cfg.System.SNMP.Description != "GROUPDESC" {
		t.Fatalf("bare snmp; must inherit group description, got %+v", cfg.System.SNMP)
	}
}

func TestGroupBareLLDPInherits16546(t *testing.T) {
	text := `groups { G { protocols { lldp { interface ge-0/0/0.0; } } } } apply-groups G; protocols { lldp; }`
	tree := parseHierText(t, text)
	if err := tree.ExpandGroups(); err != nil {
		t.Fatalf("ExpandGroups lldp: %v", err)
	}
	proto := tree.FindChild("protocols")
	if proto == nil {
		t.Fatal("no protocols node")
	}
	lldp := proto.FindChild("lldp")
	if lldp == nil || lldp.IsLeaf {
		t.Fatalf("bare lldp; must promote to container, got %+v", lldp)
	}
	if len(lldp.FindChildren("interface")) != 1 {
		t.Fatalf("group lldp interface must inherit into bare lldp;, children=%v", lldp.Children)
	}
}
func TestGroupValuedLeafStillSuppresses16546(t *testing.T) {
	// A collapsed leaf-list carries values: it is not a presence
	// statement, so the #4325/#4070 union yields exactly one node and
	// no container twin.
	text := `
groups { G { system { name-server { 1.1.1.1; 2.2.2.2; } } } }
apply-groups G;
system { name-server 9.9.9.9; }
`
	tree := parseHierText(t, text)
	if err := tree.ExpandGroups(); err != nil {
		t.Fatalf("ExpandGroups: %v", err)
	}
	ns := systemNameServerNodes(t, tree)
	if len(ns) != 1 {
		t.Fatalf("name-server nodes = %d want exactly 1 (#4325 invariant)", len(ns))
	}
	assertMembers(t, "collapsed vs block union", nameServerValues(ns[0]),
		[]string{"9.9.9.9", "1.1.1.1", "2.2.2.2"})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	_ = cfg
}

func TestGroupBarePresenceNodeCount16546(t *testing.T) {
	// Exactly one ssh node after expansion: promotion merges in place,
	// it must not adopt a twin beside the bare leaf.
	text := groupSSH16546 + `system { services { ssh; } }`
	// Re-wrap: groupSSH16546 already carries apply-groups at top level;
	// build the tree directly.
	_ = text
	full := `
groups { G { system { services { ssh { root-login deny; } } } } }
apply-groups G;
system { services { ssh; } }
`
	tree := parseHierText(t, full)
	if err := tree.ExpandGroups(); err != nil {
		t.Fatalf("ExpandGroups: %v", err)
	}
	sys := tree.FindChild("system")
	if sys == nil {
		t.Fatal("no system node")
	}
	svcs := sys.FindChildren("services")
	count := 0
	for _, sv := range svcs {
		count += len(sv.FindChildren("ssh"))
	}
	if count != 1 {
		t.Fatalf("ssh nodes after bare promotion = %d want 1", count)
	}
}
