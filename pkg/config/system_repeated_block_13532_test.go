package config

import "testing"

// #13532: repeated/flat `system` sub-blocks must merge, not reset.
//
// Three defects at compiler_system.go (master 98d56af14):
//   - `case "syslog":` assigned a fresh &SystemSyslogConfig{} on every
//     invocation, so a second `system { syslog { ... } }` root (or a second
//     `syslog` child inside one `system` block) wiped the first block's
//     hosts/files/users.
//   - The services tail read only node.FindChild("services"), which sees
//     Children only: a flat `set system services ssh ...` line packs the
//     whole run onto the `system` node's Keys, leaving Services nil.
//   - Same for snmp: node.FindChild("snmp") missed the flat form, so
//     `set system snmp location ...` yielded SNMP == nil. compileSNMP also
//     assigned a fresh *SNMPConfig for each invocation, so later blocks wiped
//     earlier fields.
func compileSystem13532Hier(t *testing.T, text string) *Config {
	t.Helper()
	tree := parseHierarchical(t, text)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	return cfg
}

func compileSystem13532Roots(t *testing.T, blocks ...string) *Config {
	t.Helper()
	tree := &ConfigTree{}
	for _, block := range blocks {
		parsed := parseHierarchical(t, block)
		tree.Children = append(tree.Children, parsed.Children...)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	return cfg
}

func compileSystem13532Set(t *testing.T, lines ...string) *Config {
	t.Helper()
	return compileSetLines(t, lines)
}

// carrying a `syslog` block must keep BOTH blocks' destinations.
func TestSystemRepeatedSyslogBlocks13532(t *testing.T) {
	cfg := compileSystem13532Roots(t,
		`system { syslog { host 10.0.0.1 any any; } }`,
		`system { syslog { host 10.0.0.2 any any; } }`,
	)
	if cfg.System.Syslog == nil {
		t.Fatalf("System.Syslog is nil")
	}
	if len(cfg.System.Syslog.Hosts) != 2 {
		t.Fatalf("Hosts = %d, want 2 (first syslog block wiped by second)", len(cfg.System.Syslog.Hosts))
	}
	got := map[string]bool{}
	for _, h := range cfg.System.Syslog.Hosts {
		got[h.Address] = true
	}
	if !got["10.0.0.1"] || !got["10.0.0.2"] {
		t.Fatalf("Hosts = %v, want both 10.0.0.1 and 10.0.0.2", got)
	}
}

func TestSystemRepeatedSameSyslogHost13532(t *testing.T) {
	cfg := compileSystem13532Roots(t,
		`system { syslog { host 10.0.0.1 daemon info; } }`,
		`system { syslog { host 10.0.0.1 auth warning; } }`,
	)
	if len(cfg.System.Syslog.Hosts) != 1 {
		t.Fatalf("Hosts = %d, want one merged destination", len(cfg.System.Syslog.Hosts))
	}
	facilities := cfg.System.Syslog.Hosts[0].Facilities
	if len(facilities) != 2 || facilities[0] != (SyslogFacility{Facility: "daemon", Severity: "info"}) ||
		facilities[1] != (SyslogFacility{Facility: "auth", Severity: "warning"}) {
		t.Fatalf("Facilities = %#v, want daemon info then auth warning", facilities)
	}
}

// TestSystemRepeatedSyslogChildren13532: two `syslog` children inside ONE
// `system` block must also merge.
func TestSystemRepeatedSyslogChildren13532(t *testing.T) {
	cfg := compileSystem13532Hier(t, `
		system {
			syslog { host 10.0.0.1 any any; }
			syslog { file messages any any; }
		}
	`)
	if cfg.System.Syslog == nil {
		t.Fatalf("System.Syslog is nil")
	}
	if len(cfg.System.Syslog.Hosts) != 1 {
		t.Fatalf("Hosts = %d, want 1 (first syslog child wiped)", len(cfg.System.Syslog.Hosts))
	}
	if len(cfg.System.Syslog.Files) != 1 {
		t.Fatalf("Files = %d, want 1", len(cfg.System.Syslog.Files))
	}
}

// TestSystemFlatServices13532: flat-set `system services ssh` must
// populate System.Services exactly like the braced spelling.
func TestSystemFlatServices13532(t *testing.T) {
	cfg := compileSystem13532Set(t,
		"set system services ssh root-login allow",
		"set system services ssh protocol-version v2",
	)
	if cfg.System.Services == nil {
		t.Fatalf("System.Services is nil for flat `set system services ...`")
	}
	if cfg.System.Services.SSH == nil {
		t.Fatalf("System.Services.SSH is nil for flat form")
	}
	if cfg.System.Services.SSH.RootLogin != "allow" {
		t.Fatalf("SSH.RootLogin = %q, want allow", cfg.System.Services.SSH.RootLogin)
	}
	if cfg.System.Services.SSH.ProtocolVersion != "v2" {
		t.Fatalf("SSH.ProtocolVersion = %q, want v2", cfg.System.Services.SSH.ProtocolVersion)
	}
}

// Brace-elided `system` statements pack their bodies on the system node's
// Keys rather than in Children. Services and SNMP must still be discovered.
func TestSystemPackedServicesAndSNMP13532(t *testing.T) {
	services := compileSystem13532Hier(t, `system services ssh root-login allow;`)
	if services.System.Services == nil || services.System.Services.SSH == nil ||
		services.System.Services.SSH.RootLogin != "allow" {
		t.Fatalf("packed services compiled as %#v, want SSH root-login allow", services.System.Services)
	}

	tree := parseHierarchical(t, `system snmp location lab;`)
	snmp, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if snmp.System.SNMP == nil || snmp.System.SNMP.Location != "lab" {
		t.Fatalf("packed SNMP compiled as %#v, want location lab", snmp.System.SNMP)
	}
}

// TestSystemFlatSNMP13532: flat-set `system snmp` must populate
// System.SNMP exactly like the braced spelling.
func TestSystemFlatSNMP13532(t *testing.T) {
	cfg := compileSystem13532Set(t,
		`set system snmp location lab`,
		`set system snmp contact "ops@example.com"`,
		`set system snmp community public authorization read-only`,
	)
	if cfg.System.SNMP == nil {
		t.Fatalf("System.SNMP is nil for flat `set system snmp ...`")
	}
	if cfg.System.SNMP.Location != "lab" {
		t.Fatalf("SNMP.Location = %q, want lab", cfg.System.SNMP.Location)
	}
	if cfg.System.SNMP.Contact != "ops@example.com" {
		t.Fatalf("SNMP.Contact = %q, want ops@example.com", cfg.System.SNMP.Contact)
	}
	if c := cfg.System.SNMP.Communities["public"]; c == nil {
		t.Fatalf("SNMP.Communities[public] is nil, got %v", cfg.System.SNMP.Communities)
	}
}

func TestSystemRepeatedServicesAndSNMPChildren13532(t *testing.T) {
	cfg := compileSystem13532Hier(t, `
		system {
			services { ssh { root-login allow; } }
			services { ssh { protocol-version v2; } }
			snmp { location lab; }
			snmp { contact "ops@example.com"; }
		}
	`)
	if cfg.System.Services == nil || cfg.System.Services.SSH == nil {
		t.Fatalf("System.Services.SSH is nil")
	}
	if cfg.System.Services.SSH.RootLogin != "allow" || cfg.System.Services.SSH.ProtocolVersion != "v2" {
		t.Fatalf("SSH = %#v, want root-login allow and protocol-version v2", cfg.System.Services.SSH)
	}
	if cfg.System.SNMP == nil || cfg.System.SNMP.Location != "lab" ||
		cfg.System.SNMP.Contact != "ops@example.com" {
		t.Fatalf("SNMP = %#v, want location and contact from both child blocks", cfg.System.SNMP)
	}
}

func TestSystemRepeatedSSHAcrossSystemRoots13532(t *testing.T) {
	cfg := compileSystem13532Roots(t,
		`system { services { ssh { root-login allow; } } }`,
		`system { services { ssh { protocol-version v2; } } }`,
	)
	if cfg.System.Services == nil || cfg.System.Services.SSH == nil ||
		cfg.System.Services.SSH.RootLogin != "allow" || cfg.System.Services.SSH.ProtocolVersion != "v2" {
		t.Fatalf("SSH = %#v, want root-login allow and protocol-version v2", cfg.System.Services)
	}
}

func TestSystemRepeatedSNMPQuarantineStaysFailClosed13532(t *testing.T) {
	tree := &ConfigTree{}
	for _, block := range []string{
		`system { snmp { community mon { clients { 10.0.0.0/8 restric; } } } }`,
		`system { snmp { community mon { clients { 0.0.0.0/0; } } } }`,
	} {
		parsed := parseHierarchical(t, block)
		tree.Children = append(tree.Children, parsed.Children...)
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	community := cfg.System.SNMP.Communities["mon"]
	if community == nil {
		t.Fatal("community mon missing")
	}
	for _, source := range []string{"8.8.8.8", "10.1.2.3", "2001:db8::1"} {
		if community.AllowsSource(snmpClientTestSource10687(source)) {
			t.Errorf("quarantined community allowed %s after later block", source)
		}
	}
}

// TestSystemRepeatedSNMPBlocks13532: two sibling `system { snmp {} }`
// blocks must keep both blocks' fields.
func TestSystemRepeatedSNMPBlocks13532(t *testing.T) {
	cfg := compileSystem13532Roots(t,
		`system { snmp { location lab; } }`,
		`system { snmp { contact "ops@example.com"; } }`,
	)
	if cfg.System.SNMP == nil {
		t.Fatalf("System.SNMP is nil")
	}
	if cfg.System.SNMP.Location != "lab" {
		t.Fatalf("SNMP.Location = %q, want lab (first snmp block wiped)", cfg.System.SNMP.Location)
	}
	if cfg.System.SNMP.Contact != "ops@example.com" {
		t.Fatalf("SNMP.Contact = %q, want ops@example.com", cfg.System.SNMP.Contact)
	}
}
