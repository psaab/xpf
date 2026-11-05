package config

import "testing"

func compileSNMPText18844(t *testing.T, text string, lenient bool) (*Config, error) {
	t.Helper()
	tree, errs := NewParser(text).Parse()
	if len(errs) != 0 {
		t.Fatalf("parse SNMP config: %v", errs)
	}
	if lenient {
		return CompileConfigLenient(tree)
	}
	return CompileConfig(tree)
}

func TestSNMPClientListMalformedFragmentQuarantinesAcrossSystemRoots18844(t *testing.T) {
	const validRoot = `system {
    host-name fw;
    snmp {
        client-list mgmt { 0.0.0.0/0; }
        community scoped { authorization read-only; client-list-name mgmt; }
    }
}`
	const malformedRoot = `system {
    domain-name example.test;
    snmp { client-list mgmt { 10.1.0.0/16 restrict extra; } }
}`
	for _, tc := range []struct {
		name string
		text string
	}{
		{"valid fragment first", validRoot + "\n" + malformedRoot},
		{"malformed fragment first", malformedRoot + "\n" + validRoot},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := compileSNMPText18844(t, tc.text, false); err == nil {
				t.Fatal("strict compilation accepted a malformed named client-list fragment")
			}
			cfg, err := compileSNMPText18844(t, tc.text, true)
			if err != nil {
				t.Fatalf("lenient compilation rejected malformed stored config: %v", err)
			}
			if cfg.System.SNMP == nil {
				t.Fatal("SNMP config was not compiled")
			}
			if got := cfg.System.SNMP.ClientLists["mgmt"]; len(got) != 0 {
				t.Fatalf("tainted named client-list retained entries: %+v", got)
			}
			community := cfg.System.SNMP.Communities["scoped"]
			if community == nil {
				t.Fatal("community scoped was not compiled")
			}
			for _, source := range []string{"8.8.8.8", "10.1.2.7"} {
				if community.AllowsSource(snmpClientTestSource10687(source)) {
					t.Errorf("community allowed %s after a malformed fragment tainted its named list", source)
				}
			}
			if len(community.clientNets) != 2 {
				t.Fatalf("community enforcement cache = %+v, want explicit IPv4+IPv6 quarantine", community.clientNets)
			}
			for _, entry := range community.clientNets {
				if !entry.restrict || entry.ones != 0 {
					t.Fatalf("community enforcement cache = %+v, want deny-all quarantine entries", community.clientNets)
				}
			}
		})
	}
}

func TestSNMPValidClientListFragmentsDoNotOverQuarantine18844(t *testing.T) {
	const text = `system {
    host-name fw;
    snmp {
        client-list mgmt { 0.0.0.0/0; }
        community scoped { authorization read-only; client-list-name mgmt; }
    }
}
system {
    domain-name example.test;
    snmp { client-list mgmt { 10.1.0.0/16; } }
}`
	for _, lenient := range []bool{false, true} {
		cfg, err := compileSNMPText18844(t, text, lenient)
		if err != nil {
			t.Fatalf("lenient=%v compilation rejected valid fragments: %v", lenient, err)
		}
		community := cfg.System.SNMP.Communities["scoped"]
		if community == nil || !community.AllowsSource(snmpClientTestSource10687("8.8.8.8")) {
			t.Fatalf("lenient=%v valid /0 client-list did not allow 8.8.8.8", lenient)
		}
		if len(cfg.System.SNMP.ClientLists["mgmt"]) != 2 {
			t.Fatalf("lenient=%v valid merged client-list = %+v, want both entries", lenient, cfg.System.SNMP.ClientLists["mgmt"])
		}
	}
}

func TestSNMPQualifierCrossChildLenientQuarantineDeniesOutsidePrefix18844(t *testing.T) {
	for _, tc := range []struct {
		name string
		text string
	}{
		{
			name: "named client-list",
			text: `system { host-name fw; snmp {
    client-list mgmt { 10.1.0.0/16; restrict 0.0.0.0/0; }
    community scoped { authorization read-only; client-list-name mgmt; }
} }`,
		},
		{
			name: "inline clients",
			text: `system { host-name fw; snmp {
    community scoped { authorization read-only; clients { 10.1.0.0/16; restrict 0.0.0.0/0; } }
} }`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := compileSNMPText18844(t, tc.text, true)
			if err != nil {
				t.Fatalf("lenient compilation rejected malformed source list: %v", err)
			}
			community := cfg.System.SNMP.Communities["scoped"]
			if community == nil {
				t.Fatal("community scoped was not compiled")
			}
			for _, source := range []string{"8.8.8.8", "10.1.2.7"} {
				if community.AllowsSource(snmpClientTestSource10687(source)) {
					t.Errorf("leniently quarantined community allowed %s", source)
				}
			}
		})
	}
}

func TestSNMPRepeatedClientListQualifierQuarantines18844(t *testing.T) {
	const text = `system { host-name fw; snmp {
    client-list mgmt { 10.1.0.0/16 restrict restrict; }
    community scoped { authorization read-only; client-list-name mgmt; }
} }`
	cfg, err := compileSNMPText18844(t, text, true)
	if err != nil {
		t.Fatalf("lenient compilation rejected malformed repeated qualifier: %v", err)
	}
	community := cfg.System.SNMP.Communities["scoped"]
	if community == nil {
		t.Fatal("community scoped was not compiled")
	}
	if len(community.clientNets) != 2 {
		t.Fatalf("repeated-qualifier cache = %+v, want explicit IPv4+IPv6 quarantine", community.clientNets)
	}
	hasIPv4, hasIPv6 := false, false
	for _, entry := range community.clientNets {
		if !entry.restrict || entry.ones != 0 || entry.net == nil {
			t.Fatalf("repeated-qualifier cache = %+v, want deny-all quarantine entries", community.clientNets)
		}
		if entry.net.IP.To4() != nil {
			hasIPv4 = true
		} else {
			hasIPv6 = true
		}
	}
	if !hasIPv4 || !hasIPv6 {
		t.Fatalf("repeated-qualifier cache = %+v, want both address families", community.clientNets)
	}
	for _, source := range []string{"8.8.8.8", "10.1.2.7"} {
		if community.AllowsSource(snmpClientTestSource10687(source)) {
			t.Errorf("repeated-qualifier community allowed %s instead of being quarantined", source)
		}
	}
}
