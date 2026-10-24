package config

import (
	"strings"
	"testing"
)

// #16462 — `system` (incl. syslog/ntp), top-level `snmp` and the
// class-of-service interfaces leg (R3-VA85-S1) were open-world: typo
// keywords committed with zero warnings and compiled to nothing.
// The #10707 warn-only advisory now covers them. Every typo row must
// WARN naming the token on strict AND lenient, and must still commit
// (warn-only, #1960). Controls must stay free of #10707 warnings.
//
// RED-on-revert: removing the system/snmp/class-of-service dispatch
// (or warnBadSyslogFacilities16462) makes every typo row warn-free.

func warn16462(ws []string, tok string) bool {
	for _, w := range ws {
		if strings.Contains(w, "#10707") && strings.Contains(w, tok) {
			return true
		}
	}
	return false
}

func anyWarn16462(ws []string) bool {
	for _, w := range ws {
		if strings.Contains(w, "#10707") {
			return true
		}
	}
	return false
}

func TestSystemSNMPOpenWorldWarn16462(t *testing.T) {
	typos := []struct {
		name string
		tok  string
		line string
	}{
		{"syslog hots", "hots", "set system syslog hots 192.0.2.10 any any"},
		{"syslog hosts", "hosts", "set system syslog hosts 192.0.2.10 any any"},
		{"ntp servr", "servr", "set system ntp servr 192.0.2.123"},
		{"name-sever", "name-sever", "set system name-sever 192.0.2.53"},
		{"snmp comunity", "comunity", "set snmp comunity public"},
		{"host-nam", "host-nam", "set system host-nam fw1"},
		{"services ssh root-logi", "root-logi", "set system services ssh root-logi allow"},
		{"cos shaping-rat", "shaping-rat", "set class-of-service interfaces ge-0/0/0 unit 0 shaping-rat 10m"},
		{"cos interfacs", "interfacs", "set class-of-service interfacs ge-0/0/0 unit 0 shaping-rate 10m"},
		{"syslog bogusfac", "bogusfac", "set system syslog file messages bogusfac info"},
		{"syslog kernl", "kernl", "set system syslog file messages kernl info"},
		{"syslog ntp facility", "ntp", "set system syslog file messages ntp info"},
	}
	for _, tc := range typos {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := CompileConfig(buildTree(t, []string{tc.line}))
			if err != nil {
				t.Fatalf("warn-only must commit: %v", err)
			}
			if !warn16462(cfg.Warnings, tc.tok) {
				t.Fatalf("strict must warn #10707 naming %q; warnings=%v", tc.tok, cfg.Warnings)
			}
			lcfg, err := CompileConfigLenient(buildTree(t, []string{tc.line}))
			if err != nil {
				t.Fatalf("lenient must commit: %v", err)
			}
			if !warn16462(lcfg.Warnings, tc.tok) {
				t.Fatalf("lenient must warn #10707 naming %q; warnings=%v", tc.tok, lcfg.Warnings)
			}
		})
	}
	// Typo compiles to nothing (the silent-loss shape, now warned).
	cfg, _ := CompileConfig(buildTree(t, []string{"set system syslog hots 192.0.2.10 any any"}))
	if cfg.System.Syslog != nil && len(cfg.System.Syslog.Hosts) != 0 {
		t.Fatalf("hots must compile no syslog host, got %+v", cfg.System.Syslog.Hosts)
	}
	cfg, _ = CompileConfig(buildTree(t, []string{"set snmp comunity public"}))
	if cfg.System.SNMP != nil && len(cfg.System.SNMP.Communities) != 0 {
		t.Fatalf("comunity must compile no community")
	}
	// Hierarchical spellings warn too.
	for _, tc := range []struct{ text, tok string }{
		{"system { syslog { hots { 192.0.2.10 { any any; } } } }", "hots"},
		{"system { ntp { servr 192.0.2.123; } }", "servr"},
		{"snmp { comunity public; }", "comunity"},
		{"class-of-service { interfaces { ge-0/0/0 { unit 0 { shaping-rat 10m; } } } }", "shaping-rat"},
		{"system { syslog { file messages { bogusfac info; } } }", "bogusfac"},
	} {
		cfg, err := CompileConfig(parseHierText(t, tc.text))
		if err != nil {
			t.Fatalf("hier %q: %v", tc.text, err)
		}
		if !warn16462(cfg.Warnings, tc.tok) {
			t.Fatalf("hier %q must warn naming %q; warnings=%v", tc.text, tc.tok, cfg.Warnings)
		}
	}
}

func TestSystemSNMPOpenWorldControls16462(t *testing.T) {
	controls := [][]string{
		{"set system syslog host 192.0.2.10 any any"},
		{"set system syslog file messages any any"},
		{"set system syslog file messages daemon info"},
		{"set system syslog file messages kern info"},
		{"set system syslog file messages auth info"},
		{"set system syslog file messages local0 info"},
		{"set system syslog file messages authorization warning"},
		{"set system syslog file messages auth,daemon info"},
		{"set system syslog user * any emergency"},
		{"set system syslog host 192.0.2.10 source-address 10.0.0.1"},
		{"set system syslog host 192.0.2.10 port 5514"},
		{"set system syslog file messages archive size 1m"},
		{"set system ntp server 192.0.2.123"},
		{"set system ntp peer 192.0.2.124"},
		{"set system name-server 192.0.2.53"},
		{"set system host-name fw1"},
		{"set snmp community public"},
		{"set snmp location lab"},
		{"set system login user bob class operator"},
		{"set system archival configuration transfer-on-commit"},
		{"set system services dhcp-local-server group g interface ge-0/0/0.0"},
		{"set class-of-service interfaces ge-0/0/0 unit 0 shaping-rate 10m"},
		{"set class-of-service forwarding-classes queue 0 best-effort"},
		// Declared-but-inert SNMP knobs: #9414 advisory only, never #10707 unknown.
		{"set snmp view v oid 1.3.6.1"},
	}
	for i, lines := range controls {
		cfg, err := CompileConfig(buildTree(t, lines))
		if err != nil {
			t.Fatalf("control %d %v: %v", i, lines, err)
		}
		if anyWarn16462(cfg.Warnings) {
			t.Fatalf("control %d %v unexpected #10707 warning: %v", i, lines, cfg.Warnings)
		}
		lcfg, err := CompileConfigLenient(buildTree(t, lines))
		if err != nil {
			t.Fatalf("control %d lenient: %v", i, err)
		}
		if anyWarn16462(lcfg.Warnings) {
			t.Fatalf("control %d lenient unexpected #10707: %v", i, lcfg.Warnings)
		}
	}
	// Hierarchical controls.
	for _, text := range []string{
		"snmp { location lab; contact noc; description d; }",
		"system { syslog { file messages { any any; } } }",
		"system { services { ssh { root-login allow; } } }",
	} {
		cfg, err := CompileConfig(parseHierText(t, text))
		if err != nil {
			t.Fatalf("hier control %q: %v", text, err)
		}
		if anyWarn16462(cfg.Warnings) {
			t.Fatalf("hier control %q unexpected #10707: %v", text, cfg.Warnings)
		}
	}
	// #9414 positive control still fires (declared-but-unsupported).
	cfg, err := CompileConfig(buildTree(t, []string{"set system syslog console any any"}))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "#9414") {
			found = true
		}
	}
	if !found {
		t.Fatalf("console must keep #9414 advisory; warnings=%v", cfg.Warnings)
	}
	if anyWarn16462(cfg.Warnings) {
		t.Fatalf("console must not draw #10707 unknown; warnings=%v", cfg.Warnings)
	}
}
