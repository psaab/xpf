package config

import (
	"strings"
	"testing"
)

// #15709: ntp peer/trusted-key and top-level syslog statements must
// either take effect or warn, never silently drop.

func compile15709(t *testing.T, cmds []string) *Config {
	t.Helper()
	tree := &ConfigTree{}
	for _, c := range cmds {
		p, err := ParseSetCommand(c)
		if err != nil {
			t.Fatalf("parse %q: %v", c, err)
		}
		if err := tree.SetPath(p); err != nil {
			t.Fatalf("set %q: %v", c, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if err := SchemaValidate(tree); err != nil {
		t.Fatalf("SchemaValidate rejected #15709 config: %v", err)
	}
	return cfg
}

func hasWarn15709(cfg *Config, subs ...string) bool {
	for _, w := range cfg.Warnings {
		ok := true
		for _, s := range subs {
			if !strings.Contains(w, s) {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

func TestNTPeerCompiles15709(t *testing.T) {
	cfg := compile15709(t, []string{
		"set system ntp server 192.0.2.2",
		"set system ntp peer 192.0.2.1",
	})
	if len(cfg.System.NTPPeers) != 1 || cfg.System.NTPPeers[0] != "192.0.2.1" {
		t.Fatalf("NTPPeers=%v want [192.0.2.1] (peer silently dropped pre-fix)", cfg.System.NTPPeers)
	}
	if len(cfg.System.NTPServers) != 1 || cfg.System.NTPServers[0] != "192.0.2.2" {
		t.Fatalf("NTPServers=%v", cfg.System.NTPServers)
	}
	// Hier spelling
	tree := parseHierText(t, "system { ntp { peer 192.0.2.5; server 192.0.2.6; } }")
	cfg2, err := CompileConfig(tree)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg2.System.NTPPeers) != 1 || cfg2.System.NTPPeers[0] != "192.0.2.5" {
		t.Fatalf("hier NTPPeers=%v", cfg2.System.NTPPeers)
	}
}

func TestNTPTrustedKeyWarns15709(t *testing.T) {
	cfg := compile15709(t, []string{"set system ntp trusted-key 1", "set system ntp trusted-key 2"})
	if !hasWarn15709(cfg, "trusted-key") {
		t.Fatalf("trusted-key silent; warnings=%q", cfg.Warnings)
	}
	if len(cfg.System.NTPTrustedKeyIDs) != 2 {
		t.Fatalf("NTPTrustedKeyIDs=%v", cfg.System.NTPTrustedKeyIDs)
	}
}

func TestNTPServerSourceAddressWarns15709(t *testing.T) {
	cfg := compile15709(t, []string{"set system ntp server 192.0.2.1 source-address 10.0.0.1"})
	if len(cfg.System.NTPServers) != 1 || cfg.System.NTPServers[0] != "192.0.2.1" {
		t.Fatalf("NTPServers=%v want single server (source-address absorbed as server pre-fix)", cfg.System.NTPServers)
	}
	opt := cfg.System.NTPServerOptions["192.0.2.1"]
	if opt.SourceAddress != "10.0.0.1" {
		t.Fatalf("opt=%+v want SourceAddress 10.0.0.1", opt)
	}
	if !hasWarn15709(cfg, "server source-address") {
		t.Fatalf("per-server source-address silent; warnings=%q", cfg.Warnings)
	}
}

func TestSyslogTopLevel15709(t *testing.T) {
	cfg := compile15709(t, []string{
		"set system syslog console any info",
		"set system syslog source-address 10.0.0.9",
		"set system syslog host 192.0.2.10 any any",
		"set system syslog host 192.0.2.11 any any",
		"set system syslog host 192.0.2.11 source-address 10.0.0.11",
		"set system syslog time-format year",
		"set system syslog archive size 1m",
		"set system syslog log-rotate-frequency 15",
	})
	if cfg.System.Syslog == nil {
		t.Fatal("Syslog nil")
	}
	if cfg.System.Syslog.DefaultSourceAddress != "10.0.0.9" {
		t.Fatalf("DefaultSourceAddress=%q", cfg.System.Syslog.DefaultSourceAddress)
	}
	if len(cfg.System.Syslog.Hosts) != 2 {
		t.Fatalf("hosts=%+v", cfg.System.Syslog.Hosts)
	}
	byAddr := map[string]*SyslogHostConfig{}
	for _, h := range cfg.System.Syslog.Hosts {
		byAddr[h.Address] = h
	}
	if byAddr["192.0.2.10"].SourceAddress != "10.0.0.9" {
		t.Fatalf("host without own source-address did not inherit top-level: %+v", byAddr["192.0.2.10"])
	}
	if byAddr["192.0.2.11"].SourceAddress != "10.0.0.11" {
		t.Fatalf("host own source-address overridden: %+v", byAddr["192.0.2.11"])
	}
	for _, kw := range []string{"console", "time-format", "archive", "log-rotate-frequency"} {
		if !hasWarn15709(cfg, "syslog", kw) {
			t.Errorf("top-level %s silent; warnings=%q", kw, cfg.Warnings)
		}
	}
	// Hier spelling
	tree := parseHierText(t, "system { syslog { source-address 10.0.0.9; console { any info; } time-format year; host 192.0.2.10 { any any; } } }")
	cfg2, err := CompileConfig(tree)
	if err != nil {
		t.Fatal(err)
	}
	if cfg2.System.Syslog.DefaultSourceAddress != "10.0.0.9" || len(cfg2.System.Syslog.Hosts) != 1 || cfg2.System.Syslog.Hosts[0].SourceAddress != "10.0.0.9" {
		t.Fatalf("hier syslog=%+v hosts=%+v", cfg2.System.Syslog, cfg2.System.Syslog.Hosts)
	}
	if !hasWarn15709(cfg2, "console") || !hasWarn15709(cfg2, "time-format") {
		t.Fatalf("hier top-level silent; warnings=%q", cfg2.Warnings)
	}
}

func TestSyslogNoTopLevelNoWarn15709(t *testing.T) {
	cfg := compile15709(t, []string{"set system syslog host 192.0.2.10 any any"})
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "top-level") {
			t.Fatalf("spurious top-level warning: %q", w)
		}
	}
	if cfg.System.Syslog.Hosts[0].SourceAddress != "" {
		t.Fatalf("source address invented: %+v", cfg.System.Syslog.Hosts[0])
	}
}
