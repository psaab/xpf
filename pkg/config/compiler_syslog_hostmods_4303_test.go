package config

import "testing"

// buildTree4303 assembles a candidate tree the way the CLI does — via
// ParseSetCommand + SetPath — so flat-set token grouping matches production
// (NewParser would merge newline-separated set lines into one node).
func buildTree4303(t *testing.T, cmds []string) *ConfigTree {
	t.Helper()
	tree := &ConfigTree{}
	for _, cmd := range cmds {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	return tree
}

// TestSyslogHostSubstatementsNotMisparsed is the RED-on-revert guard for
// #4303 S-1. A syslog host's `source-address`/`port` sub-statements must NOT
// be captured as facility/severity pairs, and the real `any warning` pair
// must survive intact. On the pre-fix code Facilities carried three entries
// ({source-address 10.0.1.1}, {any warning}, {port 5514}) and the strict
// commit-check rejected `source-address` because an IP is not a severity.
func TestSyslogHostSubstatementsNotMisparsed(t *testing.T) {
	tree := buildTree4303(t, []string{
		"set system syslog host 10.0.0.5 source-address 10.0.1.1",
		"set system syslog host 10.0.0.5 any warning",
		"set system syslog host 10.0.0.5 port 5514",
		"set system syslog host 10.0.0.5 explicit-priority",
	})
	c, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	// Strict commit-check must ACCEPT the config (source-address/port are now
	// modelled and no longer validated against the severity enum).
	if err := SchemaValidate(tree); err != nil {
		t.Fatalf("SchemaValidate rejected a valid syslog host config: %v", err)
	}
	if c.System.Syslog == nil || len(c.System.Syslog.Hosts) != 1 {
		t.Fatalf("expected exactly one syslog host, got %+v", c.System.Syslog)
	}
	h := c.System.Syslog.Hosts[0]
	if len(h.Facilities) != 1 {
		t.Fatalf("expected exactly 1 facility pair (the real `any warning`), got %d: %+v",
			len(h.Facilities), h.Facilities)
	}
	if h.Facilities[0].Facility != "any" || h.Facilities[0].Severity != "warning" {
		t.Fatalf("facility pair = %+v, want {any warning}", h.Facilities[0])
	}
	if h.SourceAddress != "10.0.1.1" {
		t.Fatalf("SourceAddress = %q, want 10.0.1.1", h.SourceAddress)
	}
	if h.Port != 5514 {
		t.Fatalf("Port = %d, want 5514", h.Port)
	}
}

// TestSyslogFileArchiveNotMisparsed guards the file-destination side: an
// `archive`/`match`/`structured-data` modifier must not overwrite the real
// facility/severity pair, and the config must commit clean.
func TestSyslogFileArchiveNotMisparsed(t *testing.T) {
	tree := buildTree4303(t, []string{
		"set system syslog file messages any info",
		"set system syslog file messages match SOMEPATTERN",
		"set system syslog file messages archive size 1m",
		"set system syslog file messages structured-data",
	})
	c, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if err := SchemaValidate(tree); err != nil {
		t.Fatalf("SchemaValidate rejected a valid syslog file config: %v", err)
	}
	if c.System.Syslog == nil || len(c.System.Syslog.Files) != 1 {
		t.Fatalf("expected one syslog file, got %+v", c.System.Syslog)
	}
	f := c.System.Syslog.Files[0]
	if len(f.Selectors) != 1 || f.Selectors[0].Facility != "any" ||
		f.Selectors[0].Severity != "info" {
		t.Fatalf("file selectors = %+v, want exactly one any/info "+
			"(archive/match/structured-data leaked in)", f.Selectors)
	}
}
