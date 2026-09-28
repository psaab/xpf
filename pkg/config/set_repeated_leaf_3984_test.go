package config

import (
	"strings"
	"testing"
)

// #3984: the keyed-list LEAVES `system ntp server <ip>`,
// `system archival configuration archive-sites <url>`,
// `system services web-management api-auth api-key <key>` and
// `security flow traceoptions flag <flag>` are repeated single-value
// statements — an operator writes one `set` line per value and the
// compiler reads EVERY sibling via FindChildren, accumulating them into a
// slice. Before this fix they were declared in setSchema as
// `{args:1, children:nil}` and were NOT `multi: true`, so SetPath's
// single-value-REPLACE branch treated a SECOND `set ... server 2.2.2.2` as
// a replacement of the first rather than an addition. A flat-set /
// `load set` / display-set round-trip of a multi-value config therefore
// DROPPED all but the LAST value silently.
//
// These are RED-on-revert guards: reverting the `multi: true` markers in
// setSchema collapses each list to its last member and fails the count
// assertions below. Every test drives the flat-set path (ParseSetCommand +
// SetPath), never NewParser — the hierarchical parser already appends one
// node per statement and would mask the SetPath collapse.

// TestSetRepeatedNTPServers proves three distinct `set system ntp server`
// statements survive SetPath as three sibling nodes and the compiler reads
// all three. RED on revert: collapsed to the last, only one present.
func TestSetRepeatedNTPServers(t *testing.T) {
	tree := buildTree(t, []string{
		"set system ntp server 1.1.1.1",
		"set system ntp server 2.2.2.2",
		"set system ntp server 3.3.3.3",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}
	want := []string{"1.1.1.1", "2.2.2.2", "3.3.3.3"}
	if len(cfg.System.NTPServers) != len(want) {
		t.Fatalf("NTPServers = %v, want %v (SetPath collapsed the repeated leaf)",
			cfg.System.NTPServers, want)
	}
	for _, ip := range want {
		found := false
		for _, got := range cfg.System.NTPServers {
			if got == ip {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("NTP server %q missing after SetPath; got %v", ip, cfg.System.NTPServers)
		}
	}
}

// TestSetSingleNTPServerUnchanged is the anti-over-broadening guard: a
// single server still compiles to exactly one entry.
func TestSetSingleNTPServerUnchanged(t *testing.T) {
	tree := buildTree(t, []string{
		"set system ntp server 1.1.1.1",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}
	if len(cfg.System.NTPServers) != 1 || cfg.System.NTPServers[0] != "1.1.1.1" {
		t.Fatalf("NTPServers = %v, want [1.1.1.1]", cfg.System.NTPServers)
	}
}

// TestSetRepeatedNTPServersDisplaySetRoundTrip proves a display-set backup
// round-trips: render the SetPath-built tree via FormatSet (`| display
// set`), re-apply every emitted line through ParseSetCommand + SetPath (the
// load-set path), and reproduce all three servers. Before the fix the
// re-applied lines collapsed back to the last server.
func TestSetRepeatedNTPServersDisplaySetRoundTrip(t *testing.T) {
	tree := buildTree(t, []string{
		"set system ntp server 1.1.1.1",
		"set system ntp server 2.2.2.2",
		"set system ntp server 3.3.3.3",
	})
	set := tree.FormatSet()
	for _, ip := range []string{"1.1.1.1", "2.2.2.2", "3.3.3.3"} {
		if !strings.Contains(set, "set system ntp server "+ip) {
			t.Fatalf("FormatSet() missing server %q; got:\n%s", ip, set)
		}
	}

	reloaded := &ConfigTree{}
	for _, line := range strings.Split(strings.TrimSpace(set), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		toks, err := ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := reloaded.SetPath(toks); err != nil {
			t.Fatalf("SetPath(%v): %v", toks, err)
		}
	}
	cfg, err := CompileConfig(reloaded)
	if err != nil {
		t.Fatalf("compile error after round-trip: %v", err)
	}
	if len(cfg.System.NTPServers) != 3 {
		t.Fatalf("round-trip NTPServers = %v, want 3 servers", cfg.System.NTPServers)
	}
}

// TestSetRepeatedArchiveSites proves repeated `archive-sites` statements
// survive SetPath, including a site that carries a `password` modifier
// (which lands on the leaf's trailing keys and must not defeat the
// distinct-sibling behaviour). RED on revert: collapsed to the last site.
func TestSetRepeatedArchiveSites(t *testing.T) {
	tree := buildTree(t, []string{
		`set system archival configuration archive-sites "scp://a@host1/c" password s3cret`,
		`set system archival configuration archive-sites "scp://b@host2/c"`,
		`set system archival configuration archive-sites "ftp://c@host3/c"`,
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}
	if cfg.System.Archival == nil {
		t.Fatal("archival config missing")
	}
	want := []string{
		"scp://a@host1/c",
		"scp://b@host2/c",
		"ftp://c@host3/c",
	}
	if len(cfg.System.Archival.ArchiveSites) != len(want) {
		t.Fatalf("ArchiveSites = %v, want %v (SetPath collapsed the repeated leaf)",
			cfg.System.Archival.ArchiveSites, want)
	}
	for _, url := range want {
		found := false
		for _, got := range cfg.System.Archival.ArchiveSites {
			if got == url {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("archive-site %q missing; got %v", url, cfg.System.Archival.ArchiveSites)
		}
	}
	// The site with a password modifier must still be recognized as such.
	if len(cfg.System.Archival.ArchiveSitesWithPassword) != 1 ||
		cfg.System.Archival.ArchiveSitesWithPassword[0] != "scp://a@host1/c" {
		t.Errorf("ArchiveSitesWithPassword = %v, want [scp://a@host1/c]",
			cfg.System.Archival.ArchiveSitesWithPassword)
	}
}

// TestSetRepeatedAPIKeys proves repeated REST-API keys survive SetPath as
// distinct siblings and the compiler reads every one. RED on revert:
// collapsed to the last key.
func TestSetRepeatedAPIKeys(t *testing.T) {
	const (
		alpha = "machine-generated-key-alpha"
		bravo = "machine-generated-key-bravo"
	)
	tree := buildTree(t, []string{
		"set system services web-management api-auth expires 2099-01-01",
		"set system services web-management api-auth api-key " + alpha,
		"set system services web-management api-auth api-key " + bravo,
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}
	if cfg.System.Services == nil || cfg.System.Services.WebManagement == nil ||
		cfg.System.Services.WebManagement.APIAuth == nil {
		t.Fatal("api-auth config missing")
	}
	keys := cfg.System.Services.WebManagement.APIAuth.APIKeys
	if len(keys) != 2 {
		t.Fatalf("APIKeys has %d rows, want 2 (SetPath collapsed the repeated leaf)", len(keys))
	}
	if !VerifyAPIAuthSecret(keys[0].Reveal(), alpha) || !VerifyAPIAuthSecret(keys[1].Reveal(), bravo) {
		t.Errorf("repeated keys compiled without usable verifier for each slot")
	}
}

// TestSetRepeatedTraceFlags proves repeated flow-traceoptions `flag`
// statements survive SetPath and the compiler reads every one. RED on
// revert: collapsed to the last flag.
func TestSetRepeatedTraceFlags(t *testing.T) {
	tree := buildTree(t, []string{
		"set security flow traceoptions flag basic-datapath",
		"set security flow traceoptions flag session",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}
	if cfg.Security.Flow.Traceoptions == nil {
		t.Fatal("flow traceoptions config missing")
	}
	flags := cfg.Security.Flow.Traceoptions.Flags
	if len(flags) != 2 {
		t.Fatalf("trace Flags = %v, want 2 (SetPath collapsed the repeated leaf)", flags)
	}
	want := map[string]bool{"basic-datapath": false, "session": false}
	for _, f := range flags {
		if _, ok := want[f]; ok {
			want[f] = true
		}
	}
	for f, seen := range want {
		if !seen {
			t.Errorf("trace flag %q missing; got %v", f, flags)
		}
	}
}
