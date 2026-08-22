package config

import (
	"strings"
	"testing"
)

// #7146: the `system syslog file <f> archive` block is modeled in setSchema
// (schema_system.go) and compiled by nothing — #4303 folded `archive` into
// compileSystem's recognized-modifier skip list, so files/size/start-time/
// transfer-interval/archive-sites all committed clean and did nothing. The
// fix is accept-with-advisory (#4316 pattern), NOT archival: the block is
// recorded on the compiled SyslogFileConfig and ValidateConfig names it at
// commit so an operator knows their logs are not being archived.
//
// These tests bind three properties:
//  1. the advisory FIRES for a file carrying an archive block, in every AST
//     shape the dual parser produces for it;
//  2. it does NOT fire for the common case (a plain facility/severity file,
//     a host/user destination, or no syslog block at all) — a guard that
//     fires on every config is noise, not a signal;
//  3. the commit still SUCCEEDS. Rejecting would fail the tolerant load /
//     peer-sync path on a config an operator already has (#1960).

// buildTree7146 compiles flat `set` lines the only correct way (ParseSetCommand
// + SetPath); NewParser merges newlines into one node.
func buildTree7146(t *testing.T, cmds []string) *ConfigTree {
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

// compile7146 compiles and returns the warnings an operator sees at commit.
// It reads cfg.Warnings — the surface runTailGates folds ValidateConfig into
// and the CLI prints — not ValidateConfig's return value, so the test fails
// if the advisory is emitted somewhere the commit path never shows.
func compile7146(t *testing.T, cmds []string) (*Config, []string) {
	t.Helper()
	cfg, err := CompileConfig(buildTree7146(t, cmds))
	if err != nil {
		t.Fatalf("CompileConfig returned an error; the archive block must WARN, never reject (#1960 tolerant-load): %v", err)
	}
	return cfg, cfg.Warnings
}

// archiveWarnings returns the subset of warnings that are the #7146 advisory.
func archiveWarnings(warnings []string) []string {
	var out []string
	for _, w := range warnings {
		if strings.Contains(w, "syslog file") && strings.Contains(w, "archive") {
			out = append(out, w)
		}
	}
	return out
}

// Quoted: the `@` and `:` in a URL are lexer tokens in a bare set value.
const archiveSiteURL = `"scp://logbot:s3cr3t@backup.example.net/logs"`

func TestSyslogFileArchiveInertWarning(t *testing.T) {
	cfg, warnings := compile7146(t, []string{
		"set system syslog file f1 any any",
		"set system syslog file f1 archive files 7",
		"set system syslog file f1 archive size 1048576",
		"set system syslog file f1 archive start-time 03:00",
		"set system syslog file f1 archive transfer-interval 60",
		"set system syslog file f1 archive world-readable",
		"set system syslog file f1 archive archive-sites " + archiveSiteURL,
	})

	got := archiveWarnings(warnings)
	if len(got) != 1 {
		t.Fatalf("want exactly 1 syslog-archive advisory, got %d: %#v (all warnings: %#v)", len(got), got, warnings)
	}
	w := got[0]

	// The operator must learn WHICH file, WHICH knobs, and that archival is
	// not happening — not merely that "something" is unsupported.
	for _, want := range []string{
		`"f1"`,
		"NOT implemented",
		"NOT archived",
		"/var/log/f1",
		"#7146",
	} {
		if !strings.Contains(w, want) {
			t.Errorf("advisory is missing %q:\n%s", want, w)
		}
	}
	for _, knob := range []string{"files", "size", "start-time", "transfer-interval", "archive-sites", "world-readable"} {
		if !strings.Contains(w, knob) {
			t.Errorf("advisory does not name the configured knob %q:\n%s", knob, w)
		}
	}

	// Keywords only. An archive-sites URL can embed credentials, and this
	// string is printed at commit and copied into support tickets.
	if strings.Contains(w, "s3cr3t") || strings.Contains(w, "backup.example.net") {
		t.Errorf("advisory echoed an archive-sites VALUE (credential leak):\n%s", w)
	}
	for _, v := range []string{"1048576", "03:00", "logbot"} {
		if strings.Contains(w, v) {
			t.Errorf("advisory echoed the configured value %q; keywords only:\n%s", v, w)
		}
	}

	// The record the advisory is built from.
	files := cfg.System.Syslog.Files
	if len(files) != 1 {
		t.Fatalf("want 1 compiled syslog file, got %d", len(files))
	}
	if !files[0].ArchiveConfigured {
		t.Error("ArchiveConfigured false for a file with an archive block")
	}
	wantKnobs := "archive-sites files size start-time transfer-interval world-readable"
	if got := strings.Join(files[0].ArchiveKnobs, " "); got != wantKnobs {
		t.Errorf("ArchiveKnobs = %q, want %q (sorted + deduplicated)", got, wantKnobs)
	}
	// Facility/severity parsing must survive the new `archive` case.
	if files[0].Facility != "any" || files[0].Severity != "any" {
		t.Errorf("facility/severity = %q/%q, want any/any", files[0].Facility, files[0].Severity)
	}
}

// The dual AST puts the same stanza in four different shapes. A walker that
// read only Children would miss the hierarchical one-line form; one that read
// only Keys would miss both block forms; one that read only direct children
// would miss the flat-compact NESTED chain.
func TestSyslogFileArchiveInertWarningASTShapes(t *testing.T) {
	t.Run("flat compact (nested key chain)", func(t *testing.T) {
		cfg, warnings := compile7146(t, []string{
			"set system syslog file f2 any any",
			"set system syslog file f2 archive size 1m files 5",
		})
		if got := archiveWarnings(warnings); len(got) != 1 {
			t.Fatalf("want 1 advisory, got %d: %#v", len(got), got)
		}
		if got := strings.Join(cfg.System.Syslog.Files[0].ArchiveKnobs, " "); got != "files size" {
			t.Errorf("ArchiveKnobs = %q, want %q", got, "files size")
		}
	})

	t.Run("hierarchical one-line (all tokens on Keys)", func(t *testing.T) {
		src := `system {
    syslog {
        file f3 {
            any any;
            archive size 1m files 5;
        }
    }
}`
		tree, perrs := NewParser(src).Parse()
		if len(perrs) > 0 {
			t.Fatalf("parse: %v", perrs)
		}
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("CompileConfig: %v", err)
		}
		if got := archiveWarnings(cfg.Warnings); len(got) != 1 {
			t.Fatalf("want 1 advisory for the one-line archive form, got %d: %#v", len(got), cfg.Warnings)
		}
		if got := strings.Join(cfg.System.Syslog.Files[0].ArchiveKnobs, " "); got != "files size" {
			t.Errorf("ArchiveKnobs = %q, want %q", got, "files size")
		}
	})

	t.Run("hierarchical block", func(t *testing.T) {
		src := `system {
    syslog {
        file f4 {
            any any;
            archive {
                files 7;
                no-world-readable;
            }
        }
    }
}`
		tree, perrs := NewParser(src).Parse()
		if len(perrs) > 0 {
			t.Fatalf("parse: %v", perrs)
		}
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("CompileConfig: %v", err)
		}
		if got := archiveWarnings(cfg.Warnings); len(got) != 1 {
			t.Fatalf("want 1 advisory, got %d: %#v", len(got), cfg.Warnings)
		}
		if got := strings.Join(cfg.System.Syslog.Files[0].ArchiveKnobs, " "); got != "files no-world-readable" {
			t.Errorf("ArchiveKnobs = %q, want %q", got, "files no-world-readable")
		}
	})

	// A bare `archive;` is archiving-with-defaults in Junos, so presence
	// alone warrants the advisory even with no sub-statement to name.
	t.Run("bare archive container", func(t *testing.T) {
		cfg, warnings := compile7146(t, []string{
			"set system syslog file f5 any any",
			"set system syslog file f5 archive",
		})
		got := archiveWarnings(warnings)
		if len(got) != 1 {
			t.Fatalf("want 1 advisory for a bare `archive`, got %d: %#v", len(got), warnings)
		}
		if strings.Contains(got[0], "[") {
			t.Errorf("bare archive advisory should name no knobs, got a knob list:\n%s", got[0])
		}
		if !cfg.System.Syslog.Files[0].ArchiveConfigured {
			t.Error("ArchiveConfigured false for a bare `archive` container")
		}
		if len(cfg.System.Syslog.Files[0].ArchiveKnobs) != 0 {
			t.Errorf("ArchiveKnobs = %#v, want empty", cfg.System.Syslog.Files[0].ArchiveKnobs)
		}
	})
}

// The guard must not fire on the common case. A commit advisory that appears
// on every syslog config trains operators to ignore it.
func TestSyslogFileArchiveInertWarningNotOnCommonCase(t *testing.T) {
	cases := []struct {
		name string
		cmds []string
	}{
		{"plain file destination", []string{
			"set system syslog file messages any warning",
			"set system syslog file security authorization info",
		}},
		{"file with non-archive modifiers", []string{
			"set system syslog file messages any warning",
			"set system syslog file messages explicit-priority",
			"set system syslog file messages structured-data",
		}},
		{"host and user destinations", []string{
			"set system syslog host 10.0.0.9 any warning",
			"set system syslog host 10.0.0.9 source-address 10.0.1.1",
			"set system syslog host 10.0.0.9 port 5514",
			"set system syslog user * any emergency",
		}},
		{"config archival (a different, implemented feature)", []string{
			"set system archival configuration transfer-interval 60",
			"set system archival configuration archive-sites ftp://host/dir",
		}},
		{"no syslog block at all", []string{
			"set system host-name fw0",
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, warnings := compile7146(t, tc.cmds)
			if got := archiveWarnings(warnings); len(got) != 0 {
				t.Errorf("syslog-archive advisory fired on the common case %q: %#v", tc.name, got)
			}
		})
	}
}

// One advisory per FILE: an operator with three archiving files must be told
// about all three, and a file without the block must not be swept in.
func TestSyslogFileArchiveInertWarningPerFile(t *testing.T) {
	_, warnings := compile7146(t, []string{
		"set system syslog file a any any",
		"set system syslog file a archive files 3",
		"set system syslog file b any any",
		"set system syslog file c any any",
		"set system syslog file c archive archive-sites " + archiveSiteURL,
	})
	got := archiveWarnings(warnings)
	if len(got) != 2 {
		t.Fatalf("want 2 advisories (files a and c), got %d: %#v", len(got), got)
	}
	joined := strings.Join(got, "\n")
	if !strings.Contains(joined, `"a"`) || !strings.Contains(joined, `"c"`) {
		t.Errorf("advisories do not name both archiving files:\n%s", joined)
	}
	if strings.Contains(joined, `"b"`) {
		t.Errorf("advisory named file b, which has no archive block:\n%s", joined)
	}
}

// syslogArchiveKnobs must never mistake a VALUE for a keyword. An
// archive-sites URL is operator-controlled text.
func TestSyslogArchiveKnobsSkipsValues(t *testing.T) {
	_, warnings := compile7146(t, []string{
		"set system syslog file f6 any any",
		"set system syslog file f6 archive archive-sites size",
	})
	got := archiveWarnings(warnings)
	if len(got) != 1 {
		t.Fatalf("want 1 advisory, got %d: %#v", len(got), got)
	}
	if !strings.Contains(got[0], "[archive-sites]") {
		t.Errorf("an archive-sites VALUE of \"size\" was read as the size keyword:\n%s", got[0])
	}
}
