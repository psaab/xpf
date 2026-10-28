package cliterm

// #17798: ReadHistorySeed re-filtered with the no-cursor
// IsSensitiveHistoryLine. A legacy pre-#16794 file could contain
// `set community S3cretF …` typed under `edit snmp`; on the bare line it
// flags nothing, so the secret was re-seeded into live recall. The seed
// filter replays the file sequentially and advances every plausible cursor
// on every scanned line (including filtered secret lines). Because concurrent
// sessions share this file without session markers, it also suppresses any
// mutation whose tokens could carry a context-gated secret, even when linear
// replay judges the line as benign under its current cursor.
//
// FAIL-ON-REVERT: reverting ReadHistorySeed to IsSensitiveHistoryLine
// re-seeds the edit-context secret row and this test fails.

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func writeSeedFile17798(t *testing.T, lines []string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "history")
	content := ""
	for _, l := range lines {
		content += l + "\n"
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestReadHistorySeedCursorAware17798(t *testing.T) {
	cases := []struct {
		name  string
		lines []string
		want  []string // nil means empty
	}{
		{"conf abbreviation enters config mode",
			[]string{"conf", "edit snmp", "set community S3cretConf17798"},
			[]string{"conf", "edit snmp"}},
		{"config abbreviation enters config mode",
			[]string{"config", "edit snmp", "set community S3cretConfig17798"},
			[]string{"config", "edit snmp"}},
		{"edit prefix with supported pipe advances cursor even when line is filtered",
			[]string{"configure", "edit snmp | no-more", "set community S3cretPipe17798"},
			[]string{"configure"}},
		{"edit prefix with chained supported pipes advances cursor",
			[]string{"configure", "edit snmp | no-more | count", "set community S3cretPipeChain17798"},
			[]string{"configure"}},
		{"ambiguous operational abbreviation stays out of config mode; community mutation still omitted from shared seed",
			[]string{"c", "edit snmp", "set community S3cretAmbiguous17798"},
			[]string{"c", "edit snmp"}},
		{"explicit exit then configure re-entry seeds navigation but omits ambiguous generic GRE key",
			[]string{
				"configure",
				"edit protocols ospf area 0 interface ge-0/0/0 authentication md5 1",
				"top exit",
				"configure",
				"edit interfaces gr-0/0/0 unit 0 tunnel",
				"set key 4242",
			},
			[]string{
				"configure",
				"edit protocols ospf area 0 interface ge-0/0/0 authentication md5 1",
				"top exit",
				"configure",
				"edit interfaces gr-0/0/0 unit 0 tunnel",
			}},
		{"configure rejected in config mode keeps snmp cursor and filters secret",
			[]string{"configure", "edit snmp", "configure", "set community S3cretRejectedConfigure17798"},
			[]string{"configure", "edit snmp", "configure"}},
		{"abbreviated configure rejected in config mode keeps snmp cursor",
			[]string{"configure", "edit snmp", "conf", "set community S3cretRejectedConf17798"},
			[]string{"configure", "edit snmp", "conf"}},
		{"config abbreviation rejected in config mode keeps snmp cursor",
			[]string{"configure", "edit snmp", "config", "set community S3cretRejectedConfig17798"},
			[]string{"configure", "edit snmp", "config"}},
		{"benign under snmp kept",
			[]string{"configure", "edit snmp", "set description uplink"},
			[]string{"configure", "edit snmp", "set description uplink"}},
		{"top-level sensitive still dropped",
			[]string{"set snmp community S3cretTop authorization read-only"},
			nil},
		{"benign top-level kept",
			[]string{"show version", "set system host-name fw1"},
			[]string{"show version", "set system host-name fw1"}},
		{"shell non-config then context-gated community omitted from shared seed",
			[]string{"show version", "set community S3cretNoCfg"},
			[]string{"show version"}},
		{"context reset by exit; context-gated community omitted before and after exit",
			[]string{"configure", "edit snmp", "set community S3cretReset authorization read-only", "exit", "set community S3cretAfterExit"},
			[]string{"configure", "edit snmp", "exit"}},
		{"secret advances cursor",
			[]string{"configure", "edit snmp", "set community S3cretAdv authorization read-only", "set trap-group S3cretTrap targets 192.0.2.1"},
			[]string{"configure", "edit snmp"}},
		{"top prefix preserves cursor",
			[]string{"configure", "edit snmp", "top set system host-name fw1", "set community S3cretAfterPrefix"},
			[]string{"configure", "edit snmp", "top set system host-name fw1"}},
		{"prefixed up exit at root releases config mode; context-gated mutation omitted from shared seed",
			[]string{"configure", "edit snmp", "up exit", "edit snmp", "set community S3cretUpExitRoot17798"},
			[]string{"configure", "edit snmp", "up exit", "edit snmp"}},
		{"quoted top exit does not release config mode",
			[]string{"configure", "edit snmp", `top "exit"`, "set community S3cretQuotedExit17798"},
			[]string{"configure", "edit snmp", `top "exit"`}},
		{"prefixed up quit at root releases config mode; context-gated mutation omitted from shared seed",
			[]string{"configure", "edit snmp", "up quit", "edit snmp", "set community S3cretUpQuitRoot17798"},
			[]string{"configure", "edit snmp", "up quit", "edit snmp"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := writeSeedFile17798(t, tc.lines)
			seed, err := ReadHistorySeed(path)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(seed, tc.want) {
				t.Fatalf("ReadHistorySeed(%v) = %q, want %q (#17798)", tc.lines, seed, tc.want)
			}
		})
	}
}

// Ambiguous configure after edit <stanza> (Ctrl-D/EOF unrecorded):
// replay cannot tell genuine re-entry from rejected in-config verb.
// Seed MUST drop the following credential under BOTH hypotheses --
// 3 verbs x 2 credential forms. Pre-fix keeps stale cursor so the
// root-only sensitive path (services/…/user-password) is missed.
func TestReadHistorySeedReentryDualCursor17972(t *testing.T) {
	verbs := []string{"configure", "conf", "config"}
	for _, v := range verbs {
		// Form A: full-path set after re-entry verb (terminal.go:424 stale prefix).
		t.Run(v+"/full-set", func(t *testing.T) {
			credential := "set services user-identification active-directory-access user-password SECRET17972A"
			lines := []string{"configure", "edit snmp", v, credential}
			seed, err := ReadHistorySeed(writeSeedFile17798(t, lines))
			if err != nil {
				t.Fatal(err)
			}
			if slices.Contains(seed, credential) {
				t.Fatalf("seed leaked credential %q", credential)
			}
		})
		// Form B: ADA prefix via edit, then relative set user-password.
		t.Run(v+"/relative-set", func(t *testing.T) {
			credential := "set user-password SECRET17972B"
			lines := []string{"configure", "edit snmp", v,
				"edit services user-identification active-directory-access", credential}
			seed, err := ReadHistorySeed(writeSeedFile17798(t, lines))
			if err != nil {
				t.Fatal(err)
			}
			if slices.Contains(seed, credential) {
				t.Fatalf("seed leaked credential %q", credential)
			}
		})
		// A generic key is context-sensitive; with no session markers,
		// seed replay cannot prove this was the GRE identifier rather than
		// a secret under another process's OSPF MD5 cursor.
		t.Run(v+"/generic-key-omitted-from-seed", func(t *testing.T) {
			lines := []string{"configure", "edit snmp", v,
				"edit interfaces gr-0/0/0 unit 0 tunnel", "set key 4242"}
			seed, err := ReadHistorySeed(writeSeedFile17798(t, lines))
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(seed, lines[:len(lines)-1]) {
				t.Fatalf("seed=%q want navigation-only %q", seed, lines[:len(lines)-1])
			}

		})
	}
}

func TestAdvanceHistorySeedCursorUpExitRestoresOriginalCursor17798(t *testing.T) {
	for _, verb := range []string{"exit", "quit"} {
		t.Run(verb, func(t *testing.T) {
			original := []string{"system", "login", "user", "alice"}
			gotPath, gotMode := advanceHistorySeedCursor(original, true, "up "+verb)
			if !slices.Equal(gotPath, original) || !gotMode {
				t.Fatalf("advanceHistorySeedCursor(%v, true, %q) = (%v, %t), want (%v, true) (#17798)",
					original, "up "+verb, gotPath, gotMode, original)
			}
		})
	}
}
