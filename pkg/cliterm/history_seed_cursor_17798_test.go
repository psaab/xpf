package cliterm

// #17798: ReadHistorySeed re-filtered with the no-cursor
// IsSensitiveHistoryLine. A legacy pre-#16794 file could contain
// `set community S3cretF …` typed under `edit snmp`; on the bare line it
// flags nothing, so the secret was re-seeded into live recall. The seed
// filter must now replay the file sequentially, judging each line at the
// edit cursor established by preceding navigation lines and advancing
// that cursor on every scanned line (including filtered secret lines),
// exactly as the live dispatch did when the lines were typed.
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
		{"edit prefix with supported pipe advances cursor even when line is filtered",
			[]string{"configure", "edit snmp | no-more", "set community S3cretPipe17798"},
			[]string{"configure"}},
		{"ambiguous operational abbreviation stays out of config mode",
			[]string{"c", "edit snmp", "set community S3cretAmbiguous17798"},
			[]string{"c", "edit snmp", "set community S3cretAmbiguous17798"}},
		{"configure re-entry starts at root and retains benign GRE key",
			[]string{
				"configure",
				"edit protocols ospf area 0 interface ge-0/0/0 authentication md5 1",
				"configure",
				"edit interfaces gr-0/0/0 unit 0 tunnel",
				"set key 4242",
			},
			[]string{
				"configure",
				"edit protocols ospf area 0 interface ge-0/0/0 authentication md5 1",
				"configure",
				"edit interfaces gr-0/0/0 unit 0 tunnel",
				"set key 4242",
			}},
		{"benign under snmp kept",
			[]string{"configure", "edit snmp", "set description uplink"},
			[]string{"configure", "edit snmp", "set description uplink"}},
		{"top-level sensitive still dropped",
			[]string{"set snmp community S3cretTop authorization read-only"},
			nil},
		{"benign top-level kept",
			[]string{"show version", "set system host-name fw1"},
			[]string{"show version", "set system host-name fw1"}},
		{"shell non-config then bare community kept",
			[]string{"show version", "set community S3cretNoCfg"},
			[]string{"show version", "set community S3cretNoCfg"}},
		{"context reset by exit; secret inside dropped, bare community after exit kept",
			[]string{"configure", "edit snmp", "set community S3cretReset authorization read-only", "exit", "set community S3cretAfterExit"},
			[]string{"configure", "edit snmp", "exit", "set community S3cretAfterExit"}},
		{"secret advances cursor",
			[]string{"configure", "edit snmp", "set community S3cretAdv authorization read-only", "set trap-group S3cretTrap targets 192.0.2.1"},
			[]string{"configure", "edit snmp"}},
		{"top prefix preserves cursor",
			[]string{"configure", "edit snmp", "top set system host-name fw1", "set community S3cretAfterPrefix"},
			[]string{"configure", "edit snmp", "top set system host-name fw1"}},
		{"prefixed up exit at root releases config mode",
			[]string{"configure", "edit snmp", "up exit", "edit snmp", "set community S3cretUpExitRoot17798"},
			[]string{"configure", "edit snmp", "up exit", "edit snmp", "set community S3cretUpExitRoot17798"}},
		{"quoted top exit does not release config mode",
			[]string{"configure", "edit snmp", `top "exit"`, "set community S3cretQuotedExit17798"},
			[]string{"configure", "edit snmp", `top "exit"`}},
		{"prefixed up quit at root releases config mode",
			[]string{"configure", "edit snmp", "up quit", "edit snmp", "set community S3cretUpQuitRoot17798"},
			[]string{"configure", "edit snmp", "up quit", "edit snmp", "set community S3cretUpQuitRoot17798"}},
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

func TestAdvanceHistorySeedCursorUpExitRestoresOriginalCursor17798(t *testing.T) {
	for _, verb := range []string{"exit", "quit"} {
		t.Run(verb, func(t *testing.T) {
			original := []string{"snmp", "community"}
			gotPath, gotMode := advanceHistorySeedCursor(original, true, "up "+verb)
			if !slices.Equal(gotPath, original) || !gotMode {
				t.Fatalf("advanceHistorySeedCursor(%v, true, %q) = (%v, %t), want (%v, true) (#17798)",
					original, "up "+verb, gotPath, gotMode, original)
			}
		})
	}
}
