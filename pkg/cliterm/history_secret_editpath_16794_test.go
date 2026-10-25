package cliterm

// #16794: the #15287 history denylist was a hand-copied flat token list.
// It missed plain-text-password(-value) entirely and every edit-context
// spelling of the context-gated secrets (snmp community, md5 key):
// after `edit snmp`, `set community <s>` carries no `snmp` token on the
// line, so the secret persisted to ~/.xpf_history / ~/.xpf_cli_history.
// The predicate now resolves editPath + lexed line tokens through the
// config SSOT (secretIndices ∪ secretLeafKeywords). These tests pin the
// five defect rows from the issue, the unchanged controls, the on-disk
// recorder, and the SSOT drift pin.
//
// FAIL-ON-REVERT: restoring the flat denylist (or dropping the cursor
// from the call sites) makes every defect row below persist again.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// persisted16794 records one line through the real on-disk recorder at
// the given cursor and reports whether it reached the file.
func persisted16794(t *testing.T, editPath []string, line string) bool {
	t.Helper()
	path := filepath.Join(t.TempDir(), "history")
	if err := SecureReadlineHistory(path); err != nil {
		t.Fatalf("secure history: %v", err)
	}
	if err := RecordHistoryLineAt(editPath, path, line); err != nil {
		t.Fatalf("record %q at %v: %v", line, editPath, err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read history: %v", err)
	}
	return strings.Contains(string(data), line)
}

func TestHistoryEditContextSecretsNotPersisted16794(t *testing.T) {
	cases := []struct {
		name     string
		editPath []string
		line     string
	}{
		// The five defect rows from #16794.
		{"plain-text-password-value flat", nil, "set system root-authentication plain-text-password-value S3cretD"},
		{"plain-text-password flat", nil, "set system root-authentication plain-text-password S3cretE"},
		{"community under edit snmp", []string{"snmp"}, "set community S3cretF authorization read-only"},
		{"key under edit authentication md5 1", []string{"protocols", "ospf", "area", "0", "interface", "ge-0/0/0", "authentication", "md5", "1"}, "set key S3cretG"},
		{"md5 key under edit authentication", []string{"protocols", "ospf", "area", "0", "interface", "ge-0/0/0", "authentication"}, "set md5 1 key S3cretH"},
		// Same secrets spelled other resolved ways.
		{"community via edit line itself", nil, "edit snmp community S3cretI"},
		{"trap-group under edit snmp", []string{"snmp"}, "set trap-group S3cretJ targets 192.0.2.1"},
		{"secret under edit api-auth key", []string{"system", "services", "web-management", "api-auth", "key", "k1"}, "set secret S3cretK"},
		{"top set from snmp cursor", []string{"snmp"}, "top set system root-authentication plain-text-password-value S3cretL"},
		{"up set to snmp cursor", []string{"snmp", "community", "old"}, "up set community S3cretM authorization read-only"},
		{"quoted community value", []string{"snmp"}, `set community "S3cret N"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if !IsSensitiveHistoryLineAt(tc.editPath, tc.line) {
				t.Errorf("IsSensitiveHistoryLineAt(%v, %q) = false, want true (#16794)", tc.editPath, tc.line)
			}
			if persisted16794(t, tc.editPath, tc.line) {
				t.Errorf("line %q at cursor %v persisted to history file (#16794)", tc.line, tc.editPath)
			}
		})
	}
}

func TestHistoryControlsUnchanged16794(t *testing.T) {
	sensitive := []string{
		// Controls from #16794: already suppressed before the fix.
		"set snmp community S3cretA authorization read-only",
		"set protocols ospf area 0 interface ge-0/0/0 authentication md5 1 key S3cretB",
		"set system root-authentication encrypted-password $6$hash",
		"edit snmp community S3cretC",
		"set security ike policy p pre-shared-key ascii-text hunter2",
	}
	for _, line := range sensitive {
		if !IsSensitiveHistoryLine(line) {
			t.Errorf("control IsSensitiveHistoryLine(%q) = false, want true", line)
		}
	}
	benign := []struct {
		editPath []string
		line     string
	}{
		{nil, "show version"},
		{nil, "set system host-name fw1"},
		{[]string{"snmp"}, "set description uplink"},
		{[]string{"policy-options"}, "set community CUST members 65000:100"},
		{[]string{"interfaces", "ge-0/0/0", "unit", "0", "tunnel"}, "set key 4242"},
		{[]string{"snmp"}, "edit community"},
		{[]string{"snmp"}, "up"},
		{nil, "set interfaces ge-0/0/0 unit 0 description key-account"},
	}
	for _, tc := range benign {
		if IsSensitiveHistoryLineAt(tc.editPath, tc.line) {
			t.Errorf("benign IsSensitiveHistoryLineAt(%v, %q) = true, want false", tc.editPath, tc.line)
		}
	}
	// Benign lines DO persist (recorder is not blanket-suppressing).
	path := filepath.Join(t.TempDir(), "history")
	if err := SecureReadlineHistory(path); err != nil {
		t.Fatal(err)
	}
	if err := RecordHistoryLineAt([]string{"snmp"}, path, "set description uplink"); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "set description uplink") {
		t.Errorf("benign line at cursor did not persist: %q", data)
	}
}

// TestHistoryPredicatePinnedToSecretSSOT16794 is the drift pin the issue
// requires: every keyword in secretLeafKeywords ∪ the gated/distinctive
// spellings secretIndices knows must suppress a history line when it
// appears with a following value in a resolved config path. Adding a
// keyword to either config resolution without the history filter
// following (it resolves through the SSOT, so it follows automatically)
// — or re-introducing a hand-copied list in cliterm — reds this test.
func TestHistoryPredicatePinnedToSecretSSOT16794(t *testing.T) {
	const sentinel = "SENTINEL16794"
	keywords := map[string]bool{}
	for kw := range config.SecretLeafKeywordSet16794() {
		keywords[kw] = true
	}
	for _, kw := range config.SecretContextKeywords16794() {
		keywords[kw] = true
	}
	if len(keywords) == 0 {
		t.Fatal("SSOT keyword population is empty — pin would pass vacuously")
	}
	// Distinctive keywords: sensitive in the leaf position of a flat set.
	for kw := range keywords {
		line := "set system " + kw + " " + sentinel
		if config.IsSecretLeafKeyword(kw) {
			if !IsSensitiveHistoryLine(line) {
				t.Errorf("secretLeafKeywords %q not suppressed by history predicate: %q", kw, line)
			}
		}
	}
	// Gated keywords: sensitive in their gated resolved contexts, and the
	// resolved path (cursor + line) is what arms them.
	gated := []struct {
		kw       string
		editPath []string
		line     string
	}{
		{"community", []string{"snmp"}, "set community " + sentinel + " authorization read-only"},
		{"trap-group", []string{"snmp"}, "set trap-group " + sentinel + " targets 192.0.2.1"},
		{"key", []string{"protocols", "ospf", "area", "0", "interface", "ge-0/0/0", "authentication", "md5", "1"}, "set key " + sentinel},
		{"password", nil, "set system services dynamic-dns provider p password " + sentinel},
		{"secret", []string{"system", "services", "web-management", "api-auth", "key", "k1"}, "set secret " + sentinel},
	}
	for _, tc := range gated {
		if !keywords[tc.kw] {
			t.Errorf("gated keyword %q missing from SSOT population — pin out of date", tc.kw)
		}
		if !IsSensitiveHistoryLineAt(tc.editPath, tc.line) {
			t.Errorf("gated keyword %q in context %v not suppressed: %q", tc.kw, tc.editPath, tc.line)
		}
	}
	// The plain-text leaves the old denylist missed, by name.
	for _, kw := range []string{"plain-text-password", "plain-text-password-value"} {
		if !keywords[kw] {
			t.Errorf("%q missing from secretLeafKeywords SSOT", kw)
		}
		if !IsSensitiveHistoryLine("set system root-authentication " + kw + " " + sentinel) {
			t.Errorf("%q line not suppressed", kw)
		}
	}
}
