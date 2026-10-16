package configstore

import (
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestShowCompareRollbackRedactedSecretOnly14170 pins #14170: a rollback slot
// and the candidate differing ONLY in a secret (or only in a credential-bearing
// URL) must render a non-empty masked diff from ShowCompareRollbackRedacted.
// The pre-fix implementation constant-masked both arms via forDisplay
// (RedactedClone), collapsing distinct secrets to the same placeholder so the
// rotation rendered "[no changes]".
func TestShowCompareRollbackRedactedSecretOnly14170(t *testing.T) {
	const (
		before = "ROLLBACK-SECRET-BEFORE-14170"
		after  = "ROLLBACK-SECRET-AFTER-14170"
	)
	s := newTestStoreAt(t, filepath.Join(t.TempDir(), "config"))
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := s.SetFromInput("security ike policy pol1 pre-shared-key ascii-text " + before); err != nil {
		t.Fatalf("SetFromInput initial secret: %v", err)
	}
	if _, err := s.Commit(); err != nil {
		t.Fatalf("Commit initial secret: %v", err)
	}
	// Commit again with no staged change: history slot 1 (most recent) is now
	// the `before`-secret active, and the candidate matches it exactly.
	if _, err := s.Commit(); err != nil {
		t.Fatalf("Commit identical: %v", err)
	}
	if got, err := s.ShowCompareRollbackRedacted(1); err != nil {
		t.Fatalf("ShowCompareRollbackRedacted identical premise: %v", err)
	} else if got != "[no changes]\n" {
		t.Fatalf("premise: identical rollback/candidate should be [no changes], got:\n%s", got)
	}
	// Rotate ONLY the secret in the candidate; the rollback slot still holds `before`.
	if err := s.SetFromInput("security ike policy pol1 pre-shared-key ascii-text " + after); err != nil {
		t.Fatalf("SetFromInput rotated secret: %v", err)
	}
	got, err := s.ShowCompareRollbackRedacted(1)
	if err != nil {
		t.Fatalf("ShowCompareRollbackRedacted(1): %v", err)
	}
	if got == "[no changes]\n" || got == "" {
		t.Fatalf("secret-only rollback difference rendered as no changes:\n%q", got)
	}
	for _, secret := range []string{before, after} {
		if strings.Contains(got, secret) {
			t.Errorf("rollback redacted compare exposed secret %q:\n%s", secret, got)
		}
	}
	beforeHash := sha256.Sum256([]byte(before))
	afterHash := sha256.Sum256([]byte(after))
	for _, want := range []string{
		"[secret fingerprint removed: " + hex.EncodeToString(beforeHash[:4]) + "]",
		"[secret fingerprint added: " + hex.EncodeToString(afterHash[:4]) + "]",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("rollback redacted compare omitted fingerprint %q:\n%s", want, got)
		}
	}
	if strings.Count(got, config.SecretDataPlaceholder) != 2 {
		t.Fatalf("secret rotation must show two constant-masked arms:\n%s", got)
	}
}

// TestShowCompareRollbackRedactedURLCredentialOnly14170 is the URL-credential
// twin: rollback slot and candidate differing only in the hidden userinfo
// password of a credential-bearing URL must show a masked diff, and neither
// credential nor the unsanitized URL may appear.
func TestShowCompareRollbackRedactedURLCredentialOnly14170(t *testing.T) {
	const (
		before = "ROLLBACK-URL-CRED-BEFORE-14170"
		after  = "ROLLBACK-URL-CRED-AFTER-14170"
	)
	s := newTestStoreAt(t, filepath.Join(t.TempDir(), "config"))
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	// Seed rollback slot + candidate directly (mirrors the 11819 URL fixture):
	// Commit rejects inline archive passwords, so build the trees without it.
	if err := s.SetFromInput(`system archival configuration archive-sites "scp://alice:` + before + `@archive.example/configs"`); err != nil {
		t.Fatalf("SetFromInput initial URL: %v", err)
	}
	s.active = s.candidate.Clone()
	// Push the `before` tree into history slot 1 (most recent).
	s.history.Push(&HistoryEntry{Config: s.active.Clone()})
	if err := s.DeleteFromInput(`system archival configuration archive-sites "scp://alice:` + before + `@archive.example/configs"`); err != nil {
		t.Fatalf("DeleteFromInput initial URL: %v", err)
	}
	if err := s.SetFromInput(`system archival configuration archive-sites "scp://alice:` + after + `@archive.example/configs"`); err != nil {
		t.Fatalf("SetFromInput rotated URL: %v", err)
	}
	// Sanity: identical arms would be [no changes]; here only the credential rotates.
	got, err := s.ShowCompareRollbackRedacted(1)
	if err != nil {
		t.Fatalf("ShowCompareRollbackRedacted(1): %v", err)
	}
	if got == "[no changes]\n" || got == "" {
		t.Fatalf("URL-credential-only rollback difference rendered as no changes:\n%q", got)
	}
	for _, secret := range []string{before, after} {
		if strings.Contains(got, secret) {
			t.Errorf("rollback redacted compare exposed URL credential %q:\n%s", secret, got)
		}
	}
	if strings.Contains(got, "alice:"+before) || strings.Contains(got, "alice:"+after) {
		t.Errorf("rollback redacted compare exposed unsanitized URL:\n%s", got)
	}
	beforeHash := sha256.Sum256([]byte("alice:" + before))
	afterHash := sha256.Sum256([]byte("alice:" + after))
	for _, want := range []string{
		"[secret fingerprint removed: " + hex.EncodeToString(beforeHash[:4]) + "]",
		"[secret fingerprint added: " + hex.EncodeToString(afterHash[:4]) + "]",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("rollback redacted compare omitted URL fingerprint %q:\n%s", want, got)
		}
	}
	var removedArm, addedArm string
	for _, line := range strings.Split(got, "\n") {
		switch {
		case strings.HasPrefix(line, "-") && strings.Contains(line, "archive-sites"):
			removedArm = line
		case strings.HasPrefix(line, "+") && strings.Contains(line, "archive-sites"):
			addedArm = line
		}
	}
	for label, arm := range map[string]string{"removed": removedArm, "added": addedArm} {
		if arm == "" || !strings.Contains(arm, "<redacted>@archive.example/configs") {
			t.Errorf("%s URL compare arm must preserve only sanitized endpoint context, got %q\n%s", label, arm, got)
		}
	}
}

// TestShowCompareRollbackRedactedIdentical14170 is the negative control:
// identical rollback slot and candidate must still render [no changes].
func TestShowCompareRollbackRedactedIdentical14170(t *testing.T) {
	s := newTestStoreAt(t, filepath.Join(t.TempDir(), "config"))
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := s.SetFromInput("security ike policy pol1 pre-shared-key ascii-text IDENTICAL-SECRET-14170"); err != nil {
		t.Fatalf("SetFromInput: %v", err)
	}
	if _, err := s.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	// After one commit, history slot 1 is the prior (empty) active, so push a
	// slot identical to the candidate explicitly.
	s.history.Push(&HistoryEntry{Config: s.candidate.Clone()})
	got, err := s.ShowCompareRollbackRedacted(1)
	if err != nil {
		t.Fatalf("ShowCompareRollbackRedacted(1): %v", err)
	}
	if got != "[no changes]\n" {
		t.Fatalf("identical rollback/candidate should be [no changes], got:\n%s", got)
	}
	if strings.Contains(got, "IDENTICAL-SECRET-14170") {
		t.Fatalf("identical compare leaked secret:\n%s", got)
	}
}
