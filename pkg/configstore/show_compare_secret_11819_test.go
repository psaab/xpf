package configstore

import (
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestShowCompareRedactedSecretFingerprint11819(t *testing.T) {
	const (
		before = "COMPARE-SECRET-BEFORE-11819"
		after  = "COMPARE-SECRET-AFTER-11819\x00xpf-sha256=deadbeef\x00"
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
	if got := s.ShowCompareRedacted(); got != "[no changes]\n" {
		t.Fatalf("identical active/candidate secrets should compare as no changes, got:\n%s", got)
	}

	// A quoted config token may contain NUL bytes matching the private marker;
	// those bytes are still secret data and must not bypass redaction.
	if err := s.SetFromInput("security ike policy pol1 pre-shared-key ascii-text \"" + after + "\""); err != nil {
		t.Fatalf("SetFromInput rotated secret: %v", err)
	}
	got := s.ShowCompareRedacted()
	for _, secret := range []string{before, after} {
		if strings.Contains(got, secret) {
			t.Errorf("redacted compare exposed secret %q:\n%s", secret, got)
		}
	}
	beforeHash := sha256.Sum256([]byte(before))
	afterHash := sha256.Sum256([]byte(after))
	beforeFingerprint := hex.EncodeToString(beforeHash[:4])
	afterFingerprint := hex.EncodeToString(afterHash[:4])
	for _, want := range []string{
		"[secret fingerprint removed: " + beforeFingerprint + "]",
		"[secret fingerprint added: " + afterFingerprint + "]",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("redacted compare omitted fingerprint metadata %q:\n%s", want, got)
		}
	}
	var removedArm, addedArm string
	for _, line := range strings.Split(got, "\n") {
		switch {
		case strings.HasPrefix(line, "-") && strings.Contains(line, "pre-shared-key"):
			removedArm = line
		case strings.HasPrefix(line, "+") && strings.Contains(line, "pre-shared-key"):
			addedArm = line
		}
	}
	for label, arm := range map[string]string{"removed": removedArm, "added": addedArm} {
		if arm == "" || !strings.Contains(arm, config.SecretDataPlaceholder) ||
			strings.Contains(arm, "fingerprint") || strings.Contains(arm, "[sha256=") ||
			strings.Contains(arm, beforeFingerprint) || strings.Contains(arm, afterFingerprint) {
			t.Errorf("%s compare arm must contain only the constant secret mask, got %q\n%s", label, arm, got)
		}
	}
	if strings.Count(got, config.SecretDataPlaceholder) != 2 ||
		strings.Count(got, "[secret fingerprint") != 2 {
		t.Fatalf("secret rotation must show two constant-masked arms and separate fingerprints:\n%s", got)
	}
}

func TestShowCompareRedactedURLCredentialFingerprint11819(t *testing.T) {
	const (
		before = "URL-CREDENTIAL-BEFORE-11819"
		after  = "URL-CREDENTIAL-AFTER-11819"
	)
	s := newTestStoreAt(t, filepath.Join(t.TempDir(), "config"))
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := s.SetFromInput(`system archival configuration archive-sites "scp://alice:` + before + `@archive.example/configs"`); err != nil {
		t.Fatalf("SetFromInput initial URL: %v", err)
	}
	// Commit correctly rejects inline archive passwords, so seed this active-
	// state fixture directly to isolate display redaction from commit checks.
	s.active = s.candidate.Clone()
	if got := s.ShowCompareRedacted(); got != "[no changes]\n" {
		t.Fatalf("identical active/candidate URLs should compare as no changes, got:\n%s", got)
	}
	if err := s.DeleteFromInput(`system archival configuration archive-sites "scp://alice:` + before + `@archive.example/configs"`); err != nil {
		t.Fatalf("DeleteFromInput initial URL: %v", err)
	}
	if err := s.SetFromInput(`system archival configuration archive-sites "scp://alice:` + after + `@archive.example/configs"`); err != nil {
		t.Fatalf("SetFromInput rotated URL: %v", err)
	}

	got := s.ShowCompareRedacted()
	for _, secret := range []string{before, after} {
		if strings.Contains(got, secret) {
			t.Errorf("redacted compare exposed URL credential %q:\n%s", secret, got)
		}
	}
	beforeHash := sha256.Sum256([]byte("alice:" + before))
	afterHash := sha256.Sum256([]byte("alice:" + after))
	for _, want := range []string{
		"[secret fingerprint removed: " + hex.EncodeToString(beforeHash[:4]) + "]",
		"[secret fingerprint added: " + hex.EncodeToString(afterHash[:4]) + "]",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("redacted compare omitted URL credential fingerprint %q:\n%s", want, got)
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
		if arm == "" || !strings.Contains(arm, "<redacted>@archive.example/configs") ||
			strings.Contains(arm, before) || strings.Contains(arm, after) {
			t.Errorf("%s URL compare arm must preserve only sanitized endpoint context, got %q\n%s", label, arm, got)
		}
	}
	if strings.Count(got, "[secret fingerprint") != 2 {
		t.Fatalf("URL credential rotation must show separate old/new fingerprints:\n%s", got)
	}
}
