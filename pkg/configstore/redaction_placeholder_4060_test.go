package configstore

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #4060 — symmetric commit-ingest guard for the #4051 raw-AST secret redaction.
//
// RedactedClone masks every secret leaf with config.SecretDataPlaceholder
// ("##SECRET-DATA##") for the REST config show / export + gRPC ShowConfig
// surfaces. Those renders are display-only and NOT restorable. An operator who
// re-applies a redacted export (a load/commit of that text) must be REJECTED at
// commit-ingest — otherwise the placeholder is silently committed as the LITERAL
// secret for every secret leaf, breaking IPsec/auth with a nonsense key.
//
// The IKE pre-shared-key is deliberately used as the probe: it is opaque free
// text to the #1319 typed-leaf validators (no per-leaf validator would reject
// "##SECRET-DATA##"), so ONLY the #4060 placeholder guard catches it — proving
// the guard is load-bearing rather than a coincidental typed-leaf rejection.

// redactedPSKLine is the config-mode `set` input (no `set` prefix, for
// SetFromInput) that a REST `export` of a configured IKE PSK renders after
// redaction: the ascii-text qualifier is kept, the key material is the masked
// placeholder (quoted by FormatSet because '#' is a non-identifier char).
const redactedPSKLine = `security ike policy pol1 pre-shared-key ascii-text "` + config.SecretDataPlaceholder + `"`
const redactedPSKConfigText = `security {
    ike {
        policy pol1 {
            pre-shared-key ascii-text "` + config.SecretDataPlaceholder + `";
        }
    }
}`

// TestCommitCheck_RejectsRedactionPlaceholder is the strict-path e2e: an
// operator committing a re-applied redacted export is rejected at both
// CommitCheck and Commit with the #4060 placeholder error.
func TestCommitCheck_RejectsRedactionPlaceholder(t *testing.T) {
	s := newTestStoreAt(t, filepath.Join(t.TempDir(), "config"))
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := s.SetFromInput(redactedPSKLine); err != nil {
		t.Fatalf("SetFromInput: %v", err)
	}
	_, err := s.CommitCheck()
	if err == nil {
		t.Fatal("expected CommitCheck to reject the ##SECRET-DATA## placeholder, got nil")
	}
	if !strings.Contains(err.Error(), config.SecretDataPlaceholder) {
		t.Fatalf("CommitCheck error should name the redaction placeholder: %v", err)
	}
	if !strings.Contains(err.Error(), "pre-shared-key") {
		t.Fatalf("CommitCheck error should name the offending config path: %v", err)
	}
	if _, err := s.Commit(); err == nil {
		t.Fatal("expected Commit to reject the ##SECRET-DATA## placeholder, got nil")
	}
}

// TestCheckText_RejectsRedactionPlaceholder proves the same rejection through
// the CheckText gate (the #1879 `xpfd check-config` day-0 path), which parses
// full config text — the shape a REST `load`/`import` of an exported file takes.
func TestCheckText_RejectsRedactionPlaceholder(t *testing.T) {
	_, err := CheckText(redactedPSKConfigText, -1)
	if err == nil {
		t.Fatal("expected CheckText to reject the ##SECRET-DATA## placeholder, got nil")
	}
	if !strings.Contains(err.Error(), config.SecretDataPlaceholder) {
		t.Fatalf("CheckText error should name the redaction placeholder: %v", err)
	}
}

// SyncApply must not promote a redacted export as a live secret. The old
// active config remains installed when the placeholder-specific error rejects
// the peer-synced tree.
func TestSyncApply_RejectsRedactionPlaceholder(t *testing.T) {
	s := newTestStoreAt(t, filepath.Join(t.TempDir(), "config"))
	if _, err := s.SyncApply("system { host-name before-placeholder; }", nil); err != nil {
		t.Fatalf("SyncApply baseline config: %v", err)
	}

	compiled, err := s.SyncApply(redactedPSKConfigText, nil)
	if err == nil {
		t.Fatal("SyncApply promoted the redaction placeholder as a live secret")
	}
	if !config.IsRedactionPlaceholderIngestError(err) {
		t.Fatalf("SyncApply error = %v, want the placeholder-specific ingest rejection", err)
	}
	if !strings.Contains(err.Error(), config.SecretDataPlaceholder) ||
		!strings.Contains(err.Error(), "pre-shared-key") {
		t.Fatalf("SyncApply error = %v, want placeholder and offending path", err)
	}
	if compiled != nil {
		t.Fatal("SyncApply returned a compiled config for a rejected placeholder")
	}
	if active := s.ActiveConfig(); active == nil || active.System.HostName != "before-placeholder" {
		t.Fatalf("rejected peer config replaced the active config: %#v", active)
	}
}

// TestCommitCheck_AcceptsRealSecret proves the guard rejects ONLY the exact
// placeholder: a normal cleartext IKE PSK still commits cleanly.
func TestCommitCheck_AcceptsRealSecret(t *testing.T) {
	s := newTestStoreAt(t, filepath.Join(t.TempDir(), "config"))
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := s.SetFromInput("security ike policy pol1 pre-shared-key ascii-text realsupersecret"); err != nil {
		t.Fatalf("SetFromInput: %v", err)
	}
	if _, err := s.CommitCheck(); err != nil {
		t.Fatalf("a real cleartext secret must pass CommitCheck, got: %v", err)
	}
	if _, err := s.Commit(); err != nil {
		t.Fatalf("a real cleartext secret must Commit, got: %v", err)
	}
}

// TestLoad_RejectsStoredRedactionPlaceholder is the tolerant-ingress exception
// for the display-only sentinel. Unlike a legacy typed-leaf violation, a
// redaction placeholder can never be a valid stored secret and must fail closed.
func TestLoad_RejectsStoredRedactionPlaceholder(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "config")
	writeStoredConfig(t, cfgPath,
		`set security ike policy pol1 pre-shared-key ascii-text "`+config.SecretDataPlaceholder+`"`)

	s := newTestStoreAt(t, cfgPath)
	err := s.Load()
	if err == nil {
		t.Fatal("Load() installed the redaction placeholder as a live secret")
	}
	if !config.IsRedactionPlaceholderIngestError(err) {
		t.Fatalf("Load() error = %v, want the placeholder-specific ingest rejection", err)
	}
	if !errors.Is(err, ErrConfigCompile) {
		t.Fatalf("Load() error = %v, want an ErrConfigCompile fail-closed error", err)
	}
	if !strings.Contains(err.Error(), config.SecretDataPlaceholder) ||
		!strings.Contains(err.Error(), "pre-shared-key") {
		t.Fatalf("Load() error = %v, want placeholder and offending path", err)
	}
	if active := s.ActiveConfig(); active != nil {
		t.Fatalf("Load() installed a compiled config containing the placeholder: %#v", active)
	}
}
