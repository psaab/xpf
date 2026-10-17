package configstore

import (
	"strings"
	"testing"
)

// #14577 (Y03-02): a config carrying `security flow
// syn-flood-protection-mode syn-cookie` arrives leniently via SyncApply
// (peer sync / load) and compiles, but the next unrelated strict commit
// is refused by the closed-world schema walk because the leaf was never
// modelled — the node is commit-locked until the operator deletes the
// documented SYN-cookie defence. After the fix the leaf is modelled, so
// CheckText accepts it and an unrelated commit succeeds after SyncApply.

func TestCheckTextAcceptsSynCookie14577(t *testing.T) {
	for _, text := range []string{
		"security {\n flow {\n syn-flood-protection-mode syn-cookie;\n }\n}\n",
		"security {\n log {\n report;\n }\n}\n",
		"security {\n flow {\n traceoptions {\n file f1 size 100000 files 3;\n }\n }\n}\n",
		"security {\n flow {\n traceoptions {\n file f1 {\n size 100000;\n files 3;\n }\n }\n }\n}\n",
	} {
		cfg, err := CheckText(text, -1)
		if err != nil {
			t.Fatalf("CheckText(%q) = %v, want nil", text, err)
		}
		if cfg == nil {
			t.Fatalf("CheckText(%q) returned nil config", text)
		}
	}
	// Compiled values must survive CheckText.
	cfg, err := CheckText("security {\n flow {\n syn-flood-protection-mode syn-cookie;\n }\n log {\n report;\n }\n}\n", -1)
	if err != nil {
		t.Fatalf("CheckText combined: %v", err)
	}
	if cfg.Security.Flow.SynFloodProtectionMode != "syn-cookie" {
		t.Fatalf("SynFloodProtectionMode = %q, want syn-cookie", cfg.Security.Flow.SynFloodProtectionMode)
	}
	if !cfg.Security.Log.Report {
		t.Fatalf("Log.Report = false, want true")
	}
	// Typo still fails.
	if _, err := CheckText("security {\n flow {\n syn-flood-protection-mod syn-cookie;\n }\n}\n", -1); err == nil ||
		!strings.Contains(err.Error(), "syn-flood-protection-mod") {
		t.Fatalf("CheckText typo = %v, want reject naming syn-flood-protection-mod", err)
	}
	// syn-proxy is not implemented: explicit reject, not silent accept.
	if _, err := CheckText("security {\n flow {\n syn-flood-protection-mode syn-proxy;\n }\n}\n", -1); err == nil ||
		!strings.Contains(err.Error(), "syn-proxy") {
		t.Fatalf("CheckText syn-proxy = %v, want explicit reject naming syn-proxy", err)
	}
}

func TestSyncApplySynCookieThenUnrelatedCommit14577(t *testing.T) {
	s := newTestStore(t)
	cfg, err := s.SyncApply("security {\n flow {\n syn-flood-protection-mode syn-cookie;\n }\n}\n", nil)
	if err != nil {
		t.Fatalf("SyncApply(syn-cookie): %v", err)
	}
	if cfg.Security.Flow.SynFloodProtectionMode != "syn-cookie" {
		t.Fatalf("SyncApply compiled mode = %q, want syn-cookie", cfg.Security.Flow.SynFloodProtectionMode)
	}
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := s.SetFromInput("system host-name b"); err != nil {
		t.Fatalf("SetFromInput: %v", err)
	}
	if _, err := s.CommitCheck(); err != nil {
		t.Fatalf("unrelated CommitCheck after SyncApply(syn-cookie) = %v, want nil (commit-lockout)", err)
	}
	if _, err := s.Commit(); err != nil {
		t.Fatalf("unrelated Commit after SyncApply(syn-cookie) = %v, want nil (commit-lockout)", err)
	}

	// Control: allow-dns-reply carried leniently, same commit succeeds.
	s2 := newTestStore(t)
	if _, err := s2.SyncApply("security {\n flow {\n allow-dns-reply;\n }\n}\n", nil); err != nil {
		t.Fatalf("SyncApply control: %v", err)
	}
	if err := s2.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure control: %v", err)
	}
	if _, err := s2.CommitCheck(); err != nil {
		t.Fatalf("control CommitCheck = %v, want nil", err)
	}
}
