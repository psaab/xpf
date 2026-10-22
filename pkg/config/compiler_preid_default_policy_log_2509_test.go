package config

import (
	"strings"
	"testing"
)

// TestPreIDDefaultPolicyLogWarnsInert proves #2509: a
// `security pre-id-default-policy then log session-init/session-close` stanza
// commits successfully (pre-id-default-policy is valid Junos) but emits a
// commit WARNING that the logging action is accepted-but-inert in the
// userspace dataplane (no pre-identification session-admit path exists to
// stamp the log mode onto, unlike the per-policy #2508 path).
//
// Fail-on-revert: deleting the validatePreIDDefaultPolicyLogWarnings call (or
// the append) removes the warning and this test fails.
func TestPreIDDefaultPolicyLogWarnsInert(t *testing.T) {
	cfg := compileSetLinesT(t, []string{
		"set system dataplane-type userspace",
		"set security pre-id-default-policy then log session-init",
		"set security pre-id-default-policy then log session-close",
	})

	warnings := ValidateConfig(cfg)

	var got string
	for _, w := range warnings {
		if strings.Contains(w, "pre-id-default-policy") && strings.Contains(w, "inert") {
			got = w
			break
		}
	}
	if got == "" {
		t.Fatalf("expected a pre-id-default-policy log inert warning, got warnings: %v", warnings)
	}
	for _, want := range []string{"session-init", "session-close", "inert", "userspace"} {
		if !strings.Contains(got, want) {
			t.Errorf("warning %q missing substring %q", got, want)
		}
	}
}

// TestPreIDDefaultPolicyLogInitOnlyWarns confirms the warning names only the
// configured mode (session-init alone), mirroring the #2508 per-policy log
// matrix where init-only and close-only are distinct.
func TestPreIDDefaultPolicyLogInitOnlyWarns(t *testing.T) {
	cfg := compileSetLinesT(t, []string{
		"set system dataplane-type userspace",
		"set security pre-id-default-policy then log session-init",
	})

	var got string
	for _, w := range ValidateConfig(cfg) {
		if strings.Contains(w, "pre-id-default-policy") && strings.Contains(w, "inert") {
			got = w
			break
		}
	}
	if got == "" {
		t.Fatalf("expected an init-only pre-id-default-policy warning")
	}
	if !strings.Contains(got, "session-init") {
		t.Errorf("init-only warning %q missing session-init", got)
	}
	if strings.Contains(got, "session-close") {
		t.Errorf("init-only warning %q wrongly mentions session-close", got)
	}
}

// TestPreIDDefaultPolicyLogCommitSucceeds confirms the warning does NOT
// fail-close the commit: pre-id-default-policy then log is valid Junos and must
// be accepted (warn, never reject) so an existing config is never bricked.
// CompileConfig already succeeded in compileSetLinesT; here we additionally
// assert the strict commit-check validator does not reject the stanza, and
// that the flags are actually stored.
func TestPreIDDefaultPolicyLogCommitSucceeds(t *testing.T) {
	tree := &ConfigTree{}
	for _, line := range []string{
		"set system dataplane-type userspace",
		"set security pre-id-default-policy then log session-init",
		"set security pre-id-default-policy then log session-close",
	} {
		path, err := ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", line, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("pre-id-default-policy log must commit (warn, not reject): %v", err)
	}
	if err := SchemaValidate(tree); err != nil {
		t.Fatalf("SchemaValidate rejected a valid pre-id-default-policy log stanza: %v", err)
	}
	p := cfg.Security.PreIDDefaultPolicy
	if p == nil || !p.LogSessionInit || !p.LogSessionClose {
		t.Fatalf("expected PreIDDefaultPolicy to store both log flags, got %+v", p)
	}
}

// TestPreIDDefaultPolicyNoLogNoWarning confirms a pre-id-default-policy stanza
// with no `then log` (or no stanza at all) emits no such warning — the warn is
// gated on the log flags being present.
func TestPreIDDefaultPolicyNoLogNoWarning(t *testing.T) {
	cfg := compileSetLinesT(t, []string{
		"set system dataplane-type userspace",
		"set security policies default-policy deny-all",
	})
	for _, w := range ValidateConfig(cfg) {
		if strings.Contains(w, "pre-id-default-policy") {
			t.Fatalf("unexpected pre-id-default-policy warning when no then-log is configured: %q", w)
		}
	}
}
