package config

import (
	"strings"
	"testing"
)

// compileSetLinesT compiles a list of `set ...` lines into a *Config using the
// flat-set path (ParseSetCommand + SetPath), per the project rule never to feed
// multiple set lines through NewParser (it merges newlines as whitespace).
func compileSetLinesT(t *testing.T, lines []string) *Config {
	t.Helper()
	tree := &ConfigTree{}
	for _, line := range lines {
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
		t.Fatalf("compile error: %v", err)
	}
	return cfg
}

// TestFilterLossPriorityWarnsInert proves #2507: a firewall-filter term with
// `then loss-priority <level>` commits successfully (loss-priority is valid
// Junos), but emits a commit WARNING that the action is accepted-but-inert in
// the userspace dataplane, naming the family/filter/term.
//
// Fail-on-revert: deleting the validateFilterLossPriorityWarnings call (or the
// per-term append) removes the warning and this test fails.
func TestFilterLossPriorityWarnsInert(t *testing.T) {
	cfg := compileSetLinesT(t, []string{
		"set system dataplane-type userspace",
		"set firewall family inet filter mark term mark-high then loss-priority high",
		"set firewall family inet filter mark term mark-high then accept",
	})

	warnings := ValidateConfig(cfg)

	var got string
	for _, w := range warnings {
		if strings.Contains(w, "loss-priority") && strings.Contains(w, "filter") {
			got = w
			break
		}
	}
	if got == "" {
		t.Fatalf("expected a firewall-filter loss-priority inert warning, got warnings: %v", warnings)
	}
	for _, want := range []string{"inet", "mark", "mark-high", "high", "inert"} {
		if !strings.Contains(got, want) {
			t.Errorf("warning %q missing substring %q", got, want)
		}
	}
}

// TestFilterLossPriorityCommitSucceeds confirms the warning does NOT fail-close
// the commit: loss-priority is valid Junos and must be accepted (warn, never
// reject) so an existing config is never bricked. CompileConfig already
// succeeded in compileSetLinesT; here we additionally assert the strict
// commit-check action validator does not reject the term.
func TestFilterLossPriorityCommitSucceeds(t *testing.T) {
	tree := &ConfigTree{}
	for _, line := range []string{
		"set system dataplane-type userspace",
		"set firewall family inet filter mark term mark-high then loss-priority high",
		"set firewall family inet filter mark term mark-high then accept",
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
		t.Fatalf("loss-priority must commit (warn, not reject): %v", err)
	}
	if err := SchemaValidate(tree); err != nil {
		t.Fatalf("SchemaValidate rejected a valid loss-priority filter: %v", err)
	}
	// Sanity: the term actually carries the parsed loss-priority.
	f := cfg.Firewall.FiltersInet["mark"]
	if f == nil || len(f.Terms) == 0 || f.Terms[0].LossPriority != "high" {
		t.Fatalf("expected term to store LossPriority=high, got %+v", f)
	}
}

// TestFilterLossPriorityNoFalsePositive confirms a filter WITHOUT loss-priority
// emits no such warning (the warn loop is gated on the action being present).
func TestFilterLossPriorityNoFalsePositive(t *testing.T) {
	cfg := compileSetLinesT(t, []string{
		"set system dataplane-type userspace",
		"set firewall family inet filter plain term t1 then accept",
	})
	for _, w := range ValidateConfig(cfg) {
		if strings.Contains(w, "loss-priority") && strings.Contains(w, "filter") {
			t.Fatalf("unexpected loss-priority warning for a filter with no loss-priority action: %q", w)
		}
	}
}
