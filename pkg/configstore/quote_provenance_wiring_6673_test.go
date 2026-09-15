package configstore

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// Round-10 WIRING guard for the #6673 quote-provenance fix.
//
// The pkg/config tests call config.ParseSetCommandQuoted + SetPathQuoted
// directly. That proves the mechanism but NOT that production uses it: every
// operator `set` — CLI, gRPC (server_config.go), REST (api/config.go) — arrives
// as a STRING at Store.SetFromInputAs, and it is that method's choice of parser
// and setter that decides whether the quoting survives into the candidate tree.
// Reverting either half (ParseSetCommandGrouped -> ParseSetCommand, or
// SetAsQuotedGrouped -> SetAs) still compiles and still passes every pkg/config
// test; this is the test that goes red. (#9881 unified the operator-set and
// replay pairs on the grouped variants; the quote half is unchanged.)
//
// LoadSet is covered too, because `show | display set` output is replayed
// through applyEditLine on rollback, rescue and peer sync.
func TestSetFromInput6673CarriesQuoteProvenance(t *testing.T) {
	s := newTestStore(t)
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := s.SetFromInput(
		`event-options policy p then change-configuration commands ` +
			`[ "set" "system host-name pwned" ]`); err != nil {
		t.Fatalf("SetFromInput: %v", err)
	}
	assertTwoAuthoredCommands6673(t, "SetFromInput", s.candidate)
}

func TestLoadSet6673CarriesQuoteProvenance(t *testing.T) {
	s := newTestStore(t)
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if _, err := s.LoadSet(
		`set event-options policy p then change-configuration commands ` +
			`[ "set" "system host-name pwned" ]` + "\n"); err != nil {
		t.Fatalf("LoadSet: %v", err)
	}
	assertTwoAuthoredCommands6673(t, "LoadSet", s.candidate)
}

// assertTwoAuthoredCommands6673 compiles the candidate and asserts the authored
// list stayed TWO values. One value means the quoted one-word member fused with
// its neighbour into `set system host-name pwned` — a command the operator never
// wrote, which classifyPlan would then accept and apply.
func assertTwoAuthoredCommands6673(t *testing.T, entry string, tree *config.ConfigTree) {
	t.Helper()
	if tree == nil {
		t.Fatalf("%s: candidate tree is nil", entry)
	}
	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("%s: compile: %v", entry, err)
	}
	if len(cfg.EventOptions) != 1 {
		t.Fatalf("%s: compiled %d event policies, want 1", entry, len(cfg.EventOptions))
	}
	got := cfg.EventOptions[0].ThenCommands
	want := []string{"set", "system host-name pwned"}
	if len(got) != len(want) {
		t.Fatalf("%s: compiled %d commands %q, want %d %q — the operator entry point "+
			"must carry per-token quote provenance into the candidate tree, or the two "+
			"authored members fuse into one applicable command (#6673)",
			entry, len(got), got, len(want), want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("%s: compiled commands %q, want %q", entry, got, want)
		}
	}
}
