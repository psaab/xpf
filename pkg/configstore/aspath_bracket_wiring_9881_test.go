package configstore

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #9881 wiring guards. The pkg/config tests prove the mechanism on trees
// built with the grouped pair directly; that does NOT prove production uses
// it. Every operator `set`/`delete` — CLI, gRPC, REST — arrives as a STRING
// at Store.SetFromInputAs / Store.DeleteFromInputAs, and it is those
// methods' choice of parser and setter that decides whether the bracket bit
// survives into the candidate tree. Reverting either half
// (ParseSetCommandGrouped -> ParseSetCommandQuoted, or SetAsQuotedGrouped ->
// SetAsQuoted) still compiles and still passes every pkg/config test; these
// are the tests that go red. Mirrors the #6673 wiring file.

func strictRejectsBracket9881(t *testing.T, entry string, tree *config.ConfigTree) {
	t.Helper()
	if tree == nil {
		t.Fatalf("%s: candidate tree is nil", entry)
	}
	_, err := config.CompileConfig(tree)
	if err == nil {
		t.Fatalf("%s: strict commit ACCEPTED an unquoted leading-bracket as-path regex — "+
			"the production entry point dropped the bracket provenance (#9881)", entry)
	}
	if !strings.Contains(err.Error(), "as-path AP1") {
		t.Errorf("%s: strict rejection does not name the as-path: %v", entry, err)
	}
	if !strings.Contains(strings.ToLower(err.Error()), "quot") {
		t.Errorf("%s: strict rejection prescribes no quoting remedy: %v", entry, err)
	}
}

func TestSetFromInput9881CarriesBracketProvenance(t *testing.T) {
	s := newTestStore(t)
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := s.SetFromInput(`policy-options as-path AP1 [0-9]+`); err != nil {
		t.Fatalf("SetFromInput: %v", err)
	}
	strictRejectsBracket9881(t, "SetFromInput", s.candidate)
}

func TestSetFromInput9881QuotedTwinCommits(t *testing.T) {
	s := newTestStore(t)
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := s.SetFromInput(`policy-options as-path AP1 "[0-9]+"`); err != nil {
		t.Fatalf("SetFromInput: %v", err)
	}
	cfg, err := config.CompileConfig(s.candidate)
	if err != nil {
		t.Fatalf("SetFromInput: strict commit rejected the QUOTED regex: %v", err)
	}
	if ap := cfg.PolicyOptions.ASPaths["AP1"]; ap == nil || ap.Regex != `[0-9]+` {
		t.Fatalf("SetFromInput: compiled %+v, want Regex=%q", ap, `[0-9]+`)
	}
}

func TestLoadSet9881CarriesBracketProvenance(t *testing.T) {
	s := newTestStore(t)
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if _, err := s.LoadSet("set policy-options as-path AP1 [0-9]+\n"); err != nil {
		t.Fatalf("LoadSet: %v", err)
	}
	strictRejectsBracket9881(t, "LoadSet", s.candidate)
}

func TestLoadMergeFlat9881CarriesBracketProvenance(t *testing.T) {
	s := newTestStore(t)
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := s.LoadMergeAs("", "set policy-options as-path AP1 [0-9]+\n"); err != nil {
		t.Fatalf("LoadMerge: %v", err)
	}
	strictRejectsBracket9881(t, "LoadMerge-flat", s.candidate)
}

// LoadOverride feeds the raw parsed tree to the write path (no FormatSet
// round trip), so hierarchical bracket provenance survives and the strict
// gate fires. (LoadMerge-hierarchical replays via FormatSet, which drops
// leaf bracket provenance — filed as #10084, the follow-up to this lane.)
func TestLoadOverrideHierarchical9881CarriesBracketProvenance(t *testing.T) {
	s := newTestStore(t)
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := s.LoadOverrideAs("", `policy-options { as-path AP1 [0-9]+; }`); err != nil {
		t.Fatalf("LoadOverride: %v", err)
	}
	strictRejectsBracket9881(t, "LoadOverride-hierarchical", s.candidate)
}

// SyncApply parses the peer text directly and compiles lenient: the flagged
// definition must be TOLERATED (no alarm-looping the cluster) with a warning
// naming the as-path.
func TestSyncApply9881WarnsLenient(t *testing.T) {
	s := newTestStore(t)
	cfg, err := s.SyncApply(`policy-options { as-path AP1 [0-9]+; }`, nil)
	if err != nil {
		t.Fatalf("SyncApply REJECTED a peer-synced config (#1960 brick): %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "as-path AP1") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("SyncApply produced no as-path warning; warnings=%v", cfg.Warnings)
	}
}

// TestInteractiveSetMatchesReplayForBracketedList_9881 pins the grouped
// upgrade: an interactive `set` line with brackets now builds the same tree
// as its replay (both go through the grouped pair). The security-zone list
// is the #6668 shape whose replay used to split; both zones must exist with
// the shared body intact.
func TestInteractiveSetMatchesReplayForBracketedList_9881(t *testing.T) {
	line := `security zones security-zone [ trust dmz ] host-inbound-traffic system-services ssh`
	viaSet := newTestStore(t)
	if err := viaSet.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := viaSet.SetFromInput(line); err != nil {
		t.Fatalf("SetFromInput: %v", err)
	}
	viaReplay := newTestStore(t)
	if err := viaReplay.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if _, err := viaReplay.LoadSet("set " + line + "\n"); err != nil {
		t.Fatalf("LoadSet: %v", err)
	}
	if got, want := viaSet.candidate.FormatSet(), viaReplay.candidate.FormatSet(); got != want {
		t.Fatalf("interactive set and its replay DIVERGED:\n--- set ---\n%s--- replay ---\n%s",
			got, want)
	}
	cfg, err := config.CompileConfig(viaSet.candidate)
	if err != nil {
		t.Fatalf("interactive bracketed-container line does not compile: %v", err)
	}
	for _, z := range []string{"trust", "dmz"} {
		if _, ok := cfg.Security.Zones[z]; !ok {
			t.Errorf("zone %q missing after interactive bracketed set — the list split", z)
		}
	}
}

// TestInteractiveDeleteNavigatesWide_9881 pins the set/delete symmetry the
// grouped upgrade requires: the interactive `set` above builds the bracketed
// container wide, so the matching interactive `delete` must navigate wide
// too — an arity re-split reports the node missing and the delete fails.
func TestInteractiveDeleteNavigatesWide_9881(t *testing.T) {
	s := newTestStore(t)
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	line := `security zones security-zone [ trust dmz ] host-inbound-traffic system-services ssh`
	if err := s.SetFromInput(line); err != nil {
		t.Fatalf("SetFromInput: %v", err)
	}
	if err := s.DeleteFromInput(`security zones security-zone [ trust dmz ]`); err != nil {
		t.Fatalf("DeleteFromInput missed the bracketed container its set built: %v", err)
	}
	if got := s.candidate.FormatSet(); strings.Contains(got, "security-zone") {
		t.Fatalf("bracketed container survived its delete:\n%s", got)
	}
}

// TestInteractiveSetBareLinesCarryNoBracketProvenance_9881 pins the no-op
// half of the grouped upgrade: a set line with no brackets records no
// bracket mask anywhere, so every pre-existing unbracketed behaviour is
// byte-identical.
func TestInteractiveSetBareLinesCarryNoBracketProvenance_9881(t *testing.T) {
	s := newTestStore(t)
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	for _, line := range []string{
		`system host-name fw1`,
		`policy-options as-path AP1 .* 65000 .*`,
		`policy-options as-path AP2 "[0-9]+"`,
	} {
		if err := s.SetFromInput(line); err != nil {
			t.Fatalf("SetFromInput(%q): %v", line, err)
		}
	}
	var walk func(nodes []*config.Node)
	walk = func(nodes []*config.Node) {
		for _, n := range nodes {
			if len(n.KeysBracketed) != 0 {
				t.Fatalf("bare set lines recorded bracket provenance on %q: %v",
					n.Keys, n.KeysBracketed)
			}
			walk(n.Children)
		}
	}
	walk(s.candidate.Children)
	cfg, err := config.CompileConfig(s.candidate)
	if err != nil {
		t.Fatalf("bare lines do not compile: %v", err)
	}
	if ap := cfg.PolicyOptions.ASPaths["AP1"]; ap == nil || ap.Regex != `.* 65000 .*` {
		t.Fatalf("compiled %+v, want the multi-token Regex intact", ap)
	}
}
