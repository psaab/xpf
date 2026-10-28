package cliterm

// #17829 shared-file interleaving: two cmd/cli processes share one
// ~/.xpf_cli_history with independent edit cursors, so the legacy file
// can interleave a navigation prefix from one session with a secret-bearing
// mutation or edit command written under another session's cursor. Linear
// replay of the exact sequence below lands the secret line under the SECOND
// session's `edit system` cursor and retains it, even though it was typed by
// the first session still at `edit snmp`. The seed format carries no session
// markers, so the governing cursor cannot be proven from linear replay;
// seeded context-gated secrets are suppressed instead (option (c) on
// ReadHistorySeed).
//
// FAIL-ON-REVERT: dropping the seed-only mutation arm in
// ReadHistorySeed re-seeds `delete community OldSecret` and this test
// fails.

import (
	"slices"
	"testing"
)

func TestReadHistorySeedInterleavedSharedHistory17829(t *testing.T) {
	t.Run("reviewer exact sequence", func(t *testing.T) {
		lines := []string{
			"configure",
			"edit snmp",
			"configure",
			"edit system",
			"delete community OldSecret",
		}
		seed, err := ReadHistorySeed(writeSeedFile17798(t, lines))
		if err != nil {
			t.Fatal(err)
		}
		if slices.Contains(seed, "delete community OldSecret") {
			t.Fatalf("seed %q retained interleaved context-gated secret (#17829)", seed)
		}
		// Navigation lines (including the second `configure`) are
		// benign and stay seeded.
		for _, want := range []string{"configure", "edit snmp", "edit system"} {
			if !slices.Contains(seed, want) {
				t.Fatalf("seed %q missing benign navigation line %q (#17829)", seed, want)
			}
		}
	})

	t.Run("interleaved edit command secret suppressed", func(t *testing.T) {
		lines := []string{
			"configure",
			"edit snmp",
			"configure",
			"edit system",
			"edit community OldSecret",
		}
		seed, err := ReadHistorySeed(writeSeedFile17798(t, lines))
		if err != nil {
			t.Fatal(err)
		}
		if slices.Contains(seed, "edit community OldSecret") {
			t.Fatalf("seed %q retained interleaved context-gated edit secret (#17829)", seed)
		}
	})

	t.Run("benign relative mutation retained", func(t *testing.T) {
		lines := []string{"configure", "edit snmp", "delete description uplink"}
		seed, err := ReadHistorySeed(writeSeedFile17798(t, lines))
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(seed, lines) {
			t.Fatalf("ReadHistorySeed(%q) = %q, want benign lines retained (#17829)", lines, seed)
		}
	})

	// Seed-only scope: the context gate still decides live recording
	// and the flat (no-cursor) judgement is unchanged.
	t.Run("live recorder cursor decisions unchanged", func(t *testing.T) {
		if !IsSensitiveHistoryLineAt([]string{"snmp"}, "delete community OldSecret") {
			t.Fatalf("live recorder no longer suppresses delete community at snmp cursor (#17829)")
		}
		if IsSensitiveHistoryLineAt([]string{"system"}, "delete community OldSecret") {
			t.Fatalf("live recorder now suppresses delete community at system cursor; seed-only arm leaked into recorder (#17829)")
		}
		if IsSensitiveHistoryLine("delete community OldSecret") {
			t.Fatalf("flat IsSensitiveHistoryLine changed; seed-only arm leaked into no-cursor form (#17829)")
		}
	})
}
