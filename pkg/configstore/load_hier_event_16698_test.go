package configstore

import (
	"strings"
	"testing"
)

// #16698: `show configuration > file` followed by `load override` /
// `load merge` of the box's own output failed for any config holding a
// hierarchically authored unquoted event-options command: Format prints
// `set system host-name pwned;` bare at line start inside `commands { }`,
// ClassifyLoadContent routed the whole body to flat replay, and flat
// replay rejected line 1 (`system {` / `event-options {`).

const hierEventSeed16698 = `event-options {
    policy p {
        events ping_test_failed;
        then {
            change-configuration {
                commands {
                    set system host-name pwned;
                }
            }
        }
    }
}
system {
    host-name before16698;
}
`

func seedStore16698(t *testing.T) *Store {
	t.Helper()
	s := newTestStore(t)
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := s.LoadOverride(hierEventSeed16698); err != nil {
		t.Fatalf("seed LoadOverride: %v", err)
	}
	return s
}

func TestShowLoadRoundTripEventCmd16698(t *testing.T) {
	src := seedStore16698(t)
	shown := src.ShowCandidate()
	// PREMISE: the box really does render the unquoted command bare at
	// line start. Without this the cells below cannot measure the defect.
	if !strings.Contains(shown, "set system host-name pwned;") {
		t.Fatalf("premise failed: ShowCandidate does not render the bare event "+
			"command; the round-trip cells would be vacuous:\n%s", shown)
	}

	t.Run("override", func(t *testing.T) {
		dst := newTestStore(t)
		if err := dst.EnterConfigure(); err != nil {
			t.Fatalf("EnterConfigure: %v", err)
		}
		if err := dst.LoadOverride(shown); err != nil {
			t.Fatalf("LoadOverride of own ShowCandidate output failed: %v\n%s", err, shown)
		}
		if got := dst.ShowCandidate(); got != shown {
			t.Errorf("override round-trip changed the configuration:\n--- shown ---\n%s\n--- reloaded ---\n%s", shown, got)
		}
	})

	t.Run("merge", func(t *testing.T) {
		dst := newTestStore(t)
		if err := dst.EnterConfigure(); err != nil {
			t.Fatalf("EnterConfigure: %v", err)
		}
		if err := dst.LoadMerge(shown); err != nil {
			t.Fatalf("LoadMerge of own ShowCandidate output failed: %v\n%s", err, shown)
		}
		// Merge lowers through FormatSet, whose rendering of a
		// single-key `events` leaf differs textually from Format's
		// (`events { ping_test_failed; }` vs `events ping_test_failed;`).
		// The acceptance is that the merge SUCCEEDS and carries the same
		// leaves — above all the bare event command — not byte identity.
		got := dst.ShowCandidate()
		for _, want := range []string{
			"set system host-name pwned;",
			"host-name before16698;",
			"ping_test_failed",
		} {
			if !strings.Contains(got, want) {
				t.Errorf("merge round-trip lost %q:\n%s", want, got)
			}
		}
		// And the merged candidate itself must reload cleanly.
		dst2 := newTestStore(t)
		if err := dst2.EnterConfigure(); err != nil {
			t.Fatalf("EnterConfigure2: %v", err)
		}
		if err := dst2.LoadOverride(got); err != nil {
			t.Fatalf("reloaded merged candidate failed override: %v\n%s", err, got)
		}
	})
}

// Control: the quoted twin already round-tripped before the fix and must
// keep doing so.
func TestShowLoadRoundTripEventCmdQuoted16698(t *testing.T) {
	quoted := strings.Replace(hierEventSeed16698,
		"commands {\n                    set system host-name pwned;\n                }",
		`commands "set system host-name pwned";`, 1)
	if quoted == hierEventSeed16698 {
		t.Fatal("quoted fixture construction failed")
	}
	s := newTestStore(t)
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := s.LoadOverride(quoted); err != nil {
		t.Fatalf("quoted LoadOverride: %v", err)
	}
	shown := s.ShowCandidate()
	dst := newTestStore(t)
	if err := dst.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := dst.LoadOverride(shown); err != nil {
		t.Fatalf("quoted round-trip LoadOverride: %v\n%s", err, shown)
	}
}
