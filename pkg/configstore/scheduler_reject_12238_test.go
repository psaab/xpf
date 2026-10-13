package configstore

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

const schedulerContradictionText12238 = `schedulers {
    scheduler S { monday { all-day; } }
    scheduler S { monday { start-time 09:00:00; stop-time 17:00:00; } }
}
`

func assertSchedulerUnion12238(t *testing.T, label string, compiled *config.Config) config.SchedulerDayWindow {
	t.Helper()
	scheduler := compiled.Schedulers["S"]
	if scheduler == nil || scheduler.Days["monday"] == nil {
		t.Fatalf("%s: compiled scheduler window is missing: %+v", label, scheduler)
	}
	window := *scheduler.Days["monday"]
	if !window.AllDay || window.Exclude || window.StartTime != "09:00:00" || window.StopTime != "17:00:00" {
		t.Fatalf("%s: window = %+v, want union AllDay plus 09:00:00..17:00:00", label, window)
	}
	return window
}

func assertSchedulerReject12238(t *testing.T, label string, err error) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), `scheduler "S"`) ||
		!strings.Contains(err.Error(), "monday") ||
		(!strings.Contains(err.Error(), "#12238") && !strings.Contains(err.Error(), "#12643")) {
		t.Fatalf("%s strict verdict = %v, want a weekday scheduler contradiction rejection", label, err)
	}
}

func assertSchedulerWarning12238(t *testing.T, label string, warnings []string) {
	t.Helper()
	for _, warning := range warnings {
		if strings.Contains(warning, `scheduler "S"`) && strings.Contains(warning, "monday") &&
			(strings.Contains(warning, "#12238") || strings.Contains(warning, "#12643")) {
			return
		}
	}
	t.Fatalf("%s warnings = %v, want a weekday scheduler contradiction warning naming scheduler S and monday", label, warnings)
}

func TestSchedulerContradictionLoadPathsRejectOrPreserveSameWindow12238(t *testing.T) {
	override := newTestStore(t)
	if err := override.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if err := override.LoadOverrideAs("", schedulerContradictionText12238); err != nil {
		t.Fatalf("LoadOverrideAs: %v", err)
	}
	_, err := override.CommitCheck()
	assertSchedulerReject12238(t, "LoadOverrideAs", err)
	overrideLenient, err := config.CompileConfigLenient(override.candidate)
	if err != nil {
		t.Fatalf("compile override candidate tolerantly: %v", err)
	}
	assertSchedulerWarning12238(t, "LoadOverrideAs tolerant", overrideLenient.Warnings)
	want := assertSchedulerUnion12238(t, "LoadOverrideAs tolerant compile", overrideLenient)

	// Load merge and display-set replay can coalesce Monday into one node.
	// #12643 makes strict acceptance independent of that storage shape.
	merge := newTestStore(t)
	if err := merge.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if err := merge.LoadMergeAs("", schedulerContradictionText12238); err != nil {
		t.Fatalf("LoadMergeAs: %v", err)
	}
	_, err = merge.CommitCheck()
	assertSchedulerReject12238(t, "LoadMergeAs", err)
	mergeLenient, err := config.CompileConfigLenient(merge.candidate)
	if err != nil {
		t.Fatalf("compile merge candidate tolerantly: %v", err)
	}
	assertSchedulerWarning12238(t, "LoadMergeAs tolerant", mergeLenient.Warnings)
	if got := assertSchedulerUnion12238(t, "LoadMergeAs tolerant", mergeLenient); got != want {
		t.Fatalf("LoadMergeAs window %+v differs from LoadOverrideAs tolerant window %+v", got, want)
	}

	set := newTestStore(t)
	if err := set.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	setText := override.ShowCandidateSet()
	if setText == "" {
		t.Fatal("LoadOverrideAs candidate produced empty display set")
	}
	if _, err := set.LoadSetAs("", setText); err != nil {
		t.Fatalf("LoadSetAs(LoadOverrideAs display set): %v", err)
	}
	_, err = set.CommitCheck()
	assertSchedulerReject12238(t, "LoadSetAs", err)
	setLenient, err := config.CompileConfigLenient(set.candidate)
	if err != nil {
		t.Fatalf("compile display-set candidate tolerantly: %v", err)
	}
	assertSchedulerWarning12238(t, "LoadSetAs tolerant", setLenient.Warnings)
	if got := assertSchedulerUnion12238(t, "LoadSetAs tolerant", setLenient); got != want {
		t.Fatalf("LoadSetAs window %+v differs from LoadOverrideAs tolerant window %+v", got, want)
	}
}

func commitSchedulerBase12238(t *testing.T, s *Store, text string) {
	t.Helper()
	if err := s.LoadOverrideAs("", text); err != nil {
		t.Fatalf("LoadOverrideAs(%q): %v", text, err)
	}
	if _, err := s.Commit(); err != nil {
		t.Fatalf("commit base %q: %v", text, err)
	}
}

// Separate Monday statements reach ONE scheduler block through an operator
// `set` or `load merge` on top of a committed `monday all-day;` leaf, or
// through `load override`. Commit check rejects each candidate, and the
// candidate still compiles tolerantly to the union with a #12238 warning.
func TestSchedulerSplitStatementsCommitCheckRejects12238(t *testing.T) {
	const allDayLeaf = `schedulers { scheduler S { monday all-day; } }`
	for _, tc := range []struct {
		name string
		edit func(t *testing.T, s *Store)
	}{
		{name: "W1 set after committed all-day leaf", edit: func(t *testing.T, s *Store) {
			commitSchedulerBase12238(t, s, allDayLeaf)
			for _, command := range []string{
				"schedulers scheduler S monday start-time 09:00:00",
				"schedulers scheduler S monday stop-time 17:00:00",
			} {
				if err := s.SetFromInput(command); err != nil {
					t.Fatalf("SetFromInput(%q): %v", command, err)
				}
			}
		}},
		{name: "W2 load merge after committed all-day leaf", edit: func(t *testing.T, s *Store) {
			commitSchedulerBase12238(t, s, allDayLeaf)
			if err := s.LoadMergeAs("", `schedulers { scheduler S { monday { start-time 09:00:00; stop-time 17:00:00; } } }`); err != nil {
				t.Fatalf("LoadMergeAs: %v", err)
			}
		}},
		{name: "W4 load override with statements in one block", edit: func(t *testing.T, s *Store) {
			if err := s.LoadOverrideAs("", `schedulers { scheduler S { monday all-day; monday { start-time 09:00:00; stop-time 17:00:00; } } }`); err != nil {
				t.Fatalf("LoadOverrideAs: %v", err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestStore(t)
			if err := s.EnterConfigure(); err != nil {
				t.Fatal(err)
			}
			tc.edit(t, s)
			_, err := s.CommitCheck()
			assertSchedulerReject12238(t, "CommitCheck", err)
			_, err = s.Commit()
			assertSchedulerReject12238(t, "Commit", err)
			tolerant, err := config.CompileConfigLenient(s.candidate)
			if err != nil {
				t.Fatalf("compile candidate tolerantly: %v", err)
			}
			assertSchedulerWarning12238(t, "tolerant candidate", tolerant.Warnings)
			assertSchedulerUnion12238(t, "tolerant candidate", tolerant)
		})
	}
}

// A config stored before #12238 can hold split Monday statements. Store.Load
// and SyncApply must still accept it with the #12238 warning and the union
// window (#1960 no-brick); the strict gate then refuses the next commit, even
// an unrelated one, until the statements are combined or removed.
func TestSchedulerSplitStatementsStoredConfigLoadsThenBlocksCommit12238(t *testing.T) {
	tree, errs := config.NewParser(`schedulers {
    scheduler S { monday all-day; monday { start-time 09:00:00; stop-time 17:00:00; } }
}
system { host-name before; }
`).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse stored config: %v", errs)
	}
	path := filepath.Join(t.TempDir(), "config")
	if err := newTestStoreAt(t, path).db.WriteActiveMarker(tree, true); err != nil {
		t.Fatalf("persist stored config: %v", err)
	}
	booted := newTestStoreAt(t, path)
	if err := booted.Load(); err != nil {
		t.Fatalf("Store.Load refused a stored split-statement scheduler: %v", err)
	}
	active := booted.ActiveConfig()
	if active == nil {
		t.Fatal("Store.Load left ActiveConfig() nil")
	}
	assertSchedulerWarning12238(t, "Store.Load", active.Warnings)
	assertSchedulerUnion12238(t, "Store.Load", active)

	synced, err := newTestStore(t).SyncApply(tree.Format(), nil)
	if err != nil {
		t.Fatalf("SyncApply refused a split-statement scheduler: %v", err)
	}
	assertSchedulerWarning12238(t, "SyncApply", synced.Warnings)
	assertSchedulerUnion12238(t, "SyncApply", synced)

	if err := booted.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if err := booted.SetFromInput("system host-name after"); err != nil {
		t.Fatal(err)
	}
	_, err = booted.Commit()
	assertSchedulerReject12238(t, "unrelated commit over the stored contradiction", err)
}

// #12643: strict commit validation rejects weekday all-day plus a complete
// window even when flat set or group inheritance composes both into one node.
func TestSchedulerSingleStatementAllDayWindowCommitCheckRejects12643(t *testing.T) {
	tests := []struct {
		name  string
		apply func(*testing.T, *Store)
	}{
		{
			name: "W3 flat set",
			apply: func(t *testing.T, s *Store) {
				for _, command := range []string{
					"schedulers scheduler S monday all-day",
					"schedulers scheduler S monday start-time 09:00:00",
					"schedulers scheduler S monday stop-time 17:00:00",
				} {
					if err := s.SetFromInput(command); err != nil {
						t.Fatalf("SetFromInput(%q): %v", command, err)
					}
				}
			},
		},
		{
			name: "W5 group-inherited",
			apply: func(t *testing.T, s *Store) {
				text := `groups { g1 { schedulers { scheduler S { monday all-day; } } } }
apply-groups g1;
schedulers { scheduler S { monday { start-time 09:00:00; stop-time 17:00:00; } } }
`
				if err := s.LoadOverrideAs("", text); err != nil {
					t.Fatalf("LoadOverrideAs: %v", err)
				}
			},
		},
		{
			name: "GR6 node0-only group",
			apply: func(t *testing.T, s *Store) {
				text := `groups {
    node0 { schedulers { scheduler S { monday all-day; } } }
    node1 { system { host-name node1; } }
}
apply-groups "${node}";
schedulers { scheduler S { monday { start-time 09:00:00; stop-time 17:00:00; } } }
`
				if err := s.LoadOverrideAs("", text); err != nil {
					t.Fatalf("LoadOverrideAs: %v", err)
				}
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestStore(t)
			if err := s.EnterConfigure(); err != nil {
				t.Fatal(err)
			}
			tc.apply(t, s)
			_, err := s.CommitCheck()
			if err == nil || !strings.Contains(err.Error(), `scheduler "S"`) ||
				!strings.Contains(err.Error(), "monday") || !strings.Contains(err.Error(), "#12643") {
				t.Fatalf("CommitCheck = %v, want a #12643 rejection naming scheduler S and monday", err)
			}
		})
	}
}

func TestSchedulerDailyAllDayWindowCommitCheckRejects12745(t *testing.T) {
	s := newTestStore(t)
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	text := `schedulers {
    scheduler S { daily { all-day; start-time 09:00:00; stop-time 17:00:00; } }
}`
	if err := s.LoadOverrideAs("", text); err != nil {
		t.Fatalf("LoadOverrideAs: %v", err)
	}
	_, err := s.CommitCheck()
	if err == nil || !strings.Contains(err.Error(), `scheduler "S"`) ||
		!strings.Contains(err.Error(), "daily") || !strings.Contains(err.Error(), "#12745") {
		t.Fatalf("CommitCheck = %v, want a #12745 rejection naming scheduler S and daily", err)
	}
}
