package configstore

// #16156: the three shared config-lifecycle helpers. ConfirmOnly is the
// pure confirm-only predicate (confirm-pending && candidate unchanged),
// ClassifyCommitError is the structural REST–gRPC commit-error
// classifier, and WarningsOf is the warnings extraction. There is no
// configops.Service and no authority-minting CommitGate: these helpers
// never mint authority, so the local CLI's authority-free commit path
// is untouched.
//
// FAIL-ON-REVERT: revert ConfirmOnly to `confirmTimer == nil || dirty`
// (or drop the dirty conjunct) and the dirty/pending cells RED;
// revert ClassifyCommitError's precedence (compiled check first) and
// the context-beats-config cells RED; return cfg.Warnings directly
// from WarningsOf and the defensive-copy cell REDS.

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// armConfirmWindow16156 commits a base config, then a commit-confirmed
// config, leaving a pending confirm window with a clean candidate.
func armConfirmWindow16156(t *testing.T, s *Store) {
	t.Helper()
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if err := s.SetFromInput("system host-name Base16156"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := s.SetFromInput("system host-name Confirmed16156"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CommitConfirmed(1); err != nil {
		t.Fatal(err)
	}
	if !s.IsConfirmPending() || s.IsDirty() {
		t.Fatal("premise: want pending window with clean candidate")
	}
}

func TestConfirmOnly16156(t *testing.T) {
	// No window, clean candidate: a bare commit is a normal commit.
	t.Run("NoWindowClean", func(t *testing.T) {
		s := newTestStore(t)
		if s.ConfirmOnly() {
			t.Fatal("ConfirmOnly = true with no confirm window, want false")
		}
	})

	// Window pending, candidate unchanged: pure confirmation.
	t.Run("PendingClean", func(t *testing.T) {
		s := newTestStore(t)
		armConfirmWindow16156(t, s)
		if !s.ConfirmOnly() {
			t.Fatal("ConfirmOnly = false with pending window and clean candidate, want true")
		}
	})

	// Window pending, new edits staged: must fall through to a normal
	// commit (#4000 — confirm-only here would silently drop the edits).
	t.Run("PendingDirty", func(t *testing.T) {
		s := newTestStore(t)
		armConfirmWindow16156(t, s)
		if err := s.SetFromInput("system host-name Edited16156"); err != nil {
			t.Fatal(err)
		}
		if !s.IsDirty() {
			t.Fatal("premise: candidate must be dirty after staging an edit")
		}
		if s.ConfirmOnly() {
			t.Fatal("ConfirmOnly = true with pending window and dirty candidate, want false")
		}
	})

	// No window, dirty candidate: normal commit.
	t.Run("NoWindowDirty", func(t *testing.T) {
		s := newTestStore(t)
		if err := s.EnterConfigure(); err != nil {
			t.Fatal(err)
		}
		if err := s.SetFromInput("system host-name Dirty16156"); err != nil {
			t.Fatal(err)
		}
		if s.ConfirmOnly() {
			t.Fatal("ConfirmOnly = true with no window and dirty candidate, want false")
		}
	})
}

func TestClassifyCommitError16156(t *testing.T) {
	nonNil := &config.Config{Warnings: []string{"tail warning"}}
	tailErr := errors.New("networkd write failed: transient control-socket hiccup")
	rejectErr := errors.New("schema validation rejected: unknown zone reference")

	cases := []struct {
		name     string
		compiled *config.Config
		err      error
		want     CommitErrorClass
	}{
		{"tail_reconcile_nonfatal", nonNil, tailErr, CommitErrCommittedTail},
		{"schema_reject", nil, rejectErr, CommitErrRejected},
		{"context_canceled", nil, fmt.Errorf("commit aborted: %w", context.Canceled), CommitErrCanceled},
		{"context_canceled_beats_config", nonNil, fmt.Errorf("commit aborted: %w", context.Canceled), CommitErrCanceled},
		{"context_deadline", nil, fmt.Errorf("commit slow: %w", context.DeadlineExceeded), CommitErrDeadlineExceeded},
		{"context_deadline_beats_config", nonNil, fmt.Errorf("commit slow: %w", context.DeadlineExceeded), CommitErrDeadlineExceeded},
		// Fail-safe: an unclassifiable error with no committed config is a
		// reject, never retryable/committed.
		{"unknown_nil_config", nil, errors.New("boom"), CommitErrRejected},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ClassifyCommitError(tc.compiled, tc.err); got != tc.want {
				t.Fatalf("ClassifyCommitError = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestWarningsOf16156(t *testing.T) {
	if got := WarningsOf(nil); got != nil {
		t.Fatalf("WarningsOf(nil) = %v, want nil", got)
	}
	if got := WarningsOf(&config.Config{}); got != nil {
		t.Fatalf("WarningsOf(empty) = %v, want nil", got)
	}
	cfg := &config.Config{Warnings: []string{"w1", "w2"}}
	got := WarningsOf(cfg)
	if len(got) != 2 || got[0] != "w1" || got[1] != "w2" {
		t.Fatalf("WarningsOf = %v, want [w1 w2]", got)
	}
	// Defensive copy: mutating the result must not write through to the
	// compiled config the dataplane retains.
	got[0] = "mutated"
	if cfg.Warnings[0] != "w1" {
		t.Fatalf("WarningsOf returned the live slice: cfg.Warnings = %v", cfg.Warnings)
	}
}
