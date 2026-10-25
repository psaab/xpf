// #5848: the daemon's commit path pre-flighted the candidate (device-map
// management-lockout gate) and promoted it in two separately-locked store ops,
// so a concurrent REST/CLI candidate edit could slip a different candidate into
// the promotion. commitWithGenBinding binds the examined candidate generation to
// the promoted one: a concurrent edit is a bounded-retry conflict that re-runs
// the pre-flight on the new generation, never a silent substitution.
//
// FAIL-ON-REVERT: the load-bearing guard is the store's generation check
// (pkg/configstore, TestCommit*Gen*). These daemon tests exercise the retry loop
// that consumes it end-to-end.
package daemon

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
)

// A candidate edit landing DURING the pre-flight window bumps the generation, so
// the first commit conflicts; the helper retries, re-runs the pre-flight on the
// new generation, and promotes exactly the RE-examined candidate. Examined ==
// promoted.
func TestCommitWithGenBindingRepreflightsOnConcurrentEdit(t *testing.T) {
	s := newCommitReadyStore(t, "system host-name base", "system host-name staged1")
	d := &Daemon{store: s}

	var examined []string
	attempt := 0
	oldActive, compiled, err := d.commitWithGenBinding(
		0,
		func(cand *config.Config) error {
			examined = append(examined, cand.System.HostName)
			if attempt == 0 {
				// Simulate a concurrent REST edit arriving during the FIRST
				// pre-flight (candidate mutation does not take applySem). This
				// advances the generation, so the first commit must conflict.
				if err := s.SetFromInput("system host-name staged2"); err != nil {
					t.Fatalf("concurrent edit: %v", err)
				}
			}
			attempt++
			return nil
		},
		func(gen uint64) (*config.Config, error) { return s.CommitWithDescriptionGen("", gen) },
	)
	if err != nil {
		t.Fatalf("commitWithGenBinding: %v", err)
	}
	if len(examined) != 2 {
		t.Fatalf("expected 2 pre-flights (conflict + retry), got %d: %v", len(examined), examined)
	}
	if examined[0] != "staged1" || examined[1] != "staged2" {
		t.Fatalf("pre-flight examined the wrong candidates: %v (want [staged1 staged2])", examined)
	}
	// The promoted config must be the one the WINNING attempt pre-flighted.
	if compiled == nil || compiled.System.HostName != "staged2" {
		t.Fatalf("promoted compiled is not the re-examined candidate: %+v", compiled)
	}
	if active := s.ShowActiveSet(); !strings.Contains(active, "host-name staged2") {
		t.Fatalf("active is not the re-examined candidate; active=%q", active)
	}
	if oldActive == nil || oldActive.System.HostName != "base" {
		t.Fatalf("oldActive not captured as the pre-commit active (base); got %+v", oldActive)
	}
}

// A candidate that keeps changing under every attempt surfaces the conflict
// after the bounded retries instead of spinning forever — the REST/gRPC caller
// then retries the whole commit.
func TestCommitWithGenBindingSurfacesPersistentConflict(t *testing.T) {
	s := newCommitReadyStore(t, "system host-name base", "system host-name s1")
	d := &Daemon{store: s}

	preflights := 0
	_, _, err := d.commitWithGenBinding(
		0,
		func(cand *config.Config) error {
			preflights++
			// Always edit the candidate → the examined generation is always
			// stale by commit time.
			return s.SetFromInput(fmt.Sprintf("system host-name h%d", preflights))
		},
		func(gen uint64) (*config.Config, error) { return s.CommitWithDescriptionGen("", gen) },
	)
	if !errors.Is(err, configstore.ErrCandidateGenerationConflict) {
		t.Fatalf("persistent conflict: err=%v, want ErrCandidateGenerationConflict", err)
	}
	if preflights != maxCommitPreflightRetries+1 {
		t.Fatalf("expected %d pre-flight attempts, got %d", maxCommitPreflightRetries+1, preflights)
	}
	// Nothing was promoted: active stays at the committed baseline.
	if active := s.ShowActiveSet(); !strings.Contains(active, "host-name base") {
		t.Fatalf("active mutated by a conflicting commit; active=%q", active)
	}
}

// The no-race common path: pre-flight runs once, the generation is unchanged,
// the candidate is promoted exactly as before #5848.
func TestCommitWithGenBindingNoRaceCommitsOnce(t *testing.T) {
	s := newCommitReadyStore(t, "system host-name base", "system host-name staged")
	d := &Daemon{store: s}

	preflights := 0
	_, compiled, err := d.commitWithGenBinding(
		0,
		func(cand *config.Config) error { preflights++; return nil },
		func(gen uint64) (*config.Config, error) { return s.CommitWithDescriptionGen("", gen) },
	)
	if err != nil {
		t.Fatalf("commitWithGenBinding: %v", err)
	}
	if preflights != 1 {
		t.Fatalf("no-race commit ran %d pre-flights, want 1", preflights)
	}
	if compiled == nil || compiled.System.HostName != "staged" {
		t.Fatalf("promoted the wrong candidate: %+v", compiled)
	}
}
