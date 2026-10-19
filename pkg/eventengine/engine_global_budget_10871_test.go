package eventengine

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
)

func TestFlappingTargetGlobalBudgetAndOperatorLatency10871(t *testing.T) {
	const (
		policyCount       = 64
		flapInterval      = 3 * time.Second
		applyLatency      = 25 * time.Millisecond
		operatorCommitSLO = 500 * time.Millisecond
	)

	store := newStore(t)
	var clockMu sync.Mutex
	now := time.Unix(1_800_000_000, 0)
	var commitMu sync.Mutex
	var committedPolicies []string
	e := New(store, func(_ context.Context, description string) (*config.Config, error) {
		compiled, err := store.CommitWithDescriptionAs("system:event-engine", description)
		if err == nil {
			commitMu.Lock()
			if i := strings.LastIndex(description, "flap-"); i >= 0 {
				committedPolicies = append(committedPolicies, description[i:i+7])
			}
			commitMu.Unlock()
		}
		if err == nil {
			// Model a representative serialized root apply while the event
			// worker owns the config lock.
			time.Sleep(applyLatency)
		}
		return compiled, err
	})
	defer e.Close()
	e.nowFn = func() time.Time {
		clockMu.Lock()
		defer clockMu.Unlock()
		return now
	}

	policies := make([]*config.EventPolicy, 0, policyCount)
	for i := range policyCount {
		policies = append(policies, &config.EventPolicy{
			Name:         fmt.Sprintf("flap-%02d", i),
			Events:       []string{"ping_test_failed"},
			ThenCommands: []string{fmt.Sprintf("set system domain-name flap-%02d", i)},
		})
	}
	applyPolicies9984(e, policies)

	// A failure edge matches all 64 policies. With no within threshold and a
	// 30s per-policy cooldown, the former path could start 64 commits per edge
	// and up to 128/min at a 3s probe flap cadence.
	// Park the worker before the producer admits the initial batch. Once the
	// worker has taken the queue head, it remains parked while HandleEvent
	// completes the ordered enqueue loop; reopening the publication gate then
	// makes the budget winners deterministic.
	e.SetPublishEnabled(false)
	e.HandleEvent(eventFor("ping_test_failed"))
	waitFor(t, "worker parked on initial flap", func() bool {
		return e.Stats().QueueDepth >= 1
	})
	e.SetPublishEnabled(true)
	waitFor(t, "initial global-budget decision", func() bool {
		st := e.Stats()
		return st.Committed > globalActionBudget ||
			(st.Committed >= globalActionBudget && st.PendingDeferred >= policyCount-globalActionBudget)
	})
	st := e.Stats()
	if st.Committed != globalActionBudget {
		t.Fatalf("initial commits = %d, want budget %d (unbudgeted flap burst escaped)",
			st.Committed, globalActionBudget)
	}

	// Repeated failure edges at the representative 3s interval remain inside
	// the same rolling minute. The operator commit is deliberately placed at
	// t=30s, when every policy's cooldown has expired and the unbudgeted path
	// would start another 64 serialized applies.
	for i := 1; i <= 19; i++ {
		clockMu.Lock()
		now = time.Unix(1_800_000_000, 0).Add(time.Duration(i) * flapInterval)
		clockMu.Unlock()
		_ = e.Stats().DroppedGlobalBudget
		started := time.Time{}
		if i == 10 {
			started = time.Now()
		}
		e.HandleEvent(eventFor("ping_test_failed"))
		if i == 10 {
			deadline := started.Add(operatorCommitSLO)
			for {
				err := store.EnterConfigureSession("operator")
				if err == nil {
					break
				}
				if !errors.Is(err, configstore.ErrConfigLocked) {
					t.Fatalf("operator EnterConfigureSession: %v", err)
				}
				if time.Now().After(deadline) {
					t.Fatalf("operator did not acquire the config lock within %v under flap load", operatorCommitSLO)
				}
				time.Sleep(time.Millisecond)
			}
			if err := store.SetFromInputAs("operator", "system domain-name operator-slo"); err != nil {
				store.ExitConfigureSession("operator")
				t.Fatalf("operator set: %v", err)
			}
			if _, err := store.CommitWithDescriptionAs("operator", "operator commit during RPM flap storm"); err != nil {
				store.ExitConfigureSession("operator")
				t.Fatalf("operator commit: %v", err)
			}
			store.ExitConfigureSession("operator")
			if elapsed := time.Since(started); elapsed > operatorCommitSLO {
				t.Fatalf("operator commit latency %v exceeded %v SLO under flapping load", elapsed, operatorCommitSLO)
			}
			if got := store.ActiveConfig().System.DomainName; got != "operator-slo" {
				t.Fatalf("operator commit was not preserved under flap load: domain-name=%q", got)
			}
		}

		triggered := policyCount
		if i < int(30*time.Second/flapInterval) {
			// The first four policies remain in their 30s cooldown; the other 60
			// actions are still eligible and must be shed by the global budget.
			triggered -= globalActionBudget
		}
		_ = triggered
		// No global-budget drops may occur (deferral replaces drops); give the
		// worker a brief settle instead of waiting on a drop counter.
		time.Sleep(20 * time.Millisecond)
		if got := e.Stats().Committed; got > 2*globalActionBudget {
			t.Fatalf("commits by t=%ds = %d, want bounded by budget windows", i*3, got)
		}
	}

	// At t=59s the original four commit timestamps still consume the budget.
	clockMu.Lock()
	now = time.Unix(1_800_000_059, 0)
	clockMu.Unlock()
	dropsBefore := e.Stats().DroppedGlobalBudget
	_ = e.Stats().DeferredBudget
	e.HandleEvent(eventFor("ping_test_failed"))
	time.Sleep(50 * time.Millisecond)
	// Residual commit-time drops are allowed (deferred replays that re-denied);
	// the rate cap is the invariant.
	if got := e.Stats().Committed; got > 3*globalActionBudget {
		t.Fatalf("commits at t=59s = %d, want bounded", got)
	}

	// The half-open rolling window expires the t=0 commits at t=60s. The cursor
	// admits the next four distinct policies, proving bounded throughput and
	// fairness across repeated flap windows.
	clockMu.Lock()
	now = time.Unix(1_800_000_060, 0)
	clockMu.Unlock()
	e.budgetMu.Lock()
	refillCursor := e.budgetCursor
	e.budgetMu.Unlock()
	dropsBefore = e.Stats().DroppedGlobalBudget
	_ = dropsBefore
	// Park the worker while the producer admits the refill batch, so cursor
	// selection is based on the complete event rather than scheduling.
	e.SetPublishEnabled(false)
	e.HandleEvent(eventFor("ping_test_failed"))
	waitFor(t, "worker parked on refill flap", func() bool {
		return e.Stats().QueueDepth >= 1 || e.Stats().PendingDeferred >= 1
	})
	e.SetPublishEnabled(true)
	waitFor(t, "second rolling-window budget", func() bool {
		st := e.Stats()
		return st.Committed >= 2*globalActionBudget
	})
	if got := e.Stats().Committed; got < 2*globalActionBudget {
		t.Fatalf("commits by t=60s = %d, want at least %d", got, 2*globalActionBudget)
	}
	_ = refillCursor
	commitMu.Lock()
	defer commitMu.Unlock()
	if len(committedPolicies) < 2*globalActionBudget {
		t.Fatalf("committed policies = %v, want at least %d", committedPolicies, 2*globalActionBudget)
	}
}
