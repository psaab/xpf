package eventengine

import (
	"context"
	"errors"
	"fmt"
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
	e := New(store, func(_ context.Context, description string) (*config.Config, error) {
		compiled, err := store.CommitWithDescriptionAs("system:event-engine", description)
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
	e.HandleEvent(eventFor("ping_test_failed"))
	waitFor(t, "initial global-budget decision", func() bool {
		st := e.Stats()
		return st.Committed > globalActionBudget ||
			st.DroppedGlobalBudget >= policyCount-globalActionBudget
	})
	st := e.Stats()
	if st.Committed != globalActionBudget {
		t.Fatalf("initial commits = %d, want budget %d (unbudgeted flap burst escaped)",
			st.Committed, globalActionBudget)
	}
	if st.DroppedGlobalBudget < policyCount-globalActionBudget {
		t.Fatalf("global-budget drops = %d, want at least %d",
			st.DroppedGlobalBudget, policyCount-globalActionBudget)
	}

	// Repeated failure edges at the representative 3s interval remain inside
	// the same rolling minute. The operator commit is deliberately placed at
	// t=30s, when every policy's cooldown has expired and the unbudgeted path
	// would start another 64 serialized applies.
	for i := 1; i <= 19; i++ {
		clockMu.Lock()
		now = time.Unix(1_800_000_000, 0).Add(time.Duration(i) * flapInterval)
		clockMu.Unlock()
		dropsBefore := e.Stats().DroppedGlobalBudget
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
		wantDrops := dropsBefore + uint64(triggered)
		waitFor(t, fmt.Sprintf("t=%ds flap actions shed", i*3), func() bool {
			st := e.Stats()
			return st.DroppedGlobalBudget >= wantDrops && st.QueueDepth == 0
		})
		if got := e.Stats().Committed; got != globalActionBudget {
			t.Fatalf("commits by t=%ds = %d, want at most %d per rolling minute",
				i*3, got, globalActionBudget)
		}
	}

	// At t=59s the original four commit timestamps still consume the budget.
	clockMu.Lock()
	now = time.Unix(1_800_000_059, 0)
	clockMu.Unlock()
	dropsBefore := e.Stats().DroppedGlobalBudget
	e.HandleEvent(eventFor("ping_test_failed"))
	waitFor(t, "t=59s action drops", func() bool {
		return e.Stats().DroppedGlobalBudget >= dropsBefore+policyCount && e.Stats().QueueDepth == 0
	})
	if got := e.Stats().Committed; got != globalActionBudget {
		t.Fatalf("commits at t=59s = %d, want %d", got, globalActionBudget)
	}

	// The half-open rolling window expires the t=0 commits at t=60s. The cursor
	// admits the next four distinct policies, proving bounded throughput and
	// fairness across repeated flap windows.
	clockMu.Lock()
	now = time.Unix(1_800_000_060, 0)
	clockMu.Unlock()
	dropsBefore = e.Stats().DroppedGlobalBudget
	e.HandleEvent(eventFor("ping_test_failed"))
	waitFor(t, "second rolling-window budget", func() bool {
		st := e.Stats()
		return st.Committed >= 2*globalActionBudget &&
			st.DroppedGlobalBudget >= dropsBefore+policyCount-globalActionBudget &&
			st.QueueDepth == 0
	})
	if got := e.Stats().Committed; got != 2*globalActionBudget {
		t.Fatalf("commits by t=60s = %d, want exactly %d (four per rolling minute)",
			got, 2*globalActionBudget)
	}
	if got := store.ActiveConfig().System.DomainName; got != "flap-07" {
		t.Fatalf("second budget refill committed through %q, want next policies ending at flap-07",
			got)
	}
}
