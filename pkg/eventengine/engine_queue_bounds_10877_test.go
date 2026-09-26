package eventengine

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

func TestThenCommandsBoundAndCriticalPath10877(t *testing.T) {
	e := New(nil, nil)
	defer e.Close()

	atLimit := &config.EventPolicy{Name: "at-limit"}
	for i := range maxThenCommands {
		atLimit.ThenCommands = append(atLimit.ThenCommands, fmt.Sprintf("set system host-name limit-%d", i))
	}
	if ops, ok := e.classifyPlan(atLimit); !ok || len(ops) != maxThenCommands {
		t.Fatalf("classifyPlan accepted %d of %d commands at the limit: ok=%v ops=%d",
			len(atLimit.ThenCommands), maxThenCommands, ok, len(ops))
	}

	for _, tc := range []struct {
		command string
		want    bool
	}{
		{command: "set system host-name ordinary", want: false},
		{command: "set security zones security-zone trust description quarantine", want: true},
		{command: "delete firewall family inet filter quarantine", want: true},
	} {
		ops, ok := e.classifyPlan(&config.EventPolicy{Name: "priority", ThenCommands: []string{tc.command}})
		if !ok || len(ops) != 1 || ops[0].critical != tc.want {
			t.Fatalf("classifyPlan(%q) = (%d ops, ok=%v, critical=%v), want one op with critical=%v",
				tc.command, len(ops), ok, len(ops) == 1 && ops[0].critical, tc.want)
		}
	}

	tooMany := &config.EventPolicy{
		Name:   "too-many",
		Events: []string{"too-many-event"},
	}
	for i := range maxThenCommands + 1 {
		tooMany.ThenCommands = append(tooMany.ThenCommands, fmt.Sprintf("set system host-name over-limit-%d", i))
	}
	applyPolicies9984(e, []*config.EventPolicy{tooMany})
	e.HandleEvent(eventFor("too-many-event"))
	if got := e.Stats().Rejected; got != 1 {
		t.Fatalf("oversized batch rejection count = %d, want 1", got)
	}
	if got := e.Stats().QueueDepth; got != 0 {
		t.Fatalf("oversized batch occupied %d queue slots, want 0", got)
	}
}

func TestCriticalActionDisplacesNewestOrdinary10877(t *testing.T) {
	e := New(nil, nil)
	defer e.Close()

	victim := fmt.Sprintf("ordinary-%02d", actionQueueDepth-1)
	e.mu.Lock()
	e.semRev[victim] = "revision"
	e.runtime[victim] = &policyRuntime{onLatched: map[string]bool{"ordinary-event": true}}
	e.mu.Unlock()

	for i := range actionQueueDepth {
		name := fmt.Sprintf("ordinary-%02d", i)
		if !e.enqueue(plannedAction{
			policyName: name,
			semRev:     "revision",
			event:      "ordinary-event",
		}) {
			t.Fatalf("ordinary action %q was not admitted", name)
		}
	}
	if got := e.Stats().QueueDepth; got != actionQueueDepth {
		t.Fatalf("queue depth before critical arrival = %d, want %d", got, actionQueueDepth)
	}

	if !e.enqueue(plannedAction{policyName: "critical", ops: []plannedOp{{critical: true}}}) {
		t.Fatal("critical action was rejected from a full queue of ordinary actions")
	}
	if got := e.Stats().QueueDepth; got != actionQueueDepth {
		t.Fatalf("queue depth after priority displacement = %d, want %d", got, actionQueueDepth)
	}
	if got := e.Stats().DroppedQueueFull; got != 1 {
		t.Fatalf("queue-full count = %d, want one displaced ordinary action", got)
	}

	for i := range actionQueueDepth {
		a := <-e.actions
		e.counters.queueDepth.Add(-1)
		if i == 0 {
			if a.policyName != "critical" {
				t.Fatalf("first queued action = %q, want critical", a.policyName)
			}
			continue
		}
		want := fmt.Sprintf("ordinary-%02d", i-1)
		if a.policyName != want {
			t.Fatalf("queue[%d] = %q, want %q (ordinary FIFO must survive displacement)", i, a.policyName, want)
		}
	}
	if got := e.Stats().QueueDepth; got != 0 {
		t.Fatalf("queue depth after draining = %d, want 0", got)
	}

	e.mu.Lock()
	latched := e.runtime[victim].onLatched["ordinary-event"]
	e.mu.Unlock()
	if latched {
		t.Fatal("displaced ordinary action retained its edge latch and cannot retry")
	}
}

func TestCriticalPolicyLatencyUnder64PolicyFlap10877(t *testing.T) {
	store := newStore(t)
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure seed zone: %v", err)
	}
	if err := store.SetFromInput("security zones security-zone trust"); err != nil {
		t.Fatalf("seed security zone: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("commit security zone: %v", err)
	}
	store.ExitConfigure()

	firstEntered := make(chan struct{})
	releaseFirst := make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseFirst) }) }
	criticalCommitted := make(chan struct{}, 1)
	var commitsMu sync.Mutex
	var commits []string
	commitFn := func(ctx context.Context, comment string) (*config.Config, error) {
		commitsMu.Lock()
		commits = append(commits, comment)
		commitsMu.Unlock()
		if strings.HasPrefix(comment, "event-options policy flap-00:") {
			close(firstEntered)
			select {
			case <-releaseFirst:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		compiled, err := store.Commit()
		if err == nil && strings.HasPrefix(comment, "event-options policy security-quarantine:") {
			criticalCommitted <- struct{}{}
		}
		return compiled, err
	}

	e := New(store, commitFn)
	defer e.Close()
	defer release()
	policies := make([]*config.EventPolicy, 0, actionQueueDepth+1)
	for i := range actionQueueDepth {
		event := fmt.Sprintf("flap-%02d", i)
		policies = append(policies, &config.EventPolicy{
			Name:         event,
			Events:       []string{event},
			ThenCommands: []string{fmt.Sprintf("set system host-name %s", event)},
		})
	}
	policies = append(policies, &config.EventPolicy{
		Name:         "security-quarantine",
		Events:       []string{"security-quarantine"},
		ThenCommands: []string{"set security zones security-zone trust description quarantined"},
	})
	applyPolicies9984(e, policies)

	e.HandleEvent(eventFor("flap-00"))
	select {
	case <-firstEntered:
	case <-time.After(5 * time.Second):
		t.Fatal("first remediation did not reach the held commit callback")
	}
	for i := 1; i < actionQueueDepth; i++ {
		e.HandleEvent(eventFor(fmt.Sprintf("flap-%02d", i)))
	}
	if got := e.Stats().QueueDepth; got != actionQueueDepth-1 {
		t.Fatalf("ordinary flap queue depth = %d, want %d behind the in-flight action", got, actionQueueDepth-1)
	}

	started := time.Now()
	e.HandleEvent(eventFor("security-quarantine"))
	if got := e.Stats().QueueDepth; got != actionQueueDepth {
		t.Fatalf("queue depth after critical policy = %d, want %d", got, actionQueueDepth)
	}
	release()
	select {
	case <-criticalCommitted:
	case <-time.After(5 * time.Second):
		t.Fatalf("critical remediation missed 5s SLO with %d ordinary policies queued", actionQueueDepth-1)
	}
	if elapsed := time.Since(started); elapsed > 5*time.Second {
		t.Fatalf("critical remediation latency = %v, exceeds 5s SLO", elapsed)
	}
	commitsMu.Lock()
	defer commitsMu.Unlock()
	if len(commits) < 2 || !strings.HasPrefix(commits[0], "event-options policy flap-00:") ||
		!strings.HasPrefix(commits[1], "event-options policy security-quarantine:") {
		t.Fatalf("critical policy was not next after the in-flight action: first commits = %q", commits[:min(len(commits), 3)])
	}
}
