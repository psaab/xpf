package eventengine

import (
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/rpm"
)

func TestReadOnlySecondaryDefersActionUntilPromotion10874(t *testing.T) {
	s := newStore(t)
	s.SetClusterReadOnly(true)
	e := New(s, nil)
	defer e.Close()
	e.retryInitial = time.Millisecond
	e.retryMax = time.Millisecond
	e.retryDeadline = 10 * time.Millisecond
	var clock atomic.Int64
	clock.Store(time.Now().UnixNano())
	e.nowFn = func() time.Time { return time.Unix(0, clock.Load()) }
	applyPolicies9984(e, []*config.EventPolicy{{
		Name:         "wan-failover",
		Events:       []string{"ping_test_failed"},
		ThenCommands: []string{"set system host-name remediated"},
	}})

	// This event represents the one fail edge from the standby's probe. If the
	// action is rejected here, a persistently failing probe emits no second edge
	// for the new primary to consume.
	e.HandleEvent(rpm.Event{Name: "ping_test_failed", TestOwner: "WAN", TestName: "test"})
	waitFor(t, "read-only action deferred behind publication gate", func() bool {
		return !e.PublishEnabled() && e.Stats().QueueDepth == 0
	})
	if stats := e.Stats(); stats.Rejected != 0 || stats.Committed != 0 {
		t.Fatalf("read-only action was consumed: stats=%+v", stats)
	}
	if got := s.ActiveConfig().System.HostName; got != "base" {
		t.Fatalf("host-name=%q on secondary, want base", got)
	}

	// Hold the store read-only beyond the normal lock-retry deadline. After
	// promotion, a transient operator lock still gets a fresh retry window.
	clock.Add(int64(time.Second))
	s.SetClusterReadOnly(false)
	if err := s.EnterConfigureSession("operator"); err != nil {
		t.Fatalf("hold config lock after promotion: %v", err)
	}
	defer s.ExitConfigureSession("operator")
	e.SetPublishEnabled(true)
	retryDeadline := time.Now().Add(2 * time.Second)
	for e.Stats().Retried == 0 && e.Stats().DroppedLockHeld == 0 && time.Now().Before(retryDeadline) {
		time.Sleep(time.Millisecond)
	}
	if got := e.Stats(); got.Retried == 0 {
		t.Fatalf("deferred action did not get a fresh lock-retry window: %+v", got)
	}
	s.ExitConfigureSession("operator")
	waitFor(t, "deferred remediation commit after promotion", func() bool {
		return e.Stats().Committed == 1
	})
	if got := s.ActiveConfig().System.HostName; got != "remediated" {
		t.Fatalf("host-name=%q after promotion, want remediated", got)
	}
	if got := e.Stats(); got.Rejected != 0 || got.Committed != 1 {
		t.Fatalf("promotion stats=%+v, want one commit and no rejection", got)
	}
	entries, err := s.ListCommitHistory(1)
	if err != nil {
		t.Fatalf("ListCommitHistory: %v", err)
	}
	if len(entries) != 1 || !strings.Contains(entries[0].Detail, "[local-only; not peer-synced]") {
		t.Fatalf("remediation history detail=%+v, want explicit local-only divergence notation", entries)
	}
}

func TestReadOnlyDemotionDuringCandidateMutationDefersAction10874(t *testing.T) {
	s := newStore(t)
	e := New(s, nil)
	defer e.Close()
	pol := &config.EventPolicy{
		Name:         "wan-failover",
		Events:       []string{"ping_test_failed"},
		ThenCommands: []string{"set system host-name remediated"},
	}
	applyPolicies9984(e, []*config.EventPolicy{pol})
	ops, ok := e.classifyPlan(pol)
	if !ok {
		t.Fatal("classifyPlan rejected test policy")
	}
	a := plannedAction{
		policyName: pol.Name,
		semRev:     policySemanticRevision(pol),
		plantClass: pol.PlantClass,
		event:      "ping_test_failed",
		testOwner:  "WAN",
		testName:   "test",
		ops:        ops,
	}
	if !e.PublishEnabled() {
		t.Fatal("publication gate starts closed")
	}

	// Block applyOnce after EnterConfigure and staleReason's first lock, so
	// the store can become read-only while the candidate is already open.
	e.mu.Lock()
	locked := true
	defer func() {
		if locked {
			e.mu.Unlock()
		}
	}()
	finished := make(chan struct{})
	go func() {
		e.runAction(a)
		close(finished)
	}()
	waitFor(t, "candidate entered configure", func() bool { return s.InConfigMode() })
	s.SetClusterReadOnly(true)
	e.mu.Unlock()
	locked = false

	deadline := time.Now().Add(2 * time.Second)
	for e.PublishEnabled() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if e.PublishEnabled() {
		t.Fatalf("mid-batch ErrClusterReadOnly was not deferred: stats=%+v", e.Stats())
	}
	if stats := e.Stats(); stats.Rejected != 0 || stats.Committed != 0 {
		t.Fatalf("mid-batch read-only action was consumed: stats=%+v", stats)
	}
	if s.InConfigMode() {
		t.Fatal("failed candidate was not discarded")
	}
	if got := s.ActiveConfig().System.HostName; got != "base" {
		t.Fatalf("host-name=%q during deferral, want base", got)
	}

	s.SetClusterReadOnly(false)
	e.SetPublishEnabled(true)
	waitFor(t, "deferred mid-batch remediation commit", func() bool {
		return e.Stats().Committed == 1
	})
	select {
	case <-finished:
	case <-time.After(2 * time.Second):
		t.Fatal("runAction did not finish after promotion")
	}
	if got := s.ActiveConfig().System.HostName; got != "remediated" {
		t.Fatalf("host-name=%q after promotion, want remediated", got)
	}
	if stats := e.Stats(); stats.Rejected != 0 || stats.Committed != 1 {
		t.Fatalf("promotion stats=%+v, want one commit and no rejection", stats)
	}
}
