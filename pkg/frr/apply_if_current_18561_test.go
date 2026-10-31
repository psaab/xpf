package frr

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// #18561: ApplyFullIfCurrent writes and reloads only while its predicate
// holds; a superseded render touches neither frr.conf nor FRR.
func TestApplyFullIfCurrentSkipsSupersededRender18561(t *testing.T) {
	rec := &RecordingExecutor{}
	conf := filepath.Join(t.TempDir(), "frr.conf")
	m := NewForTest(conf, rec)
	fc := &FullConfig{ClusterMode: true}

	err := m.ApplyFullIfCurrent(fc, func() bool { return false })
	if !errors.Is(err, ErrFRRApplySuperseded) {
		t.Fatalf("superseded apply returned %v, want ErrFRRApplySuperseded", err)
	}
	if rec.ReloadCalls != 0 {
		t.Fatal("a superseded render reloaded FRR")
	}
	if _, statErr := os.Stat(conf); !os.IsNotExist(statErr) {
		t.Fatalf("a superseded render wrote frr.conf (stat err %v)", statErr)
	}
	if err := m.ApplyFullIfCurrent(&FullConfig{}, func() bool { return false }); !errors.Is(err, ErrFRRApplySuperseded) {
		t.Fatalf("superseded clear returned %v, want ErrFRRApplySuperseded", err)
	}

	if err := m.ApplyFullIfCurrent(fc, func() bool { return true }); err != nil {
		t.Fatalf("current apply: %v", err)
	}
	if rec.ReloadCalls != 1 {
		t.Fatalf("reload calls = %d after a current apply, want 1", rec.ReloadCalls)
	}
}

func quarantiningConfig18561() *FullConfig {
	big := oversizedPolicy6807("BIG")
	big.Terms[0].FromProtocols = []string{"static"}
	big.DefaultAction = ""
	return &FullConfig{
		PolicyOptions: &config.PolicyOptionsConfig{
			PolicyStatements: map[string]*config.PolicyStatement{"BIG": big},
			PrefixLists:      map[string]*config.PrefixList{},
			Communities:      map[string]*config.CommunityDef{},
			ASPaths:          map[string]*config.ASPathDef{},
		},
		BGP: &config.BGPConfig{
			LocalAS: 65001, RouterID: "1.1.1.1",
			Neighbors: []*config.BGPNeighbor{
				{Address: "10.0.2.1", PeerAS: 65002, FamilyInet: true, Import: []string{"BIG"}},
			},
		},
	}
}

// A superseded render must not touch the build state: the quarantine gauge
// keeps describing the section that is actually applied. RED if the
// predicate is judged only after the build.
func TestSupersededRenderLeavesGaugesAlone18561(t *testing.T) {
	m := NewForTest(filepath.Join(t.TempDir(), "frr.conf"), &RecordingExecutor{})
	if err := m.ApplyFull(&FullConfig{ClusterMode: true}); err != nil {
		t.Fatalf("premise apply: %v", err)
	}
	if got := m.QuarantinedRouteMaps(); len(got) != 0 {
		t.Fatalf("premise: no quarantine after a healthy apply, got %v", got)
	}
	err := m.ApplyFullIfCurrent(quarantiningConfig18561(), func() bool { return false })
	if !errors.Is(err, ErrFRRApplySuperseded) {
		t.Fatalf("superseded apply returned %v", err)
	}
	if got := m.QuarantinedRouteMaps(); len(got) != 0 {
		t.Fatalf("a superseded render that was never written changed the quarantine gauge to %v", got)
	}
	// Control: the same config applied for real does quarantine.
	if err := m.ApplyFullIfCurrent(quarantiningConfig18561(), func() bool { return true }); err != nil {
		t.Fatalf("current apply: %v", err)
	}
	if got := m.QuarantinedRouteMaps(); len(got) == 0 {
		t.Fatal("premise: the oversized policy quarantines when applied")
	}
}

// Concurrent applies must not interleave builds (run under -race: before
// buildMu, ApplyFull and ApplyFullIfCurrent raced on resetQuarantined and the
// #16625 RIP group index). Each apply's written section must also be one
// coherent render.
func TestConcurrentAppliesSerializeBuilds18561(t *testing.T) {
	m := NewForTest(filepath.Join(t.TempDir(), "frr.conf"), &RecordingExecutor{})
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			_ = m.ApplyFull(quarantiningConfig18561())
		}()
		go func() {
			defer wg.Done()
			_ = m.ApplyFullIfCurrent(&FullConfig{ClusterMode: true}, func() bool { return true })
		}()
	}
	wg.Wait()
}

// The predicate is judged again under reloadMu, immediately before the
// write: a render overtaken while it was being built is still skipped.
// RED if only the pre-build check remains.
func TestPredicateRecheckedBeforeWrite18561(t *testing.T) {
	rec := &RecordingExecutor{}
	conf := filepath.Join(t.TempDir(), "frr.conf")
	m := NewForTest(conf, rec)
	calls := 0
	err := m.ApplyFullIfCurrent(&FullConfig{ClusterMode: true}, func() bool {
		calls++
		return calls == 1 // current before the build, overtaken during it
	})
	if !errors.Is(err, ErrFRRApplySuperseded) {
		t.Fatalf("overtaken apply returned %v, want ErrFRRApplySuperseded", err)
	}
	if rec.ReloadCalls != 0 {
		t.Fatal("a render overtaken during its build was written and reloaded")
	}
	if _, statErr := os.Stat(conf); !os.IsNotExist(statErr) {
		t.Fatal("a render overtaken during its build wrote frr.conf")
	}
}

type blockingReloadFRR18561 struct {
	*RecordingExecutor
	entered chan struct{}
	release chan struct{}
}

func (b *blockingReloadFRR18561) FrrReloadPy(ctx context.Context, conf string) error {
	close(b.entered)
	<-b.release
	return b.RecordingExecutor.FrrReloadPy(ctx, conf)
}

// BuildBarrier waits out an apply that is already writing: factory reset
// raises its flag, passes the barrier, and only then strips frr.conf, so an
// HA write that predates the flag cannot land after the strip. RED if the
// barrier does not take buildMu.
func TestBuildBarrierWaitsForInFlightApply18561(t *testing.T) {
	blk := &blockingReloadFRR18561{RecordingExecutor: &RecordingExecutor{}, entered: make(chan struct{}), release: make(chan struct{})}
	m := NewForTest(filepath.Join(t.TempDir(), "frr.conf"), blk)
	go func() { _ = m.ApplyFullIfCurrent(&FullConfig{ClusterMode: true}, func() bool { return true }) }()
	<-blk.entered
	passed := make(chan struct{})
	go func() { m.BuildBarrier(); close(passed) }()
	select {
	case <-passed:
		close(blk.release)
		t.Fatal("BuildBarrier returned while an apply was still writing")
	case <-time.After(100 * time.Millisecond):
	}
	close(blk.release)
	select {
	case <-passed:
	case <-time.After(5 * time.Second):
		t.Fatal("BuildBarrier never returned after the apply finished")
	}
}
