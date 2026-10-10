package userspace

import (
	"errors"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestDeferredPublishInBandRefusalNotifiesHA12235(t *testing.T) {
	refusal := newHelperRejection("snapshot integrity preflight rejected")
	f := newDeferredPublishFixture9337(t, refusal)
	f.m.pendingFullSnapshotMetadata = true
	var gotGeneration uint64
	var gotErr error
	f.m.SetPolicySnapshotPublishFailure(func(generation uint64, err error) {
		gotGeneration, gotErr = generation, err
	})
	if err := f.runSync(t); !errors.Is(err, errHelperRejected) {
		t.Fatalf("deferred publish error = %v, want an in-band helper refusal", err)
	}
	if gotGeneration != f.snap.Generation || !errors.Is(gotErr, errHelperRejected) {
		t.Fatalf("HA refusal notification = (%d, %v), want generation %d and helper rejection",
			gotGeneration, gotErr, f.snap.Generation)
	}
}

func TestDeferredFullSnapshotBlocksTakeoverReadiness12235(t *testing.T) {
	snap, err := buildSnapshot(&config.Config{}, config.UserspaceConfig{Workers: 1}, 9, 0)
	if err != nil {
		t.Fatalf("buildSnapshot: %v", err)
	}
	m := healthyTakeoverManager12235(t)
	m.lastSnapshot = snap
	m.publishedSnapshot = 8
	m.pendingFullSnapshotMetadata = true
	if ready, reasons := m.TakeoverReady(); ready || !hasReasonSubstr(reasons, "generation 9 unpublished") {
		t.Fatalf("TakeoverReady() = (%v, %v) before deferred publication; want generation-specific not-ready", ready, reasons)
	}

	m.mu.Lock()
	m.publishedSnapshot = snap.Generation
	m.pendingFullSnapshotMetadata = false
	m.mu.Unlock()
	if ready, reasons := m.TakeoverReady(); !ready {
		t.Fatalf("TakeoverReady() = false after publication: %v", reasons)
	}
}

func healthyTakeoverManager12235(t *testing.T) *Manager {
	t.Helper()
	m := &Manager{
		lastStatus: ProcessStatus{
			Enabled: true, ForwardingArmed: true,
			Capabilities: UserspaceCapabilities{ForwardingSupported: true},
		},
		mode: ModeUserspaceCompat, xskLivenessProven: true,
		eventStream: boundEventStream(t),
	}
	m.proc = selfProc(t)
	return m
}
