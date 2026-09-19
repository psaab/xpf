package daemon

import (
	"errors"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/nfqueue"
	xnft "github.com/psaab/xpf/pkg/nftables"
)

func wiringHandles9506() []ipsecQueueHandle {
	classes := []struct {
		family ipsecQueueFamily
		hook   ipsecQueueHook
		number uint16
	}{
		{ipsecFamilyInet, ipsecHookForward, 1001},
		{ipsecFamilyInet, ipsecHookInput, 1002},
		{ipsecFamilyBridge, ipsecHookForward, 1003},
		{ipsecFamilyBridge, ipsecHookInput, 1004},
	}
	handles := make([]ipsecQueueHandle, 0, len(classes))
	for _, class := range classes {
		handles = append(handles, ipsecQueueHandle{
			Number: class.number,
			Epoch:  9,
			Key: ipsecQueueKey{
				Generation: 4,
				Family:     class.family,
				Hook:       class.hook,
				Owner:      "vpn-a",
				STN:        "st1.0",
				Ifindex:    17,
			},
		})
	}
	return handles
}

func TestIpsecCaptureWiringBuildsFourClassSpecAndOrigins9506(t *testing.T) {
	handles := wiringHandles9506()
	spec, err := ipsecCaptureDivertSpec(handles)
	if err != nil {
		t.Fatalf("divert spec: %v", err)
	}
	if len(spec.InetForward) != 1 || len(spec.InetInput) != 1 || len(spec.BridgeForward) != 1 || len(spec.BridgeInput) != 1 {
		t.Fatalf("four-class spec = %+v", spec)
	}
	registry := new(nfqueue.OriginRegistry)
	if err := ipsecCaptureRegisterOrigins(registry, handles); err != nil {
		t.Fatalf("register origins: %v", err)
	}
	origin, ok := registry.Lookup(1004)
	if !ok || origin.Family != nfqueue.CaptureFamilyBridge || origin.Hook != nfqueue.CaptureHookInput || origin.Owner != "vpn-a" || origin.STN != "st1.0" || origin.OwnedIfindex != 17 {
		t.Fatalf("bridge input origin = %+v/%v", origin, ok)
	}
	if _, err := ipsecCaptureDivertSpec(handles[:3]); err == nil {
		t.Fatal("incomplete four-class generation was accepted")
	}
}

func TestIpsecCaptureRuntimeAnnounceSnapshotPreservesClosingEpoch9506(t *testing.T) {
	supervisor := newIpsecSupervisor()
	supervisor.permit.Store(&permitRecord{state: ipsecPermitOpen, permitEpoch: 17})
	runtime := &ipsecCaptureRuntime{supervisor: supervisor, handles: wiringHandles9506()}
	epoch, open, rows := runtime.authoritySnapshot()
	if epoch != 17 || !open || len(rows) != 4 {
		t.Fatalf("open authority=(%d,%v,%+v), want epoch 17/open/4 rows", epoch, open, rows)
	}
	supervisor.permit.Store(&permitRecord{state: ipsecPermitClosing, permitEpoch: 17})
	epoch, open, rows = runtime.authoritySnapshot()
	if epoch != 17 || open || len(rows) != 4 {
		t.Fatalf("closing authority=(%d,%v,%+v), want epoch 17/closed/4 rows", epoch, open, rows)
	}
	snapshotEpoch, snapshotRows := runtime.epochSnapshot()
	if snapshotEpoch != 0 || snapshotRows != nil {
		t.Fatalf("closed compile snapshot=(%d,%+v), want zero/nil", snapshotEpoch, snapshotRows)
	}
}

func TestRestoreIpsecCaptureRuntimeInvalidatesAuthorityAnnouncement9506(t *testing.T) {
	runtime := &ipsecCaptureRuntime{
		announced:       true,
		announcedPermit: 17,
		announcedOpen:   true,
		announcedRows:   []nfqueue.ReinjectQueueEpoch{{Queue: 1001, Epoch: 9}},
	}
	d := new(Daemon)
	d.restoreIpsecCaptureRuntime(runtime)
	runtime.authorityMu.Lock()
	announced := runtime.announced
	runtime.authorityMu.Unlock()
	if announced {
		t.Fatal("restored runtime retained stale authority announcement")
	}
	if d.ipsecCapture != runtime || d.ipsecCaptureStaged != nil || d.ipsecCaptureStagePending {
		t.Fatalf("restored daemon state = active=%p staged=%p pending=%v", d.ipsecCapture, d.ipsecCaptureStaged, d.ipsecCaptureStagePending)
	}
}

type fakeIpsecReinjectSubmitter9506 struct {
	announces int
}

func (f *fakeIpsecReinjectSubmitter9506) SubmitAdjudicated([]nfqueue.AdjudicatedFrame) ([]nfqueue.ReinjectAdmission, error) {
	return nil, nil
}

func (f *fakeIpsecReinjectSubmitter9506) DrainReinjectCompletions(uint32) ([]nfqueue.ReinjectCompletion, error) {
	return nil, nil
}

func (f *fakeIpsecReinjectSubmitter9506) CancelReinject([]uint64, uint64, []nfqueue.ReinjectQueueScope) ([]uint64, error) {
	return nil, nil
}

func (f *fakeIpsecReinjectSubmitter9506) AnnounceReinject(uint64, bool, []nfqueue.ReinjectQueueEpoch) error {
	f.announces++
	return nil
}

func (f *fakeIpsecReinjectSubmitter9506) Close() error {
	return nil
}

func TestReconcileIpsecCaptureRejectsStaleSampleAfterRestore9506(t *testing.T) {
	supervisor := newIpsecSupervisor()
	supervisor.permit.Store(&permitRecord{state: ipsecPermitOpen, permitEpoch: 17})
	submitter := new(fakeIpsecReinjectSubmitter9506)
	runtime := &ipsecCaptureRuntime{
		supervisor: supervisor,
		handles:    wiringHandles9506(),
		submitter:  submitter,
		announced:  true,
	}
	d := new(Daemon)
	d.ipsecCapture = runtime
	d.ipsecCaptureAuthorityRevision.Store(1)
	sampled := make(chan struct{})
	resume := make(chan struct{})
	reconcileDone := make(chan error, 1)
	go func() {
		reconcileDone <- d.reconcileIpsecCaptureAuthorityWithHook(func() {
			close(sampled)
			<-resume
		})
	}()
	<-sampled
	d.restoreIpsecCaptureRuntime(runtime)
	close(resume)
	if err := <-reconcileDone; err != nil {
		t.Fatal(err)
	}
	runtime.authorityMu.Lock()
	announced := runtime.announced
	runtime.authorityMu.Unlock()
	if announced {
		t.Fatal("stale reconcile re-announced restored authority")
	}
	if submitter.announces != 0 {
		t.Fatalf("stale reconcile sent %d authority announcements", submitter.announces)
	}
}

func TestIpsecCapturePublicationSerializesOverlappingTransitions9506(t *testing.T) {
	oldRuntime := &ipsecCaptureRuntime{}
	newRuntime := &ipsecCaptureRuntime{}
	d := &Daemon{ipsecCapture: oldRuntime}
	done := make(chan struct{}, 2)
	go func() {
		for range 256 {
			d.publishIpsecCaptureCommitted(newRuntime)
			d.restoreIpsecCaptureRuntime(oldRuntime)
		}
		done <- struct{}{}
	}()
	go func() {
		for range 256 {
			d.restoreIpsecCaptureRuntime(newRuntime)
			d.publishIpsecCaptureCommitted(oldRuntime)
		}
		done <- struct{}{}
	}()
	timeout := time.NewTimer(2 * time.Second)
	defer timeout.Stop()
	for range 2 {
		select {
		case <-done:
		case <-timeout.C:
			t.Fatal("overlapping capture publications deadlocked")
		}
	}
	d.ipsecCaptureMu.Lock()
	current := d.ipsecCapture
	revision := d.ipsecCaptureAuthorityRevision.Load()
	d.ipsecCaptureMu.Unlock()
	if current != oldRuntime && current != newRuntime {
		t.Fatalf("final capture runtime=%p, want one of %p/%p", current, oldRuntime, newRuntime)
	}
	if revision < 512 {
		t.Fatalf("publication revision=%d, want at least 512", revision)
	}
}

func stagedIpsecCaptureRuntime9506(t *testing.T) *ipsecCaptureRuntime {
	t.Helper()
	actor, err := NewIpsecCapturePipeline(IpsecCapturePipelineConfig{
		Supervisor: newIpsecSupervisor(),
		Registry:   new(nfqueue.OriginRegistry),
		Pipeline:   nfqueue.CapturePipelineConfig{Phase: nfqueue.PipelineQuarantine},
	})
	if err != nil {
		t.Fatalf("NewIpsecCapturePipeline: %v", err)
	}
	return &ipsecCaptureRuntime{actor: actor}
}

func TestCommitIpsecCaptureStageRemoveFailureUsesNftInstaller9506(t *testing.T) {
	orig := nftInstaller
	t.Cleanup(func() { nftInstaller = orig })
	fake := &fakeNftInstaller{
		divertRemove: func() error { return errors.New("remove failed") },
	}
	nftInstaller = fake
	old := &ipsecCaptureRuntime{}
	d := &Daemon{ipsecCapture: old, ipsecCaptureStagePending: true}
	if err := d.commitIpsecCaptureStage(old, nil); err == nil {
		t.Fatal("remove failure was swallowed")
	}
	if len(fake.divertCalls) != 1 || fake.divertCalls[0] != "remove" {
		t.Fatalf("divert calls=%v, want one remove", fake.divertCalls)
	}
	if d.ipsecCapture != old || d.ipsecCaptureStagePending {
		t.Fatalf("daemon state after remove failure = active=%p pending=%v", d.ipsecCapture, d.ipsecCaptureStagePending)
	}
}

func TestCommitIpsecCaptureStageInstallFailureUsesNftInstaller9506(t *testing.T) {
	orig := nftInstaller
	t.Cleanup(func() { nftInstaller = orig })
	fake := &fakeNftInstaller{
		divertInstall: func(xnft.IpsecDivertSpec) error { return errors.New("install failed") },
	}
	nftInstaller = fake
	staged := stagedIpsecCaptureRuntime9506(t)
	d := &Daemon{ipsecCaptureStaged: staged, ipsecCaptureStagePending: true}
	if err := d.commitIpsecCaptureStage(nil, staged); err == nil {
		t.Fatal("install failure was swallowed")
	}
	if len(fake.divertCalls) != 1 || fake.divertCalls[0] != "install" {
		t.Fatalf("divert calls=%v, want one install", fake.divertCalls)
	}
	if d.ipsecCapture != nil || d.ipsecCaptureStaged != nil || d.ipsecCaptureStagePending {
		t.Fatalf("daemon state after install failure = active=%p staged=%p pending=%v", d.ipsecCapture, d.ipsecCaptureStaged, d.ipsecCaptureStagePending)
	}
}

func TestCommitIpsecCaptureStageActorStartFailureRestoresDivert9506(t *testing.T) {
	orig := nftInstaller
	t.Cleanup(func() { nftInstaller = orig })
	fake := new(fakeNftInstaller)
	nftInstaller = fake
	staged := stagedIpsecCaptureRuntime9506(t)
	if err := staged.actor.Start(); err != nil {
		t.Fatalf("pre-start actor: %v", err)
	}
	d := &Daemon{ipsecCaptureStaged: staged, ipsecCaptureStagePending: true}
	if err := d.commitIpsecCaptureStage(nil, staged); err == nil {
		t.Fatal("actor start failure was swallowed")
	}
	if len(fake.divertCalls) != 2 || fake.divertCalls[0] != "install" || fake.divertCalls[1] != "remove" {
		t.Fatalf("divert calls=%v, want install then remove", fake.divertCalls)
	}
	if d.ipsecCapture != nil || d.ipsecCaptureStaged != nil || d.ipsecCaptureStagePending {
		t.Fatalf("daemon state after actor failure = active=%p staged=%p pending=%v", d.ipsecCapture, d.ipsecCaptureStaged, d.ipsecCaptureStagePending)
	}
}
