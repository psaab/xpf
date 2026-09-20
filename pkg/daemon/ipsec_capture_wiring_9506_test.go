package daemon

import (
	"errors"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/nfqueue"
	xnft "github.com/psaab/xpf/pkg/nftables"
	"github.com/vishvananda/netlink"
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
func TestIpsecCaptureEmptyGenerationDefaultsToQuarantine9506(t *testing.T) {
	spec, err := ipsecCaptureDivertSpec(nil)
	if err != nil {
		t.Fatalf("empty generation: %v", err)
	}
	if !spec.QuarantineAll {
		t.Fatalf("empty generation spec = %+v, want QuarantineAll", spec)
	}
}

func TestIpsecCaptureQueuePlanKeepsValidKeysAndQuarantinesSkips9506(t *testing.T) {
	orig := ipsecCaptureLinkByName
	t.Cleanup(func() { ipsecCaptureLinkByName = orig })
	ipsecCaptureLinkByName = func(name string) (netlink.Link, error) {
		if name == "st2.0" {
			return &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: name, Index: 41}}, nil
		}
		return nil, errors.New("missing link")
	}
	cfg := &config.Config{}
	cfg.Security.IPsec.VPNs = map[string]*config.IPsecVPN{
		"bad-bind":  {BindInterface: "not-an-xfrmi"},
		"good":      {BindInterface: "st2.0"},
		"good-copy": {BindInterface: "st2.0"},
	}
	plan, err := buildIpsecCaptureQueuePlan(cfg, 7)
	if err != nil {
		t.Fatalf("queue plan: %v", err)
	}
	if len(plan.Keys) != 8 {
		t.Fatalf("valid queue key count = %d, want eight classes for two claimants", len(plan.Keys))
	}
	for _, key := range plan.Keys {
		if (key.Owner != "good" && key.Owner != "good-copy") || key.Ifindex != 41 || key.Generation != 7 {
			t.Fatalf("queue key = %+v, want good claimants/ifindex=41/generation=7", key)
		}
	}
	if !plan.Quarantine.QuarantineAll ||
		plan.Quarantine.QuarantineReasonMask&xnft.IpsecQuarantineMaskIFIDUnderivable == 0 ||
		plan.Quarantine.QuarantineReasonMask&xnft.IpsecQuarantineMaskOwnerContested == 0 {
		t.Fatalf("skip quarantine = %+v, want IFID_UNDERIVABLE+OWNER_CONTESTED", plan.Quarantine)
	}
	if len(plan.Quarantine.CandidateIfindices) != 1 || plan.Quarantine.CandidateIfindices[0] != 41 {
		t.Fatalf("candidate ifindices = %v, want [41]", plan.Quarantine.CandidateIfindices)
	}
	keys, err := ipsecCaptureQueueKeys(cfg, 7)
	if err != nil || len(keys) != 8 {
		t.Fatalf("queue key wrapper = %d/%v, want eight/nil", len(keys), err)
	}
}
func TestBuildPMechZoneSnapshotMarksDuplicateBindsAmbiguous9506(t *testing.T) {
	bindA, ifIDA := config.XFRMIfNameAndID("st1")
	bindB, ifIDB := config.XFRMIfNameAndID("st1.0")
	if bindA == bindB || ifIDA == 0 || ifIDA != ifIDB {
		t.Fatalf("collision premise broken: st1=(%q,%d) st1.0=(%q,%d)", bindA, ifIDA, bindB, ifIDB)
	}
	cfg := &config.Config{}
	cfg.Security.IPsec.VPNs = map[string]*config.IPsecVPN{
		"vpn-a": {BindInterface: "st1"},
		"vpn-b": {BindInterface: "st1.0"},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"zone-a": {Interfaces: []string{"st1.0"}},
	}
	snapshot := buildPMechZoneSnapshot(cfg, wiringHandles9506(), 4, 4)
	for _, stn := range []string{"st1", "st1.0"} {
		resolution := snapshot.ResolveSTN(stn)
		if resolution.Reason != nfqueue.ZoneReasonAmbiguous || resolution.ZoneID != 0 {
			t.Fatalf("distinct duplicate bind %q resolution=%+v, want ambiguous/zone=0", stn, resolution)
		}
	}
}
func TestIpsecCaptureStagePassesStagedQueuesToActor9506(t *testing.T) {
	origLink := ipsecCaptureLinkByName
	origOpen := ipsecCaptureOpenQueue
	origNew := ipsecCaptureNewPipeline
	t.Cleanup(func() {
		ipsecCaptureLinkByName = origLink
		ipsecCaptureOpenQueue = origOpen
		ipsecCaptureNewPipeline = origNew
	})
	ipsecCaptureLinkByName = func(name string) (netlink.Link, error) {
		return &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: name, Index: 41}}, nil
	}
	ipsecCaptureOpenQueue = func(_ uint16, _ ipsecQueueFamily) (*nfqueue.Queue, error) {
		return nil, nil
	}
	var captured IpsecCapturePipelineConfig
	ipsecCaptureNewPipeline = func(cfg IpsecCapturePipelineConfig) (*IpsecCapturePipeline, error) {
		captured = cfg
		// Queue objects are deliberately nil in this hermetic constructor seam;
		// the stage/runtime handoff is what this test observes.
		cfg.Queues = nil
		return NewIpsecCapturePipeline(cfg)
	}
	cfg := &config.Config{}
	cfg.Security.IPsec.VPNs = map[string]*config.IPsecVPN{
		"vpn": {BindInterface: "st1.0"},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"zone": {Interfaces: []string{"st1.0"}},
	}
	daemon := &Daemon{}
	old, staged, err := daemon.stageIpsecCapture(cfg)
	if err != nil {
		t.Fatalf("stage capture: %v", err)
	}
	if old != nil || staged == nil || staged.actor == nil {
		t.Fatalf("stage result old=%p staged=%+v", old, staged)
	}
	if len(captured.Queues) != 4 || len(staged.queues) != len(captured.Queues) {
		t.Fatalf("captured staged queues=%d runtime queues=%d, want four", len(captured.Queues), len(staged.queues))
	}
	if len(captured.QueueEpochs) != len(captured.Queues) {
		t.Fatalf("captured queue epochs=%d queues=%d, want one epoch per queue", len(captured.QueueEpochs), len(captured.Queues))
	}
	for _, captureQueue := range captured.Queues {
		if captureQueue.Queue != nil {
			t.Fatal("hermetic queue opener unexpectedly returned a live queue")
		}
		if captured.QueueEpochs[captureQueue.QueueNumber] != captureQueue.QueueEpoch {
			t.Fatalf("queue %d epoch=%d not carried in actor config: %+v", captureQueue.QueueNumber, captureQueue.QueueEpoch, captured.QueueEpochs)
		}
	}
	if staged.actor.Status().Active {
		t.Fatal("staged actor active before explicit start")
	}
	if err := staged.close(); err != nil {
		t.Fatalf("first staged close: %v", err)
	}
	if err := staged.close(); err != nil {
		t.Fatalf("second staged close: %v", err)
	}
}

func TestIpsecCaptureStageInvalidVPNPublishesQuarantine9506(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.IPsec.VPNs = map[string]*config.IPsecVPN{
		"invalid": {BindInterface: "not-an-xfrmi"},
	}
	d := &Daemon{}
	old, staged, err := d.stageIpsecCapture(cfg)
	if err != nil {
		t.Fatalf("stage invalid VPN: %v", err)
	}
	if old != nil || staged == nil || !staged.spec.QuarantineAll || staged.actor != nil {
		t.Fatalf("stage result old=%p staged=%+v", old, staged)
	}
	if !d.ipsecCaptureStagePending {
		t.Fatal("quarantine stage was not marked pending")
	}
	_ = staged.close()
}

func TestIpsecCaptureUnknownQueueKeyDenies9506(t *testing.T) {
	handles := wiringHandles9506()
	handles[0].Key.Family = ipsecQueueFamily(0xff)
	spec, err := ipsecCaptureDivertSpec(handles)
	if err != nil {
		t.Fatalf("unknown queue key returned an error instead of quarantine: %v", err)
	}
	if !spec.QuarantineAll || spec.QuarantineRawReason == xnft.IpsecQuarantineReasonUnknown {
		t.Fatalf("unknown queue key spec = %+v, want preserved raw reason and quarantine", spec)
	}
}

func TestIpsecCaptureRawQuarantineMaskDenies9506(t *testing.T) {
	handles := wiringHandles9506()
	rawMask := xnft.IpsecQuarantineReasonMask(1 << 29)
	spec, err := ipsecCaptureDivertSpecWithQuarantine(handles, xnft.IpsecDivertSpec{
		QuarantineRawMask: rawMask,
	})
	if err != nil {
		t.Fatalf("raw quarantine mask returned an error: %v", err)
	}
	if !spec.QuarantineAll || spec.QuarantineRawMask != rawMask {
		t.Fatalf("raw quarantine mask spec = %+v, want quarantine with raw mask 0x%x", spec, rawMask)
	}
}

func TestIpsecCaptureRuntimeAnnounceSnapshotPreservesClosingEpoch9506(t *testing.T) {
	supervisor := newIpsecSupervisor()
	supervisor.permit.Store(&permitRecord{state: ipsecPermitOpen, permitEpoch: 17})
	runtime := &ipsecCaptureRuntime{supervisor: supervisor, handles: wiringHandles9506(), runID: "test-run"}
	runID, generation, epoch, open, rows := runtime.authoritySnapshot()
	if runID != "test-run" || generation != 4 || epoch != 17 || !open || len(rows) != 4 {
		t.Fatalf("open authority=(%q,%d,%d,%v,%+v), want test-run/4/17/open/4 rows", runID, generation, epoch, open, rows)
	}
	supervisor.permit.Store(&permitRecord{state: ipsecPermitClosing, permitEpoch: 17})
	runID, generation, epoch, open, rows = runtime.authoritySnapshot()
	if runID != "test-run" || generation != 4 || epoch != 17 || open || len(rows) != 4 {
		t.Fatalf("closing authority=(%q,%d,%d,%v,%+v), want test-run/4/17/closed/4 rows", runID, generation, epoch, open, rows)
	}
	snapshotEpoch, snapshotRows := runtime.epochSnapshot()
	if snapshotEpoch != 0 || snapshotRows != nil {
		t.Fatalf("closed compile snapshot=(%d,%+v), want zero/nil", snapshotEpoch, snapshotRows)
	}
}
func TestIpsecCaptureRuntimeJoinKeyUsesWiredGeneration9506(t *testing.T) {
	supervisor := newIpsecSupervisor()
	supervisor.permit.Store(&permitRecord{state: ipsecPermitOpen, permitEpoch: 17})
	handles := wiringHandles9506()
	actor := &IpsecCapturePipeline{
		supervisor: supervisor,
		queues:     []IpsecCaptureQueue{{Generation: handles[0].Key.Generation}},
		rotation:   newIpsecRotation(),
		runID:      "test-run",
	}
	runtime := &ipsecCaptureRuntime{
		supervisor: supervisor,
		handles:    handles,
		actor:      actor,
		runID:      "test-run",
	}
	runID, generation, epoch, open, _ := runtime.authoritySnapshot()
	if runID != "test-run" || generation != handles[0].Key.Generation || epoch != 17 || !open {
		t.Fatalf("join key=(%q,%d,%d,%v), want test-run/%d/17/open", runID, generation, epoch, open, handles[0].Key.Generation)
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

func (f *fakeIpsecReinjectSubmitter9506) AnnounceReinject(string, uint64, uint64, bool, []nfqueue.ReinjectQueueEpoch) error {
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
	if len(fake.divertCalls) != 2 || fake.divertCalls[0] != "install" || fake.divertCalls[1] != "install" {
		t.Fatalf("divert calls=%v, want install then deny-only install", fake.divertCalls)
	}
	if d.ipsecCapture != nil || d.ipsecCaptureStaged != nil || d.ipsecCaptureStagePending {
		t.Fatalf("daemon state after actor failure = active=%p staged=%p pending=%v", d.ipsecCapture, d.ipsecCaptureStaged, d.ipsecCaptureStagePending)
	}
}
