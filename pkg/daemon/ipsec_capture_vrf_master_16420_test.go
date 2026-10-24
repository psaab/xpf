package daemon

import (
	"testing"

	"github.com/vishvananda/netlink"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/logging"
	"github.com/psaab/xpf/pkg/nfqueue"
	"github.com/psaab/xpf/pkg/routing"
)

// #16420: the VRF master for the IPsec NFQUEUE divert was sampled at
// stageIpsecCapture, before the same apply enslaved a freshly created st0
// into its routing-instance VRF. First deploy and every reboot installed
// the iifname-only rule that never matches enslaved traffic, and the
// divert chain is policy ACCEPT so uncaptured packets continued on the
// kernel path.
//
// Fix: (1) applyInterfaceReconcile binds RI members right after ApplyXfrmi,
// before the stage; (2) buildIpsecCaptureQueuePlan resolves the master
// from the CONFIGURED routing-instance member (live master must agree),
// so even a not-yet-enslaved tunnel renders iifname=vrf-X + sdifname;
// (3) the topology census refuses OPEN when a live master differs from
// the installed divert's Master.

// masterApplyingOps16420 is bindRecorderOps plus kernel-faithful master
// application and ifindex assignment, so the stage sees the enslaved link
// exactly as a real kernel would present it after the bind.
type masterApplyingOps16420 struct {
	*bindRecorderOps
	nextIndex int
}

func (o *masterApplyingOps16420) LinkAdd(l netlink.Link) error {
	if err := o.bindRecorderOps.LinkAdd(l); err != nil {
		return err
	}
	if l.Attrs().Index == 0 {
		o.nextIndex++
		l.Attrs().Index = 100 + o.nextIndex
	}
	// Re-store: reconcileFakeLinkOps.LinkAdd keys by name at call time.
	o.links[l.Attrs().Name] = l
	return nil
}

func (o *masterApplyingOps16420) LinkSetMaster(link, master netlink.Link) error {
	if err := o.bindRecorderOps.LinkSetMaster(link, master); err != nil {
		return err
	}
	link.Attrs().MasterIndex = master.Attrs().Index
	return nil
}

func vrfCaptureCfg16420() *config.Config {
	cfg := &config.Config{}
	cfg.RoutingInstances = []*config.RoutingInstanceConfig{{
		Name: "blue", InstanceType: "vrf", TableID: 100,
		Interfaces: []string{"st0.0"},
	}}
	cfg.Security.IPsec.VPNs = map[string]*config.IPsecVPN{
		"vpn-a": {Name: "vpn-a", BindInterface: "st0.0"},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"vpn": {Interfaces: []string{"st0.0"}},
	}
	return cfg
}

func stubCaptureLinks16420(t *testing.T, ops *masterApplyingOps16420) {
	t.Helper()
	origLink, origFence := ipsecCaptureLinkByName, ipsecFenceLinkByIndex
	origOpen, origNew := ipsecCaptureOpenQueue, ipsecCaptureNewPipeline
	t.Cleanup(func() {
		ipsecCaptureLinkByName, ipsecFenceLinkByIndex = origLink, origFence
		ipsecCaptureOpenQueue, ipsecCaptureNewPipeline = origOpen, origNew
	})
	ipsecCaptureLinkByName = func(name string) (netlink.Link, error) {
		if l, ok := ops.links[name]; ok {
			return l, nil
		}
		return nil, netlink.LinkNotFoundError{}
	}
	ipsecFenceLinkByIndex = func(index int) (netlink.Link, error) {
		for _, l := range ops.links {
			if l.Attrs().Index == index {
				return l, nil
			}
		}
		return nil, netlink.LinkNotFoundError{}
	}
	ipsecCaptureOpenQueue = func(_ uint16, _ ipsecQueueFamily) (*nfqueue.Queue, error) {
		return nil, nil
	}
	ipsecCaptureNewPipeline = func(cfg IpsecCapturePipelineConfig) (*IpsecCapturePipeline, error) {
		cfg.Queues = nil
		return NewIpsecCapturePipeline(cfg)
	}
}

// TestApplyCreatesXfrmiThenStagesVRFDivert16420 is the acceptance cell:
// the apply creates the xfrmi (absent at step 0a, as on first deploy /
// every reboot) and ends with an `iifname vrf-blue sdifname st0.0` divert.
//
// FAIL-ON-REVERT: drop the bindRoutingInstanceMembers call from
// applyInterfaceReconcile AND the config-authoritative master resolution,
// and the staged spec renders Master=="" (iifname-only).
func TestApplyCreatesXfrmiThenStagesVRFDivert16420(t *testing.T) {
	ops := &masterApplyingOps16420{bindRecorderOps: &bindRecorderOps{reconcileFakeLinkOps: newReconcileFakeLinkOps()}}
	ops.links["vrf-blue"] = &netlink.Vrf{LinkAttrs: netlink.LinkAttrs{Name: "vrf-blue", Index: 22}}
	d := &Daemon{routing: routing.NewManagerWithLinkOpsForTest(ops), eventBuf: logging.NewEventBuffer(8)}
	cfg := vrfCaptureCfg16420()
	stubCaptureLinks16420(t, ops)

	// The xfrmi does not exist yet (first deploy / reboot shape).
	if err := d.applyInterfaceReconcile(cfg); err != nil {
		t.Fatalf("applyInterfaceReconcile: %v", err)
	}
	link, ok := ops.links["st0.0"]
	if !ok {
		t.Fatalf("xfrmi st0.0 was not created; links=%v", ops.links)
	}
	if link.Attrs().MasterIndex != 22 {
		t.Fatalf("st0.0 MasterIndex = %d after interface reconcile, want 22 (vrf-blue); binds=%v",
			link.Attrs().MasterIndex, ops.recorded())
	}

	_, staged, err := d.stageIpsecCapture(cfg)
	if err != nil {
		t.Fatalf("stageIpsecCapture: %v", err)
	}
	if staged == nil {
		t.Fatal("stage returned no runtime")
	}
	defer staged.close()
	if staged.spec.QuarantineAll {
		t.Fatalf("staged spec quarantined: %+v", staged.spec)
	}
	assertDivertMaster16420(t, staged)
}

func assertDivertMaster16420(t *testing.T, staged *ipsecCaptureRuntime) {
	t.Helper()
	classes := map[string][]string{}
	for _, r := range staged.spec.InetForward {
		classes["inet-forward"] = append(classes["inet-forward"], r.Ifname+"/"+r.Master)
	}
	for _, r := range staged.spec.InetInput {
		classes["inet-input"] = append(classes["inet-input"], r.Ifname+"/"+r.Master)
	}
	for _, r := range staged.spec.BridgeForward {
		classes["bridge-forward"] = append(classes["bridge-forward"], r.Ifname+"/"+r.Master)
	}
	for _, r := range staged.spec.BridgeInput {
		classes["bridge-input"] = append(classes["bridge-input"], r.Ifname+"/"+r.Master)
	}
	// Ifname is the xfrmi device name XFRMIfNameAndID derives from the
	// bind (st0.0 here); the renderer emits iifname=<Master> +
	// sdifname=<Ifname> for enslaved tunnels.
	for name, got := range classes {
		if len(got) != 1 || got[0] != "st0.0/vrf-blue" {
			t.Fatalf("%s divert = %v, want [st0.0/vrf-blue] (iifname vrf-blue sdifname st0.0)", name, got)
		}
	}
	for _, h := range staged.handles {
		if h.Key.Master != "vrf-blue" {
			t.Fatalf("handle key %+v Master = %q, want vrf-blue", h.Key, h.Key.Master)
		}
	}
}

// TestQueuePlanUsesConfiguredMasterBeforeEnslavement16420 pins the
// config-authoritative half: even when the live link is not yet enslaved
// (MasterIndex 0), a tunnel listed in exactly one RI renders its VRF.
func TestQueuePlanUsesConfiguredMasterBeforeEnslavement16420(t *testing.T) {
	origLink, origFence := ipsecCaptureLinkByName, ipsecFenceLinkByIndex
	t.Cleanup(func() { ipsecCaptureLinkByName, ipsecFenceLinkByIndex = origLink, origFence })
	ipsecCaptureLinkByName = func(name string) (netlink.Link, error) {
		return &netlink.Xfrmi{LinkAttrs: netlink.LinkAttrs{Name: name, Index: 11, MasterIndex: 0}}, nil
	}
	ipsecFenceLinkByIndex = func(index int) (netlink.Link, error) {
		return &netlink.Vrf{LinkAttrs: netlink.LinkAttrs{Name: "vrf-blue", Index: index}}, nil
	}
	plan, err := buildIpsecCaptureQueuePlan(vrfCaptureCfg16420(), 5)
	if err != nil {
		t.Fatalf("queue plan: %v", err)
	}
	if plan.Quarantine.QuarantineAll {
		t.Fatalf("configured-but-unenslaved tunnel quarantined: %+v", plan.Quarantine)
	}
	if len(plan.Keys) != 4 {
		t.Fatalf("keys = %d, want 4", len(plan.Keys))
	}
	for _, k := range plan.Keys {
		if k.Master != "vrf-blue" {
			t.Fatalf("key %+v Master = %q, want vrf-blue from configured RI member", k, k.Master)
		}
	}
}

// TestQueuePlanRejectsLiveMasterMismatch16420: live enslavement to a
// DIFFERENT VRF than the configured member must fail closed, never render
// a divert for the wrong master.
func TestQueuePlanRejectsLiveMasterMismatch16420(t *testing.T) {
	origLink, origFence := ipsecCaptureLinkByName, ipsecFenceLinkByIndex
	t.Cleanup(func() { ipsecCaptureLinkByName, ipsecFenceLinkByIndex = origLink, origFence })
	ipsecCaptureLinkByName = func(name string) (netlink.Link, error) {
		return &netlink.Xfrmi{LinkAttrs: netlink.LinkAttrs{Name: name, Index: 11, MasterIndex: 99}}, nil
	}
	ipsecFenceLinkByIndex = func(index int) (netlink.Link, error) {
		return &netlink.Vrf{LinkAttrs: netlink.LinkAttrs{Name: "vrf-red", Index: index}}, nil
	}
	plan, err := buildIpsecCaptureQueuePlan(vrfCaptureCfg16420(), 5)
	if err != nil {
		t.Fatalf("queue plan: %v", err)
	}
	if !plan.Quarantine.QuarantineAll || len(plan.Keys) != 0 {
		t.Fatalf("mismatched-master plan = keys %d quarantine %v, want quarantine with no keys",
			len(plan.Keys), plan.Quarantine.QuarantineAll)
	}
}

// TestCensusRefusesOpenOnStaleDivertMaster16420: the topology census must
// not mark SAFE (and must not OPEN) when the live VRF master differs from
// the installed divert's Master — the out-of-band / stale-install shape.
func TestCensusRefusesOpenOnStaleDivertMaster16420(t *testing.T) {
	vrf, xfrmi, outlet := vrfTopologyLinks15067()
	stubTopology15067(t, []netlink.Link{xfrmi, vrf, outlet}, map[int]netlink.Link{22: vrf})

	mkRuntime := func(master string) *ipsecCaptureRuntime {
		handles := vrfHandles14974()
		for i := range handles {
			handles[i].Key.Master = master
		}
		return &ipsecCaptureRuntime{handles: handles}
	}

	// Stale iifname-only installed divert (Master="") + enslaved live link.
	d := &Daemon{ipsecS4: newIpsecSupervisor(), ipsecCapture: mkRuntime("")}
	d.ipsecTopologySubscribed.Store(true)
	d.pollIpsecTopology()
	snap := d.ipsecS4.watch.Load()
	if snap == nil || snap.Ready != ipsecReadyUnsafe {
		t.Fatalf("stale-divert census ready = %v, want UNSAFE", snapshotReady(snap))
	}
	if permit := d.ipsecS4.loadPermit(); permit != nil && d.ipsecS4.tryOpenPermit(permit, snap.closeKey(), snap.Generation) {
		t.Fatal("permit OPENed on a stale iifname-only divert (#16420)")
	}

	// Control: installed divert matches the live master -> SAFE + OPEN.
	d2 := &Daemon{ipsecS4: newIpsecSupervisor(), ipsecCapture: mkRuntime("vrf-blue")}
	d2.ipsecTopologySubscribed.Store(true)
	d2.pollIpsecTopology()
	snap2 := d2.ipsecS4.watch.Load()
	if snap2 == nil || snap2.Ready != ipsecReadySafe {
		t.Fatalf("matching-divert census ready = %v, want SAFE", snapshotReady(snap2))
	}
	permit := d2.ipsecS4.loadPermit()
	if permit == nil || !d2.ipsecS4.tryOpenPermit(permit, snap2.closeKey(), snap2.Generation) {
		t.Fatal("permit did not OPEN on matching divert (control)")
	}
	if got := d2.ipsecS4.loadPermit(); got == nil || got.state != ipsecPermitOpen {
		t.Fatalf("permit state = %v, want OPEN (control)", got.state)
	}
}
