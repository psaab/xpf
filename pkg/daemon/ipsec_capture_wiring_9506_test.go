package daemon

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	"github.com/psaab/xpf/pkg/logging"
	"github.com/psaab/xpf/pkg/nfqueue"
	xnft "github.com/psaab/xpf/pkg/nftables"
	"github.com/vishvananda/netlink"
	"golang.org/x/sync/semaphore"
)


func TestDaemonD11ArmGateFrozenAtConstruction10484(t *testing.T) {
	const envName = "XPF_ATTEST_10484_ARM"
	old, hadOld := os.LookupEnv(envName)
	t.Cleanup(func() {
		if hadOld {
			_ = os.Setenv(envName, old)
		} else {
			_ = os.Unsetenv(envName)
		}
	})
	_ = os.Unsetenv(envName)
	d, err := New(Options{
		ConfigFile:  filepath.Join(t.TempDir(), "xpf.conf"),
		NoDataplane: true,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_ = os.Setenv(envName, "1")
	err = d.d11Armer.Arm(
		"attest-0123456789abcdef0123456789abcdef",
		9,
		"00112233445566778899aabbccddeeff",
	)
	if err == nil || !strings.Contains(err.Error(), "environment is disabled") {
		t.Fatalf("Arm after daemon construction = %v, want cached environment-disabled error", err)
	}
}

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

func TestPMechSnapshotAdvancesAcceptedAuthorityWithoutCaptureRotation10485(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.IPsec.VPNs = map[string]*config.IPsecVPN{
		"vpn-a": {BindInterface: "st1.0"},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"zone": {Interfaces: []string{"st1.0"}},
	}
	snapshot := buildPMechZoneSnapshot(cfg, wiringHandles9506(), 4, 4)
	if capture, fib := snapshot.Generations(); capture != 4 || fib != 4 {
		t.Fatalf("capture authority=(%d,%d), want (4,4)", capture, fib)
	}
	if accepted, fib := snapshot.AcceptedGenerations(); accepted != 4 || fib != 4 {
		t.Fatalf("initial accepted authority=(%d,%d), want (4,4)", accepted, fib)
	}
	runtime := &ipsecCaptureRuntime{
		zoneSnapshot: snapshot,
		handles:      wiringHandles9506(),
	}
	runtime.publishSnapshotAuthority(9, 7)
	if capture, fib := snapshot.Generations(); capture != 4 || fib != 4 {
		t.Fatalf("capture authority changed=(%d,%d), want immutable (4,4)", capture, fib)
	}
	if accepted, fib := snapshot.AcceptedGenerations(); accepted != 9 || fib != 7 {
		t.Fatalf("accepted authority=(%d,%d), want (9,7)", accepted, fib)
	}
	rows := runtime.tunnelRowsSnapshot()
	if len(rows) != 1 || rows[0].STN != "st1.0" {
		t.Fatalf("unambiguous tunnel rows=%+v, want one st1.0 row", rows)
	}
}

func TestIpsecCaptureOmitsAmbiguousTunnelRows10485(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.IPsec.VPNs = map[string]*config.IPsecVPN{
		"vpn-a": {BindInterface: "st1"},
		"vpn-b": {BindInterface: "st1.0"},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"zone": {Interfaces: []string{"st1.0"}},
	}
	handles := wiringHandles9506()
	runtime := &ipsecCaptureRuntime{
		handles:      handles,
		zoneSnapshot: buildPMechZoneSnapshot(cfg, handles, 4, 4),
	}
	if rows := runtime.tunnelRowsSnapshot(); len(rows) != 0 {
		t.Fatalf("ambiguous tunnel rows=%+v, want closed-world omission", rows)
	}
}

type captureAuthorityHealDP10485 struct {
	dataplane.RuntimeDataPlane
	current    func() *ipsecCaptureRuntime
	observed   *ipsecCaptureRuntime
	published  bool
	publishErr error
	bumpErr    error
	calls      []string
}

func (f *captureAuthorityHealDP10485) RepublishCurrentCaptureAuthority() (bool, error) {
	f.calls = append(f.calls, "republish")
	if f.current != nil {
		f.observed = f.current()
	}
	if f.publishErr != nil {
		return false, f.publishErr
	}
	return f.published, nil
}

func (f *captureAuthorityHealDP10485) BumpFIBGeneration() (uint32, error) {
	f.calls = append(f.calls, "bump")
	return 1, f.bumpErr
}

func TestIpsecCaptureRollbackHealRestoresHelperAuthority10485(t *testing.T) {
	old := &ipsecCaptureRuntime{}
	staged := &ipsecCaptureRuntime{}
	d := &Daemon{
		ipsecCapture:             staged,
		ipsecCaptureStaged:       staged,
		ipsecCaptureStagePending: true,
	}
	dp := &captureAuthorityHealDP10485{
		published: true,
		current: func() *ipsecCaptureRuntime {
			d.ipsecCaptureMu.Lock()
			defer d.ipsecCaptureMu.Unlock()
			return d.ipsecCapture
		},
	}
	d.dpCell.Store(&dpSlot{v: dp})

	if err := d.rollbackIpsecCaptureStage(old, staged); err != nil {
		t.Fatalf("rollback stage: %v", err)
	}
	if err := d.healIpsecCaptureAuthorityAfterRollback(nil); err != nil {
		t.Fatalf("post-rollback authority heal: %v", err)
	}
	if dp.observed != old {
		t.Fatalf("helper republish observed runtime=%p, want restored old runtime=%p", dp.observed, old)
	}
	if len(dp.calls) != 2 || dp.calls[0] != "republish" || dp.calls[1] != "bump" {
		t.Fatalf("heal calls=%v, want [republish bump]", dp.calls)
	}
}

func TestApplyConfigRollbackWiresAuthorityHeal10485(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "daemon_apply.go", nil, 0)
	if err != nil {
		t.Fatalf("parse daemon_apply.go: %v", err)
	}
	var apply *ast.FuncDecl
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if ok && fn.Name.Name == "applyConfigLocked" {
			apply = fn
			break
		}
	}
	if apply == nil {
		t.Fatal("applyConfigLocked declaration not found")
	}
	var heals, joins int
	ast.Inspect(apply.Body, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		switch selector.Sel.Name {
		case "healIpsecCaptureAuthorityAfterRollback":
			heals++
		case "Join":
			if len(call.Args) != 2 {
				return true
			}
			for _, arg := range call.Args {
				if ident, ok := arg.(*ast.Ident); ok && ident.Name == "healErr" {
					joins++
					break
				}
			}
		}
		return true
	})
	if heals != 1 {
		t.Fatalf("applyConfigLocked authority-heal calls=%d, want exactly one", heals)
	}
	if joins != 1 {
		t.Fatalf("applyConfigLocked errors.Join(…, healErr) calls=%d, want exactly one", joins)
	}
}

func TestIpsecCaptureRollbackHealDuplicateSkipDoesNotBump10485(t *testing.T) {
	d := &Daemon{}
	dp := &captureAuthorityHealDP10485{}
	d.dpCell.Store(&dpSlot{v: dp})
	if err := d.healIpsecCaptureAuthorityAfterRollback(nil); err != nil {
		t.Fatalf("duplicate-skip heal: %v", err)
	}
	if len(dp.calls) != 1 || dp.calls[0] != "republish" {
		t.Fatalf("duplicate-skip calls=%v, want [republish] without FIB bump", dp.calls)
	}
}

func TestIpsecCaptureRollbackHealReportsPublisherFailures10485(t *testing.T) {
	publishErr := errors.New("republish failed")
	bumpErr := errors.New("fib bump failed")
	for _, tc := range []struct {
		name       string
		publishErr error
		bumpErr    error
		published  bool
		want       error
	}{
		{name: "republish", publishErr: publishErr, want: publishErr},
		{name: "fib-bump", published: true, bumpErr: bumpErr, want: bumpErr},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := &Daemon{}
			dp := &captureAuthorityHealDP10485{
				published:  tc.published,
				publishErr: tc.publishErr,
				bumpErr:    tc.bumpErr,
			}
			d.dpCell.Store(&dpSlot{v: dp})
			err := d.healIpsecCaptureAuthorityAfterRollback(nil)
			if err == nil || !errors.Is(err, tc.want) {
				t.Fatalf("heal error=%v, want wrapped %v", err, tc.want)
			}
		})
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
	daemon := &Daemon{eventBuf: logging.NewEventBuffer(8)}
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
	if captured.Pipeline.DenyEvents == nil {
		t.Fatal("staged pipeline has no production deny-event sink")
	}

	for _, reason := range []nfqueue.IpsecInnerReason{
		nfqueue.ReasonZoneUnzoned, nfqueue.ReasonStaleGeneration,
		nfqueue.ReasonEvaluatorUnavailable, nfqueue.ReasonUnsupportedHook,
	} {
		if !captured.Pipeline.DenyEvents.EmitIpsecInnerDeny(nfqueue.IpsecInnerDeny{
			Reason: reason, Tunnel: "st1.0", Generation: 4,
		}) {
			t.Fatalf("production sink rejected %s", reason)
		}
	}
	events := daemon.eventBuf.Latest(8)
	if len(events) != 4 {
		t.Fatalf("operator event buffer received %d D11 denials, want 4: %+v", len(events), events)
	}
	for i, reason := range []nfqueue.IpsecInnerReason{
		nfqueue.ReasonUnsupportedHook, nfqueue.ReasonEvaluatorUnavailable,
		nfqueue.ReasonStaleGeneration, nfqueue.ReasonZoneUnzoned,
	} {
		got := events[i]
		if got.Type != "POLICY_DENY" || got.Action != "deny" ||
			got.Reason != "D11 "+reason.String() || got.IngressIface != "st1.0" {
			t.Fatalf("operator event[%d]=%+v, want D11 %s POLICY_DENY for st1.0", i, got, reason)
		}
	}
	daemon.eventBuf = nil
	if captured.Pipeline.DenyEvents.EmitIpsecInnerDeny(nfqueue.IpsecInnerDeny{
		Reason: nfqueue.ReasonEvaluatorUnavailable, Tunnel: "st1.0",
	}) {
		t.Fatal("production sink claimed delivery after the operator event buffer disappeared")
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

func TestIpsecCaptureZoneOnlyRezoneRotatesAuthorityWithoutQueueKeyChange11015(t *testing.T) {
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
	ipsecCaptureOpenQueue = func(uint16, ipsecQueueFamily) (*nfqueue.Queue, error) {
		return nil, nil
	}
	ipsecCaptureNewPipeline = func(cfg IpsecCapturePipelineConfig) (*IpsecCapturePipeline, error) {
		cfg.Queues = nil
		return NewIpsecCapturePipeline(cfg)
	}

	cfg := &config.Config{}
	cfg.Security.IPsec.VPNs = map[string]*config.IPsecVPN{"vpn": {BindInterface: "st1.0"}}
	cfg.Security.Zones = map[string]*config.ZoneConfig{"zone-a": {Interfaces: []string{"st1.0"}}}
	oldHandles := make([]ipsecQueueHandle, 0, 4)
	for i, class := range []struct {
		family ipsecQueueFamily
		hook   ipsecQueueHook
	}{
		{ipsecFamilyInet, ipsecHookForward},
		{ipsecFamilyInet, ipsecHookInput},
		{ipsecFamilyBridge, ipsecHookForward},
		{ipsecFamilyBridge, ipsecHookInput},
	} {
		oldHandles = append(oldHandles, ipsecQueueHandle{
			Number: uint16(1001 + i), Epoch: 9,
			Key: ipsecQueueKey{
				Generation: 4, Family: class.family, Hook: class.hook,
				Owner: "vpn", STN: "st1.0", Ifindex: 41,
			},
		})
	}
	old := &ipsecCaptureRuntime{
		handles: oldHandles, spec: xnft.IpsecDivertSpec{},
		zoneSnapshot: buildPMechZoneSnapshot(cfg, oldHandles, 4, 4),
	}
	daemon := &Daemon{ipsecCapture: old}

	unchangedOld, unchangedStaged, err := daemon.stageIpsecCapture(cfg)
	if err != nil {
		t.Fatalf("stage unchanged config: %v", err)
	}
	if unchangedOld != old || unchangedStaged != old || daemon.ipsecCaptureStagePending {
		t.Fatal("unchanged authority rotated capture queues")
	}

	cfg.Security.Zones = map[string]*config.ZoneConfig{"zone-b": {Interfaces: []string{"st1.0"}}}
	oldRuntime, staged, err := daemon.stageIpsecCapture(cfg)
	if err != nil {
		t.Fatalf("stage zone-only rezone: %v", err)
	}
	if oldRuntime != old || staged == nil || staged == old {
		t.Fatalf("zone-only rezone runtime=(%p,%p), want old runtime and a rotated staged runtime", oldRuntime, staged)
	}
	if !daemon.ipsecCaptureStagePending || len(staged.handles) != 4 {
		t.Fatalf("zone-only rezone stage pending=%v queues=%d, want pending complete four-class rotation",
			daemon.ipsecCaptureStagePending, len(staged.handles))
	}
	for i, handle := range staged.handles {
		if handle.Key.Generation == oldHandles[i].Key.Generation ||
			handle.Key.Family != oldHandles[i].Key.Family ||
			handle.Key.Hook != oldHandles[i].Key.Hook ||
			handle.Key.Owner != oldHandles[i].Key.Owner ||
			handle.Key.STN != oldHandles[i].Key.STN ||
			handle.Key.Ifindex != oldHandles[i].Key.Ifindex {
			t.Fatalf("queue identity changed beyond capture generation: old=%+v next=%+v", oldHandles[i].Key, handle.Key)
		}
	}
	resolution := staged.zoneSnapshot.ResolveSTN("st1.0")
	if resolution.Reason != nfqueue.ZoneReasonZoned || resolution.ZoneID != config.StableZoneID("zone-b") {
		t.Fatalf("staged zone authority=%+v, want zone-b=%d", resolution, config.StableZoneID("zone-b"))
	}
	_ = daemon.rollbackIpsecCaptureStage(old, staged)
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

func TestIpsecCapturePublishesAdmittedTunnelRows10485(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.IPsec.VPNs = map[string]*config.IPsecVPN{
		"vpn-a": {BindInterface: "st1.0"},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"zone-a": {Interfaces: []string{"st1.0"}},
	}
	handles := wiringHandles9506()
	zoneSnapshot := buildPMechZoneSnapshot(cfg, handles, handles[0].Key.Generation, 7)
	runtime := &ipsecCaptureRuntime{handles: handles, zoneSnapshot: zoneSnapshot}
	daemon := &Daemon{ipsecCapture: runtime}

	_, _, captureGeneration, rows := daemon.ipsecCaptureConfigSnapshot(33, 9)
	if captureGeneration != handles[0].Key.Generation || len(rows) != 1 {
		t.Fatalf("authority=(%d,%+v), want capture generation %d and one row",
			captureGeneration, rows, handles[0].Key.Generation)
	}
	if got := rows[0]; got.STN != "st1.0" || got.IfID == 0 || got.LogicalIfindex != 17 {
		t.Fatalf("published row=%+v, want st1.0/nonzero-if_id/ifindex=17", got)
	}

	daemon.publishIpsecCaptureCommitted(nil)
	_, _, captureGeneration, rows = daemon.ipsecCaptureConfigSnapshot(34, 10)
	if captureGeneration != 0 || rows != nil {
		t.Fatalf("teardown authority=(%d,%+v), want zero/nil", captureGeneration, rows)
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
	announces   int
	runID       string
	generation  uint64
	permitEpoch uint64
	permitOpen  bool
	rows        []nfqueue.ReinjectQueueEpoch
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

func (f *fakeIpsecReinjectSubmitter9506) AnnounceReinject(runID string, generation, permitEpoch uint64, permitOpen bool, rows []nfqueue.ReinjectQueueEpoch) error {
	f.announces++
	f.runID = runID
	f.generation = generation
	f.permitEpoch = permitEpoch
	f.permitOpen = permitOpen
	f.rows = append(f.rows[:0], rows...)
	return nil
}

func TestD11CloseRevokesSelectedAuthorityWithoutMutatingPermit10484(t *testing.T) {
	supervisor := newIpsecSupervisor()
	supervisor.permit.Store(&permitRecord{state: ipsecPermitOpen, permitEpoch: 17})
	submitter := new(fakeIpsecReinjectSubmitter9506)
	rows := []nfqueue.ReinjectQueueEpoch{{Queue: 1000, Epoch: 4}}
	runtime := &ipsecCaptureRuntime{
		supervisor: supervisor,
		submitter:  submitter,
		d11Override: &d11AuthorityOverride{
			runID:       "attest-00112233445566778899aabbccddeeff",
			generation:  4,
			permitEpoch: 17,
			permitOpen:  true,
			rows:        rows,
		},
	}
	if err := runtime.clearD11AuthorityOverride(); err != nil {
		t.Fatalf("clear D11 authority: %v", err)
	}
	if submitter.runID != "attest-00112233445566778899aabbccddeeff" ||
		submitter.generation != 4 || submitter.permitEpoch != 17 ||
		submitter.permitOpen {
		t.Fatalf("revoke announcement = run %q generation %d epoch %d open %v",
			submitter.runID, submitter.generation, submitter.permitEpoch, submitter.permitOpen)
	}
	if len(submitter.rows) != 1 || submitter.rows[0] != rows[0] {
		t.Fatalf("revoke rows = %+v, want %+v", submitter.rows, rows)
	}
	if got := supervisor.loadPermit(); got == nil || got.state != ipsecPermitOpen ||
		got.permitEpoch != 17 {
		t.Fatalf("shared permit mutated by D11 revoke: %+v", got)
	}
	runtime.authorityMu.Lock()
	overrideActive := runtime.d11Override != nil
	runtime.authorityMu.Unlock()
	if overrideActive {
		t.Fatal("D11 override retained after successful revoke announcement")
	}
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

func TestIpsecCaptureZeroRowStageTokenFence10485(t *testing.T) {
	tests := []struct {
		name   string
		staged *ipsecCaptureRuntime
		token  uint64
	}{
		{name: "teardown", staged: nil, token: 41},
		{name: "quarantine", staged: &ipsecCaptureRuntime{}, token: 42},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &Daemon{
				ipsecCaptureStagePending:    true,
				ipsecCaptureStaged:          tt.staged,
				ipsecCaptureStageGeneration: tt.token,
			}
			d.publishIpsecCaptureSnapshotAuthority(7, 9, tt.token-1)
			if d.ipsecCaptureSnapshotLandedForStage() {
				t.Fatal("stale zero-row callback landed replacement stage")
			}
			d.publishIpsecCaptureSnapshotAuthority(7, 9, tt.token)
			if !d.ipsecCaptureSnapshotLandedForStage() {
				t.Fatal("matching zero-row callback did not land stage")
			}
		})
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
func TestIpsecCaptureWitnessUsesD11JoinKey10484(t *testing.T) {
	const runID = "attest-0123456789abcdef0123456789abcdef"
	supervisor := newIpsecSupervisor()
	supervisor.permit.Store(&permitRecord{state: ipsecPermitOpen, permitEpoch: 17})
	armer := nfqueue.NewD11AttestationArmer("node-a", nil, func(string, uint64) error {
		return nil
	})
	armer.SetEnvironmentGate(func() bool { return true })
	if err := armer.Arm(runID, 17, "00112233445566778899aabbccddeeff"); err != nil {
		t.Fatalf("Arm: %v", err)
	}
	runtime := &ipsecCaptureRuntime{
		supervisor: supervisor,
		actor:      &IpsecCapturePipeline{supervisor: supervisor, runID: "process-run"},
		d11Armer:   armer,
		d11Override: &d11AuthorityOverride{
			runID: runID, permitEpoch: 17, permitOpen: true,
		},
	}
	d := &Daemon{opts: Options{NoDataplane: true}, ipsecCapture: runtime, d11Armer: armer}
	witness := d.apiServerConfig(nil).IpsecCaptureWitnessFn()
	if !witness.D11Available || witness.D11RunID != runID ||
		witness.D11PermitEpoch != 17 || witness.RunID == runID {
		t.Fatalf("witness D11 key = available=%v run=%q epoch=%d actor=%q, want true/%q/17/process",
			witness.D11Available, witness.D11RunID, witness.D11PermitEpoch, witness.RunID, runID)
	}
}
func newF1CaptureFenceTestEnv(t *testing.T, withCapture bool, removeErr error) (*Daemon, *fakeNftInstaller, *[]string) {
	t.Helper()
	origInstaller := nftInstaller
	origDelete := conntrackDeleteFilters
	origOverlayDelete := hostInputFenceConntrackDeleteFilters
	origCensus := hostInputFenceAllLocalAddrs
	t.Cleanup(func() {
		nftInstaller = origInstaller
		conntrackDeleteFilters = origDelete
		hostInputFenceConntrackDeleteFilters = origOverlayDelete
		hostInputFenceAllLocalAddrs = origCensus
	})
	hostInputFenceAllLocalAddrs = func() ([]string, error) { return nil, nil }
	conntrackDeleteFilters = func(netlink.InetFamily, ...netlink.CustomConntrackFilter) (uint, error) {
		return 0, nil
	}
	hostInputFenceConntrackDeleteFilters = func(netlink.InetFamily, ...netlink.CustomConntrackFilter) (uint, error) {
		return 0, nil
	}

	store := newConfigStore(t, filepath.Join(t.TempDir(), "config.db"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := store.LoadOverride("system { host-name f1-capture-test; }"); err != nil {
		t.Fatalf("LoadOverride: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	tuple := ipsecTopologyTuple{Kind: "xfrmi", Ifindex: 11, Name: "st0", Owner: "kernel"}
	key := testKey(ipsecReadySafe, 4, tuple)
	supervisor := newIpsecSupervisor()
	permit := testClosingRecord(8, 12, key, 4)
	if withCapture {
		permit = testOpenRecord(8, 12, key, 4)
	}
	supervisor.permit.Store(permit)
	supervisor.watch.Store(&TransitWatchSnapshot{Generation: 4, Ready: ipsecReadySafe, Tuples: key.Tuples})
	d := &Daemon{store: store, ipsecS4: supervisor, applySem: semaphore.NewWeighted(1)}
	events := new([]string)
	fake := &fakeNftInstaller{}
	fake.hostInbound = func(spec xnft.HostInboundSpec) error {
		if spec.Overlay == nil || spec.Overlay.State != "CLOSING" ||
			len(spec.Overlay.MasterSet) != 1 || spec.Overlay.MasterSet[0] != "st0" {
			return errors.New("host-input DROP overlay missing st0/CLOSING authority")
		}
		*events = append(*events, "install")
		return nil
	}
	fake.overlayReadback = func(overlay xnft.HostInputFenceOverlay) error {
		if overlay.State != "CLOSING" || len(overlay.MasterSet) != 1 || overlay.MasterSet[0] != "st0" {
			return errors.New("host-input DROP overlay readback did not cover st0")
		}
		*events = append(*events, "readback")
		return nil
	}
	fake.divertRemove = func() error {
		*events = append(*events, "remove")
		current := supervisor.loadPermit()
		if current == nil || current.state != ipsecPermitClosing {
			return errors.New("divert removal crossed an OPEN permit")
		}
		acked := d.ipsecOverlayAcked.Load()
		if acked == nil || !hostInputFenceOverlayAuthorityMatches(acked, current) ||
			!d.ipsecCaptureRemovalPending.Load() {
			return errors.New("divert removal began before acknowledged host-input DROP hold")
		}
		return removeErr
	}
	nftInstaller = fake
	if withCapture {
		d.ipsecCapture = &ipsecCaptureRuntime{
			supervisor: supervisor,
			spec:       xnft.IpsecDivertSpec{InetInput: []xnft.IpsecDivertRule{{Ifname: "st0", Queue: 1002}}},
		}
		d.ipsecCaptureStagePending = true
	}
	return d, fake, events
}

func commitIpsecCaptureStageF1(t *testing.T, d *Daemon, old *ipsecCaptureRuntime) error {
	t.Helper()
	if err := d.applySem.Acquire(context.Background(), 1); err != nil {
		t.Fatalf("acquire apply semaphore: %v", err)
	}
	defer d.applySem.Release(1)
	return d.commitIpsecCaptureStage(old, nil)
}

func TestIpsecCaptureRemovalAcknowledgesFenceBeforeDivertAndKeepsIt9506(t *testing.T) {
	d, fake, events := newF1CaptureFenceTestEnv(t, true, nil)
	old := d.ipsecCapture
	if err := commitIpsecCaptureStageF1(t, d, old); err != nil {
		t.Fatalf("remove capture: %v", err)
	}
	if got := strings.Join(*events, ","); got != "install,readback,remove" {
		t.Fatalf("transition order = %s, want install/readback before remove", got)
	}
	if len(fake.divertCalls) != 1 || fake.divertCalls[0] != "remove" {
		t.Fatalf("divert calls = %v, want one removal", fake.divertCalls)
	}
	if d.ipsecCapture != nil || d.ipsecCaptureStagePending {
		t.Fatalf("capture state after removal = active %p pending %v", d.ipsecCapture, d.ipsecCaptureStagePending)
	}
	permit := d.ipsecS4.loadPermit()
	if permit == nil || permit.state != ipsecPermitClosing {
		t.Fatalf("permit after removal = %+v, want CLOSING while divert absent", permit)
	}
	overlay := d.activeHostInputFenceOverlay()
	if overlay == nil || overlay.State != "CLOSING" || len(overlay.MasterSet) != 1 || overlay.MasterSet[0] != "st0" {
		t.Fatalf("fence after removal = %+v, want acknowledged st0 DROP", overlay)
	}
	d.tryOpenIpsecPermitAfterFenceAck(permit)
	if got := d.ipsecS4.loadPermit(); got != permit || got.state != ipsecPermitClosing {
		t.Fatalf("fence ACK reopened permit without a committed divert: %+v", got)
	}
}

func TestIpsecCaptureRemovalFailureRestoresDivertBehindFence9506(t *testing.T) {
	injected := errors.New("remove failed")
	d, fake, events := newF1CaptureFenceTestEnv(t, true, injected)
	old := d.ipsecCapture
	if err := commitIpsecCaptureStageF1(t, d, old); !errors.Is(err, injected) {
		t.Fatalf("remove error = %v, want injected failure", err)
	}
	if got := strings.Join(*events, ","); got != "install,readback,remove" {
		t.Fatalf("transition order = %s, want install/readback before failed remove", got)
	}
	if len(fake.divertCalls) != 1 || fake.divertCalls[0] != "remove" {
		t.Fatalf("divert calls = %v, want one removal attempt", fake.divertCalls)
	}
	if d.ipsecCapture != old || d.ipsecCaptureStagePending || d.ipsecCaptureRemovalPending.Load() {
		t.Fatalf("failed removal did not restore old capture: active %p pending-stage %v pending-remove %v",
			d.ipsecCapture, d.ipsecCaptureStagePending, d.ipsecCaptureRemovalPending.Load())
	}
	permit := d.ipsecS4.loadPermit()
	if permit == nil || permit.state != ipsecPermitClosing ||
		!hostInputFenceOverlayAuthorityMatches(d.ipsecOverlayAcked.Load(), permit) {
		t.Fatalf("failed removal lost fence hold authority: permit=%+v acked=%+v", permit, d.ipsecOverlayAcked.Load())
	}
}

func TestIpsecCaptureRemovalReadbackFailureKeepsDivert9506(t *testing.T) {
	injected := errors.New("host-input overlay readback mismatch")
	d, fake, events := newF1CaptureFenceTestEnv(t, true, nil)
	fake.overlayReadback = func(xnft.HostInputFenceOverlay) error {
		*events = append(*events, "readback")
		return injected
	}
	old := d.ipsecCapture
	if err := commitIpsecCaptureStageF1(t, d, old); !errors.Is(err, injected) {
		t.Fatalf("fence readback error = %v, want injected mismatch", err)
	}
	if got := strings.Join(*events, ","); got != "install,readback" {
		t.Fatalf("transition after readback failure = %s, want no divert removal", got)
	}
	if len(fake.divertCalls) != 0 || d.ipsecCapture != old || d.ipsecCaptureStagePending {
		t.Fatalf("unverified fence did not retain divert: calls=%v active=%p pending=%v",
			fake.divertCalls, d.ipsecCapture, d.ipsecCaptureStagePending)
	}
	if d.ipsecOverlayAcked.Load() != nil {
		t.Fatalf("failed fence readback published ACK: %+v", d.ipsecOverlayAcked.Load())
	}
}

func TestIpsecFenceRemainsClosedBeforeFirstCaptureAndAtBoot9506(t *testing.T) {
	d, _, events := newF1CaptureFenceTestEnv(t, false, nil)
	d.reconcileIpsecHostInputFence(context.Background())
	if got := strings.Join(*events, ","); got != "install,readback" {
		t.Fatalf("boot fence order = %s, want acknowledged host-input DROP", got)
	}
	permit := d.ipsecS4.loadPermit()
	if permit == nil || permit.state != ipsecPermitClosing {
		t.Fatalf("pre-first-install permit = %+v, want CLOSING", permit)
	}
	overlay := d.activeHostInputFenceOverlay()
	if overlay == nil || !hostInputFenceOverlayAuthorityMatches(d.ipsecOverlayAcked.Load(), permit) ||
		len(overlay.MasterSet) != 1 || overlay.MasterSet[0] != "st0" {
		t.Fatalf("boot host-input fence = %+v acked=%+v, want read-back st0 DROP", overlay, d.ipsecOverlayAcked.Load())
	}
	d.tryOpenIpsecPermitAfterFenceAck(permit)
	if got := d.ipsecS4.loadPermit(); got != permit || got.state != ipsecPermitClosing {
		t.Fatalf("pre-first-install fence ACK opened permit without a divert: %+v", got)
	}
}
