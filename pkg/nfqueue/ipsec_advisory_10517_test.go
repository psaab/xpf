package nfqueue

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestIpsecAdvisoryMatchesInstalledDivertDrop10517 keeps the operator-facing
// warning aligned with the normal route-VPN receive path. The config compiler
// owns the wording; this package owns submitEligible's terminal disposition.
// Keeping both assertions in one test prevents a future advisory edit from
// silently restoring the pre-divert claim that INPUT is delivered.
func TestIpsecAdvisoryMatchesInstalledDivertDrop10517(t *testing.T) {
	tree := &config.ConfigTree{}
	path, err := config.ParseSetCommand("set security ipsec vpn myvpn bind-interface st0.0")
	if err != nil {
		t.Fatalf("ParseSetCommand: %v", err)
	}
	if err := tree.SetPath(path); err != nil {
		t.Fatalf("SetPath: %v", err)
	}
	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	var advisory string
	for _, warning := range cfg.Warnings {
		if strings.Contains(warning, "#5619") {
			advisory = warning
			break
		}
	}
	if advisory == "" {
		t.Fatalf("missing #5619 advisory: %v", cfg.Warnings)
	}
	for _, want := range []string{
		"IPsec divert installed",
		"terminally drops every frame",
		"V1PermitSuppressed",
		"divert-absent window",
		"no decrypted plaintext reaches",
		"installed IPsec divert is fail-closed",
		"until capture is restored",
	} {
		if !strings.Contains(advisory, want) {
			t.Errorf("advisory missing corrected mechanism %q: %s", want, advisory)
		}
	}
	for _, stale := range []string{
		"INPUT/host-bound plaintext still reaches the local input path",
		"until this is enforced",
	} {
		if strings.Contains(advisory, stale) {
			t.Errorf("advisory retained stale wording %q: %s", stale, advisory)
		}
	}

	inputOrigin := CaptureOrigin{
		Family: CaptureFamilyInet, Hook: CaptureHookInput,
		Owner: "myvpn", STN: "st0.0", OwnedIfindex: 7,
	}
	forwardOrigin := CaptureOrigin{
		Family: CaptureFamilyInet, Hook: CaptureHookForward,
		Owner: "myvpn", STN: "st0.0", OwnedIfindex: 7,
	}
	bridgeOrigin := CaptureOrigin{
		Family: CaptureFamilyBridge, Hook: CaptureHookForward,
		Owner: "myvpn", STN: "st0.0", OwnedIfindex: 7,
	}
	var registry OriginRegistry
	for _, tc := range []struct {
		queue  uint16
		origin CaptureOrigin
	}{
		{77, inputOrigin},
		{78, forwardOrigin},
		{79, bridgeOrigin},
	} {
		if err := registry.Register(tc.queue, tc.origin); err != nil {
			t.Fatalf("register queue %d origin: %v", tc.queue, err)
		}
	}
	submitter := new(pipelineTestSubmitter)
	sink := new(pipelineTestSink)
	p, err := NewCapturePipeline(CapturePipelineConfig{
		Registry:      &registry,
		Phase:         PipelineEnforcing,
		Sink:          sink,
		Submitter:     submitter,
		ZoneEvaluator: passZoneEvaluator9506{},
		ZoneSnapshot:  passZoneSnapshot9506{},
		HandoffCap:    4,
		BatchCap:      4,
	})
	if err != nil {
		t.Fatalf("NewCapturePipeline: %v", err)
	}
	makeFrame := func(queue uint16, packetFamily, packetHook uint8, flow string, origin CaptureOrigin) CaptureFrame {
		return CaptureFrame{
			Packet:             pipelineTestPacket(queue, packetFamily, packetHook, origin.OwnedIfindex, uint32(queue)),
			FlowKey:            flow,
			Generation:         1,
			SnapshotGeneration: 1,
			ConfigGeneration:   1,
			FIBGeneration:      1,
			QueueNumber:        queue,
			QueueEpoch:         1,
			origin:             origin,
			originSet:          true,
		}
	}

	// Phase routing into submitEligible is covered by
	// TestCapturePipelineRoutineV1SuppressionHasNoDenyEvent9506. This test
	// deliberately calls submitEligible directly to pin each Enforcing
	// per-origin terminal disposition and keep the advisory coupling narrow.
	p.submitEligible([]CaptureFrame{
		makeFrame(77, 2, 1, "route-vpn-input", inputOrigin),
		makeFrame(78, 2, 2, "route-vpn-forward", forwardOrigin),
		makeFrame(79, 7, 2, "route-vpn-bridge-forward", bridgeOrigin),
	})
	stats := p.Stats()
	if stats.V1PermitSuppressed != 2 || stats.L2Unsupported != 1 || stats.ZoneGateDrops != 0 {
		t.Fatalf("stats=%+v, want two inet V1 suppressions and one bridge L2 drop", stats)
	}
	if len(sink.verdicts) != 3 {
		t.Fatalf("verdicts=%+v, want INPUT, FORWARD, and bridge terminal drops", sink.verdicts)
	}
	for _, verdict := range sink.verdicts {
		if verdict.v != VerdictDrop {
			t.Fatalf("verdicts=%+v, want every captured frame dropped", sink.verdicts)
		}
	}
	if len(submitter.submitted) != 0 {
		t.Fatalf("submitted=%d, want no reinject delivery after terminal drops", len(submitter.submitted))
	}

	dropOrigin := CaptureOrigin{
		Family: CaptureFamilyInet, Hook: CaptureHookInput,
		Owner: "myvpn", STN: "st0.0", OwnedIfindex: 7,
	}
	var dropRegistry OriginRegistry
	if err := dropRegistry.Register(80, dropOrigin); err != nil {
		t.Fatalf("register zone-drop origin: %v", err)
	}
	dropSubmitter := new(pipelineTestSubmitter)
	dropSink := new(pipelineTestSink)
	dropPipeline, err := NewCapturePipeline(CapturePipelineConfig{
		Registry:      &dropRegistry,
		Phase:         PipelineEnforcing,
		Sink:          dropSink,
		Submitter:     dropSubmitter,
		ZoneEvaluator: dropZoneEvaluator10517{},
		ZoneSnapshot:  passZoneSnapshot9506{},
		HandoffCap:    1,
		BatchCap:      1,
	})
	if err != nil {
		t.Fatalf("NewCapturePipeline zone-drop: %v", err)
	}
	dropPipeline.submitEligible([]CaptureFrame{
		makeFrame(80, 2, 1, "route-vpn-zone-drop", dropOrigin),
	})
	dropStats := dropPipeline.Stats()
	if dropStats.ZoneGateDrops != 1 || dropStats.V1PermitSuppressed != 0 {
		t.Fatalf("zone-drop stats=%+v, want one zone drop and no V1 suppression", dropStats)
	}
	if len(dropSink.verdicts) != 1 || dropSink.verdicts[0].v != VerdictDrop {
		t.Fatalf("zone-drop verdicts=%+v, want one terminal DROP", dropSink.verdicts)
	}
	if len(dropSubmitter.submitted) != 0 {
		t.Fatalf("zone-drop submitted=%d, want no reinject delivery", len(dropSubmitter.submitted))
	}
}

type dropZoneEvaluator10517 struct{}

func (dropZoneEvaluator10517) Evaluate(CaptureOrigin, ZoneSnapshotRef) ZoneEvaluation {
	return ZoneEvaluation{Decision: ZoneDrop, ZoneID: 1, IfID: 7, Reason: ZoneReasonUnzoned}
}
