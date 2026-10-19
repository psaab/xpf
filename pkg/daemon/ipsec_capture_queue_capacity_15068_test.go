package daemon

// #15068 (A35-03): the 128-handle capture queue cap is consumed by the old
// plus the staged generation. Each tunnel needs four provenance classes, so
// 32 tunnels need 128 staged handles alone; with the old generation still
// holding its handles until commit retires it (and a further tick frees the
// numbers), staging a 17th tunnel — or rezoning any of 17..32 — exhausted
// the allocator and quarantined every tunnel (QUEUE_OPEN). The allocator is
// sized for two generations and a single staged generation is bounded to
// the supported 32 tunnels.

import (
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/logging"
	"github.com/psaab/xpf/pkg/nfqueue"
	xnft "github.com/psaab/xpf/pkg/nftables"
	"github.com/vishvananda/netlink"
)

func ipsecCaptureConfig15068(tunnels int, zone string) *config.Config {
	cfg := &config.Config{}
	cfg.Security.IPsec.VPNs = make(map[string]*config.IPsecVPN, tunnels)
	ifaces := make([]string, 0, tunnels)
	for i := range tunnels {
		bind := fmt.Sprintf("st%d.0", i)
		cfg.Security.IPsec.VPNs[fmt.Sprintf("vpn-%02d", i)] = &config.IPsecVPN{BindInterface: bind}
		ifaces = append(ifaces, bind)
	}
	if zone != "" {
		cfg.Security.Zones = map[string]*config.ZoneConfig{
			zone: {Interfaces: ifaces},
		}
	}
	return cfg
}

func installIpsecCaptureStageSeams15068(t *testing.T) {
	t.Helper()
	origLink := ipsecCaptureLinkByName
	origOpen := ipsecCaptureOpenQueue
	origNew := ipsecCaptureNewPipeline
	t.Cleanup(func() {
		ipsecCaptureLinkByName = origLink
		ipsecCaptureOpenQueue = origOpen
		ipsecCaptureNewPipeline = origNew
	})
	ipsecCaptureLinkByName = func(name string) (netlink.Link, error) {
		// name is the xfrmi device for bind st<N>.0.
		rest := strings.TrimPrefix(name, "st")
		num, _, _ := strings.Cut(rest, ".")
		idx, err := strconv.Atoi(num)
		if err != nil {
			return nil, fmt.Errorf("bad test link name %q", name)
		}
		return &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: name, Index: 100 + idx}}, nil
	}
	ipsecCaptureOpenQueue = func(uint16, ipsecQueueFamily) (*nfqueue.Queue, error) {
		return nil, nil
	}
	ipsecCaptureNewPipeline = func(cfg IpsecCapturePipelineConfig) (*IpsecCapturePipeline, error) {
		cfg.Queues = nil
		return NewIpsecCapturePipeline(cfg)
	}
}

func stageIpsecCapture15068(t *testing.T, d *Daemon, cfg *config.Config) (old, staged *ipsecCaptureRuntime) {
	t.Helper()
	old, staged, err := d.stageIpsecCapture(cfg)
	if err != nil {
		t.Fatalf("stage capture: %v", err)
	}
	if staged == nil {
		t.Fatal("stage returned no staged runtime")
	}
	return old, staged
}

func assertStagedGeneration15068(t *testing.T, staged *ipsecCaptureRuntime, tunnels int) {
	t.Helper()
	if staged.spec.QuarantineAll {
		t.Fatalf("staged %d tunnels quarantined (reason=%v mask=0x%x raw=%v handles=%d actor=%v), want a complete divert generation",
			tunnels, staged.spec.QuarantinePrimaryReason, staged.spec.QuarantineReasonMask, staged.spec.QuarantineRawReason, len(staged.handles), staged.actor != nil)
	}
	if got, want := len(staged.handles), tunnels*4; got != want {
		t.Fatalf("staged handles = %d, want %d (%d tunnels x 4 classes)", got, want, tunnels)
	}
	if len(staged.spec.InetForward) != tunnels || len(staged.spec.InetInput) != tunnels ||
		len(staged.spec.BridgeForward) != tunnels || len(staged.spec.BridgeInput) != tunnels {
		t.Fatalf("staged divert classes = %d/%d/%d/%d, want %d each",
			len(staged.spec.InetForward), len(staged.spec.InetInput),
			len(staged.spec.BridgeForward), len(staged.spec.BridgeInput), tunnels)
	}
}

// TestIpsecCaptureAdd31To32StagesWithoutQuarantine15068 is the add leg: the
// old 31-tunnel generation still holds 124 handles while the 32-tunnel
// generation stages its 128, so the pair needs 252 live handles.
func TestIpsecCaptureAdd31To32StagesWithoutQuarantine15068(t *testing.T) {
	installIpsecCaptureStageSeams15068(t)
	d := &Daemon{eventBuf: logging.NewEventBuffer(8)}

	_, first := stageIpsecCapture15068(t, d, ipsecCaptureConfig15068(31, "zone-a"))
	assertStagedGeneration15068(t, first, 31)
	// Simulate the commit publishing the 31-tunnel generation: it stays
	// live (handles allocated) until the next commit retires it.
	d.ipsecCapture = first

	_, second := stageIpsecCapture15068(t, d, ipsecCaptureConfig15068(32, "zone-a"))
	assertStagedGeneration15068(t, second, 32)
	if !d.ipsecCaptureStagePending {
		t.Fatal("32-tunnel stage was not marked pending")
	}
	_ = second.close()
	_ = first.close()
}

// TestIpsecCaptureRezone32StagesWithoutQuarantine15068 is the rezone leg: a
// zone-only change rotates the capture generation even though the queue keys
// are unchanged, so old (128) plus staged (128) handles coexist.
func TestIpsecCaptureRezone32StagesWithoutQuarantine15068(t *testing.T) {
	installIpsecCaptureStageSeams15068(t)
	d := &Daemon{eventBuf: logging.NewEventBuffer(8)}

	_, first := stageIpsecCapture15068(t, d, ipsecCaptureConfig15068(32, "zone-a"))
	assertStagedGeneration15068(t, first, 32)
	d.ipsecCapture = first

	old, second := stageIpsecCapture15068(t, d, ipsecCaptureConfig15068(32, "zone-b"))
	if old != first || second == first {
		t.Fatalf("rezone runtimes = (%p, %p), want old published runtime and a rotated staged runtime", old, second)
	}
	assertStagedGeneration15068(t, second, 32)
	resolution := second.zoneSnapshot.ResolveSTN("st0.0")
	if resolution.Reason != nfqueue.ZoneReasonZoned || resolution.ZoneID != config.StableZoneID("zone-b") {
		t.Fatalf("staged zone authority = %+v, want zone-b=%d", resolution, config.StableZoneID("zone-b"))
	}
	_ = second.close()
	_ = first.close()
}

// TestIpsecCaptureBeyond32TunnelsStillQuarantines15068 is the fail-closed
// control: the supported bound is 32 tunnels per generation, so a 33-tunnel
// generation must still refuse allocation as QUEUE_OPEN rather than admit
// an unbounded generation (with or without a live old generation).
func TestIpsecCaptureBeyond32TunnelsStillQuarantines15068(t *testing.T) {
	installIpsecCaptureStageSeams15068(t)

	fresh := &Daemon{eventBuf: logging.NewEventBuffer(8)}
	_, stagedFresh := stageIpsecCapture15068(t, fresh, ipsecCaptureConfig15068(33, "zone-a"))
	if !stagedFresh.spec.QuarantineAll || stagedFresh.spec.QuarantinePrimaryReason != xnft.IpsecQuarantineReasonQueueOpen {
		t.Fatalf("33 tunnels from empty = %+v, want QUEUE_OPEN quarantine", stagedFresh.spec)
	}
	if len(stagedFresh.handles) != 0 {
		t.Fatalf("quarantined generation retained %d handles, want none", len(stagedFresh.handles))
	}

	d := &Daemon{eventBuf: logging.NewEventBuffer(8)}
	_, first := stageIpsecCapture15068(t, d, ipsecCaptureConfig15068(32, "zone-a"))
	assertStagedGeneration15068(t, first, 32)
	d.ipsecCapture = first
	_, stagedOver := stageIpsecCapture15068(t, d, ipsecCaptureConfig15068(33, "zone-a"))
	if !stagedOver.spec.QuarantineAll || stagedOver.spec.QuarantinePrimaryReason != xnft.IpsecQuarantineReasonQueueOpen {
		t.Fatalf("33 tunnels over a live 32 = %+v, want QUEUE_OPEN quarantine", stagedOver.spec)
	}
	_ = first.close()
}
