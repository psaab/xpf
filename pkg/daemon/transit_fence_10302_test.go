package daemon

import (
	"errors"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
	xnft "github.com/psaab/xpf/pkg/nftables"
	"github.com/vishvananda/netlink"
)

type fenceRuntime10302 struct {
	dataplane.RuntimeDataPlane
	ifindexes []int
}

func (r *fenceRuntime10302) AttachedXDPIfindexes() []int {
	return append([]int(nil), r.ifindexes...)
}

func TestArmedForwardFenceDropsUnownedTransit10302(t *testing.T) {
	oldLinks := transitFenceLinkList
	t.Cleanup(func() { transitFenceLinkList = oldLinks })
	transitFenceLinkList = func() ([]netlink.Link, error) {
		return []netlink.Link{
			&netlink.Device{LinkAttrs: netlink.LinkAttrs{Name: "xdp-owned0", Index: 101}},
			&netlink.Device{LinkAttrs: netlink.LinkAttrs{Name: "leave-alone0", Index: 102}},
			&netlink.Xfrmi{LinkAttrs: netlink.LinkAttrs{Name: "xfrm1", Index: 103}},
			&netlink.Tuntap{
				LinkAttrs: netlink.LinkAttrs{Name: "xpf-usp0", Index: 104},
				Mode:      netlink.TUNTAP_MODE_TUN,
			},
			&netlink.Tuntap{
				LinkAttrs: netlink.LinkAttrs{Name: armedTransitReinjectIfname, Index: 105},
				Mode:      netlink.TUNTAP_MODE_TUN,
			},
		}, nil
	}

	f := withBarrierRecorder(t)
	d := &Daemon{}
	d.setDataplane(&fenceRuntime10302{ifindexes: []int{101}})

	if err := d.applyTransitBarrier(true); err != nil {
		t.Fatalf("armed fence install: %v", err)
	}
	if len(f.fenceCalls10302) != 1 || f.fenceCalls10302[0] != "install" {
		t.Fatalf("armed transit must install the explicit forward fence, calls=%v barrier=%v", f.fenceCalls10302, f.barrierCalls)
	}
	if len(f.fenceSpecs10302) != 1 {
		t.Fatalf("armed transit must supply exactly one forward-fence spec, got %d", len(f.fenceSpecs10302))
	}
	got := f.fenceSpecs10302[0]
	if len(got.AllowedIfnames) != 1 || got.AllowedIfnames[0] != "xdp-owned0" {
		t.Fatalf("armed unmarked pinholes = %v, want only tracked XDP xpf-usp1 excluded", got.AllowedIfnames)
	}
	if len(got.AllowedMarks) != 1 {
		t.Fatalf("armed marked pinholes = %v, want one xpf-usp1 mark conjunction", got.AllowedMarks)
	}
	marked := got.AllowedMarks[0]
	if marked.Ifname != armedTransitReinjectIfname ||
		marked.Mark != xnft.AdjudicatedTransitMark ||
		marked.Mask != xnft.AdjudicatedTransitMarkMask {
		t.Fatalf("armed marked pinhole = %+v, want xpf-usp1 mark %#x/%#x",
			marked, xnft.AdjudicatedTransitMark, xnft.AdjudicatedTransitMarkMask)
	}
	for _, name := range got.AllowedIfnames {
		if name == "leave-alone0" || name == "unmanaged0" || name == "xfrm1" || name == "xpf-usp0" || name == armedTransitReinjectIfname {
			t.Fatalf("unowned/unadjudicated or LocalDelivery fixture %q must not be an unmarked forward pinhole: %v", name, got.AllowedIfnames)
		}
	}
}

func TestArmedForwardFenceResolverFailureKeepsGateClosed10302(t *testing.T) {
	oldLinks := transitFenceLinkList
	t.Cleanup(func() { transitFenceLinkList = oldLinks })
	transitFenceLinkList = func() ([]netlink.Link, error) {
		return nil, errors.New("netlink unavailable")
	}

	f := withBarrierRecorder(t)
	d := &Daemon{}
	d.setDataplane(&fenceRuntime10302{ifindexes: []int{101}})

	if err := d.applyTransitBarrier(true); err == nil {
		t.Fatal("armed transit must fail closed when kernel link provenance cannot be resolved")
	}
	if len(f.fenceCalls10302) != 0 {
		t.Fatalf("resolver failure must not install an armed fence: %v", f.fenceCalls10302)
	}
}

func TestArmedForwardFenceAllTrackedIfindexesUnresolvedKeepsGateClosed10302(t *testing.T) {
	oldLinks := transitFenceLinkList
	t.Cleanup(func() { transitFenceLinkList = oldLinks })
	transitFenceLinkList = func() ([]netlink.Link, error) {
		return []netlink.Link{
			&netlink.Tuntap{
				LinkAttrs: netlink.LinkAttrs{Name: armedTransitReinjectIfname, Index: 105},
				Mode:      netlink.TUNTAP_MODE_TUN,
			},
		}, nil
	}

	f := withBarrierRecorder(t)
	d := &Daemon{}
	d.setDataplane(&fenceRuntime10302{ifindexes: []int{101}})

	if err := d.applyTransitBarrier(true); err == nil {
		t.Fatal("armed transit must fail closed when all tracked XDP ifindexes are unresolved")
	}
	if len(f.fenceCalls10302) != 0 {
		t.Fatalf("unresolved XDP provenance must not install a fence with only xpf-usp1: %v", f.fenceCalls10302)
	}
}

func TestArmedFenceReassertFailureRestoresBarrier10302(t *testing.T) {
	withTempTransitForwardSysctls(t, "1")
	oldLinks := transitFenceLinkList
	t.Cleanup(func() { transitFenceLinkList = oldLinks })
	transitFenceLinkList = func() ([]netlink.Link, error) {
		return []netlink.Link{
			&netlink.Device{LinkAttrs: netlink.LinkAttrs{Name: "xdp-owned0", Index: 101}},
		}, nil
	}

	f := withBarrierRecorder(t)
	d := &Daemon{}
	d.setDataplane(&fenceRuntime10302{ifindexes: []int{101}})
	if err := d.applyTransitBarrier(true); err != nil {
		t.Fatalf("initial armed fence install: %v", err)
	}
	f.barrierCalls = nil
	transitFenceLinkList = func() ([]netlink.Link, error) {
		return nil, errors.New("link list failed during reassert")
	}

	if opened := d.writeTransitGateLocked("reassert", true); opened {
		t.Fatal("reassert with unresolved provenance must stay closed")
	}
	if got := lastBarrierCall(f); got != "install" {
		t.Fatalf("open-path failure must restore unconditional barrier, got %q (calls=%v)", got, f.barrierCalls)
	}
}

func TestUnarmedTransitBarrierRemainsUnconditional10302(t *testing.T) {
	f := withBarrierRecorder(t)
	d := &Daemon{}
	if err := d.applyTransitBarrier(false); err != nil {
		t.Fatalf("unarmed barrier install: %v", err)
	}
	if got := lastBarrierCall(f); got != "install" {
		t.Fatalf("unarmed transit must install the unconditional barrier, got %q", got)
	}
	if len(f.fenceCalls10302) != 0 {
		t.Fatalf("unarmed transit must not install an armed pinhole fence: %v", f.fenceCalls10302)
	}
}

type leasedFenceRuntime10302 struct {
	*fenceRuntime10302
}

func (r *leasedFenceRuntime10302) WithAttachedXDPFence(fn func([]int) error) error {
	return fn(r.ifindexes)
}

// TestArmedTransitUnsupportedBridgeKeepsGateClosed10725 is RED-on-revert for
// both armed-fence paths: bridge-family unsupported must propagate before
// either path raises the transit sysctls. Unlike ip_forward, bridge frames do
// not pass through the inet hook or obey the routing sysctl.
func TestArmedTransitUnsupportedBridgeKeepsGateClosed10725(t *testing.T) {
	for _, tc := range []struct {
		name    string
		runtime func() dataplane.RuntimeDataPlane
	}{
		{
			name: "without-XDP-lease",
			runtime: func() dataplane.RuntimeDataPlane {
				return &fenceRuntime10302{ifindexes: []int{101}}
			},
		},
		{
			name: "with-XDP-lease",
			runtime: func() dataplane.RuntimeDataPlane {
				return &leasedFenceRuntime10302{
					fenceRuntime10302: &fenceRuntime10302{ifindexes: []int{101}},
				}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v4, v6 := withTempTransitForwardSysctls(t, "0")
			oldLinks := transitFenceLinkList
			t.Cleanup(func() { transitFenceLinkList = oldLinks })
			transitFenceLinkList = func() ([]netlink.Link, error) {
				return []netlink.Link{
					&netlink.Device{LinkAttrs: netlink.LinkAttrs{Name: "xdp-owned0", Index: 101}},
				}, nil
			}

			f := withBarrierRecorder(t)
			injected := errors.Join(xnft.ErrTransitBarrierBridgeUnsupported)
			f.fenceInstall10302 = func(xnft.ForwardFenceSpec) error { return injected }
			d := &Daemon{}
			d.setDataplane(tc.runtime())

			if err := d.openTransitGateLocked(); !errors.Is(err, xnft.ErrTransitBarrierBridgeUnsupported) {
				t.Fatalf("openTransitGateLocked error = %v, want bridge barrier unsupported", err)
			}
			assertTransitForwarding(t, v4, v6, "0", "when the armed bridge barrier leg is unsupported")
			if len(f.fenceCalls10302) != 1 {
				t.Fatalf("armed fence install calls = %v, want one failed bridge-leg install", f.fenceCalls10302)
			}
		})
	}
}
