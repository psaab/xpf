package daemon

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	xnft "github.com/psaab/xpf/pkg/nftables"
)

// #16618: every QuarantineAll guard the daemon builds from a normal
// (lifeline-free) staged/old/active spec must record lifelines [fxp0]
// at the installer seam. HostInboundLifelineIngressNetdevs always
// contains fxp0, so even with no live config the fallback guard must
// not be lifeline-free.

func hasFxp016618(names []string) bool {
	for _, n := range names {
		if n == "fxp0" {
			return true
		}
	}
	return false
}

func TestIpsecQuarantineFallbackRecordsFxp016618(t *testing.T) {
	// Unit seam: the stamping helper itself.
	d := &Daemon{}
	got := d.withIpsecQuarantineLifelines16618(xnft.IpsecDivertSpec{
		InetInput: []xnft.IpsecDivertRule{{Ifname: "st0", Queue: 1002}},
	}, nil)
	if !got.QuarantineAll || !hasFxp016618(got.LifelineNetdevs) {
		t.Fatalf("stamped fallback = %+v, want QuarantineAll with fxp0 lifeline", got)
	}
	// A spec already carrying lifelines keeps them (no widening to a
	// different set, no duplicate stamping).
	custom := d.withIpsecQuarantineLifelines16618(xnft.IpsecDivertSpec{
		LifelineNetdevs: []string{"em0"},
	}, &config.Config{})
	if len(custom.LifelineNetdevs) != 1 || custom.LifelineNetdevs[0] != "em0" {
		t.Fatalf("pre-stamped lifelines overwritten: %v", custom.LifelineNetdevs)
	}
}

func TestIpsecAmbiguousRemovalFallbackRecordsFxp016618(t *testing.T) {
	removeErr := errString16618("remove ACK lost after flush")
	readbackErr := errString16618("host-input fence readback unavailable")
	d, fake, events := newF1CaptureFenceTestEnv(t, true, removeErr)
	old := d.ipsecCapture
	originalRemove := fake.divertRemove
	divertAbsent := false
	fake.divertRemove = func() error {
		err := originalRemove()
		divertAbsent = true
		return err
	}
	verifyExact := fake.overlayReadback
	readbacks := 0
	fake.overlayReadback = func(overlay xnft.HostInputFenceOverlay) error {
		readbacks++
		if readbacks == 1 {
			return verifyExact(overlay)
		}
		*events = append(*events, "readback")
		return readbackErr
	}
	var guardSpec xnft.IpsecDivertSpec
	fake.quarantineGuard = func(spec xnft.IpsecDivertSpec) error {
		if !divertAbsent || !spec.QuarantineAll {
			return errString16618("fallback did not install a DROP guard after ambiguous divert removal")
		}
		guardSpec = spec
		*events = append(*events, "quarantine")
		return nil
	}
	err := commitIpsecCaptureStageF1(t, d, old)
	if err == nil || !strings.Contains(err.Error(), removeErr.Error()) {
		t.Fatalf("ambiguous removal error = %v, want removal failure", err)
	}
	if !hasFxp016618(guardSpec.LifelineNetdevs) {
		t.Fatalf("ambiguous-removal fallback guard lifelines = %v, want [fxp0]", guardSpec.LifelineNetdevs)
	}
}

func TestIpsecShutdownFallbackRecordsFxp016618(t *testing.T) {
	removeErr := errString16618("shutdown remove ACK lost")
	readbackErr := errString16618("shutdown fence readback unavailable")
	d, fake, events := newF1CaptureFenceTestEnv(t, true, removeErr)
	originalRemove := fake.divertRemove
	divertAbsent := false
	fake.divertRemove = func() error {
		err := originalRemove()
		divertAbsent = true
		return err
	}
	verifyExact := fake.overlayReadback
	readbacks := 0
	fake.overlayReadback = func(overlay xnft.HostInputFenceOverlay) error {
		readbacks++
		if readbacks == 1 {
			return verifyExact(overlay)
		}
		*events = append(*events, "readback")
		return readbackErr
	}
	var guardSpec xnft.IpsecDivertSpec
	fake.quarantineGuard = func(spec xnft.IpsecDivertSpec) error {
		if !divertAbsent || !spec.QuarantineAll {
			return errString16618("shutdown fallback did not install DROP guard after ambiguous removal")
		}
		guardSpec = spec
		*events = append(*events, "quarantine")
		return nil
	}
	d.shutdownIpsecCapture()
	if !hasFxp016618(guardSpec.LifelineNetdevs) {
		t.Fatalf("shutdown fallback guard lifelines = %v, want [fxp0]", guardSpec.LifelineNetdevs)
	}
}

// Normal staged specs now keep plan lifelines (#16618 finalize change):
// a valid-VPN stage must carry fxp0 on its (non-quarantine) spec so the
// installer's transition guard inherits it.
func TestIpsecNormalPlanKeepsLifelines16618(t *testing.T) {
	plan := ipsecCaptureQueuePlan{cfg: &config.Config{}}
	plan.finalize(3)
	if plan.Quarantine.QuarantineAll {
		t.Fatalf("empty plan quarantined: %+v", plan.Quarantine)
	}
	if !hasFxp016618(plan.Quarantine.LifelineNetdevs) {
		t.Fatalf("normal plan lifelines = %v, want fxp0 retained", plan.Quarantine.LifelineNetdevs)
	}
	if len(plan.Quarantine.CandidateIfindices) != 0 {
		t.Fatalf("normal plan retained candidates %v, want cleared", plan.Quarantine.CandidateIfindices)
	}
}

type errString16618 string

func (e errString16618) Error() string { return string(e) }
