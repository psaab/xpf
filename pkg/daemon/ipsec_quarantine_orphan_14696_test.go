package daemon

import (
	"errors"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	xnft "github.com/psaab/xpf/pkg/nftables"
)

// #14696 orphan arm: a failed guarded transition retains kernel
// quarantine/divert tables while restore(nil) clears the runtimes.
// The residency flag must survive that, so (a) an empty-VPN
// stage+commit and (b) shutdown both still attempt removal.

type guardedFake14696 struct {
	fakeNftInstaller
	guardedErr error
}

func (g *guardedFake14696) InstallIpsecDivertWithDrain(spec xnft.IpsecDivertSpec, drain func() error) error {
	g.divertCalls = append(g.divertCalls, "guarded")
	if drain != nil {
		if err := drain(); err != nil {
			return err
		}
	}
	return g.guardedErr
}

func TestIpsecQuarantineOrphanEmptyStageCommitRemoves14696(t *testing.T) {
	orig := nftInstaller
	t.Cleanup(func() { nftInstaller = orig })
	injected := errors.New("guarded transition failed")
	fake := &guardedFake14696{guardedErr: injected}
	nftInstaller = fake

	old := &ipsecCaptureRuntime{}
	staged := stagedIpsecCaptureRuntime9506(t)
	d := &Daemon{ipsecCapture: old, ipsecCaptureStaged: staged, ipsecCaptureStagePending: true}
	if err := d.commitIpsecCaptureStage(old, staged); err == nil {
		t.Fatal("guarded failure was swallowed")
	}
	if !d.ipsecKernelQuarantineOrphaned() {
		t.Fatal("orphan flag not set after failed guarded transition with restore(nil)")
	}
	if d.ipsecCapture != nil {
		t.Fatalf("active = %p, want nil after guarded failure", d.ipsecCapture)
	}

	// (a) empty-VPN stage + commit must attempt removal.
	old2, staged2, err := d.stageIpsecCapture(&config.Config{})
	if err != nil {
		t.Fatalf("empty stage: %v", err)
	}
	if staged2 != nil {
		t.Fatalf("empty stage staged = %p, want nil", staged2)
	}
	_ = old2
	if err := d.commitIpsecCaptureStage(old2, staged2); err != nil {
		t.Fatalf("empty commit after orphan: %v", err)
	}
	if !strings.Contains(strings.Join(fake.divertCalls, ","), "remove") {
		t.Fatalf("divert calls = %v, want a remove after orphaned empty commit", fake.divertCalls)
	}
	if d.ipsecKernelQuarantineOrphaned() {
		t.Fatal("orphan flag not cleared after successful removal")
	}
}

func TestIpsecQuarantineOrphanShutdownRemoves14696(t *testing.T) {
	orig := nftInstaller
	t.Cleanup(func() { nftInstaller = orig })
	injected := errors.New("guarded transition failed")
	fake := &guardedFake14696{guardedErr: injected}
	nftInstaller = fake

	old := &ipsecCaptureRuntime{}
	staged := stagedIpsecCaptureRuntime9506(t)
	d := &Daemon{ipsecCapture: old, ipsecCaptureStaged: staged, ipsecCaptureStagePending: true}
	if err := d.commitIpsecCaptureStage(old, staged); err == nil {
		t.Fatal("guarded failure was swallowed")
	}
	// (b) shutdown with active==nil && staged==nil must still remove.
	d.shutdownIpsecCapture()
	if !strings.Contains(strings.Join(fake.divertCalls, ","), "remove") {
		t.Fatalf("divert calls = %v, want a remove on orphaned shutdown", fake.divertCalls)
	}
	if d.ipsecKernelQuarantineOrphaned() {
		t.Fatal("orphan flag not cleared after shutdown removal")
	}
}

func TestIpsecQuarantineStageCarriesLifelines14696(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.IPsec.VPNs = map[string]*config.IPsecVPN{
		"vpn-a": {BindInterface: ""},
	}
	d := &Daemon{}
	_, staged, err := d.stageIpsecCapture(cfg)
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
	if staged == nil {
		t.Fatal("staged quarantine runtime is nil")
	}
	found := false
	for _, n := range staged.spec.LifelineNetdevs {
		if n == "fxp0" {
			found = true
		}
	}
	if !found {
		t.Fatalf("staged quarantine lifelines = %v, want fxp0 included", staged.spec.LifelineNetdevs)
	}
}
