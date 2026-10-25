package daemon

import (
	"errors"
	"strings"
	"testing"

	xnft "github.com/psaab/xpf/pkg/nftables"
)

// #16703: the guarded-failure path must re-verify that a quarantine
// guard table actually exists before retiring the old actor. When the
// guard install itself failed (no guard was ever installed), one
// explicit guard install is attempted; the transition error must
// report when no guard could be verified.

func newGuardedDaemon16703(t *testing.T, fake *guardedFake14696) (*Daemon, *ipsecCaptureRuntime, *ipsecCaptureRuntime) {
	t.Helper()
	orig := nftInstaller
	t.Cleanup(func() { nftInstaller = orig })
	nftInstaller = fake
	old := &ipsecCaptureRuntime{}
	staged := stagedIpsecCaptureRuntime9506(t)
	d := &Daemon{ipsecCapture: old, ipsecCaptureStaged: staged, ipsecCaptureStagePending: true}
	return d, old, staged
}

func TestGuardedFailureReverifiesGuardPresent16703(t *testing.T) {
	// Guard verifies on readback: no explicit install is attempted.
	fake := &guardedFake14696{guardedErr: errors.New("guarded transition failed")}
	fake.quarantineVerify = func() error { return nil }
	d, old, staged := newGuardedDaemon16703(t, fake)
	err := d.commitIpsecCaptureStage(old, staged)
	if err == nil || !strings.Contains(err.Error(), "guarded divert transition") {
		t.Fatalf("err = %v, want guarded transition failure", err)
	}
	if strings.Contains(err.Error(), "no quarantine guard verified") {
		t.Fatalf("err = %v, guard verified so no unverified marker expected", err)
	}
	if fake.quarantineVerifyCalls != 1 {
		t.Fatalf("verify calls = %d, want 1", fake.quarantineVerifyCalls)
	}
	if len(fake.quarantineCalls) != 0 {
		t.Fatalf("quarantine installs = %v, want none when guard verifies", fake.quarantineCalls)
	}
	if !d.ipsecKernelQuarantineOrphaned() {
		t.Fatal("orphan flag not set after failed guarded transition")
	}
}

func TestGuardedFailureInstallsGuardWhenAbsent16703(t *testing.T) {
	// Guard absent on readback but explicit install succeeds.
	fake := &guardedFake14696{guardedErr: errors.New("guarded transition failed")}
	fake.quarantineVerify = func() error { return errors.New("guard table missing") }
	d, old, staged := newGuardedDaemon16703(t, fake)
	err := d.commitIpsecCaptureStage(old, staged)
	if err == nil || !strings.Contains(err.Error(), "guarded divert transition") {
		t.Fatalf("err = %v, want guarded transition failure", err)
	}
	if strings.Contains(err.Error(), "no quarantine guard verified") {
		t.Fatalf("err = %v, explicit install succeeded so no unverified marker expected", err)
	}
	if fake.quarantineVerifyCalls != 1 {
		t.Fatalf("verify calls = %d, want 1", fake.quarantineVerifyCalls)
	}
	if len(fake.quarantineCalls) != 1 {
		t.Fatalf("quarantine installs = %v, want one explicit install", fake.quarantineCalls)
	}
}

func TestGuardedFailureReportsUnverifiedGuard16703(t *testing.T) {
	// Guard absent and explicit install also fails: the returned error
	// must say no guard was verified, and the old actor is still
	// retired with the orphan flag set (never silent).
	fake := &guardedFake14696{guardedErr: errors.New("guarded transition failed")}
	fake.quarantineVerify = func() error { return errors.New("guard table missing") }
	fake.quarantineGuard = func(xnft.IpsecDivertSpec) error { return errors.New("guard install failed") }
	d, old, staged := newGuardedDaemon16703(t, fake)
	err := d.commitIpsecCaptureStage(old, staged)
	if err == nil || !strings.Contains(err.Error(), "no quarantine guard verified") {
		t.Fatalf("err = %v, want unverified-guard marker", err)
	}
	if len(fake.quarantineCalls) != 1 {
		t.Fatalf("quarantine installs = %v, want one explicit install attempt", fake.quarantineCalls)
	}
	if !d.ipsecKernelQuarantineOrphaned() {
		t.Fatal("orphan flag not set after unverified guarded failure")
	}
	if d.ipsecCapture != nil {
		t.Fatalf("active = %p, want nil after guarded failure", d.ipsecCapture)
	}
}
