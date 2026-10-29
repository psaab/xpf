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

// #17750: when the guarded install fails before invoking drain, the
// old divert table and its actor are still the active authority. A
// failed guard readback plus failed explicit install must not stop that
// actor or clear the published runtime. The post-drain control below
// continues to pin retirement after the old actor has been drained.
type preDrainGuardFailureInstaller17750 struct {
	fakeNftInstaller
	guardedErr error
}

func (g *preDrainGuardFailureInstaller17750) InstallIpsecDivertWithDrain(_ xnft.IpsecDivertSpec, _ func() error) error {
	g.divertCalls = append(g.divertCalls, "guarded")
	return g.guardedErr
}

func TestGuardedFailureBeforeDrainKeepsOldActor17750(t *testing.T) {
	fake := &preDrainGuardFailureInstaller17750{guardedErr: errors.New("quarantine guard install failed")}
	fake.quarantineVerify = func() error { return errors.New("guard table missing") }
	fake.quarantineGuard = func(xnft.IpsecDivertSpec) error { return errors.New("guard install failed") }
	orig := nftInstaller
	t.Cleanup(func() { nftInstaller = orig })
	nftInstaller = fake

	old := stagedIpsecCaptureRuntime9506(t)
	if err := old.actor.Start(); err != nil {
		t.Fatalf("start old actor: %v", err)
	}
	t.Cleanup(func() { _ = old.close() })
	staged := stagedIpsecCaptureRuntime9506(t)
	d := &Daemon{ipsecCapture: old, ipsecCaptureStaged: staged, ipsecCaptureStagePending: true}
	err := d.commitIpsecCaptureStage(old, staged)
	if err == nil || !strings.Contains(err.Error(), "no quarantine guard verified") {
		t.Fatalf("err = %v, want unverified-guard marker", err)
	}
	if len(fake.quarantineCalls) != 1 {
		t.Fatalf("quarantine installs = %v, want one explicit install attempt", fake.quarantineCalls)
	}
	if !old.actor.Status().Active {
		t.Fatal("old actor stopped after a pre-drain failure without a verified guard")
	}
	if d.ipsecCapture != old {
		t.Fatalf("active = %p, want retained old runtime %p", d.ipsecCapture, old)
	}
	if d.ipsecCaptureStaged != nil || d.ipsecCaptureStagePending {
		t.Fatalf("staged = %p pending=%v, want staged state cleared", d.ipsecCaptureStaged, d.ipsecCaptureStagePending)
	}
	if d.ipsecKernelQuarantineOrphaned() {
		t.Fatal("orphan flag set although the old divert still points at live listeners")
	}
}

func TestGuardedFailureAfterDrainStillRetiresOldActor17750(t *testing.T) {
	fake := &guardedFake14696{guardedErr: errors.New("guarded transition failed")}
	fake.quarantineVerify = func() error { return nil }
	d, old, staged := newGuardedDaemon16703(t, fake)
	old.actor = stagedIpsecCaptureRuntime9506(t).actor
	if err := old.actor.Start(); err != nil {
		t.Fatalf("start old actor: %v", err)
	}
	err := d.commitIpsecCaptureStage(old, staged)
	if err == nil || !strings.Contains(err.Error(), "guarded divert transition") {
		t.Fatalf("err = %v, want guarded transition failure", err)
	}
	if old.actor.Status().Active {
		t.Fatal("old actor remains active although the drain callback retired it")
	}
	if d.ipsecCapture != nil {
		t.Fatalf("active = %p, want nil after drained guarded failure", d.ipsecCapture)
	}
	if !d.ipsecKernelQuarantineOrphaned() {
		t.Fatal("orphan flag not set after drained guarded failure")
	}
}

// #17750 drained+unverified control: the drain callback ran, then both
// guard readback and the explicit fallback install fail. Retention is
// no longer sound (the old actor is mid/fully torn down), so the old
// actor is retired, the published runtime is cleared, and orphaned
// kernel tables are recorded — the pre-#17750 drained semantics. This
// cell discriminates the drain gate directly: weakening the retention
// condition to !guardVerified alone flips it.
func TestGuardedFailureAfterDrainUnverifiedStillRetiresOldActor17750(t *testing.T) {
	fake := &guardedFake14696{guardedErr: errors.New("guarded transition failed")}
	fake.quarantineVerify = func() error { return errors.New("guard table missing") }
	fake.quarantineGuard = func(xnft.IpsecDivertSpec) error { return errors.New("guard install failed") }
	d, old, staged := newGuardedDaemon16703(t, fake)
	old.actor = stagedIpsecCaptureRuntime9506(t).actor
	if err := old.actor.Start(); err != nil {
		t.Fatalf("start old actor: %v", err)
	}
	err := d.commitIpsecCaptureStage(old, staged)
	if err == nil || !strings.Contains(err.Error(), "no quarantine guard verified") {
		t.Fatalf("err = %v, want unverified-guard marker", err)
	}
	if len(fake.quarantineCalls) != 1 {
		t.Fatalf("quarantine installs = %v, want one explicit install attempt", fake.quarantineCalls)
	}
	if old.actor.Status().Active {
		t.Fatal("old actor remains active although the drain callback retired it")
	}
	if d.ipsecCapture != nil {
		t.Fatalf("active = %p, want nil after drained unverified failure", d.ipsecCapture)
	}
	if !d.ipsecKernelQuarantineOrphaned() {
		t.Fatal("orphan flag not set after drained unverified failure")
	}
}
