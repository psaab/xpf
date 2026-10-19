package daemon

import (
	"errors"
	"strings"
	"testing"
	"time"

	xnft "github.com/psaab/xpf/pkg/nftables"
)

// #15264 (B06-02): the host-inbound applied state is a latch — after `nft flush
// ruleset` (accepted operator action, xpf-input-closed.service:22-26) the
// kernel tables are gone but HostInboundApplied still reports Current.
// The low-rate kernel-truth recheck must mark it stale (and Warn once).

func hostDriftDaemon15264() *Daemon {
	d := &Daemon{}
	d.hostInboundEnforced.Store(true)
	d.noteHostInboundApplySucceeded()
	d.lo0Enforced.Store(true)
	return d
}

func TestKernelTruthDriftMarksHostInboundStale15264(t *testing.T) {
	orig := nftInstaller
	t.Cleanup(func() { nftInstaller = orig })
	d := hostDriftDaemon15264()
	if !d.HostInboundApplied().Current() {
		t.Fatalf("precondition: want Current, got %+v", d.HostInboundApplied())
	}
	// Out-of-band flush: kernel reports no DROP on either table.
	nftInstaller = &fakeNftInstaller{
		tableDropsInput: func(string) (bool, error) { return false, nil },
		tableEnforcing:  func(string) (bool, error) { return false, nil },
	}
	buf, restore := captureSlog(t)
	defer restore()
	d.recheckHostKernelTruth15264(time.Now())
	st := d.HostInboundApplied()
	if st.Current() {
		t.Fatalf("after flush, probe still Current: %+v (B06-02 stale status)", st)
	}
	if !st.LastApplyFailed {
		t.Fatalf("after flush, LastApplyFailed must be true: %+v", st)
	}
	if d.lo0Enforced.Load() {
		t.Fatalf("after flush, lo0Enforced must clear (table gone): %+v", st)
	}
	if !d.lo0LastFailed.Load() {
		t.Fatal("after flush, lo0LastFailed must be true")
	}
	if !strings.Contains(buf.String(), "15264") {
		t.Fatalf("expected Warn log naming #15264 on drift, got: %q", buf.String())
	}
	// Idempotent: second check stays stale, no panic.
	d.recheckHostKernelTruth15264(time.Now())
	if d.HostInboundApplied().Current() {
		t.Fatal("second check resurrected Current")
	}
}

func TestKernelTruthPresentKeepsCurrent15264(t *testing.T) {
	orig := nftInstaller
	t.Cleanup(func() { nftInstaller = orig })
	d := hostDriftDaemon15264()
	nftInstaller = &fakeNftInstaller{} // defaults: drops=true, enforcing=true
	d.recheckHostKernelTruth15264(time.Now())
	if !d.HostInboundApplied().Current() {
		t.Fatalf("control: tables present must stay Current: %+v", d.HostInboundApplied())
	}
}

// Program-only host-inbound generation: DROPs live in junos-host subchains,
// so TableDropsInput reads false but the table IS enforcing by shape. Must
// stay Current — a false stale here would lie in the opposite direction.
func TestKernelTruthProgramOnlyStaysCurrent15264(t *testing.T) {
	orig := nftInstaller
	t.Cleanup(func() { nftInstaller = orig })
	d := hostDriftDaemon15264()
	nftInstaller = &fakeNftInstaller{
		tableDropsInput: func(string) (bool, error) { return false, nil },
		tableEnforcing:  func(string) (bool, error) { return true, nil },
	}
	d.recheckHostKernelTruth15264(time.Now())
	if !d.HostInboundApplied().Current() {
		t.Fatalf("program-only (enforcing, subchain DROPs) must stay Current: %+v", d.HostInboundApplied())
	}
}

// lo0-only drift: never-established host-inbound is untouched, while an
// established lo0 table that vanished clears its latch.
func TestKernelTruthLo0DriftOnly15264(t *testing.T) {
	orig := nftInstaller
	t.Cleanup(func() { nftInstaller = orig })
	d := &Daemon{}
	d.lo0Enforced.Store(true)
	nftInstaller = &fakeNftInstaller{
		tableDropsInput: func(string) (bool, error) { return false, nil },
		tableEnforcing:  func(name string) (bool, error) { return name != xnft.Lo0TableName, nil },
	}
	d.recheckHostKernelTruth15264(time.Now())
	if d.lo0Enforced.Load() {
		t.Fatal("lo0Enforced must clear when xpf_lo0 vanished")
	}
	if d.HostInboundApplied().LastApplyFailed {
		t.Fatal("never-established host-inbound must not be marked stale")
	}
}

func TestKernelTruthNotEstablishedIsNoop15264(t *testing.T) {
	orig := nftInstaller
	t.Cleanup(func() { nftInstaller = orig })
	d := &Daemon{} // nothing established, nothing configured
	calls := 0
	nftInstaller = &fakeNftInstaller{
		tableDropsInput: func(string) (bool, error) { calls++; return false, nil },
		tableEnforcing:  func(string) (bool, error) { calls++; return false, nil },
	}
	d.recheckHostKernelTruth15264(time.Now())
	if calls != 0 {
		t.Fatalf("no established/configured surface must not probe kernel, calls=%d", calls)
	}
	if d.HostInboundApplied().LastApplyFailed {
		t.Fatal("cold daemon must not be marked stale")
	}
}

func TestKernelTruthReadErrorKeepsCurrent15264(t *testing.T) {
	orig := nftInstaller
	t.Cleanup(func() { nftInstaller = orig })
	d := hostDriftDaemon15264()
	nftInstaller = &fakeNftInstaller{
		tableDropsInput: func(string) (bool, error) { return false, errors.New("netlink boom") },
		tableEnforcing:  func(string) (bool, error) { return false, errors.New("netlink boom") },
	}
	d.recheckHostKernelTruth15264(time.Now())
	if !d.HostInboundApplied().Current() {
		t.Fatalf("read error must not mark stale (unreadable proves nothing): %+v", d.HostInboundApplied())
	}
	_ = xnft.HostInboundTableName
}
