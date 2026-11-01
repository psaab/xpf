package daemon

import (
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	xnft "github.com/psaab/xpf/pkg/nftables"
	"golang.org/x/sync/semaphore"
)

// #18746 end to end: the daemon's kernel-truth recheck and the early-barrier
// handoff re-verify decide on TableEnforcing / TableDropsInput. Since #16841
// every xpf input chain carries the zero-hop DROP. Before the fix, a table
// holding ONLY that rule read as enforcing, so drift went undetected and the
// handoff went ahead over an empty shell.
//
// The zero-hop-only table here is the one production really renders: an lo0
// filter with no terms (InstallLo0(Lo0FilterSpec{}) emits just the zero-hop
// rule). Its twin adds one real enforcing term.

func lo0EnforcingSpec18746() xnft.Lo0FilterSpec {
	return xnft.Lo0FilterSpec{V4Terms: []xnft.Lo0FilterTerm{{
		Name: "deny-telnet", Protocols: []string{"tcp"}, DestinationPorts: []string{"23"}, Action: "discard",
	}}}
}

func realKernelInstaller18746(t *testing.T) xnft.Installer {
	t.Helper()
	enterPrivateNetns9813(t)
	installer := xnft.NewNetlinkInstaller()
	orig := nftInstaller
	nftInstaller = installer
	t.Cleanup(func() {
		nftInstaller = orig
		_ = installer.DeleteTable(xnft.Lo0TableName)
		_ = installer.DeleteTable(xnft.HostInboundTableName)
		_ = installer.RemoveEarlyInputBarrier()
	})
	// A real host-inbound table with a real catch-all DROP, so the host-inbound
	// arm of the recheck stands in both cases and only lo0 varies.
	if err := installer.InstallHostInbound(xnft.HostInboundSpec{Views: []xnft.HostInboundZoneView{{
		Zone: "trust", SystemServices: []string{"ssh"}, V4Addrs: []string{"192.0.2.1"},
	}}}); err != nil {
		t.Fatalf("install host-inbound: %v", err)
	}
	return installer
}

func TestKernelTruthDeclaresDriftOnAZeroHopOnlyTable18746(t *testing.T) {
	installer := realKernelInstaller18746(t)

	// A table holding only the zero-hop rule: drift.
	if _, err := installer.InstallLo0(xnft.Lo0FilterSpec{}); err != nil {
		t.Fatalf("install empty lo0 filter: %v", err)
	}
	d := hostDriftDaemon15264()
	d.recheckHostKernelTruth15264(time.Now())
	if d.lo0Enforced.Load() || !d.lo0LastFailed.Load() {
		t.Errorf("an lo0 table holding only the zero-hop rule was read as a real filter: lo0Enforced=%v lo0LastFailed=%v",
			d.lo0Enforced.Load(), d.lo0LastFailed.Load())
	}
	if !d.HostInboundApplied().Current() {
		t.Errorf("control: the host-inbound table (zero-hop plus a real DROP) must stand: %+v", d.HostInboundApplied())
	}

	// The twin: the zero-hop rule plus a real enforcing term stands.
	if _, err := installer.InstallLo0(lo0EnforcingSpec18746()); err != nil {
		t.Fatalf("install enforcing lo0 filter: %v", err)
	}
	d = hostDriftDaemon15264()
	d.recheckHostKernelTruth15264(time.Now())
	if !d.lo0Enforced.Load() || d.lo0LastFailed.Load() {
		t.Errorf("an lo0 table with a real term was read as drift: lo0Enforced=%v lo0LastFailed=%v",
			d.lo0Enforced.Load(), d.lo0LastFailed.Load())
	}
	if !d.HostInboundApplied().Current() {
		t.Errorf("control: the host-inbound table must stand: %+v", d.HostInboundApplied())
	}
}

// The handoff re-verify (input_barrier_gate_10751.go): after removing the
// early barrier, every expected table must still enforce. Otherwise the
// guard is reinstalled and the handoff refused.
func TestHandoffReverifyRefusesAZeroHopOnlyTable18746(t *testing.T) {
	installer := realKernelInstaller18746(t)
	cfg := &config.Config{}
	handoff := func() (error, bool) {
		t.Helper()
		if err := installer.InstallEarlyInputBarrier(); err != nil {
			t.Fatalf("install early barrier: %v", err)
		}
		d := &Daemon{applySem: semaphore.NewWeighted(1)}
		err := d.removeEarlyInputBarrierAtHandoff(cfg, []string{xnft.Lo0TableName}, map[string]struct{}{})
		present, perr := installer.EarlyInputBarrierPresent()
		if perr != nil {
			t.Fatalf("read early barrier: %v", perr)
		}
		return err, present
	}

	if _, err := installer.InstallLo0(xnft.Lo0FilterSpec{}); err != nil {
		t.Fatalf("install empty lo0 filter: %v", err)
	}
	err, present := handoff()
	if err == nil || !strings.Contains(err.Error(), "missing after barrier removal") || !present {
		t.Errorf("handoff over a zero-hop-only table = %v (barrier present=%v); want refused with the guard reinstalled", err, present)
	}

	if _, err := installer.InstallLo0(lo0EnforcingSpec18746()); err != nil {
		t.Fatalf("install enforcing lo0 filter: %v", err)
	}
	err, present = handoff()
	if err != nil || present {
		t.Errorf("handoff over an enforcing table = %v (barrier present=%v); want it to proceed with the barrier removed", err, present)
	}
}
