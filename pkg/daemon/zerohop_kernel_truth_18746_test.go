package daemon

import (
	"errors"
	"strings"
	"testing"
	"time"

	gnft "github.com/google/nftables"
	"github.com/google/nftables/expr"
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

	// The host-inbound arm (AD on #18759): strip the real host-inbound table
	// down to ONLY its own zero-hop rule. Every other input rule is deleted
	// by handle, so xpf's exact encoding of the zero-hop rule stays. Kernel
	// truth must then declare host-inbound drift. Before #18746,
	// TableDropsInput counted the zero-hop DROP, so this table "stood".
	c, err := gnft.New()
	if err != nil {
		t.Fatalf("conn: %v", err)
	}
	tbl := &gnft.Table{Family: gnft.TableFamilyINet, Name: xnft.HostInboundTableName}
	chain := &gnft.Chain{Name: "input", Table: tbl}
	rules, err := c.GetRules(tbl, chain)
	if err != nil || len(rules) < 2 {
		t.Fatalf("read the real host-inbound chain: %d rules, %v", len(rules), err)
	}
	zeroHop := false
	for _, e := range rules[0].Exprs {
		if _, ok := e.(*expr.Fib); ok {
			zeroHop = true
		}
	}
	if !zeroHop {
		t.Fatalf("fixture: host-inbound rule 0 is not the zero-hop DROP: %#v", rules[0].Exprs)
	}
	for _, r := range rules[1:] {
		if err := c.DelRule(&gnft.Rule{Table: tbl, Chain: chain, Handle: r.Handle}); err != nil {
			t.Fatalf("queue delete of handle %d: %v", r.Handle, err)
		}
	}
	if err := c.Flush(); err != nil {
		t.Fatalf("strip host-inbound to the zero-hop rule: %v", err)
	}
	d = hostDriftDaemon15264()
	d.recheckHostKernelTruth15264(time.Now())
	if d.HostInboundApplied().Current() || d.hostInboundEnforced.Load() {
		t.Errorf("a host-inbound table holding only the zero-hop rule was not drift: applied=%+v enforced=%v",
			d.HostInboundApplied(), d.hostInboundEnforced.Load())
	}
}

// AD on #18759: an unreadable kernel-truth pass stays Current, so a probe that
// is stuck unreadable must still be visible. Each unreadable pass logs at
// Debug, and the third consecutive one logs a single Warn. A readable pass
// resets the count.
func TestKernelTruthStuckUnreadableIsVisible18746(t *testing.T) {
	orig := nftInstaller
	t.Cleanup(func() { nftInstaller = orig })
	readErr := errors.New("generation changed during readback")
	failing := true
	nftInstaller = &fakeNftInstaller{
		tableDropsInput: func(string) (bool, error) {
			if failing {
				return false, readErr
			}
			return true, nil
		},
		tableEnforcing: func(string) (bool, error) {
			if failing {
				return false, readErr
			}
			return true, nil
		},
	}
	d := hostDriftDaemon15264()
	buf, restore := captureSlog(t)
	defer restore()
	for i := 0; i < 5; i++ {
		d.recheckHostKernelTruth15264(time.Now())
	}
	if !d.HostInboundApplied().Current() || !d.lo0Enforced.Load() {
		t.Fatalf("unreadable passes must stay Current: %+v lo0=%v", d.HostInboundApplied(), d.lo0Enforced.Load())
	}
	out := buf.String()
	if got := strings.Count(out, "drift detection is blind"); got != 1 {
		t.Errorf("stuck-unreadable Warn logged %d times over 5 unreadable passes, want exactly 1:\n%s", got, out)
	}
	if got := strings.Count(out, "could not read the kernel"); got != 5 {
		t.Errorf("unreadable Debug logged %d times over 5 passes, want 5", got)
	}
	// A readable pass resets the count; the next episode warns again.
	failing = false
	d.recheckHostKernelTruth15264(time.Now())
	if d.hostKernelTruthUnreadable18746.Load() != 0 {
		t.Errorf("a readable pass left the unreadable count at %d", d.hostKernelTruthUnreadable18746.Load())
	}
	failing = true
	buf.Reset()
	for i := 0; i < 3; i++ {
		d.recheckHostKernelTruth15264(time.Now())
	}
	if got := strings.Count(buf.String(), "drift detection is blind"); got != 1 {
		t.Errorf("the second stuck-unreadable episode logged %d Warns, want 1", got)
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

// emptyLo0Renderer18746 stands in for a renderer that drifts from the
// daemon's preflight: it installs an EMPTY lo0 spec through the REAL netlink
// installer and reports that installer's real count. The daemon preflight
// still predicts real rules.
type emptyLo0Renderer18746 struct{ xnft.Installer }

func (e emptyLo0Renderer18746) InstallLo0(xnft.Lo0FilterSpec) (int, error) {
	return e.Installer.InstallLo0(xnft.Lo0FilterSpec{})
}

// #18746 fix 3, end to end: the daemon's empty-shell guard (daemon_nft.go,
// "rendered no rules") keys on InstallLo0's count. Since #16841 an empty
// render still carried the zero-hop rule and counted 1, so the guard could
// never fire. The daemon then recorded an empty policy-accept shell as a real
// operator filter (lo0Enforced) and installed no fence.
func TestLo0EmptyShellGuardFiresOnTheRealInstaller18746(t *testing.T) {
	installer := realKernelInstaller18746(t)
	nftInstaller = emptyLo0Renderer18746{installer}
	cfg := lo0FenceTestConfig()
	d := &Daemon{}
	err := d.applyLo0Filter(cfg)
	if err == nil || !strings.Contains(err.Error(), "rendered no rules") {
		t.Fatalf("an empty real render = %v, want the daemon_nft.go zero-rule guard (\"rendered no rules\")", err)
	}
	if d.lo0Enforced.Load() {
		t.Error("an empty policy-accept shell was recorded as a real lo0 filter")
	}
	// The guard's fail-closed step installs the cold-boot fence over the shell.
	if enforcing, err := installer.TableEnforcing(xnft.Lo0TableName); err != nil || !enforcing {
		t.Errorf("after the guard, the lo0 table must be the enforcing cold-boot fence: enforcing=%v, %v", enforcing, err)
	}
}
