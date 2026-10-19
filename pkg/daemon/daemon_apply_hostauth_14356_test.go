package daemon

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	"github.com/psaab/xpf/pkg/networkd"
	xnft "github.com/psaab/xpf/pkg/nftables"
	"github.com/psaab/xpf/pkg/vrrp"
	"github.com/vishvananda/netlink"
)

// closeoutInstaller14356 counts host-authorization nft activity and captures
// the specs the closeout renders. refuseBarrier drives the #10751 naming gate
// refusal used by the bootstrap subtest.
type closeoutInstaller14356 struct {
	calls         int
	hostSpecs     []xnft.HostInboundSpec
	gapSpecs      []xnft.GapFenceSpec
	refuseBarrier bool
	failLifeline  bool
	failGap       bool
}

func (c *closeoutInstaller14356) VerifyHostInboundOverlay(xnft.HostInputFenceOverlay) error {
	c.calls++
	return nil
}
func (c *closeoutInstaller14356) InstallEarlyInputBarrier() error { c.calls++; return nil }
func (c *closeoutInstaller14356) RemoveEarlyInputBarrier() error  { c.calls++; return nil }
func (c *closeoutInstaller14356) EarlyInputBarrierPresent() (bool, error) {
	return !c.refuseBarrier, nil
}
func (c *closeoutInstaller14356) InstallEarlyInputBarrierWithLifelineAdmit([]string) error {
	if c.refuseBarrier || c.failLifeline {
		return errors.New("guard reinstall failed")
	}
	return nil
}
func (c *closeoutInstaller14356) InstallHostInbound(s xnft.HostInboundSpec) error {
	c.calls++
	c.hostSpecs = append(c.hostSpecs, s)
	return nil
}
func (c *closeoutInstaller14356) InstallColdBootFence(xnft.FenceSpec) error {
	c.calls++
	return nil
}
func (c *closeoutInstaller14356) InstallLo0ColdBootFence(xnft.FenceSpec) error {
	c.calls++
	return nil
}
func (c *closeoutInstaller14356) InstallGapFence(s xnft.GapFenceSpec) error {
	c.calls++
	if c.failGap {
		return errors.New("gap fence install failed")
	}
	c.gapSpecs = append(c.gapSpecs, s)
	return nil
}
func (c *closeoutInstaller14356) InstallLo0(s xnft.Lo0FilterSpec) (int, error) {
	c.calls++
	return fakeLo0Rules(s), nil
}
func (c *closeoutInstaller14356) DeleteTable(string) error             { c.calls++; return nil }
func (c *closeoutInstaller14356) TableEnforcing(string) (bool, error)  { return true, nil }
func (c *closeoutInstaller14356) TableDropsInput(string) (bool, error) { return true, nil }
func (c *closeoutInstaller14356) InstallTransitBarrier() error         { return nil }
func (c *closeoutInstaller14356) InstallArmedTransitFence(xnft.ForwardFenceSpec) error {
	return nil
}
func (c *closeoutInstaller14356) RemoveTransitBarrier() error { return nil }
func (c *closeoutInstaller14356) InstallIpsecDivert(xnft.IpsecDivertSpec) error {
	c.calls++
	return nil
}
func (c *closeoutInstaller14356) RemoveIpsecDivert() error { c.calls++; return nil }

// TestApplyConfigLockedRunsHostAuthCloseoutOnNonCancelDataplaneAbortAndBootstrapError
// is the #14356 fail-on-revert guard. Both subtests drive the REAL
// applyConfigLocked, which runs after Store.Commit has already promoted cfg:
//
//   - non-cancel dataplane abort: the dataplane returns a required
//     protocol-gate sentinel (compileErrorMustAbortApply). Before the fix,
//     closeoutHostAuthOnCancel returned the error untouched for non-cancel
//     errors, so no host-authorization owner ran and the preactivation
//     fence installed earlier in the same apply was left standing with no
//     real table behind it.
//   - bootstrap error: maybeExitBootstrapOnFirstConfig returns a
//     non-cancellation barrier refusal. Before the fix, applyConfigLocked
//     returned that error bare, again skipping every host-auth owner.
//
// In both cases the committed tightening must still be enforced by the
// bounded closeout, fail-closed: the closeout renders host-inbound WITHOUT
// the reinject accept (the dataplane never published this generation).
//
// Fail-on-revert: restore the cancel-only guard (or the bare bootstrap
// return) and the host-inbound capture / root-auth sentinel stay empty — RED.
//
// TestApplyConfigLockedRunsHostAuthCloseoutOnEarliestPostPromotionErrors is
// the reopened #14356 guard for the two earliest post-promotion returns:
// requireEarlyInputProtectionPreApply and applyHostInboundPreNetworkdAddressFence.
// Fail-on-revert: restore either bare return and its subtest's root-auth
// sentinel stays empty — RED.
func TestApplyConfigLockedRunsHostAuthCloseoutOnNonCancelDataplaneAbortAndBootstrapError(t *testing.T) {
	t.Run("dataplane abort", func(t *testing.T) {
		installFakeNetworkctl(t)

		orig := nftInstaller
		inst := &closeoutInstaller14356{}
		nftInstaller = inst
		defer func() { nftInstaller = orig }()

		// Script a newcomer address so applyHostInboundPreNetworkdAddressFence
		// installs the preactivation fence before the abort (mirrors the
		// #11497 scripted-snapshot harness; addresses live only in snapshots).
		origSample := sampleHostInboundSnapshots
		defer func() { sampleHostInboundSnapshots = origSample }()
		uni := int(netlink.SCOPE_UNIVERSE)
		snap := scriptedSnap10751("ge-0/0/0.0", "trust",
			scriptedAddr10751("inet", "10.0.0.1/24", uni))
		sampleHostInboundSnapshots = func(*config.Config) []dpuserspace.InterfaceSnapshot {
			return []dpuserspace.InterfaceSnapshot{snap}
		}

		dp := &runtimeOnlyApplyTestDP{applyErr: dpuserspace.ErrPolicySchedulerProtocolIncompatible}
		d := &Daemon{
			networkd: networkd.NewInDir(t.TempDir()),
			vrrpMgr:  vrrp.NewManager(),
			store:    newConfigStore(t, filepath.Join(t.TempDir(), "config.db")),
			opts:     Options{NoDataplane: true},
		}
		d.setDataplane(dp)
		// Previous generation was fresh; the abort closeout must clear it so
		// the render omits the reinject accept.
		d.hostInboundDataplaneFresh.Store(true)

		cfg := &config.Config{}
		cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
			"ge-0/0/0": {Name: "ge-0/0/0", Units: map[int]*config.InterfaceUnit{0: {Number: 0}}},
		}
		cfg.Security.Zones = map[string]*config.ZoneConfig{
			"trust": {Name: "trust", Interfaces: []string{"ge-0/0/0.0"}},
		}

		err := d.applyConfigLocked(context.Background(), cfg)
		if !errors.Is(err, dpuserspace.ErrPolicySchedulerProtocolIncompatible) {
			t.Fatalf("applyConfigLocked = %v, want the abort sentinel", err)
		}
		if dp.applyCalls != 1 {
			t.Fatalf("dataplane apply ran %d times, want 1", dp.applyCalls)
		}
		if len(inst.gapSpecs) == 0 || !inst.gapSpecs[0].PreActivation {
			t.Fatal("preactivation fence was not installed before the abort; test is not exercising the stranded-fence leg")
		}
		if len(inst.hostSpecs) == 0 {
			t.Fatal("host-auth closeout did NOT run on a non-cancel dataplane abort (#14356): " +
				"committed tightening left unenforced in kernel/OS state")
		}
		for _, s := range inst.hostSpecs {
			if s.DataplaneFresh {
				t.Error("closeout must render host-inbound accept-less: the dataplane never published this generation (fail-closed)")
			}
		}
		if d.hostInboundDataplaneFresh.Load() {
			t.Error("hostInboundDataplaneFresh must be clear after a non-cancel abort closeout")
		}
		if d.hostInboundPreActivationFence != nil {
			t.Error("preactivation fence stranded after the abort: the closeout's real install must retire it")
		}
	})

	t.Run("bootstrap error", func(t *testing.T) {
		installFakeNetworkctl(t)

		orig := nftInstaller
		inst := &closeoutInstaller14356{refuseBarrier: true}
		nftInstaller = inst
		defer func() { nftInstaller = orig }()

		sentinel, _ := stageRootAuthEnv(t, "$6$old14356salt$oldroot")

		d := newStoreDaemon(t)
		d.bootstrapMode.Store(true)
		// The pre-apply guard must no-op so the failure under test is the
		// bootstrap naming gate, not the apply-entry barrier install.
		d.earlyInputHandoffDone.Store(true)
		d.vrrpMgr = vrrp.NewManager()
		d.setDataplane(&runtimeOnlyApplyTestDP{})

		cfg := rootAuthCloseoutCfg(rootAuthCloseoutHash)
		cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
			"reth0": {Name: "reth0", Units: map[int]*config.InterfaceUnit{
				0: {Number: 0, Addresses: []string{"10.7.7.1/24"}},
			}},
		}
		cfg.Security.Zones = map[string]*config.ZoneConfig{
			"trust": {
				Name:               "trust",
				Interfaces:         []string{"reth0.0"},
				HostInboundTraffic: &config.HostInboundTraffic{SystemServices: []string{"ssh"}},
			},
		}

		err := d.applyConfigLocked(context.Background(), cfg)
		if !errors.Is(err, errEarlyInputProtectionRefused) {
			t.Fatalf("applyConfigLocked = %v, want errEarlyInputProtectionRefused", err)
		}
		if !d.inBootstrap() {
			t.Fatal("a refused bootstrap exit must stay in bootstrap mode for retry")
		}
		if len(inst.hostSpecs) == 0 {
			t.Fatal("host-auth closeout did NOT run on a non-cancel bootstrap error (#14356)")
		}
		for _, s := range inst.hostSpecs {
			if s.DataplaneFresh {
				t.Error("closeout must render host-inbound accept-less: the dataplane never published this generation (fail-closed)")
			}
		}
		assertRootAuthApplied(t, sentinel, "#14356: bootstrap-error closeout omitted root-auth")
	})
}

// TestApplyConfigLockedRunsHostAuthCloseoutOnEarliestPostPromotionErrors
// covers the two reopened #14356 returns that sit BEFORE the bootstrap-exit
// and dataplane funnels: requireEarlyInputProtectionPreApply and
// applyHostInboundPreNetworkdAddressFence. Both are post-promotion
// (Store.Commit ran upstream), so each must run the same bounded closeout.
//
//   - early-guard refusal: the lifeline-guard install fails pre-handoff.
//     The closeout's host-inbound owner re-invokes that guard and fails
//     visibly (joined), but the lo0 and credential owners must still run —
//     asserted via the root-auth chpasswd sentinel, the one owner observable
//     that does not depend on the barrier.
//   - fence-install failure: the gap-fence install fails for a scripted
//     newcomer address. The closeout's real host-inbound install must run
//     (accept-less); the returned error stays the fence error (joined with
//     any closeout owner failures) rather than a false success.
//
// Fail-on-revert: restore either bare `return err` and its subtest's
// closeout observable (sentinel / hostSpecs) stays empty — RED.
func TestApplyConfigLockedRunsHostAuthCloseoutOnEarliestPostPromotionErrors(t *testing.T) {
	t.Run("early input protection refusal", func(t *testing.T) {
		installFakeNetworkctl(t)

		orig := nftInstaller
		inst := &closeoutInstaller14356{failLifeline: true}
		nftInstaller = inst
		defer func() { nftInstaller = orig }()

		sentinel, _ := stageRootAuthEnv(t, "$6$old14356salt$oldroot")

		d := newStoreDaemon(t)
		d.networkd = networkd.NewInDir(t.TempDir())
		d.vrrpMgr = vrrp.NewManager()
		d.opts = Options{NoDataplane: true}
		d.setDataplane(&runtimeOnlyApplyTestDP{})
		// Pre-handoff (earlyInputHandoffDone false) so
		// requireEarlyInputProtectionPreApply actually attempts the install.
		d.hostInboundDataplaneFresh.Store(true)

		err := d.applyConfigLocked(context.Background(), rootAuthCloseoutCfg(rootAuthCloseoutHash))
		if err == nil || !strings.Contains(err.Error(), "install early host-input guard before first handoff") {
			t.Fatalf("applyConfigLocked = %v, want the early-guard refusal", err)
		}
		assertRootAuthApplied(t, sentinel, "#14356 reopened: early-guard closeout omitted root-auth")
		if d.hostInboundDataplaneFresh.Load() {
			t.Error("hostInboundDataplaneFresh must be clear after an early-guard closeout (fail-closed)")
		}
	})

	t.Run("preactivation fence install failure", func(t *testing.T) {
		installFakeNetworkctl(t)

		orig := nftInstaller
		inst := &closeoutInstaller14356{failGap: true}
		nftInstaller = inst
		defer func() { nftInstaller = orig }()

		origSample := sampleHostInboundSnapshots
		defer func() { sampleHostInboundSnapshots = origSample }()
		uni := int(netlink.SCOPE_UNIVERSE)
		snap := scriptedSnap10751("ge-0/0/0.0", "trust",
			scriptedAddr10751("inet", "10.0.0.1/24", uni))
		sampleHostInboundSnapshots = func(*config.Config) []dpuserspace.InterfaceSnapshot {
			return []dpuserspace.InterfaceSnapshot{snap}
		}

		d := newStoreDaemon(t)
		d.networkd = networkd.NewInDir(t.TempDir())
		d.vrrpMgr = vrrp.NewManager()
		d.opts = Options{NoDataplane: true}
		d.setDataplane(&runtimeOnlyApplyTestDP{})
		// Post-handoff no-op so the failure under test is the fence install,
		// not the apply-entry barrier guard (same isolation as the bootstrap
		// subtest above).
		d.earlyInputHandoffDone.Store(true)
		d.hostInboundDataplaneFresh.Store(true)

		cfg := rootAuthCloseoutCfg(rootAuthCloseoutHash)
		cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
			"ge-0/0/0": {Name: "ge-0/0/0", Units: map[int]*config.InterfaceUnit{0: {Number: 0}}},
		}
		cfg.Security.Zones = map[string]*config.ZoneConfig{
			"trust": {Name: "trust", Interfaces: []string{"ge-0/0/0.0"}},
		}

		err := d.applyConfigLocked(context.Background(), cfg)
		if err == nil || !strings.Contains(err.Error(), "install host-inbound coverage-gap fence") {
			t.Fatalf("applyConfigLocked = %v, want the fence-install failure", err)
		}
		if len(inst.hostSpecs) == 0 {
			t.Fatal("host-auth closeout did NOT run on a preactivation-fence install failure (#14356 reopened)")
		}
		for _, s := range inst.hostSpecs {
			if s.DataplaneFresh {
				t.Error("closeout must render host-inbound accept-less: the dataplane never published this generation (fail-closed)")
			}
		}
		if d.hostInboundDataplaneFresh.Load() {
			t.Error("hostInboundDataplaneFresh must be clear after a fence-failure closeout")
		}
		if d.hostInboundPreActivationFence != nil {
			t.Error("no preactivation fence spec may be retained: the install failed, so none was recorded")
		}
	})
}
