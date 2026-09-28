package daemon

import (
	"errors"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	xnft "github.com/psaab/xpf/pkg/nftables"
	"github.com/vishvananda/netlink"
)

func TestEarlyInputBarrierHandoffFollowsEnforcement10751(t *testing.T) {
	orig := nftInstaller
	t.Cleanup(func() { nftInstaller = orig })

	t.Run("real host-inbound install", func(t *testing.T) {
		var events []string
		nftInstaller = &fakeNftInstaller{
			hostInbound: func(xnft.HostInboundSpec) error {
				events = append(events, "real")
				return nil
			},
			earlyInputBarrierRemove: func() error {
				events = append(events, "remove-input-barrier")
				return nil
			},
		}
		d := &Daemon{}
		if err := d.applyHostInboundFilter(hostInboundTestConfig()); err != nil {
			t.Fatalf("apply host-inbound: %v", err)
		}
		if got := strings.Join(events, ","); got != "real,remove-input-barrier" {
			t.Fatalf("host-input lifecycle = %q, want enforcement before barrier removal", got)
		}
		if !d.hostInboundEnforced.Load() {
			t.Fatal("real host-inbound table did not publish enforcement before handoff")
		}
		if !d.earlyInputHandoffDone.Load() {
			t.Fatal("successful real install must mark the handoff done")
		}
	})

	t.Run("real install surfaces barrier removal failure", func(t *testing.T) {
		removeErr := errors.New("early input barrier removal failed")
		nftInstaller = &fakeNftInstaller{
			hostInbound: func(xnft.HostInboundSpec) error { return nil },
			earlyInputBarrierRemove: func() error {
				return removeErr
			},
		}
		d := &Daemon{}
		err := d.applyHostInboundFilter(hostInboundTestConfig())
		if !errors.Is(err, removeErr) {
			t.Fatalf("handoff error = %v, want early barrier removal failure", err)
		}
		if !d.hostInboundEnforced.Load() {
			t.Fatal("real host-inbound enforcement was not retained after removal failure")
		}
		// B9: the real table stands but the handoff is incomplete — the
		// recorded state must agree with the failing result (STALE, gen held).
		st := d.HostInboundApplied()
		if !st.Established || !st.LastApplyFailed || st.Current() {
			t.Fatalf("applied state after failed handoff = %+v, want established-but-stale", st)
		}
		if st.LastFailureAt.IsZero() {
			t.Fatal("failed handoff did not record a failure timestamp")
		}
		if st.Generation != 0 {
			t.Fatalf("applied generation = %d, want 0 (success must not advance on handoff failure)", st.Generation)
		}
		if d.earlyInputHandoffDone.Load() {
			t.Fatal("failed barrier removal must not mark the handoff done")
		}
	})

	t.Run("address-scoped fallback fence", func(t *testing.T) {
		var events []string
		installErr := errors.New("real host-inbound load failed")
		nftInstaller = &fakeNftInstaller{
			hostInbound: func(xnft.HostInboundSpec) error {
				events = append(events, "real")
				return installErr
			},
			coldBootFence: func(xnft.FenceSpec) error {
				events = append(events, "fallback")
				return nil
			},
			earlyInputBarrierRemove: func() error {
				events = append(events, "remove-input-barrier")
				return nil
			},
		}
		d := &Daemon{}
		err := d.applyHostInboundFilter(hostInboundTestConfig())
		if !errors.Is(err, installErr) {
			t.Fatalf("fallback apply error = %v, want real install error", err)
		}
		if got := strings.Join(events, ","); got != "real,fallback,remove-input-barrier" {
			t.Fatalf("fallback lifecycle = %q, want fence installed before barrier removal", got)
		}
		if !d.hostInboundEnforced.Load() {
			t.Fatal("address-scoped fallback did not publish enforcement before handoff")
		}
		// The fallback protects but the requested real policy failed: STALE.
		st := d.HostInboundApplied()
		if !st.Established || !st.LastApplyFailed || st.Current() {
			t.Fatalf("applied state after fenced fallback = %+v, want established-but-stale", st)
		}
		if st.LastFailureAt.IsZero() {
			t.Fatal("fenced fallback did not record a failure timestamp")
		}
		if !d.earlyInputHandoffDone.Load() {
			t.Fatal("successful fenced-fallback handoff must mark the handoff done")
		}
	})

	t.Run("failed replacement after success marks stale", func(t *testing.T) {
		installErr := errors.New("replacement host-inbound load failed")
		calls := 0
		nftInstaller = &fakeNftInstaller{
			hostInbound: func(xnft.HostInboundSpec) error {
				calls++
				if calls == 1 {
					return nil
				}
				return installErr
			},
		}
		d := &Daemon{}
		cfg := hostInboundTestConfig()
		if err := d.applyHostInboundFilter(cfg); err != nil {
			t.Fatalf("initial real install: %v", err)
		}
		if st := d.HostInboundApplied(); !st.Current() || st.Generation != 1 {
			t.Fatalf("applied state after success = %+v, want current generation 1", st)
		}
		// Same snapshot: no new coverage gap, so no gap fence — the
		// retained generation still stands, but the render failed.
		if err := d.applyHostInboundFilter(cfg); !errors.Is(err, installErr) {
			t.Fatalf("replacement error = %v, want real install error", err)
		}
		st := d.HostInboundApplied()
		if !st.Established || !st.LastApplyFailed || st.Current() {
			t.Fatalf("applied state after failed replacement = %+v, want established-but-stale", st)
		}
		if st.LastFailureAt.IsZero() {
			t.Fatal("failed replacement did not record a failure timestamp")
		}
		if st.Generation != 1 {
			t.Fatalf("applied generation = %d, want 1 (failed render must not advance)", st.Generation)
		}
	})

	t.Run("failed fallback keeps barrier", func(t *testing.T) {
		var events []string
		installErr := errors.New("real host-inbound load failed")
		fenceErr := errors.New("fallback fence load failed")
		nftInstaller = &fakeNftInstaller{
			hostInbound: func(xnft.HostInboundSpec) error {
				events = append(events, "real")
				return installErr
			},
			coldBootFence: func(xnft.FenceSpec) error {
				events = append(events, "fallback")
				return fenceErr
			},
			earlyInputBarrierRemove: func() error {
				events = append(events, "remove-input-barrier")
				return nil
			},
		}
		d := &Daemon{}
		err := d.applyHostInboundFilter(hostInboundTestConfig())
		if !errors.Is(err, installErr) || !errors.Is(err, fenceErr) {
			t.Fatalf("failed fallback error = %v, want both real and fallback failures", err)
		}
		if got := strings.Join(events, ","); got != "real,fallback" {
			t.Fatalf("failed fallback lifecycle = %q, early barrier must remain installed", got)
		}
		if d.hostInboundEnforced.Load() {
			t.Fatal("failed real and fallback installs must not publish enforcement")
		}
		if d.earlyInputHandoffDone.Load() {
			t.Fatal("failed fallback must not mark the handoff done")
		}
	})

	t.Run("zero-drop fallback keeps barrier", func(t *testing.T) {
		var events []string
		installErr := errors.New("real host-inbound load failed")
		nftInstaller = &fakeNftInstaller{
			hostInbound: func(xnft.HostInboundSpec) error {
				events = append(events, "real")
				return installErr
			},
			coldBootFence: func(xnft.FenceSpec) error {
				events = append(events, "zero-drop-fallback")
				return nil
			},
			earlyInputBarrierRemove: func() error {
				events = append(events, "remove-input-barrier")
				return nil
			},
		}
		d := &Daemon{}
		if err := d.applyHostInboundFilter(addresslessProgramOnlyConfig10751(t)); !errors.Is(err, installErr) {
			t.Fatalf("zero-drop fallback error = %v, want real install error", err)
		}
		if got := strings.Join(events, ","); got != "real,zero-drop-fallback" {
			t.Fatalf("zero-drop fallback lifecycle = %q, early barrier must remain until an address-scoped fence or real install", got)
		}
		if d.hostInboundEnforced.Load() {
			t.Fatal("zero-drop fallback must not claim enforcement")
		}
		if d.earlyInputHandoffDone.Load() {
			t.Fatal("zero-drop fallback must not mark the handoff done")
		}
	})

	t.Run("no-enforcement teardown", func(t *testing.T) {
		var events []string
		nftInstaller = &fakeNftInstaller{
			del: func(name string) error {
				events = append(events, "delete:"+name)
				return nil
			},
			earlyInputBarrierRemove: func() error {
				events = append(events, "remove-input-barrier")
				return nil
			},
		}
		d := &Daemon{}
		if err := d.applyHostInboundFilter(&config.Config{}); err != nil {
			t.Fatalf("empty host-inbound teardown: %v", err)
		}
		want := []string{
			"delete:" + xnft.HostInboundTableName,
			"delete:" + xnft.HostInboundGapTableName,
			"remove-input-barrier",
		}
		if got := strings.Join(events, ","); got != strings.Join(want, ",") {
			t.Fatalf("no-enforcement lifecycle = %q, want deletions before barrier handoff %q", got, strings.Join(want, ","))
		}
		if !d.earlyInputHandoffDone.Load() {
			t.Fatal("successful no-enforcement teardown must mark the handoff done")
		}
	})

	t.Run("teardown surfaces barrier removal failure", func(t *testing.T) {
		removeErr := errors.New("early input barrier removal failed")
		nftInstaller = &fakeNftInstaller{
			del:                     func(string) error { return nil },
			earlyInputBarrierRemove: func() error { return removeErr },
		}
		d := &Daemon{}
		err := d.applyHostInboundFilter(&config.Config{})
		if !errors.Is(err, removeErr) {
			t.Fatalf("teardown handoff error = %v, want barrier removal failure", err)
		}
		// Tables are gone but the handoff is incomplete: failure recorded.
		st := d.HostInboundApplied()
		if st.Established || !st.LastApplyFailed || st.Current() {
			t.Fatalf("applied state after failed teardown handoff = %+v, want failed, nothing established", st)
		}
		if d.earlyInputHandoffDone.Load() {
			t.Fatal("failed teardown handoff must not mark the handoff done")
		}
	})
}

func TestEarlyInputHandoffGatedOnLo0AndIntent10751(t *testing.T) {
	orig := nftInstaller
	t.Cleanup(func() { nftInstaller = orig })

	lo0OnlyConfig := func() *config.Config {
		cfg := &config.Config{}
		cfg.System.Lo0FilterInputV4 = "protect-re"
		cfg.Firewall.FiltersInet = map[string]*config.FirewallFilter{
			"protect-re": {Name: "protect-re", Terms: []*config.FirewallFilterTerm{
				{Name: "deny-rest", Action: "discard"},
			}},
		}
		return cfg
	}

	t.Run("failed lo0 retains barrier on host teardown", func(t *testing.T) {
		fake := &fakeNftInstaller{
			lo0: func(xnft.Lo0FilterSpec) error { return errors.New("lo0 load failed") },
		}
		nftInstaller = fake
		cfg := lo0OnlyConfig()
		d := &Daemon{}
		// Tail order: lo0 first, then host-inbound on the same Daemon.
		if err := d.applyLo0Filter(cfg); err == nil {
			t.Fatal("lo0 apply unexpectedly succeeded")
		}
		if err := d.applyHostInboundFilter(cfg); err != nil {
			t.Fatalf("host teardown with failed lo0: %v", err)
		}
		for _, call := range fake.earlyInputBarrierCalls {
			if call == "remove" {
				t.Fatalf("barrier calls = %v, a failed lo0 must retain the pre-handoff barrier", fake.earlyInputBarrierCalls)
			}
		}
		if d.earlyInputHandoffDone.Load() {
			t.Fatal("failed lo0 must not mark the handoff done")
		}
	})

	t.Run("successful lo0 hands off on host teardown", func(t *testing.T) {
		fake := &fakeNftInstaller{}
		nftInstaller = fake
		cfg := lo0OnlyConfig()
		d := &Daemon{}
		if err := d.applyLo0Filter(cfg); err != nil {
			t.Fatalf("lo0 apply: %v", err)
		}
		if err := d.applyHostInboundFilter(cfg); err != nil {
			t.Fatalf("host teardown: %v", err)
		}
		if len(fake.earlyInputBarrierCalls) != 2 || fake.earlyInputBarrierCalls[0] != "install-lifeline" || fake.earlyInputBarrierCalls[1] != "remove" {
			t.Fatalf("barrier calls = %v, want guard converge plus the handoff remove", fake.earlyInputBarrierCalls)
		}
		if !d.earlyInputHandoffDone.Load() {
			t.Fatal("successful lo0-only handoff must mark the handoff done")
		}
	})

	t.Run("failed lo0 retains barrier after real host install", func(t *testing.T) {
		fake := &fakeNftInstaller{
			lo0: func(xnft.Lo0FilterSpec) error { return errors.New("lo0 load failed") },
		}
		nftInstaller = fake
		cfg := lo0FenceTestConfig()
		d := &Daemon{}
		if err := d.applyLo0Filter(cfg); err == nil {
			t.Fatal("lo0 apply unexpectedly succeeded")
		}
		if err := d.applyHostInboundFilter(cfg); err != nil {
			t.Fatalf("real host install with failed lo0: %v", err)
		}
		for _, call := range fake.earlyInputBarrierCalls {
			if call == "remove" {
				t.Fatalf("barrier calls = %v, failed lo0 must retain the barrier after a real host install", fake.earlyInputBarrierCalls)
			}
		}
		if !d.hostInboundEnforced.Load() {
			t.Fatal("real host install must still publish enforcement")
		}
		if d.earlyInputHandoffDone.Load() {
			t.Fatal("lo0-retained barrier must not mark the handoff done")
		}
		if st := d.HostInboundApplied(); !st.Current() {
			t.Fatalf("host scope installed cleanly but applied state = %+v, want current", st)
		}
	})

	t.Run("addressless enforcing zone retains barrier without programs", func(t *testing.T) {
		fake := &fakeNftInstaller{}
		nftInstaller = fake
		cfg := enforcingZoneNoProgramConfig10751(t, nil, true)
		if len(dpuserspace.AddresslessEnforcingZones(cfg)) == 0 {
			t.Fatal("fixture has no addressless enforcing zone; the test would be vacuous")
		}
		d := &Daemon{}
		if err := d.applyHostInboundFilter(cfg); err != nil {
			t.Fatalf("addressless enforcing apply: %v", err)
		}
		for _, call := range fake.earlyInputBarrierCalls {
			if call == "remove" {
				t.Fatalf("barrier calls = %v, intended-but-unresolved enforcement must retain the barrier", fake.earlyInputBarrierCalls)
			}
		}
		if d.earlyInputHandoffDone.Load() {
			t.Fatal("addressless intended enforcement must not mark the handoff done")
		}
	})

	t.Run("address appearance hands off v4 and v6", func(t *testing.T) {
		fake := &fakeNftInstaller{}
		var installed xnft.HostInboundSpec
		fake.hostInbound = func(spec xnft.HostInboundSpec) error {
			installed = spec
			return nil
		}
		nftInstaller = fake
		d := &Daemon{}
		// Phase 1: DHCP-pending, nothing resolved — barrier retained.
		if err := d.applyHostInboundFilter(enforcingZoneNoProgramConfig10751(t, nil, true)); err != nil {
			t.Fatalf("addressless phase: %v", err)
		}
		for _, call := range fake.earlyInputBarrierCalls {
			if call == "remove" {
				t.Fatalf("phase-1 barrier calls = %v, want no handoff before addresses appear", fake.earlyInputBarrierCalls)
			}
		}
		// Phase 2: static v4+v6 arrive — real install hands off.
		if err := d.applyHostInboundFilter(enforcingZoneNoProgramConfig10751(t,
			[]string{"10.0.0.5/24", "2001:db8::5/64"}, false)); err != nil {
			t.Fatalf("addressed phase: %v", err)
		}
		if len(hostInboundViewAddrs(installed, false)) == 0 || len(hostInboundViewAddrs(installed, true)) == 0 {
			t.Fatal("addressed install did not scope both v4 and v6; the appearance half would be vacuous")
		}
		removes := 0
		for _, call := range fake.earlyInputBarrierCalls {
			if call == "remove" {
				removes++
			}
		}
		if removes != 1 {
			t.Fatalf("barrier calls = %v, want exactly one handoff remove after appearance", fake.earlyInputBarrierCalls)
		}
		if !d.earlyInputHandoffDone.Load() {
			t.Fatal("addressed handoff must mark the handoff done")
		}
	})
}

// enforcingZoneNoProgramConfig10751 builds an enforcing zone with the given
// static addresses (DHCP-pending when addrs is nil) and NO junos-host DENY
// program — the ordinary addressless-zone branch, not the program-only
// fallback branch.
func enforcingZoneNoProgramConfig10751(t *testing.T, addrs []string, dhcp bool) *config.Config {
	t.Helper()
	unit := &config.InterfaceUnit{Number: 0, DHCP: dhcp, Addresses: addrs}
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"xpf10751wan": {Name: "xpf10751wan", Units: map[int]*config.InterfaceUnit{0: unit}},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"untrust": {
			Name:               "untrust",
			Interfaces:         []string{"xpf10751wan.0"},
			HostInboundTraffic: &config.HostInboundTraffic{SystemServices: []string{"ssh"}},
		},
	}
	if len(dpuserspace.BuildJunosHostPrograms(cfg)) != 0 {
		t.Fatal("fixture unexpectedly produced a host-input deny program")
	}
	return cfg
}

func TestEarlyInputBarrierAttestation10751(t *testing.T) {
	orig := nftInstaller
	t.Cleanup(func() { nftInstaller = orig })

	t.Run("pre-handoff apply converges to lifeline guard", func(t *testing.T) {
		fake := &fakeNftInstaller{}
		nftInstaller = fake
		d := &Daemon{}
		if err := d.applyHostInboundFilter(hostInboundTestConfig()); err != nil {
			t.Fatalf("converge-then-install apply: %v", err)
		}
		lifeline, removes := 0, 0
		for _, call := range fake.earlyInputBarrierCalls {
			switch call {
			case "install-lifeline":
				lifeline++
			case "remove":
				removes++
			}
		}
		if lifeline != 1 || removes != 1 {
			t.Fatalf("barrier calls = %v, want one guard converge plus the real-install handoff", fake.earlyInputBarrierCalls)
		}
		if len(fake.earlyInputBarrierLifelineSpecs) != 1 || len(fake.earlyInputBarrierLifelineSpecs[0]) == 0 {
			t.Fatal("guard converge recorded no lifeline set")
		}
		if !d.earlyInputHandoffDone.Load() {
			t.Fatal("converge-then-handoff must mark the handoff done")
		}
	})

	t.Run("guard converge failure fails closed", func(t *testing.T) {
		installErr := errors.New("guard converge failed")
		realCalled := false
		fake := &fakeNftInstaller{
			earlyInputBarrierLifelineInstall: func([]string) error { return installErr },
			hostInbound: func(xnft.HostInboundSpec) error {
				realCalled = true
				return nil
			},
		}
		nftInstaller = fake
		d := &Daemon{}
		err := d.applyHostInboundFilter(hostInboundTestConfig())
		if !errors.Is(err, installErr) {
			t.Fatalf("converge failure error = %v, want the guard install error", err)
		}
		if realCalled {
			t.Fatal("real install must not run when the guard cannot converge")
		}
		if got := len(fake.earlyInputBarrierCalls); got != 1 {
			t.Fatalf("barrier calls = %v, want only the failed converge attempt", fake.earlyInputBarrierCalls)
		}
		if st := d.HostInboundApplied(); !st.LastApplyFailed {
			t.Fatalf("applied state = %+v, want failure recorded", st)
		}
	})

	t.Run("post-handoff apply does not reinstall", func(t *testing.T) {
		fake := &fakeNftInstaller{}
		nftInstaller = fake
		d := &Daemon{}
		d.earlyInputHandoffDone.Store(true)
		if err := d.applyHostInboundFilter(hostInboundTestConfig()); err != nil {
			t.Fatalf("post-handoff apply: %v", err)
		}
		for _, call := range fake.earlyInputBarrierCalls {
			if call == "install-lifeline" {
				t.Fatalf("barrier calls = %v, post-handoff must not reinstall the guard", fake.earlyInputBarrierCalls)
			}
		}
	})
}

func TestEarlyInputGateForLinkActivation10751(t *testing.T) {
	origInstaller := nftInstaller
	origProbe := nftProbeAvailable
	t.Cleanup(func() { nftInstaller = origInstaller; nftProbeAvailable = origProbe })

	t.Run("present barrier converges to guard and proceeds", func(t *testing.T) {
		fake := &fakeNftInstaller{}
		nftInstaller = fake
		if !ensureEarlyInputProtectionForNaming(nil) {
			t.Fatal("gate refused with the barrier present")
		}
		if fake.earlyInputBarrierPresentCalls != 1 {
			t.Fatalf("presence attestations = %d, want 1", fake.earlyInputBarrierPresentCalls)
		}
		installs := 0
		for _, call := range fake.earlyInputBarrierCalls {
			if call == "install-lifeline" {
				installs++
			}
		}
		if installs != 1 {
			t.Fatalf("guard installs = %d, want 1 converge to the lifeline variant", installs)
		}
	})

	t.Run("absent barrier installs guard and proceeds", func(t *testing.T) {
		fake := &fakeNftInstaller{
			earlyInputBarrierPresent: func() (bool, error) { return false, nil },
		}
		nftInstaller = fake
		if !ensureEarlyInputProtectionForNaming(nil) {
			t.Fatal("gate refused after a successful guard install")
		}
		installs := 0
		for _, call := range fake.earlyInputBarrierCalls {
			if call == "install-lifeline" {
				installs++
			}
		}
		if installs != 1 {
			t.Fatalf("guard installs = %d, want 1 self-heal install", installs)
		}
	})

	t.Run("absent barrier with unusable nft proceeds loudly", func(t *testing.T) {
		fake := &fakeNftInstaller{
			earlyInputBarrierPresent:         func() (bool, error) { return false, nil },
			earlyInputBarrierLifelineInstall: func([]string) error { return errors.New("nft unavailable") },
		}
		nftInstaller = fake
		nftProbeAvailable = func() error { return errors.New("no nf_tables") }
		if !ensureEarlyInputProtectionForNaming(nil) {
			t.Fatal("gate refused on an unenforceable platform; boot must never brick where no enforcement is possible")
		}
	})

	t.Run("absent barrier with usable nft refuses", func(t *testing.T) {
		fake := &fakeNftInstaller{
			earlyInputBarrierPresent:         func() (bool, error) { return false, nil },
			earlyInputBarrierLifelineInstall: func([]string) error { return errors.New("guard install failed") },
		}
		nftInstaller = fake
		nftProbeAvailable = func() error { return nil }
		if ensureEarlyInputProtectionForNaming(nil) {
			t.Fatal("gate proceeded with protection known-absent and nft usable")
		}
	})

	t.Run("readback error proceeds", func(t *testing.T) {
		fake := &fakeNftInstaller{
			earlyInputBarrierPresent: func() (bool, error) { return false, errors.New("netlink readback failed") },
		}
		nftInstaller = fake
		if !ensureEarlyInputProtectionForNaming(nil) {
			t.Fatal("gate refused on a presence-readback error; it blocks on known-absent, not on unobservable")
		}
	})

	t.Run("naming policy performs no link activation on gate refusal", func(t *testing.T) {
		nftInstaller = &fakeNftInstaller{
			earlyInputBarrierPresent:         func() (bool, error) { return false, nil },
			earlyInputBarrierLifelineInstall: func([]string) error { return errors.New("reinstall failed") },
		}
		nftProbeAvailable = func() error { return nil }
		// Belt-and-braces link-op recorders: the gate returns before any
		// enumeration, so none of these may fire.
		var linkOps []string
		oldByName, oldDown, oldName, oldUp := nlLinkByName, nlLinkSetDown, nlLinkSetName, nlLinkSetUp
		t.Cleanup(func() {
			nlLinkByName, nlLinkSetDown, nlLinkSetName, nlLinkSetUp = oldByName, oldDown, oldName, oldUp
		})
		nlLinkByName = func(name string) (netlink.Link, error) {
			linkOps = append(linkOps, "byname:"+name)
			return nil, errors.New("no links in gate test")
		}
		nlLinkSetDown = func(netlink.Link) error { linkOps = append(linkOps, "down"); return nil }
		nlLinkSetName = func(netlink.Link, string) error { linkOps = append(linkOps, "rename"); return nil }
		nlLinkSetUp = func(netlink.Link) error { linkOps = append(linkOps, "up"); return nil }
		err := applyStartupNamingPolicy(nil, 0, false, 0, true, nil, nil)
		if err == nil || !strings.Contains(err.Error(), "early host-input barrier") {
			t.Fatalf("naming policy error = %v, want barrier gate refusal", err)
		}
		if len(linkOps) != 0 {
			t.Fatalf("link operations on gate refusal = %v, want none", linkOps)
		}
	})
}

func TestEarlyInputBootstrapGuard10751(t *testing.T) {
	orig := nftInstaller
	t.Cleanup(func() { nftInstaller = orig })

	t.Run("bootstrap swaps global barrier for lifeline guard", func(t *testing.T) {
		withFailClosedBootDetect(t, func() (string, bool, error) { return "hb0", true, nil })
		fake := &fakeNftInstaller{}
		nftInstaller = fake
		d := &Daemon{}
		d.bootstrapMode.Store(true)
		d.ensureEarlyInputBootstrapGuard()
		if len(fake.earlyInputBarrierCalls) != 1 || fake.earlyInputBarrierCalls[0] != "install-lifeline" {
			t.Fatalf("barrier calls = %v, want a single lifeline-guard swap (never a lift)", fake.earlyInputBarrierCalls)
		}
		if len(fake.earlyInputBarrierLifelineSpecs) != 1 {
			t.Fatalf("lifeline specs recorded = %d, want 1", len(fake.earlyInputBarrierLifelineSpecs))
		}
		got := map[string]bool{}
		for _, name := range fake.earlyInputBarrierLifelineSpecs[0] {
			got[name] = true
		}
		for _, want := range []string{"fxp0", "em0", "fab0", "fab1", "hb0"} {
			if !got[want] {
				t.Errorf("lifeline guard omits %q (admitted %v)", want, fake.earlyInputBarrierLifelineSpecs[0])
			}
		}
		if d.earlyInputHandoffDone.Load() {
			t.Fatal("installed guard must not mark the handoff done (the table still stands)")
		}
	})

	t.Run("guard install failure retains the global barrier", func(t *testing.T) {
		withFailClosedBootDetect(t, func() (string, bool, error) { return "hb0", true, nil })
		nftInstaller = &fakeNftInstaller{
			earlyInputBarrierLifelineInstall: func([]string) error { return errors.New("kernel install failed") },
		}
		d := &Daemon{}
		d.bootstrapMode.Store(true)
		d.ensureEarlyInputBootstrapGuard()
		if d.earlyInputHandoffDone.Load() {
			t.Fatal("failed guard swap must not mark the handoff done")
		}
	})

	t.Run("detection failure still admits default lifelines", func(t *testing.T) {
		withFailClosedBootDetect(t, func() (string, bool, error) { return "", false, errors.New("no routes readable") })
		fake := &fakeNftInstaller{}
		nftInstaller = fake
		d := &Daemon{}
		d.bootstrapMode.Store(true)
		d.ensureEarlyInputBootstrapGuard()
		if len(fake.earlyInputBarrierLifelineSpecs) != 1 {
			t.Fatalf("lifeline specs recorded = %d, want 1", len(fake.earlyInputBarrierLifelineSpecs))
		}
		got := map[string]bool{}
		for _, name := range fake.earlyInputBarrierLifelineSpecs[0] {
			got[name] = true
		}
		for _, want := range []string{"fxp0", "em0", "fab0", "fab1"} {
			if !got[want] {
				t.Errorf("fallback guard omits default %q (admitted %v)", want, fake.earlyInputBarrierLifelineSpecs[0])
			}
		}
	})

	t.Run("fail-closed fences install before the guard swap", func(t *testing.T) {
		d, fake := failClosedBootFixture(t)
		var events []string
		fake.coldBootFence = func(xnft.FenceSpec) error { events = append(events, "host-fence"); return nil }
		fake.lo0ColdBootFence = func(xnft.FenceSpec) error { events = append(events, "lo0-fence"); return nil }
		fake.earlyInputBarrierLifelineInstall = func([]string) error { events = append(events, "install-guard"); return nil }
		d.bootstrapMode.Store(true)
		// initManagers order: fail-closed fences first, then the guard swap.
		d.installFailClosedBootHostFences(true)
		d.ensureEarlyInputBootstrapGuard()
		want := "host-fence,lo0-fence,install-guard"
		if got := strings.Join(events, ","); got != want {
			t.Fatalf("bootstrap order = %q, want %q (data fences own their scope before the guard swap)", got, want)
		}
		removes := 0
		for _, call := range fake.earlyInputBarrierCalls {
			if call == "remove" {
				removes++
			}
		}
		if removes != 0 {
			t.Fatalf("barrier calls = %v, bootstrap must swap the guard, never lift it", fake.earlyInputBarrierCalls)
		}
	})

	t.Run("failed fence installation still swaps the guard", func(t *testing.T) {
		d, fake := failClosedBootFixture(t)
		fake.coldBootFence = func(xnft.FenceSpec) error { return errors.New("host fence failed") }
		fake.lo0ColdBootFence = func(xnft.FenceSpec) error { return errors.New("lo0 fence failed") }
		d.bootstrapMode.Store(true)
		d.installFailClosedBootHostFences(true)
		d.ensureEarlyInputBootstrapGuard()
		installs := 0
		removes := 0
		for _, call := range fake.earlyInputBarrierCalls {
			switch call {
			case "install-lifeline":
				installs++
			case "remove":
				removes++
			}
		}
		if installs != 1 || removes != 0 {
			t.Fatalf("barrier calls = %v, want exactly one guard swap and no lift when fences fail", fake.earlyInputBarrierCalls)
		}
		if d.earlyInputHandoffDone.Load() {
			t.Fatal("guard swap must not mark the handoff done")
		}
	})

	t.Run("data link-local ingress stays guarded in bootstrap", func(t *testing.T) {
		withFailClosedBootLifelineFile(t)
		withFailClosedBootDetect(t, func() (string, bool, error) { return "fxp0", true, nil })
		withFailClosedBootLinkList(t, func() ([]netlink.Link, error) {
			return []netlink.Link{failClosedBootTestLink("fxp0", false), failClosedBootTestLink("ge-0-0-0", false)}, nil
		})
		withFailClosedBootAddrList(t, func(link netlink.Link, _ int) ([]netlink.Addr, error) {
			if link.Attrs().Name == "ge-0-0-0" {
				return []netlink.Addr{failClosedBootTestAddr(t, "fe80::10/64")}, nil
			}
			return []netlink.Addr{failClosedBootTestAddr(t, "10.0.0.1/24")}, nil
		})
		fake := &fakeNftInstaller{}
		withFailClosedBootNft(t, fake)
		d := &Daemon{store: &configstore.Store{}}
		d.bootstrapMode.Store(true)
		// The fail-closed fences exclude link-locals by design (#10732); the
		// lifeline guard's DROP policy is what covers them — so bootstrap
		// must install the guard (not lift the table) on this box.
		d.installFailClosedBootHostFences(true)
		d.ensureEarlyInputBootstrapGuard()
		removes, installs := 0, 0
		for _, call := range fake.earlyInputBarrierCalls {
			switch call {
			case "install-lifeline":
				installs++
			case "remove":
				removes++
			}
		}
		if installs != 1 || removes != 0 {
			t.Fatalf("barrier calls = %v, want the guard standing over link-local data ingress", fake.earlyInputBarrierCalls)
		}
	})
}

func addresslessProgramOnlyConfig10751(t *testing.T) *config.Config {
	t.Helper()
	unit := &config.InterfaceUnit{Number: 0, DHCP: true}
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"xpf10751wan": {Name: "xpf10751wan", Units: map[int]*config.InterfaceUnit{0: unit}},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"untrust": {
			Name:               "untrust",
			Interfaces:         []string{"xpf10751wan.0"},
			HostInboundTraffic: &config.HostInboundTraffic{SystemServices: []string{"ssh"}},
		},
	}
	cfg.Security.AddressBook = &config.AddressBook{Addresses: map[string]*config.Address{
		"blocked-host": {Name: "blocked-host", Value: "10.0.0.5/32"},
	}}
	cfg.Security.Policies = []*config.ZonePairPolicies{{
		FromZone: "untrust",
		ToZone:   "junos-host",
		Policies: []*config.Policy{{
			Name:   "block-host",
			Action: config.PolicyDeny,
			Match:  config.PolicyMatch{SourceAddresses: []string{"blocked-host"}, Applications: []string{"any"}},
		}},
	}}
	if len(dpuserspace.BuildJunosHostPrograms(cfg)) == 0 {
		t.Fatal("program-only fixture did not produce a host-input deny program")
	}
	return cfg
}

func TestEarlyInputBarrierBootUnitAndStaging10751(t *testing.T) {
	root := transitBarrierRepoRoot9852(t)
	unit := transitBarrierReadFile9852(t, root+"/scripts/image/xpf-input-closed.service")
	code := transitBarrierUnitCodeOnly9852(unit)
	unitSection := transitBarrierSection9852(code, "Unit")
	serviceSection := transitBarrierSection9852(code, "Service")
	installSection := transitBarrierSection9852(code, "Install")
	for _, check := range []struct {
		section string
		want    string
	}{
		{section: unitSection, want: "After=nftables.service"},
		{section: unitSection, want: "Before=network-pre.target systemd-networkd.service frr.service xpfd.service"},
		{section: installSection, want: "RequiredBy=systemd-networkd.service"},
		{section: installSection, want: "RequiredBy=xpfd.service"},
		{section: serviceSection, want: "ExecStart=/usr/local/sbin/xpfd input-barrier close"},
		{section: serviceSection, want: "ExecReload=/usr/local/sbin/xpfd input-barrier close"},
		{section: serviceSection, want: "Type=oneshot"},
		{section: serviceSection, want: "RemainAfterExit=yes"},
	} {
		if !strings.Contains(check.section, check.want) {
			t.Errorf("early input unit missing %q in effective section", check.want)
		}
	}
	if strings.Contains(serviceSection, "ExecStart=-") || strings.Contains(code, "transit-barrier") {
		t.Error("early host-input unit suppresses failure or shares the forward-only transit command")
	}

	checks := []struct {
		name string
		path string
		want []string
	}{
		{
			name: "debian package",
			path: root + "/debian/rules",
			want: []string{
				"cp scripts/image/xpf-input-closed.service debian/xpf.xpf-input-closed.service",
				"dh_installsystemd --no-start --no-stop-on-upgrade --name=xpf-input-closed",
			},
		},
		{
			name: "baked image",
			path: root + "/scripts/image/bake.py",
			want: []string{
				"--copy-in\", f\"{HERE}/xpf-input-closed.service:/usr/lib/systemd/system",
				"systemctl enable xpf-input-closed.service",
			},
		},
		{
			name: "standalone Incus",
			path: root + "/test/incus/setup.sh",
			want: []string{
				"${PROJECT_ROOT}/scripts/image/xpf-input-closed.service",
				"systemctl enable --now xpf-input-closed.service",
			},
		},
		{
			name: "cluster Incus",
			path: root + "/test/incus/cluster-setup.sh",
			want: []string{
				"${PROJECT_ROOT}/scripts/image/xpf-input-closed.service",
				"systemctl enable --now xpf-input-closed.service",
			},
		},
	}
	for _, check := range checks {
		t.Run(check.name, func(t *testing.T) {
			source := transitBarrierReadFile9852(t, check.path)
			for _, want := range check.want {
				if !strings.Contains(source, want) {
					t.Errorf("%s missing %q", check.path, want)
				}
			}
		})
	}
}

func TestEarlyInputPendingIntentAllBranches10751(t *testing.T) {
	orig := nftInstaller
	t.Cleanup(func() { nftInstaller = orig })

	scenarios := []struct {
		name        string
		zonesSilent bool // phase-1 pending visible ONLY at interface/family granularity
		phase1      func(*testing.T) *config.Config
		phase2      func(*testing.T) *config.Config
	}{
		{"addressed-plus-addressless-zones", false,
			func(t *testing.T) *config.Config { return pendingIntentTwoZoneConfig10751(t, nil, true) },
			func(t *testing.T) *config.Config {
				return pendingIntentTwoZoneConfig10751(t, []string{"10.2.0.1/24", "2001:db8:2::1/64"}, false)
			}},
		{"mixed-zone-sibling", true,
			func(t *testing.T) *config.Config { return pendingIntentMixedZoneConfig10751(t, nil, true) },
			func(t *testing.T) *config.Config {
				return pendingIntentMixedZoneConfig10751(t, []string{"10.3.0.2/24"}, false)
			}},
		{"v4-then-v6", true,
			func(t *testing.T) *config.Config {
				return sequentialFamilyConfig10751(t, []string{"10.4.0.1/24"}, false, true)
			},
			func(t *testing.T) *config.Config {
				return sequentialFamilyConfig10751(t, []string{"10.4.0.1/24", "2001:db8:4::1/64"}, false, true)
			}},
		{"v6-then-v4", true,
			func(t *testing.T) *config.Config {
				return sequentialFamilyConfig10751(t, []string{"2001:db8:5::1/64"}, true, false)
			},
			func(t *testing.T) *config.Config {
				return sequentialFamilyConfig10751(t, []string{"10.5.0.1/24", "2001:db8:5::1/64"}, true, false)
			}},
	}

	runLifecycle := func(t *testing.T, zonesSilent bool, phase1, phase2 *config.Config, failPhase1Real bool) {
		t.Helper()
		if !hostInboundHasPendingEnforcingIntent(phase1) {
			t.Fatal("phase-1 fixture has no pending intent; the retention half would be vacuous")
		}
		if zonesSilent && len(dpuserspace.AddresslessEnforcingZones(phase1)) != 0 {
			t.Fatal("phase-1 fixture must be zone-silent so only interface/family granularity catches it")
		}
		if hostInboundHasPendingEnforcingIntent(phase2) {
			t.Fatal("phase-2 fixture still pending; the completion half would be vacuous")
		}
		installErr := errors.New("phase-1 real install failed")
		calls := 0
		fake := &fakeNftInstaller{}
		if failPhase1Real {
			fake.hostInbound = func(xnft.HostInboundSpec) error {
				calls++
				if calls == 1 {
					return installErr
				}
				return nil
			}
		}
		nftInstaller = fake
		d := &Daemon{}
		// Phase 1: pending intent — barrier retained.
		err := d.applyHostInboundFilter(phase1)
		if failPhase1Real {
			if !errors.Is(err, installErr) {
				t.Fatalf("phase-1 error = %v, want real install error", err)
			}
			if st := d.HostInboundApplied(); !st.Established || !st.LastApplyFailed {
				t.Fatalf("phase-1 state = %+v, want established-but-stale fenced fallback", st)
			}
		} else if err != nil {
			t.Fatalf("phase-1 real install: %v", err)
		}
		for _, call := range fake.earlyInputBarrierCalls {
			if call == "remove" {
				t.Fatalf("phase-1 barrier calls = %v, pending intent must retain the barrier", fake.earlyInputBarrierCalls)
			}
		}
		if d.earlyInputHandoffDone.Load() {
			t.Fatal("phase-1 must not mark the handoff done while intent is pending")
		}
		// Phase 2: every scope resolved — real install hands off.
		if err := d.applyHostInboundFilter(phase2); err != nil {
			t.Fatalf("phase-2 real install: %v", err)
		}
		removes := 0
		for _, call := range fake.earlyInputBarrierCalls {
			if call == "remove" {
				removes++
			}
		}
		if removes != 1 {
			t.Fatalf("barrier calls = %v, want exactly one handoff remove after all scopes resolve", fake.earlyInputBarrierCalls)
		}
		if !d.earlyInputHandoffDone.Load() {
			t.Fatal("resolved handoff must mark the handoff done")
		}
	}

	for _, sc := range scenarios {
		t.Run(sc.name+"/real-success", func(t *testing.T) {
			runLifecycle(t, sc.zonesSilent, sc.phase1(t), sc.phase2(t), false)
		})
		t.Run(sc.name+"/fallback-success", func(t *testing.T) {
			runLifecycle(t, sc.zonesSilent, sc.phase1(t), sc.phase2(t), true)
		})
	}
}

// pendingIntentTwoZoneConfig10751 builds zone A fully addressed plus zone B
// with the given addresses (DHCP-pending when bAddrs is nil). No junos-host
// programs anywhere.
func pendingIntentTwoZoneConfig10751(t *testing.T, bAddrs []string, bDHCP bool) *config.Config {
	t.Helper()
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"xpfA": {Name: "xpfA", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, Addresses: []string{"10.1.0.1/24", "2001:db8:1::1/64"}},
		}},
		"xpfB": {Name: "xpfB", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, DHCP: bDHCP, DHCPv6: bDHCP, Addresses: bAddrs},
		}},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"zoneA": {Name: "zoneA", Interfaces: []string{"xpfA.0"},
			HostInboundTraffic: &config.HostInboundTraffic{SystemServices: []string{"ssh"}}},
		"zoneB": {Name: "zoneB", Interfaces: []string{"xpfB.0"},
			HostInboundTraffic: &config.HostInboundTraffic{SystemServices: []string{"ssh"}}},
	}
	if len(dpuserspace.BuildJunosHostPrograms(cfg)) != 0 {
		t.Fatal("fixture unexpectedly produced a host-input deny program")
	}
	return cfg
}

// pendingIntentMixedZoneConfig10751 builds ONE zone with an addressed unit 0
// and a sibling unit 1 carrying sibAddrs (DHCP-pending when nil).
func pendingIntentMixedZoneConfig10751(t *testing.T, sibAddrs []string, sibDHCP bool) *config.Config {
	t.Helper()
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"xpfM": {Name: "xpfM", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, Addresses: []string{"10.3.0.1/24"}},
			1: {Number: 1, DHCP: sibDHCP, Addresses: sibAddrs},
		}},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"mixed": {Name: "mixed", Interfaces: []string{"xpfM.0", "xpfM.1"},
			HostInboundTraffic: &config.HostInboundTraffic{SystemServices: []string{"ssh"}}},
	}
	if len(dpuserspace.BuildJunosHostPrograms(cfg)) != 0 {
		t.Fatal("fixture unexpectedly produced a host-input deny program")
	}
	return cfg
}

// sequentialFamilyConfig10751 builds a single-zone single-unit config with the
// given addresses and DHCP-client flags, for v4-before-v6 and v6-before-v4
// arrival orders.
func sequentialFamilyConfig10751(t *testing.T, addrs []string, dhcp, dhcpv6 bool) *config.Config {
	t.Helper()
	unit := &config.InterfaceUnit{Number: 0, DHCP: dhcp, DHCPv6: dhcpv6, Addresses: addrs}
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"xpfS": {Name: "xpfS", Units: map[int]*config.InterfaceUnit{0: unit}},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"edge": {Name: "edge", Interfaces: []string{"xpfS.0"},
			HostInboundTraffic: &config.HostInboundTraffic{SystemServices: []string{"ssh"}}},
	}
	if len(dpuserspace.BuildJunosHostPrograms(cfg)) != 0 {
		t.Fatal("fixture unexpectedly produced a host-input deny program")
	}
	return cfg
}

func TestResolveEarlyInputGuardLifelines10751(t *testing.T) {
	origRecord := lifelineRecordNameFn
	t.Cleanup(func() { lifelineRecordNameFn = origRecord })

	leafConfig := func(leaf string) *config.Config {
		cfg := &config.Config{}
		if leaf != "" {
			cfg.System.ManagementInterface = leaf
		}
		return cfg
	}

	for _, tc := range []struct {
		name       string
		leaf       string
		record     string
		recordOK   bool
		detect     string
		detectErr  bool
		want       []string
		wantAbsent []string
	}{
		{"defaults plus detected fallback", "", "", false, "ge-data", false,
			[]string{"fxp0", "em0", "fab0", "fab1", "vrf-mgmt", "ge-data"}, nil},
		{"leaf narrows fxp0 and excludes detected data", "hb0", "", false, "ge-data", false,
			[]string{"hb0", "em0", "fab0", "fab1", "vrf-mgmt"}, []string{"fxp0", "ge-data"}},
		{"record identity excludes detected data", "", "r1", true, "ge-data", false,
			[]string{"fxp0", "em0", "fab0", "fab1", "vrf-mgmt", "r1"}, []string{"ge-data"}},
		{"leaf plus record union", "hb0", "r1", true, "ge-data", false,
			[]string{"hb0", "em0", "fab0", "fab1", "vrf-mgmt", "r1"}, []string{"fxp0", "ge-data"}},
		{"detection failure keeps verified set", "hb0", "", false, "", true,
			[]string{"hb0", "em0", "fab0", "fab1", "vrf-mgmt"}, []string{"fxp0"}},
		{"detected member deduped", "", "", false, "fxp0", false,
			[]string{"fxp0", "em0", "fab0", "fab1", "vrf-mgmt"}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lifelineRecordNameFn = func() (string, bool) { return tc.record, tc.recordOK }
			if tc.detectErr {
				withFailClosedBootDetect(t, func() (string, bool, error) { return "", false, errors.New("no routes") })
			} else {
				withFailClosedBootDetect(t, func() (string, bool, error) { return tc.detect, tc.detect != "", nil })
			}
			got := resolveEarlyInputGuardLifelines(leafConfig(tc.leaf))
			set := map[string]bool{}
			for _, n := range got {
				if set[n] {
					t.Fatalf("lifelines %v contain duplicate %q", got, n)
				}
				set[n] = true
			}
			for _, w := range tc.want {
				if !set[w] {
					t.Errorf("lifelines %v omit %q", got, w)
				}
			}
			for _, b := range tc.wantAbsent {
				if set[b] {
					t.Errorf("lifelines %v wrongly admit %q", got, b)
				}
			}
		})
	}
}

func TestEarlyInputHandoffReattestation10751(t *testing.T) {
	orig := nftInstaller
	t.Cleanup(func() { nftInstaller = orig })

	counts := func(fake *fakeNftInstaller) (installs, removes int) {
		t.Helper()
		for _, call := range fake.earlyInputBarrierCalls {
			switch call {
			case "install-lifeline":
				installs++
			case "remove":
				removes++
			}
		}
		return installs, removes
	}

	t.Run("missing barrier at handoff reinstalls guard and fails", func(t *testing.T) {
		fake := &fakeNftInstaller{
			earlyInputBarrierPresent: func() (bool, error) { return false, nil },
		}
		nftInstaller = fake
		d := &Daemon{}
		err := d.applyHostInboundFilter(hostInboundTestConfig())
		if err == nil || !strings.Contains(err.Error(), "handoff refused") {
			t.Fatalf("tripwire error = %v, want handoff refusal over wiped enforcement", err)
		}
		installs, removes := counts(fake)
		if installs != 2 || removes != 0 {
			t.Fatalf("barrier calls = %v, want entry converge plus tripwire reinstall and no removal", fake.earlyInputBarrierCalls)
		}
		if st := d.HostInboundApplied(); !st.Established || !st.LastApplyFailed || st.Current() {
			t.Fatalf("applied state = %+v, want established-but-stale", st)
		}
		if d.earlyInputHandoffDone.Load() {
			t.Fatal("refused handoff must not mark the handoff done")
		}
	})

	t.Run("handoff readback error reinstalls then proceeds", func(t *testing.T) {
		fake := &fakeNftInstaller{
			earlyInputBarrierPresent: func() (bool, error) { return false, errors.New("unreadable") },
		}
		nftInstaller = fake
		d := &Daemon{}
		if err := d.applyHostInboundFilter(hostInboundTestConfig()); err != nil {
			t.Fatalf("reinstall-first handoff: %v", err)
		}
		installs, removes := counts(fake)
		if installs != 2 || removes != 1 {
			t.Fatalf("barrier calls = %v, want entry converge plus tripwire reinstall-first then removal", fake.earlyInputBarrierCalls)
		}
		if !d.earlyInputHandoffDone.Load() {
			t.Fatal("successful handoff must mark the handoff done")
		}
	})

	t.Run("handoff reinstall failure fails closed", func(t *testing.T) {
		installCalls := 0
		fake := &fakeNftInstaller{
			earlyInputBarrierPresent: func() (bool, error) { return false, errors.New("unreadable") },
			earlyInputBarrierLifelineInstall: func([]string) error {
				installCalls++
				if installCalls == 1 {
					return nil
				}
				return errors.New("tripwire reinstall failed")
			},
		}
		nftInstaller = fake
		d := &Daemon{}
		err := d.applyHostInboundFilter(hostInboundTestConfig())
		if err == nil {
			t.Fatal("tripwire reinstall failure unexpectedly succeeded")
		}
		installs, removes := counts(fake)
		if installs != 2 || removes != 0 {
			t.Fatalf("barrier calls = %v, want entry converge plus failed tripwire reinstall and no removal", fake.earlyInputBarrierCalls)
		}
		if st := d.HostInboundApplied(); !st.LastApplyFailed {
			t.Fatalf("applied state = %+v, want failure recorded", st)
		}
	})
}
