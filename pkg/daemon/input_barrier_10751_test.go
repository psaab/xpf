package daemon

import (
	"errors"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
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
		if len(fake.earlyInputBarrierCalls) != 1 || fake.earlyInputBarrierCalls[0] != "remove" {
			t.Fatalf("barrier calls = %v, want a single handoff remove", fake.earlyInputBarrierCalls)
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

	callsOf := func(fake *fakeNftInstaller, want string) int {
		t.Helper()
		n := 0
		for _, call := range fake.earlyInputBarrierCalls {
			if call == want {
				n++
			}
		}
		return n
	}

	t.Run("missing barrier reinstalled before real install", func(t *testing.T) {
		fake := &fakeNftInstaller{
			earlyInputBarrierPresent: func() (bool, error) { return false, nil },
		}
		nftInstaller = fake
		d := &Daemon{}
		if err := d.applyHostInboundFilter(hostInboundTestConfig()); err != nil {
			t.Fatalf("reinstall-then-install apply: %v", err)
		}
		if got := callsOf(fake, "install"); got != 1 {
			t.Fatalf("barrier install calls = %d, want 1 reinstall of the flushed barrier", got)
		}
		if got := callsOf(fake, "remove"); got != 1 {
			t.Fatalf("barrier remove calls = %d, want the real-install handoff after reinstall", got)
		}
		if fake.earlyInputBarrierPresentCalls != 1 {
			t.Fatalf("presence attestations = %d, want 1 pre-apply readback", fake.earlyInputBarrierPresentCalls)
		}
		if !d.earlyInputHandoffDone.Load() {
			t.Fatal("reinstall-then-handoff must mark the handoff done")
		}
	})

	t.Run("missing barrier with failing reinstall fails closed", func(t *testing.T) {
		installErr := errors.New("barrier reinstall failed")
		realCalled := false
		fake := &fakeNftInstaller{
			earlyInputBarrierPresent: func() (bool, error) { return false, nil },
			earlyInputBarrierInstall: func() error { return installErr },
			hostInbound: func(xnft.HostInboundSpec) error {
				realCalled = true
				return nil
			},
		}
		nftInstaller = fake
		d := &Daemon{}
		err := d.applyHostInboundFilter(hostInboundTestConfig())
		if !errors.Is(err, installErr) {
			t.Fatalf("reinstall failure error = %v, want the reinstall error", err)
		}
		if realCalled {
			t.Fatal("real install must not run when the missing barrier cannot be reinstalled")
		}
		if got := callsOf(fake, "remove"); got != 0 {
			t.Fatalf("barrier remove calls = %d, want none on reinstall failure", got)
		}
		if st := d.HostInboundApplied(); !st.LastApplyFailed {
			t.Fatalf("applied state = %+v, want failure recorded", st)
		}
	})

	t.Run("flush with failed fallback stays closed", func(t *testing.T) {
		installErr := errors.New("real host-inbound load failed")
		fake := &fakeNftInstaller{
			earlyInputBarrierPresent: func() (bool, error) { return false, nil },
			hostInbound:              func(xnft.HostInboundSpec) error { return installErr },
			coldBootFence:            func(xnft.FenceSpec) error { return errors.New("fence failed") },
		}
		nftInstaller = fake
		d := &Daemon{}
		err := d.applyHostInboundFilter(hostInboundTestConfig())
		if !errors.Is(err, installErr) {
			t.Fatalf("flushed failed-handoff error = %v, want the real install error", err)
		}
		if got := callsOf(fake, "install"); got != 1 {
			t.Fatalf("barrier install calls = %d, want 1 reinstall before the failed handoff", got)
		}
		if got := callsOf(fake, "remove"); got != 0 {
			t.Fatalf("barrier remove calls = %d, a failed handoff must not lift the reinstalled barrier", got)
		}
	})

	t.Run("present readback error proceeds to enforcement", func(t *testing.T) {
		fake := &fakeNftInstaller{
			earlyInputBarrierPresent: func() (bool, error) { return false, errors.New("netlink readback failed") },
		}
		nftInstaller = fake
		d := &Daemon{}
		if err := d.applyHostInboundFilter(hostInboundTestConfig()); err != nil {
			t.Fatalf("readback-error apply: %v", err)
		}
		if got := callsOf(fake, "install"); got != 0 {
			t.Fatalf("barrier install calls = %d, want none when presence is unreadable (warn-and-proceed)", got)
		}
		if got := callsOf(fake, "remove"); got != 1 {
			t.Fatalf("barrier remove calls = %d, want the real-install handoff", got)
		}
	})
}

func TestEarlyInputGateForLinkActivation10751(t *testing.T) {
	origInstaller := nftInstaller
	origProbe := nftProbeAvailable
	t.Cleanup(func() { nftInstaller = origInstaller; nftProbeAvailable = origProbe })

	t.Run("present barrier proceeds", func(t *testing.T) {
		fake := &fakeNftInstaller{}
		nftInstaller = fake
		if !ensureEarlyInputProtectionForNaming() {
			t.Fatal("gate refused with the barrier present")
		}
		if fake.earlyInputBarrierPresentCalls != 1 {
			t.Fatalf("presence attestations = %d, want 1", fake.earlyInputBarrierPresentCalls)
		}
	})

	t.Run("absent barrier reinstalls and proceeds", func(t *testing.T) {
		fake := &fakeNftInstaller{
			earlyInputBarrierPresent: func() (bool, error) { return false, nil },
		}
		nftInstaller = fake
		if !ensureEarlyInputProtectionForNaming() {
			t.Fatal("gate refused after a successful reinstall")
		}
		installs := 0
		for _, call := range fake.earlyInputBarrierCalls {
			if call == "install" {
				installs++
			}
		}
		if installs != 1 {
			t.Fatalf("barrier install calls = %d, want 1 self-heal reinstall", installs)
		}
	})

	t.Run("absent barrier with unusable nft proceeds loudly", func(t *testing.T) {
		fake := &fakeNftInstaller{
			earlyInputBarrierPresent: func() (bool, error) { return false, nil },
			earlyInputBarrierInstall: func() error { return errors.New("nft unavailable") },
		}
		nftInstaller = fake
		nftProbeAvailable = func() error { return errors.New("no nf_tables") }
		if !ensureEarlyInputProtectionForNaming() {
			t.Fatal("gate refused on an unenforceable platform; boot must never brick where no enforcement is possible")
		}
	})

	t.Run("absent barrier with usable nft refuses", func(t *testing.T) {
		fake := &fakeNftInstaller{
			earlyInputBarrierPresent: func() (bool, error) { return false, nil },
			earlyInputBarrierInstall: func() error { return errors.New("reinstall failed") },
		}
		nftInstaller = fake
		nftProbeAvailable = func() error { return nil }
		if ensureEarlyInputProtectionForNaming() {
			t.Fatal("gate proceeded with protection known-absent and nft usable")
		}
	})

	t.Run("readback error proceeds", func(t *testing.T) {
		fake := &fakeNftInstaller{
			earlyInputBarrierPresent: func() (bool, error) { return false, errors.New("netlink readback failed") },
		}
		nftInstaller = fake
		if !ensureEarlyInputProtectionForNaming() {
			t.Fatal("gate refused on a presence-readback error; it blocks on known-absent, not on unobservable")
		}
	})

	t.Run("naming policy performs no link activation on gate refusal", func(t *testing.T) {
		nftInstaller = &fakeNftInstaller{
			earlyInputBarrierPresent: func() (bool, error) { return false, nil },
			earlyInputBarrierInstall: func() error { return errors.New("reinstall failed") },
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

func TestEarlyInputBootstrapHandoff10751(t *testing.T) {
	orig := nftInstaller
	t.Cleanup(func() { nftInstaller = orig })

	t.Run("bootstrap lifts the barrier", func(t *testing.T) {
		fake := &fakeNftInstaller{}
		nftInstaller = fake
		d := &Daemon{}
		d.bootstrapMode.Store(true)
		d.removeEarlyInputBarrierForBootstrap("test-bootstrap")
		if len(fake.earlyInputBarrierCalls) != 1 || fake.earlyInputBarrierCalls[0] != "remove" {
			t.Fatalf("barrier calls = %v, want a single bootstrap lift", fake.earlyInputBarrierCalls)
		}
		if !d.earlyInputHandoffDone.Load() {
			t.Fatal("bootstrap lift must mark the handoff done")
		}
	})

	t.Run("bootstrap lift failure is loud but non-fatal", func(t *testing.T) {
		nftInstaller = &fakeNftInstaller{
			earlyInputBarrierRemove: func() error { return errors.New("kernel delete failed") },
		}
		d := &Daemon{}
		d.bootstrapMode.Store(true)
		d.removeEarlyInputBarrierForBootstrap("test-bootstrap")
		if d.earlyInputHandoffDone.Load() {
			t.Fatal("failed bootstrap lift must not mark the handoff done")
		}
	})

	t.Run("fail-closed fences install before the bootstrap lift", func(t *testing.T) {
		d, fake := failClosedBootFixture(t)
		var events []string
		fake.coldBootFence = func(xnft.FenceSpec) error { events = append(events, "host-fence"); return nil }
		fake.lo0ColdBootFence = func(xnft.FenceSpec) error { events = append(events, "lo0-fence"); return nil }
		fake.earlyInputBarrierRemove = func() error { events = append(events, "lift-barrier"); return nil }
		d.bootstrapMode.Store(true)
		// initManagers order: fail-closed fences first, then the bootstrap lift.
		d.installFailClosedBootHostFences(true)
		d.removeEarlyInputBarrierForBootstrap("test-fail-closed")
		want := "host-fence,lo0-fence,lift-barrier"
		if got := strings.Join(events, ","); got != want {
			t.Fatalf("bootstrap order = %q, want %q (data fences must own their scope before the global lift)", got, want)
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
