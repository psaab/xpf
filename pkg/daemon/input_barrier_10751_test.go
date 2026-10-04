package daemon

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	"github.com/psaab/xpf/pkg/networkd"
	xnft "github.com/psaab/xpf/pkg/nftables"
	"github.com/psaab/xpf/pkg/vrrp"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
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

	t.Run("addressless multicast fallback keeps barrier for pending address", func(t *testing.T) {
		var events []string
		installErr := errors.New("real host-inbound load failed")
		nftInstaller = &fakeNftInstaller{
			hostInbound: func(xnft.HostInboundSpec) error {
				events = append(events, "real")
				return installErr
			},
			coldBootFence: func(xnft.FenceSpec) error {
				events = append(events, "catalog-multicast-fallback")
				return nil
			},
			earlyInputBarrierRemove: func() error {
				events = append(events, "remove-input-barrier")
				return nil
			},
		}
		d := &Daemon{}
		if err := d.applyHostInboundFilter(addresslessProgramOnlyConfig10751(t)); !errors.Is(err, installErr) {
			t.Fatalf("catalog-only fallback error = %v, want real install error", err)
		}
		if got := strings.Join(events, ","); got != "real,catalog-multicast-fallback" {
			t.Fatalf("catalog-only fallback lifecycle = %q, barrier must remain until the pending local address is covered", got)
		}
		if !d.hostInboundEnforced.Load() {
			t.Fatal("addressless catalog fallback must publish multicast enforcement")
		}
		if d.earlyInputHandoffDone.Load() {
			t.Fatal("catalog fallback must not hand off while the local-address intent is pending")
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
		// Production order via installBootstrapInputProtection (initManagers
		// calls this; reversing it must break this cell).
		d.installBootstrapInputProtection(true)
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
		d.installBootstrapInputProtection(true)
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
		d.installBootstrapInputProtection(true)
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
		{section: serviceSection, want: "ExecStart=/usr/local/sbin/xpfd input-barrier ensure"},
		{section: serviceSection, want: "ExecReload=/usr/local/sbin/xpfd input-barrier ensure"},
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
		pendingOf := func(cfg *config.Config) bool {
			return hostInboundHasPendingEnforcingIntentFromSnapshots(cfg, dpuserspace.BuildInterfaceSnapshots(cfg))
		}
		if !pendingOf(phase1) {
			t.Fatal("phase-1 fixture has no pending intent; the retention half would be vacuous")
		}
		if zonesSilent && len(dpuserspace.AddresslessEnforcingZones(phase1)) != 0 {
			t.Fatal("phase-1 fixture must be zone-silent so only interface/family granularity catches it")
		}
		if pendingOf(phase2) {
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
		{"narrowed fxp0 stays out even when detected", "hb0", "", false, "fxp0", false,
			[]string{"hb0", "em0", "fab0", "fab1", "vrf-mgmt"}, []string{"fxp0"}},
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

	t.Run("handoff readback error reinstalls and refuses", func(t *testing.T) {
		fake := &fakeNftInstaller{
			earlyInputBarrierPresent: func() (bool, error) { return false, errors.New("unreadable") },
		}
		nftInstaller = fake
		d := &Daemon{}
		err := d.applyHostInboundFilter(hostInboundTestConfig())
		if err == nil || !strings.Contains(err.Error(), "handoff refused") {
			t.Fatalf("tripwire error = %v, want handoff refusal on unreadable state", err)
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

func TestEarlyInputRefusalAbortsActivationBoundary10751(t *testing.T) {
	origInstaller, origProbe := nftInstaller, nftProbeAvailable
	t.Cleanup(func() { nftInstaller, nftProbeAvailable = origInstaller, origProbe })
	refuseInstaller := func() {
		nftInstaller = &fakeNftInstaller{
			earlyInputBarrierPresent: func() (bool, error) { return false, nil },
			earlyInputBarrierLifelineInstall: func([]string) error {
				return errors.New("guard install failed")
			},
		}
		nftProbeAvailable = func() error { return nil }
	}

	t.Run("startup naming refusal aborts with no link ops", func(t *testing.T) {
		refuseInstaller()
		var linkOps []string
		oldByName, oldDown, oldName, oldUp := nlLinkByName, nlLinkSetDown, nlLinkSetName, nlLinkSetUp
		t.Cleanup(func() {
			nlLinkByName, nlLinkSetDown, nlLinkSetName, nlLinkSetUp = oldByName, oldDown, oldName, oldUp
		})
		nlLinkByName = func(name string) (netlink.Link, error) {
			linkOps = append(linkOps, "byname:"+name)
			return nil, errors.New("no links in refusal test")
		}
		nlLinkSetDown = func(netlink.Link) error { linkOps = append(linkOps, "down"); return nil }
		nlLinkSetName = func(netlink.Link, string) error { linkOps = append(linkOps, "rename"); return nil }
		nlLinkSetUp = func(netlink.Link) error { linkOps = append(linkOps, "up"); return nil }
		d := &Daemon{store: newConfigStore(t, filepath.Join(t.TempDir(), "config.db"))}
		err := d.setupInterfaceNaming()
		if !errors.Is(err, errEarlyInputProtectionRefused) {
			t.Fatalf("setupInterfaceNaming error = %v, want barrier refusal sentinel", err)
		}
		if len(linkOps) != 0 {
			t.Fatalf("link operations after refusal = %v, want none", linkOps)
		}
	})

	t.Run("config apply aborts before reconcile on refusal", func(t *testing.T) {
		installFakeNetworkctl(t)
		refuseInstaller()
		tailCalled := false
		if fake, ok := nftInstaller.(*fakeNftInstaller); ok {
			fake.hostInbound = func(xnft.HostInboundSpec) error { tailCalled = true; return nil }
			fake.lo0 = func(xnft.Lo0FilterSpec) error { tailCalled = true; return nil }
		}
		dp := &runtimeOnlyApplyTestDP{}
		d := &Daemon{
			networkd: networkd.NewInDir(t.TempDir()),
			store:    newConfigStore(t, filepath.Join(t.TempDir(), "config.db")),
			vrrpMgr:  vrrp.NewManager(),
			opts:     Options{NoDataplane: true},
		}
		d.setDataplane(dp)
		cfg := &config.Config{}
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
		if err == nil || !strings.Contains(err.Error(), "early host-input guard") {
			t.Fatalf("apply error = %v, want pre-apply guard refusal", err)
		}
		if tailCalled {
			t.Fatal("host-inbound/lo0 tail ran after a pre-apply refusal")
		}
		if dp.applyCalls != 0 {
			t.Fatalf("dataplane apply ran %d times after refusal, want 0", dp.applyCalls)
		}
	})
}

func TestEarlyInputHandoffMarker10751(t *testing.T) {
	origInstaller := nftInstaller
	origMarker := EarlyInputHandoffMarkerPath
	t.Cleanup(func() { nftInstaller = origInstaller; EarlyInputHandoffMarkerPath = origMarker })
	EarlyInputHandoffMarkerPath = filepath.Join(t.TempDir(), "early-input-handoff.done")
	nftInstaller = &fakeNftInstaller{}

	t.Run("successful handoff writes marker", func(t *testing.T) {
		d := &Daemon{}
		if err := d.applyHostInboundFilter(&config.Config{}); err != nil {
			t.Fatalf("teardown handoff: %v", err)
		}
		if !EarlyInputHandoffMarked() {
			t.Fatal("successful handoff did not write the marker file")
		}
	})

	t.Run("pre-handoff work clears stale marker", func(t *testing.T) {
		if err := os.WriteFile(EarlyInputHandoffMarkerPath, []byte("stale\n"), 0644); err != nil {
			t.Fatalf("stage stale marker: %v", err)
		}
		d := &Daemon{}
		if err := d.requireEarlyInputProtectionPreApply(&config.Config{}); err != nil {
			t.Fatalf("pre-apply converge: %v", err)
		}
		if EarlyInputHandoffMarked() {
			t.Fatal("pre-handoff work left a stale marker behind")
		}
	})
}

func TestEarlyInputGuardSwapFailedSignal10751(t *testing.T) {
	orig := nftInstaller
	t.Cleanup(func() { nftInstaller = orig })
	withFailClosedBootDetect(t, func() (string, bool, error) { return "hb0", true, nil })

	d := &Daemon{}
	d.bootstrapMode.Store(true)
	if d.EarlyInputGuardSwapFailed() {
		t.Fatal("fresh daemon reports swap failure")
	}
	nftInstaller = &fakeNftInstaller{
		earlyInputBarrierLifelineInstall: func([]string) error { return errors.New("nope") },
	}
	d.ensureEarlyInputBootstrapGuard()
	if !d.EarlyInputGuardSwapFailed() {
		t.Fatal("failed swap did not latch the signal")
	}
	nftInstaller = &fakeNftInstaller{}
	d.ensureEarlyInputBootstrapGuard()
	if d.EarlyInputGuardSwapFailed() {
		t.Fatal("successful swap did not clear the signal")
	}
}

// TestHandoffClearsSwapFailedLatch10751: a bootstrap swap failure latches
// the signal (global barrier retained), but a LATER completed handoff —
// the recovery path — must clear it. Otherwise a recovered box keeps
// reporting swap-failed with the gauge and /health stuck on (#10751 R4-7).
// RED on revert: drop the clear and the latch stays set after handoff.
func TestHandoffClearsSwapFailedLatch10751(t *testing.T) {
	orig := nftInstaller
	t.Cleanup(func() { nftInstaller = orig })
	nftInstaller = &fakeNftInstaller{
		earlyInputBarrierLifelineInstall: func([]string) error { return errors.New("swap failed") },
	}
	d := &Daemon{}
	d.ensureEarlyInputBootstrapGuard()
	if !d.EarlyInputGuardSwapFailed() {
		t.Fatal("failed swap must latch the signal")
	}
	nftInstaller = &fakeNftInstaller{} // heal: the handoff path succeeds
	if err := d.applyHostInboundFilter(hostInboundTestConfig()); err != nil {
		t.Fatalf("handoff apply: %v", err)
	}
	if !d.earlyInputHandoffDone.Load() {
		t.Fatal("apply must have handed off")
	}
	if d.EarlyInputGuardSwapFailed() {
		t.Fatal("a completed handoff must clear a latched swap failure")
	}
}

// --- #10751 R4-2: single-snapshot handoff (transition injection) ---
//
// The install inputs render from one sample; the handoff re-samples and
// refuses when an address appeared since. These cells script that transition
// through sampleHostInboundSnapshots: the first call (install sample)
// returns s1, later calls (handoff re-sample) return s2.

func scriptedSnap10751(name, zone string, addrs ...dpuserspace.InterfaceAddressSnapshot) dpuserspace.InterfaceSnapshot {
	return dpuserspace.InterfaceSnapshot{Name: name, Zone: zone, IsUnit: true, LinuxName: name, Addresses: addrs}
}

func scriptedAddr10751(fam, cidr string, scope int) dpuserspace.InterfaceAddressSnapshot {
	return dpuserspace.InterfaceAddressSnapshot{Family: fam, Address: cidr, Scope: scope}
}

func scriptSnapshotTransition10751(t *testing.T, s1, s2 []dpuserspace.InterfaceSnapshot) *int {
	t.Helper()
	orig := sampleHostInboundSnapshots
	t.Cleanup(func() { sampleHostInboundSnapshots = orig })
	calls := 0
	sampleHostInboundSnapshots = func(*config.Config) []dpuserspace.InterfaceSnapshot {
		calls++
		if calls == 1 {
			return s1
		}
		return s2
	}
	return &calls
}

// newcomerCfg10751 builds a single-zone config over scripted units. Addresses
// live ONLY in the scripted snapshots (the FromSnapshots cores never merge
// config addresses), so units carry just identity plus DHCP flags.
func newcomerCfg10751(zone string, units map[string]*config.InterfaceUnit) *config.Config {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{}
	var refs []string
	for name, unit := range units {
		cfg.Interfaces.Interfaces[name] = &config.InterfaceConfig{Name: name, Units: map[int]*config.InterfaceUnit{unit.Number: unit}}
		refs = append(refs, fmt.Sprintf("%s.%d", name, unit.Number))
	}
	sort.Strings(refs)
	cfg.Security.Zones = map[string]*config.ZoneConfig{zone: {Name: zone, Interfaces: refs}}
	return cfg
}

func assertBarrierRetained10751(t *testing.T, fake *fakeNftInstaller, d *Daemon) {
	t.Helper()
	for _, ev := range fake.earlyInputBarrierCalls {
		if ev == "remove" {
			t.Fatalf("barrier calls = %v: a newcomer must retain, never remove", fake.earlyInputBarrierCalls)
		}
	}
	if d.earlyInputHandoffDone.Load() {
		t.Fatal("handoff marked done over an uncovered newcomer")
	}
	if !d.hostInboundLastApplyFailed.Load() {
		t.Fatal("newcomer abort must record STALE so the commit result agrees with applied state")
	}
}

// TestSnapshotNewcomerRetainsBarrierRealInstall10751: a static unit (pending
// impossible — no DHCP flags) whose re-sample gains an address. The install
// covered only the install sample, so the handoff refuses with a retry
// error. RED on revert: drop the newcomer block and the apply succeeds with
// a removal.
func TestSnapshotNewcomerRetainsBarrierRealInstall10751(t *testing.T) {
	orig := nftInstaller
	t.Cleanup(func() { nftInstaller = orig })
	fake := &fakeNftInstaller{}
	nftInstaller = fake
	cfg := newcomerCfg10751("trust", map[string]*config.InterfaceUnit{"ge-0/0/0": {Number: 0}})
	v4 := scriptedAddr10751("inet", "10.0.0.1/24", int(netlink.SCOPE_UNIVERSE))
	newcomer := scriptedAddr10751("inet6", "2001:db8::99/64", int(netlink.SCOPE_UNIVERSE))
	s1 := []dpuserspace.InterfaceSnapshot{scriptedSnap10751("ge-0/0/0.0", "trust", v4)}
	s2 := []dpuserspace.InterfaceSnapshot{scriptedSnap10751("ge-0/0/0.0", "trust", v4, newcomer)}
	if hostInboundHasPendingEnforcingIntentFromSnapshots(cfg, s1) || hostInboundHasPendingEnforcingIntentFromSnapshots(cfg, s2) {
		t.Fatal("static fixture must be pending-free on both samples; else the cell cannot isolate the newcomer check")
	}
	calls := scriptSnapshotTransition10751(t, s1, s2)
	d := &Daemon{}
	err := d.applyHostInboundFilter(cfg)
	if err == nil || !strings.Contains(err.Error(), "changed during apply") {
		t.Fatalf("apply err = %v, want newcomer retry error", err)
	}
	assertBarrierRetained10751(t, fake, d)
	if *calls != 2 {
		t.Fatalf("snapshot samples = %d, want 2 (install + handoff re-sample)", *calls)
	}
}

// TestSnapshotNewcomerBeatsPendingMasking10751 is the core race cell: sibling
// A is resolved while sibling B's DHCPv6 lease lands BETWEEN the install
// sample and the handoff re-sample. The re-sample alone is pending-free, so
// without the newcomer check the handoff would proceed with the lease
// uncovered; the install covered A only. RED on revert: same as above.
func TestSnapshotNewcomerBeatsPendingMasking10751(t *testing.T) {
	orig := nftInstaller
	t.Cleanup(func() { nftInstaller = orig })
	fake := &fakeNftInstaller{}
	nftInstaller = fake
	cfg := newcomerCfg10751("trust", map[string]*config.InterfaceUnit{
		"ge-0/0/0": {Number: 0},
		"ge-0/0/1": {Number: 0, DHCPv6: true},
	})
	v4 := scriptedAddr10751("inet", "10.0.0.1/24", int(netlink.SCOPE_UNIVERSE))
	lease := scriptedAddr10751("inet6", "2001:db8::7/64", int(netlink.SCOPE_UNIVERSE))
	s1 := []dpuserspace.InterfaceSnapshot{
		scriptedSnap10751("ge-0/0/0.0", "trust", v4),
		scriptedSnap10751("ge-0/0/1.0", "trust"),
	}
	s2 := []dpuserspace.InterfaceSnapshot{
		scriptedSnap10751("ge-0/0/0.0", "trust", v4),
		scriptedSnap10751("ge-0/0/1.0", "trust", lease),
	}
	if !hostInboundHasPendingEnforcingIntentFromSnapshots(cfg, s1) {
		t.Fatal("S1 must be pending (B DHCPv6-unresolved); else the transition is vacuous")
	}
	if hostInboundHasPendingEnforcingIntentFromSnapshots(cfg, s2) {
		t.Fatal("S2 must be pending-free; else the test cannot prove the newcomer check (not pending) retained")
	}
	scriptSnapshotTransition10751(t, s1, s2)
	d := &Daemon{}
	err := d.applyHostInboundFilter(cfg)
	if err == nil || !strings.Contains(err.Error(), "changed during apply") {
		t.Fatalf("apply err = %v, want newcomer retry error", err)
	}
	assertBarrierRetained10751(t, fake, d)
}

// TestSnapshotNewcomerLinkLocalRetainsBarrier10751: a NEW link-local (a link
// that came up mid-apply) is uncovered by the install sample's ruleset
// exactly like a new global — installed views deny fe80 destinations, so
// handing off over it would open link-local host input under `policy
// accept`. The newcomer comparison is include-all; scope-link is excluded
// ONLY from pending-intent resolution.
func TestSnapshotNewcomerLinkLocalRetainsBarrier10751(t *testing.T) {
	orig := nftInstaller
	t.Cleanup(func() { nftInstaller = orig })
	fake := &fakeNftInstaller{}
	nftInstaller = fake
	cfg := newcomerCfg10751("trust", map[string]*config.InterfaceUnit{"ge-0/0/0": {Number: 0}})
	v4 := scriptedAddr10751("inet", "10.0.0.1/24", int(netlink.SCOPE_UNIVERSE))
	ll := scriptedAddr10751("inet6", "fe80::7/64", int(netlink.SCOPE_LINK))
	s1 := []dpuserspace.InterfaceSnapshot{scriptedSnap10751("ge-0/0/0.0", "trust", v4)}
	s2 := []dpuserspace.InterfaceSnapshot{scriptedSnap10751("ge-0/0/0.0", "trust", v4, ll)}
	scriptSnapshotTransition10751(t, s1, s2)
	d := &Daemon{}
	err := d.applyHostInboundFilter(cfg)
	if err == nil || !strings.Contains(err.Error(), "changed during apply") || !strings.Contains(err.Error(), "fe80::7") {
		t.Fatalf("apply err = %v, want newcomer retry error naming fe80::7", err)
	}
	assertBarrierRetained10751(t, fake, d)
}

// TestSnapshotNewcomerRetainsBarrierFallback10751: the fenced-fallback path
// (real install failed, cold-boot fence standing) re-samples too — the
// fence covered the install sample only. The fence path reports uncovered
// destinations (not "changed": a stable fence-withheld address is
// uncovered without any change).
func TestSnapshotNewcomerRetainsBarrierFallback10751(t *testing.T) {
	orig := nftInstaller
	t.Cleanup(func() { nftInstaller = orig })
	installErr := errors.New("real host-inbound load failed")
	fake := &fakeNftInstaller{hostInbound: func(xnft.HostInboundSpec) error { return installErr }}
	nftInstaller = fake
	cfg := newcomerCfg10751("trust", map[string]*config.InterfaceUnit{"ge-0/0/0": {Number: 0}})
	v4 := scriptedAddr10751("inet", "10.0.0.1/24", int(netlink.SCOPE_UNIVERSE))
	newcomer := scriptedAddr10751("inet6", "2001:db8::99/64", int(netlink.SCOPE_UNIVERSE))
	s1 := []dpuserspace.InterfaceSnapshot{scriptedSnap10751("ge-0/0/0.0", "trust", v4)}
	s2 := []dpuserspace.InterfaceSnapshot{scriptedSnap10751("ge-0/0/0.0", "trust", v4, newcomer)}
	scriptSnapshotTransition10751(t, s1, s2)
	d := &Daemon{}
	err := d.applyHostInboundFilter(cfg)
	if err == nil || !strings.Contains(err.Error(), "not covered by installed fallback") || !strings.Contains(err.Error(), installErr.Error()) {
		t.Fatalf("apply err = %v, want joined real-install + fallback-coverage errors", err)
	}
	assertBarrierRetained10751(t, fake, d)
}

// TestSnapshotNewcomerAbortsTeardownHandoff10751: the no-enforcement teardown
// deleted on the install sample's premise (nothing to enforce); an address
// in the re-sample aborts the handoff with a retry error (the newcomer arm
// runs before the pending arm, so this errors rather than silently
// retaining).
func TestSnapshotNewcomerAbortsTeardownHandoff10751(t *testing.T) {
	orig := nftInstaller
	t.Cleanup(func() { nftInstaller = orig })
	var deleted []string
	fake := &fakeNftInstaller{del: func(name string) error { deleted = append(deleted, name); return nil }}
	nftInstaller = fake
	cfg := newcomerCfg10751("trust", map[string]*config.InterfaceUnit{"ge-0/0/0": {Number: 0, DHCP: true, DHCPv6: true}})
	s2 := []dpuserspace.InterfaceSnapshot{scriptedSnap10751("ge-0/0/0.0", "trust",
		scriptedAddr10751("inet", "203.0.113.5/24", int(netlink.SCOPE_UNIVERSE)))}
	scriptSnapshotTransition10751(t, nil, s2)
	d := &Daemon{}
	err := d.applyHostInboundFilter(cfg)
	if err == nil || !strings.Contains(err.Error(), "changed during apply") {
		t.Fatalf("apply err = %v, want newcomer retry error", err)
	}
	assertBarrierRetained10751(t, fake, d)
	joined := strings.Join(deleted, ",")
	if !strings.Contains(joined, xnft.HostInboundTableName) || !strings.Contains(joined, xnft.HostInboundGapTableName) {
		t.Fatalf("deleted tables = %v, want the teardown deletes to have run before the abort", deleted)
	}
}

// TestSnapshotStableHandsOff10751 (control): identical install and handoff
// samples hand off normally — the seam and the newcomer check must not
// disturb the stable path.
func TestSnapshotStableHandsOff10751(t *testing.T) {
	orig := nftInstaller
	t.Cleanup(func() { nftInstaller = orig })
	fake := &fakeNftInstaller{}
	nftInstaller = fake
	cfg := newcomerCfg10751("trust", map[string]*config.InterfaceUnit{"ge-0/0/0": {Number: 0}})
	s := []dpuserspace.InterfaceSnapshot{scriptedSnap10751("ge-0/0/0.0", "trust",
		scriptedAddr10751("inet", "10.0.0.1/24", int(netlink.SCOPE_UNIVERSE)))}
	calls := scriptSnapshotTransition10751(t, s, s)
	d := &Daemon{}
	if err := d.applyHostInboundFilter(cfg); err != nil {
		t.Fatalf("stable apply err = %v, want nil", err)
	}
	removed := false
	for _, ev := range fake.earlyInputBarrierCalls {
		removed = removed || ev == "remove"
	}
	if !removed {
		t.Fatalf("barrier calls = %v, want a removal on the stable path", fake.earlyInputBarrierCalls)
	}
	if !d.earlyInputHandoffDone.Load() {
		t.Fatal("stable apply must mark the handoff done")
	}
	if *calls != 3 {
		t.Fatalf("snapshot samples = %d, want 3 (install + handoff re-sample + post-removal re-sample)", *calls)
	}
}

// TestSnapshotRemovalStillHandsOff10751 pins the check's direction: an
// address that VANISHED since the install sample is over-denied
// harmlessly, so the handoff proceeds.
func TestSnapshotRemovalStillHandsOff10751(t *testing.T) {
	orig := nftInstaller
	t.Cleanup(func() { nftInstaller = orig })
	fake := &fakeNftInstaller{}
	nftInstaller = fake
	cfg := newcomerCfg10751("trust", map[string]*config.InterfaceUnit{"ge-0/0/0": {Number: 0}})
	v4 := scriptedAddr10751("inet", "10.0.0.1/24", int(netlink.SCOPE_UNIVERSE))
	gone := scriptedAddr10751("inet6", "2001:db8::99/64", int(netlink.SCOPE_UNIVERSE))
	s1 := []dpuserspace.InterfaceSnapshot{scriptedSnap10751("ge-0/0/0.0", "trust", v4, gone)}
	s2 := []dpuserspace.InterfaceSnapshot{scriptedSnap10751("ge-0/0/0.0", "trust", v4)}
	scriptSnapshotTransition10751(t, s1, s2)
	d := &Daemon{}
	if err := d.applyHostInboundFilter(cfg); err != nil {
		t.Fatalf("removal-direction apply err = %v, want nil", err)
	}
	if !d.earlyInputHandoffDone.Load() {
		t.Fatal("a vanished address must not block the handoff")
	}
}

// --- #10751 R4-5: post-remove enforcement readback ---
//
// After a successful barrier removal the handoff re-reads the presence of
// the enforcement tables it relies on: a flush interleaved between the
// install and the removal wipes enforcement while absent-removal still
// succeeds.

// TestHandoffRefusesWhenEnforcementMissingAfterRemove10751: barrier present
// at attestation, removal succeeds, but the just-installed table is gone at
// re-read — reinstall the guard and refuse WITHOUT recording handoff-done.
// RED on revert: drop the post-remove loop and the handoff succeeds.
func TestHandoffRefusesWhenEnforcementMissingAfterRemove10751(t *testing.T) {
	orig := nftInstaller
	t.Cleanup(func() { nftInstaller = orig })
	fake := &fakeNftInstaller{
		earlyInputBarrierPresent: func() (bool, error) { return true, nil },
		tableEnforcing: func(name string) (bool, error) {
			if name == xnft.HostInboundTableName {
				return false, nil // wiped between install and removal
			}
			return true, nil
		},
	}
	nftInstaller = fake
	d := &Daemon{}
	err := d.applyHostInboundFilter(hostInboundTestConfig())
	if err == nil || !strings.Contains(err.Error(), "missing after barrier removal") {
		t.Fatalf("apply err = %v, want post-remove enforcement refusal", err)
	}
	var removes, reinstalls int
	for _, ev := range fake.earlyInputBarrierCalls {
		switch ev {
		case "remove":
			removes++
		case "install-lifeline":
			reinstalls++
		}
	}
	if removes != 1 {
		t.Fatalf("barrier calls = %v, want exactly the attested removal to have run", fake.earlyInputBarrierCalls)
	}
	if reinstalls != 2 {
		t.Fatalf("barrier calls = %v, want pre-apply converge + post-verify reinstall", fake.earlyInputBarrierCalls)
	}
	if d.earlyInputHandoffDone.Load() {
		t.Fatal("handoff marked done over wiped enforcement")
	}
	if !d.hostInboundLastApplyFailed.Load() {
		t.Fatal("post-remove refusal must record STALE")
	}
}

// TestHandoffRefusesOnUnreadableEnforcement10751: an unreadable post-remove
// readback refuses too — it cannot prove the enforcement survived.
func TestHandoffRefusesOnUnreadableEnforcement10751(t *testing.T) {
	orig := nftInstaller
	t.Cleanup(func() { nftInstaller = orig })
	readErr := errors.New("nftables list denied")
	fake := &fakeNftInstaller{
		earlyInputBarrierPresent: func() (bool, error) { return true, nil },
		tableEnforcing:           func(string) (bool, error) { return false, readErr },
	}
	nftInstaller = fake
	d := &Daemon{}
	err := d.applyHostInboundFilter(hostInboundTestConfig())
	if err == nil || !strings.Contains(err.Error(), "unreadable after barrier removal") {
		t.Fatalf("apply err = %v, want unreadable-readback refusal", err)
	}
	if d.earlyInputHandoffDone.Load() {
		t.Fatal("handoff marked done over unverifiable enforcement")
	}
}

// TestHandoffVerifiesGapTableWhenStanding10751: a fallback handoff with a
// standing gap fence expects BOTH tables; a missing gap table refuses even
// when the main table reads present.
func TestHandoffVerifiesGapTableWhenStanding10751(t *testing.T) {
	orig := nftInstaller
	t.Cleanup(func() { nftInstaller = orig })
	installErr := errors.New("real host-inbound load failed")
	fake := &fakeNftInstaller{
		hostInbound:              func(xnft.HostInboundSpec) error { return installErr },
		earlyInputBarrierPresent: func() (bool, error) { return true, nil },
		tableEnforcing: func(name string) (bool, error) {
			return name != xnft.HostInboundGapTableName, nil
		},
	}
	nftInstaller = fake
	d := &Daemon{}
	d.hostInboundEnforced.Store(true) // retained generation; empty coverage forces a gap
	d.hostInboundCoveredAddrs = map[string]struct{}{}
	err := d.applyHostInboundFilter(hostInboundTestConfig())
	if err == nil || !strings.Contains(err.Error(), xnft.HostInboundGapTableName) || !strings.Contains(err.Error(), "missing after barrier removal") {
		t.Fatalf("apply err = %v, want gap-table post-remove refusal", err)
	}
	if !d.hostInboundGapFenceActive.Load() {
		t.Fatal("fixture must have installed a gap fence; else the cell is vacuous")
	}
	if got, want := fake.tableEnforcingCalls, []string{xnft.HostInboundTableName, xnft.HostInboundGapTableName}; !reflect.DeepEqual(got, want) {
		t.Fatalf("tableEnforcing calls = %v, want %v", got, want)
	}
	if d.earlyInputHandoffDone.Load() {
		t.Fatal("handoff marked done with the gap table missing")
	}
}

// TestHandoffSkipsVerifyOnTeardown10751: the no-enforcement teardown passes
// no expected tables — intended-empty needs no readback, so even a
// report-everything-absent kernel still hands off, consulting nothing.
func TestHandoffSkipsVerifyOnTeardown10751(t *testing.T) {
	orig := nftInstaller
	t.Cleanup(func() { nftInstaller = orig })
	fake := &fakeNftInstaller{
		earlyInputBarrierPresent: func() (bool, error) { return true, nil },
		tableEnforcing:           func(string) (bool, error) { return false, nil },
	}
	nftInstaller = fake
	d := &Daemon{}
	if err := d.applyHostInboundFilter(&config.Config{}); err != nil {
		t.Fatalf("teardown apply err = %v, want nil", err)
	}
	if !d.earlyInputHandoffDone.Load() {
		t.Fatal("teardown must hand off without consulting table enforcement")
	}
	if len(fake.tableEnforcingCalls) != 0 {
		t.Fatalf("tableEnforcing calls = %v, want none on the teardown path", fake.tableEnforcingCalls)
	}
}

// TestNoDHCPLinkLocalOnlyHandsOff10751 (#10751 R5-A lifecycle): a
// non-lifeline enforcing unit with only automatic fe80::/64 and NO DHCP
// intent installs its link-local deny and COMPLETES the handoff — the
// installed rules already cover its only reachable address, so retaining
// the global barrier would strand it indefinitely with no lease ever
// arriving. RED on revert: without the DHCP-intent guard the zone stays
// pending and no removal runs.
func TestNoDHCPLinkLocalOnlyHandsOff10751(t *testing.T) {
	orig := nftInstaller
	t.Cleanup(func() { nftInstaller = orig })
	var specs []xnft.HostInboundSpec
	fake := &fakeNftInstaller{
		hostInbound: func(spec xnft.HostInboundSpec) error {
			specs = append(specs, spec)
			return nil
		},
	}
	nftInstaller = fake
	cfg := newcomerCfg10751("trust", map[string]*config.InterfaceUnit{"ge-0/0/0": {Number: 0}})
	s := []dpuserspace.InterfaceSnapshot{scriptedSnap10751("ge-0/0/0.0", "trust",
		scriptedAddr10751("inet6", "fe80::7/64", int(netlink.SCOPE_LINK)))}
	scriptSnapshotTransition10751(t, s, s)
	d := &Daemon{}
	if err := d.applyHostInboundFilter(cfg); err != nil {
		t.Fatalf("LL-only no-DHCP apply err = %v, want nil (handoff must complete)", err)
	}
	if len(specs) != 1 {
		t.Fatalf("real installs = %d, want 1 (the LL deny must install)", len(specs))
	}
	covered := false
	for _, v := range specs[0].Views {
		for _, a := range v.V6Addrs {
			covered = covered || a == "fe80::7"
		}
	}
	if !covered {
		t.Fatalf("installed spec views = %+v, want fe80::7 denied", specs[0].Views)
	}
	removed := false
	for _, ev := range fake.earlyInputBarrierCalls {
		removed = removed || ev == "remove"
	}
	if !removed {
		t.Fatalf("barrier calls = %v, want a removal: LL-only no-DHCP must hand off", fake.earlyInputBarrierCalls)
	}
	if !d.earlyInputHandoffDone.Load() {
		t.Fatal("handoff must be marked done")
	}
}

// --- #10751 R5-B: coverage-proof newcomer + post-removal re-sample ---

// scriptSnapshot3Phase10751 scripts install (S1), handoff re-sample (S2),
// and post-removal re-sample (S3) independently.
func scriptSnapshot3Phase10751(t *testing.T, s1, s2, s3 []dpuserspace.InterfaceSnapshot) *int {
	t.Helper()
	orig := sampleHostInboundSnapshots
	t.Cleanup(func() { sampleHostInboundSnapshots = orig })
	calls := 0
	sampleHostInboundSnapshots = func(*config.Config) []dpuserspace.InterfaceSnapshot {
		calls++
		switch calls {
		case 1:
			return s1
		case 2:
			return s2
		default:
			return s3
		}
	}
	return &calls
}

// TestCoverageNewcomerFindsLifelineWithheld10751: 10.0.0.5 lives on the
// lifeline in S1 (withheld from the rendered scope, never denied), then
// appears on a data interface in S2 whose zone admits ssh (non-empty view
// keeps the shared address, so it IS rendered). Raw bare-IP comparison
// would miss it — the IP exists in S1 rows — but the S1 rendered scope
// never covered it, so the handoff must refuse. RED on revert: compare
// raw rows and the handoff succeeds over the uncovered destination.
func TestCoverageNewcomerFindsLifelineWithheld10751(t *testing.T) {
	orig := nftInstaller
	t.Cleanup(func() { nftInstaller = orig })
	fake := &fakeNftInstaller{}
	nftInstaller = fake
	cfg := newcomerCfg10751("trust", map[string]*config.InterfaceUnit{"ge-0/0/0": {Number: 0}})
	cfg.Security.Zones["trust"].HostInboundTraffic = &config.HostInboundTraffic{SystemServices: []string{"ssh"}}
	uni := int(netlink.SCOPE_UNIVERSE)
	y := scriptedAddr10751("inet", "10.0.0.1/24", uni)
	shared := scriptedAddr10751("inet", "10.0.0.5/24", uni)
	llRow := func(addrs ...dpuserspace.InterfaceAddressSnapshot) dpuserspace.InterfaceSnapshot {
		return scriptedSnap10751("fxp0.0", "", addrs...)
	}
	s1 := []dpuserspace.InterfaceSnapshot{
		llRow(shared),
		scriptedSnap10751("ge-0/0/0.0", "trust", y),
	}
	s2 := []dpuserspace.InterfaceSnapshot{
		llRow(shared),
		scriptedSnap10751("ge-0/0/0.0", "trust", y, shared),
	}
	// Preconditions proving the cell discriminates rendered coverage from
	// raw presence: S1 rows carry the bare IP, but the S1 rendered scope
	// does not, while the S2 rendered scope does.
	s1views := dpuserspace.BuildZoneHostInboundViewsFromSnapshots(cfg, s1)
	for _, v := range s1views {
		for _, a := range v.V4Addrs {
			if a == "10.0.0.5" {
				t.Fatalf("S1 rendered scope unexpectedly covers 10.0.0.5: %+v", s1views)
			}
		}
	}
	s2covered := false
	for _, v := range dpuserspace.BuildZoneHostInboundViewsFromSnapshots(cfg, s2) {
		for _, a := range v.V4Addrs {
			s2covered = s2covered || a == "10.0.0.5"
		}
	}
	if !s2covered {
		t.Fatal("S2 rendered scope must cover 10.0.0.5 (non-empty view keeps the shared address)")
	}
	scriptSnapshotTransition10751(t, s1, s2)
	d := &Daemon{}
	err := d.applyHostInboundFilter(cfg)
	if err == nil || !strings.Contains(err.Error(), "changed during apply") {
		t.Fatalf("apply err = %v, want coverage-newcomer retry error", err)
	}
	assertBarrierRetained10751(t, fake, d)
}

// TestCoverageNewcomerIgnoresLifelineOnly10751: an address appearing ONLY
// on a lifeline between samples is never a rendered destination, so it
// must not stall the handoff. (Raw include-all comparison would flag it
// and retry spuriously.)
func TestCoverageNewcomerIgnoresLifelineOnly10751(t *testing.T) {
	orig := nftInstaller
	t.Cleanup(func() { nftInstaller = orig })
	fake := &fakeNftInstaller{}
	nftInstaller = fake
	cfg := newcomerCfg10751("trust", map[string]*config.InterfaceUnit{"ge-0/0/0": {Number: 0}})
	uni := int(netlink.SCOPE_UNIVERSE)
	y := scriptedAddr10751("inet", "10.0.0.1/24", uni)
	z := scriptedAddr10751("inet", "10.9.9.9/24", uni)
	s1 := []dpuserspace.InterfaceSnapshot{scriptedSnap10751("ge-0/0/0.0", "trust", y)}
	s2 := []dpuserspace.InterfaceSnapshot{
		scriptedSnap10751("fxp0.0", "", z),
		scriptedSnap10751("ge-0/0/0.0", "trust", y),
	}
	scriptSnapshotTransition10751(t, s1, s2)
	d := &Daemon{}
	if err := d.applyHostInboundFilter(cfg); err != nil {
		t.Fatalf("lifeline-only newcomer apply err = %v, want nil (never a rendered destination)", err)
	}
	if !d.earlyInputHandoffDone.Load() {
		t.Fatal("a lifeline-only address must not block the handoff")
	}
}

// TestPostRemovalCoverageDriftReinstalls10751: S1 and S2 agree (pre-removal
// checks pass, the barrier is removed), but S3 — sampled AFTER removal —
// gains an address. The handoff must detect the drift, reinstall the
// guard, and refuse WITHOUT recording handoff-done: the address landed in
// the S2→removal interval, absent from both the installed ruleset and the
// finished pre-removal comparison. RED on revert: drop the S3 check and
// the handoff succeeds over the uncovered address.
func TestPostRemovalCoverageDriftReinstalls10751(t *testing.T) {
	orig := nftInstaller
	t.Cleanup(func() { nftInstaller = orig })
	fake := &fakeNftInstaller{}
	nftInstaller = fake
	cfg := newcomerCfg10751("trust", map[string]*config.InterfaceUnit{"ge-0/0/0": {Number: 0}})
	uni := int(netlink.SCOPE_UNIVERSE)
	y := scriptedAddr10751("inet", "10.0.0.1/24", uni)
	late := scriptedAddr10751("inet", "10.0.0.99/24", uni)
	s12 := []dpuserspace.InterfaceSnapshot{scriptedSnap10751("ge-0/0/0.0", "trust", y)}
	s3 := []dpuserspace.InterfaceSnapshot{scriptedSnap10751("ge-0/0/0.0", "trust", y, late)}
	calls := scriptSnapshot3Phase10751(t, s12, s12, s3)
	d := &Daemon{}
	err := d.applyHostInboundFilter(cfg)
	if err == nil || !strings.Contains(err.Error(), "after barrier removal") {
		t.Fatalf("apply err = %v, want post-removal drift refusal", err)
	}
	var removes, reinstalls int
	for _, ev := range fake.earlyInputBarrierCalls {
		switch ev {
		case "remove":
			removes++
		case "install-lifeline":
			reinstalls++
		}
	}
	if removes != 1 {
		t.Fatalf("barrier calls = %v, want the removal to have run before drift was found", fake.earlyInputBarrierCalls)
	}
	if reinstalls != 2 {
		t.Fatalf("barrier calls = %v, want pre-apply converge + post-drift guard reinstall", fake.earlyInputBarrierCalls)
	}
	if d.earlyInputHandoffDone.Load() {
		t.Fatal("handoff marked done over an address that landed after the last pre-removal sample")
	}
	if !d.hostInboundLastApplyFailed.Load() {
		t.Fatal("post-removal drift must record STALE")
	}
	if *calls != 3 {
		t.Fatalf("snapshot samples = %d, want 3 (S1 + S2 + post-removal S3)", *calls)
	}
}

// --- #10751 R5-C: durable handoff marker ---

// blockHandoffMarker10751 redirects the marker path under a regular file so
// every marker write fails deterministically (MkdirAll: not a directory).
func blockHandoffMarker10751(t *testing.T) {
	t.Helper()
	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0644); err != nil {
		t.Fatalf("stage marker blocker: %v", err)
	}
	EarlyInputHandoffMarkerPath = filepath.Join(blocker, "early-input-handoff.done")
}

// TestHandoffMarkerWriteFailureBlocksHandoff10751: a failed marker write
// blocks handoff completion — memory stays unmarked (so a later unit start
// correctly installs instead of injecting into a live handed-off daemon),
// the commit fails STALE with the enforcement recorded, and healing the
// path lets the next apply converge and complete.
// RED on revert: warn-past (nil error) completes the handoff in memory
// with no marker on disk.
func TestHandoffMarkerWriteFailureBlocksHandoff10751(t *testing.T) {
	orig := nftInstaller
	origMarker := EarlyInputHandoffMarkerPath
	t.Cleanup(func() { nftInstaller = orig; EarlyInputHandoffMarkerPath = origMarker })
	nftInstaller = &fakeNftInstaller{}
	blockHandoffMarker10751(t)
	d := &Daemon{}
	err := d.applyHostInboundFilter(hostInboundTestConfig())
	if err == nil || !strings.Contains(err.Error(), "record early-input handoff") {
		t.Fatalf("apply err = %v, want durable-marker failure", err)
	}
	if d.earlyInputHandoffDone.Load() {
		t.Fatal("memory must stay unmarked when the marker write fails")
	}
	if !d.hostInboundLastApplyFailed.Load() {
		t.Fatal("marker failure must record STALE")
	}
	if !d.hostInboundEnforced.Load() {
		t.Fatal("real table stands; must record established coverage")
	}
	EarlyInputHandoffMarkerPath = filepath.Join(t.TempDir(), "early-input-handoff.done")
	if err := d.applyHostInboundFilter(hostInboundTestConfig()); err != nil {
		t.Fatalf("healed apply err = %v, want nil", err)
	}
	if !d.earlyInputHandoffDone.Load() {
		t.Fatal("healed apply must complete the handoff")
	}
	if _, err := os.Stat(EarlyInputHandoffMarkerPath); err != nil {
		t.Fatalf("marker missing after healed handoff: %v", err)
	}
}

// TestPostHandoffMarkerRefreshBestEffort10751: once handed off, an
// idempotent marker refresh failure must NOT fail the commit (already
// durable from the first handoff; live enforcement re-checked by ensure).
func TestPostHandoffMarkerRefreshBestEffort10751(t *testing.T) {
	orig := nftInstaller
	origMarker := EarlyInputHandoffMarkerPath
	t.Cleanup(func() { nftInstaller = orig; EarlyInputHandoffMarkerPath = origMarker })
	nftInstaller = &fakeNftInstaller{}
	EarlyInputHandoffMarkerPath = filepath.Join(t.TempDir(), "early-input-handoff.done")
	d := &Daemon{}
	if err := d.applyHostInboundFilter(hostInboundTestConfig()); err != nil {
		t.Fatalf("first apply err = %v, want nil", err)
	}
	if !d.earlyInputHandoffDone.Load() {
		t.Fatal("first apply must hand off")
	}
	blockHandoffMarker10751(t)
	if err := d.applyHostInboundFilter(hostInboundTestConfig()); err != nil {
		t.Fatalf("post-handoff apply err = %v, want nil (refresh is best-effort)", err)
	}
	if !d.earlyInputHandoffDone.Load() {
		t.Fatal("post-handoff refresh failure must not unmark the handoff")
	}
}

// --- #10751 R6-A: fallback proves fence coverage ---

// TestFallbackRefusesStableSharedNotCoveredByFence10751: S1 has Y plus
// W-shared (W on lifeline fxp0.0 AND data ge-0/0/0.0) in a zone admitting
// ssh, so the REAL scope covers W but the cold-boot fence WITHHOLDS it.
// Real install fails; the fence stands scoped via Y. S2 is STABLE (no
// change). The handoff must REFUSE — the standing fallback never drops W,
// so handing off would admit all services to W via policy-accept until
// the next successful real install. Then heal real and converge. Proves
// the fence spec omits W while the real spec keeps W.
// RED on revert: baseline on S1 real desiredDrop reports no newcomer and
// hands off over the uncovered W.
func TestFallbackRefusesStableSharedNotCoveredByFence10751(t *testing.T) {
	orig := nftInstaller
	t.Cleanup(func() { nftInstaller = orig })
	installErr := errors.New("real host-inbound load failed")
	var fenceSpecs []xnft.FenceSpec
	var realSpecs []xnft.HostInboundSpec
	calls := 0
	fake := &fakeNftInstaller{
		hostInbound: func(spec xnft.HostInboundSpec) error {
			calls++
			realSpecs = append(realSpecs, spec)
			if calls == 1 {
				return installErr
			}
			return nil
		},
		coldBootFence: func(spec xnft.FenceSpec) error {
			fenceSpecs = append(fenceSpecs, spec)
			return nil
		},
	}
	nftInstaller = fake
	cfg := newcomerCfg10751("trust", map[string]*config.InterfaceUnit{"ge-0/0/0": {Number: 0}})
	cfg.Security.Zones["trust"].HostInboundTraffic = &config.HostInboundTraffic{SystemServices: []string{"ssh"}}
	uni := int(netlink.SCOPE_UNIVERSE)
	y := scriptedAddr10751("inet", "10.0.0.1/24", uni)
	w := scriptedAddr10751("inet", "10.0.0.5/24", uni)
	s := []dpuserspace.InterfaceSnapshot{
		scriptedSnap10751("fxp0.0", "", w),
		scriptedSnap10751("ge-0/0/0.0", "trust", y, w),
	}
	if hostInboundHasPendingEnforcingIntentFromSnapshots(cfg, s) {
		t.Fatal("stable scoped fixture must be pending-free; else the cell cannot isolate fence coverage")
	}
	scriptSnapshotTransition10751(t, s, s)
	d := &Daemon{}
	err := d.applyHostInboundFilter(cfg)
	if err == nil || !strings.Contains(err.Error(), "not covered by installed fallback") || !strings.Contains(err.Error(), "10.0.0.5") {
		t.Fatalf("apply err = %v, want fence-coverage refusal naming 10.0.0.5", err)
	}
	assertBarrierRetained10751(t, fake, d)
	if !d.hostInboundEnforced.Load() {
		t.Fatal("fence must stand scoped (via Y); else the handoff attempt is vacuous")
	}
	if len(fenceSpecs) != 1 {
		t.Fatalf("fence installs = %d, want 1", len(fenceSpecs))
	}
	for _, v := range fenceSpecs[0].Views {
		for _, a := range v.V4Addrs {
			if a == "10.0.0.5" {
				t.Fatalf("fence spec covers 10.0.0.5; the fence must withhold lifeline-shared: %+v", fenceSpecs[0].Views)
			}
		}
	}
	kept := false
	for _, v := range realSpecs[0].Views {
		for _, a := range v.V4Addrs {
			kept = kept || a == "10.0.0.5"
		}
	}
	if !kept {
		t.Fatalf("real spec must keep 10.0.0.5 (admitting view); got %+v", realSpecs[0].Views)
	}
	if err := d.applyHostInboundFilter(cfg); err != nil {
		t.Fatalf("healed apply err = %v, want nil", err)
	}
	if !d.earlyInputHandoffDone.Load() {
		t.Fatal("healed real install must complete the handoff")
	}
}

// TestGateRefusalLogsInstallError10751: the known-absent reinstall refusal
// must log the REAL install failure, not err=<nil> (carried Host6
// diagnostic: the log sat outside the if-scoped shadow).
func TestGateRefusalLogsInstallError10751(t *testing.T) {
	orig := nftInstaller
	t.Cleanup(func() { nftInstaller = orig })
	nftInstaller = &fakeNftInstaller{
		earlyInputBarrierPresent:         func() (bool, error) { return false, nil },
		earlyInputBarrierLifelineInstall: func([]string) error { return errors.New("guard-install failed") },
	}
	prev := slog.Default()
	var logs bytes.Buffer
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelWarn})))
	t.Cleanup(func() { slog.SetDefault(prev) })
	if ensureEarlyInputProtectionForNaming(nil) {
		t.Fatal("gate must refuse when the barrier is absent and the guard install fails")
	}
	if out := logs.String(); !strings.Contains(out, "guard-install failed") {
		t.Fatalf("refusal log = %q, want the install error, not nil", out)
	}
}

// --- #10751 R7-A: first-apply ownership marker ---

// TestHostInboundInstallRecordsFirstApplyMarker10751: a successful
// host-inbound install records first-apply ownership for `ensure`.
func TestHostInboundInstallRecordsFirstApplyMarker10751(t *testing.T) {
	orig := nftInstaller
	origMarker := HostInboundFirstApplyMarkerPath
	t.Cleanup(func() { nftInstaller = orig; HostInboundFirstApplyMarkerPath = origMarker })
	nftInstaller = &fakeNftInstaller{}
	HostInboundFirstApplyMarkerPath = filepath.Join(t.TempDir(), "host-inbound-applied.done")
	d := &Daemon{}
	if err := d.applyHostInboundFilter(hostInboundTestConfig()); err != nil {
		t.Fatalf("apply err = %v, want nil", err)
	}
	if _, err := os.Stat(HostInboundFirstApplyMarkerPath); err != nil {
		t.Fatalf("first-apply marker missing after successful install: %v", err)
	}
}

// TestHostInboundInstallMarkerBestEffort10751: an unwritable first-apply
// path must NOT fail the commit — absence only makes `ensure` install
// fail-closed (the opposite direction from the handoff marker, which
// blocks because memory-true + marker-absent would inject).
func TestHostInboundInstallMarkerBestEffort10751(t *testing.T) {
	orig := nftInstaller
	origMarker := HostInboundFirstApplyMarkerPath
	t.Cleanup(func() { nftInstaller = orig; HostInboundFirstApplyMarkerPath = origMarker })
	nftInstaller = &fakeNftInstaller{}
	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0644); err != nil {
		t.Fatalf("stage blocker: %v", err)
	}
	HostInboundFirstApplyMarkerPath = filepath.Join(blocker, "host-inbound-applied.done")
	d := &Daemon{}
	if err := d.applyHostInboundFilter(hostInboundTestConfig()); err != nil {
		t.Fatalf("apply err = %v, want nil (first-apply marker is best-effort)", err)
	}
	if !d.earlyInputHandoffDone.Load() {
		t.Fatal("handoff must complete despite the first-apply marker failure")
	}
}

// TestClearHostInboundFirstApplyMarker10751 pins the startup-clear helper
// Run uses so a new process never inherits a dead predecessor's marker.
func TestClearHostInboundFirstApplyMarker10751(t *testing.T) {
	origMarker := HostInboundFirstApplyMarkerPath
	t.Cleanup(func() { HostInboundFirstApplyMarkerPath = origMarker })
	HostInboundFirstApplyMarkerPath = filepath.Join(t.TempDir(), "host-inbound-applied.done")
	if err := os.WriteFile(HostInboundFirstApplyMarkerPath, []byte("applied\n"), 0644); err != nil {
		t.Fatalf("stage marker: %v", err)
	}
	clearHostInboundFirstApplyMarker()
	if _, err := os.Stat(HostInboundFirstApplyMarkerPath); !os.IsNotExist(err) {
		t.Fatalf("marker still present after clear: %v", err)
	}
}

// TestFirstApplyMarkerRedirectedInTests10751: the package init redirect
// (daemon_nft_netlink_testhelper_test.go) must cover the first-apply
// marker too — without it, root test runs plant
// /run/xpf/host-inbound-applied.done on the host. RED if the var still
// points at the production path; a successful install must then write
// the marker under temp.
func TestFirstApplyMarkerRedirectedInTests10751(t *testing.T) {
	if HostInboundFirstApplyMarkerPath == "/run/xpf/host-inbound-applied.done" {
		t.Fatal("first-apply marker not redirected into temp: root runs would plant host state")
	}
	orig := nftInstaller
	t.Cleanup(func() { nftInstaller = orig })
	nftInstaller = &fakeNftInstaller{}
	_ = os.Remove(HostInboundFirstApplyMarkerPath)
	d := &Daemon{}
	if err := d.applyHostInboundFilter(hostInboundTestConfig()); err != nil {
		t.Fatalf("apply err = %v, want nil", err)
	}
	if _, err := os.Stat(HostInboundFirstApplyMarkerPath); err != nil {
		t.Fatalf("marker missing at redirected path %q: %v", HostInboundFirstApplyMarkerPath, err)
	}
}

// TestMarkerOwnershipLifecycle10751 pins the M2 ownership binding: set/note
// leave the marker HELD (live), clear releases it. Uses the init-redirected
// temp paths (no redirect needed — every path through set/note/clear is
// deterministic here whether or not an earlier test already holds the
// slot, since all share the same init temp files).
func TestMarkerOwnershipLifecycle10751(t *testing.T) {
	d := &Daemon{}
	if err := d.setEarlyInputHandoffDone(); err != nil {
		t.Fatalf("set handoff err = %v, want nil", err)
	}
	if !EarlyInputHandoffLive() {
		t.Fatal("handoff marker not live after set: the daemon must hold its markers (stale ownership would install)")
	}
	assertMarkerMode060010751(t, EarlyInputHandoffMarkerPath)
	clearEarlyInputHandoffMarker()
	if EarlyInputHandoffLive() {
		t.Fatal("handoff marker still live after clear")
	}
	noteHostInboundInstalled()
	if !HostInboundFirstApplyLive() {
		t.Fatal("first-apply marker not live after note: the daemon must hold its markers")
	}
	assertMarkerMode060010751(t, HostInboundFirstApplyMarkerPath)
	clearHostInboundFirstApplyMarker()
	if HostInboundFirstApplyLive() {
		t.Fatal("first-apply marker still live after clear")
	}
	if EarlyInputHandoffMarked() || HostInboundFirstApplyMarked() {
		t.Fatal("cleared markers must report absent by existence too")
	}
}

// assertMarkerMode060010751 pins the Sec9 separation: ownership markers
// are root-only (0600), so an unprivileged UID cannot open (and therefore
// cannot flock) them to forge liveness. Deterministic under any umask
// (0600 carries no group/other bits to mask).
func assertMarkerMode060010751(t *testing.T, path string) {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	if fi.Mode().Perm() != 0600 {
		t.Fatalf("marker %s mode = %o, want 600 (unprivileged flock forgery must fail at open)", path, fi.Mode().Perm())
	}
}

// TestMarkerLivenessErrorDiscrimination10751 pins the Sec9 probe logic:
// only steady EXCLUSIVE contention reads live. An unexpected flock error
// fails closed; a transient denial clears on retry; shared-only
// contention (the SH forgery shape) reads NOT live.
func TestMarkerLivenessErrorDiscrimination10751(t *testing.T) {
	origFlock := flockFn
	origPath := EarlyInputHandoffMarkerPath
	t.Cleanup(func() { flockFn = origFlock; EarlyInputHandoffMarkerPath = origPath })
	EarlyInputHandoffMarkerPath = filepath.Join(t.TempDir(), "early-input-handoff.done")
	if err := os.WriteFile(EarlyInputHandoffMarkerPath, []byte("handed-off\n"), 0600); err != nil {
		t.Fatalf("stage marker: %v", err)
	}
	t.Run("unexpected error fails closed", func(t *testing.T) {
		flockFn = func(fd int, how int) error { return unix.ENOLCK }
		if EarlyInputHandoffLive() {
			t.Fatal("ENOLCK must read not-live (fail closed), never live-owner")
		}
	})
	t.Run("transient contention clears on retry", func(t *testing.T) {
		calls := 0
		flockFn = func(fd int, how int) error {
			calls++
			if calls <= 2 {
				return unix.EWOULDBLOCK // attempt 1: EX denied, SH denied
			}
			return nil // attempt 2: EX succeeds (transient gone)
		}
		if EarlyInputHandoffLive() {
			t.Fatal("transient contention must clear on retry (not-live)")
		}
		if calls != 3 {
			t.Fatalf("flock calls = %d, want 3 (EX, SH, EX-clear)", calls)
		}
	})
	t.Run("steady exclusive reads live", func(t *testing.T) {
		flockFn = func(fd int, how int) error { return unix.EWOULDBLOCK }
		if !EarlyInputHandoffLive() {
			t.Fatal("steady EX contention must read live-owner")
		}
	})
	t.Run("shared-only reads not-live", func(t *testing.T) {
		flockFn = func(fd int, how int) error {
			if how == unix.LOCK_SH|unix.LOCK_NB {
				return nil // no EX owner: SH succeeds
			}
			return unix.EWOULDBLOCK
		}
		if EarlyInputHandoffLive() {
			t.Fatal("SH-only contention must read not-live (LOCK_SH forgery must fail)")
		}
	})
}

// TestMarkerLockContentionBlocksHandoff10751: a persistently contended
// handoff marker (another live EX holder) fails set loudly (R5-C: no
// provable ownership, no silent memory-true) instead of proceeding
// unlocked. Transient contention is absorbed by the in-function retry.
func TestMarkerLockContentionBlocksHandoff10751(t *testing.T) {
	origPath := EarlyInputHandoffMarkerPath
	t.Cleanup(func() { EarlyInputHandoffMarkerPath = origPath })
	EarlyInputHandoffMarkerPath = filepath.Join(t.TempDir(), "early-input-handoff.done")
	if err := os.WriteFile(EarlyInputHandoffMarkerPath, []byte("handed-off\n"), 0600); err != nil {
		t.Fatalf("stage marker: %v", err)
	}
	holder, err := os.OpenFile(EarlyInputHandoffMarkerPath, os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("open staged marker: %v", err)
	}
	defer holder.Close()
	if err := unix.Flock(int(holder.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatalf("stage EX holder: %v", err)
	}
	d := &Daemon{}
	if err := d.setEarlyInputHandoffDone(); err == nil {
		t.Fatal("set with contended marker err = nil, want the lock failure (loud, no silent memory-true)")
	}
	if d.earlyInputHandoffDone.Load() {
		t.Fatal("memory marked done despite failing to prove ownership")
	}
}

// TestMarkerWriteLockBeforePublish10751 pins the Sec9 publish discipline:
// a contended write publishes NOTHING (no unlocked marker file is ever
// observable, so a polling SH loop cannot pre-position on a
// write-then-lock gap). Publish-first code leaves the file behind.
func TestMarkerWriteLockBeforePublish10751(t *testing.T) {
	path := filepath.Join(t.TempDir(), "early-input-handoff.done")
	holder, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		t.Fatalf("stage marker: %v", err)
	}
	defer holder.Close()
	if err := unix.Flock(int(holder.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatalf("stage EX holder: %v", err)
	}
	var slot *os.File
	if err := writeMarkerLocked(path, "handed-off\n", &slot); err == nil {
		t.Fatal("contended write err = nil, want the lock failure")
	}
	if slot != nil {
		t.Fatal("contended write left a slot set")
	}
	// The file exists (staged by us) but must carry NO published
	// content: the writer locked nothing and wrote nothing.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read staged marker: %v", err)
	}
	if len(raw) != 0 {
		t.Fatalf("contended write published %q without holding the lock", raw)
	}
}

// --- #10751 R7-B: unzoned DHCP interface backstop ---
//
// An unzoned DHCP unit with no lease has no destination for any catch-all,
// yet its first lease would land host-reachable before the debounced
// re-apply installs one. The first apply therefore renders LAST-placed
// `iifname <dev> drop` rules for such units and hands off WITH that
// protection — no hold (a never-leasing unit must not strand the GLOBAL
// barrier), no window. A later lease re-renders to destination DROPs.

// unzonedDHCPConfig10751 builds a config with an unzoned DHCP unit
// (ge-0/0/9.0) and, optionally, a scoped trust zone.
func unzonedDHCPConfig10751(withTrustZone bool) *config.Config {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0/0/9": {Name: "ge-0/0/9", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, DHCP: true, DHCPv6: true},
		}},
	}
	if withTrustZone {
		cfg.Interfaces.Interfaces["ge-0/0/0"] = &config.InterfaceConfig{Name: "ge-0/0/0", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0},
		}}
		cfg.Security.Zones = map[string]*config.ZoneConfig{
			"trust": {Name: "trust", Interfaces: []string{"ge-0/0/0.0"}},
		}
	}
	return cfg
}

// TestUnzonedDHCPHandsOffWithInterfaceDrop10751: zoned-plus-unzoned config,
// unzoned DHCP unit unleased at first apply — the real install carries the
// interface DROP and the handoff COMPLETES with protection (no hold, no
// window). A later lease re-renders to destination DROPs and drops the
// interface rule. RED on revert: without the backstop the spec has no
// unleased rule while the handoff still completes.
func TestUnzonedDHCPHandsOffWithInterfaceDrop10751(t *testing.T) {
	orig := nftInstaller
	t.Cleanup(func() { nftInstaller = orig })
	var specs []xnft.HostInboundSpec
	fake := &fakeNftInstaller{
		hostInbound: func(spec xnft.HostInboundSpec) error {
			specs = append(specs, spec)
			return nil
		},
	}
	nftInstaller = fake
	cfg := unzonedDHCPConfig10751(true)
	uni := int(netlink.SCOPE_UNIVERSE)
	y := scriptedAddr10751("inet", "10.0.0.1/24", uni)
	s1 := []dpuserspace.InterfaceSnapshot{
		scriptedSnap10751("ge-0/0/0.0", "trust", y),
		scriptedSnap10751("ge-0/0/9.0", ""),
	}
	if hostInboundHasPendingEnforcingIntentFromSnapshots(cfg, s1) {
		t.Fatal("unzoned DHCP is intentionally not pending (no hold); protection comes from the interface rule")
	}
	scriptSnapshotTransition10751(t, s1, s1)
	d := &Daemon{}
	if err := d.applyHostInboundFilter(cfg); err != nil {
		t.Fatalf("first apply err = %v, want nil (hand off WITH interface protection)", err)
	}
	if len(specs) != 1 || len(specs[0].UnleasedV4) != 1 || specs[0].UnleasedV4[0] != "ge-0-0-9" || len(specs[0].UnleasedV6) != 1 || specs[0].UnleasedV6[0] != "ge-0-0-9" {
		t.Fatalf("real spec unleased v4/v6 = %+v, want [ge-0-0-9]/[ge-0-0-9]", specs)
	}
	if !d.earlyInputHandoffDone.Load() {
		t.Fatal("first apply must hand off (protected by the interface rule, not held)")
	}
	// Lease lands: the re-rendered spec carries destination DROPs for the
	// lease and drops the interface rule (the unit is no longer unleased).
	lease := scriptedAddr10751("inet", "203.0.113.9/24", uni)
	lease6 := scriptedAddr10751("inet6", "2001:db8:9::9/64", uni)
	s2 := []dpuserspace.InterfaceSnapshot{
		scriptedSnap10751("ge-0/0/0.0", "trust", y),
		scriptedSnap10751("ge-0/0/9.0", "", lease, lease6),
	}
	scriptSnapshotTransition10751(t, s2, s2)
	if err := d.applyHostInboundFilter(cfg); err != nil {
		t.Fatalf("lease apply err = %v, want nil", err)
	}
	if len(specs) != 2 {
		t.Fatalf("real installs = %d, want 2", len(specs))
	}
	if len(specs[1].UnleasedV4) != 0 || len(specs[1].UnleasedV6) != 0 {
		t.Fatalf("leased spec unleased v4/v6 = %v/%v, want empty/empty (replaced by destination DROPs)", specs[1].UnleasedV4, specs[1].UnleasedV6)
	}
	covered := false
	for _, a := range specs[1].UnzonedV4 {
		covered = covered || a == "203.0.113.9"
	}
	if !covered {
		t.Fatalf("leased spec unzoned v4 = %v, want the lease denied by destination", specs[1].UnzonedV4)
	}
	covered6 := false
	for _, a := range specs[1].UnzonedV6 {
		covered6 = covered6 || a == "2001:db8:9::9"
	}
	if !covered6 {
		t.Fatalf("leased spec unzoned v6 = %v, want the lease denied by destination", specs[1].UnzonedV6)
	}
	if !covered {
		t.Fatalf("leased spec unzoned v4 = %v, want the lease denied by destination", specs[1].UnzonedV4)
	}
}

// TestUnzonedDHCPBlocksTeardown10751: zone-less config with ONLY an unzoned
// DHCP unit (nothing enforceable by address) must NOT tear down — it
// installs the interface backstop and hands off protected.
func TestUnzonedDHCPBlocksTeardown10751(t *testing.T) {
	orig := nftInstaller
	t.Cleanup(func() { nftInstaller = orig })
	var specs []xnft.HostInboundSpec
	var deleted []string
	fake := &fakeNftInstaller{
		hostInbound: func(spec xnft.HostInboundSpec) error {
			specs = append(specs, spec)
			return nil
		},
		del: func(name string) error { deleted = append(deleted, name); return nil },
	}
	nftInstaller = fake
	cfg := unzonedDHCPConfig10751(false)
	s := []dpuserspace.InterfaceSnapshot{scriptedSnap10751("ge-0/0/9.0", "")}
	scriptSnapshotTransition10751(t, s, s)
	d := &Daemon{}
	if err := d.applyHostInboundFilter(cfg); err != nil {
		t.Fatalf("apply err = %v, want nil", err)
	}
	for _, name := range deleted {
		if name == xnft.HostInboundTableName {
			t.Fatalf("deleted tables = %v: teardown must not delete the host table (unleased blocks teardown; gap cleanup alone is fine)", deleted)
		}
	}
	if len(specs) != 1 || len(specs[0].UnleasedV4) != 1 || len(specs[0].UnleasedV6) != 1 {
		t.Fatalf("real specs = %+v, want one install carrying the interface backstop in both families", specs)
	}
	if !d.earlyInputHandoffDone.Load() {
		t.Fatal("must hand off with interface protection installed")
	}
}

// TestUnzonedDHCPFallbackKeepsInterfaceDrop10751: real fails on the
// unleased shape — the cold-boot fence carries the interface backstop
// and the handoff completes protected; healing converges to the real
// table. Failure must never drop the backstop before convergence.
func TestUnzonedDHCPFallbackKeepsInterfaceDrop10751(t *testing.T) {
	orig := nftInstaller
	t.Cleanup(func() { nftInstaller = orig })
	installErr := errors.New("real host-inbound load failed")
	var fenceSpecs []xnft.FenceSpec
	var realSpecs []xnft.HostInboundSpec
	calls := 0
	fake := &fakeNftInstaller{
		hostInbound: func(spec xnft.HostInboundSpec) error {
			calls++
			realSpecs = append(realSpecs, spec)
			if calls == 1 {
				return installErr
			}
			return nil
		},
		coldBootFence: func(spec xnft.FenceSpec) error {
			fenceSpecs = append(fenceSpecs, spec)
			return nil
		},
	}
	nftInstaller = fake
	cfg := unzonedDHCPConfig10751(false)
	s := []dpuserspace.InterfaceSnapshot{scriptedSnap10751("ge-0/0/9.0", "")}
	scriptSnapshotTransition10751(t, s, s)
	d := &Daemon{}
	err := d.applyHostInboundFilter(cfg)
	if err == nil || !strings.Contains(err.Error(), installErr.Error()) {
		t.Fatalf("failing apply err = %v, want the real-install error (fence stands)", err)
	}
	if len(fenceSpecs) != 1 || len(fenceSpecs[0].UnleasedV4) != 1 || len(fenceSpecs[0].UnleasedV6) != 1 {
		t.Fatalf("fence specs = %+v, want the interface backstop in the fence in both families", fenceSpecs)
	}
	if !d.earlyInputHandoffDone.Load() {
		t.Fatal("fence with interface backstop must hand off (scoped, protected)")
	}
	if err := d.applyHostInboundFilter(cfg); err != nil {
		t.Fatalf("healed apply err = %v, want nil", err)
	}
	if len(realSpecs) != 2 || len(realSpecs[1].UnleasedV4) != 1 || len(realSpecs[1].UnleasedV6) != 1 {
		t.Fatalf("healed real spec = %+v, want the backstop retained while unleased in both families", realSpecs)
	}
}

// TestUnleasedOraclePlacement10751: the text oracles render the per-family
// backstop LAST (after every destination rule, so addressed families and
// explicit programs win), family-guarded (a v6-only backstop must not
// shadow v4 fallthrough and vice versa), and the per-family DHCP admits
// BEFORE every destination rule (so a first ADVERTISE is not shadowed by
// the link-local DROP on an already-up link). Set form for several
// netdevs; omitted when empty.
func TestUnleasedOraclePlacement10751(t *testing.T) {
	views := []dpuserspace.ZoneHostInboundView{{Zone: "trust", V4Addrs: []string{"10.0.0.1"}}}
	unleasedV4 := []string{"ge-0-0-8", "ge-0-0-9"}
	unleasedV6 := []string{"ge-0-0-9"}
	wantDropV4 := `iifname { "ge-0-0-8", "ge-0-0-9" } meta nfproto ipv4 drop`
	wantDropV6 := `iifname "ge-0-0-9" meta nfproto ipv6 drop`
	wantAdmitV4 := `iifname { "ge-0-0-8", "ge-0-0-9" } meta nfproto ipv4 udp dport 68 accept`
	wantAdmitV6 := `iifname "ge-0-0-9" meta nfproto ipv6 udp dport 546 accept`
	for name, payload := range map[string]string{
		"real":  buildHostInboundFilterPayloadWithOverlay(views, []string{"10.9.9.9"}, nil, nil, nil, true, nil, unleasedV4, unleasedV6, dhcpBackstopVRFLists{}),
		"fence": buildHostInboundFencePayload(views, nil, nil, nil, nil, unleasedV4, unleasedV6, dhcpBackstopVRFLists{}),
		"gap":   buildHostInboundGapFencePayload(views, []string{"10.0.0.2"}, nil, nil, nil, unleasedV4, unleasedV6, nil, nil, nil, dhcpBackstopVRFLists{}, nil, nil),
	} {
		for _, want := range []string{wantDropV4, wantDropV6, wantAdmitV4, wantAdmitV6} {
			if !strings.Contains(payload, want) {
				t.Errorf("%s oracle lacks %q:\n%s", name, want, payload)
			}
		}
		if strings.LastIndex(payload, "daddr") > strings.Index(payload, wantDropV4) {
			t.Errorf("%s oracle places the interface backstop before a destination rule:\n%s", name, payload)
		}
		// Admits precede every destination DROP: the last admit must
		// sit before the first destination drop. (The #10752
		// stale-reply guards also carry daddr but precede the admits
		// by design — DHCP client ports are catalog-exempt — so
		// guard lines, marked by "ct direction reply", are skipped.)
		lastAdmit := strings.LastIndex(payload, wantAdmitV6)
		for _, line := range strings.Split(payload, "\n") {
			if !strings.Contains(line, "daddr") || !strings.Contains(line, "drop") || strings.Contains(line, "ct direction reply") {
				continue
			}
			if strings.Index(payload, line) < lastAdmit {
				t.Errorf("%s oracle places a DHCP admit after destination drop %q:\n%s", name, strings.TrimSpace(line), payload)
			}
			break
		}
	}
	plain := buildHostInboundFilterPayload(views, nil, nil, nil, nil, true)
	if strings.Contains(plain, "ge-0-0-9") {
		t.Errorf("real oracle without unleased must not reference the netdev:\n%s", plain)
	}
}

// --- #10751 R7-C: gap withholds lifeline-shared; joint-actual baseline ---

// sharedLifelineDataConfig10751 builds the ruling's topology: W on lifeline
// fxp0.0 AND data ge-0/0/0.0 in an ssh-admitting zone (non-empty view keeps
// W, so the REAL scope covers it while any fence withholds it).
func sharedLifelineDataConfig10751() *config.Config {
	cfg := newcomerCfg10751("trust", map[string]*config.InterfaceUnit{"ge-0/0/0": {Number: 0}})
	cfg.Security.Zones["trust"].HostInboundTraffic = &config.HostInboundTraffic{SystemServices: []string{"ssh"}}
	cfg.Chassis.Cluster = &config.ClusterConfig{ControlInterface: "em0"}
	cfg.Interfaces.Interfaces["em0"] = &config.InterfaceConfig{
		Name:  "em0",
		Units: map[int]*config.InterfaceUnit{0: {Number: 0}},
	}
	return cfg
}

func sharedLifelineDataSnaps10751() []dpuserspace.InterfaceSnapshot {
	uni := int(netlink.SCOPE_UNIVERSE)
	return []dpuserspace.InterfaceSnapshot{
		scriptedSnap10751("fxp0.0", "", scriptedAddr10751("inet", "10.0.0.5/24", uni)),
		scriptedSnap10751("ge-0/0/0.0", "trust",
			scriptedAddr10751("inet", "10.0.0.1/24", uni),
			scriptedAddr10751("inet", "10.0.0.5/24", uni)),
	}
}

// TestFallbackDoubleFailureRefusesWithGapException10751: apply1 real-fails
// → fence withholds W and REFUSES handoff; apply2 real-fails again →
// Enforced, so the gap branch runs — the gap installs WITH W (bare DROP
// on data ingress plus the lifeline-ingress exception ACCEPT, M1), but
// the joint-actual baseline still excludes conditionally-denied shared →
// REFUSE again (pre-handoff refusal retained: the barrier backstop stays
// until a real install). The barrier stays retained throughout
// (lifeline-admitting: fxp0 in every guard spec, so new management on W
// provably works) while data stays DROP-closed. Apply3 heals. RED on
// revert: gap-DROPs W without the exception (lockout) or hands off over
// it (fail-open).
func TestFallbackDoubleFailureRefusesWithGapException10751(t *testing.T) {
	orig := nftInstaller
	t.Cleanup(func() { nftInstaller = orig })
	installErr := errors.New("real host-inbound load failed")
	calls := 0
	var gapSpecs []xnft.GapFenceSpec
	fake := &fakeNftInstaller{
		hostInbound: func(xnft.HostInboundSpec) error {
			calls++
			if calls <= 2 {
				return installErr
			}
			return nil
		},
		coldBootFence: func(xnft.FenceSpec) error { return nil },
		gapFence: func(spec xnft.GapFenceSpec) error {
			gapSpecs = append(gapSpecs, spec)
			return nil
		},
	}
	nftInstaller = fake
	cfg := sharedLifelineDataConfig10751()
	s := sharedLifelineDataSnaps10751()
	if hostInboundHasPendingEnforcingIntentFromSnapshots(cfg, s) {
		t.Fatal("stable scoped fixture must be pending-free; else the cells cannot isolate fallback coverage")
	}
	scriptSnapshotTransition10751(t, s, s)
	d := &Daemon{}
	for i, want := range []string{"not covered by installed fallback", "not covered by installed fallback"} {
		err := d.applyHostInboundFilter(cfg)
		if err == nil || !strings.Contains(err.Error(), want) || !strings.Contains(err.Error(), "10.0.0.5") {
			t.Fatalf("apply%d err = %v, want fence/gap coverage refusal naming W", i+1, err)
		}
	}
	if len(gapSpecs) != 1 {
		t.Fatalf("gap installs = %d, want 1: apply2 installs the gap WITH the lifeline exception for W", len(gapSpecs))
	}
	assertGapExceptShared10751(t, gapSpecs[0], []string{"10.0.0.5"}, []string{"10.0.0.5"})
	for _, ev := range fake.earlyInputBarrierCalls {
		if ev == "remove" {
			t.Fatalf("barrier calls = %v: double failure must retain, never remove", fake.earlyInputBarrierCalls)
		}
	}
	if d.earlyInputHandoffDone.Load() {
		t.Fatal("handoff marked done over a destination no fallback denies")
	}
	if len(fake.earlyInputBarrierLifelineSpecs) == 0 {
		t.Fatal("no guard installs observed; lifeline admission unprovable")
	}
	last := fake.earlyInputBarrierLifelineSpecs[len(fake.earlyInputBarrierLifelineSpecs)-1]
	found := false
	for _, n := range last {
		found = found || n == "fxp0"
	}
	if !found {
		t.Fatalf("latest guard lifelines = %v, want fxp0 admitted (new management on W must work)", last)
	}
	if err := d.applyHostInboundFilter(cfg); err != nil {
		t.Fatalf("healed apply err = %v, want nil", err)
	}
	if !d.earlyInputHandoffDone.Load() {
		t.Fatal("healed real install must complete the handoff")
	}
}

// assertGapExceptShared10751 pins the M1 gap shape: Uncovered carries both
// the shared values (bare DROP on data ingress) and the plain newcomers,
// Shared carries exactly the lifeline-shared subset (exception ACCEPT on
// lifeline ingress), and the lifeline set covers the defaults.
func assertGapExceptShared10751(t *testing.T, spec xnft.GapFenceSpec, wantUncovered, wantShared []string) {
	t.Helper()
	has := func(list []string, want string) bool {
		for _, a := range list {
			if a == want {
				return true
			}
		}
		return false
	}
	for _, want := range wantUncovered {
		if !has(spec.UncoveredV4, want) {
			t.Fatalf("gap spec uncovered v4 = %v, want %q (bare DROP on data ingress)", spec.UncoveredV4, want)
		}
	}
	if len(spec.SharedV4) != len(wantShared) {
		t.Fatalf("gap spec shared v4 = %v, want exactly %v", spec.SharedV4, wantShared)
	}
	for _, want := range wantShared {
		if !has(spec.SharedV4, want) {
			t.Fatalf("gap spec shared v4 = %v, want %q (lifeline-ingress exception)", spec.SharedV4, want)
		}
	}
	for _, want := range []string{"fxp0", "em0"} {
		if !has(spec.LifelineNetdevs, want) {
			t.Fatalf("gap spec lifelines = %v, want default %q in the exception scope", spec.LifelineNetdevs, want)
		}
	}
}

// TestGapInstallExceptLifelineShared10751: gap branch with uncovered
// {W-shared, X-new} installs a gap covering BOTH in the bare DROP with W
// in the lifeline-ingress exception. The handoff still refuses on W (the
// baseline excludes conditionally-denied shared) — converging on the next
// successful real install, never by fencing management.
func TestGapInstallExceptLifelineShared10751(t *testing.T) {
	orig := nftInstaller
	t.Cleanup(func() { nftInstaller = orig })
	installErr := errors.New("real host-inbound load failed")
	var gapSpecs []xnft.GapFenceSpec
	fake := &fakeNftInstaller{
		hostInbound: func(xnft.HostInboundSpec) error { return installErr },
		gapFence: func(spec xnft.GapFenceSpec) error {
			gapSpecs = append(gapSpecs, spec)
			return nil
		},
	}
	nftInstaller = fake
	cfg := sharedLifelineDataConfig10751()
	uni := int(netlink.SCOPE_UNIVERSE)
	s := []dpuserspace.InterfaceSnapshot{
		scriptedSnap10751("fxp0.0", "", scriptedAddr10751("inet", "10.0.0.5/24", uni)),
		scriptedSnap10751("ge-0/0/0.0", "trust",
			scriptedAddr10751("inet", "10.0.0.1/24", uni),
			scriptedAddr10751("inet", "10.0.0.5/24", uni),
			scriptedAddr10751("inet", "10.0.0.9/24", uni)),
	}
	scriptSnapshotTransition10751(t, s, s)
	d := &Daemon{}
	d.hostInboundEnforced.Store(true) // retained real generation covering Y only
	d.hostInboundCoveredAddrs = map[string]struct{}{hostInboundDropAddrKey('4', "10.0.0.1"): {}}
	err := d.applyHostInboundFilter(cfg)
	if err == nil || !strings.Contains(err.Error(), "not covered by installed fallback") {
		t.Fatalf("apply err = %v, want joint-coverage refusal (shared excluded from the baseline)", err)
	}
	if len(gapSpecs) != 1 {
		t.Fatalf("gap installs = %d, want 1 (X plus shared W with the exception)", len(gapSpecs))
	}
	assertGapExceptShared10751(t, gapSpecs[0], []string{"10.0.0.5", "10.0.0.9"}, []string{"10.0.0.5"})
}

// TestGapExceptLifelineSharedDayTwo10751 is the Opus8 R4-2 day-2 shape:
// HandoffDone=true, retained covers Y only, W lifeline+data shared and X
// newly appear, real fails. The gap installs WITH W (bare DROP on data
// ingress plus the lifeline-ingress exception) and X; the apply reports
// the real-install error WITHOUT the pre-handoff coverage refusal
// (post-handoff skips those checks — no barrier is left to retain);
// healing converges on the next success and tears the gap down. RED on
// revert: W missing from the gap (data fail-open) or refused post-handoff
// (never heals without a barrier to retain).
func TestGapExceptLifelineSharedDayTwo10751(t *testing.T) {
	orig := nftInstaller
	t.Cleanup(func() { nftInstaller = orig })
	installErr := errors.New("real host-inbound load failed")
	calls := 0
	var gapSpecs []xnft.GapFenceSpec
	var deleted []string
	fake := &fakeNftInstaller{
		hostInbound: func(xnft.HostInboundSpec) error {
			calls++
			if calls == 1 {
				return installErr
			}
			return nil
		},
		gapFence: func(spec xnft.GapFenceSpec) error {
			gapSpecs = append(gapSpecs, spec)
			return nil
		},
		del: func(name string) error { deleted = append(deleted, name); return nil },
	}
	nftInstaller = fake
	cfg := sharedLifelineDataConfig10751()
	uni := int(netlink.SCOPE_UNIVERSE)
	s := []dpuserspace.InterfaceSnapshot{
		scriptedSnap10751("fxp0.0", "", scriptedAddr10751("inet", "10.0.0.5/24", uni)),
		scriptedSnap10751("ge-0/0/0.0", "trust",
			scriptedAddr10751("inet", "10.0.0.1/24", uni),
			scriptedAddr10751("inet", "10.0.0.5/24", uni),
			scriptedAddr10751("inet", "10.0.0.9/24", uni)),
	}
	scriptSnapshotTransition10751(t, s, s)
	d := &Daemon{}
	d.hostInboundEnforced.Store(true) // retained real generation covering Y only
	d.hostInboundCoveredAddrs = map[string]struct{}{hostInboundDropAddrKey('4', "10.0.0.1"): {}}
	d.earlyInputHandoffDone.Store(true) // POST-handoff: no barrier stands behind the gap
	err := d.applyHostInboundFilter(cfg)
	if err == nil || !strings.Contains(err.Error(), installErr.Error()) {
		t.Fatalf("apply err = %v, want the real-install error", err)
	}
	if strings.Contains(err.Error(), "not covered by installed fallback") {
		t.Fatalf("apply err = %v, want NO coverage refusal post-handoff (nothing left to retain)", err)
	}
	if len(gapSpecs) != 1 {
		t.Fatalf("gap installs = %d, want 1 (X plus shared W with the exception)", len(gapSpecs))
	}
	assertGapExceptShared10751(t, gapSpecs[0], []string{"10.0.0.5", "10.0.0.9"}, []string{"10.0.0.5"})
	if !d.hostInboundGapFenceActive.Load() {
		t.Fatal("gap fence must stand beside the retained table until healing")
	}
	if !d.earlyInputHandoffDone.Load() {
		t.Fatal("handoff must stay done")
	}
	if err := d.applyHostInboundFilter(cfg); err != nil {
		t.Fatalf("healed apply err = %v, want nil", err)
	}
	for _, name := range deleted {
		if name == xnft.HostInboundGapTableName {
			return
		}
	}
	t.Fatalf("deleted tables = %v, want the obsolete gap torn down on heal", deleted)
}

// TestGapLifelineExceptionPlacement10751: the gap oracle renders TWO
// lifeline-ingress exception ACCEPTs before the bare DROP — iifname for
// unenslaved lifelines plus meta sdifname for VRF-enslaved members (no
// vrf-mgmt blanket: non-lifeline members stay denied) — both scoped to
// the lifeline set; empty shared/lifelines omit them (fail-closed:
// shared stays bare-DROPped on every ingress).
func TestGapLifelineExceptionPlacement10751(t *testing.T) {
	payload := buildHostInboundGapFencePayload(
		nil, []string{"10.0.0.5", "10.0.0.9"}, nil, nil, nil,
		nil, nil, []string{"10.0.0.5"}, nil, []string{"em0", "fxp0"},
		dhcpBackstopVRFLists{}, nil, nil,
	)
	wantExcept := `iifname { "em0", "fxp0" } ip daddr 10.0.0.5 accept`
	wantExceptSdif := `meta sdifname { "em0", "fxp0" } ip daddr 10.0.0.5 accept`
	wantDrop := `ip daddr { 10.0.0.5, 10.0.0.9 } drop`
	if !strings.Contains(payload, wantExcept) {
		t.Errorf("gap oracle lacks the lifeline exception %q:\n%s", wantExcept, payload)
	}
	if !strings.Contains(payload, wantExceptSdif) {
		t.Errorf("gap oracle lacks the slave exception %q:\n%s", wantExceptSdif, payload)
	}
	if strings.Contains(payload, "vrf-mgmt") {
		t.Errorf("gap oracle must not blanket-admit vrf-mgmt (non-lifeline members must stay deniable):\n%s", payload)
	}
	if !strings.Contains(payload, wantDrop) {
		t.Fatalf("gap oracle lacks the bare DROP %q:\n%s", wantDrop, payload)
	}
	if strings.Index(payload, wantExcept) > strings.Index(payload, wantDrop) ||
		strings.Index(payload, wantExceptSdif) > strings.Index(payload, wantDrop) {
		t.Errorf("gap oracle places an exception after the bare DROP (lifeline management would be denied):\n%s", payload)
	}
	plain := buildHostInboundGapFencePayload(nil, []string{"10.0.0.9"}, nil, nil, nil, nil, nil, nil, nil, nil, dhcpBackstopVRFLists{}, nil, nil)
	if strings.Contains(plain, "iifname") || strings.Contains(plain, "sdifname") {
		t.Errorf("gap oracle without shared must emit no iifname/sdifname rule:\n%s", plain)
	}
}
