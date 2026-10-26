package daemon

import (
	"context"
	"errors"
	"testing"

	"github.com/vishvananda/netlink"

	"github.com/psaab/xpf/pkg/config"
)

// TestReconcileSNMPTransientLookupErrorDoesNotBounce17686 pins #17686 (Opus
// lane): a transient fabricLinkByName error is not proof the VRF device was
// re-created. The healthy listener must not be bounced; a genuine
// netlink.LinkNotFoundError still counts as absence and must restart.
//
// Mutation check: treat any lookup error as an index change (pre-fix
// behaviour) and the transient arm fails — serve count goes 1 -> 2.
func TestReconcileSNMPTransientLookupErrorDoesNotBounce17686(t *testing.T) {
	f := newSNMPVRFRecreateFixture16626(t)
	cfg := f.d.store.ActiveConfig()
	first := f.d.snmpAgent

	orig := f.d.linkByNameFn
	// Transient error: device is alive at index 77, lookup fails for another
	// reason (e.g. dump interruption).
	f.d.linkByNameFn = func(name string) (netlink.Link, error) {
		if name == config.ManagementVRFDeviceName {
			return nil, errors.New("transient netlink dump interruption")
		}
		return orig(name)
	}
	if f.d.reconcileSNMP(cfg) {
		t.Fatal("transient lookup error reported a change (listener bounced)")
	}
	if got := f.rec.count(); got != 1 || f.d.snmpAgent != first {
		t.Fatalf("transient lookup error bounced SNMP: starts=%d sameAgent=%v, want 1/true",
			got, f.d.snmpAgent == first)
	}
	if f.d.snmpVRFIndex != 77 {
		t.Fatalf("recorded index after transient error = %d, want 77 (unchanged)", f.d.snmpVRFIndex)
	}

	// Control: confirmed absence (LinkNotFoundError) is a re-create and must
	// restart (or attempt restart). The device is absent, so the restart's
	// start path re-looks-up and records 0; serve count must advance.
	f.d.linkByNameFn = func(name string) (netlink.Link, error) {
		if name == config.ManagementVRFDeviceName {
			return nil, netlink.LinkNotFoundError{}
		}
		return orig(name)
	}
	if !f.d.reconcileSNMP(cfg) {
		t.Fatal("confirmed-absent reconcile did not restart the SNMP listener")
	}
	if got := f.rec.count(); got != 2 {
		t.Fatalf("SNMP starts after confirmed absence = %d, want 2", got)
	}
}

// TestReconcileSNMPUnknownIndexRebindsOnFirstSuccessfulLookup17686 covers
// #17686's start-time lookup failure. With no recorded ifindex, a later live
// index cannot prove which device the existing socket bound to: vrf-mgmt may
// have been re-created before this first successful check. Rebinding once
// establishes a trustworthy index; subsequent re-creates remain detectable.
//
// Mutation check: adopt the live index without restarting, and the
// recreate-before-first-success arm leaves the listener pinned to index 77
// while recording index 99.
func TestReconcileSNMPUnknownIndexRebindsOnFirstSuccessfulLookup17686(t *testing.T) {
	for _, tc := range []struct {
		name      string
		liveIndex int
	}{
		{name: "unchanged device", liveIndex: 77},
		{name: "recreated before first successful lookup", liveIndex: 99},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newSNMPVRFRecreateFixture16626(t)
			cfg := f.d.store.ActiveConfig()
			first := f.d.snmpAgent

			// Simulate an unavailable post-bind lookup, followed optionally
			// by a same-name VRF re-create before the next successful lookup.
			f.d.snmpReconMu.Lock()
			f.d.snmpVRFIndex = 0
			f.d.snmpReconMu.Unlock()
			f.recreateAt(tc.liveIndex)

			if !f.d.reconcileSNMP(cfg) {
				t.Fatal("first successful lookup with unknown bound index did not rebind SNMP")
			}
			if got := f.rec.count(); got != 2 {
				t.Fatalf("SNMP starts after unknown-index lookup = %d, want 2", got)
			}
			if f.d.snmpAgent == first || f.d.snmpAgent == nil {
				t.Fatal("unknown-index listener kept the agent bound before the successful lookup")
			}
			if f.d.snmpVRFIndex != tc.liveIndex {
				t.Fatalf("recorded SNMP VRF ifindex = %d, want %d", f.d.snmpVRFIndex, tc.liveIndex)
			}

			// The new listener has an authoritative index now, so a later
			// same-name re-create must still be detected.
			nextIndex := tc.liveIndex + 1
			f.recreateAt(nextIndex)
			if !f.d.reconcileSNMP(cfg) {
				t.Fatal("re-create after unknown-index rebind did not restart SNMP")
			}
			if got := f.rec.count(); got != 3 {
				t.Fatalf("SNMP starts after later re-create = %d, want 3", got)
			}
			if f.d.snmpVRFIndex != nextIndex {
				t.Fatalf("recorded SNMP VRF ifindex after later re-create = %d, want %d",
					f.d.snmpVRFIndex, nextIndex)
			}
		})
	}
}

// TestReassertHealsSNMPWhenAnotherPathRecreatedVRF17686 pins #17686 (Astra
// lane, fabric-overlay race): if vrf-mgmt was already re-created by another
// owner before the management tick (tick did not itself create it), the
// tick must still heal a vrf-mgmt-pinned SNMP listener instead of returning
// early on `recreated == false`.
//
// Mutation check: gate the SNMP heal on this tick's `recreated` flag
// (pre-fix behaviour) and this test fails — serve count stays 1.
func TestReassertHealsSNMPWhenAnotherPathRecreatedVRF17686(t *testing.T) {
	f := newSNMPVRFRecreateFixture16626(t)
	first := f.d.snmpAgent

	// Another owner already re-created vrf-mgmt at index 99 before the tick:
	// the device is present in the fake kernel, the member is enslaved to
	// the new index, so the tick sees no missing device and no drift.
	f.ops.links[config.ManagementVRFDeviceName] = &netlink.Vrf{LinkAttrs: netlink.LinkAttrs{
		Name: config.ManagementVRFDeviceName, Index: 99,
	}}
	f.recreateAt(99)
	f.ops.links["fxp0"].Attrs().MasterIndex = 99

	prevRoute := mgmtVRFRouteReconcileFn
	mgmtVRFRouteReconcileFn = func(*Daemon) error { return nil }
	t.Cleanup(func() { mgmtVRFRouteReconcileFn = prevRoute })

	f.d.reassertMgmtVRFOnce(context.Background())

	if got := f.rec.count(); got != 2 {
		t.Fatalf("SNMP listener starts after another-path VRF re-create = %d, want 2 (healed in tick)", got)
	}
	if f.d.snmpAgent == first || f.d.snmpAgent == nil {
		t.Fatal("another-path VRF re-create kept the old SNMP agent bound to the dead ifindex")
	}
	if f.d.snmpVRFIndex != 99 {
		t.Fatalf("recorded SNMP VRF ifindex after heal = %d, want 99", f.d.snmpVRFIndex)
	}

	// Control: a second healthy tick must not bounce again.
	f.d.reassertMgmtVRFOnce(context.Background())
	if got := f.rec.count(); got != 2 {
		t.Fatalf("healthy second tick restarted SNMP: starts = %d, want 2", got)
	}
}

// TestReassertHealthyTickDoesNotBounceSNMP17686 is the negative control for
// the unconditional-ish heal probe: with the device healthy at the recorded
// index and no drift, the tick must leave the listener alone (and, pre-fix,
// it returns before any SNMP check, so this also passes pre-fix by design).
func TestReassertHealthyTickDoesNotBounceSNMP17686(t *testing.T) {
	f := newSNMPVRFRecreateFixture16626(t)
	// Device healthy at 77, member enslaved to 77 (fixture default).
	prevRoute := mgmtVRFRouteReconcileFn
	mgmtVRFRouteReconcileFn = func(*Daemon) error { return nil }
	t.Cleanup(func() { mgmtVRFRouteReconcileFn = prevRoute })

	f.d.reassertMgmtVRFOnce(context.Background())

	if got := f.rec.count(); got != 1 {
		t.Fatalf("healthy tick bounced SNMP: starts = %d, want 1", got)
	}
}
