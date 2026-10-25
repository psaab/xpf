package vrrp

import (
	"testing"
	"time"
)

// #16768: the fixed 3s deafness shield replaced Master_Down_Interval for
// non-preempting instances. With advertise-interval I > ~1s the RFC 5798
// §6.1 horizon (3*I + Skew) exceeds 3s, so a restarting no-preempt node
// promoted into a live master before its next advert (probability
// ~(I-3)/I at I>3s), and a lower-priority restart ran dual-MASTER until
// the master's next advert. The shield must only LENGTHEN the RFC
// horizon: arm max(deafMasterDownInterval, masterDownInterval()) at both
// initialMasterDownInterval and masterDownAfterSyncHoldRelease.
//
// RED-on-revert: restoring `return deafMasterDownInterval` in either
// helper makes the 5s/40s cells below fail (armed 3s < RFC horizon).

func newDeafShieldInstance(priority, advertiseMS int) *vrrpInstance {
	return &vrrpInstance{cfg: Instance{
		Interface: "ge-0-0-2", GroupID: 7, Priority: priority, Preempt: false,
		AdvertiseInterval: advertiseMS,
	}}
}

// TestDeafShieldNeverShortensMasterDown16768 is the defect cell for the
// startup arm: at long intervals the initial arm must equal the RFC
// master-down interval, not the bare 3s shield.
func TestDeafShieldNeverShortensMasterDown16768(t *testing.T) {
	for _, tc := range []struct {
		name        string
		advertiseMS int
	}{
		{"5s-interval", 5000},
		{"40s-interval-max", 40000},
		{"2s-interval", 2000},
	} {
		t.Run(tc.name, func(t *testing.T) {
			vi := newDeafShieldInstance(200, tc.advertiseMS)
			rfc := vi.masterDownInterval()
			if rfc <= deafMasterDownInterval {
				t.Fatalf("precondition: RFC horizon %v must exceed deaf shield %v at %dms, cell asserts nothing", rfc, deafMasterDownInterval, tc.advertiseMS)
			}
			if got := vi.initialMasterDownInterval(); got != rfc {
				t.Fatalf("initialMasterDownInterval() = %v, want RFC horizon %v (max(3s, masterDownInterval)); bare 3s shield promotes into a live master before its next advert", got, rfc)
			}
			d, rearm := vi.masterDownAfterSyncHoldRelease()
			if !rearm {
				t.Fatal("masterDownAfterSyncHoldRelease: rearm=false for no-preempt node, want true")
			}
			if d != rfc {
				t.Fatalf("masterDownAfterSyncHoldRelease() = %v, want RFC horizon %v (must be >= masterDownInterval)", d, rfc)
			}
			if d < vi.masterDownInterval() {
				t.Fatalf("release interval %v < masterDownInterval %v", d, vi.masterDownInterval())
			}
		})
	}
}

// TestDeafShieldShortIntervalUnchanged16768 is the control: at the 30ms
// RETH interval the RFC horizon is far below the shield, so the armed
// value stays exactly deafMasterDownInterval — the #7579 behaviour is
// unchanged where it was correct. At 1s the priority-200 RFC horizon
// (~3.219s) already exceeds 3s, so only the max() floor relationship
// is asserted there.
func TestDeafShieldShortIntervalUnchanged16768(t *testing.T) {
	for _, tc := range []struct {
		name        string
		advertiseMS int
	}{
		{"30ms-reth", 30},
		{"1s-interval", 1000},
	} {
		t.Run(tc.name, func(t *testing.T) {
			vi := newDeafShieldInstance(200, tc.advertiseMS)
			// At 1s, priority 200: RFC = 3s + (56/256)*1s = ~3.219s > 3s,
			// so only assert the floor relationship, not equality, there.
			// At 30ms the RFC horizon (~97ms) is far below the shield.
			if tc.advertiseMS == 30 {
				if got := vi.initialMasterDownInterval(); got != deafMasterDownInterval {
					t.Fatalf("initialMasterDownInterval() = %v, want deaf shield %v at 30ms (unchanged #7579 behaviour)", got, deafMasterDownInterval)
				}
				d, rearm := vi.masterDownAfterSyncHoldRelease()
				if !rearm || d != deafMasterDownInterval {
					t.Fatalf("masterDownAfterSyncHoldRelease() = (%v,%v), want (%v,true)", d, rearm, deafMasterDownInterval)
				}
			} else {
				if got := vi.initialMasterDownInterval(); got < vi.masterDownInterval() || got < deafMasterDownInterval {
					t.Fatalf("initialMasterDownInterval() = %v, want >= max(%v, %v)", got, deafMasterDownInterval, vi.masterDownInterval())
				}
				d, _ := vi.masterDownAfterSyncHoldRelease()
				if d < vi.masterDownInterval() || d < deafMasterDownInterval {
					t.Fatalf("release interval %v, want >= max(%v, %v)", d, deafMasterDownInterval, vi.masterDownInterval())
				}
			}
		})
	}
}

// TestDeafShieldStaysBackupUntilMasterAdvert16768 exercises the
// acceptance scenario at the helper/timer level: a no-preempt node at a
// 5s interval whose master's next advert arrives at 4.5s must not have
// its master-down timer fire before that advert. With the bare 3s shield
// it fired at 3s and promoted (the probe's subject cell); with
// max(3s, RFC ~16.09s at priority 200) it stays BACKUP.
func TestDeafShieldStaysBackupUntilMasterAdvert16768(t *testing.T) {
	vi := newDeafShieldInstance(200, 5000)
	armed := vi.initialMasterDownInterval()
	rfc := vi.masterDownInterval()
	if armed != rfc {
		t.Fatalf("armed %v, want RFC horizon %v", armed, rfc)
	}
	if armed <= 4500*time.Millisecond {
		t.Fatalf("armed %v must exceed the 4.5s next-advert gap; the bare 3s shield fired at 3s and promoted into the live master", armed)
	}
	// Timer-level: a timer armed with `armed` must not fire within the
	// window in which the old 3s shield would have fired. We do not wait
	// 16s; we assert the armed duration itself plus that a 3s timer
	// (the pre-fix value) is strictly shorter — the duration equality
	// above is the guard, this documents the mechanism.
	if deafMasterDownInterval >= armed {
		t.Fatalf("deaf shield %v must be < armed %v at 5s interval", deafMasterDownInterval, armed)
	}
}

// TestDeafShieldPreemptUnchanged16768 pins that preempting nodes (and the
// priority-255 owner) are untouched: startup uses the plain RFC interval
// and sync-hold release does not re-arm.
func TestDeafShieldPreemptUnchanged16768(t *testing.T) {
	preempt := &vrrpInstance{cfg: Instance{
		Interface: "ge-0-0-2", GroupID: 7, Priority: 200, Preempt: true,
		AdvertiseInterval: 5000,
	}}
	if got, want := preempt.initialMasterDownInterval(), preempt.masterDownInterval(); got != want {
		t.Fatalf("preempt initialMasterDownInterval() = %v, want %v (no shield for preempting node)", got, want)
	}
	if _, rearm := preempt.masterDownAfterSyncHoldRelease(); rearm {
		t.Fatal("preempting node must not re-arm at sync-hold release")
	}
	owner := &vrrpInstance{cfg: Instance{
		Interface: "ge-0-0-2", GroupID: 7, Priority: 255, Preempt: false,
		AdvertiseInterval: 5000,
	}}
	if _, rearm := owner.masterDownAfterSyncHoldRelease(); rearm {
		t.Fatal("priority-255 owner (effective preempt) must not re-arm at sync-hold release")
	}
}
