package userspace

import (
	"testing"
)

// #7002: what every required-protocol gate does when NO helper version has ever
// been observed — i.e. when the helper is DOWN.
//
// THE DISPOSITION, and why it is not an open design question. The issue asks
// whether arming while the helper is down is the behaviour we want. The project
// had already answered it twice, in the same direction, before the issue was
// filed — and both answers carry their reasoning:
//
//   - ensureSecureTunnelProtocolLocked (#6691 round 10): "arming would disarm a
//     dataplane and abort the operator's commit on the strength of a reading
//     that never happened." It defers on !helperStatusObserved.
//   - ensureEgressZoneProtocolLocked (#6722): "a gate that fired on 'version
//     unknown' would abort every commit made while the helper is down or still
//     starting — a brick, not a fence." It deferred on `observed <= 0`.
//
// So the answer is "defer", and this file makes the remaining gates agree with
// the two that already did rather than re-litigating the question per lane.
//
// THE ISSUE'S ENUMERATION IS A FLOOR. It names FOUR gates; there are SIX —
// ensureEgressZoneProtocolLocked joined the set in #6722 and
// ensureFabricBondProtocolLocked joined it in #9925. Both are in
// requiredProtocolGateSentinels alongside the other four. Its measured table
// is also stale: it lists secure-tunnel as arming, which stopped being true
// when #6691 round 10 landed the deferral and cited this issue by number while
// deliberately scoping the fix to itself.
//
// WHY helperStatusObserved AND NOT `version <= 0`. Three states share one
// value: "never observed" and "a helper answered reporting 0" both leave
// ConfigSnapshotProtocolVersion at 0, and only the first is not evidence of a
// mismatch. A helper that ANSWERS with 0 is one old enough not to emit the
// field, which is exactly what these gates exist to refuse. Only the pair
// (lastStatus, helperStatusObserved) separates them, which is why
// manager_status.go maintains them in a single function — and it is the reason
// this file's `observed-zero` column is asserted separately from
// `never-observed` rather than folded into it.
//
// MEASURED GATE CENSUS, all six gates x four states:
//
//	gate                   never-observed  observed-v1  observed-0  observed-current
//	policy-scheduler       ARM             ARM          ARM         DEFER
//	persistent-source-nat  ARM             ARM          ARM         DEFER
//	scoped-global-zoneset  ARM             ARM          ARM         DEFER
//	secure-tunnel          DEFER           ARM          ARM         DEFER
//	fabric-bond            DEFER           ARM          ARM         DEFER
//	egress-zone            DEFER           ARM          DEFER  <--  DEFER
//
// The `persistent-source-nat` row is the one the issue explicitly could not
// measure ("no fixture built for it — its inclusion rests on the identical
// body, which is a READ"). It is measured here, and the read was right.
//
// The marked cell is the divergence the census turned up on its own: the two
// gates that already deferred disagreed about a helper reporting 0, because
// they used different discriminators. Latent rather than live — no shipping
// helper reports 0, since lifecycle.rs sets the field unconditionally to a
// non-zero constant — but a weaker discriminator with no stated reason is one a
// later helper change makes live.

// gateCase is one required-protocol gate, driven directly with a config or
// snapshot whose SHAPE arms it. A gate whose shape predicate returns false
// returns nil for every version, so a fixture that does not arm the gate would
// make every cell below pass vacuously; `TestRequiredProtocolGateFixturesArm7002`
// asserts each fixture actually reaches the version comparison.
type gateCase struct {
	name string
	run  func(m *Manager) error
}

func requiredProtocolGateCases(t *testing.T) []gateCase {
	t.Helper()
	t.Cleanup(stubLinkSnapshot5619(t, map[string]int{"st0": 42, "ge-0-0-0": 11}))
	stCfg, _, _ := spellingConfig(t, "st0.0", "st0", 0)
	stSnap := gateSnapshot(t, stCfg)
	if !snapshotRequiresRefusalProtocol(stSnap) {
		t.Fatal("fixture invalid: the secure-tunnel snapshot carries no flagged row, " +
			"so that gate's cells would pass without ever reaching its version check")
	}
	bondSnap := &ConfigSnapshot{
		Interfaces: []InterfaceSnapshot{{FabricBond: true}},
	}
	if !snapshotRequiresFabricBondProtocol(bondSnap) {
		t.Fatal("fixture invalid: the fabric-bond snapshot carries no flagged row, " +
			"so that gate's cells would pass without ever reaching its version check")
	}
	return []gateCase{
		{"policy-scheduler", func(m *Manager) error {
			return m.ensurePolicySchedulerProtocolLocked(schedulerFloorCfg())
		}},
		{"persistent-source-nat", func(m *Manager) error {
			return m.ensurePersistentSourceNATProtocolLocked(persistentNATFloorCfg())
		}},
		{"scoped-global-zoneset", func(m *Manager) error {
			return m.ensureScopedGlobalZoneSetProtocolLocked(multiZoneScopeFloorCfg())
		}},
		{"secure-tunnel", func(m *Manager) error {
			return m.ensureSecureTunnelProtocolLocked(stSnap)
		}},
		{"fabric-bond", func(m *Manager) error {
			return m.ensureFabricBondProtocolLocked(bondSnap)
		}},
		{"egress-zone", func(m *Manager) error {
			return m.ensureEgressZoneProtocolLocked()
		}},
	}
}

// TestRequiredProtocolGateDefersOnNeverObserved7002 is the #7002 disposition,
// executable.
//
// RED on revert: drop the `!m.helperStatusObserved` deferral from any one of
// the six gates and that gate's row fails on the never-observed cell alone —
// the other cells are unchanged by the mutation, so the row localises which
// gate regressed.
func TestRequiredProtocolGateDefersOnNeverObserved7002(t *testing.T) {
	for _, g := range requiredProtocolGateCases(t) {
		t.Run(g.name, func(t *testing.T) {
			// NEVER OBSERVED: a fresh Manager, no helper has ever answered.
			m := New()
			if m.helperStatusObserved {
				t.Fatal("fixture invalid: a fresh Manager already claims to have " +
					"observed a helper status")
			}
			if err := g.run(m); err != nil {
				t.Errorf("gate ARMED with no helper version ever observed: %v.\n"+
					"There is no helper present to misenforce anything, so this aborts "+
					"the operator's commit and DISARMS a dataplane that is not running "+
					"— a brick, not a fence (#7002/#1960). The fail-closed property is "+
					"kept one step later: the helper gets a fresh apply when it returns "+
					"and its own exact-equality gate refuses the snapshot if it must",
					err)
			}

			// OBSERVED, AND TOO OLD: the state the gate exists for.
			m = New()
			m.setLastStatusLocked(ProcessStatus{ConfigSnapshotProtocolVersion: 1})
			if err := g.run(m); err == nil {
				t.Error("gate DEFERRED for a helper that answered with version 1. " +
					"That is a real incompatibility, and deferring lets the commit " +
					"report success against a helper that stays ARMED on its " +
					"previous-good image with the new config never installed (#2138)")
			}

			// OBSERVED, REPORTING 0: the third state, and the one the census
			// turned up a divergence on. A helper old enough not to emit the
			// field ANSWERED — evidence of a mismatch, not silence — and a gate
			// keying on the value alone cannot tell it from the first cell.
			//
			// Five gates arm here. `egress-zone` DEFERS, and that is recorded
			// rather than corrected: no shipping helper reports 0 (lifecycle.rs
			// sets the field unconditionally to a non-zero constant), so the case
			// is unreachable, while that gate alone has no shape predicate and
			// runs on every commit and route-overlay publish — tightening it
			// fences callers whose status probe answers with a partial
			// ProcessStatus. Changing a deliberate #6722 design for an
			// unreachable benefit would be a revert wearing the shape of a fix.
			// This cell is what a later change making zero-reporting helpers
			// reachable will trip over.
			m = New()
			m.setLastStatusLocked(ProcessStatus{ConfigSnapshotProtocolVersion: 0})
			if !m.helperStatusObserved {
				t.Fatal("fixture invalid: setLastStatusLocked must record the observation")
			}
			err := g.run(m)
			if g.name == "egress-zone" {
				if err != nil {
					t.Errorf("egress-zone armed for an answering-zero helper (%v). That is "+
						"the STRONGER behaviour, and this census records the gate as "+
						"deferring — if the divergence was deliberately closed, update "+
						"this cell and the comment above it (#7002)", err)
				}
			} else if err == nil {
				t.Error("gate DEFERRED for a helper that ANSWERED reporting version 0. " +
					"`version <= 0` cannot distinguish that from never having heard " +
					"from a helper; only helperStatusObserved can, which is why " +
					"manager_status.go maintains the two as a pair (#7002)")
			}

			// OBSERVED AND CURRENT: the ordinary case must not be fenced.
			m = New()
			m.setLastStatusLocked(ProcessStatus{ConfigSnapshotProtocolVersion: ProtocolVersion})
			if err := g.run(m); err != nil {
				t.Errorf("gate armed against a CURRENT helper: %v", err)
			}
		})
	}
}

// TestRequiredProtocolGateFixturesArm7002 is the anti-vacuity control for the
// cells above. Every gate short-circuits to nil when its SHAPE predicate is
// false, so a fixture that does not carry the feature would make the
// never-observed and current cells pass while proving nothing. This asserts
// each fixture DOES reach the version comparison, by driving it at a version
// that must arm.
//
// It stays green under the mutation the test above catches (removing a
// deferral changes only the never-observed cell), which is what makes it a
// control rather than a second copy.
func TestRequiredProtocolGateFixturesArm7002(t *testing.T) {
	for _, g := range requiredProtocolGateCases(t) {
		t.Run(g.name, func(t *testing.T) {
			m := New()
			m.setLastStatusLocked(ProcessStatus{ConfigSnapshotProtocolVersion: 1})
			if err := g.run(m); err == nil {
				t.Fatal("this gate's fixture does not arm it even at version 1, so its " +
					"shape predicate is returning false and every #7002 cell for it is " +
					"vacuous")
			}
		})
	}
}

// TestRequiredProtocolGateSentinelsCoverEveryGate7002 pins the census's
// population. #7002 names FOUR gates; there are SIX, and the abort/disarm
// contract keys on this list — a gate added without an entry disarms the helper
// while the commit reports success, which is exactly #2138.
func TestRequiredProtocolGateSentinelsCoverEveryGate7002(t *testing.T) {
	const wantGates = 6
	if got := len(requiredProtocolGateSentinels); got != wantGates {
		t.Fatalf("requiredProtocolGateSentinels has %d entries, want %d. A gate was "+
			"added or removed: add its cell to TestRequiredProtocolGateDefersOnNeverObserved7002 "+
			"so the #7002 disposition covers it, or this census silently stops being a "+
			"census (#7002)", got, wantGates)
	}
	if got := len(requiredProtocolGateCases(t)); got != wantGates {
		t.Fatalf("the #7002 census drives %d gates but %d sentinels are registered",
			got, wantGates)
	}
}
