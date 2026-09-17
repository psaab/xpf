package userspace

import (
	"errors"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #6648: each per-feature required-protocol gate must fence on an IMMUTABLE
// floor — the version at which that feature's wire representation landed — not
// on the shared ProtocolVersion constant.
//
// Before the fix all four gates compared against ProtocolVersion, so every bump
// for an unrelated wire feature retroactively re-armed all of them. The
// operator-visible consequence was a wrong REASON: a helper running a
// scheduled-policy config was told "policy scheduler snapshots" required
// version 8, when policy-scheduler state has been representable since v2.
//
// The behaviour is NOT "the mismatch stops being caught". Since #6722 the
// unconditional egress-zone gate refuses ANY version skew, so a helper between
// a feature's floor and ProtocolVersion still fails closed — it just gets the
// accurate general reason instead of a misleading feature-specific one. That
// composition is pinned by TestFeatureFlooredHelperStillFailsClosed6648 below.
//
// FAIL-ON-REVERT: point any gate's comparison back at ProtocolVersion and its
// at-floor cell flips RED (the gate fires for a helper that can represent the
// feature perfectly well).

func schedulerFloorCfg() *config.Config {
	cfg := &config.Config{}
	cfg.Security.GlobalPolicies = []*config.Policy{{Name: "p", SchedulerName: "sched"}}
	return cfg
}

func persistentNATFloorCfg() *config.Config {
	cfg := &config.Config{}
	cfg.Security.NAT.SourcePools = map[string]*config.NATPool{
		"pool-a": {
			Name:          "pool-a",
			Addresses:     []string{"203.0.113.10"},
			PersistentNAT: &config.PersistentNATConfig{InactivityTimeout: 300},
		},
	}
	cfg.Security.NAT.Source = []*config.NATRuleSet{{
		Name: "rs", FromZone: "trust", ToZone: "wan",
		Rules: []*config.NATRule{{
			Name: "snat",
			Then: config.NATThen{Type: config.NATSource, PoolName: "pool-a"},
		}},
	}}
	return cfg
}

// Reuse the #5488 fixture rather than hand-rolling a second multi-zone shape:
// policyScopeIsMultiZone reads the scope through config.PolicyMatch, and a
// locally-invented literal that missed the real field names would leave this
// cell asserting on a config the gate never considers scoped at all.
func multiZoneScopeFloorCfg() *config.Config {
	return multiZoneScopedGlobalDenyConfig()
}

// Each gate is called DIRECTLY, not through ensureRequiredSnapshotProtocolLocked:
// at any version below ProtocolVersion the unconditional egress-zone gate at the
// tail of the chain also fires, so an orchestrator-level assertion could not
// tell "this gate stayed silent" from "a sibling answered first". That is the
// distinction the floor changes, so it is the one the cell has to isolate.
func TestPerFeatureGatesFenceOnTheirOwnFloor6648(t *testing.T) {
	for _, tc := range []struct {
		name  string
		floor int
		cfg   *config.Config
		sent  error
		call  func(m *Manager, cfg *config.Config) error
	}{
		{
			name: "policy-scheduler", floor: MinProtocolPolicyScheduler,
			cfg: schedulerFloorCfg(), sent: ErrPolicySchedulerProtocolIncompatible,
			call: func(m *Manager, cfg *config.Config) error {
				return m.ensurePolicySchedulerProtocolLocked(cfg)
			},
		},
		{
			name: "persistent-source-nat", floor: MinProtocolPersistentSourceNAT,
			cfg: persistentNATFloorCfg(), sent: ErrPersistentSourceNATProtocolIncompatible,
			call: func(m *Manager, cfg *config.Config) error {
				return m.ensurePersistentSourceNATProtocolLocked(cfg)
			},
		},
		{
			name: "scoped-global-zone-set", floor: MinProtocolMultiZoneScopedPolicy,
			cfg: multiZoneScopeFloorCfg(), sent: ErrScopedGlobalZoneSetProtocolIncompatible,
			call: func(m *Manager, cfg *config.Config) error {
				return m.ensureScopedGlobalZoneSetProtocolLocked(cfg)
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Premise: the fixture actually trips this gate's feature predicate.
			// Without this a silent gate would look like a pass for the wrong
			// reason — the config simply not carrying the feature.
			m := New()
			m.lastStatus.ConfigSnapshotProtocolVersion = tc.floor - 1
			if err := tc.call(m, tc.cfg); !errors.Is(err, tc.sent) {
				t.Fatalf("helper at floor-1 (%d) got %v, want %v: the fixture must "+
					"carry the feature and the gate must still fence a helper that "+
					"genuinely cannot represent it", tc.floor-1, err, tc.sent)
			}

			// THE CELL THE FLOOR EXISTS FOR. A helper exactly at the feature's
			// floor can represent it, so this gate must stay silent — even
			// though the helper is far below ProtocolVersion. Comparing against
			// ProtocolVersion makes this fire.
			m = New()
			m.lastStatus.ConfigSnapshotProtocolVersion = tc.floor
			if err := tc.call(m, tc.cfg); err != nil {
				t.Fatalf("helper at the feature floor (%d) was fenced by its own gate: %v. "+
					"The floor is the version at which the feature became representable, so "+
					"this gate must have nothing to say about it; firing here is the #6648 "+
					"coupling to ProtocolVersion (currently %d)", tc.floor, err, ProtocolVersion)
			}

			// And a helper between the floor and ProtocolVersion is likewise not
			// this gate's business.
			if tc.floor < ProtocolVersion {
				m = New()
				m.lastStatus.ConfigSnapshotProtocolVersion = ProtocolVersion - 1
				if err := tc.call(m, tc.cfg); err != nil {
					t.Fatalf("helper at ProtocolVersion-1 (%d) was fenced by the %s gate: %v",
						ProtocolVersion-1, tc.name, err)
				}
			}
		})
	}
}

// The secure-tunnel gate takes a SNAPSHOT rather than a config (#6691 round 9)
// and is scoped by snapshotRequiresRefusalProtocol, so it gets its own cell.
// Its floor is the LAST of the three bumps that built the refusal contract.
func TestSecureTunnelGateFencesOnItsOwnFloor6648(t *testing.T) {
	if MinProtocolSecureTunnelRefusal >= ProtocolVersion {
		t.Skipf("floor %d is not below ProtocolVersion %d, so the coupling this "+
			"cell isolates is not observable at this version",
			MinProtocolSecureTunnelRefusal, ProtocolVersion)
	}
	// Use the #6691 fixture that actually carries a refusal verdict. An empty
	// config produces a snapshot with no flagged row, and the gate is then
	// silent because it is SCOPED OUT — a green indistinguishable from the one
	// the floor is supposed to produce, i.e. no measurement at all.
	cfg, _, _ := spellingConfig(t, "st0", "st0", 0)
	snap := gateSnapshot(t, cfg)
	if !snapshotRequiresRefusalProtocol(snap) {
		t.Fatal("premise broken: the snapshot carries no refusal verdict, so a " +
			"silent gate would say nothing about the floor")
	}

	// Below the floor the gate must still fire — the floor is not a licence to
	// stop fencing a helper that cannot read the refusal contract.
	m := New()
	m.helperStatusObserved = true
	m.lastStatus.ConfigSnapshotProtocolVersion = MinProtocolSecureTunnelRefusal - 1
	if err := m.ensureSecureTunnelProtocolLocked(snap); !errors.Is(err, ErrSecureTunnelProtocolIncompatible) {
		t.Fatalf("helper at floor-1 (%d) got %v, want ErrSecureTunnelProtocolIncompatible",
			MinProtocolSecureTunnelRefusal-1, err)
	}

	m = New()
	m.helperStatusObserved = true
	m.lastStatus.ConfigSnapshotProtocolVersion = MinProtocolSecureTunnelRefusal
	if err := m.ensureSecureTunnelProtocolLocked(snap); err != nil {
		t.Fatalf("helper at the secure-tunnel floor (%d) was fenced: %v",
			MinProtocolSecureTunnelRefusal, err)
	}
}

// The floors are HISTORICAL FACTS about the wire. Pinning them by literal is
// the point: a floor written as `ProtocolVersion - N` or re-derived from the
// shared constant would drift on the next bump and silently restore #6648.
func TestProtocolFloorsAreImmutableLiterals6648(t *testing.T) {
	for _, tc := range []struct {
		name string
		got  int
		want int
	}{
		{"policy scheduler landed in the v2 bump (f7c4b125c)", MinProtocolPolicyScheduler, 2},
		{"persistent source NAT landed in the v3 bump (c0a047ea2)", MinProtocolPersistentSourceNAT, 3},
		{"multi-zone scoped policy landed in the v4 bump (8119bfe27)", MinProtocolMultiZoneScopedPolicy, 4},
		{"persistent NAT lease routing scope landed in the v25 bump (#10018)", MinProtocolPersistentNatLeaseScope, 25},
		{"the secure-tunnel refusal contract completed at the v7 bump (8c011681c)", MinProtocolSecureTunnelRefusal, 7},
	} {
		if tc.got != tc.want {
			t.Errorf("%s: floor = %d, want %d. These name when a feature's wire "+
				"representation appeared; renumbering one rewrites history and "+
				"re-couples its gate to an unrelated bump", tc.name, tc.got, tc.want)
		}
	}
	if MinProtocolSecureTunnelRefusal > ProtocolVersion {
		t.Errorf("secure-tunnel floor %d exceeds ProtocolVersion %d: a floor above "+
			"the shipped version fences every helper unconditionally",
			MinProtocolSecureTunnelRefusal, ProtocolVersion)
	}
}

// #6649 + #6648 COMPOSITION. The per-feature gates admit `>=` their floor,
// which by design says nothing about a helper NEWER than this control plane.
// The helper's own contract is EXACT equality (its apply_snapshot and
// bump_fib_generation handlers compare `!=` and return before any mutation), so
// a newer helper refuses our snapshot and must still fail the commit closed.
//
// #6649 was filed when that was untrue: every gate was `>= ProtocolVersion`, a
// newer helper passed all of them, and no required-protocol sentinel was
// raised. #6722 closed it by adding the UNCONDITIONAL equality gate
// (ensureEgressZoneProtocolLocked) at the tail of the chain — which is also why
// #6648's per-feature floors are safe: they answer "can this helper represent
// this feature?", and the acceptance rule lives in exactly ONE place.
//
// Nothing pinned that COMPOSITION before this cell. Measured at origin/master
// (a1a7d9653) with the per-feature gate alone: `<nil>`. Narrow the unconditional
// gate — or drop it from the chain — and a newer helper silently slips again,
// with the per-feature gates now floored and even less likely to catch it.
//
// FAIL-ON-REVERT: change ensureEgressZoneProtocolLocked's `==` to `>=`, or drop
// it from ensureRequiredSnapshotProtocolLocked, and this cell reds.
func TestFeatureFlooredHelperStillFailsClosed6648(t *testing.T) {
	for _, tc := range []struct {
		name     string
		observed int
		why      string
	}{
		{
			name:     "newer-helper",
			observed: ProtocolVersion + 1,
			why: "the helper's own gate is exact equality, so it refuses our " +
				"snapshot and stays on its previous-good image (#6649)",
		},
		{
			name:     "between-floor-and-current",
			observed: ProtocolVersion - 1,
			why: "it can represent the scheduler feature (floor v2) but cannot " +
				"accept a snapshot at this version, so the commit must still abort",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := schedulerFloorCfg()
			m := New()
			m.lastStatus.ConfigSnapshotProtocolVersion = tc.observed

			// The FEATURE gate is correctly silent: the helper can represent it.
			if err := m.ensurePolicySchedulerProtocolLocked(cfg); err != nil {
				t.Fatalf("policy-scheduler gate fired for a helper at %d that can "+
					"represent the feature (floor %d): %v",
					tc.observed, MinProtocolPolicyScheduler, err)
			}

			// The CHAIN must still refuse, and the refusal must be one the
			// commit-abort policy recognises — that predicate, not a particular
			// sentinel, is what compileErrorMustAbortApply keys on.
			err := m.ensureRequiredSnapshotProtocolLocked(gateSnapshot(t, cfg))
			if err == nil {
				t.Fatalf("a helper at version %d was ACCEPTED by the whole chain; %s",
					tc.observed, tc.why)
			}
			if !IsRequiredProtocolGateError(err) {
				t.Fatalf("chain returned %v, which IsRequiredProtocolGateError does "+
					"not recognise — the commit would not abort and the helper "+
					"would not be disarmed (#2138)", err)
			}
		})
	}
}
