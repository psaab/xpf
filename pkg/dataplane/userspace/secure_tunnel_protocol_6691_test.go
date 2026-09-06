package userspace

import (
	"errors"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #6691 B2 — the v5 protocol bump and its required-protocol gate.
//
// `InterfaceSnapshot.secure_tunnel` is a NEW field that is AUTHORITATIVE over
// existing behaviour: the helper's binding admission refuses a candidate on it.
// The repo rule (userspace-dp/src/server/README.md) is to bump the snapshot
// protocol version whenever that happens, and this PR shipped the field at an
// unchanged version 4 — the same shape as #5488.
//
// WHAT AN OLD HELPER ACTUALLY DOES, which is why this is not cosmetic. A v4
// helper decodes the snapshot, ignores the unknown `secure_tunnel` tag, and
// plans the xfrmi as an ordinary AF_XDP candidate. Its queue count is the
// GLOBAL MINIMUM across candidates (replan_bindings_from_candidates,
// userspace-dp/src/server/helpers/planning.rs) and an xfrm interface has
// exactly ONE RX queue — measured on a real device: `ip -d link` reports
// `numrxqueues 1` and `/sys/class/net/<if>/queues` holds a single `rx-0`, the
// same entry userspaceRXQueueCount counts. So the ignored flag does not cost
// the tunnel a binding; it re-plans EVERY physical interface on the box onto
// one queue and one worker (#3091). Nothing on the wire is malformed, so the
// same-version equality check and the snapshot content hash both see a
// perfectly good snapshot.

// preSecureTunnelProtocolVersion is the version this PR shipped the
// `secure_tunnel` field at before the #6691 round-8 bump — the version whose
// readers cannot see the field. A LITERAL, not `ProtocolVersion - 1`, for the
// same reason preV4SnapshotProtocolVersion is: the property under test is that
// the current version no longer COLLIDES with the version that misreads the
// snapshot, so tracking the constant would make the test vacuous the moment
// the constant moves again.
const preSecureTunnelProtocolVersion = 4

// secureTunnelSnapshotProtocolVersion is the version this PR must ship at, and
// it is asserted by EQUALITY. #6691 round 9 raised it from 5 to 6 because the
// refusal rule the `secure_tunnel` flag feeds changed WITHIN this PR: a round-8
// v5 helper and a round-9 v5 helper would accept identical bytes and plan
// different bindings for a VLAN sibling of a flagged parent. A version whose
// meaning depends on which round produced the binary is not a version. Nothing
// has shipped at either value, so the cost is zero.
//
// issue 8892 moved it 8 -> 9. That bump is NOT about secure_tunnel: it is the
// routing_domain field, which was added at v8 with no bump. This constant
// tracks the CURRENT snapshot version, so it moves with any bump — it is not a
// feature floor. The floor for this feature is MinProtocolSecureTunnelRefusal
// (7) in protocol.go, it gates real behaviour in manager_compile.go, it is
// immutable, and it is deliberately untouched: a v8 helper still handles
// secure_tunnel correctly, so nothing about this feature's compatibility
// changed.
//
// What the equality below still buys after that bump: the two planes must
// agree on the number, and the number must move whenever the meaning does.
// Both survive; only the literal moved.
//
// Issue 9054 moved it 9 -> 10, and the reasoning is identical to 8892's: the
// bump is for `learned_route_import_capped`, not for secure_tunnel. A v9 helper
// still handles secure_tunnel correctly, so MinProtocolSecureTunnelRefusal (7)
// is again untouched.
const secureTunnelSnapshotProtocolVersion = 10

// preV5HelperAcceptsSnapshot models the exact-equality version gate a pre-v5
// helper applies before touching any dataplane state
// (userspace-dp/src/server/handlers/snapshot.rs).
func preV5HelperAcceptsSnapshot(version int) bool {
	return version == preSecureTunnelProtocolVersion
}

// preV5HelperPlansBinding models a pre-v5 helper's binding admission: the
// current predicate MINUS the `secure_tunnel` arm, which such a helper does not
// have. Everything else is unchanged, so this isolates the one field.
func preV5HelperPlansBinding(iface InterfaceSnapshot) bool {
	if iface.Zone == "" || iface.Tunnel || iface.LocalFabric != "" {
		return false
	}
	base := iface.Name
	for i := 0; i < len(base); i++ {
		if base[i] == '.' {
			base = base[:i]
			break
		}
	}
	switch {
	case len(base) >= 3 && base[:3] == "fxp",
		len(base) >= 2 && base[:2] == "em",
		len(base) >= 3 && base[:3] == "fab",
		base == "lo0":
		return false
	}
	switch iface.Zone {
	case "mgmt", "control":
		return false
	}
	return true
}

// TestSecureTunnelFieldIsNotIgnorableByAPreV5Helper is the #6691 B2
// regression: the version must have MOVED off the value whose readers ignore
// the field, and the gate must turn the resulting refusal into a fail-closed
// disarm plus an aborted commit.
//
// FAIL-ON-REVERT: set ProtocolVersion back to 4 and the first assertion reds
// (a pre-v5 helper accepts the snapshot); drop
// ensureSecureTunnelProtocolLocked from ensureRequiredSnapshotProtocolLocked
// and the gate assertion reds; drop the sentinel from
// requiredProtocolGateSentinels and the abort-set assertion reds.
func TestSecureTunnelFieldIsNotIgnorableByAPreV5Helper(t *testing.T) {
	// EQUALITY, not `> preV5` (#6691 round 9). The inequality stayed green at
	// the colliding value — the whole point of the finding — because a version
	// whose MEANING changed inside this PR is not distinguished by being merely
	// larger than the one before it. Round 8 shipped v5 with an ANY-owner
	// refusal; round 9's EVERY-owner rule accepts the same bytes and re-keys an
	// unflagged VLAN sibling onto its flagged parent where round 8 dropped it.
	// Neither v5 nor v6 has ever shipped (#6691 is unmerged), so the bump costs
	// nothing and buys a version number that means one thing.
	if ProtocolVersion != secureTunnelSnapshotProtocolVersion {
		t.Fatalf("ProtocolVersion = %d, want exactly %d. `secure_tunnel` is authoritative "+
			"over binding admission AND the refusal rule it feeds changed inside this PR, so "+
			"the version must move whenever either does — an inequality cannot say that",
			ProtocolVersion, secureTunnelSnapshotProtocolVersion)
	}
	if ProtocolVersion <= preSecureTunnelProtocolVersion {
		t.Fatalf("ProtocolVersion = %d, must be > %d: `secure_tunnel` became authoritative "+
			"over binding admission, so a reader that cannot see it must not share our version",
			ProtocolVersion, preSecureTunnelProtocolVersion)
	}

	cfg, unitRef, wantDev := spellingConfig(t, "st0.0", "st0", 0)
	restore := stubLinkSnapshot5619(t, map[string]int{wantDev: 42, "ge-0-0-0": 11})
	defer restore()

	// PREMISE: the snapshot really does carry a flagged row, and it really
	// does resolve to a device — otherwise every assertion below is vacuous.
	var tunnelRow *InterfaceSnapshot
	for i := range buildInterfaceSnapshots(cfg) {
		row := buildInterfaceSnapshots(cfg)[i]
		if row.Name == unitRef {
			tunnelRow = &row
			break
		}
	}
	if tunnelRow == nil || !tunnelRow.SecureTunnel || tunnelRow.Ifindex <= 0 {
		t.Fatalf("premise broken: %q row = %+v, want SecureTunnel with a resolved ifindex",
			unitRef, tunnelRow)
	}

	// 1. THE OLD READER MISBEHAVES. Stated so the gate has a documented reason
	//    rather than an asserted one: a pre-v5 helper plans the xfrmi, and the
	//    planner's global-minimum queue count then collapses the box.
	if !preV5HelperPlansBinding(*tunnelRow) {
		t.Fatalf("premise broken: a pre-v5 helper must PLAN this row (it cannot see "+
			"secure_tunnel); row = %+v", tunnelRow)
	}

	// 2. THE VERSION KEEPS IT AWAY FROM THAT READER. The daemon stamps its own
	//    ProtocolVersion onto every snapshot; a pre-v5 helper must refuse it.
	snap := &ConfigSnapshot{Version: ProtocolVersion}
	if preV5HelperAcceptsSnapshot(snap.Version) {
		t.Errorf("a pre-v5 helper ACCEPTS the snapshot at version %d: it ignores secure_tunnel, "+
			"plans an AF_XDP binding for the xfrmi, and its one RX queue becomes the global "+
			"minimum — every interface collapses to one queue and one worker (#3091)",
			snap.Version)
	}

	// 3. AND THE REFUSAL IS FAIL-CLOSED. A refused snapshot alone leaves the
	//    old helper ARMED on its previous-good image while the commit reports
	//    success. Drive the REAL dispatcher, not the gate function, so the
	//    wiring is what is under test.
	m := New()
	m.setLastStatusLocked(ProcessStatus{ConfigSnapshotProtocolVersion: preSecureTunnelProtocolVersion})
	gateErr := m.ensureRequiredSnapshotProtocolLocked(gateSnapshot(t, cfg))
	if !errors.Is(gateErr, ErrSecureTunnelProtocolIncompatible) {
		t.Errorf("ensureRequiredSnapshotProtocolLocked against a pre-v5 helper = %v, want "+
			"ErrSecureTunnelProtocolIncompatible — the helper must be disarmed, not handed a "+
			"snapshot whose secure_tunnel flag it will ignore", gateErr)
	}
	// #2138: a gate that disarms but is missing from the abort set promotes the
	// commit against a disarmed dataplane.
	if !IsRequiredProtocolGateError(gateErr) {
		t.Errorf("IsRequiredProtocolGateError(%v) = false, want true — the #6691 gate must "+
			"abort the commit", gateErr)
	}

	// 4. A CURRENT HELPER IS NOT GATED.
	m2 := New()
	m2.setLastStatusLocked(ProcessStatus{ConfigSnapshotProtocolVersion: ProtocolVersion})
	if err := m2.ensureRequiredSnapshotProtocolLocked(gateSnapshot(t, cfg)); err != nil {
		t.Errorf("current-version helper gated: %v, want nil", err)
	}
}

// TestSecureTunnelGateIsScopedToConfigsThatDeriveAnXfrmi is the negative
// control. A config with no route-based IPsec cannot be misread by a pre-v5
// helper — there is no flagged row for it to ignore — so it must NOT be gated.
// Without this, the fix disarms every operator on an older helper for a field
// none of their interfaces carry.
func TestSecureTunnelGateIsScopedToConfigsThatDeriveAnXfrmi(t *testing.T) {
	cfg := compileForTest5619(t,
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.1.1/24",
		"set security zones security-zone trust interfaces ge-0/0/0.0",
	)
	if snapshotRequiresRefusalProtocol(gateSnapshot(t, cfg)) {
		t.Fatal("premise broken: this config derives no xfrmi")
	}

	m := New()
	m.setLastStatusLocked(ProcessStatus{ConfigSnapshotProtocolVersion: preSecureTunnelProtocolVersion})
	if err := m.ensureSecureTunnelProtocolLocked(gateSnapshot(t, cfg)); err != nil {
		t.Errorf("a config with no secure tunnel was gated against a pre-v5 helper: %v", err)
	}
}

// TestSecureTunnelGateSeesEverySpelling: the gate's arming predicate walks the
// same refs the snapshot builder walks, so it must arm for every spelling the
// builder flags. A gate that fires for `st0.0` but not `st10.5` would leave the
// multi-digit spellings ungated on exactly the upgrade this exists to stop.
func TestSecureTunnelGateSeesEverySpelling(t *testing.T) {
	for _, tc := range secureTunnelSpellings {
		t.Run(tc.name, func(t *testing.T) {
			cfg, _, _ := spellingConfig(t, tc.bindIface, tc.ifName, tc.unit)
			if !snapshotRequiresRefusalProtocol(gateSnapshot(t, cfg)) {
				t.Fatalf("configHasSecureTunnel = false for bind-interface %q; the v5 gate "+
					"would not arm and a pre-v5 helper would plan its binding", tc.bindIface)
			}
			m := New()
			m.setLastStatusLocked(ProcessStatus{ConfigSnapshotProtocolVersion: preSecureTunnelProtocolVersion})
			if err := m.ensureSecureTunnelProtocolLocked(gateSnapshot(t, cfg)); !errors.Is(err, ErrSecureTunnelProtocolIncompatible) {
				t.Fatalf("gate for bind-interface %q = %v, want ErrSecureTunnelProtocolIncompatible",
					tc.bindIface, err)
			}
		})
	}
}

// gateSnapshot builds the snapshot a required-protocol gate now takes (#6691
// round 9). The gate reads the flags the BUILDER stamped rather than
// re-deriving them from config, so a test must hand it a real snapshot for the
// assertion to be about production's oracle.
func gateSnapshot(t *testing.T, cfg *config.Config) *ConfigSnapshot {
	t.Helper()
	snap, err := buildSnapshot(cfg, deriveUserspaceConfig(cfg), 0, 0)
	if err != nil {
		t.Fatalf("buildSnapshot for gate: %v", err)
	}
	return snap
}

// TestSecureTunnelGateReadsTheAppliedSnapshot binds the #6691 round 9 fix for
// the triple-sampled kernel evidence — and it is the guard that was missing:
// the first round-9b mutation grid found "gate re-derives instead of reading
// the snapshot" SURVIVING, because every other test hands the gate a snapshot it
// built from the same stub a moment earlier, so re-deriving looks identical.
//
// The oracle must answer DIFFERENTLY on the second call for the two to be
// distinguishable, which is exactly the production hazard: the builder's
// RTM_GETLINK dump and any later one see different kernels. Round 8 sampled
// twice and, measured, returned false for a snapshot carrying SecureTunnel=true
// — so a pre-v6 helper stayed ARMED on its previous-good image for precisely the
// snapshot this gate exists to refuse.
//
// FAIL-ON-REVERT: make snapshotRequiresRefusalProtocol re-derive
// (`buildInterfaceSnapshots(snap.Config)`) instead of reading snap.Interfaces
// and this reds — the gate returns nil for a flagged snapshot.
func TestSecureTunnelGateReadsTheAppliedSnapshot(t *testing.T) {
	defer stubLinkSnapshot5619(t, map[string]int{"ge-0-0-0": 10, "st10": 11})()

	prev := liveXfrmNetdevs
	calls := 0
	// A kernel that shows the xfrm device to the FIRST dump and nothing after —
	// a device deleted between two samples, or a dump interrupted by concurrent
	// link churn.
	liveXfrmNetdevs = func() (map[string]bool, error) {
		calls++
		if calls == 1 {
			return map[string]bool{"st10": true}, nil
		}
		return nil, nil
	}
	defer func() { liveXfrmNetdevs = prev }()

	cfg := compileForTest5619(t,
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.1.1/24",
		"set interfaces st10 unit 0 family inet address 192.0.2.1/24",
		"set security zones security-zone trust interfaces ge-0/0/0.0",
		"set security zones security-zone trust interfaces st10.0",
	)
	// The APPLIED snapshot — one build, one sample.
	applied, err := buildSnapshot(cfg, deriveUserspaceConfig(cfg), 0, 0)
	if err != nil {
		t.Fatalf("buildSnapshot: %v", err)
	}
	if calls != 1 {
		t.Fatalf("premise broken: the builder took %d samples, want 1", calls)
	}

	// PREMISES. The snapshot must carry the flag, and a SECOND sample must not
	// see it — without both, re-deriving and reading are indistinguishable and
	// this test is the vacuous one it replaces.
	// Read the ROWS directly, not through snapshotRequiresRefusalProtocol — the premise
	// must not be expressed with the function under test, or a mutation of that
	// function reds this as a "premise broken" and misdirects the next reader to
	// the fixture instead of to production.
	flagged := false
	for _, iface := range applied.Interfaces {
		if iface.SecureTunnel {
			flagged = true
			break
		}
	}
	if !flagged {
		t.Fatal("premise broken: the applied snapshot carries no flagged row")
	}
	if rebuilt := buildInterfaceSnapshots(cfg); func() bool {
		for _, iface := range rebuilt {
			if iface.SecureTunnel {
				return true
			}
		}
		return false
	}() {
		t.Fatal("premise broken: a re-derivation still sees the xfrmi, so the two " +
			"oracles agree and nothing is being distinguished")
	}

	m := &Manager{}
	m.setLastStatusLocked(ProcessStatus{ConfigSnapshotProtocolVersion: preSecureTunnelProtocolVersion})
	err = m.ensureSecureTunnelProtocolLocked(applied)
	if !errors.Is(err, ErrSecureTunnelProtocolIncompatible) {
		t.Fatalf("gate returned %v, want %v. The applied snapshot carries "+
			"SecureTunnel=true and the helper is pre-v6, so the gate must fire — a "+
			"gate that re-samples the kernel answers about a DIFFERENT instant and "+
			"leaves that helper armed on its previous-good image",
			err, ErrSecureTunnelProtocolIncompatible)
	}
}

// TestSecureTunnelGateNeedsAnObservedVersion is the #6691 round 10 guard for
// B2: the gate must arm on an OBSERVED too-old version and never on the ABSENCE
// of one.
//
// The two states it separates both leave ConfigSnapshotProtocolVersion below
// ProtocolVersion, so the value alone cannot tell them apart:
//
//   - a helper answered and reported an old version — an incompatibility, arm;
//   - no helper has ever answered — nothing to be incompatible WITH, do not arm.
//
// Arming on the second disarms a dataplane and aborts an operator's commit on
// the strength of a reading that never happened. It is REACHABLE rather than
// theoretical: the deferred-worker arm (manager_worker_arm_5134.go) reaches
// this gate through ensureRequiredSnapshotProtocolLocked BEFORE any helper
// liveness check, so a pending-XSK re-apply attempted while the helper is down
// took the abort path on a config that had merely acquired a live xfrm device.
//
// SCOPE: this test covers the secure-tunnel gate only. The three sibling
// required-protocol gates share the shape, and what each should do on an
// unobserved version is #7002 — each has its own fail-closed argument to weigh,
// so they are deliberately not changed here.
//
// FAIL-ON-REVERT: delete the `!m.helperStatusObserved` return and the first
// subtest reds; make it unconditional and the second reds.
func TestSecureTunnelGateNeedsAnObservedVersion(t *testing.T) {
	cfg, _, _ := spellingConfig(t, "st0", "st0", 0)
	snap := gateSnapshot(t, cfg)
	if !snapshotRequiresRefusalProtocol(snap) {
		t.Fatal("premise broken: the snapshot carries no flagged row, so the gate " +
			"is scoped out and neither subtest measures the conditionality")
	}

	t.Run("never observed: does not arm", func(t *testing.T) {
		m := New()
		// No status recorded and no helper to answer the live "status"
		// request the gate makes — exactly the pending-XSK-with-helper-down
		// state.
		if m.helperStatusObserved {
			t.Fatal("premise broken: a fresh Manager already claims an observed version")
		}
		if err := m.ensureSecureTunnelProtocolLocked(snap); err != nil {
			t.Fatalf("gate armed with no version ever observed: %v. lastStatus is a "+
				"zero value because no helper has answered, not because one reported "+
				"an old version — arming here disarms the dataplane and aborts the "+
				"commit on a reading that never happened", err)
		}
	})

	t.Run("observed and too old: arms", func(t *testing.T) {
		m := New()
		m.setLastStatusLocked(ProcessStatus{ConfigSnapshotProtocolVersion: preSecureTunnelProtocolVersion})
		if err := m.ensureSecureTunnelProtocolLocked(snap); !errors.Is(err, ErrSecureTunnelProtocolIncompatible) {
			t.Fatalf("gate = %v, want ErrSecureTunnelProtocolIncompatible. A helper "+
				"DID report version %d, which cannot represent this snapshot",
				err, preSecureTunnelProtocolVersion)
		}
	})

	t.Run("observed with no version field at all: arms", func(t *testing.T) {
		// A helper old enough to omit config_snapshot_protocol_version decodes
		// to 0 — indistinguishable BY VALUE from "never observed", and the
		// opposite verdict. This is the case the explicit marker exists for;
		// a `version > 0` shortcut would fail-open here.
		m := New()
		m.setLastStatusLocked(ProcessStatus{PID: 4242})
		if m.lastStatus.ConfigSnapshotProtocolVersion != 0 {
			t.Fatal("premise broken: this status must carry no version")
		}
		if err := m.ensureSecureTunnelProtocolLocked(snap); !errors.Is(err, ErrSecureTunnelProtocolIncompatible) {
			t.Fatalf("gate = %v, want ErrSecureTunnelProtocolIncompatible. A helper "+
				"that answers WITHOUT the version field is too old for this snapshot; "+
				"only silence is not an observation", err)
		}
	})

	t.Run("observation is forgotten when the helper goes away", func(t *testing.T) {
		// A version read from a process that no longer exists is not an
		// observation about the one that replaces it, so stopping the helper
		// must clear both halves together.
		m := New()
		m.setLastStatusLocked(ProcessStatus{ConfigSnapshotProtocolVersion: preSecureTunnelProtocolVersion})
		m.clearLastStatusLocked()
		if m.helperStatusObserved {
			t.Fatal("clearLastStatusLocked kept the observation while dropping the " +
				"status — the two must move together or the gate arms on a version " +
				"belonging to a dead process")
		}
		if err := m.ensureSecureTunnelProtocolLocked(snap); err != nil {
			t.Fatalf("gate armed against a forgotten helper: %v", err)
		}
	})
}
