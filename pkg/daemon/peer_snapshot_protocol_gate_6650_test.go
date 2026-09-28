// #6650: the #5488 snapshot-protocol gate protects the daemon<->local-helper
// skew and NOT the cross-chassis one, where the same fail-open reappears.
//
// Trace, two-node cluster, node A upgraded and node B not yet: A's gate
// short-circuits because A's OWN helper is current, the commit succeeds, and
// pushCommittedConfigToPeer ships the config TEXT to B. B recompiles it with
// its older compiler against its older helper, passes its own gate ("3 == 3"),
// and installs a deny scoped to the FIRST zone only. Traffic from the dropped
// zones is denied on A and permitted on B — and on failover to B, or for any
// flow B already owns, the operator's deny is simply not enforced.
//
// B cannot defend itself: it is the old binary, and an old binary cannot be
// taught a shape it does not parse. Only the sender can decline to push, so
// the sender has to learn what the peer can represent — which nothing in the
// tree exchanged.
//
// FAIL-ON-REVERT: bypassing the commit protocol preflight makes the behavioral
// incompatible-peer row in peer_snapshot_commit_confirmed_10782_test.go promote
// and push a snapshot the peer cannot represent.
package daemon

import (
	"errors"
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane/userspace"
)

// TestPeerSnapshotProtocolDecision6650 is the exhaustive decision matrix.
//
// Every nil-returning arm is here as a NAMED negative control, not as filler:
// each one is a way this gate could become a worse bug than the one it fixes.
// The dead-peer arm especially — refusing a commit because the peer is down
// would turn a peer outage into a config freeze.
func TestPeerSnapshotProtocolDecision6650(t *testing.T) {
	const capable = userspace.MinProtocolMultiZoneScopedPolicy
	cases := []struct {
		name      string
		clustered bool
		connected bool
		multiZone bool
		peerProto uint16
		refuse    bool
		why       string
	}{
		{
			name: "pre-#6650 peer advertises nothing", clustered: true, connected: true,
			multiZone: true, peerProto: 0, refuse: true,
			why: "a CONNECTED peer that advertises no version runs a build predating " +
				"#6650, which necessarily predates v4 — 0 must read as INCAPABLE, not " +
				"as unknown-so-allow, or the gate never fires against the exact peer " +
				"population it exists for",
		},
		{
			name: "peer one below the floor", clustered: true, connected: true,
			multiZone: true, peerProto: capable - 1, refuse: true,
			why: "the peer would read only the first zone of the scope",
		},
		{
			name: "peer exactly at the floor", clustered: true, connected: true,
			multiZone: true, peerProto: capable, refuse: false,
			why: "the floor is inclusive; refusing here would block a peer that CAN " +
				"represent the shape",
		},
		{
			name: "peer above the floor", clustered: true, connected: true,
			multiZone: true, peerProto: capable + 1, refuse: false,
		},
		{
			name:      "peer at the floor but below the current shared ProtocolVersion",
			clustered: true, connected: true, multiZone: true, peerProto: capable,
			refuse: false,
			why: "THE #6648 CONTROL. The gate must key on the per-feature floor, not on " +
				"userspace.ProtocolVersion. Keying on the shared constant would make " +
				"every future unrelated wire bump retroactively refuse multi-zone " +
				"commits across any skew — a version-skew freeze bolted onto a " +
				"narrowing fix",
		},
		{
			name: "not clustered", clustered: false, connected: true,
			multiZone: true, peerProto: 0, refuse: false,
			why: "no push, so nothing can narrow",
		},
		{
			name: "peer disconnected", clustered: true, connected: false,
			multiZone: true, peerProto: 0, refuse: false,
			why: "THE DEAD-PEER CONTROL. A node whose peer is down must keep being able " +
				"to commit — refusing would convert a peer outage into a config freeze, " +
				"and a disconnected peer receives no push to narrow anyway",
		},
		{
			name: "single-zone scope", clustered: true, connected: true,
			multiZone: false, peerProto: 0, refuse: false,
			why: "a one-element scope is bit-identical in both wire shapes, so an old " +
				"reader cannot narrow it; arming here would disarm rolling upgrades " +
				"for configs that were never at risk",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := peerSnapshotProtocolDecision(tc.clustered, tc.connected, tc.multiZone, tc.peerProto)
			if tc.refuse && err == nil {
				t.Fatalf("expected the commit to be REFUSED but it was allowed.\nwhy: %s", tc.why)
			}
			if !tc.refuse && err != nil {
				t.Fatalf("expected the commit to be ALLOWED but it was refused: %v\nwhy: %s", err, tc.why)
			}
			if !tc.refuse {
				return
			}
			if !errors.Is(err, ErrPeerSnapshotProtocolIncompatible) {
				t.Errorf("refusal does not wrap ErrPeerSnapshotProtocolIncompatible: %v", err)
			}
		})
	}
}

// TestPeerSnapshotFloorIsNotTheSharedProtocolVersion6650 states the #6648
// property as an invariant rather than leaving it to the matrix row above.
//
// If the floor were ever redefined as the shared constant, the matrix's
// "peer exactly at the floor" row would still pass — it is written in terms of
// the floor — so that row alone cannot catch the regression. This can: the
// floor names a historical wire fact (v4, when the plural zone fields landed)
// and must never track the current version.
func TestPeerSnapshotFloorIsNotTheSharedProtocolVersion6650(t *testing.T) {
	if userspace.MinProtocolMultiZoneScopedPolicy != 4 {
		t.Fatalf("MinProtocolMultiZoneScopedPolicy = %d, want 4. It names the version at "+
			"which the plural MatchFromZones/MatchToZones fields landed (#6644); that is a "+
			"historical fact and renumbering it silently changes which peers are refused",
			userspace.MinProtocolMultiZoneScopedPolicy)
	}
	if userspace.ProtocolVersion <= userspace.MinProtocolMultiZoneScopedPolicy {
		t.Skipf("ProtocolVersion (%d) has not advanced past the floor (%d), so this "+
			"invariant cannot discriminate yet", userspace.ProtocolVersion,
			userspace.MinProtocolMultiZoneScopedPolicy)
	}
	// A peer at the floor but below the current shared version must be ACCEPTED.
	if err := peerSnapshotProtocolDecision(true, true, true,
		uint16(userspace.MinProtocolMultiZoneScopedPolicy)); err != nil {
		t.Fatalf("a peer at the per-feature floor (%d) was refused while the shared "+
			"ProtocolVersion is %d: %v — the gate is keying on the shared constant, so "+
			"every future unrelated wire bump will retroactively freeze multi-zone "+
			"commits across a version skew (open #6648's defect, imported into new code)",
			userspace.MinProtocolMultiZoneScopedPolicy, userspace.ProtocolVersion, err)
	}
}

// TestCrossChassisGateSharesTheLocalArmingPredicate6650 binds the two gates to
// ONE arming predicate.
//
// The local #5488 gate and this cross-chassis gate must fire on the same shape.
// If they drift, either a config the local helper refuses is still pushed to
// the peer, or a config both nodes can represent is blocked. A copy of the
// predicate in pkg/daemon would drift silently — the two live in different
// packages and nothing would connect them — so the exported wrapper delegates,
// and this asserts the delegation on the shapes that matter.
func TestCrossChassisGateSharesTheLocalArmingPredicate6650(t *testing.T) {
	multi := &config.Config{}
	multi.Security.GlobalPolicies = []*config.Policy{{
		Name:  "g",
		Match: config.PolicyMatch{FromZones: []string{"dmz", "trust"}, ToZones: []string{"untrust"}},
	}}
	single := &config.Config{}
	single.Security.GlobalPolicies = []*config.Policy{{
		Name:  "g",
		Match: config.PolicyMatch{FromZones: []string{"dmz"}, ToZones: []string{"untrust"}},
	}}
	unscoped := &config.Config{}
	unscoped.Security.GlobalPolicies = []*config.Policy{{Name: "g"}}

	for _, tc := range []struct {
		name string
		cfg  *config.Config
		want bool
	}{
		{"multi-zone from-scope", multi, true},
		{"single-zone scope", single, false},
		{"unscoped global", unscoped, false},
		{"nil config", nil, false},
	} {
		if got := userspace.ConfigHasMultiZoneScopedPolicy(tc.cfg); got != tc.want {
			t.Errorf("ConfigHasMultiZoneScopedPolicy(%s) = %v, want %v — the exported "+
				"wrapper has drifted from the predicate that arms the local #5488 gate",
				tc.name, got, tc.want)
		}
	}
}

func TestSnapshotProtocolGateRequiresClusterRuntime6650(t *testing.T) {
	ss := cluster.NewSessionSync(":0", ":0", nil)
	ss.SetConnectedForTesting(true)
	ss.SetPeerSnapshotProtocolVersionForTesting(3)
	d := &Daemon{sessionSync: ss}
	cand := &config.Config{}
	cand.Chassis.Cluster = &config.ClusterConfig{ConfigSync: true}
	cand.Security.GlobalPolicies = []*config.Policy{{
		Match: config.PolicyMatch{
			FromZones: []string{"dmz", "trust"},
			ToZones:   []string{"untrust"},
		},
	}}

	auth, err := d.peerSnapshotProtocolAuthorizationForConfig(cand)
	if err != nil || auth != nil {
		t.Fatalf("snapshot authorization ran without a cluster runtime: auth=%#v err=%v", auth, err)
	}
}
