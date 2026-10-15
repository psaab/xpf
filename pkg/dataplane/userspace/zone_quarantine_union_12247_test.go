package userspace

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// nodeScopedZones12247 scopes z174 to groups node0 and z214 to groups node1.
// The two names fold to one StableZoneID, so each node installs one side of a
// colliding pair and only the cross-node runtime name set sees the collision.
const nodeScopedZones12247 = `groups {
  node0 { security { zones { security-zone z174 { interfaces { ge-0/0/0.0; } } } } }
  node1 { security { zones { security-zone z214 { interfaces { ge-0/0/1.0; } } } } }
}
apply-groups "${node}";
interfaces {
  ge-0/0/0 { unit 0 { family inet { address 10.0.0.1/24; } } }
  ge-0/0/1 { unit 0 { family inet { address 10.0.1.1/24; } } }
}`

func parseTree12247(t *testing.T, text string) *config.ConfigTree {
	t.Helper()
	if config.StableZoneID("z174") != config.StableZoneID("z214") {
		t.Fatal("test premise broken: z174/z214 no longer collide under the frozen fold")
	}
	tree, errs := config.NewParser(text).Parse()
	if len(errs) != 0 {
		t.Fatalf("parse: %v", errs)
	}
	return tree
}

// lenientCompile12247 tolerant-compiles tree for nodeID, or generically when
// nodeID is negative. Compiles clone the tree, so one tree serves every call.
func lenientCompile12247(t *testing.T, tree *config.ConfigTree, nodeID int) *config.Config {
	t.Helper()
	var cfg *config.Config
	var err error
	if nodeID < 0 {
		cfg, err = config.CompileConfigLenient(tree)
	} else {
		cfg, err = config.CompileConfigForNodeLenient(tree, nodeID)
	}
	if err != nil {
		t.Fatalf("tolerant compile (node %d): %v", nodeID, err)
	}
	return cfg
}

// hermeticSnapshot12247 stubs the netlink ip-rule and link reads buildSnapshot
// performs, so a snapshot depends only on the compiled config.
func hermeticSnapshot12247(t *testing.T) {
	t.Helper()
	stubRuleListHermetic(t)
	prev := buildLinkSnapshot
	t.Cleanup(func() { buildLinkSnapshot = prev })
	buildLinkSnapshot = func(string) (int, int, string, []InterfaceAddressSnapshot) {
		return 0, 0, "", nil
	}
}

func TestNodeScopedZoneQuarantineUsesThreeViewUnion12247(t *testing.T) {
	hermeticSnapshot12247(t)
	tree := parseTree12247(t, `groups {
  node0 { security { zones { security-zone z174; } } }
  node1 { security { zones { security-zone z214; } } }
}
apply-groups "${node}";`)

	for _, tc := range []struct {
		name           string
		nodeID         int
		wantZone       string
		wantQuarantine bool
	}{
		{name: "node0", nodeID: 0, wantZone: "z174"},
		{name: "node1", nodeID: 1, wantZone: "z214", wantQuarantine: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := lenientCompile12247(t, tree, tc.nodeID)
			if len(cfg.ZoneQuarantineNames) != 2 ||
				cfg.ZoneQuarantineNames[0] != "z174" ||
				cfg.ZoneQuarantineNames[1] != "z214" {
				t.Fatalf("node%d quarantine-name union = %v, want [z174 z214]",
					tc.nodeID, cfg.ZoneQuarantineNames)
			}
			excluded := config.ZoneQuarantineExclusionsForConfig(cfg)
			if _, ok := excluded["z214"]; !ok {
				t.Fatalf("node%d config exclusions = %v, want peer-union loser z214",
					tc.nodeID, excluded)
			}
			if _, ok := excluded["z174"]; ok {
				t.Fatalf("node%d config exclusions = %v, want survivor z174 retained",
					tc.nodeID, excluded)
			}
			if got := config.ZoneQuarantineExcludedReason("z214", cfg); got == "" {
				t.Fatalf("node%d did not report peer-union loser z214 as quarantined", tc.nodeID)
			}
			if len(cfg.Security.Zones) != 1 || cfg.Security.Zones[tc.wantZone] == nil {
				t.Fatalf("node%d zones = %v, want only %q", tc.nodeID, cfg.Security.Zones, tc.wantZone)
			}

			// The real builder, so the zone build -> quarantine ordering in
			// buildSnapshot is what is pinned, not a hand-assembled snapshot.
			snap, err := buildSnapshot(cfg, config.UserspaceConfig{}, 0, 0)
			if err != nil {
				t.Fatalf("node%d snapshot build: %v", tc.nodeID, err)
			}
			collisions := snap.zoneIDCollisions
			if tc.wantQuarantine {
				if len(collisions) != 1 || collisions[0].Quarantined != "z214" || collisions[0].Survivor != "z174" {
					t.Fatalf("node%d collision records = %+v, want z214 quarantined in favor of z174", tc.nodeID, collisions)
				}
				if len(snap.Zones) != 0 {
					t.Fatalf("node%d published zones = %+v, want z214 quarantined", tc.nodeID, snap.Zones)
				}
				return
			}
			if len(collisions) != 0 || len(snap.Zones) != 1 || snap.Zones[0].Name != "z174" {
				t.Fatalf("node%d published zones = %+v, collisions = %+v; want survivor z174", tc.nodeID, snap.Zones, collisions)
			}
		})
	}
}

// TestNodeScopedQuarantineUnzonesLoserInterface12247 pins the interface->zone
// map the interface and host-inbound builders read (buildInterfaceZoneMap).
// node1's z214 loses to node0's z174, so z214's interface must resolve to no
// zone on node1 (fail closed), while node0 keeps z174 on its own interface.
func TestNodeScopedQuarantineUnzonesLoserInterface12247(t *testing.T) {
	tree := parseTree12247(t, nodeScopedZones12247)
	for _, tc := range []struct {
		nodeID int
		zone   string
		iface  string
		want   string
	}{
		{nodeID: 0, zone: "z174", iface: "ge-0/0/0.0", want: "z174"},
		{nodeID: 1, zone: "z214", iface: "ge-0/0/1.0", want: ""},
	} {
		cfg := lenientCompile12247(t, tree, tc.nodeID)
		// The authored claim must exist, or an empty result below would pass
		// because the config never bound the interface at all.
		if zone := cfg.Security.Zones[tc.zone]; zone == nil || !slices.Contains(zone.Interfaces, tc.iface) {
			t.Fatalf("node%d precondition: zone %q does not author %s: %+v", tc.nodeID, tc.zone, tc.iface, zone)
		}
		if got := buildInterfaceZoneMap(cfg)[tc.iface]; got != tc.want {
			t.Fatalf("node%d runtime zone of %s = %q, want %q", tc.nodeID, tc.iface, got, tc.want)
		}
	}
}

// TestSchedulerRepublishScrubsNodeScopedLoser12247 drives the scheduler-only
// partial republish (UpdatePolicyScheduleState) on node1. It rebuilds policies
// from raw cfg while inheriting the full build's reduced zones, so it must
// re-scrub against the same runtime name set (quarantinedZoneNamesForConfig).
// Scrubbing against node1's own zones alone would keep the trust->z214 rule
// with z214 absent from the published zones, which the Rust
// UnresolvableZoneReference preflight rejects as a whole snapshot (#6480).
func TestSchedulerRepublishScrubsNodeScopedLoser12247(t *testing.T) {
	hermeticSnapshot12247(t)
	tree := parseTree12247(t, nodeScopedZones12247+`
schedulers { scheduler workhours { daily { start-time 09:00:00; stop-time 17:00:00; } } }
security {
  zones { security-zone trust; security-zone untrust; }
  policies {
    from-zone trust to-zone untrust {
      policy local-allow {
        match { source-address any; destination-address any; application any; }
        then { permit; }
        scheduler-name workhours;
      }
    }
    from-zone trust to-zone z214 {
      policy peer-loser-allow {
        match { source-address any; destination-address any; application any; }
        then { permit; }
        scheduler-name workhours;
      }
    }
  }
}`)
	cfg := lenientCompile12247(t, tree, 1)
	if !schedPolicyPresentInConfig12247(cfg, "z214", "peer-loser-allow") {
		t.Fatal("precondition: node1 config does not carry the trust->z214 scheduled permit")
	}

	dir, err := os.MkdirTemp("", "x12247")
	if err != nil {
		t.Fatalf("mkdtemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	controlSock := filepath.Join(dir, "control.sock")

	m := New()
	m.proc = &exec.Cmd{Process: &os.Process{Pid: os.Getpid()}}
	m.cfg.ControlSocket = controlSock
	m.generation = 5
	m.lastStatus.ConfigSnapshotProtocolVersion = ProtocolVersion
	m.lastSnapshot, err = buildSnapshotWithSchedulerState(
		cfg, config.UserspaceConfig{ControlSocket: controlSock}, 5, 0,
		map[string]bool{"workhours": true}, nil, nil)
	if err != nil {
		t.Fatalf("build lastSnapshot: %v", err)
	}
	// Precondition: the full build already quarantined z214 and dropped its rule.
	assertNoDanglingZoneRef5328(t, m.lastSnapshot)
	if len(m.lastSnapshot.zoneIDCollisions) != 1 || m.lastSnapshot.zoneIDCollisions[0].Quarantined != "z214" {
		t.Fatalf("seed collisions = %+v, want z214 quarantined", m.lastSnapshot.zoneIDCollisions)
	}
	if schedPolicyPresent5328(m.lastSnapshot.Policies, "peer-loser-allow") {
		t.Fatal("precondition: the full build kept the trust->z214 permit")
	}

	reqs := startArmControlServer(t, controlSock, 1)
	if err := m.UpdatePolicyScheduleState(cfg, map[string]bool{"workhours": false}); err != nil {
		t.Fatalf("UpdatePolicyScheduleState: %v", err)
	}
	var req ControlRequest
	select {
	case req = <-reqs:
	case <-time.After(10 * time.Second):
		t.Fatal("scheduler republish sent no snapshot to the helper")
	}
	if req.Snapshot == nil {
		t.Fatal("captured control request carried no snapshot")
	}
	assertNoDanglingZoneRef5328(t, req.Snapshot)
	if schedPolicyPresent5328(req.Snapshot.Policies, "peer-loser-allow") {
		t.Fatal("scheduler republish reintroduced the trust->z214 permit for quarantined z214")
	}
	if !schedPolicyInactive5328(t, req.Snapshot.Policies, "local-allow") {
		t.Fatal("scheduler republish did not apply the closed window to local-allow")
	}
}

// TestPartialRepublishRefusesQuarantineOnlySkew12247 pins the #6480/#5680
// skew guard (configsContentEqual) to the runtime zone-name set, which is
// `json:"-"` and so invisible to the guard's marshal comparison. On node1,
// config A keeps z174 in a group nothing applies and config B renames that
// group to node0. Both compile to the same JSON (zones, policies and the
// View-1 warning), yet B quarantines node1's z214 in favour of the peer's z174
// while A keeps it live. With A applied and B's full apply failed, a partial
// republish of B would scrub z214's deny while inheriting A's live z214, so
// z214 traffic would reach the global permit. Both partial-republish paths
// must refuse B, while a recompile of A stays content-equal.
func TestPartialRepublishRefusesQuarantineOnlySkew12247(t *testing.T) {
	hermeticSnapshot12247(t)
	compileWithGroup := func(group string) *config.Config {
		return lenientCompile12247(t, parseTree12247(t, `groups {
  `+group+` { security { zones { security-zone z174; } } }
  node1 { security { zones { security-zone z214 { interfaces { ge-0/0/1.0; } } } } }
}
apply-groups "${node}";
interfaces { ge-0/0/1 { unit 0 { family inet { address 10.0.1.1/24; } } } }
schedulers { scheduler workhours { daily { start-time 09:00:00; stop-time 17:00:00; } } }
security {
  zones { security-zone trust; security-zone untrust; }
  policies {
    from-zone trust to-zone untrust {
      policy office-hours {
        match { source-address any; destination-address any; application any; }
        then { permit; }
        scheduler-name workhours;
      }
    }
    from-zone trust to-zone z214 {
      policy z214-deny {
        match { source-address any; destination-address any; application any; }
        then { deny; }
      }
    }
    global {
      policy allow-rest {
        match { source-address any; destination-address any; application any; }
        then { permit; }
      }
    }
  }
}`), 1)
	}
	cfgA := compileWithGroup("unused")
	cfgB := compileWithGroup("node0")

	// The skew must be invisible to the marshal, or this cell would pass on
	// the JSON comparison alone.
	jsonA, err := json.Marshal(cfgA)
	if err != nil {
		t.Fatalf("marshal A: %v", err)
	}
	jsonB, err := json.Marshal(cfgB)
	if err != nil {
		t.Fatalf("marshal B: %v", err)
	}
	if string(jsonA) != string(jsonB) {
		t.Fatal("fixture: renaming the unapplied group to node0 must leave node1's config JSON unchanged")
	}
	if reason := config.ZoneQuarantineExcludedReason("z214", cfgA); reason != "" {
		t.Fatalf("fixture: A must keep z214 live on node1, got %s", reason)
	}
	if config.ZoneQuarantineExcludedReason("z214", cfgB) == "" {
		t.Fatal("fixture: B must quarantine node1's z214 in favour of the peer's z174")
	}
	if routeOnlyPublishHybrid(compileWithGroup("unused"), cfgA) {
		t.Fatal("a distinct recompile of A was treated as a hybrid (false refusal)")
	}

	dir, err := os.MkdirTemp("", "x12247q")
	if err != nil {
		t.Fatalf("mkdtemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	controlSock := filepath.Join(dir, "control.sock")

	m := New()
	m.proc = &exec.Cmd{Process: &os.Process{Pid: os.Getpid()}}
	m.cfg.ControlSocket = controlSock
	m.generation = 5
	m.lastStatus.ConfigSnapshotProtocolVersion = ProtocolVersion
	m.lastSnapshot, err = buildSnapshotWithSchedulerState(
		cfgA, config.UserspaceConfig{ControlSocket: controlSock}, 5, 0,
		map[string]bool{"workhours": true}, nil, nil)
	if err != nil {
		t.Fatalf("build lastSnapshot: %v", err)
	}
	applied := m.lastSnapshot
	if !zonePublished12247(applied, "z214") || !schedPolicyPresent5328(applied.Policies, "z214-deny") {
		t.Fatal("precondition: applied A must install z214 together with its deny")
	}

	// One slot, so a regression ships its hybrid instead of failing to dial.
	reqs := startArmControlServer(t, controlSock, 1)
	if err := m.UpdatePolicyScheduleState(cfgB, map[string]bool{"workhours": false}); err == nil {
		shipped := "no snapshot captured"
		select {
		case req := <-reqs:
			if req.Snapshot != nil {
				shipped = fmt.Sprintf("z214 live=%v, z214-deny kept=%v",
					zonePublished12247(req.Snapshot, "z214"),
					schedPolicyPresent5328(req.Snapshot.Policies, "z214-deny"))
			}
		case <-time.After(10 * time.Second):
		}
		t.Fatalf("scheduler republish of B over applied A was accepted (%s): B's "+
			"quarantine scrubbed z214's deny while A's z214 stayed live (#6480)", shipped)
	} else if !strings.Contains(err.Error(), "refusing scheduled-policy republish") {
		t.Fatalf("scheduler republish error = %q, want the #6480 skew refusal", err)
	}
	published, err := m.PublishRouteOverlaySnapshot(cfgB, nil, nil)
	if published || err == nil || !strings.Contains(err.Error(), "refusing route-only publish") {
		t.Fatalf("route-only publish of B over applied A: published=%v err=%v, want the #5680 refusal",
			published, err)
	}
	if m.generation != 5 || m.lastSnapshot != applied {
		t.Fatalf("refused republishes advanced the manager: generation=%d, snapshot replaced=%v",
			m.generation, m.lastSnapshot != applied)
	}
	select {
	case req := <-reqs:
		t.Fatalf("a refused republish shipped a snapshot: %q", req.Type)
	case <-time.After(200 * time.Millisecond):
	}
}

func zonePublished12247(snap *ConfigSnapshot, name string) bool {
	return slices.ContainsFunc(snap.Zones, func(z ZoneSnapshot) bool { return z.Name == name })
}

func schedPolicyPresentInConfig12247(cfg *config.Config, toZone, name string) bool {
	for _, zpp := range cfg.Security.Policies {
		if zpp == nil || zpp.ToZone != toZone {
			continue
		}
		for _, p := range zpp.Policies {
			if p != nil && p.Name == name {
				return true
			}
		}
	}
	return false
}

// TestGroupOnlyZoneNameDoesNotQuarantineLiveZone12247 pins the runtime name
// set to the main/node0/node1 views. Each row pairs a live zone with a
// colliding name only a groups block declares — a group nothing applies, a
// `<*>` wildcard template, a group applied under another stanza. No node
// installs that name, so it must not quarantine the live zone on any compile
// path: the live zone keeps its interface and stays published.
//
// The strict gate still counts View 1's raw groups scan for concrete
// group-only names and keeps rejecting those configs. A wildcard template
// is the exception since #13113: `<*>` is a pattern, not an installed zone,
// so it claims no StableZoneID and strict commit accepts it (pinned by
// TestZoneIDCollisionIgnoresWildcardAndReserved13113). The wildcard row
// therefore asserts strict acceptance, not the pre-#13113 collision
// (#13361).
func TestGroupOnlyZoneNameDoesNotQuarantineLiveZone12247(t *testing.T) {
	const wildcardCollider = "z65162"
	if config.StableZoneID("<*>") != config.StableZoneID(wildcardCollider) {
		t.Fatalf("test premise broken: %q no longer folds to the id of `<*>`", wildcardCollider)
	}
	hermeticSnapshot12247(t)
	liveZone := func(name string) string {
		return "security { zones { security-zone " + name + ` { interfaces { ge-0/0/0.0; } } } }
interfaces { ge-0/0/0 { unit 0 { family inet { address 10.0.0.1/24; } } } }`
	}
	for _, tc := range []struct {
		name       string
		text       string
		live       string
		phantom    string
		strictColl bool
	}{
		{
			name:       "group nothing applies",
			text:       "groups { unused { security { zones { security-zone z174; } } } }\n" + liveZone("z214"),
			live:       "z214",
			phantom:    "z174",
			strictColl: true,
		},
		{
			name: "wildcard template",
			text: "groups { G { security { zones { security-zone <*> { tcp-rst; } } } } }\napply-groups G;\n" +
				liveZone(wildcardCollider),
			live:    wildcardCollider,
			phantom: "<*>",
		},
		{
			name:       "group applied under another stanza",
			text:       "groups { g1 { security { zones { security-zone z174; } } } }\nsystem { apply-groups g1; host-name p; }\n" + liveZone("z214"),
			live:       "z214",
			phantom:    "z174",
			strictColl: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree := parseTree12247(t, tc.text)
			_, strictErr := config.CompileConfig(tree)
			if tc.strictColl {
				if strictErr == nil || !strings.Contains(strictErr.Error(), "zone id collision") {
					t.Fatalf("strict compile error = %v, want the unchanged View-1 zone id collision", strictErr)
				}
			} else if strictErr != nil {
				t.Fatalf("strict compile error = %v, want acceptance of the wildcard template (#13113)", strictErr)
			}
			for _, nodeID := range []int{-1, 0, 1} {
				cfg := lenientCompile12247(t, tree, nodeID)
				if slices.Contains(cfg.ZoneQuarantineNames, tc.phantom) {
					t.Fatalf("node %d runtime names %v include group-only %q", nodeID, cfg.ZoneQuarantineNames, tc.phantom)
				}
				if !slices.Contains(cfg.ZoneQuarantineNames, tc.live) {
					t.Fatalf("node %d runtime names %v omit live %q", nodeID, cfg.ZoneQuarantineNames, tc.live)
				}
				if reason := config.ZoneQuarantineExcludedReason(tc.live, cfg); reason != "" {
					t.Fatalf("node %d quarantined live %q: %s", nodeID, tc.live, reason)
				}
				if got := buildInterfaceZoneMap(cfg)["ge-0/0/0.0"]; got != tc.live {
					t.Fatalf("node %d runtime zone of ge-0/0/0.0 = %q, want %q", nodeID, got, tc.live)
				}
				snap, err := buildSnapshot(cfg, config.UserspaceConfig{}, 0, 0)
				if err != nil {
					t.Fatalf("node %d snapshot build: %v", nodeID, err)
				}
				if len(snap.zoneIDCollisions) != 0 {
					t.Fatalf("node %d collision records = %+v, want none", nodeID, snap.zoneIDCollisions)
				}
				if !slices.ContainsFunc(snap.Zones, func(z ZoneSnapshot) bool { return z.Name == tc.live }) {
					t.Fatalf("node %d published zones %+v omit live %q", nodeID, snap.Zones, tc.live)
				}
			}
		})
	}
}

// TestGenericOnlyZoneNameDoesNotQuarantineOnClusterNodes12247 pins why the
// runtime name set counts the node0/node1 expansions but not the generic
// compile's: a group literally named "${node}" is applied only by the generic
// compile (no node variable), so its zone exists on no cluster node. The node
// compiles must not quarantine the live zone for it, while the generic compile,
// which installs both names, still quarantines its own collision.
func TestGenericOnlyZoneNameDoesNotQuarantineOnClusterNodes12247(t *testing.T) {
	tree := parseTree12247(t, `groups {
  "${node}" { security { zones { security-zone z174; } } }
  node0 { system { host-name n0; } }
  node1 { system { host-name n1; } }
}
apply-groups "${node}";
security { zones { security-zone z214; } }`)
	generic := lenientCompile12247(t, tree, -1)
	if generic.Security.Zones["z174"] == nil || config.ZoneQuarantineExcludedReason("z214", generic) == "" {
		t.Fatalf("generic compile: zones %v, want z174 installed and z214 quarantined by it", generic.Security.Zones)
	}
	for _, nodeID := range []int{0, 1} {
		cfg := lenientCompile12247(t, tree, nodeID)
		if cfg.Security.Zones["z174"] != nil || cfg.Security.Zones["z214"] == nil {
			t.Fatalf("node%d precondition: zones %v, want z214 without z174", nodeID, cfg.Security.Zones)
		}
		if slices.Contains(cfg.ZoneQuarantineNames, "z174") {
			t.Fatalf("node%d runtime names %v include generic-only z174", nodeID, cfg.ZoneQuarantineNames)
		}
		if reason := config.ZoneQuarantineExcludedReason("z214", cfg); reason != "" {
			t.Fatalf("node%d quarantined live z214 for a zone no cluster node installs: %s", nodeID, reason)
		}
	}
}
