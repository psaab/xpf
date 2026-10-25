package userspace

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
)

// stubRuleListHermetic makes buildRouteSnapshots hermetic by stubbing the
// netlink ip-rule enumerator (routes.go ruleListFn), which otherwise calls the
// real netlink.RuleList and fails "operation not permitted" in a restricted
// sandbox (both the seed full build and the route-overlay republish enumerate
// ip-rules). Restored on test cleanup.
func stubRuleListHermetic(t *testing.T) {
	t.Helper()
	orig := ruleListFn
	t.Cleanup(func() { ruleListFn = orig })
	ruleListFn = func(int) ([]netlink.Rule, error) { return nil, nil }
}

// schedPolicyInactive5328 returns the Inactive bit of the named policy rule in
// a published snapshot, failing the test if the rule is absent.
func schedPolicyInactive5328(t *testing.T, policies []PolicyRuleSnapshot, name string) bool {
	t.Helper()
	for _, p := range policies {
		if p.Name == name {
			return p.Inactive
		}
	}
	t.Fatalf("policy %q not found in published snapshot (%d policies)", name, len(policies))
	return false
}

// schedPolicyPresent5328 reports whether the named policy rule is present in a
// published snapshot (unlike schedPolicyInactive5328 it does not fail on
// absence), so a test can assert a rule was dropped.
func schedPolicyPresent5328(policies []PolicyRuleSnapshot, name string) bool {
	for _, p := range policies {
		if p.Name == name {
			return true
		}
	}
	return false
}

// collidingSchedCfg5328 builds a config whose zone-name set carries a verified
// StableZoneID collision (zzq17760/zzq8100, later-sorting zzq8100 quarantined) plus a
// non-colliding survivor zone "trust", with two scheduled zone-pair permits: one
// survivor (trust->zzq17760) and one whose to-zone is the quarantined zzq8100. A FULL
// build quarantines zzq8100 and DROPS the trust->zzq8100 permit; a partial republish
// that rebuilds policies from this cfg WITHOUT re-applying the quarantine would
// reintroduce the trust->zzq8100 permit as a dangling reference (#6480).
func collidingSchedCfg5328(t *testing.T) *config.Config {
	t.Helper()
	if config.StableZoneID("zzq17760") != config.StableZoneID("zzq8100") {
		t.Fatalf("test premise broken: zzq17760/zzq8100 no longer collide under the frozen fold")
	}
	mkPol := func(name string) *config.Policy {
		return &config.Policy{
			Name:          name,
			SchedulerName: "workhours",
			Match: config.PolicyMatch{
				SourceAddresses:      []string{"any"},
				DestinationAddresses: []string{"any"},
				Applications:         []string{"any"},
			},
			Action: config.PolicyPermit,
		}
	}
	cfg := &config.Config{}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust":    {Name: "trust"},
		"zzq17760": {Name: "zzq17760"},
		"zzq8100":  {Name: "zzq8100"},
	}
	cfg.Security.Policies = []*config.ZonePairPolicies{
		{FromZone: "trust", ToZone: "zzq17760", Policies: []*config.Policy{mkPol("survivor-allow")}},
		{FromZone: "trust", ToZone: "zzq8100", Policies: []*config.Policy{mkPol("dangling-allow")}},
	}
	cfg.Schedulers = map[string]*config.SchedulerConfig{"workhours": {Name: "workhours"}}
	return cfg
}

// assertNoDanglingZoneRef5328 fails if any policy in the snapshot references a
// security zone absent from the snapshot's own Zones — the exact condition the
// Rust UnresolvableZoneReference preflight rejects the whole snapshot on (#6480).
// "" and "junos-global" are structural sentinels, not zone references. It also
// asserts Summary.PolicyCount == len(Policies), the bookkeeping invariant the
// full build maintains after quarantine.
func assertNoDanglingZoneRef5328(t *testing.T, snap *ConfigSnapshot) {
	t.Helper()
	published := map[string]bool{}
	for _, z := range snap.Zones {
		published[z.Name] = true
	}
	for _, p := range snap.Policies {
		slots := append([]string{p.FromZone, p.ToZone, p.MatchFromZone, p.MatchToZone},
			append(append([]string{}, p.MatchFromZones...), p.MatchToZones...)...)
		for _, z := range slots {
			if z == "" || z == "junos-global" {
				continue
			}
			if !published[z] {
				t.Fatalf("published policy %q references zone %q absent from snapshot Zones "+
					"(%d policies, %d zones) — the Rust UnresolvableZoneReference preflight "+
					"would reject the WHOLE snapshot (#6480)", p.Name, z, len(snap.Policies), len(snap.Zones))
			}
		}
	}
	if snap.Summary.PolicyCount != len(snap.Policies) {
		t.Fatalf("Summary.PolicyCount = %d, want %d (== len(Policies)) (#6480)",
			snap.Summary.PolicyCount, len(snap.Policies))
	}
}

// TestPublishRouteOverlaySnapshotRefreshesSchedulerPolicyBits5328 pins the
// #5328 (A6-b2-F4) fix: a route-overlay publish that is handed a policy-
// scheduler active-state map MUST rebuild the published snapshot's policy
// inactive bits from that map in the SAME publish, not merely cache the map
// and inherit the last-compiled (stale) policy sections.
//
// The daemon's ip-monitoring actuator calls PublishRouteOverlaySnapshot with a
// live scheduler.ActiveState() (pkg/daemon/daemon_ipmon.go). Here the seeded
// lastSnapshot was compiled with the "workhours" scheduler ACTIVE, so its
// "scheduled-allow" permit is Inactive=false. We then publish a routes-only
// overlay carrying the CLOSED window (workhours:false). The published snapshot
// must show the permit as Inactive=true — otherwise the Rust helper keeps
// enforcing a permit whose schedule window already closed, while this publish
// reports success.
//
// FAIL-ON-REVERT: dropping the `if schedulerState != nil { ... rebuild ... }`
// block from PublishRouteOverlaySnapshot leaves next.Policies inherited from
// lastSnapshot (Inactive=false), so the captured published snapshot reports the
// permit ACTIVE and this test goes RED on the "Inactive=false" assertion.
func TestPublishRouteOverlaySnapshotRefreshesSchedulerPolicyBits5328(t *testing.T) {
	stubRuleListHermetic(t)
	// A SHORT temp-dir prefix (not t.TempDir(), whose long sub-test name would
	// push the AF_UNIX path past the 108-byte sun_path limit under a long
	// TMPDIR / GOTMPDIR=/dev/shm — "bind: invalid argument"). Run with
	// TMPDIR=/tmp if the default TMPDIR is long.
	dir, err := os.MkdirTemp("", "x5328")
	if err != nil {
		t.Fatalf("mkdtemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	controlSock := filepath.Join(dir, "control.sock")

	cfg := &config.Config{}
	cfg.Security.Policies = []*config.ZonePairPolicies{{
		FromZone: "trust",
		ToZone:   "untrust",
		Policies: []*config.Policy{{
			Name:          "scheduled-allow",
			SchedulerName: "workhours",
			Match: config.PolicyMatch{
				SourceAddresses:      []string{"any"},
				DestinationAddresses: []string{"any"},
				Applications:         []string{"any"},
			},
			Action: config.PolicyPermit,
		}},
	}}
	cfg.Schedulers = map[string]*config.SchedulerConfig{
		"workhours": {Name: "workhours"},
	}

	m := New()
	m.proc = &exec.Cmd{Process: &os.Process{Pid: os.Getpid()}}
	m.cfg.ControlSocket = controlSock
	m.generation = 5
	m.lastStatus.ConfigSnapshotProtocolVersion = ProtocolVersion

	// Seed lastSnapshot compiled with the scheduler window OPEN so the
	// permit is ACTIVE (Inactive=false). Reuse the SAME cfg pointer so the
	// #5680 route-only-hybrid guard's pointer fast path admits the publish.
	m.lastSnapshot, err = buildSnapshotWithSchedulerState(
		cfg, config.UserspaceConfig{ControlSocket: controlSock}, 5, 0,
		map[string]bool{"workhours": true}, nil, nil)
	if err != nil {
		t.Fatalf("build lastSnapshot: %v", err)
	}
	if schedPolicyInactive5328(t, m.lastSnapshot.Policies, "scheduled-allow") {
		t.Fatal("precondition: seeded lastSnapshot permit must be ACTIVE (Inactive=false)")
	}

	reqs := startArmControlServer(t, controlSock, 1)

	// Window CLOSED: publish a routes-only overlay carrying workhours:false.
	published, err := m.PublishRouteOverlaySnapshot(cfg, nil, map[string]bool{"workhours": false})
	if err != nil {
		t.Fatalf("PublishRouteOverlaySnapshot returned error: %v", err)
	}
	if !published {
		t.Fatal("expected a real publish (policy inactive bit changed), got duplicate-skip")
	}

	req := <-reqs
	if req.Snapshot == nil {
		t.Fatal("captured control request carried no snapshot")
	}
	if !schedPolicyInactive5328(t, req.Snapshot.Policies, "scheduled-allow") {
		t.Fatal("published snapshot reports the scheduled permit ACTIVE (Inactive=false): " +
			"the route-overlay publish did NOT refresh policy scheduler bits from schedulerState " +
			"(#5328 A6-b2-F4) — the helper would enforce a permit whose window already closed")
	}
}

// TestPublishRouteOverlaySnapshotSchedulerFlipDefeatsDuplicateSkip5328 pins the
// ORDERING half of the #5328 (A6-b2-F4) fix: the scheduler-state policy rebuild
// runs BEFORE the duplicate-publish content-hash skip, so a scheduler-only bit
// flip on UNCHANGED routes still publishes rather than being falsely deduped as
// "content unchanged".
//
// The seeded lastSnapshotHash equals the seeded snapshot's content hash and the
// overlay carries NO route change (nil), so the ONLY forwarding-content delta in
// this publish is the policy inactive bit. If the rebuild were placed AFTER the
// dedup check (line "Duplicate-publish skip" in manager_overlay.go), the
// routes-and-policies-still-unchanged snapshot would hash-match m.lastSnapshotHash
// and be skipped (published=false) — the helper would keep enforcing the stale
// OPEN-window permit while this publish silently reported nothing to do.
//
// FAIL-ON-REVERT / FAIL-ON-REORDER: neutralizing the rebuild block (or moving it
// below the content-hash skip) makes the publish hash-match the seed and return
// published=false, so the "expected a real publish" assertion goes RED.
func TestPublishRouteOverlaySnapshotSchedulerFlipDefeatsDuplicateSkip5328(t *testing.T) {
	stubRuleListHermetic(t)
	dir, err := os.MkdirTemp("", "x5328o")
	if err != nil {
		t.Fatalf("mkdtemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	controlSock := filepath.Join(dir, "control.sock")

	cfg := &config.Config{}
	cfg.Security.Policies = []*config.ZonePairPolicies{{
		FromZone: "trust",
		ToZone:   "untrust",
		Policies: []*config.Policy{{
			Name:          "scheduled-allow",
			SchedulerName: "workhours",
			Match: config.PolicyMatch{
				SourceAddresses:      []string{"any"},
				DestinationAddresses: []string{"any"},
				Applications:         []string{"any"},
			},
			Action: config.PolicyPermit,
		}},
	}}
	cfg.Schedulers = map[string]*config.SchedulerConfig{
		"workhours": {Name: "workhours"},
	}

	m := New()
	m.proc = &exec.Cmd{Process: &os.Process{Pid: os.Getpid()}}
	m.cfg.ControlSocket = controlSock
	m.generation = 5
	m.lastStatus.ConfigSnapshotProtocolVersion = ProtocolVersion

	// Seed lastSnapshot compiled with the window OPEN (permit ACTIVE).
	m.lastSnapshot, err = buildSnapshotWithSchedulerState(
		cfg, config.UserspaceConfig{ControlSocket: controlSock}, 5, 0,
		map[string]bool{"workhours": true}, nil, nil)
	if err != nil {
		t.Fatalf("build lastSnapshot: %v", err)
	}
	// Seed the dedup baseline to the seeded snapshot's content hash so an
	// unchanged-content publish WOULD be skipped — the discriminator that
	// forces the rebuild to run before the dedup check.
	h, ok := snapshotContentHash(m.lastSnapshot)
	if !ok {
		t.Fatal("seed snapshot content hash failed")
	}
	m.lastSnapshotHash = h

	reqs := startArmControlServer(t, controlSock, 1)

	// Window CLOSED, routes UNCHANGED (nil overlay): the only content delta
	// is the scheduled permit's inactive bit.
	published, err := m.PublishRouteOverlaySnapshot(cfg, nil, map[string]bool{"workhours": false})
	if err != nil {
		t.Fatalf("PublishRouteOverlaySnapshot returned error: %v", err)
	}
	if !published {
		t.Fatal("scheduler-only inactive-bit flip on unchanged routes was deduped away " +
			"(published=false): the schedulerState policy rebuild must run BEFORE the " +
			"duplicate-publish content-hash skip (#5328 A6-b2-F4) — otherwise the helper " +
			"keeps enforcing the stale open-window permit")
	}

	req := <-reqs
	if req.Snapshot == nil {
		t.Fatal("captured control request carried no snapshot")
	}
	if !schedPolicyInactive5328(t, req.Snapshot.Policies, "scheduled-allow") {
		t.Fatal("published snapshot still reports the scheduled permit ACTIVE (Inactive=false) " +
			"after a closed-window scheduler flip (#5328 A6-b2-F4)")
	}
}

// TestPublishRouteOverlaySnapshotReappliesZoneQuarantine6480 pins the #6480
// hostile-review MAJOR: the route-overlay publish rebuilds next.Policies from raw
// cfg under the scheduler map but inherits the already-reduced next.Zones (the
// full build quarantined the later-sorting colliding zone). Without re-applying
// the StableZoneID quarantine the rebuild reintroduces the trust->zzq8100 permit,
// which references the quarantined zone zzq8100 absent from next.Zones — a dangling
// reference the Rust UnresolvableZoneReference preflight rejects wholesale. On the
// supported ip-monitoring path FRR is updated BEFORE this publish
// (daemon_ipmon.go), so the reject strands the kernel/FRR on new routes while
// userspace keeps the old FIB, unable to converge.
//
// FAIL-ON-REVERT: dropping the scrubPoliciesForQuarantinedZones re-application
// from rebuildScheduledPolicySectionsLocked leaves the trust->zzq8100 permit in the
// published snapshot, so assertNoDanglingZoneRef5328 goes RED (clean assertion).
func TestPublishRouteOverlaySnapshotReappliesZoneQuarantine6480(t *testing.T) {
	stubRuleListHermetic(t)
	dir, err := os.MkdirTemp("", "x6480")
	if err != nil {
		t.Fatalf("mkdtemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	controlSock := filepath.Join(dir, "control.sock")

	cfg := collidingSchedCfg5328(t)

	m := New()
	m.proc = &exec.Cmd{Process: &os.Process{Pid: os.Getpid()}}
	m.cfg.ControlSocket = controlSock
	m.generation = 5
	m.lastStatus.ConfigSnapshotProtocolVersion = ProtocolVersion

	// Seed lastSnapshot via the FULL build with the scheduler ACTIVE: the full
	// build quarantines zzq8100 and drops the trust->zzq8100 permit, so the seed carries
	// the reduced Zones {trust, zzq17760} and only the survivor permit. Reuse the SAME
	// cfg pointer so the #5680 route-only-hybrid guard's pointer fast path admits
	// the publish.
	m.lastSnapshot, err = buildSnapshotWithSchedulerState(
		cfg, config.UserspaceConfig{ControlSocket: controlSock}, 5, 0,
		map[string]bool{"workhours": true}, nil, nil)
	if err != nil {
		t.Fatalf("build lastSnapshot: %v", err)
	}
	// Precondition: the seed is already quarantined (zzq8100 gone, dangling permit gone).
	assertNoDanglingZoneRef5328(t, m.lastSnapshot)
	if len(m.lastSnapshot.zoneIDCollisions) != 1 {
		t.Fatalf("seed must record the zzq17760/zzq8100 collision, got %v", m.lastSnapshot.zoneIDCollisions)
	}
	if schedPolicyPresent5328(m.lastSnapshot.Policies, "dangling-allow") {
		t.Fatal("precondition: full-build seed must have dropped the trust->zzq8100 permit")
	}

	reqs := startArmControlServer(t, controlSock, 1)

	// Route-overlay publish carrying the scheduler map: the rebuild reintroduces
	// the trust->zzq8100 permit from raw cfg and MUST re-quarantine it.
	published, err := m.PublishRouteOverlaySnapshot(cfg, nil, map[string]bool{"workhours": true})
	if err != nil {
		t.Fatalf("PublishRouteOverlaySnapshot returned error: %v", err)
	}
	if !published {
		t.Fatal("expected a real publish")
	}

	req := <-reqs
	if req.Snapshot == nil {
		t.Fatal("captured control request carried no snapshot")
	}
	assertNoDanglingZoneRef5328(t, req.Snapshot)
	// The survivor permit must remain (the scrub must not over-drop).
	if !schedPolicyPresent5328(req.Snapshot.Policies, "survivor-allow") {
		t.Fatal("survivor permit trust->zzq17760 was wrongly dropped by the re-quarantine")
	}
	// The dangling permit must be gone.
	if schedPolicyPresent5328(req.Snapshot.Policies, "dangling-allow") {
		t.Fatal("dangling permit trust->zzq8100 survived the re-quarantine (references quarantined zzq8100) (#6480)")
	}
}

// TestUpdatePolicyScheduleStateReappliesZoneQuarantine6480 is the mirror of the
// route-overlay test for the canonical scheduler-only republish path. It shares
// the SAME latent #6480 defect — UpdatePolicyScheduleState rebuilds next.Policies
// from raw cfg while inheriting the reduced next.Zones — and the SAME shared
// rebuildScheduledPolicySectionsLocked re-quarantine fixes both paths in lockstep.
func TestUpdatePolicyScheduleStateReappliesZoneQuarantine6480(t *testing.T) {
	stubRuleListHermetic(t)
	dir, err := os.MkdirTemp("", "x6480u")
	if err != nil {
		t.Fatalf("mkdtemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	controlSock := filepath.Join(dir, "control.sock")

	cfg := collidingSchedCfg5328(t)

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
	assertNoDanglingZoneRef5328(t, m.lastSnapshot)

	reqs := startArmControlServer(t, controlSock, 1)

	// A CLOSED-window scheduler republish: rebuilds policies from raw cfg (which
	// reintroduces the trust->zzq8100 permit) and MUST re-quarantine it.
	if err := m.UpdatePolicyScheduleState(cfg, map[string]bool{"workhours": false}); err != nil {
		t.Fatalf("UpdatePolicyScheduleState returned error: %v", err)
	}

	req := <-reqs
	if req.Snapshot == nil {
		t.Fatal("captured control request carried no snapshot")
	}
	assertNoDanglingZoneRef5328(t, req.Snapshot)
	if !schedPolicyPresent5328(req.Snapshot.Policies, "survivor-allow") {
		t.Fatal("survivor permit trust->zzq17760 was wrongly dropped by the re-quarantine")
	}
	if schedPolicyPresent5328(req.Snapshot.Policies, "dangling-allow") {
		t.Fatal("dangling permit trust->zzq8100 survived the re-quarantine (references quarantined zzq8100) (#6480)")
	}
}

// TestPublishRouteOverlaySnapshotReadsFreshSchedulerStateNotStale5328 strengthens
// the freshness coverage (Codex nit): the existing OPEN->CLOSED tests seed
// m.policySchedulerActive nil, and since a nil/absent scheduler read is
// fail-closed (Inactive=true) a rebuild that IGNORED the passed schedulerState
// would still land on Inactive=true and pass. This drives the CLOSED->OPEN
// direction with the cache PRE-SEEDED to the STALE closed state, so only a rebuild
// that reads the FRESH open state can make the permit ACTIVE (Inactive=false).
//
// FAIL-ON-REVERT: neutralizing the rebuild (or the schedulerState cache update
// before it) leaves the inherited/stale CLOSED bit (Inactive=true), so the
// "Inactive=false" assertion goes RED — binding that the publish uses the
// freshly-passed {workhours:true}, not a stale cache.
func TestPublishRouteOverlaySnapshotReadsFreshSchedulerStateNotStale5328(t *testing.T) {
	stubRuleListHermetic(t)
	dir, err := os.MkdirTemp("", "x5328f")
	if err != nil {
		t.Fatalf("mkdtemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	controlSock := filepath.Join(dir, "control.sock")

	cfg := &config.Config{}
	cfg.Security.Policies = []*config.ZonePairPolicies{{
		FromZone: "trust",
		ToZone:   "untrust",
		Policies: []*config.Policy{{
			Name:          "scheduled-allow",
			SchedulerName: "workhours",
			Match: config.PolicyMatch{
				SourceAddresses:      []string{"any"},
				DestinationAddresses: []string{"any"},
				Applications:         []string{"any"},
			},
			Action: config.PolicyPermit,
		}},
	}}
	cfg.Schedulers = map[string]*config.SchedulerConfig{"workhours": {Name: "workhours"}}

	m := New()
	m.proc = &exec.Cmd{Process: &os.Process{Pid: os.Getpid()}}
	m.cfg.ControlSocket = controlSock
	m.generation = 5
	m.lastStatus.ConfigSnapshotProtocolVersion = ProtocolVersion

	// Seed lastSnapshot with the window CLOSED so the permit is INACTIVE.
	m.lastSnapshot, err = buildSnapshotWithSchedulerState(
		cfg, config.UserspaceConfig{ControlSocket: controlSock}, 5, 0,
		map[string]bool{"workhours": false}, nil, nil)
	if err != nil {
		t.Fatalf("build lastSnapshot: %v", err)
	}
	if !schedPolicyInactive5328(t, m.lastSnapshot.Policies, "scheduled-allow") {
		t.Fatal("precondition: seeded permit must be INACTIVE (window CLOSED)")
	}
	// Pre-seed the scheduler cache to the STALE closed state: a rebuild that fails
	// to read the freshly-passed OPEN map would keep the permit INACTIVE.
	m.policySchedulerActive = map[string]bool{"workhours": false}

	reqs := startArmControlServer(t, controlSock, 1)

	// Publish the OPEN window: only a rebuild reading the FRESH map makes it ACTIVE.
	published, err := m.PublishRouteOverlaySnapshot(cfg, nil, map[string]bool{"workhours": true})
	if err != nil {
		t.Fatalf("PublishRouteOverlaySnapshot returned error: %v", err)
	}
	if !published {
		t.Fatal("expected a real publish (permit inactive bit changed CLOSED->OPEN)")
	}

	req := <-reqs
	if req.Snapshot == nil {
		t.Fatal("captured control request carried no snapshot")
	}
	if schedPolicyInactive5328(t, req.Snapshot.Policies, "scheduled-allow") {
		t.Fatal("published permit still INACTIVE after a fresh OPEN-window publish: the " +
			"route-overlay rebuild read a STALE scheduler state instead of the freshly-passed " +
			"{workhours:true} (#5328 A6-b2-F4 / #6480)")
	}
}

// skewCfgA6480 builds config A: zones {trust, zzq8100} with NO StableZoneID
// collision (zzq8100 alone folds to nothing else here), so a FULL build keeps zzq8100
// a live zone and keeps the scheduled trust->zzq8100 DENY. This is the applied /
// inherited config a scheduler republish copies its Zones/Interfaces from.
func skewCfgA6480(t *testing.T) *config.Config {
	t.Helper()
	cfg := &config.Config{}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust":   {Name: "trust"},
		"zzq8100": {Name: "zzq8100"},
	}
	cfg.Security.Policies = []*config.ZonePairPolicies{
		{FromZone: "trust", ToZone: "zzq8100", Policies: []*config.Policy{{
			Name:          "trust-zzq8100-deny",
			SchedulerName: "workhours",
			Match: config.PolicyMatch{
				SourceAddresses:      []string{"any"},
				DestinationAddresses: []string{"any"},
				Applications:         []string{"any"},
			},
			Action: config.PolicyDeny,
		}}},
	}
	cfg.Schedulers = map[string]*config.SchedulerConfig{"workhours": {Name: "workhours"}}
	return cfg
}

// skewCfgB6480 builds config B: config A PLUS the colliding zone zzq17760. Under B,
// zzq17760/zzq8100 fold to the SAME StableZoneID and the later-sorting zzq8100 is
// quarantined, so B's quarantine set is {zzq8100} while A's is empty. B carries the
// same scheduled trust->zzq8100 deny; a full Compile of B would drop zzq8100 from Zones
// AND drop the deny (fail-closed). B content-differs from A only by the added
// zone, so relative to a snapshot built from A it is a genuine config-generation
// skew.
func skewCfgB6480(t *testing.T) *config.Config {
	t.Helper()
	if config.StableZoneID("zzq17760") != config.StableZoneID("zzq8100") {
		t.Fatalf("test premise broken: zzq17760/zzq8100 no longer collide under the frozen fold")
	}
	cfg := skewCfgA6480(t)
	cfg.Security.Zones["zzq17760"] = &config.ZoneConfig{Name: "zzq17760"}
	return cfg
}

// TestUpdatePolicyScheduleStateRefusesConfigSkew6480 pins the fold-introduced
// fail-open the #6480 round-2 fix opened on the scheduler-only republish path and
// this fold closes. rebuildScheduledPolicySectionsLocked rebuilds+scrubs policies
// against the PASSED cfg while inheriting next.Zones/next.Interfaces from
// m.lastSnapshot. During a config-skew window the daemon reconciles the scheduler
// to store.ActiveConfig() (the NEWLY promoted config B) while a transient apply
// failure left the OLD snapshot (config A) live: the store promotes B before
// applying (store_commit.go), and daemon_apply_dataplane.go continues on a
// dataplane apply error yet still reconciles the scheduler to B.
//
// A has zones {trust, zzq8100} (no collision) with a live scheduled trust->zzq8100
// DENY; B adds colliding zzq17760 so B's quarantine set is {zzq8100}. WITHOUT the guard
// the scheduler tick copies A's Zones {trust, zzq8100} but scrubs the rebuilt
// policies with B's {zzq8100} quarantine, DROPPING the trust->zzq8100 deny while zzq8100
// stays a live zone in next.Zones — the Rust preflight accepts the snapshot and
// traffic to zzq8100 falls through to the inherited default PERMIT (fail-OPEN). A
// full Compile of B would instead drop zzq8100 from Zones + unzone its iface
// (fail-closed). The route-overlay path already refuses this skew
// (routeOnlyPublishHybrid, #5680); this fold mirrors that refusal inside the
// shared rebuildScheduledPolicySectionsLocked so BOTH partial-republish paths are
// safe.
//
// FAIL-ON-REVERT (clean assertion): removing the routeOnlyPublishHybrid skew
// guard from rebuildScheduledPolicySectionsLocked lets the skew republish SUCCEED
// — UpdatePolicyScheduleState returns nil, bumps m.generation to 6, and advances
// m.lastSnapshot.Config to cfgB while shipping the fail-open snapshot — so the
// phase-(a) err / generation / lastSnapshot assertions go RED. The same-config
// phase (b) proves the guard does not over-refuse the common (pointer-identical)
// path and still refreshes scheduler bits.
func TestUpdatePolicyScheduleStateRefusesConfigSkew6480(t *testing.T) {
	stubRuleListHermetic(t)
	dir, err := os.MkdirTemp("", "x6480skew")
	if err != nil {
		t.Fatalf("mkdtemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	controlSock := filepath.Join(dir, "control.sock")

	cfgA := skewCfgA6480(t)
	cfgB := skewCfgB6480(t)

	m := New()
	m.proc = &exec.Cmd{Process: &os.Process{Pid: os.Getpid()}}
	m.cfg.ControlSocket = controlSock
	m.generation = 5
	m.lastStatus.ConfigSnapshotProtocolVersion = ProtocolVersion

	// Seed lastSnapshot from config A with the window OPEN: A has no collision, so
	// zzq8100 is a live zone and the trust->zzq8100 deny is present + ACTIVE. The builder
	// stamps snapshot.Config = cfgA (pointer), which the same-config phase relies on.
	m.lastSnapshot, err = buildSnapshotWithSchedulerState(
		cfgA, config.UserspaceConfig{ControlSocket: controlSock}, 5, 0,
		map[string]bool{"workhours": true}, nil, nil)
	if err != nil {
		t.Fatalf("build lastSnapshot: %v", err)
	}
	if m.lastSnapshot.Config != cfgA {
		t.Fatal("precondition: seeded snapshot must carry cfgA by pointer")
	}
	assertNoDanglingZoneRef5328(t, m.lastSnapshot)
	if !schedPolicyPresent5328(m.lastSnapshot.Policies, "trust-zzq8100-deny") {
		t.Fatal("precondition: config-A seed must keep the trust->zzq8100 deny (zzq8100 not quarantined)")
	}
	// zzq8100 must be a LIVE zone in the seed — the fail-open hinges on it surviving
	// in the inherited next.Zones while B's quarantine would drop the deny.
	zzq8100Live := false
	for _, z := range m.lastSnapshot.Zones {
		if z.Name == "zzq8100" {
			zzq8100Live = true
		}
	}
	if !zzq8100Live {
		t.Fatal("precondition: zzq8100 must be a live zone in the config-A seed")
	}

	// Arm the control server for exactly ONE publish — the same-config phase (b).
	// The skew phase (a) must ship NOTHING (the guard refuses before any
	// apply_snapshot); on revert it WOULD ship the fail-open snapshot and consume
	// this slot, but the phase-(a) assertions fail first.
	reqs := startArmControlServer(t, controlSock, 1)

	// Phase (a): SKEW — call with cfgB (quarantines zzq8100, a zone A still has live).
	// The guard must REFUSE and retain the prior snapshot.
	skewErr := m.UpdatePolicyScheduleState(cfgB, map[string]bool{"workhours": false})
	if skewErr == nil {
		t.Fatal("UpdatePolicyScheduleState accepted a config-skew republish: the rebuilt " +
			"policies were scrubbed with cfgB's quarantine {zzq8100} against cfgA's inherited " +
			"Zones (zzq8100 live), shipping a fail-open snapshot (#6480)")
	}
	if !strings.Contains(skewErr.Error(), "refusing scheduled-policy republish") {
		t.Fatalf("skew refusal error = %q, want the #6480 scheduled-policy skew guard", skewErr)
	}
	// Prior snapshot retained (fail-closed): generation not advanced, lastSnapshot
	// still config A. On revert both flip (generation->6, Config->cfgB).
	if m.generation != 5 {
		t.Fatalf("generation advanced to %d on a refused skew republish (want 5): a fail-open "+
			"snapshot was published (#6480)", m.generation)
	}
	if m.lastSnapshot == nil || m.lastSnapshot.Config != cfgA {
		t.Fatal("refused skew republish advanced lastSnapshot past the applied config A (#6480)")
	}

	// Phase (b): SAME CONFIG — call with cfgA (pointer-identical to the applied
	// snapshot's config), window CLOSED. The guard's pointer fast path admits it;
	// the republish must succeed and refresh the scheduler bits.
	if err := m.UpdatePolicyScheduleState(cfgA, map[string]bool{"workhours": false}); err != nil {
		t.Fatalf("same-config scheduler republish was wrongly refused: %v", err)
	}
	req := <-reqs
	if req.Snapshot == nil {
		t.Fatal("same-config republish shipped no snapshot")
	}
	assertNoDanglingZoneRef5328(t, req.Snapshot)
	if !schedPolicyPresent5328(req.Snapshot.Policies, "trust-zzq8100-deny") {
		t.Fatal("same-config republish dropped the trust->zzq8100 deny (A has no quarantine)")
	}
	// Scheduler bits refreshed: the CLOSED window must render the deny INACTIVE.
	if !schedPolicyInactive5328(t, req.Snapshot.Policies, "trust-zzq8100-deny") {
		t.Fatal("same-config republish did not refresh scheduler bits: the CLOSED-window deny " +
			"is still ACTIVE (Inactive=false) (#6480 phase-b regression guard)")
	}
}
