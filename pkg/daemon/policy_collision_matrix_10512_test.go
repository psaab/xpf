package daemon

import (
	"context"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	dpruntime "github.com/psaab/xpf/pkg/dataplane/runtime"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// collisionDP10512 is the #10512 T-matrix fake: a per-domain session table
// where both tenants of a colliding bare tuple coexist (A under 100007, B
// under 100008), a scripted helper READ (ListSessionsByPolicy filters by
// the requested policy ids + families, records the mode that drove it),
// and a recording helper delete (DeletePolicySessions removes + records).
// It models the helper authority, not the bare-keyed BPF mirror — a
// mirror scan could hold only ONE row per tuple and could never express
// the collision these cells pin.
type collisionDP10512 struct {
	dataplane.DataPlane // embedded nil — only the overridden methods are called

	matches []dpuserspace.SessionPolicyMatch
	deleted []dpuserspace.SessionPolicyMatch
	modes   []string

	complete  bool
	readErr   error
	delErr    error
	incomple  bool
	workerErr string
}

func newCollisionDP10512(matches []dpuserspace.SessionPolicyMatch) *collisionDP10512 {
	return &collisionDP10512{matches: matches, complete: true}
}

func (f *collisionDP10512) Start(context.Context) error { return nil }
func (f *collisionDP10512) Close() error                { return nil }
func (f *collisionDP10512) Teardown() error             { return nil }
func (f *collisionDP10512) ApplyConfig(context.Context, *config.Config) (*dataplane.ApplyResult, error) {
	return &dataplane.ApplyResult{}, nil
}
func (f *collisionDP10512) LastApplyResult() *dataplane.ApplyResult { return &dataplane.ApplyResult{} }
func (f *collisionDP10512) Link() dataplane.LinkController          { return noopLinkController{} }
func (f *collisionDP10512) HA() dataplane.HAController {
	return dataplane.NewDataPlaneHAController(nil)
}
func (f *collisionDP10512) Sessions() dataplane.SessionStore { return nil }
func (f *collisionDP10512) Telemetry() dataplane.Telemetry {
	return dataplane.TelemetryOf(nil)
}
func (f *collisionDP10512) SessionDeltas() dpruntime.SessionDeltaSource { return nil }
func (f *collisionDP10512) GetPersistentNAT() *dataplane.PersistentNATTable {
	return nil
}

// ListSessionsByPolicy serves the helper READ from the per-domain table:
// only matches whose policy is requested AND whose family is allowed are
// returned. The driving mode (prepublish vs legacy) is recorded so cells
// can pin which producer ran.
func (f *collisionDP10512) ListSessionsByPolicy(req dpuserspace.SessionPolicyListRequest) (dpuserspace.ControlResponse, error) {
	f.modes = append(f.modes, req.Mode)
	if f.readErr != nil {
		return dpuserspace.ControlResponse{}, f.readErr
	}
	want := make(map[uint32]bool, len(req.PolicyIDs))
	for _, id := range req.PolicyIDs {
		want[id] = true
	}
	famOK := func(fam uint8) bool {
		if len(req.Families) == 0 {
			return true
		}
		for _, c := range req.Families {
			if c == fam {
				return true
			}
		}
		return false
	}
	var out []dpuserspace.SessionPolicyMatch
	for _, m := range f.matches {
		if !want[m.PolicyID] || !famOK(m.AddrFamily) {
			continue
		}
		out = append(out, m)
	}
	resp := dpuserspace.ControlResponse{
		SessionPolicyMatches:  out,
		SessionPolicyComplete: f.complete && !f.incomple,
	}
	if f.incomple {
		resp.SessionPolicyPerWorkerErrors = []string{f.workerErr}
	}
	return resp, nil
}

// DeletePolicySessions removes the named matches from the per-domain table
// and records them. Deletion is by (domain, tuple, identity) — never by
// bare tuple — so deleting A cannot disturb colliding B.
func (f *collisionDP10512) DeletePolicySessions(matches []dpuserspace.SessionPolicyMatch) (dpuserspace.PolicyDeleteResult, error) {
	if f.delErr != nil {
		return dpuserspace.PolicyDeleteResult{}, f.delErr
	}
	applied := 0
	for _, m := range matches {
		for i, live := range f.matches {
			if live.RoutingDomain == m.RoutingDomain &&
				live.Tuple == m.Tuple &&
				live.ExpectedRTFlowSessionID == m.ExpectedRTFlowSessionID {
				f.matches = append(f.matches[:i], f.matches[i+1:]...)
				applied++
				break
			}
		}
		f.deleted = append(f.deleted, m)
	}
	return dpuserspace.PolicyDeleteResult{Applied: applied}, nil
}

func (f *collisionDP10512) liveIn(domain uint32) int {
	n := 0
	for _, m := range f.matches {
		if m.RoutingDomain == domain {
			n++
		}
	}
	return n
}

// collisionMatches10512 builds the colliding tenants: A (the deleted
// policy's session) + B (a surviving policy's session) on the SAME bare
// tuple, v4 + v6, distinguished only by domain + identity.
func collisionMatches10512(webID, sshID uint32) []dpuserspace.SessionPolicyMatch {
	v4tuple := dpuserspace.SessionPolicyTuple{
		AddrFamily: 4, Protocol: 6,
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 40001, DstPort: 80,
	}
	v6tuple := dpuserspace.SessionPolicyTuple{
		AddrFamily: 6, Protocol: 6,
		SrcIP: "2001:db8::1", DstIP: "2001:db8::2",
		SrcPort: 40003, DstPort: 80,
	}
	mk := func(fam uint8, tuple dpuserspace.SessionPolicyTuple, domain uint32, policy uint32, id uint64) dpuserspace.SessionPolicyMatch {
		return dpuserspace.SessionPolicyMatch{
			AddrFamily: fam, RoutingDomain: domain, Tuple: tuple,
			PolicyID: policy, ExpectedRTFlowSessionID: id,
		}
	}
	return []dpuserspace.SessionPolicyMatch{
		mk(4, v4tuple, 100007, webID, 0xA11CE),
		mk(4, v4tuple, 100008, sshID, 0xB10512),
		mk(6, v6tuple, 100007, webID, 0xA11CE6),
		mk(6, v6tuple, 100008, sshID, 0xB105126),
	}
}

// driveCapture10512 runs the CAPTURE producer: arm the plan, take the
// pre-publication READ, then clear from the capture.
func driveCapture10512(d *Daemon, oldCfg, newCfg *config.Config) error {
	d.policyInvalidationPlan = &policyInvalidationPlan{oldCfg: oldCfg, newCfg: newCfg}
	d.capturePolicyInvalidationLocked(newCfg)
	return d.clearSessionsForDeletedPolicies(oldCfg, newCfg)
}

// T1 deleted/v4/capture: deleting A's policy reaps A's v4 row; B's v4 row
// on the same tuple survives. On base (PolicyID-only mirror scan) A
// survives behind B's row and the commit reports nil.
func TestT1DeletedV4CaptureReapsOnlyA10512(t *testing.T) {
	oldCfg := twoPolicyConfig([]string{"p-first", "p-web", "p-ssh"}, nil)
	newCfg := twoPolicyConfig([]string{"p-first", "p-ssh"}, nil)
	ids := dpuserspace.PolicyIDsByStableKey(oldCfg)
	fake := newCollisionDP10512(collisionMatches10512(ids["trust->untrust/p-web"], ids["trust->untrust/p-ssh"]))
	d := &Daemon{}
	d.setDataplane(fake)

	if err := driveCapture10512(d, oldCfg, newCfg); err != nil {
		t.Fatalf("capture clear: %v", err)
	}
	if len(fake.modes) != 1 || fake.modes[0] != "prepublish" {
		t.Fatalf("modes = %v, want [prepublish] (the capture producer)", fake.modes)
	}
	for _, m := range fake.deleted {
		if m.RoutingDomain != 100007 {
			t.Errorf("deleted a domain-%d row; only A's (100007) may go", m.RoutingDomain)
		}
		if m.PolicyID != ids["trust->untrust/p-web"] {
			t.Errorf("deleted policy %d; only p-web (%d) may go", m.PolicyID, ids["trust->untrust/p-web"])
		}
	}
	if got := fake.liveIn(100008); got != 2 {
		t.Errorf("B holds %d live rows, want 2 (v4+v6 untouched)", got)
	}
	v4gone := true
	for _, m := range fake.matches {
		if m.RoutingDomain == 100007 && m.AddrFamily == 4 {
			v4gone = false
		}
	}
	if !v4gone {
		t.Error("A's v4 row survives the capture clear — the #10512 miss")
	}
}

// T2 deleted/v6/capture: the v6 twin of T1.
func TestT2DeletedV6CaptureReapsOnlyA10512(t *testing.T) {
	oldCfg := twoPolicyConfig([]string{"p-first", "p-web", "p-ssh"}, nil)
	newCfg := twoPolicyConfig([]string{"p-first", "p-ssh"}, nil)
	ids := dpuserspace.PolicyIDsByStableKey(oldCfg)
	fake := newCollisionDP10512(collisionMatches10512(ids["trust->untrust/p-web"], ids["trust->untrust/p-ssh"]))
	d := &Daemon{}
	d.setDataplane(fake)

	if err := driveCapture10512(d, oldCfg, newCfg); err != nil {
		t.Fatalf("capture clear: %v", err)
	}
	v6gone := true
	for _, m := range fake.matches {
		if m.RoutingDomain == 100007 && m.AddrFamily == 6 {
			v6gone = false
		}
	}
	if !v6gone {
		t.Error("A's v6 row survives the capture clear — the #10512 miss")
	}
	if got := fake.liveIn(100008); got != 2 {
		t.Errorf("B holds %d live rows, want 2 (v4+v6 untouched)", got)
	}
}

// T3 deleted/v4/legacy: the legacy producer reaps A's v4 row through the
// legacy-mode READ; B survives. The legacy READ carries before_secs and
// the same identity-conditional delete.
func TestT3DeletedV4LegacyReapsOnlyA10512(t *testing.T) {
	oldCfg := twoPolicyConfig([]string{"p-first", "p-web", "p-ssh"}, nil)
	newCfg := twoPolicyConfig([]string{"p-first", "p-ssh"}, nil)
	ids := dpuserspace.PolicyIDsByStableKey(oldCfg)
	fake := newCollisionDP10512(collisionMatches10512(ids["trust->untrust/p-web"], ids["trust->untrust/p-ssh"]))
	d := &Daemon{}
	d.setDataplane(fake)
	d.policyInvalidationCapture = nil // force the legacy producer

	if err := d.clearSessionsForDeletedPolicies(oldCfg, newCfg); err != nil {
		t.Fatalf("legacy clear: %v", err)
	}
	if len(fake.modes) != 1 || fake.modes[0] != "legacy" {
		t.Fatalf("modes = %v, want [legacy] (the legacy producer)", fake.modes)
	}
	v4gone := true
	for _, m := range fake.matches {
		if m.RoutingDomain == 100007 && m.AddrFamily == 4 {
			v4gone = false
		}
	}
	if !v4gone {
		t.Error("A's v4 row survives the legacy clear — the #10512 miss")
	}
	if got := fake.liveIn(100008); got != 2 {
		t.Errorf("B holds %d live rows, want 2 (v4+v6 untouched)", got)
	}
}

// T4 deleted/v6/legacy: the v6 twin of T3.
func TestT4DeletedV6LegacyReapsOnlyA10512(t *testing.T) {
	oldCfg := twoPolicyConfig([]string{"p-first", "p-web", "p-ssh"}, nil)
	newCfg := twoPolicyConfig([]string{"p-first", "p-ssh"}, nil)
	ids := dpuserspace.PolicyIDsByStableKey(oldCfg)
	fake := newCollisionDP10512(collisionMatches10512(ids["trust->untrust/p-web"], ids["trust->untrust/p-ssh"]))
	d := &Daemon{}
	d.setDataplane(fake)
	d.policyInvalidationCapture = nil

	if err := d.clearSessionsForDeletedPolicies(oldCfg, newCfg); err != nil {
		t.Fatalf("legacy clear: %v", err)
	}
	v6gone := true
	for _, m := range fake.matches {
		if m.RoutingDomain == 100007 && m.AddrFamily == 6 {
			v6gone = false
		}
	}
	if !v6gone {
		t.Error("A's v6 row survives the legacy clear — the #10512 miss")
	}
	if got := fake.liveIn(100008); got != 2 {
		t.Errorf("B holds %d live rows, want 2 (v4+v6 untouched)", got)
	}
}

// Protocol-state contrast: complete+empty is an authoritative empty (nil),
// incomplete joins clearErr, and a nil capture selects the legacy producer.
// The three states must stay distinct — an authoritative empty is never
// manufactured from a missing or incomplete capture.
func TestProtocolContrastEmptyIncompleteMissing10512(t *testing.T) {
	oldCfg := twoPolicyConfig([]string{"p-first", "p-web", "p-ssh"}, nil)
	newCfg := twoPolicyConfig([]string{"p-first", "p-ssh"}, nil)
	ids := dpuserspace.PolicyIDsByStableKey(oldCfg)

	// Complete + zero matches: nil, no delete attempted.
	fake := newCollisionDP10512(nil)
	d := &Daemon{}
	d.setDataplane(fake)
	if err := driveCapture10512(d, oldCfg, newCfg); err != nil {
		t.Fatalf("authoritative empty must return nil, got %v", err)
	}
	if len(fake.deleted) != 0 {
		t.Fatalf("authoritative empty deleted %d rows, want 0", len(fake.deleted))
	}

	// Incomplete: clearErr surfaces, no success.
	fake2 := newCollisionDP10512(collisionMatches10512(ids["trust->untrust/p-web"], ids["trust->untrust/p-ssh"]))
	fake2.incomple = true
	fake2.workerErr = "worker-3:queue-full"
	d2 := &Daemon{}
	d2.setDataplane(fake2)
	if err := driveCapture10512(d2, oldCfg, newCfg); err == nil {
		t.Fatal("incomplete capture must surface clearErr, got nil")
	}

	// Nil capture selects the legacy producer (mode pin).
	fake3 := newCollisionDP10512(nil)
	d3 := &Daemon{}
	d3.setDataplane(fake3)
	d3.policyInvalidationCapture = nil
	if err := d3.clearSessionsForDeletedPolicies(oldCfg, newCfg); err != nil {
		t.Fatalf("legacy empty must return nil, got %v", err)
	}
	if len(fake3.modes) != 1 || fake3.modes[0] != "legacy" {
		t.Fatalf("modes = %v, want [legacy] (nil capture selects legacy)", fake3.modes)
	}
}

// T5 modified/v4+v6/capture+legacy: p-ssh's action changes with
// policy-rematch set → ssh sessions reaped in both producers, colliding
// web sessions untouched. Same shadow as deleted: all three classes
// share the predicate.
func TestT5ModifiedActionChangeReapsOnlyChanged10512(t *testing.T) {
	for _, producer := range []string{"capture", "legacy"} {
		t.Run(producer, func(t *testing.T) {
			oldCfg := twoPolicyConfig([]string{"p-first", "p-web", "p-ssh"}, nil)
			newCfg := twoPolicyConfig([]string{"p-first", "p-web", "p-ssh"}, nil)
			newCfg.Security.Policies[0].Policies[2].Action = config.PolicyDeny
			newCfg.Security.PolicyRematch = true
			ids := dpuserspace.PolicyIDsByStableKey(oldCfg)
			webID := ids["trust->untrust/p-web"]
			sshID := ids["trust->untrust/p-ssh"]
			// A = ssh session (changed policy, reaped); B = web session
			// (unchanged policy, survives) on the same tuples.
			fake := newCollisionDP10512(collisionMatches10512(sshID, webID))
			// collisionMatches puts webID first; swap roles: domain 100007
			// holds the ssh (changed) rows, 100008 the web (unchanged).
			for i := range fake.matches {
				if fake.matches[i].RoutingDomain == 100007 {
					fake.matches[i].PolicyID = sshID
				} else {
					fake.matches[i].PolicyID = webID
				}
			}
			d := &Daemon{}
			d.setDataplane(fake)
			var err error
			if producer == "capture" {
				d.policyInvalidationPlan = &policyInvalidationPlan{oldCfg: oldCfg, newCfg: newCfg}
				d.capturePolicyInvalidationLocked(newCfg)
				err = d.clearSessionsForModifiedPolicies(oldCfg, newCfg)
			} else {
				d.policyInvalidationCapture = nil
				err = d.clearSessionsForModifiedPolicies(oldCfg, newCfg)
			}
			if err != nil {
				t.Fatalf("%s modified clear: %v", producer, err)
			}
			if got := fake.liveIn(100007); got != 0 {
				t.Errorf("%s: changed-policy domain holds %d rows, want 0", producer, got)
			}
			if got := fake.liveIn(100008); got != 2 {
				t.Errorf("%s: unchanged-policy domain holds %d rows, want 2", producer, got)
			}
		})
	}
}

// T6 scheduler-flip (#4343)/v4+v6/capture+legacy: p-ssh's scheduler flips
// active→inactive → same assertions as T5 (an inactive-scheduled policy
// is fail-closed skipped, so its sessions must re-enter evaluation).
func TestT6SchedulerFlipReapsOnlyFlipped10512(t *testing.T) {
	for _, producer := range []string{"capture", "legacy"} {
		t.Run(producer, func(t *testing.T) {
			oldCfg := twoPolicyConfig([]string{"p-first", "p-web", "p-ssh"}, nil)
			newCfg := twoPolicyConfig([]string{"p-first", "p-web", "p-ssh"}, nil)
			oldCfg.Security.Policies[0].Policies[2].SchedulerName = "sched"
			newCfg.Security.Policies[0].Policies[2].SchedulerName = "sched"
			oldCfg.Schedulers = map[string]*config.SchedulerConfig{
				"sched": {Name: "sched", AllDay: true},
			}
			newCfg.Schedulers = map[string]*config.SchedulerConfig{
				"sched": {Name: "sched", StartTime: "23:59", StopTime: "00:01"},
			}
			newCfg.Security.PolicyRematch = true
			ids := dpuserspace.PolicyIDsByStableKey(oldCfg)
			webID := ids["trust->untrust/p-web"]
			sshID := ids["trust->untrust/p-ssh"]
			fake := newCollisionDP10512(collisionMatches10512(sshID, webID))
			for i := range fake.matches {
				if fake.matches[i].RoutingDomain == 100007 {
					fake.matches[i].PolicyID = sshID
				} else {
					fake.matches[i].PolicyID = webID
				}
			}
			d := &Daemon{}
			d.setDataplane(fake)
			var err error
			if producer == "capture" {
				d.policyInvalidationPlan = &policyInvalidationPlan{oldCfg: oldCfg, newCfg: newCfg}
				d.capturePolicyInvalidationLocked(newCfg)
				err = d.clearSessionsForModifiedPolicies(oldCfg, newCfg)
			} else {
				d.policyInvalidationCapture = nil
				err = d.clearSessionsForModifiedPolicies(oldCfg, newCfg)
			}
			if err != nil {
				t.Fatalf("%s scheduler clear: %v", producer, err)
			}
			if got := fake.liveIn(100007); got != 0 {
				t.Errorf("%s: flipped-policy domain holds %d rows, want 0", producer, got)
			}
			if got := fake.liveIn(100008); got != 2 {
				t.Errorf("%s: unflipped-policy domain holds %d rows, want 2", producer, got)
			}
		})
	}
}

// T7 default/v4+v6/capture+legacy (#4342): default permit→deny with
// colliding default-permit sessions (DefaultPolicySentinelID) → the
// default rows are reaped, colliding named-policy rows untouched.
func TestT7DefaultFlipReapsOnlyDefault10512(t *testing.T) {
	for _, producer := range []string{"capture", "legacy"} {
		t.Run(producer, func(t *testing.T) {
			oldCfg := twoPolicyConfig([]string{"p-first", "p-web", "p-ssh"}, nil)
			newCfg := twoPolicyConfig([]string{"p-first", "p-web", "p-ssh"}, nil)
			oldCfg.Security.DefaultPolicy = config.PolicyPermit
			newCfg.Security.DefaultPolicy = config.PolicyDeny
			ids := dpuserspace.PolicyIDsByStableKey(oldCfg)
			webID := ids["trust->untrust/p-web"]
			fake := newCollisionDP10512(collisionMatches10512(dataplane.DefaultPolicySentinelID, webID))
			for i := range fake.matches {
				if fake.matches[i].RoutingDomain == 100007 {
					fake.matches[i].PolicyID = dataplane.DefaultPolicySentinelID
				} else {
					fake.matches[i].PolicyID = webID
				}
			}
			d := &Daemon{}
			d.setDataplane(fake)
			var err error
			if producer == "capture" {
				d.policyInvalidationPlan = &policyInvalidationPlan{oldCfg: oldCfg, newCfg: newCfg}
				d.capturePolicyInvalidationLocked(newCfg)
				err = d.clearSessionsForDefaultPolicyChange(oldCfg, newCfg)
			} else {
				d.policyInvalidationCapture = nil
				err = d.clearSessionsForDefaultPolicyChange(oldCfg, newCfg)
			}
			if err != nil {
				t.Fatalf("%s default clear: %v", producer, err)
			}
			if got := fake.liveIn(100007); got != 0 {
				t.Errorf("%s: default-policy domain holds %d rows, want 0", producer, got)
			}
			if got := fake.liveIn(100008); got != 2 {
				t.Errorf("%s: named-policy domain holds %d rows, want 2", producer, got)
			}
		})
	}
}

// T8 failover, delete-before-promotion: the primary clears A and syncs
// the delete; the standby promotes with A gone and B live. Sync is
// modeled by applying the primary's recorded deletes to the standby
// fake — this pins ORDERING (delete lands before promotion reads the
// table), not transport (the cluster scoped-delete wire is covered by
// its own matrix); no A resurrection, no B loss.
func TestT8FailoverDeleteBeforePromotion10512(t *testing.T) {
	oldCfg := twoPolicyConfig([]string{"p-first", "p-web", "p-ssh"}, nil)
	newCfg := twoPolicyConfig([]string{"p-first", "p-ssh"}, nil)
	ids := dpuserspace.PolicyIDsByStableKey(oldCfg)
	webID := ids["trust->untrust/p-web"]
	sshID := ids["trust->untrust/p-ssh"]
	primary := newCollisionDP10512(collisionMatches10512(webID, sshID))
	standby := newCollisionDP10512(collisionMatches10512(webID, sshID))
	d := &Daemon{}
	d.setDataplane(primary)
	if err := driveCapture10512(d, oldCfg, newCfg); err != nil {
		t.Fatalf("primary clear: %v", err)
	}
	// HA sync: the standby applies the primary's deletes.
	if _, err := standby.DeletePolicySessions(primary.deleted); err != nil {
		t.Fatalf("standby sync-apply: %v", err)
	}
	// Promotion reads the standby table: A gone, B live.
	if got := standby.liveIn(100007); got != 0 {
		t.Errorf("promoted standby holds %d A rows (resurrection), want 0", got)
	}
	if got := standby.liveIn(100008); got != 2 {
		t.Errorf("promoted standby holds %d B rows (loss), want 2", got)
	}
}

// T8 failover, promotion-before-delete: the standby promotes first (both
// rows live), then the delete lands post-promotion; same end state — no
// A resurrection, no B loss. The delete applies to the promoted table
// exactly as to the primary's.
func TestT8FailoverPromotionBeforeDelete10512(t *testing.T) {
	oldCfg := twoPolicyConfig([]string{"p-first", "p-web", "p-ssh"}, nil)
	newCfg := twoPolicyConfig([]string{"p-first", "p-ssh"}, nil)
	ids := dpuserspace.PolicyIDsByStableKey(oldCfg)
	webID := ids["trust->untrust/p-web"]
	sshID := ids["trust->untrust/p-ssh"]
	primary := newCollisionDP10512(collisionMatches10512(webID, sshID))
	standby := newCollisionDP10512(collisionMatches10512(webID, sshID))
	// Promote first: both rows live on the new primary.
	d := &Daemon{}
	d.setDataplane(standby)
	if err := driveCapture10512(d, oldCfg, newCfg); err != nil {
		t.Fatalf("post-promotion clear: %v", err)
	}
	_ = primary // the old primary's table is fenced after promotion
	if got := standby.liveIn(100007); got != 0 {
		t.Errorf("promoted table holds %d A rows (resurrection), want 0", got)
	}
	if got := standby.liveIn(100008); got != 2 {
		t.Errorf("promoted table holds %d B rows (loss), want 2", got)
	}
}
