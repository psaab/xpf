package daemon

import (
	"context"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	dpruntime "github.com/psaab/xpf/pkg/dataplane/runtime"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// Control-row identities (domain 100009): the post-activation forward
// pins the legacy before_secs fence (deleted prepublish, fenced legacy);
// the reverse row pins the producers' Classes:["forward"] contract
// (never discovered, always survives).
const (
	postID10512 = 0xCAFE01
	revID10512  = 0x9E9E01
)

// collisionDP10512 is the #10512 T-matrix fake: a per-domain session table
// where both tenants of a colliding bare tuple coexist (A under 100007, B
// under 100008, controls under 100009), a verb-coherent helper READ
// (ListSessionsByPolicy mirrors the helper's policy/family/class/cutoff
// filtering and records every request), and a recording helper delete
// (DeletePolicySessions removes + records). It models the helper
// authority, not the bare-keyed BPF mirror — a mirror scan could hold
// only ONE row per tuple and could never express the collision.
type collisionDP10512 struct {
	dataplane.DataPlane // embedded nil — only the overridden methods are called

	matches []dpuserspace.SessionPolicyMatch
	revRows []dpuserspace.SessionPolicyMatch
	// over, when set, is appended to every READ unfiltered (faithless
	// helper modeling for the P6 over-return cells).
	over []dpuserspace.SessionPolicyMatch
	deleted []dpuserspace.SessionPolicyMatch
	modes   []string
	reqs    []dpuserspace.SessionPolicyListRequest

	complete  bool
	readErr   error
	delErr    error
	incomple  bool
	workerErr string
}

func newCollisionDP10512(fwd, rev []dpuserspace.SessionPolicyMatch) *collisionDP10512 {
	return &collisionDP10512{matches: fwd, revRows: rev, complete: true}
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

// ListSessionsByPolicy serves the helper READ from the per-domain table,
// mirroring the helper's filter chain exactly: requested policy, allowed
// family, allowed class (forward rows vs reverse rows), and — legacy
// mode only — the before_secs fence (Some(0) unbounded, None rejected).
func (f *collisionDP10512) ListSessionsByPolicy(req dpuserspace.SessionPolicyListRequest) (dpuserspace.ControlResponse, error) {
	f.modes = append(f.modes, req.Mode)
	f.reqs = append(f.reqs, req)
	if f.readErr != nil {
		return dpuserspace.ControlResponse{}, f.readErr
	}
	// Legacy without a boundary is a caller bug (helper:
	// legacy-before-secs-missing), never silently unbounded.
	legacyNoFence := req.Mode == "legacy" && req.BeforeSecs == nil
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
	classOK := func(reverse bool) bool {
		if len(req.Classes) == 0 {
			return true
		}
		for _, c := range req.Classes {
			if reverse && c == "reverse" || !reverse && c == "forward" {
				return true
			}
		}
		return false
	}
	fenced := func(created uint64) bool {
		return req.Mode == "legacy" && req.BeforeSecs != nil &&
			*req.BeforeSecs != 0 && created > *req.BeforeSecs
	}
	var out []dpuserspace.SessionPolicyMatch
	for _, m := range f.matches {
		if !want[m.PolicyID] || !famOK(m.AddrFamily) || !classOK(false) || fenced(m.CreatedSecs) {
			continue
		}
		out = append(out, m)
	}
	for _, m := range f.revRows {
		if !want[m.PolicyID] || !famOK(m.AddrFamily) || !classOK(true) || fenced(m.CreatedSecs) {
			continue
		}
		out = append(out, m)
	}

	// Faithless mode (P6 cells): over-returned rows bypass all filters,
	// modeling a helper that ignores the requested set.
	out = append(out, f.over...)
	resp := dpuserspace.ControlResponse{
		SessionPolicyMatches:  out,
		SessionPolicyComplete: f.complete && !f.incomple && !legacyNoFence,
	}
	if f.incomple {
		resp.SessionPolicyPerWorkerErrors = []string{f.workerErr}
	}
	if legacyNoFence {
		resp.SessionPolicyPerWorkerErrors = append(resp.SessionPolicyPerWorkerErrors, "legacy-before-secs-missing")
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
	remove := func(list []dpuserspace.SessionPolicyMatch, m dpuserspace.SessionPolicyMatch) []dpuserspace.SessionPolicyMatch {
		for i, live := range list {
			if live.RoutingDomain == m.RoutingDomain &&
				live.Tuple == m.Tuple &&
				live.ExpectedRTFlowSessionID == m.ExpectedRTFlowSessionID {
				return append(list[:i], list[i+1:]...)
			}
		}
		return list
	}
	applied := 0
	for _, m := range matches {
		before := len(f.matches) + len(f.revRows)
		f.matches = remove(f.matches, m)
		f.revRows = remove(f.revRows, m)
		if len(f.matches)+len(f.revRows) < before {
			applied++
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
	for _, m := range f.revRows {
		if m.RoutingDomain == domain {
			n++
		}
	}
	return n
}

func (f *collisionDP10512) liveHas(domain uint32, id uint64) bool {
	for _, m := range f.matches {
		if m.RoutingDomain == domain && m.ExpectedRTFlowSessionID == id {
			return true
		}
	}
	for _, m := range f.revRows {
		if m.RoutingDomain == domain && m.ExpectedRTFlowSessionID == id {
			return true
		}
	}
	return false
}

// collisionMatches10512 builds the colliding tenants: A (the deleted
// policy's session) + B (a surviving policy's session) on the SAME bare
// tuple, v4 + v6, distinguished only by domain + identity — plus the
// domain-100009 controls (post-activation forward + reverse row) carrying
// A's policy. Main rows are CreatedSecs=100 (inside any test fence).
func collisionMatches10512(aPolicy, bPolicy uint32) (fwd, rev []dpuserspace.SessionPolicyMatch) {
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
	mk := func(fam uint8, tuple dpuserspace.SessionPolicyTuple, domain uint32, policy uint32, id uint64, created uint64) dpuserspace.SessionPolicyMatch {
		return dpuserspace.SessionPolicyMatch{
			AddrFamily: fam, RoutingDomain: domain, Tuple: tuple,
			PolicyID: policy, ExpectedRTFlowSessionID: id, CreatedSecs: created,
		}
	}
	fwd = []dpuserspace.SessionPolicyMatch{
		mk(4, v4tuple, 100007, aPolicy, 0xA11CE, 100),
		mk(4, v4tuple, 100008, bPolicy, 0xB10512, 100),
		mk(6, v6tuple, 100007, aPolicy, 0xA11CE6, 100),
		mk(6, v6tuple, 100008, bPolicy, 0xB105126, 100),
		mk(4, dpuserspace.SessionPolicyTuple{
			AddrFamily: 4, Protocol: 6,
			SrcIP: "10.9.9.1", DstIP: "10.9.9.2",
			SrcPort: 50001, DstPort: 80,
		}, 100009, aPolicy, postID10512, 0xFFFFFFFF),
	}
	rev = []dpuserspace.SessionPolicyMatch{
		mk(4, dpuserspace.SessionPolicyTuple{
			AddrFamily: 4, Protocol: 6,
			SrcIP: "10.0.0.2", DstIP: "10.0.0.1",
			SrcPort: 80, DstPort: 40001,
		}, 100009, aPolicy, revID10512, 100),
	}
	return fwd, rev
}

// driveCapture10512 runs the CAPTURE producer: arm the plan, take the
// pre-publication READ, then clear from the capture.
func driveCapture10512(d *Daemon, oldCfg, newCfg *config.Config) error {
	d.policyInvalidationPlan = &policyInvalidationPlan{oldCfg: oldCfg, newCfg: newCfg}
	d.capturePolicyInvalidationLocked(newCfg)
	return d.clearSessionsForDeletedPolicies(oldCfg, newCfg)
}

// T1 deleted/v4/capture: deleting A's policy reaps A's v4 row; B's v4 row
// on the same tuple survives. Prepublish has NO cutoff, so the
// post-activation control is reaped too; the reverse control is never
// discovered (Classes:["forward"]) and survives.
func TestT1DeletedV4CaptureReapsOnlyA10512(t *testing.T) {
	oldCfg := twoPolicyConfig([]string{"p-first", "p-web", "p-ssh"}, nil)
	newCfg := twoPolicyConfig([]string{"p-first", "p-ssh"}, nil)
	ids := dpuserspace.PolicyIDsByStableKey(oldCfg)
	webID := ids["trust->untrust/p-web"]
	fwd, rev := collisionMatches10512(webID, ids["trust->untrust/p-ssh"])
	fake := newCollisionDP10512(fwd, rev)
	d := &Daemon{}
	d.setDataplane(fake)

	if err := driveCapture10512(d, oldCfg, newCfg); err != nil {
		t.Fatalf("capture clear: %v", err)
	}
	if len(fake.modes) != 1 || fake.modes[0] != "prepublish" {
		t.Fatalf("modes = %v, want [prepublish] (the capture producer)", fake.modes)
	}
	for _, m := range fake.deleted {
		if m.RoutingDomain != 100007 && m.RoutingDomain != 100009 {
			t.Errorf("deleted a domain-%d row; only A (100007) + controls (100009) may go", m.RoutingDomain)
		}
		if m.PolicyID != webID {
			t.Errorf("deleted policy %d; only p-web (%d) may go", m.PolicyID, webID)
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
	if fake.liveHas(100009, postID10512) {
		t.Error("post-activation control survives prepublish — prepublish has no cutoff")
	}
	if !fake.liveHas(100009, revID10512) {
		t.Error("reverse control reaped — Classes:[forward] must exclude it from discovery")
	}
}

// T2 deleted/v6/capture: the v6 twin of T1.
func TestT2DeletedV6CaptureReapsOnlyA10512(t *testing.T) {
	oldCfg := twoPolicyConfig([]string{"p-first", "p-web", "p-ssh"}, nil)
	newCfg := twoPolicyConfig([]string{"p-first", "p-ssh"}, nil)
	ids := dpuserspace.PolicyIDsByStableKey(oldCfg)
	fwd, rev := collisionMatches10512(ids["trust->untrust/p-web"], ids["trust->untrust/p-ssh"])
	fake := newCollisionDP10512(fwd, rev)
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
	if fake.liveHas(100009, postID10512) {
		t.Error("post-activation control survives prepublish — prepublish has no cutoff")
	}
	if !fake.liveHas(100009, revID10512) {
		t.Error("reverse control reaped — Classes:[forward] must exclude it from discovery")
	}
}

// T3 deleted/v4/legacy: the legacy producer reaps A's v4 row through the
// legacy-mode READ with a nonzero before_secs fence; B survives, the
// post-activation control is FENCED (survives), the reverse control is
// undiscovered (survives).
func TestT3DeletedV4LegacyReapsOnlyA10512(t *testing.T) {
	oldCfg := twoPolicyConfig([]string{"p-first", "p-web", "p-ssh"}, nil)
	newCfg := twoPolicyConfig([]string{"p-first", "p-ssh"}, nil)
	ids := dpuserspace.PolicyIDsByStableKey(oldCfg)
	fwd, rev := collisionMatches10512(ids["trust->untrust/p-web"], ids["trust->untrust/p-ssh"])
	fake := newCollisionDP10512(fwd, rev)
	d := &Daemon{}
	d.setDataplane(fake)
	d.policyInvalidationCapture = nil // force the legacy producer
	d.policyActivationSecs = 1000

	if err := d.clearSessionsForDeletedPolicies(oldCfg, newCfg); err != nil {
		t.Fatalf("legacy clear: %v", err)
	}
	if len(fake.modes) != 1 || fake.modes[0] != "legacy" {
		t.Fatalf("modes = %v, want [legacy] (the legacy producer)", fake.modes)
	}
	if len(fake.reqs) != 1 || fake.reqs[0].BeforeSecs == nil || *fake.reqs[0].BeforeSecs != 1000 {
		t.Fatal("legacy READ must carry a non-nil before_secs fence (1000)")
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
	if !fake.liveHas(100009, postID10512) {
		t.Error("post-activation control reaped under a nonzero fence — the fence is not bound")
	}
	if !fake.liveHas(100009, revID10512) {
		t.Error("reverse control reaped — Classes:[forward] must exclude it from discovery")
	}
}

// T4 deleted/v6/legacy: the v6 twin of T3.
func TestT4DeletedV6LegacyReapsOnlyA10512(t *testing.T) {
	oldCfg := twoPolicyConfig([]string{"p-first", "p-web", "p-ssh"}, nil)
	newCfg := twoPolicyConfig([]string{"p-first", "p-ssh"}, nil)
	ids := dpuserspace.PolicyIDsByStableKey(oldCfg)
	fwd, rev := collisionMatches10512(ids["trust->untrust/p-web"], ids["trust->untrust/p-ssh"])
	fake := newCollisionDP10512(fwd, rev)
	d := &Daemon{}
	d.setDataplane(fake)
	d.policyInvalidationCapture = nil
	d.policyActivationSecs = 1000

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
	if !fake.liveHas(100009, postID10512) {
		t.Error("post-activation control reaped under a nonzero fence — the fence is not bound")
	}
	if !fake.liveHas(100009, revID10512) {
		t.Error("reverse control reaped — Classes:[forward] must exclude it from discovery")
	}
}

// Legacy with a zero activation stamp ("boundary unknown") is UNBOUNDED:
// the post-activation control is returned and reaped, exactly like the
// #6948 activationSecs==0 contract this branch replaces.
func TestLegacyZeroActivationIsUnbounded10512(t *testing.T) {
	oldCfg := twoPolicyConfig([]string{"p-first", "p-web", "p-ssh"}, nil)
	newCfg := twoPolicyConfig([]string{"p-first", "p-ssh"}, nil)
	ids := dpuserspace.PolicyIDsByStableKey(oldCfg)
	fwd, rev := collisionMatches10512(ids["trust->untrust/p-web"], ids["trust->untrust/p-ssh"])
	fake := newCollisionDP10512(fwd, rev)
	d := &Daemon{}
	d.setDataplane(fake)
	d.policyInvalidationCapture = nil
	// policyActivationSecs left 0: boundary unknown.

	if err := d.clearSessionsForDeletedPolicies(oldCfg, newCfg); err != nil {
		t.Fatalf("legacy unbounded clear: %v", err)
	}
	if len(fake.reqs) != 1 || fake.reqs[0].BeforeSecs == nil || *fake.reqs[0].BeforeSecs != 0 {
		t.Fatal("legacy READ must carry Some(0) (never nil) when the boundary is unknown")
	}
	if fake.liveHas(100009, postID10512) {
		t.Error("post-activation control survives a zero-stamp legacy clear — zero must be unbounded")
	}
	if !fake.liveHas(100009, revID10512) {
		t.Error("reverse control reaped — Classes:[forward] must exclude it from discovery")
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
	fake := newCollisionDP10512(nil, nil)
	d := &Daemon{}
	d.setDataplane(fake)
	if err := driveCapture10512(d, oldCfg, newCfg); err != nil {
		t.Fatalf("authoritative empty must return nil, got %v", err)
	}
	if len(fake.deleted) != 0 {
		t.Fatalf("authoritative empty deleted %d rows, want 0", len(fake.deleted))
	}

	// Incomplete: the aggregate reports the shared enumerate error ONCE
	// for all three classes (they share one scan — the per-class joins
	// must not duplicate it). Production reaches the capture only
	// through clearSessionsForPolicyChanges, so the cell drives that.
	fwd2, rev2 := collisionMatches10512(ids["trust->untrust/p-web"], ids["trust->untrust/p-ssh"])
	fake2 := newCollisionDP10512(fwd2, rev2)
	fake2.incomple = true
	fake2.workerErr = "worker-3:queue-full"
	d2 := &Daemon{}
	d2.setDataplane(fake2)
	d2.policyInvalidationPlan = &policyInvalidationPlan{oldCfg: oldCfg, newCfg: newCfg}
	d2.capturePolicyInvalidationLocked(newCfg)
	if err := d2.clearSessionsForPolicyChanges(oldCfg, newCfg); err == nil {
		t.Fatal("incomplete capture must surface clearErr via the aggregate, got nil")
	} else if got := strings.Count(err.Error(), "worker-3:queue-full"); got != 1 {
		t.Fatalf("aggregate error mentions the READ failure %d times, want exactly once (P9 single path): %v", got, err)
	}

	// Nil capture selects the legacy producer (mode pin).
	fake3 := newCollisionDP10512(nil, nil)
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
			// (unchanged policy, survives) on the same tuples. Controls
			// already carry the changed (first-arg) policy; the swap
			// leaves domain 100009 alone.
			fwd, rev := collisionMatches10512(sshID, webID)
			fake := newCollisionDP10512(fwd, rev)
			for i := range fake.matches {
				if fake.matches[i].RoutingDomain == 100007 {
					fake.matches[i].PolicyID = sshID
				} else if fake.matches[i].RoutingDomain == 100008 {
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
// Deterministic: AllDay is always-active; a windowless scheduler is
// fail-closed inactive (no wall-clock window involved).
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
				"sched": {Name: "sched"},
			}
			newCfg.Security.PolicyRematch = true
			ids := dpuserspace.PolicyIDsByStableKey(oldCfg)
			webID := ids["trust->untrust/p-web"]
			sshID := ids["trust->untrust/p-ssh"]
			fwd, rev := collisionMatches10512(sshID, webID)
			fake := newCollisionDP10512(fwd, rev)
			for i := range fake.matches {
				if fake.matches[i].RoutingDomain == 100007 {
					fake.matches[i].PolicyID = sshID
				} else if fake.matches[i].RoutingDomain == 100008 {
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
			fwd, rev := collisionMatches10512(dataplane.DefaultPolicySentinelID, webID)
			fake := newCollisionDP10512(fwd, rev)
			for i := range fake.matches {
				if fake.matches[i].RoutingDomain == 100007 {
					fake.matches[i].PolicyID = dataplane.DefaultPolicySentinelID
				} else if fake.matches[i].RoutingDomain == 100008 {
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
	fwdP, revP := collisionMatches10512(webID, sshID)
	primary := newCollisionDP10512(fwdP, revP)
	fwdS, revS := collisionMatches10512(webID, sshID)
	standby := newCollisionDP10512(fwdS, revS)
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

// T8 failover, promotion-before-delete: the old primary captures and
// deletes while the standby is still standby; promotion lands while
// both rows are live there; then the old primary's already-captured
// scoped deletes arrive as stale post-promotion HA delivery and must
// still apply exactly (A gone, B live) — the captured identities,
// not the promotion, decide.
func TestT8FailoverPromotionBeforeDelete10512(t *testing.T) {
	oldCfg := twoPolicyConfig([]string{"p-first", "p-web", "p-ssh"}, nil)
	newCfg := twoPolicyConfig([]string{"p-first", "p-ssh"}, nil)
	ids := dpuserspace.PolicyIDsByStableKey(oldCfg)
	webID := ids["trust->untrust/p-web"]
	sshID := ids["trust->untrust/p-ssh"]
	fwdP, revP := collisionMatches10512(webID, sshID)
	primary := newCollisionDP10512(fwdP, revP)
	fwdS, revS := collisionMatches10512(webID, sshID)
	standby := newCollisionDP10512(fwdS, revS)
	// Capture + delete on the old primary (pre-promotion identities).
	d := &Daemon{}
	d.setDataplane(primary)
	if err := driveCapture10512(d, oldCfg, newCfg); err != nil {
		t.Fatalf("primary clear: %v", err)
	}
	// Promote while both rows are still live on the standby (no sync yet).
	if got := standby.liveIn(100007); got != 2 {
		t.Fatalf("pre-delivery standby holds %d A rows, want 2 (both live)", got)
	}
	// Stale post-promotion HA delivery: the old primary's captured
	// deletes land after promotion and must apply exactly.
	if _, err := standby.DeletePolicySessions(primary.deleted); err != nil {
		t.Fatalf("stale post-promotion delivery: %v", err)
	}
	if got := standby.liveIn(100007); got != 0 {
		t.Errorf("promoted table holds %d A rows (resurrection), want 0", got)
	}
	if got := standby.liveIn(100008); got != 2 {
		t.Errorf("promoted table holds %d B rows (loss), want 2", got)
	}
	if !standby.liveHas(100009, revID10512) {
		t.Error("reverse control reaped in stale delivery — only captured forwards travel")
	}
}

// P6 capture: an over-returned match (policy outside the requested
// set) is skipped loudly — never routed to a bucket — while the
// legitimate rows still clear. Driven via the aggregate (production
// path: the readErr joins there).
func TestCaptureOverReturnSkippedLoudly10512(t *testing.T) {
	oldCfg := twoPolicyConfig([]string{"p-first", "p-web", "p-ssh"}, nil)
	newCfg := twoPolicyConfig([]string{"p-first", "p-ssh"}, nil)
	ids := dpuserspace.PolicyIDsByStableKey(oldCfg)
	webID := ids["trust->untrust/p-web"]
	fwd, rev := collisionMatches10512(webID, ids["trust->untrust/p-ssh"])
	fake := newCollisionDP10512(fwd, rev)
	fake.over = []dpuserspace.SessionPolicyMatch{{
		AddrFamily: 4, RoutingDomain: 100007, PolicyID: 999,
		ExpectedRTFlowSessionID: 0xE11CE,
		Tuple: dpuserspace.SessionPolicyTuple{
			AddrFamily: 4, Protocol: 6,
			SrcIP: "10.9.9.9", DstIP: "10.9.9.10",
			SrcPort: 50009, DstPort: 80,
		},
	}}
	d := &Daemon{}
	d.setDataplane(fake)
	d.policyInvalidationPlan = &policyInvalidationPlan{oldCfg: oldCfg, newCfg: newCfg}
	d.capturePolicyInvalidationLocked(newCfg)
	err := d.clearSessionsForPolicyChanges(oldCfg, newCfg)
	if err == nil {
		t.Fatal("over-returned match must surface an error")
	}
	for _, m := range fake.deleted {
		if m.PolicyID == 999 {
			t.Fatal("extraneous policy 999 was deleted (over-clear)")
		}
	}
	if fake.liveHas(100007, 0xA11CE) {
		t.Error("A's v4 row survives despite a valid capture (over-return must not block it)")
	}
}

// P6 legacy twin: same skip+loud through the legacy producer.
func TestLegacyOverReturnSkippedLoudly10512(t *testing.T) {
	oldCfg := twoPolicyConfig([]string{"p-first", "p-web", "p-ssh"}, nil)
	newCfg := twoPolicyConfig([]string{"p-first", "p-ssh"}, nil)
	ids := dpuserspace.PolicyIDsByStableKey(oldCfg)
	fwd, rev := collisionMatches10512(ids["trust->untrust/p-web"], ids["trust->untrust/p-ssh"])
	fake := newCollisionDP10512(fwd, rev)
	fake.over = []dpuserspace.SessionPolicyMatch{{
		AddrFamily: 4, RoutingDomain: 100007, PolicyID: 999,
		ExpectedRTFlowSessionID: 0xE11CE,
		Tuple: dpuserspace.SessionPolicyTuple{
			AddrFamily: 4, Protocol: 6,
			SrcIP: "10.9.9.9", DstIP: "10.9.9.10",
			SrcPort: 50009, DstPort: 80,
		},
	}}
	d := &Daemon{}
	d.setDataplane(fake)
	d.policyInvalidationCapture = nil
	if err := d.clearSessionsForDeletedPolicies(oldCfg, newCfg); err == nil {
		t.Fatal("legacy over-return must surface an error")
	}
	for _, m := range fake.deleted {
		if m.PolicyID == 999 {
			t.Fatal("extraneous policy 999 was deleted (over-clear)")
		}
	}
	if fake.liveHas(100007, 0xA11CE) {
		t.Error("A's v4 row survives despite a valid legacy READ")
	}
}

// P7 capture-partial: an incomplete READ still revokes what was
// gathered (delete-partial beats zero-delete) while the joined error
// surfaces the gap — and the HA peer observes the same partial
// revocation (scoped deletes queued per attempted match).
func TestCapturePartialDeletesAndSyncsPeer10512(t *testing.T) {
	d, ss := primaryForRG1Daemon9752()
	d.cluster = clusterManagerPrimaryForRGs(1)
	ss.SetScopedPolicyDeleteCapableForTesting(true)
	oldCfg := twoPolicyConfig([]string{"p-first", "p-web", "p-ssh"}, nil)
	newCfg := twoPolicyConfig([]string{"p-first", "p-ssh"}, nil)
	ids := dpuserspace.PolicyIDsByStableKey(oldCfg)
	fwd, rev := collisionMatches10512(ids["trust->untrust/p-web"], ids["trust->untrust/p-ssh"])
	fake := newCollisionDP10512(fwd, rev)
	fake.incomple = true
	fake.workerErr = "worker-1:queue-full"
	d.setDataplane(fake)
	d.policyInvalidationPlan = &policyInvalidationPlan{oldCfg: oldCfg, newCfg: newCfg}
	d.capturePolicyInvalidationLocked(newCfg)
	if err := d.clearSessionsForPolicyChanges(oldCfg, newCfg); err == nil {
		t.Fatal("incomplete capture must surface clearErr")
	}
	if fake.liveHas(100007, 0xA11CE) {
		t.Fatal("partial capture deleted nothing — incomplete must still revoke gathered rows")
	}
	key4, _, err := policyTupleV4(fwd[0].Tuple)
	if err != nil {
		t.Fatalf("FIXTURE: %v", err)
	}
	if domain, id, ok := ss.ScopedDeleteJournalEntryForTesting(key4); !ok || domain != 100007 || id != 0xA11CE {
		t.Fatalf("peer observed (%d, %#x, %v), want the partial row (100007, 0xA11CE, true)", domain, id, ok)
	}
}

// P7 legacy-partial twin (delete + error + peer-observed).
func TestLegacyPartialDeletesAndSyncsPeer10512(t *testing.T) {
	d, ss := primaryForRG1Daemon9752()
	d.cluster = clusterManagerPrimaryForRGs(1)
	ss.SetScopedPolicyDeleteCapableForTesting(true)
	oldCfg := twoPolicyConfig([]string{"p-first", "p-web", "p-ssh"}, nil)
	newCfg := twoPolicyConfig([]string{"p-first", "p-ssh"}, nil)
	ids := dpuserspace.PolicyIDsByStableKey(oldCfg)
	fwd, rev := collisionMatches10512(ids["trust->untrust/p-web"], ids["trust->untrust/p-ssh"])
	fake := newCollisionDP10512(fwd, rev)
	fake.incomple = true
	fake.workerErr = "worker-2:dead"
	d.setDataplane(fake)
	d.policyInvalidationCapture = nil
	if err := d.clearSessionsForDeletedPolicies(oldCfg, newCfg); err == nil {
		t.Fatal("incomplete legacy READ must surface clearErr")
	}
	if fake.liveHas(100007, 0xA11CE) {
		t.Fatal("partial legacy READ deleted nothing — incomplete must still revoke gathered rows")
	}
	key4, _, err := policyTupleV4(fwd[0].Tuple)
	if err != nil {
		t.Fatalf("FIXTURE: %v", err)
	}
	if domain, id, ok := ss.ScopedDeleteJournalEntryForTesting(key4); !ok || domain != 100007 || id != 0xA11CE {
		t.Fatalf("peer observed (%d, %#x, %v), want the partial row (100007, 0xA11CE, true)", domain, id, ok)
	}
}
