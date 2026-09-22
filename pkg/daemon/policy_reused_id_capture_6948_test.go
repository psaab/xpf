package daemon

// policy_reused_id_capture_6948_test.go — #6948, the PRE-PUBLICATION capture.
//
// Runtime policy ids are POSITIONAL, so a deletion renumbers every later
// policy and a survivor can INHERIT a deleted policy's id:
//
//	C1 = [A, B, C]  ->  A=0, B=1, C=2
//	delete B
//	C2 = [A, C]     ->  A=0, C=1        <- C INHERITED B's id
//
// The commit-time invalidation derives its target set from the OLD numbering
// but used to read the session table AFTER the apply. Two independent writers
// move the live row's policy_id out from under that read:
//
//   - ADMISSION under the new numbering (the half the #7803 `Created` guard
//     addresses), and
//   - the helper's #3395 live-row RE-STAMP: refresh_bpf_conntrack_last_seen
//     re-resolves every forward row's policy_id from its bound rule handle
//     against the CURRENT rule table and writes it into the same pinned
//     conntrack map Go enumerates, on a 100ms-slice / 10s-full-table rolling
//     cycle. Within the seconds the apply tail takes, C's LONG-ESTABLISHED
//     rows become policy_id 1 and B's become the default sentinel.
//
// The second writer is invisible to any creation-time predicate: those rows
// were created long before the commit. The cells below are built on it for
// that reason — a fixture that only admits a fresh session after activation
// is satisfied by the pre-existing `Created` guard and would pass either way.
//
// The fix reads the candidate set ONCE, immediately before the dataplane
// publishes the new snapshot, and deletes from that capture afterwards.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// inheritedIDFixture6948 builds the worked example and returns BOTH old ids.
// It asserts the inheritance instead of assuming it: if the allocator ever
// stopped renumbering, every cell here would pass for the wrong reason.
func inheritedIDFixture6948(t *testing.T) (oldCfg, newCfg *config.Config, webOldID, sshOldID uint32) {
	t.Helper()
	o := twoPolicyConfig([]string{"p-first", "p-web", "p-ssh"}, nil)
	n := twoPolicyConfig([]string{"p-first", "p-ssh"}, nil)

	oldIDs := dpuserspace.PolicyIDsByStableKey(o)
	newIDs := dpuserspace.PolicyIDsByStableKey(n)
	webOldID = oldIDs["trust->untrust/p-web"]
	sshOldID = oldIDs["trust->untrust/p-ssh"]
	sshNewID := newIDs["trust->untrust/p-ssh"]

	if webOldID == sshOldID {
		t.Fatalf("precondition: p-web and p-ssh must hold DIFFERENT ids before the "+
			"commit (%d == %d) or the re-stamp this cell models is not observable", webOldID, sshOldID)
	}
	if sshNewID != webOldID {
		t.Fatalf("precondition: this cell needs p-ssh to INHERIT deleted p-web's "+
			"runtime id, which is what makes the over-clear possible. "+
			"p-web(old)=%d p-ssh(new)=%d — ids are no longer positional, so "+
			"re-derive #6948 before trusting these cells", webOldID, sshNewID)
	}
	return o, n, webOldID, sshOldID
}

func v4Key6948(host byte, sport uint16, dport uint16) dataplane.SessionKey {
	return dataplane.SessionKey{
		SrcIP: [4]byte{10, 0, 0, host}, DstIP: [4]byte{10, 0, 0, 254},
		SrcPort: sport, DstPort: dport, Protocol: 6,
	}
}

// TestRestampedSurvivorIsNotSweptFromCapture6948 is the defect, in the shape
// the #7803 `Created` guard cannot see.
//
// p-ssh's session is ESTABLISHED — created an hour before the commit — and the
// helper's #3395 refresh has re-stamped its row from p-ssh's old id to the id
// p-ssh now holds, which is the id deleted p-web used to hold. A post-apply
// read of the table therefore finds a row carrying the deletion set's id whose
// creation time is far BEFORE the activation stamp, so the creation-time guard
// passes it straight through to the delete.
//
// FAIL-ON-REVERT: drop the capture branch from clearSessionsForDeletedPolicies
// and this reds — a correctly-permitted, long-established session is dropped by
// an unrelated policy's deletion.
func TestRestampedSurvivorIsNotSweptFromCapture6948(t *testing.T) {
	oldCfg, newCfg, webOldID, sshOldID := inheritedIDFixture6948(t)

	const activation = 100000
	sshSess := v4Key6948(9, 41001, 22)
	dp := &policyInvalTestDP{
		v4: map[dataplane.SessionKey]dataplane.SessionValue{
			// Established an hour before the commit, carrying p-ssh's OWN old id.
			sshSess: {State: dataplane.SessStateEstablished, PolicyID: sshOldID, Created: activation - 3600},
		},
	}
	d := &Daemon{}
	d.setDataplane(dp)
	// The #7803 stamp is present and correct — this cell exists because it is
	// not sufficient. An established row's Created is far below it either way.
	d.policyActivationSecs = activation

	// The apply: capture at the publication boundary, while the row still
	// carries the numbering the deletion set was derived from.
	d.armPolicyInvalidationPlan(oldCfg, newCfg)
	d.capturePolicyInvalidationLocked(newCfg)

	// ... then the helper's #3395 refresh re-resolves the row against the NEW
	// rule table: p-ssh survived, so its row is re-stamped to p-ssh's new id —
	// which is the id deleted p-web held.
	restamped := dp.v4[sshSess]
	restamped.PolicyID = webOldID
	dp.v4[sshSess] = restamped

	if err := d.clearSessionsForPolicyChanges(oldCfg, newCfg); err != nil {
		t.Fatalf("clearSessionsForPolicyChanges: %v", err)
	}

	if _, ok := dp.v4[sshSess]; !ok {
		t.Fatal("an ESTABLISHED session of the SURVIVING policy p-ssh was swept by " +
			"the deletion of p-web. It matched only because the helper's #3395 " +
			"live-row refresh re-stamped it to the id p-ssh inherited from p-web, " +
			"and its creation time predates the activation stamp so no " +
			"creation-time guard can see it. The invalidation must delete what it " +
			"observed BEFORE the new policy set was published, not what the table " +
			"says afterwards (#6948)")
	}
}

// TestDeletedPolicySessionSweptEvenAfterRestamp6948 is the necessary half of
// the pair: the capture must still DELETE what the deletion-clear exists to
// remove. Without it, "never sweep a re-stamped row" is satisfied by a change
// that deletes nothing — the stale-authorization direction, strictly worse than
// the over-clear being fixed.
//
// It also pins the second half of the same re-stamp defect: p-web's own rows
// are re-resolved to DEFAULT_POLICY_SENTINEL_ID once its rule is gone (the rule
// id no longer resolves), so a post-apply read MISSES them entirely. The
// capture saw them under p-web's id and deletes them regardless.
func TestDeletedPolicySessionSweptEvenAfterRestamp6948(t *testing.T) {
	oldCfg, newCfg, webOldID, _ := inheritedIDFixture6948(t)

	const activation = 100000
	webSess := v4Key6948(1, 40001, 80)
	dp := &policyInvalTestDP{
		v4: map[dataplane.SessionKey]dataplane.SessionValue{
			webSess: {State: dataplane.SessStateEstablished, PolicyID: webOldID, Created: activation - 3600},
		},
	}
	d := &Daemon{}
	d.setDataplane(dp)
	d.policyActivationSecs = activation

	d.armPolicyInvalidationPlan(oldCfg, newCfg)
	d.capturePolicyInvalidationLocked(newCfg)

	// The refresh re-resolves a DELETED rule to the unattributed sentinel.
	restamped := dp.v4[webSess]
	restamped.PolicyID = dataplane.DefaultPolicySentinelID
	dp.v4[webSess] = restamped

	if err := d.clearSessionsForPolicyChanges(oldCfg, newCfg); err != nil {
		t.Fatalf("clearSessionsForPolicyChanges: %v", err)
	}

	if _, ok := dp.v4[webSess]; ok {
		t.Fatal("a session admitted by the DELETED policy p-web survived the commit " +
			"clear. Once its rule is gone the #3395 refresh re-stamps the row to the " +
			"default-policy sentinel, so a post-apply read by the OLD id no longer " +
			"matches it — traffic the new config no longer permits keeps forwarding " +
			"until idle timeout. The capture observed it under p-web's id before the " +
			"publish and must delete it (#6948)")
	}
}

// TestRestampedSurvivorIsNotSweptFromCaptureV6_6948 is the IPv6 half. The
// capture walks both families and the #3395 refresh re-stamps both, so a v4-only
// capture just moves the defect to the other address family — and no v4 cell can
// see that.
func TestRestampedSurvivorIsNotSweptFromCaptureV6_6948(t *testing.T) {
	oldCfg, newCfg, webOldID, sshOldID := inheritedIDFixture6948(t)

	sshSess := dataplane.SessionKeyV6{
		SrcIP: [16]byte{0x20, 0x01, 15: 0x09}, DstIP: [16]byte{0x20, 0x01, 15: 0xfe},
		SrcPort: 41001, DstPort: 22, Protocol: 6,
	}
	webSess := dataplane.SessionKeyV6{
		SrcIP: [16]byte{0x20, 0x01, 15: 0x01}, DstIP: [16]byte{0x20, 0x01, 15: 0xfe},
		SrcPort: 40001, DstPort: 80, Protocol: 6,
	}
	dp := &policyInvalTestDP{
		v6: map[dataplane.SessionKeyV6]dataplane.SessionValueV6{
			sshSess: {State: dataplane.SessStateEstablished, PolicyID: sshOldID, Created: 500},
			webSess: {State: dataplane.SessStateEstablished, PolicyID: webOldID, Created: 500},
		},
	}
	d := &Daemon{}
	d.setDataplane(dp)

	d.armPolicyInvalidationPlan(oldCfg, newCfg)
	d.capturePolicyInvalidationLocked(newCfg)

	// The refresh re-stamps both: the survivor to the id it inherited, the
	// deleted policy's row to the unattributed sentinel.
	ssh := dp.v6[sshSess]
	ssh.PolicyID = webOldID
	dp.v6[sshSess] = ssh
	web := dp.v6[webSess]
	web.PolicyID = dataplane.DefaultPolicySentinelID
	dp.v6[webSess] = web

	if err := d.clearSessionsForPolicyChanges(oldCfg, newCfg); err != nil {
		t.Fatalf("clearSessionsForPolicyChanges: %v", err)
	}

	if _, ok := dp.v6[sshSess]; !ok {
		t.Fatal("v6: an established session of the SURVIVING policy p-ssh was swept " +
			"after the #3395 refresh re-stamped it to the id it inherited from " +
			"deleted p-web. The capture must cover BOTH address families or the " +
			"defect simply moves to the other one (#6948)")
	}
	if _, ok := dp.v6[webSess]; ok {
		t.Fatal("v6: the DELETED policy's own session survived — once re-stamped to " +
			"the sentinel a post-apply read by the old id no longer matches it, so " +
			"the capture is what must delete it (#6948)")
	}
}

// TestSessionAdmittedAfterCaptureIsNotSwept6948 covers the ADMISSION half
// through the capture rather than through the creation-time stamp — the stamp
// is deliberately left at 0 here, so the legacy guard is inert and only the
// capture can distinguish the two sessions.
func TestSessionAdmittedAfterCaptureIsNotSwept6948(t *testing.T) {
	oldCfg, newCfg, webOldID, _ := inheritedIDFixture6948(t)

	webSess := v4Key6948(1, 40001, 80)
	dp := &policyInvalTestDP{
		v4: map[dataplane.SessionKey]dataplane.SessionValue{
			webSess: {State: dataplane.SessStateEstablished, PolicyID: webOldID, Created: 500},
		},
	}
	d := &Daemon{}
	d.setDataplane(dp)
	// policyActivationSecs deliberately 0: the pre-#6948 guard cannot help.

	d.armPolicyInvalidationPlan(oldCfg, newCfg)
	d.capturePolicyInvalidationLocked(newCfg)

	// After publication p-ssh admits a fresh session; it carries p-ssh's NEW id,
	// which is the id p-web held.
	freshSess := v4Key6948(9, 41002, 22)
	dp.v4[freshSess] = dataplane.SessionValue{
		State: dataplane.SessStateEstablished, PolicyID: webOldID, Created: 900,
	}

	if err := d.clearSessionsForPolicyChanges(oldCfg, newCfg); err != nil {
		t.Fatalf("clearSessionsForPolicyChanges: %v", err)
	}

	if _, ok := dp.v4[freshSess]; !ok {
		t.Fatal("a session admitted by p-ssh AFTER the new policy set went live was " +
			"swept by the deletion of p-web, whose id it inherited (#6948)")
	}
	if _, ok := dp.v4[webSess]; ok {
		t.Fatal("the DELETED policy's own session survived: the capture must delete " +
			"what it observed, not nothing (#6948)")
	}
}

// TestDefaultPolicyTighteningClearsFromCapture6948 pins the class the #7803
// creation-time guard could only HARM. DefaultPolicySentinelID is never
// inherited, so a default-permit session can never be over-cleared by
// renumbering — but the guard was applied in the shared core, so a default
// -permit session created after the activation stamp and before the publish was
// SKIPPED on a `permit-all` -> `deny-all` commit and kept forwarding under an
// authorization the new config revokes.
//
// The stamp is taken before the apply preamble (RETH-MAC pre-check, snapshot
// build) and the publish comes after it, so crossing a one-second boundary in
// between is ordinary, not exotic.
func TestDefaultPolicyTighteningClearsFromCapture6948(t *testing.T) {
	oldCfg := &config.Config{}
	oldCfg.Security.DefaultPolicy = config.PolicyPermit
	newCfg := &config.Config{}
	newCfg.Security.DefaultPolicy = config.PolicyDeny

	const activation = 100000
	sess := v4Key6948(3, 40003, 53)
	dp := &policyInvalTestDP{
		v4: map[dataplane.SessionKey]dataplane.SessionValue{
			sess: {
				State:    dataplane.SessStateEstablished,
				PolicyID: dataplane.DefaultPolicySentinelID,
				// Created inside the stamp -> publish window.
				Created: activation + 2,
			},
		},
	}
	d := &Daemon{}
	d.setDataplane(dp)
	d.policyActivationSecs = activation

	d.armPolicyInvalidationPlan(oldCfg, newCfg)
	d.capturePolicyInvalidationLocked(newCfg)

	if err := d.clearSessionsForPolicyChanges(oldCfg, newCfg); err != nil {
		t.Fatalf("clearSessionsForPolicyChanges: %v", err)
	}

	if _, ok := dp.v4[sess]; ok {
		t.Fatal("a live default-PERMIT session survived a default-policy " +
			"permit->deny commit because it was created after the activation stamp. " +
			"The sentinel is never inherited, so no ambiguity exists for this class " +
			"and skipping it is a pure stale-authorization gap (#6948/#4342)")
	}
}

// TestModifiedPolicyRematchUsesTheCapture6948 covers the third bucket. The
// rematch half is exposed to the same re-stamp: a surviving-but-changed policy
// whose id SHIFTED has its rows re-stamped to the new id, so a post-apply read
// by the OLD id both misses them and hits whichever policy now holds that id.
func TestModifiedPolicyRematchUsesTheCapture6948(t *testing.T) {
	// p-first, p-web, p-ssh; delete p-web AND tighten p-ssh. p-ssh survives with
	// a changed action, so it is the rematch half's target, and its id shifts
	// from 2 to 1 because p-web was removed ahead of it.
	oldCfg := twoPolicyConfig([]string{"p-first", "p-web", "p-ssh"}, nil)
	newCfg := twoPolicyConfig([]string{"p-first", "p-ssh"}, nil)
	newCfg.Security.PolicyRematch = true
	newCfg.Security.Policies[0].Policies[1].Action = config.PolicyDeny

	oldIDs := dpuserspace.PolicyIDsByStableKey(oldCfg)
	sshOldID := oldIDs["trust->untrust/p-ssh"]
	webOldID := oldIDs["trust->untrust/p-web"]
	if sshOldID == webOldID {
		t.Fatalf("precondition: p-ssh(%d) and p-web(%d) must differ", sshOldID, webOldID)
	}

	sshSess := v4Key6948(9, 41003, 22)
	dp := &policyInvalTestDP{
		v4: map[dataplane.SessionKey]dataplane.SessionValue{
			sshSess: {State: dataplane.SessStateEstablished, PolicyID: sshOldID, Created: 500},
		},
	}
	d := &Daemon{}
	d.setDataplane(dp)

	d.armPolicyInvalidationPlan(oldCfg, newCfg)
	d.capturePolicyInvalidationLocked(newCfg)

	// The refresh re-stamps the row to p-ssh's NEW id (the one p-web vacated).
	restamped := dp.v4[sshSess]
	restamped.PolicyID = webOldID
	dp.v4[sshSess] = restamped

	if err := d.clearSessionsForPolicyChanges(oldCfg, newCfg); err != nil {
		t.Fatalf("clearSessionsForPolicyChanges: %v", err)
	}

	if _, ok := dp.v4[sshSess]; ok {
		t.Fatal("a session of the TIGHTENED policy p-ssh (permit -> deny under " +
			"policy-rematch) survived the commit. Its row was re-stamped to p-ssh's " +
			"NEW id, so a post-apply read by p-ssh's OLD id no longer matches it and " +
			"traffic the new policy DENIES keeps forwarding (#6948)")
	}
}

// TestCaptureIsConsumedOnce6948 pins the lifecycle. A capture is a candidate
// list of 5-tuples; deleting it against a DIFFERENT config pair would drop
// unrelated sessions. It must therefore be dropped when the invalidation
// consumes it, and dropped again at the top of the next apply for the path
// where an apply bails before reaching its own capture point.
func TestCaptureIsConsumedOnce6948(t *testing.T) {
	oldCfg, newCfg, webOldID, _ := inheritedIDFixture6948(t)

	webSess := v4Key6948(1, 40001, 80)
	dp := &policyInvalTestDP{
		v4: map[dataplane.SessionKey]dataplane.SessionValue{
			webSess: {State: dataplane.SessStateEstablished, PolicyID: webOldID, Created: 500},
		},
	}
	d := &Daemon{}
	d.setDataplane(dp)

	d.armPolicyInvalidationPlan(oldCfg, newCfg)
	d.capturePolicyInvalidationLocked(newCfg)
	if d.policyInvalidationCapture == nil {
		t.Fatal("an armed plan must produce a capture")
	}
	if d.policyInvalidationPlan != nil {
		t.Fatal("the plan must be consumed by the capture, or a later apply " +
			"re-captures against a stale config pair")
	}
	if err := d.clearSessionsForPolicyChanges(oldCfg, newCfg); err != nil {
		t.Fatalf("clearSessionsForPolicyChanges: %v", err)
	}
	if d.policyInvalidationCapture != nil {
		t.Fatal("the capture must be consumed by the invalidation; a surviving " +
			"candidate list can be deleted against a later, unrelated commit (#6948)")
	}

	// The next apply resets it even when it bails before its own capture point.
	d.policyInvalidationCapture = &policyInvalidationCapture{}
	d.applyBodyForTest = func(*config.Config) {}
	if err := d.applyConfigLocked(t.Context(), newCfg); err != nil {
		t.Fatalf("applyConfigLocked: %v", err)
	}
	if d.policyInvalidationCapture != nil {
		t.Fatal("applyConfigLocked must drop a capture left by a previous apply " +
			"before doing anything else (#6948)")
	}
}

// TestStalePlanIsNotCapturedAgainstADifferentConfig6948 pins the identity
// check. An apply that bails before its own capture point leaves its plan
// armed, and the next apply to reach the capture may be a different one — a
// feed-driven re-apply, a rollback. A candidate set is a list of live 5-tuples,
// so capturing one under a diff that does not describe what is being published
// is the same error as reading the table after the publish.
func TestStalePlanIsNotCapturedAgainstADifferentConfig6948(t *testing.T) {
	oldCfg, newCfg, webOldID, _ := inheritedIDFixture6948(t)
	otherCfg := twoPolicyConfig([]string{"p-first", "p-web", "p-ssh"}, nil)

	webSess := v4Key6948(1, 40001, 80)
	dp := &policyInvalTestDP{
		v4: map[dataplane.SessionKey]dataplane.SessionValue{
			webSess: {State: dataplane.SessStateEstablished, PolicyID: webOldID, Created: 500},
		},
	}
	d := &Daemon{}
	d.setDataplane(dp)

	d.armPolicyInvalidationPlan(oldCfg, newCfg)
	// A DIFFERENT config reaches the publication boundary.
	d.capturePolicyInvalidationLocked(otherCfg)

	if d.policyInvalidationCapture != nil {
		t.Fatal("a plan armed for one config was captured against another. The " +
			"candidate set would name sessions by a diff that does not describe " +
			"the config being published (#6948)")
	}
	if d.policyInvalidationPlan != nil {
		t.Fatal("the stale plan must be dropped, not left armed for the apply " +
			"after this one (#6948)")
	}
}

// TestUnarmedApplyFallsBackToTheLegacyScan6948 is the compatibility floor: a
// path that reaches the invalidation without an armed plan (a boot apply, a
// future caller) must still clear, using the pre-#6948 post-apply scan. A
// missing capture must never mean "clear nothing".
func TestUnarmedApplyFallsBackToTheLegacyScan6948(t *testing.T) {
	oldCfg, newCfg, webOldID, _ := inheritedIDFixture6948(t)

	webSess := v4Key6948(1, 40001, 80)
	dp := &policyInvalTestDP{
		v4: map[dataplane.SessionKey]dataplane.SessionValue{
			webSess: {State: dataplane.SessStateEstablished, PolicyID: webOldID, Created: 500},
		},
	}
	d := &Daemon{}
	d.setDataplane(dp)
	// No armPolicyInvalidationPlan / capturePolicyInvalidationLocked.

	if err := d.clearSessionsForPolicyChanges(oldCfg, newCfg); err != nil {
		t.Fatalf("clearSessionsForPolicyChanges: %v", err)
	}
	if _, ok := dp.v4[webSess]; ok {
		t.Fatal("with no capture the deletion-clear did nothing. An unarmed path must " +
			"degrade to the pre-#6948 post-apply scan, not silently disable the " +
			"invalidation (#6948)")
	}
}

// TestCommitApplyArmsThePolicyInvalidationPlan6948 binds the WIRING of the arm,
// not the function it calls.
//
// Only applyAndSyncCommitted holds the pre-commit active config, so if it stops
// arming the plan every commit silently reverts to the post-apply scan — the
// defect returns with every behavioural cell above still green, because they
// arm the plan themselves. The stub body observes the plan while the apply is
// notionally running, which is where the capture would read it.
func TestCommitApplyArmsThePolicyInvalidationPlan6948(t *testing.T) {
	oldCfg, newCfg, _, _ := inheritedIDFixture6948(t)

	var seen *policyInvalidationPlan
	d := &Daemon{}
	d.applyBodyForTest = func(*config.Config) { seen = d.policyInvalidationPlan }

	if _, err := d.applyAndSyncCommitted(oldCfg, newCfg, peerSyncNever); err != nil {
		t.Fatalf("applyAndSyncCommitted: %v", err)
	}
	if seen == nil {
		t.Fatal("the commit apply did not arm the #6948 invalidation plan, so the " +
			"capture never runs and every commit falls back to the post-apply scan " +
			"this fix exists to remove")
	}
	if seen.oldCfg != oldCfg || seen.newCfg != newCfg {
		t.Fatalf("the armed plan must carry the commit's own (old, new) pair; "+
			"got old=%p new=%p want old=%p new=%p", seen.oldCfg, seen.newCfg, oldCfg, newCfg)
	}
}

// TestCaptureRunsBeforeTheDataplanePublish6948 binds the PLACEMENT, which is
// the whole design: a capture taken after rt.ApplyConfig reads the new
// numbering and is exactly the defect. Nothing about the behavioural cells
// above can see this — they call the capture directly.
//
// Parsed with parser.ParseFile(..., 0), so comments are discarded before
// matching: no prose in the audited file — including the comment that explains
// the ordering — can satisfy it.
func TestCaptureRunsBeforeTheDataplanePublish6948(t *testing.T) {
	_, self, ok := callerFile6948()
	if !ok {
		t.Fatal("runtime.Caller(0) failed")
	}
	path := filepath.Join(filepath.Dir(self), "daemon_apply_dataplane.go")
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}

	var captureAt, applyAt token.Pos
	for _, d := range f.Decls {
		fd, isFunc := d.(*ast.FuncDecl)
		if !isFunc || fd.Body == nil || fd.Name.Name != "applyDataplaneAndHACore" {
			continue
		}
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			ce, isCall := n.(*ast.CallExpr)
			if !isCall {
				return true
			}
			sel, isSel := ce.Fun.(*ast.SelectorExpr)
			if !isSel {
				return true
			}
			switch sel.Sel.Name {
			case "captureAndStagePolicyRenameAncestry":
				// The helper takes the capture as its first statement and
				// then stages any rename rows, so a call to it IS the
				// pre-publication capture for ordering purposes. The direct
				// capture call was intentionally replaced by the helper;
				// only this spelling is accepted.
				if !captureAt.IsValid() {
					captureAt = ce.Pos()
				}
			case "ApplyConfig":
				if !applyAt.IsValid() {
					applyAt = ce.Pos()
				}
			}
			return true
		})
	}

	if !applyAt.IsValid() {
		t.Fatal("no ApplyConfig call found in applyDataplaneAndHACore; this guard is " +
			"not reading the function it claims to audit")
	}
	if !captureAt.IsValid() {
		t.Fatal("applyDataplaneAndHACore no longer takes a pre-publication capture " +
			"(no captureAndStagePolicyRenameAncestry helper call). Without it no " +
			"commit takes a pre-publication capture and every invalidation falls " +
			"back to the post-apply scan, which sweeps the sessions of whichever " +
			"policy inherited a deleted policy's id (#6948)")
	}
	if captureAt >= applyAt {
		t.Fatalf("the pre-publication capture is called at or after ApplyConfig "+
			"(capture pos %d, apply pos %d). The capture must read the session table "+
			"BEFORE the new policy snapshot is published — after it, the rows carry "+
			"the NEW numbering and the capture reproduces the defect it exists to "+
			"fix (#6948)", captureAt, applyAt)
	}
}

func callerFile6948() (uintptr, string, bool) {
	pc, file, _, ok := runtime.Caller(1)
	return pc, file, ok
}
