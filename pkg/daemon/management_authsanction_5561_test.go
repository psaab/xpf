// #5561 round 13: the grant-half gate must ask the question it means, not a
// proxy for it.
//
// reconcileTo withholds a committed credential grant from a listener that is
// serving an address the commit asked to leave. The gate that implemented that
// was `rebinding && len(errs) == 0` — "some leg was going to move AND every
// rebind succeeded". That is strictly wider than the property: a leg that fails
// to be ENABLED leaves no listener behind at all, so nothing is serving an
// unsanctioned address, yet the proxy withheld anyway. These tests pin the
// property directly (`everyLiveLegNamedBy`) and pin the two things that make the
// withholding acceptable when it IS justified: it is an intersection, and it is
// EXITABLE by a subsequent commit.
package daemon

import (
	"context"
	"testing"

	"github.com/psaab/xpf/pkg/api"
)

// TestMgmtFailedHTTPSEnableStillGrantsOnTheUnmovedListener_5561 is the
// fail-on-revert gate for the round-13 MAJOR.
//
// The sequence is an ordinary one: a single commit rotates the web-management
// password AND enables TLS. The HTTPS bind fails (port already held by
// something else on the box). The HTTP listener is at exactly the address this
// commit named and never moved — and no HTTPS listener exists, because
// api.Server.ReconcileHTTPS assigns s.httpsLeg only after both the keypair and
// the bind succeed. So NO listener anywhere is at an address this config did
// not name, and the reason the grant half is ever withheld does not apply.
//
// Under the `rebinding && len(errs) == 0` proxy it was withheld regardless:
// `next.TLS != m.cur.tls` made `rebinding` true and the HTTPS error made
// `len(errs) != 0`, so the early intersection stood. For the dominant
// deployment shape — one account whose password changes — the intersection of
// {webadmin: old} with {webadmin: new} is EMPTY, and an empty non-nil snapshot
// makes dynamicAuthMiddleware reject every non-exempt request. The REST
// management API 401s every caller on the address the operator committed, while
// the commit reports success.
//
// Worse, that state could not be left. The empty set is absorbing under the
// intersection (∅ ∩ X = ∅ for every X), and the endpoint fingerprint never
// converges while port 443 stays held, so neither re-committing the identical
// config nor rotating again restored access; only backing the TLS enable out
// did. The exitability property is pinned separately below.
//
// FAIL-ON-REVERT: restore the `len(errs) == 0` proxy (or gate the late publish
// on anything other than where the live legs actually are) and the rotated
// secret never reaches the listener that never moved.
func TestMgmtFailedHTTPSEnableStillGrantsOnTheUnmovedListener_5561(t *testing.T) {
	reg := newFakeReg()
	m := newTestMgmt(reg)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Live: plain HTTP on a routable address with one account.
	a := &api.AuthConfig{Users: map[string]string{"webadmin": "secret-a"}}
	if err := m.startTo(ctx, cfgFor(reg, "10.0.0.1:80", false, "", a)); err != nil {
		t.Fatalf("initial start: %v", err)
	}
	httpLn := reg.get("10.0.0.1:80")

	// One commit: rotate the password AND enable TLS. Port 443 is held.
	reg.failAddr["10.0.0.1:443"] = true
	b := &api.AuthConfig{Users: map[string]string{"webadmin": "secret-b"}}
	if err := m.reconcileTo(cfgFor(reg, "10.0.0.1:80", true, "10.0.0.1:443", b)); err == nil {
		t.Fatal("the HTTPS enable was expected to FAIL, so the case never reached the state it tests")
	}

	// Preconditions: the HTTP leg never moved, and no HTTPS listener exists.
	if m.cur.addr != "10.0.0.1:80" {
		t.Fatalf("HTTP fingerprint = %q, want the unmoved 10.0.0.1:80", m.cur.addr)
	}
	if httpLn == nil || !httpLn.isOpen() {
		t.Fatal("the HTTP listener was disturbed by the HTTPS enable")
	}
	if m.cur.tls {
		t.Fatalf("HTTPS fingerprint advanced (tls=%v httpsAddr=%q) despite a failed bind — "+
			"the case assumes the leg never came up", m.cur.tls, m.cur.httpsAddr)
	}
	if ln := reg.get("10.0.0.1:443"); ln != nil && ln.isOpen() {
		t.Fatal("an HTTPS listener is open at 10.0.0.1:443 despite the bind failing — " +
			"the case assumes nothing is serving that address")
	}

	// The property: the committed credential is live on the listener the commit
	// named and never moved.
	snap := m.srv.LiveAuth()
	if snap == nil {
		t.Fatal("the live snapshot went nil on a failed HTTPS enable — that drops api-auth " +
			"entirely on a routable listener")
	}
	if api.CredentialCount(snap) == 0 {
		t.Fatalf("live snapshot = %+v — EVERY credential was withheld. The HTTP listener is at "+
			"10.0.0.1:80, exactly the address this commit named, and it never moved; no listener "+
			"anywhere is at an address the config did not name, so the reason to withhold does "+
			"not apply. An empty non-nil snapshot rejects every non-exempt request, so the "+
			"management API on the committed address now 401s every caller while the commit "+
			"reported success", snap)
	}
	if got := snap.Users["webadmin"]; got != "secret-b" {
		t.Fatalf("live snapshot = %+v, want the committed secret-b on the listener this commit "+
			"named. A failure to ENABLE a leg leaves nothing serving an unsanctioned address, so "+
			"it must not withhold the grant half", snap)
	}
	// The revocation half still landed — this is a rotation, and the old secret
	// must be gone whatever the HTTPS outcome (#5561 round 7).
	if got := snap.Users["webadmin"]; got == "secret-a" {
		t.Fatalf("live snapshot = %+v still authorizes the superseded secret-a", snap)
	}
}

// TestMgmtFailedHTTPSEnableStillGrantsAfterAConvergedHTTPMove_5561 is the same
// defect at the other gate.
//
// The fix has two halves, because the predicate is read twice. Read BEFORE the
// rebinds it decides whether the early publish is the whole set or the
// intersection; read AFTER, whether the full set still goes out. The case above
// is settled by the first read alone (nothing moved, so it was sanctioned from
// the start). This one is settled only by the second: the HTTP bind DOES move,
// so the early publish is correctly an intersection — and then the move
// SUCCEEDS while the bundled TLS enable fails.
//
// After the rebinds the only listener serving is the new HTTP one, at exactly
// the address this commit named; the HTTPS leg does not exist. So the full
// committed set must go out. `len(errs) == 0` said otherwise — some call in the
// batch returned an error — and left the operator's rotated credential
// withheld, i.e. the same deny-all on the address they had just committed and
// successfully bound.
//
// FAIL-ON-REVERT: put `len(errs) == 0` back on the late gate and this reds while
// the previous test still passes.
func TestMgmtFailedHTTPSEnableStillGrantsAfterAConvergedHTTPMove_5561(t *testing.T) {
	reg := newFakeReg()
	m := newTestMgmt(reg)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	a := &api.AuthConfig{Users: map[string]string{"webadmin": "secret-a"}}
	if err := m.startTo(ctx, cfgFor(reg, "10.0.0.1:80", false, "", a)); err != nil {
		t.Fatalf("initial start: %v", err)
	}

	// One commit: move the HTTP bind, rotate the password, and enable TLS. The
	// move succeeds; port 443 is held, so the enable fails.
	reg.failAddr["10.0.0.1:443"] = true
	b := &api.AuthConfig{Users: map[string]string{"webadmin": "secret-b"}}
	if err := m.reconcileTo(cfgFor(reg, "10.0.0.2:80", true, "10.0.0.1:443", b)); err == nil {
		t.Fatal("the HTTPS enable was expected to FAIL, so the case never reached the state it tests")
	}

	// Preconditions: the HTTP leg CONVERGED onto the committed address (so the
	// early read was an intersection and only the late one can settle this), and
	// no HTTPS listener exists.
	if m.cur.addr != "10.0.0.2:80" {
		t.Fatalf("HTTP fingerprint = %q, want the converged 10.0.0.2:80 — the case assumes the "+
			"move succeeded", m.cur.addr)
	}
	if m.cur.tls {
		t.Fatalf("HTTPS fingerprint advanced (tls=%v httpsAddr=%q) despite a failed bind",
			m.cur.tls, m.cur.httpsAddr)
	}
	if ln := reg.get("10.0.0.1:443"); ln != nil && ln.isOpen() {
		t.Fatal("an HTTPS listener is open at 10.0.0.1:443 despite the bind failing")
	}

	snap := m.srv.LiveAuth()
	if snap == nil {
		t.Fatal("the live snapshot went nil — that drops api-auth entirely on a routable listener")
	}
	if got := snap.Users["webadmin"]; got != "secret-b" {
		t.Fatalf("live snapshot = %+v, want the committed secret-b. The HTTP leg converged onto "+
			"10.0.0.2:80 — the address this commit named — and the HTTPS leg never came up, so "+
			"NO listener is serving an address the config did not name. Gating the grant on "+
			"\"every call in the batch returned nil\" instead of on where the live legs ended up "+
			"denies every caller on an endpoint the operator committed AND successfully bound", snap)
	}
}

// TestMgmtWithheldGrantIsExitableByASubsequentCommit_5561 pins what makes the
// withholding acceptable in the case where it IS justified.
//
// When a listener really is retained at an address the commit asked to leave,
// the published set is the intersection with what that listener already
// accepted, and for a single-account rotation that intersection is EMPTY. An
// empty set denies everyone, and it is absorbing: no later intersection can
// re-introduce a credential, because the loop keeps only values already present
// in the live snapshot.
//
// That is tolerable only because the state has an EXIT that a subsequent commit
// can reach. Two exits exist and both are pinned here:
//
//   - fix the endpoint — the failing bind converges, every live leg is at an
//     address the config names, and the full committed set publishes; or
//   - back the endpoint change out — commit the address that is actually
//     serving, which has nothing to converge and publishes whole.
//
// The absorbing algebra is left as it is deliberately. Refusing to represent ∅
// would mean keeping some credential the committed config no longer carries on
// a listener the operator asked to leave, which is exactly the round-7
// fail-open (a replaced secret honoured indefinitely on the retained listener).
// The defect was never that ∅ is representable; it was that the gate entered it
// with no listener retained anywhere, in a configuration whose fingerprint could
// never converge — a state with no exit at all. This test is the standing check
// that every ∅ the gate can enter has one.
func TestMgmtWithheldGrantIsExitableByASubsequentCommit_5561(t *testing.T) {
	// Exit 1: the endpoint converges on a later commit.
	t.Run("the failing bind converges", func(t *testing.T) {
		reg := newFakeReg()
		m := newTestMgmt(reg)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		a := &api.AuthConfig{Users: map[string]string{"webadmin": "secret-a"}}
		if err := m.startTo(ctx, cfgFor(reg, "10.0.0.1:80", false, "", a)); err != nil {
			t.Fatalf("initial start: %v", err)
		}
		reg.failAddr["10.0.0.2:80"] = true
		b := &api.AuthConfig{Users: map[string]string{"webadmin": "secret-b"}}
		if err := m.reconcileTo(cfgFor(reg, "10.0.0.2:80", false, "", b)); err == nil {
			t.Fatal("the HTTP rebind was expected to FAIL")
		}
		// The justified withholding: 10.0.0.1:80 is retained and this commit
		// asked to leave it, so the single-account rotation empties the set.
		if snap := m.srv.LiveAuth(); api.CredentialCount(snap) != 0 {
			t.Fatalf("live snapshot = %+v, want the empty intersection — the case assumes the "+
				"state whose exit it is testing", snap)
		}
		// Re-committing the identical config does not recover, by construction.
		_ = m.reconcileTo(cfgFor(reg, "10.0.0.2:80", false, "", b))
		if snap := m.srv.LiveAuth(); api.CredentialCount(snap) != 0 {
			t.Fatalf("live snapshot = %+v after an identical re-commit; the case assumes ∅ is "+
				"absorbing, so the exits below are the only ones", snap)
		}

		// EXIT: the operator frees the port and re-commits.
		delete(reg.failAddr, "10.0.0.2:80")
		if err := m.reconcileTo(cfgFor(reg, "10.0.0.2:80", false, "", b)); err != nil {
			t.Fatalf("converging reconcile: %v", err)
		}
		if snap := m.srv.LiveAuth(); snap == nil || snap.Users["webadmin"] != "secret-b" {
			t.Fatalf("live snapshot = %+v after the bind converged. Every live leg is now at an "+
				"address the config names, so the full committed set must publish — otherwise the "+
				"deny-all has no exit and the operator is locked out of the REST API permanently", snap)
		}
	})

	// Exit 2: the operator backs the endpoint change out.
	t.Run("the endpoint change is backed out", func(t *testing.T) {
		reg := newFakeReg()
		m := newTestMgmt(reg)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		a := &api.AuthConfig{Users: map[string]string{"webadmin": "secret-a"}}
		if err := m.startTo(ctx, cfgFor(reg, "10.0.0.1:80", false, "", a)); err != nil {
			t.Fatalf("initial start: %v", err)
		}
		reg.failAddr["10.0.0.2:80"] = true
		b := &api.AuthConfig{Users: map[string]string{"webadmin": "secret-b"}}
		if err := m.reconcileTo(cfgFor(reg, "10.0.0.2:80", false, "", b)); err == nil {
			t.Fatal("the HTTP rebind was expected to FAIL")
		}
		if snap := m.srv.LiveAuth(); api.CredentialCount(snap) != 0 {
			t.Fatalf("live snapshot = %+v, want the empty intersection", snap)
		}

		// EXIT: commit the address that is actually serving. Nothing has to
		// converge, so the full set goes out.
		if err := m.reconcileTo(cfgFor(reg, "10.0.0.1:80", false, "", b)); err != nil {
			t.Fatalf("back-out reconcile: %v", err)
		}
		if snap := m.srv.LiveAuth(); snap == nil || snap.Users["webadmin"] != "secret-b" {
			t.Fatalf("live snapshot = %+v after the operator committed the address that is "+
				"actually serving. That commit moves nothing, so the full set must publish", snap)
		}
	})
}

// TestMgmtNilAuthNeverDropsARetainedOffLoopbackHTTPSLeg_5561 binds the HTTPS
// conjunct of the nil-auth gate:
//
//	next.Auth == nil && mgmtAddrIsLoopback(m.cur.addr) &&
//	    (!m.cur.tls || mgmtAddrIsLoopback(m.cur.httpsAddr))
//
// The sibling conjunct (the live HTTP address) is pinned by
// TestMgmtReconcileRemoveAuthDeniesAllWhenHTTPRebindFails_5866. This one was not
// pinned by anything: deleting it left the whole pkg/daemon suite green.
//
// The state it guards is reachable in one commit. Removing ALL api-auth makes
// resolveAPIBinds clamp BOTH binds to loopback (#4047/#5127), and the legs
// reconcile independently: the HTTP leg converges onto loopback while the HTTPS
// leg's bind fails, so the fail-safe RETAINS the previous off-loopback HTTPS
// listener — and it is still serving. The HTTP conjunct is then satisfied (the
// live HTTP address really is loopback) and only this conjunct stands between
// the commit and publishing a nil snapshot, which is dynamicAuthMiddleware's
// pass-through: an unauthenticated, mutating REST/config API reachable from the
// network.
//
// FAIL-ON-REVERT: delete the `mgmtAddrIsLoopback(e.httpsAddr)` conjunct from
// mgmtEndpoint.allLoopback and the live snapshot goes nil here while
// 10.0.0.1:8443 is serving.
//
// What the retained leg enforces INSTEAD of the nil is the deny-all set (#5561
// round 14, MAJOR 4), not the credential the commit deleted — asserted below.
func TestMgmtNilAuthNeverDropsARetainedOffLoopbackHTTPSLeg_5561(t *testing.T) {
	reg := newFakeReg()
	m := newTestMgmt(reg)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Live: both legs off-loopback, credentialed (legitimate — auth present).
	a := &api.AuthConfig{Users: map[string]string{"webadmin": "secret"}}
	if err := m.startTo(ctx, cfgFor(reg, "10.0.0.1:8080", true, "10.0.0.1:8443", a)); err != nil {
		t.Fatalf("initial start: %v", err)
	}
	oldHTTPS := reg.get("10.0.0.1:8443")

	// The commit removes ALL api-auth, so both binds clamp to loopback. The HTTP
	// leg converges; the HTTPS leg's bind fails.
	reg.failAddr["127.0.0.1:8443"] = true
	if err := m.reconcileTo(cfgFor(reg, "127.0.0.1:8080", true, "127.0.0.1:8443", nil)); err == nil {
		t.Fatal("the HTTPS rebind was expected to FAIL, so the case never reached the state it tests")
	}

	// Preconditions: HTTP loopback (so the sibling conjunct is SATISFIED and this
	// test is not a duplicate of the HTTP one), HTTPS retained off-loopback and
	// still serving.
	if !mgmtAddrIsLoopback(m.cur.addr) {
		t.Fatalf("live HTTP address = %q, want the converged loopback bind — otherwise the HTTP "+
			"conjunct alone would suppress the nil and this case would prove nothing about the "+
			"HTTPS one", m.cur.addr)
	}
	if !m.cur.tls || mgmtAddrIsLoopback(m.cur.httpsAddr) {
		t.Fatalf("live HTTPS leg = (tls=%v addr=%q), want the RETAINED off-loopback 10.0.0.1:8443",
			m.cur.tls, m.cur.httpsAddr)
	}
	if oldHTTPS == nil || !oldHTTPS.isOpen() {
		t.Fatal("the retained off-loopback HTTPS listener is not serving, so a nil snapshot " +
			"would expose nothing and the case proves nothing")
	}

	// The property.
	if snap := m.srv.LiveAuth(); snap == nil {
		t.Fatalf("api-auth was dropped to nil while the RETAINED HTTPS listener at %q is serving "+
			"off-loopback. A nil snapshot is dynamicAuthMiddleware's pass-through, so the "+
			"mutating REST/config API is now reachable from the network with no credential at "+
			"all. The #4047/#5127 clamp that justified the nil was evaluated against the bind "+
			"this commit attempted, not against the listener that is actually serving — FAIL-OPEN",
			m.cur.httpsAddr)
	} else if pw, ok := snap.Users["webadmin"]; ok {
		t.Fatalf("the retained off-loopback HTTPS listener still accepts webadmin=%q, a credential "+
			"this commit DELETED (#5561 round 14, MAJOR 4). Keeping the previous set alive there "+
			"was the pre-round-14 behavior and it inverted the operator's instruction: the secret "+
			"they removed kept authenticating full-power requests on a routable address for as "+
			"long as the loopback bind kept failing", pw)
	} else if api.CredentialCount(snap) != 0 {
		t.Fatalf("the retained off-loopback HTTPS listener enforces %+v, want the EMPTY (deny-all) "+
			"set — the committed policy authorizes no credential, and deny-all is the only way to "+
			"say that at an address where nil would fail open", snap)
	}

	// Control: the suppression is scoped to the RETAINED off-loopback leg. Once
	// the loopback HTTPS bind converges, both live addresses are loopback and the
	// nil publishes — otherwise the assertion above would also be satisfied by an
	// implementation that never removes api-auth at all.
	delete(reg.failAddr, "127.0.0.1:8443")
	if err := m.reconcileTo(cfgFor(reg, "127.0.0.1:8080", true, "127.0.0.1:8443", nil)); err != nil {
		t.Fatalf("retry reconcile: %v", err)
	}
	if snap := m.srv.LiveAuth(); snap != nil {
		t.Fatalf("post-convergence snapshot = %+v, want nil — both live legs are loopback now, so "+
			"the committed removal of api-auth must take effect", snap)
	}
}

// TestMgmtLiveHTTPSLegIsGrantedWhenTheHTTPLegNeverBound_5561 is the fail-on-revert
// gate for the round-16 MAJOR: `everyLiveLegNamedBy` asserted that "the HTTP leg
// is always serving, at e.addr", and that premise is false when the HTTP leg has
// NEVER bound.
//
// The state is reachable only because of this branch. On master, startTo returned
// early on a boot HTTP bind failure and left m.srv nil, so reconcileTo's
// `m.srv == nil` short-circuit made every later reconcile a no-op — neither leg
// was ever retried. Round 14 fixed that (the server is adopted regardless so the
// bind CAN be retried), and the fix put the reconciler into a configuration the
// gate could not describe: curSet false, m.cur.addr "", and an HTTPS leg that a
// later reconcile successfully binds.
//
// From there the gate compared "" against next.Addr, read FALSE, and treated the
// absent HTTP leg as a listener sitting at an address the config does not name.
// The consequence lands on the HTTPS leg, which is the only listener there is and
// is at exactly the address next names:
//
//   - The early publish intersects, so a ROTATION from {A} to {B} publishes
//     {A} ∩ {B} = ∅ and the live HTTPS listener rejects every credential.
//   - The late full-publish gate re-reads the same predicate, which is still
//     false because m.cur.addr is still "" — so it never converges.
//   - Neither exit named in AuthForRetainedListener's contract is available.
//     "Converge the bind" cannot be reached while the HTTP bind keeps failing,
//     and "commit the address that is actually serving" is not expressible:
//     resolveAPIBinds always yields a non-empty Addr, so no committed config can
//     make next.Addr equal "". Re-committing repeats ∅ ∩ {B} = ∅, which is
//     absorbing.
//
// An empty addr means that leg is not serving and imposes no requirement — the
// same reasoning the HTTPS arm already used for a cleared tls flag, and the same
// reading mgmtAddrIsLoopback already gives an empty bind.
//
// FAIL-ON-REVERT: drop the `e.addr != ""` guard in everyLiveLegNamedBy so the
// absent HTTP leg counts as a mismatch again, and the rotation below locks the
// live HTTPS listener out permanently.
func TestMgmtLiveHTTPSLegIsGrantedWhenTheHTTPLegNeverBound_5561(t *testing.T) {
	reg := newFakeReg()
	m := newTestMgmt(reg)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// The HTTP bind is refused for the whole case; HTTPS is bindable.
	reg.failAddr["10.0.0.1:80"] = true
	a := &api.AuthConfig{Users: map[string]string{"webadmin": "secret-a"}}
	b := &api.AuthConfig{Users: map[string]string{"webadmin": "secret-b"}}

	// Boot: the HTTP bind fails. api.Server.Start returns before it reaches the
	// HTTPS leg, so nothing is serving at all and the fingerprint stays empty.
	if err := m.startTo(ctx, cfgFor(reg, "10.0.0.1:80", true, "10.0.0.1:443", a)); err == nil {
		t.Fatal("the BOOT HTTP bind was expected to fail; without that the reconciler never " +
			"reaches the curSet-false state this case is about")
	}
	if m.curSet || m.cur.addr != "" {
		t.Fatalf("after the failed boot bind: curSet=%v cur.addr=%q, want false and empty — the "+
			"whole case rests on the HTTP leg having never bound", m.curSet, m.cur.addr)
	}

	// The retry commit. HTTP still fails; the HTTPS leg binds and becomes the ONLY
	// live listener — at exactly the address this config names.
	if err := m.reconcileTo(cfgFor(reg, "10.0.0.1:80", true, "10.0.0.1:443", a)); err == nil {
		t.Fatal("the HTTP retry was expected to fail (the HTTPS leg still binds), so the " +
			"reconcile must surface the HTTP error")
	}
	if ln := reg.get("10.0.0.1:443"); ln == nil || !ln.isOpen() {
		t.Fatal("the HTTPS leg did not bind, so there is no live listener to lock out and the " +
			"case proves nothing")
	}
	if m.cur.addr != "" || !m.cur.tls || m.cur.httpsAddr != "10.0.0.1:443" {
		t.Fatalf("fingerprint after the retry = %+v, want an EMPTY http addr with the HTTPS leg "+
			"converged", m.cur)
	}
	if got := m.srv.LiveAuth().Users["webadmin"]; got != "secret-a" {
		t.Fatalf("the raw live snapshot carries %q, want secret-a before the rotation", got)
	}

	// The operator rotates the password. Nothing is serving an address this config
	// does not name, so the full committed set must go out.
	if err := m.reconcileTo(cfgFor(reg, "10.0.0.1:80", true, "10.0.0.1:443", b)); err == nil {
		t.Fatal("the HTTP retry was expected to fail again")
	}
	snap := m.srv.LiveAuth()
	if snap != nil && api.CredentialCount(snap) == 0 {
		t.Fatal("the rotation intersected to the EMPTY set. The only listener serving is the " +
			"HTTPS leg at 10.0.0.1:443, which is exactly the address this config names — there " +
			"is no retained listener anywhere to protect, because the HTTP leg has never bound. " +
			"An empty non-nil snapshot rejects every non-exempt request, so a correctly-named, " +
			"correctly-bound management listener now 401s the operator's own credential")
	}
	if snap == nil || snap.Users["webadmin"] != "secret-b" {
		t.Fatal("the live HTTPS listener does not carry secret-b after the rotation")
	}

	// The exit that does not exist under the defect: re-committing is absorbing,
	// and no committed config can name an empty HTTP address, so ∅ would be
	// permanent.
	if err := m.reconcileTo(cfgFor(reg, "10.0.0.1:80", true, "10.0.0.1:443", b)); err == nil {
		t.Fatal("the HTTP retry was expected to fail on the re-commit too")
	}
	if got := m.srv.LiveAuth().Users["webadmin"]; got != "secret-b" {
		t.Fatalf("re-committing the identical config left the live listener with %q, want secret-b", got)
	}
}
