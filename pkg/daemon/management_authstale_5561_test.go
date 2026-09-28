package daemon

import (
	"context"
	"fmt"
	"net"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/api"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
)

// management_authstale_5561_test.go is the fail-on-revert gate for the #5561
// round-10 finding-3 property: a FAILED listener rebind must never leave a
// SUPERSEDED api-auth credential governing the listener that is actually
// serving.
//
// reconcileTo publishes a non-nil credential set unconditionally — before the
// rebind and regardless of its outcome — because a committed revocation must
// not be blocked by a bind failure (#5561 round 7). That is right only while
// the config it came from is the newest COMMITTED one, and on the apply path it
// need not be: a caller that snapshots store.ActiveConfig() and THEN waits on
// the apply semaphore (the DHCP lease-change callback) can be overtaken by a
// commit and re-enter applyConfig carrying a superseded config. The listener
// stays where the newer commit put it — the stale replay's own rebind fails —
// while the credential the newer commit REPLACED is published onto it.
//
// Both directions are driven here, because the naive repair for one is the
// reintroduction of the other: gating the publish on the rebind outcome (the
// pre-round-7 shape) fixes the stale replay and restores the round-7 fail-open
// in the same edit. The two cases are the SAME shape from inside reconcileTo —
// differing bind, differing credential, failed rebind — and differ only in
// which config is newer, so only the second case's control proves the fix
// discriminates rather than merely refuses.
//
// A THIRD interleaving (#5561 round 12) is the one the first two fixtures could
// not express: the ACTIVE config's api-auth is NIL. Round 10 overrode the stale
// credential only when the active config carried one, so a commit that REMOVED
// api-auth left the stale replay's credential to be published — and, contrary to
// the argument that justified the asymmetry, the listener it lands on need not
// be loopback. See TestMgmtStaleReplayCannotResurrectRemovedAuth_5561 and the
// mgmtAuthConfigRemoveAuth fixture.

// mgmtAuthIfaceAddrs points the bind resolver at two fixed interface addresses,
// so two committed configs resolve to two DIFFERENT listener endpoints without
// depending on the host's real interfaces.
func mgmtAuthIfaceAddrs(t *testing.T) {
	t.Helper()
	prev := interfaceAddrsByName
	t.Cleanup(func() { interfaceAddrsByName = prev })
	interfaceAddrsByName = func(kernelName string) ([]net.Addr, error) {
		switch kernelName {
		case "ge-0-0-0":
			return []net.Addr{&net.IPNet{IP: net.IPv4(10, 0, 0, 1), Mask: net.CIDRMask(24, 32)}}, nil
		case "ge-0-0-1":
			return []net.Addr{&net.IPNet{IP: net.IPv4(10, 0, 0, 2), Mask: net.CIDRMask(24, 32)}}, nil
		}
		return nil, fmt.Errorf("no such kernel interface: %s", kernelName)
	}
}

// mgmtAuthConfigFor is a committed web-management config binding `iface` with
// `secret` as the api-auth password over HTTPS. Clear HTTP cannot carry
// credentials (#10826).
func mgmtAuthConfigFor(iface, secret string) string {
	secret = mgmtAuthTestSecret(secret)
	return "set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24\n" +
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.0.2/24\n" +
		"set system services web-management https system-generated-certificate\n" +
		"set system services web-management https interface " + iface + "\n" +
		"set system services web-management api-auth expires 2099-01-01\n" +
		`set system services web-management api-auth user webadmin password "` + secret + `"` + "\n"
}

func mgmtAuthTestSecret(secret string) string {
	if len(secret) < config.APIAuthBasicPasswordMinRunes {
		return secret + "-long"
	}
	return secret
}

// mgmtAuthCommit commits text through the real configure/load/commit path and
// returns the config it promoted to ACTIVE — which is what an apply caller
// snapshots, and what a later commit supersedes.
func mgmtAuthCommit(t *testing.T, store *configstore.Store, text string) *config.Config {
	t.Helper()
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if _, err := store.LoadSet(text); err != nil {
		t.Fatalf("LoadSet: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	store.ExitConfigure()
	active := store.ActiveConfig()
	if active == nil {
		t.Fatal("store has no active config after commit")
	}
	return active
}

// mgmtAuthSecretMatches checks a live snapshot without exposing its verifier.
func mgmtAuthSecretMatches(t *testing.T, snap *api.AuthConfig, expected string) bool {
	t.Helper()
	if snap == nil {
		return false
	}
	got, ok := snap.Users["webadmin"]
	if !ok {
		return false
	}
	expected = mgmtAuthTestSecret(expected)
	if config.IsAPIAuthSecretHash(got) {
		return config.VerifyAPIAuthSecret(got, expected)
	}
	return got == expected
}

// TestMgmtStaleReplayNeverDrivesTheStaleEndpoint_5561 is the generation fence
// itself (#5561 round 14), and it replaces
// TestMgmtFailedRebindKeepsTheCommittedCredential_5561 — which asserted the same
// credential property but through a mechanism the fence removes.
//
// C1 binds ge-0/0/0 with secret-a; C2 binds ge-0/0/1 with secret-b and is
// committed second, so the live listener is at C2's endpoint under secret-b and
// secret-a is REVOKED. A stale apply then replays C1.
//
// Rounds 10 and 12 pinned only the CREDENTIAL half against the store, which left
// the replay driving the listener toward C1's ENDPOINT under C2's credentials —
// a desired state belonging to no committed generation. Everything downstream
// then reasons about that fiction: the grant gate asks whether every serving leg
// sits at an address `next` names, and `next` names the stale address, so it
// reads TRUE and publishes the full committed set at an endpoint the committed
// config never authorized it for (round 14, MAJOR 3). With the credential half
// nil, the same rewrite yields an off-loopback endpoint with NO authentication
// and nothing left to restore (MAJOR 1).
//
// So the assertion is not about what the stale rebind does — it is that there is
// no stale rebind. The replay's desired state IS the committed one, which is
// already converged, so it is a no-op that republishes secret-b.
//
// withCommittedAuth shape) instead of from the store's active generation, and
// the replay binds 10.0.0.1:443 and moves the live listener onto it.
func TestMgmtStaleReplayNeverDrivesTheStaleEndpoint_5561(t *testing.T) {
	mgmtAuthIfaceAddrs(t)
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))

	// C1 is committed first and then superseded; `stale` is the snapshot an
	// apply caller took before it blocked on the apply semaphore.
	stale := mgmtAuthCommit(t, store, mgmtAuthConfigFor("ge-0/0/0.0", "secret-a"))
	committed := mgmtAuthCommit(t, store, mgmtAuthConfigFor("ge-0/0/1.0", "secret-b"))

	reg := newFakeReg()
	d := &Daemon{store: store}
	m := newManagementReconciler(d, api.Config{ListenFunc: reg.listen})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// The live listener is where the NEWEST commit put it.
	live := m.desired(committed)
	if live.HTTPSAddr != "10.0.0.2:443" {
		t.Fatalf("the committed config resolves to %q, want 10.0.0.2:443 — the fixture is not "+
			"exercising two distinct endpoints", live.HTTPSAddr)
	}
	if err := m.startTo(ctx, live); err != nil {
		t.Fatalf("initial start: %v", err)
	}
	if !mgmtAuthSecretMatches(t, m.srv.LiveAuth(), "secret-b") {
		t.Fatal("the live snapshot does not verify secret-b before the case starts")
	}
	if staleDesired := m.desired(stale); staleDesired.HTTPSAddr != "10.0.0.1:443" {
		t.Fatalf("the stale config resolves to %q, want 10.0.0.1:443 — if the two generations "+
			"named the same endpoint the case could not tell them apart", staleDesired.HTTPSAddr)
	}

	// The stale replay. It must be a no-op: the newest committed generation is
	// already live.
	if err := m.reconcile(stale); err != nil {
		t.Fatalf("the stale replay must reconcile to the ALREADY-CONVERGED committed state, "+
			"which binds nothing and cannot fail: %v", err)
	}

	// The property: the replay never reached for the stale endpoint at all.
	if ln := reg.get("10.0.0.1:443"); ln != nil {
		t.Fatalf("the stale replay bound 10.0.0.1:443 — the endpoint of a generation the store " +
			"has already superseded. Endpoint and credentials must come from ONE committed " +
			"generation; a listener at C1's address under C2's policy is a state the operator " +
			"never committed, and it is the state MAJOR 1 and MAJOR 3 are both reached through")
	}
	if m.cur.httpsAddr != "10.0.0.2:443" {
		t.Fatalf("live HTTPS bind = %q after the stale replay, want the committed 10.0.0.2:443", m.cur.httpsAddr)
	}

	// The credential property the superseded test guarded, restated: the listener
	// that is serving is governed by the COMMITTED credential, never the replay's.
	if !mgmtAuthSecretMatches(t, m.srv.LiveAuth(), "secret-b") {
		t.Fatal("after the stale replay the live listener no longer verifies the committed secret-b; " +
			"it must never accept a superseded credential on this off-loopback bind")
	}
	// Control: the committed listener really is the one still serving, so the
	// assertions above are about a live socket and not a dead one.
	if ln := reg.get("10.0.0.2:443"); ln == nil || !ln.isOpen() {
		t.Fatal("the committed listener at 10.0.0.2:443 is not serving after the replay, " +
			"so the credential governing it is moot and the case proved nothing")
	}
}

// TestMgmtFailedRebindStillRevokesACommittedRotation_5561 is the OTHER
// direction — the #5561 round-7 property, restated here as the control that
// keeps the fix above from being implemented by gating the publish on the
// rebind outcome.
//
// The operator commits BOTH a new endpoint and a new secret. The endpoint's
// bind fails, so the previous listener is retained — and the previous secret
// must stop working on it anyway, because revoking a leaked credential is
// precisely what the operator committed. The REPLACEMENT secret is a different
// question and gets the opposite answer (#5561 round 12): it was committed for
// the endpoint that failed to bind, and the retained listener never accepted it,
// so it is withheld until the rebind converges. Both halves are asserted, since
// each alone is satisfiable by an implementation that gets the other wrong.
//
// FAIL-ON-REVERT: gate the whole non-nil publish on the rebind outcome and the
// retained listener keeps honouring the replaced secret indefinitely, until
// some later reconcile happens to bind.
func TestMgmtFailedRebindStillRevokesACommittedRotation_5561(t *testing.T) {
	mgmtAuthIfaceAddrs(t)
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))

	first := mgmtAuthCommit(t, store, mgmtAuthConfigFor("ge-0/0/0.0", "secret-a"))

	reg := newFakeReg()
	d := &Daemon{store: store}
	m := newManagementReconciler(d, api.Config{ListenFunc: reg.listen})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := m.startTo(ctx, m.desired(first)); err != nil {
		t.Fatalf("initial start: %v", err)
	}
	if !mgmtAuthSecretMatches(t, m.srv.LiveAuth(), "secret-a") {
		t.Fatal("the live snapshot does not verify secret-a before the case starts")
	}

	// The commit the operator actually makes: move the bind AND rotate the
	// secret. The new bind is refused.
	rotated := mgmtAuthCommit(t, store, mgmtAuthConfigFor("ge-0/0/1.0", "secret-b"))
	reg.failAddr["10.0.0.2:443"] = true

	if err := m.reconcile(rotated); err == nil {
		t.Fatal("the rebind was expected to FAIL, so the case never reached the state it " +
			"tests (a retained listener under a rotated credential)")
	}

	snap := m.srv.LiveAuth()
	if snap == nil {
		t.Fatal("the live snapshot went nil on a failed rebind — that drops api-auth entirely " +
			"on an off-loopback listener, the fail-open the whole ordering exists to prevent")
	}
	if mgmtAuthSecretMatches(t, snap, "secret-a") {
		t.Fatal("after a FAILED rebind the retained listener still authorizes secret-a. The " +
			"operator committed a rotation — replacing secret-a means secret-a must stop " +
			"working — and deferring the revocation behind a bind that may never succeed " +
			"leaves the replaced secret live not for a race window but permanently")
	}
	if mgmtAuthSecretMatches(t, snap, "secret-b") {
		t.Fatal("the REPLACEMENT secret was published to the listener at 10.0.0.1:443 — an " +
			"off-loopback address this commit asked to move away from, which never accepted " +
			"secret-b. The operator's containment was to stop serving there; publishing the " +
			"new secret on it undoes that (#5561 round 12)")
	}
	if ln := reg.get("10.0.0.1:443"); ln == nil || !ln.isOpen() {
		t.Fatal("the retained listener at 10.0.0.1:443 is not serving, so the credential " +
			"governing it is moot and the case proved nothing")
	}

	reg.failAddr["10.0.0.2:443"] = false
	if err := m.reconcile(rotated); err != nil {
		t.Fatalf("retry reconcile: %v", err)
	}
	if !mgmtAuthSecretMatches(t, m.srv.LiveAuth(), "secret-b") {
		t.Fatal("post-convergence live listener does not verify secret-b, the committed credential")
	}
}

// mgmtAuthConfigRemoveAuth removes the credential and the off-box HTTPS bind.
// Without an interface, the configured system-generated HTTPS listener resolves
// to loopback, which is valid without API authentication.
func mgmtAuthConfigRemoveAuth() string {
	return "delete system services web-management api-auth\n" +
		"delete system services web-management https interface\n"
}

// TestMgmtStaleReplayCannotResurrectRemovedAuth_5561 is the third interleaving:
// the ACTIVE config has NO api-auth at all.
//
// Round 10 pinned only the non-nil direction of the override, on the argument
// that a stale replay could then over-restrict but never under-restrict,
// "because a resurrected credential over-restricts a management API that is
// clamped to loopback regardless". The premise is false, and this case is the
// counterexample the fixture above could not express.
//
// The #4047/#5127 clamp is evaluated by resolveAPIBinds against the config being
// applied, using THAT config's own api-auth. It is never re-evaluated against
// the listener that is serving. So:
//
//  1. A committed config WITH a credential binds HTTPS off-loopback legitimately —
//     the clamp is a no-op for it.
//  2. A later commit REMOVES api-auth and the HTTPS interface. Its own HTTPS bind
//     resolves to loopback, and that bind FAILS, so the off-loopback listener from
//     step 1 is RETAINED. The nil publish is correctly suppressed, and that listener
//     keeps the credential of step 1.
//  3. The live listener is now NON-loopback while the ACTIVE config's api-auth
//     is nil — the state round 10's premise says cannot exist. The case asserts
//     it directly (m.cur.httpsAddr must not be loopback) before testing anything,
//     so a future change that made the premise TRUE would fail here loudly rather
//     than silently turn the test into a tautology.
//  4. A stale apply replay carrying the credential the operator DELETED finds
//     `committed == nil`, is not overridden, and publishes that credential onto
//     the retained off-loopback listener.
//
// The result is a deleted secret authorizing `POST /api/v1/system/action` from
// off-box: under-restriction, the exact direction round 10 claimed was
// impossible.
//
// FAIL-ON-REVERT: drop the generation fence — make committedDesired return
// m.desired(cfg) without consulting m.d.store.ActiveConfig(). The replay then
// drives C0's own desired state, whose off-loopback bind the fixture does NOT
// refuse, so the reconcile returns nil where the case requires an error (the
// t.Fatal at "the stale replay was expected to retry the committed loopback bind
// and FAIL"), it binds 10.0.0.1:443, and it republishes the deleted secret-a.
//
// Round 14 replaced the credential-only override this instruction used to name
// (`withCommittedAuth`'s `if committed != nil` guard) with that whole-state
// fence, and the function is gone — see committedDesired for why pinning only
// the credential half was itself a defect. The step-3 precondition additionally
// binds publishNilDirectionLocked's DENY-ALL arm: delete
// `m.srv.ReplaceAuth(&api.AuthConfig{})` and the assertion that the retained
// off-loopback listener already enforces the empty set fails instead.
func TestMgmtStaleReplayCannotResurrectRemovedAuth_5561(t *testing.T) {
	mgmtAuthIfaceAddrs(t)
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))

	// C0: the config the stale apply caller snapshotted, with secret-a.
	stale := mgmtAuthCommit(t, store, mgmtAuthConfigFor("ge-0/0/0.0", "secret-a"))
	// C1: moves the listener off-loopback under secret-b, revoking secret-a.
	served := mgmtAuthCommit(t, store, mgmtAuthConfigFor("ge-0/0/1.0", "secret-b"))
	// C2: removes api-auth entirely and is the newest COMMITTED policy.
	removed := mgmtAuthCommit(t, store, mgmtAuthConfigRemoveAuth())

	reg := newFakeReg()
	d := &Daemon{store: store}
	m := newManagementReconciler(d, api.Config{ListenFunc: reg.listen})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := m.startTo(ctx, m.desired(served)); err != nil {
		t.Fatalf("initial start: %v", err)
	}

	// C2 applies: nil auth, with HTTPS resolved to loopback, and that bind fails.
	rm := m.desired(removed)
	if rm.Auth != nil {
		t.Fatalf("the api-auth removal fixture still resolves to a credential (%+v) — the case "+
			"would never reach a COMMITTED NIL, which is the whole point of it", rm.Auth)
	}
	if !rm.TLS || !mgmtAddrIsLoopback(rm.HTTPSAddr) {
		t.Fatalf("the api-auth removal resolves to HTTPS %q (TLS=%v); want a loopback HTTPS bind",
			rm.HTTPSAddr, rm.TLS)
	}
	reg.failAddr[rm.HTTPSAddr] = true
	if err := m.reconcile(removed); err == nil {
		t.Fatal("the loopback HTTPS rebind was expected to FAIL, so the case never reached the state " +
			"it tests (an off-loopback listener retained under a nil-auth active config)")
	}

	// Step 3: the state round 10's premise denies. Asserted, not assumed.
	if mgmtAddrIsLoopback(m.cur.httpsAddr) {
		t.Fatalf("the retained live HTTPS bind is %q, which IS loopback — the case cannot "+
			"demonstrate under-restriction on a clamped listener and proves nothing", m.cur.httpsAddr)
	}

	// The api-auth removal has already revoked secret-b: the committed policy
	// authorizes no credential, and the live listener is off-loopback, so the
	// only expression of that which does not fail open is DENY-ALL (#5561 round
	// 14, MAJOR 4). Keeping secret-b alive here — the pre-round-14 behavior —
	// left a deleted secret authenticating on a routable address indefinitely.
	if snap := m.srv.LiveAuth(); snap == nil || api.CredentialCount(snap) != 0 {
		t.Fatalf("before the replay the retained off-loopback listener enforces %+v, want the "+
			"EMPTY (deny-all) set — C2 deleted api-auth, and a revocation lands immediately "+
			"whatever the rebind does", snap)
	}

	// Step 4: the stale replay. Under the generation fence it reconciles to C2's
	// desired state, not C0's, so it retries the SAME loopback HTTPS bind — which
	// is still refused — and the off-loopback listener keeps serving.
	if err := m.reconcile(stale); err == nil {
		t.Fatal("the stale replay was expected to retry the committed loopback HTTPS bind and FAIL")
	}

	// The property.
	snap := m.srv.LiveAuth()
	if snap == nil {
		t.Fatalf("api-auth was dropped entirely while the live listener is %q — a non-loopback "+
			"management API with no authentication is the fail-open the nil gate exists to "+
			"prevent", m.cur.httpsAddr)
	}
	if got, ok := snap.Users["webadmin"]; ok {
		t.Fatalf("the off-loopback listener at %q accepts webadmin=%q. secret-a was REPLACED by "+
			"one commit and secret-b DELETED by the next; a stale apply replay must not publish "+
			"its own credential over the committed policy, and the committed policy being nil is "+
			"not a licence to keep the old one — it is the case where the operator asked for "+
			"every credential to be gone", m.cur.httpsAddr, got)
	}
	if api.CredentialCount(snap) != 0 {
		t.Fatalf("the retained listener is governed by %+v, want the EMPTY (deny-all) set", snap)
	}
	// The fence itself: the replay never reached for C0's endpoint.
	if ln := reg.get("10.0.0.1:443"); ln != nil {
		t.Fatal("the stale replay bound 10.0.0.1:443, the endpoint of a superseded generation")
	}
	if ln := reg.get("10.0.0.2:443"); ln == nil || !ln.isOpen() {
		t.Fatal("the off-loopback listener at 10.0.0.2:443 is not serving, so the credential " +
			"governing it is moot and the case proved nothing")
	}
}

// TestMgmtStaleReplayWithCommittedNilNeverDropsOffLoopbackToNoAuth_5561 guards
// the hazard the fix above introduces, and the reason the repair is not simply
// "let the ACTIVE nil overwrite the stale credential".
//
// The name is about what must NOT happen: the off-loopback listener is never
// dropped to dynamicAuthMiddleware's pass-through. It does not KEEP a credential
// — the assertion below is CredentialCount == 0, the deny-all set — because the
// committed policy authorizes nobody and the removal lands immediately.
//
// Propagating a committed NIL through a stale replay is only safe because the
// nil publish is gated on the addresses the LIVE listeners are bound to. The
// pre-round-12 gate asked a different question — did the HTTPS rebind succeed? —
// which is a proxy for "the live bind is the one whose #4047/#5127 clamp
// justified the nil". A stale replay breaks the proxy: its endpoint is the OLD
// config's, that config carried a credential, so its bind is legitimately
// off-loopback and it can succeed. The proxy then reads TRUE while the live
// listener is off-loopback, and the nil is published: a routable management API
// with no authentication at all, which is strictly worse than the credential
// resurrection the round-12 fix removes.
//
// FAIL-ON-REVERT: make mgmtEndpoint.allLoopback return true unconditionally
// (`return true` in place of the two mgmtAddrIsLoopback reads). The nil then
// publishes against a live listener at 10.0.0.2:443 and the snapshot goes nil on
// an off-loopback bind — the t.Fatal at "api-auth was removed entirely while the
// live listener is ...".
//
// It is specifically the ADDRESS predicate that this case binds, not the choice
// to gate at all: gating the publish on the HTTPS REBIND OUTCOME — the
// pre-round-12 shape — leaves it GREEN. Under the generation fence the replay
// reconciles to the COMMITTED loopback endpoint, whose bind this fixture refuses,
// so an outcome gate reads FALSE, deny-all publishes, and both assertions below
// hold. The outcome gate is still wrong (it is a proxy for "the live bind is the
// one whose #4047/#5127 clamp justified the nil", and a rebind that SUCCEEDS at an
// off-loopback address satisfies it), but the state that exposes it is not
// reachable from here once the endpoint is fenced to the committed generation.
func TestMgmtStaleReplayWithCommittedNilNeverDropsOffLoopbackToNoAuth_5561(t *testing.T) {
	mgmtAuthIfaceAddrs(t)
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))

	stale := mgmtAuthCommit(t, store, mgmtAuthConfigFor("ge-0/0/0.0", "secret-a"))
	served := mgmtAuthCommit(t, store, mgmtAuthConfigFor("ge-0/0/1.0", "secret-b"))
	removed := mgmtAuthCommit(t, store, mgmtAuthConfigRemoveAuth())

	reg := newFakeReg()
	d := &Daemon{store: store}
	m := newManagementReconciler(d, api.Config{ListenFunc: reg.listen})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := m.startTo(ctx, m.desired(served)); err != nil {
		t.Fatalf("initial start: %v", err)
	}
	// The api-auth removal resolves HTTPS to loopback, but that bind is refused,
	// so the off-loopback listener is retained under the deny-all snapshot.
	rm := m.desired(removed)
	if !rm.TLS || !mgmtAddrIsLoopback(rm.HTTPSAddr) {
		t.Fatalf("the api-auth removal resolves to HTTPS %q (TLS=%v), want loopback HTTPS",
			rm.HTTPSAddr, rm.TLS)
	}
	reg.failAddr[rm.HTTPSAddr] = true
	if err := m.reconcile(removed); err == nil {
		t.Fatal("the loopback HTTPS rebind was expected to FAIL")
	}

	// The stale replay's OWN endpoint is a legitimate off-loopback address (the
	// config it came from carried a credential), and it is bindable — the
	// registry does not refuse it. That is what made the pre-round-14 hybrid
	// dangerous: the rewrite kept C0's endpoint, the bind succeeded, and the
	// off-loopback listener it created was then governed by the committed NIL.
	sd := m.desired(stale)
	if mgmtAddrIsLoopback(sd.HTTPSAddr) {
		t.Fatalf("the stale config resolves to %q; the case needs an off-loopback stale endpoint "+
			"for the hybrid to be able to expose one", sd.HTTPSAddr)
	}
	if reg.failAddr[sd.HTTPSAddr] {
		t.Fatalf("the stale endpoint %q is refused by the fixture, so a hybrid would fail to bind "+
			"it and the case could not reach the state it tests", sd.HTTPSAddr)
	}
	if err := m.reconcile(stale); err == nil {
		t.Fatal("under the generation fence the replay reconciles to the COMMITTED desired " +
			"state, whose loopback HTTPS bind is still refused, so it must still surface an error")
	}

	// The fence: the replay never bound the stale endpoint, so the live listener
	// is still the one the committed generation left retained.
	if ln := reg.get(sd.HTTPSAddr); ln != nil {
		t.Fatalf("the stale replay bound %q. Its endpoint came from a superseded generation and "+
			"its credentials from the newest one — a hybrid the operator never committed. With "+
			"the committed policy NIL, that hybrid is an off-loopback listener with NO "+
			"authentication, and reconcileTo cannot repair it: the nil gate only declines to "+
			"publish ANOTHER nil, and the nil is already live. There is no credential left to "+
			"restore (#5561 round 14, MAJOR 1)", sd.HTTPSAddr)
	}
	if m.cur.httpsAddr != "10.0.0.2:443" {
		t.Fatalf("live HTTPS bind = %q, want the retained 10.0.0.2:443", m.cur.httpsAddr)
	}

	// The property: an off-loopback listener is never dropped to no-auth.
	snap := m.srv.LiveAuth()
	if snap == nil {
		t.Fatalf("api-auth was removed entirely while the live listener is %q — an UNAUTHENTICATED "+
			"routable management API serving the mutating config endpoints. The committed nil is "+
			"justified only by the loopback bind that config asked for, and this is not that bind",
			m.cur.httpsAddr)
	}
	if api.CredentialCount(snap) != 0 {
		t.Fatalf("the live snapshot is %+v, want the EMPTY (deny-all) set: the committed policy "+
			"authorizes no credential at all, and at an off-loopback address the only "+
			"non-fail-open way to say so is to accept nobody (#5561 round 14, MAJOR 4)", snap)
	}
}
