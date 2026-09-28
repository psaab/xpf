package api

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/authz"
	"github.com/psaab/xpf/pkg/configstore"
)

// authz_freshness_5561_test.go is the fail-on-revert gate for the three
// FRESHNESS properties of the #5561 mutation gate — the ones a fixture that
// holds its inputs immutable for the whole request cannot see:
//
//  1. The config snapshot the decision is evaluated against is read AFTER the
//     gate's blocking peer wait, not before it.
//  2. An api-auth credential principal cannot outlive the snapshot that minted
//     it: a revocation landing while the request is blocked must deny it.
//  3. An accept-time lookup slot is RETURNED when the lookup finishes, so the
//     admission pool is a ceiling on concurrency rather than a lifetime budget.
//
// Every case here drives real HTTP through the production constructor
// (buildHTTPServer) so the ConnContext plumbing is on the tested path, and every
// case carries a CONTROL that must NOT deny — a freshness test whose only
// assertion is "403" passes just as well when the endpoint is broken.

// authzRecommit replaces a store's ACTIVE config through the real
// configure/load/commit path, which is what a `commit` from another session
// does while a request is in flight.
func authzRecommit(t *testing.T, store *configstore.Store, text string) {
	t.Helper()
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := store.LoadOverride(text); err != nil {
		t.Fatalf("LoadOverride: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	store.ExitConfigure()
}

// waitForPeerWaiter blocks until a request is parked in the mutation gate's peer
// wait — the happens-before edge that says "the gate has started and has read
// nothing yet".
func waitForPeerWaiter(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if PeerIdentityWaitersForTest() > 0 {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("no request ever parked in the gate's peer wait, so the case never reached the " +
		"window it tests")
}

// authzConfigAdminDemoted is authzTestConfig with adminuser demoted from
// super-user to read-only — the class no longer holds `configure`.
const authzConfigAdminDemoted = `
system {
    host-name authz-test;
    login {
        user opsuser {
            class read-only;
        }
        user adminuser {
            class read-only;
        }
    }
}
`

// authzConfigAdminDeleted is authzTestConfig with adminuser removed from the
// login model entirely — no class governs it, so Authorize denies whatever
// snapshot it is handed.
const authzConfigAdminDeleted = `
system {
    host-name authz-test;
    login {
        user opsuser {
            class read-only;
        }
    }
}
`

// TestConfigSnapshotIsReadAfterThePeerWait_5561 is the round-9 finding-1 guard.
//
// mutationAuthzGuard read the active config and THEN called principal(), whose
// first action is pendingPeer.wait — the only unbounded block in the gate, up to
// peerLookupTimeout (5 seconds). The authorization decision was therefore
// evaluated against a snapshot captured up to five seconds before it was made,
// and a commit landing inside that window did not reach the decision at all: a
// principal demoted or deleted while its own request was blocked kept the
// authority the superseded config gave it.
//
// The window is caller-influenced, which is what makes it more than a race. The
// lookup a request waits on is a socket-table read; a caller that opens
// connections while the table is contended lengthens its own wait, and every
// millisecond it adds is a millisecond of revoked authority it keeps.
//
// Each case runs TWICE against the same fixture: once with no commit (the
// CONTROL) and once with the revoking commit landing while the lookup is
// blocked (which must be denied). Without the control a reverted ordering could
// be "caught" by any unrelated 403.
//
// # Why the route carries a WITHHELD body (#5561 round 18, finding 2)
//
// The first shape of this case drove POST /api/v1/config/enter and asserted
// only "403". That does not bind the ordering it is named for, and the proof is
// mechanical: hoist `cfg := s.activeConfig()` back to before `pending.wait` in
// authorizeInputs — the exact pre-round-9 shape the paragraphs above describe —
// and the case still PASSED. Pass 2 (reauthorizeInputs) is unconditional and
// re-reads the snapshot, and the commit has landed by the time it runs, so a
// stale pass 1 is simply overruled and the caller sees the same 403 either way.
// The round-9 property was entirely subsumed by the round-10/11 two-pass gate.
//
// What distinguishes the two orderings is not WHETHER the request is denied but
// WHEN — before the caller-controlled block or after it. So the request here is
// a body-carrying route (POST /api/v1/config/set, mutationBodyEdit) whose body
// is declared and never sent:
//
//	fixed ordering   pass 1 reads the post-commit snapshot -> 403 arrives while
//	                 the body is still withheld
//	hoisted ordering pass 1 reads the pre-commit snapshot -> ADMITS, and the
//	                 gate parks in bufferMutationBody waiting for a body that
//	                 never comes; nothing answers until apiReadTimeout (30s)
//
// The control arm is what makes the timing assertion mean something: with no
// commit, the same request must PARK rather than answer, which proves the
// withheld body genuinely holds a request that passes pass 1. A prompt 403 in
// the revoked arm can therefore only have come from pass 1.
func TestConfigSnapshotIsReadAfterThePeerWait_5561(t *testing.T) {
	for _, tc := range []struct {
		name    string
		revoked string
		why     string
	}{
		{
			name:    "demoted",
			revoked: authzConfigAdminDemoted,
			why: "adminuser was demoted from super-user to read-only while its own request " +
				"was blocked in the peer lookup",
		},
		{
			name:    "deleted",
			revoked: authzConfigAdminDeleted,
			why: "adminuser was deleted from `system login user` while its own request was " +
				"blocked in the peer lookup",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, commitDuringWait := range []bool{false, true} {
				name := "control-no-commit"
				if commitDuringWait {
					name = "commit-during-wait"
				}
				t.Run(name, func(t *testing.T) {
					usePasswdFixture(t)
					store := authzStore(t, authzTestConfig)

					entered := make(chan struct{}, 1)
					release := make(chan struct{})
					_, base := authzServer(t, Config{
						Addr:  "127.0.0.1:8080",
						Store: store,
						PeerLookupFn: func(net.Addr, net.Addr) authz.PeerIdentity {
							select {
							case entered <- struct{}{}:
							default:
							}
							<-release
							return authz.PeerIdentity{UID: authzUIDSuperuser, OK: true, Local: true}
						},
					})

					// No request from an earlier subtest may still be parked in
					// the drain, or this one's waiter edge would be another
					// case's. Both counters, not just the byte charge: the
					// waiter decrements before the budget releases, so a settled
					// budget implies a settled waiter only for a request that
					// was charged at all.
					waitForGateQuiescent(t)

					// Headers only: the body is DECLARED and withheld, so a
					// request that gets past pass 1 parks in the gate's drain
					// instead of being answered. openDeclaredBody writes the
					// headers synchronously, so the request reaches the gate
					// immediately.
					const body = `{"input":"set system host-name r18"}`
					// #6977: the baseline for THIS case's park, read before the
					// request exists, so the wait below cannot be satisfied by
					// anyone else's.
					parked := MutationBodyWaitersForTest()
					conn := openDeclaredBody(t, base, "POST /api/v1/config/set", len(body), "", nil)

					// Wait for the accept-time lookup to start...
					select {
					case <-entered:
					case <-time.After(10 * time.Second):
						t.Fatal("the peer lookup never started; the case never reached the window it tests")
					}
					// ...and then for the REQUEST to be parked on it. This second
					// edge is the one that makes the case deterministic, and the
					// first draft of this test did not have it: connContext runs at
					// ACCEPT, so `entered` fires before the request bytes are even
					// read, and a commit landing there is a commit landing BEFORE the
					// gate runs — which both the fixed and the broken ordering answer
					// identically. A parked waiter means the gate has entered
					// authorizeInputs and has not yet returned from the wait, so a
					// snapshot read before the wait has ALREADY happened and one read
					// after it has NOT.
					waitForPeerWaiter(t)
					if commitDuringWait {
						authzRecommit(t, store, tc.revoked)
					}
					close(release)

					if !commitDuringWait {
						// The control's assertion is positive and then negative:
						// the request got PAST pass 1 into the gate's body
						// drain, and stays there rather than being answered. If
						// it did not park, the revoked arm's prompt 403 would
						// prove nothing about WHERE the denial came from.
						waitForNewMutationBodyWaiter(t, parked)
						if status, answered := readStatus(t, conn, time.Second); answered {
							t.Fatalf("the CONTROL answered %d with its body still withheld — a "+
								"super-user with no intervening commit must be admitted by pass "+
								"1 and then park on its caller", status)
						}
						return
					}

					// The window this assertion lives in: the body has not been
					// sent and will not be. Whatever answers here answered
					// WITHOUT it, and the only adjudication that runs before the
					// body is pass 1.
					status, answered := readStatus(t, conn, 5*time.Second)
					if !answered {
						t.Fatalf("nothing answered within 5s while the body was withheld: %s. "+
							"Pass 1 therefore ADMITTED the request and the gate is parked in "+
							"its body drain — the active config was read BEFORE the blocking "+
							"peer wait, so pass 1 was evaluated against the snapshot the commit "+
							"superseded. Pass 2 will overrule it once the caller finishes, but "+
							"that is the round-10 gate doing the work, not this ordering",
							tc.why)
					}
					if status != http.StatusForbidden {
						t.Fatalf("got %d, want 403: %s", status, tc.why)
					}
				})
			}
		})
	}
}

// TestRevokedCredentialCannotFinishAnInFlightRequest_5561 is the round-9
// finding-2 guard.
//
// principal() minted an authz.CredentialPrincipal from the auth snapshot live at
// the moment the credential row was entered, and that principal is a VALUE:
// ReplaceAuth swaps the atomic pointer and cannot reach anything already
// constructed. A credential revoked or rotated mid-request therefore did not
// invalidate the principal already speaking for that request — and Authorize
// short-circuits on Superuser, so the principal is full power.
//
// The gap is not a nanosecond. peerIsLocalNow sits between the mint and the
// decision and BLOCKS: it takes hostAddrScan's single-flight, so a request can
// wait out another goroutine's whole interface enumeration inside that window.
// The test makes that block explicit through Config.PeerLocalityFn, which is the
// production seam for exactly this step.
//
// Both credential SHAPES are covered, because credentialPrincipalUser has two
// arms — a Basic header and an X-API-Key token — and a re-validation added to
// one only would leave the other on the old behaviour.
func TestRevokedCredentialCannotFinishAnInFlightRequest_5561(t *testing.T) {
	const (
		user   = "webadmin"
		secret = "s3cret"
		apiKey = "k3y-aaaaaaaaaaaaaaaaaaaa"
	)
	for _, tc := range []struct {
		name string
		hdrs map[string]string
	}{
		{
			name: "basic",
			hdrs: map[string]string{
				"Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+secret)),
			},
		},
		{
			name: "api-key",
			hdrs: map[string]string{"X-API-Key": apiKey},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, revokeDuringWait := range []bool{false, true} {
				name := "control-no-revocation"
				if revokeDuringWait {
					name = "revoked-during-adjudication"
				}
				t.Run(name, func(t *testing.T) {
					usePasswdFixture(t)

					entered := make(chan struct{}, 1)
					release := make(chan struct{})
					s, base := authzServer(t, Config{
						Addr:  "127.0.0.1:8080",
						Store: authzStore(t, authzTestConfig),
						Auth: &AuthConfig{
							Users:         map[string]string{user: secret},
							UserClasses:   map[string]string{user: "super-user"},
							APIKeys:       map[string]bool{apiKey: true},
							APIKeyClasses: map[string]string{apiKey: "super-user"},
						},
						PeerLookupFn: remotePeer(),
						// The production step this stands in for is
						// authz.PeerCouldBeLocalNow, which single-flights an
						// interface enumeration and so genuinely blocks.
						PeerLocalityFn: func(net.Addr, net.Addr) bool {
							select {
							case entered <- struct{}{}:
							default:
							}
							<-release
							return false
						},
					})

					type result struct {
						status int
						msg    string
					}
					done := make(chan result, 1)
					go func() {
						status, msg := postRoute(t, base, "POST /api/v1/config/enter", tc.hdrs)
						done <- result{status, msg}
					}()

					// The request has authenticated against the LIVE snapshot and is
					// now parked in the locality re-derivation, holding a principal
					// minted from that snapshot.
					select {
					case <-entered:
					case <-time.After(10 * time.Second):
						t.Fatal("the locality re-derivation never started; the case never reached " +
							"the window it tests")
					}
					if revokeDuringWait {
						// Exactly what a `delete system services web-management
						// ... api-auth` commit does: ReplaceAuth with a policy that
						// no longer honours the presented credential.
						s.ReplaceAuth(&AuthConfig{Users: map[string]string{"someone-else": "different"}})
					}
					close(release)

					var got result
					select {
					case got = <-done:
					case <-time.After(20 * time.Second):
						t.Fatal("the request never completed")
					}

					if !revokeDuringWait {
						if got.status == http.StatusForbidden || got.status == http.StatusUnauthorized {
							t.Fatalf("the CONTROL was refused (%d, %q) — an off-box caller holding a "+
								"VALID credential must be admitted, so the refusal below would prove "+
								"nothing", got.status, got.msg)
						}
						return
					}
					if got.status == http.StatusOK {
						t.Fatalf("a request whose api-auth credential was REVOKED while it was "+
							"blocked in the locality re-derivation was still authorized (%d). The "+
							"credential principal was minted from the superseded snapshot and "+
							"ReplaceAuth cannot reach it, so revoking a leaked secret does not stop "+
							"a request already in flight", got.status)
					}
				})
			}
		})
	}
}

// TestCredentialRereadDeniesBeforeTheBodyIsSupplied_5561 isolates the credential
// re-read the case above cannot distinguish (#6645 r22, finding 1).
//
// TestRevokedCredentialCannotFinishAnInFlightRequest_5561 proves a DISJUNCTION:
// that at least one live credential re-validation happens between
// Config.PeerLocalityFn and the handler. It cannot say WHICH, because the two
// sites on that path cover for each other, and the masking is measured, not
// reasoned:
//
//	mutation                                                  that case
//	principalFrom's credential branch returns the principal
//	  minted BEFORE the enumeration (drop the re-read)         PASS
//	mutationAuthzGuard's second pass (reauthorizeInputs)
//	  deleted                                                  PASS
//	both                                                       FAIL
//
// So a SINGLE-site regression escapes it, and two guards that each cover for
// the other read as redundancy while actually being a gap.
//
// This case answers the question the second pass cannot, by asking it before
// the second pass exists: a body-carrying route (POST /api/v1/config/set,
// mutationBodyEdit) whose body is declared and never sent. Pass 1 blocks inside
// PeerLocalityFn, the credential is revoked while it is parked, locality is
// released — and the 403 must arrive WITHOUT the body. Only pass 1 runs before
// the body, and within pass 1 only the branch's own re-read can see a
// revocation that landed after the check at the top of principalFrom, so the
// denial has exactly one possible author.
//
// The CONTROL is what makes that timing mean something: with no revocation the
// same request must PARK rather than answer, which proves a withheld body
// genuinely holds a request that passed pass 1. Without it, "a prompt 403"
// would be satisfied by any refusal at all.
//
// Both credential SHAPES are driven for the same reason the case above drives
// them: credentialPrincipalUser has a Basic arm and an X-API-Key arm, and a
// re-validation covering one only leaves the other on the old behaviour.
func TestCredentialRereadDeniesBeforeTheBodyIsSupplied_5561(t *testing.T) {
	const (
		user   = "webadmin"
		secret = "s3cret"
		apiKey = "k3y-aaaaaaaaaaaaaaaaaaaa"
	)
	for _, tc := range []struct {
		name string
		hdrs map[string]string
	}{
		{
			name: "basic",
			hdrs: map[string]string{
				"Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+secret)),
			},
		},
		{
			name: "api-key",
			hdrs: map[string]string{"X-API-Key": apiKey},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, revokeDuringWait := range []bool{false, true} {
				name := "control-no-revocation"
				if revokeDuringWait {
					name = "revoked-during-the-first-pass"
				}
				t.Run(name, func(t *testing.T) {
					usePasswdFixture(t)

					entered := make(chan struct{}, 1)
					release := make(chan struct{})
					s, base := authzServer(t, Config{
						Addr:  "127.0.0.1:8080",
						Store: authzStore(t, authzTestConfig),
						Auth: &AuthConfig{
							Users:         map[string]string{user: secret},
							UserClasses:   map[string]string{user: "super-user"},
							APIKeys:       map[string]bool{apiKey: true},
							APIKeyClasses: map[string]string{apiKey: "super-user"},
						},
						// Off-box, so principalFrom takes the credential row —
						// the only row whose re-read this case isolates.
						PeerLookupFn: remotePeer(),
						// The production step this stands in for
						// (authz.PeerCouldBeLocalNow) single-flights an
						// interface enumeration and so genuinely blocks.
						PeerLocalityFn: func(net.Addr, net.Addr) bool {
							select {
							case entered <- struct{}{}:
							default:
							}
							<-release
							return false
						},
					})

					// The waiter edge below is a process-global count, so no
					// request from another case may still be parked in the drain.
					waitForGateQuiescent(t)

					// Headers only: the body is DECLARED and withheld, so a
					// request that gets past pass 1 parks in the gate's drain
					// instead of being answered.
					const body = `{"input":"set system host-name r22"}`
					// #6977: baseline before this case's own request exists.
					parked := MutationBodyWaitersForTest()
					conn := openDeclaredBody(t, base, "POST /api/v1/config/set", len(body), "", tc.hdrs)

					// The request has authenticated against the LIVE snapshot,
					// entered the credential row, and is now parked in the
					// locality re-derivation — inside PASS 1, before the drain.
					select {
					case <-entered:
					case <-time.After(10 * time.Second):
						t.Fatal("the locality re-derivation never started; the case never " +
							"reached the window it tests")
					}
					if revokeDuringWait {
						// Exactly what a `delete system services web-management
						// ... api-auth` commit does: ReplaceAuth with a policy
						// that no longer honours the presented credential.
						s.ReplaceAuth(&AuthConfig{Users: map[string]string{"someone-else": "different"}})
					}
					close(release)

					if !revokeDuringWait {
						// Positive then negative: the request got PAST pass 1
						// into the gate's body drain, and stays there rather
						// than being answered.
						waitForNewMutationBodyWaiter(t, parked)
						if status, answered := readStatus(t, conn, time.Second); answered {
							t.Fatalf("the CONTROL answered %d with its body still withheld — "+
								"an off-box caller holding a VALID credential must be admitted "+
								"by pass 1 and then park on its caller, or the prompt 403 below "+
								"proves nothing about WHERE the denial came from", status)
						}
						return
					}

					// The window this assertion lives in: the body has not been
					// sent and will not be. Whatever answers here answered
					// WITHOUT it, so pass 2 has not run.
					status, answered := readStatus(t, conn, 5*time.Second)
					if !answered {
						t.Fatal("nothing answered within 5s while the body was withheld. Pass 1 " +
							"therefore ADMITTED a request whose api-auth credential had already " +
							"been revoked, and the gate is parked in its body drain: the " +
							"credential branch returned the principal it minted BEFORE the " +
							"locality enumeration, and ReplaceAuth cannot reach a value. Pass 2 " +
							"will overrule it once the caller finishes — but a caller that never " +
							"finishes holds an admitted, revoked request for the whole " +
							"apiReadTimeout, and pass 2 is the site this case exists to hold " +
							"constant")
					}
					if status != http.StatusForbidden {
						t.Fatalf("got %d, want 403: the credential was revoked while this request "+
							"was parked in the locality re-derivation, and the re-read inside the "+
							"credential branch is what must catch it", status)
					}
				})
			}
		})
	}
}

// slotConn is the minimum net.Conn Server.connContext reads: the two addresses.
type slotConn struct {
	net.Conn
	client, server net.Addr
}

func (c slotConn) RemoteAddr() net.Addr { return c.client }
func (c slotConn) LocalAddr() net.Addr  { return c.server }

// waitSlots polls the admission pool until it holds want tokens.
func waitSlots(t *testing.T, want int, what string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if PeerLookupSlotsInUseForTest() == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("%s: the pool holds %d tokens, want %d", what, PeerLookupSlotsInUseForTest(), want)
}

// waitForPeerLookupsToFinish blocks until at least `want` accept-time lookups
// have been counted AND none is still running (#6645 r22, finding 3).
//
// Both halves are needed, and the second is the one an obvious test omits. The
// lookup runs in a goroutine connContext starts at ACCEPT, and a SAFE request
// never enters the mutation gate — so nothing on the request path waits for it,
// and a case that samples its counter the moment a response lands can read a
// value the lookup has not reached yet. Zero pool occupancy is the only edge
// that says every lookup started so far has finished: connContext releases the
// admission token in the goroutine's LAST defer, after the resolver returns.
//
// It is also why <-p.done is not that edge. Defers run LIFO, so close(p.done)
// runs BEFORE the token is returned — a case that joins on p.done returns while
// the token is still out, which is what waitSlots exists to absorb.
func waitForPeerLookupsToFinish(t *testing.T, count func() int, want int, what string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if count() >= want && PeerLookupSlotsInUseForTest() == 0 {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("%s: %d lookups counted with %d still in flight, want at least %d counted and "+
		"none in flight", what, count(), PeerLookupSlotsInUseForTest(), want)
}

// TestPeerLookupSlotsAreReturned_5561 is the round-9 finding-5 guard: it
// exercises the RELEASE side of the accept-time admission pool.
//
// TestWedgedLookupsDoNotAccumulate_5561 fills the pool with a bare channel send
// and drains it in a defer, so it never acquires a token through connContext and
// the `defer func() { <-peerLookupSlots }()` at the acquire site is unexercised
// by it. Delete that defer and it stays green — while the daemon converts a
// CONCURRENCY ceiling into a LIFETIME budget: the 1024th connection ever
// accepted exhausts the pool permanently, and every connection after it resolves
// to the capacity denial. That is a total management-plane lockout reached by
// ordinary use, with no attacker and no wedge.
//
// Three accounting facts are pinned, which together are the pool's whole
// contract:
//
//	acquire   a running lookup HOLDS a token
//	release   a finished lookup RETURNS it, and the token is genuinely reusable
//	refusal   a connection REFUSED admission neither takes nor returns one
//
// The third is the other edge. A release moved or duplicated into the refusal
// arm would keep this test's first two assertions green while letting the pool
// drain below zero occupancy — i.e. admitting past the cap it exists to enforce.
func TestPeerLookupSlotsAreReturned_5561(t *testing.T) {
	usePasswdFixture(t)

	// The pool is PROCESS-GLOBAL and a preceding case can still be holding a
	// token when this one starts (#6645 r22, finding 3): connContext returns the
	// token in the goroutine's LAST defer, and close(p.done) is deferred after
	// it — so it runs FIRST, and a case that joins on <-p.done (or simply drives
	// HTTP and reads its response) returns while the token is still out. With
	// one already held, the fill below can only take maxConcurrentPeerLookups-1
	// more and the pool reads one OVER, so the case fails on its own
	// precondition — "pool holds 1024 tokens before the case starts, want 1023"
	// — rather than on anything it tests.
	waitSlots(t, 0, "the lookup pool never returned to zero occupancy before this case started")

	// Take every token but one, so a single lookup can be observed against a
	// pool whose occupancy is otherwise pinned.
	//
	// #6974: FROM THE POOL THIS CASE'S OWN CONNECTION WILL USE. The budget is
	// split by whether a connection can reach the interface enumeration, and
	// this fixture's addresses are loopback on both ends, so it draws on the
	// loopback pool. Filling the other one would leave this case's acquire
	// unconstrained and the accounting assertions below would measure nothing.
	// The pool is resolved through the production selector rather than named
	// here, so a case cannot fill one pool while its fixture uses the other.
	slotPool := PeerLookupPoolForTest(
		&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40001},
		&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8080},
	)
	held := 0
	defer func() {
		for i := 0; i < held; i++ {
			<-slotPool
		}
	}()
	for held < maxConcurrentPeerLookups-1 {
		select {
		case slotPool <- struct{}{}:
			held++
		default:
			t.Fatalf("could not fill the lookup pool; %d of %d taken before it refused",
				held, maxConcurrentPeerLookups-1)
		}
	}
	if n := PeerLookupSlotsInUseForTest(); n != maxConcurrentPeerLookups-1 {
		t.Fatalf("pool holds %d tokens before the case starts, want %d", n, maxConcurrentPeerLookups-1)
	}

	entered := make(chan struct{}, 4)
	release := make(chan struct{})
	s := NewServer(Config{
		Addr:  "127.0.0.1:8080",
		Store: authzStore(t, authzTestConfig),
		PeerLookupFn: func(net.Addr, net.Addr) authz.PeerIdentity {
			entered <- struct{}{}
			<-release
			return authz.PeerIdentity{UID: authzUIDSuperuser, OK: true, Local: true}
		},
	})
	conn := slotConn{
		client: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40001},
		server: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8080},
	}

	// ACQUIRE: the running lookup holds the last token.
	ctx := s.connContext(context.Background(), conn)
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatal("the lookup never started, so the acquire path was not exercised")
	}
	if n := PeerLookupSlotsInUseForTest(); n != maxConcurrentPeerLookups {
		t.Fatalf("a RUNNING lookup left the pool at %d, want the full %d — the acquire path "+
			"did not take a token", n, maxConcurrentPeerLookups)
	}

	// REFUSAL: with the pool full, a second connection must be refused WITHOUT
	// disturbing the accounting in either direction.
	refused := s.connContext(context.Background(), conn)
	rp, ok := peerIdentityFrom(refused)
	if !ok {
		t.Fatal("connContext did not attach a pending identity to the refused connection")
	}
	<-rp.done
	if rp.id.OK || !rp.id.Local {
		t.Fatalf("a connection refused admission resolved to %+v, want an unattributable LOCAL "+
			"identity (which denies)", rp.id)
	}
	if n := PeerLookupSlotsInUseForTest(); n != maxConcurrentPeerLookups {
		t.Fatalf("a REFUSED connection moved the pool to %d, want it untouched at %d — the "+
			"refusal arm must neither take a token nor return one it never took",
			n, maxConcurrentPeerLookups)
	}

	// RELEASE: finishing the lookup returns the token.
	close(release)
	p, ok := peerIdentityFrom(ctx)
	if !ok {
		t.Fatal("connContext did not attach a pending identity")
	}
	<-p.done
	if !p.id.OK {
		t.Fatalf("the admitted lookup resolved to %+v, want the injected attribution", p.id)
	}
	waitSlots(t, maxConcurrentPeerLookups-1,
		"a FINISHED lookup did not return its token, so the pool is a lifetime budget rather "+
			"than a concurrency ceiling: the 1024th connection ever accepted locks the "+
			"management plane out permanently")

	// And the returned token is genuinely REUSABLE — the operator-visible half.
	// A connection arriving now must reach the resolver, not the capacity denial.
	// `release` is already closed, so this lookup runs straight through.
	next := s.connContext(context.Background(), conn)
	np, ok := peerIdentityFrom(next)
	if !ok {
		t.Fatal("connContext did not attach a pending identity to the follow-on connection")
	}
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatal("the follow-on connection never reached the resolver: it was refused admission " +
			"even though the previous lookup had finished")
	}
	<-np.done
	if !np.id.OK {
		t.Fatalf("a connection arriving after a completed lookup resolved to %+v, want the "+
			"injected attribution — the token the finished lookup returned was not reusable", np.id)
	}
	waitSlots(t, maxConcurrentPeerLookups-1, "the follow-on lookup did not return its token")
}

// withheldBody is a mutating request whose HEADERS have been sent and whose
// BODY has not. It is the shape the gate's second adjudication exists for: the
// caller, not the server, decides when the handler's decode can finish.
//
// It speaks HTTP on a raw connection rather than going through http.Client on
// purpose. A client-side io.Pipe body does NOT reproduce the case: net/http
// buffers the request headers and only flushes them once the body produces
// bytes (or an Expect: 100-continue handshake forces it), so a withheld body
// withholds the headers too and the server never starts the request at all.
type withheldBody struct {
	conn net.Conn
	req  *http.Request
}

// openWithheldBody sends `route`'s request line and headers, declaring a
// two-byte body that finish() supplies later.
func openWithheldBody(t *testing.T, base, route string, hdrs map[string]string) *withheldBody {
	t.Helper()
	method, path, ok := strings.Cut(route, " ")
	if !ok {
		t.Fatalf("malformed route key %q", route)
	}
	addr := strings.TrimPrefix(base, "http://")
	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	var b strings.Builder
	fmt.Fprintf(&b, "%s %s HTTP/1.1\r\n", method, path)
	fmt.Fprintf(&b, "Host: %s\r\n", addr)
	b.WriteString("Content-Type: application/json\r\n")
	b.WriteString("Content-Length: 2\r\n")
	for k, v := range hdrs {
		fmt.Fprintf(&b, "%s: %s\r\n", k, v)
	}
	b.WriteString("Connection: close\r\n\r\n")
	if err := conn.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}
	if _, err := io.WriteString(conn, b.String()); err != nil {
		t.Fatalf("write request headers: %v", err)
	}
	return &withheldBody{conn: conn, req: &http.Request{Method: method}}
}

// finish supplies the withheld body and reads the response.
func (w *withheldBody) finish(t *testing.T) (int, string) {
	t.Helper()
	// A write error here means the server already answered and closed — which is
	// itself a valid outcome to read below, so it is not fatal.
	_, _ = io.WriteString(w.conn, "{}")
	resp, err := http.ReadResponse(bufio.NewReader(w.conn), w.req)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var r Response
	_ = json.Unmarshal(body, &r)
	return resp.StatusCode, r.Error
}

// awaitMutationBodyWaiterAbove reports whether the count of requests parked
// reading a caller's body inside the mutation gate ROSE above baseline within
// `within`. It is the predicate half of waitForNewMutationBodyWaiter, split out
// so a test can drive it with its own deadline and observe a wait that must NOT
// return — t.Fatal from a helper goroutine is not available (#6977).
func awaitMutationBodyWaiterAbove(baseline int, within time.Duration) bool {
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if MutationBodyWaitersForTest() > baseline {
			return true
		}
		time.Sleep(time.Millisecond)
	}
	return false
}

// waitForNewMutationBodyWaiter blocks until a request the CALLER opened is
// parked reading its body inside the mutation gate — the happens-before edge
// that says "the first adjudication has finished and the second has not
// started".
//
// baseline is the count read IMMEDIATELY BEFORE the caller opened that request,
// and the delta is what makes the edge the caller's own (#6977). The counter is
// PROCESS-GLOBAL: every api.Server in the process adds to it. The earlier form
// of this helper accepted any value above zero, so a request some other case
// left parked — or one the SAME case parked a moment earlier, which is the
// commoner shape — satisfied a wait it had nothing to do with, and the case
// proceeded before its own request had reached the gate. Under -shuffle the two
// cases need not even be adjacent in the source.
//
// A bare `> 0` can be made attributable by establishing quiescence first, and
// every call site did exactly that. But that is a convention a caller has to
// remember: the precondition lives in a different statement, sometimes a
// different function, from the wait that depends on it. A delta is attributable
// by construction — a leftover park raises the baseline too, so only a NEW park
// can satisfy the wait — and it needs nothing remembered.
//
// waitForGateQuiescent is still the right postcondition for a case that parks a
// request (authzServer's cleanup runs it), and still the right precondition
// where a case asserts on the aggregate BYTE budget, which is a level rather
// than a delta.
func waitForNewMutationBodyWaiter(t *testing.T, baseline int) {
	t.Helper()
	if awaitMutationBodyWaiterAbove(baseline, 10*time.Second) {
		return
	}
	t.Fatalf("no request the case opened ever parked reading its body inside the gate "+
		"(%d parked, baseline %d), so the case never reached the window it tests",
		MutationBodyWaitersForTest(), baseline)
}

// waitForGateQuiescent blocks until NO request is parked in the gate's body
// drain and nothing is charged against its aggregate budget (#6645 r22,
// finding 2).
//
// It is the precondition every case that waits on those process-global counters
// needs, and the postcondition every case that parks a request owes. Both are
// package-level gauges shared by every api.Server in the process, so "some
// request is parked" and "this case's request is parked" are the same
// observation unless the count is known to have started at zero.
func waitForGateQuiescent(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if MutationBodyWaitersForTest() == 0 && MutationBodyBytesAdmittedForTest() == 0 {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("the gate never went quiescent: %d requests parked reading a body, %d bytes "+
		"charged against the aggregate budget. A case that returns while a request is still "+
		"parked poisons the next case's waiter edge",
		MutationBodyWaitersForTest(), MutationBodyBytesAdmittedForTest())
}

// TestAuthorizationIsRemadeAfterTheCallerSuppliesItsBody_5561 is the round-10
// finding-1 guard.
//
// Ordering the gate's own blocking steps (the two guards above) is necessary and
// not sufficient, because the gate is not the last thing that blocks before the
// mutation runs. The handler is, and it blocks on the one input the CALLER owns
// outright: the request body. decodeJSONBody reads it AFTER the middleware has
// returned its verdict, for as long as apiReadTimeout (30s) allows, and the
// caller chooses how long that takes:
//
//	send headers for POST /api/v1/config/set, withhold the body
//	  -> the gate authorizes and the handler is entered, parked in Decode
//	another session commits a demotion / revokes the credential
//	  -> nothing re-reads it
//	supply the body
//	  -> the mutation runs on an authorization made up to 30 seconds ago
//
// Both revocation shapes are driven, because they are caught by different
// halves of the second adjudication: the config demotion by its fresh
// ActiveConfig() read, the api-auth revocation by its fresh credential check. A
// fix that re-read only one of the two leaves the other on the old behaviour.
//
// Each row runs TWICE, once with no revocation. The control must be ADMITTED:
// without it, a second adjudication that denied EVERYTHING would look like a
// fix.
func TestAuthorizationIsRemadeAfterTheCallerSuppliesItsBody_5561(t *testing.T) {
	const (
		credUser = "webadmin"
		credPass = "s3cret"
	)
	for _, tc := range []struct {
		name string
		// hdrs is the credential the request presents, if any.
		hdrs map[string]string
		// serverFor builds the fixture; revoke performs the revocation that must
		// reach the in-flight request.
		credentialRow bool
		why           string
	}{
		{
			name: "class-demoted-while-body-withheld",
			why: "adminuser was demoted from super-user to read-only while its own request " +
				"sat withholding its body",
		},
		{
			name:          "credential-revoked-while-body-withheld",
			hdrs:          map[string]string{"Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte(credUser+":"+credPass))},
			credentialRow: true,
			why: "the api-auth credential was revoked while the request that presented it sat " +
				"withholding its body",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, revoke := range []bool{false, true} {
				name := "control-no-revocation"
				if revoke {
					name = "revoked-while-body-withheld"
				}
				t.Run(name, func(t *testing.T) {
					usePasswdFixture(t)
					store := authzStore(t, authzTestConfig)

					var enumerations atomic.Int64
					cfg := Config{Addr: "127.0.0.1:8080", Store: store}
					if tc.credentialRow {
						cfg.Auth = &AuthConfig{
							Users:       map[string]string{credUser: credPass},
							UserClasses: map[string]string{credUser: "super-user"},
						}
						cfg.PeerLookupFn = remotePeer()
						cfg.PeerLocalityFn = func(net.Addr, net.Addr) bool {
							enumerations.Add(1)
							return false
						}
					} else {
						cfg.PeerLookupFn = fixedPeerUID(authzUIDSuperuser)
					}
					s, base := authzServer(t, cfg)

					// The waiter edge below is a process-global count, so no
					// request from another case may still be parked in the drain.
					waitForGateQuiescent(t)

					// config/set is a route whose HANDLER genuinely blocks on the
					// caller: configSetHandler decodes the body before it looks at
					// anything else, so the window this case drives is the real one
					// and not an artefact of the gate buffering on a handler's
					// behalf. A route in the mutationBodyNone class would answer
					// without ever entering it.
					// #6977: baseline before the request exists.
					parked := MutationBodyWaitersForTest()
					req := openWithheldBody(t, base, "POST /api/v1/config/set", tc.hdrs)

					// The request has been authorized and is now parked reading the
					// body it has not sent. This is the window, and it is the caller
					// that holds it open.
					waitForNewMutationBodyWaiter(t, parked)
					if revoke {
						if tc.credentialRow {
							// Exactly what `delete system services web-management
							// ... api-auth` does: ReplaceAuth with a policy that no
							// longer honours the presented credential.
							s.ReplaceAuth(&AuthConfig{Users: map[string]string{"someone-else": "different"}})
						} else {
							authzRecommit(t, store, authzConfigAdminDemoted)
						}
					}

					status, msg := req.finish(t)

					if tc.credentialRow {
						// The locality re-derivation is a property of the
						// connection's addresses, which did not change. Adjudicating
						// twice must not enumerate twice — see requestIdentity.
						if got := enumerations.Load(); got != 1 {
							t.Fatalf("the credential row drove %d interface enumerations for ONE "+
								"request, want exactly 1: the second adjudication must reuse the "+
								"connection-fixed locality verdict, not pay for it again", got)
						}
					}
					if !revoke {
						if status == http.StatusForbidden || status == http.StatusUnauthorized {
							t.Fatalf("the CONTROL was refused (%d, %q) — a caller whose authority "+
								"was never revoked must be admitted, so the refusal below would "+
								"prove nothing", status, msg)
						}
						return
					}
					if status != http.StatusForbidden {
						t.Fatalf("got %d, want 403: %s, and the mutation was still authorized "+
							"(error=%q). The gate adjudicated once, BEFORE the caller-controlled "+
							"body read, so the verdict the handler ran under was made up to "+
							"apiReadTimeout before the mutation itself", status, tc.why, msg)
					}
				})
			}
		})
	}
}
