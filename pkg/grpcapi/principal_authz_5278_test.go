package grpcapi

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	"github.com/psaab/xpf/pkg/authz"
	"github.com/psaab/xpf/pkg/configstore"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"github.com/psaab/xpf/pkg/osident"
	"github.com/psaab/xpf/pkg/sysservices"
)

// Per-principal authorization on the PRIMARY gRPC listener (#5278).
//
// Every end-to-end case here runs the PRODUCTION path: Server.Run binds a real
// loopback listener, builds the real interceptor chain (buildPrimaryServer),
// and a real grpc-go client dials it over TCP. Only WHICH uid the kernel would
// report is injected (Config.PeerLookupFn), so a case can state which principal
// is calling instead of testing whichever account runs the suite; the kernel
// lookup behind it is covered against live sockets in pkg/authz, and
// TestProductionServerEnforcesRealPeerIdentity_5278 closes the loop here with
// no injection at all.

const (
	authzUIDReadOnly  = 4242
	authzUIDOperator  = 4243
	authzUIDSuperuser = 4244
	authzUIDStranger  = 4245 // a real OS account that is NOT a `system login user`
)

// authzConfig5278 is the active config every case is evaluated against. Three
// provisioned login users with different classes, so a denial is attributable
// to the CLASS rather than to the absence of a login model.
const authzConfig5278 = `
system {
    host-name authz-grpc-test;
    login {
        user opsuser {
            class read-only;
        }
        user opuser {
            class operator;
        }
        user adminuser {
            class super-user;
        }
    }
}
`

// authzPasswd5278 maps the UIDs above to account names. It replaces
// /etc/passwd for the duration of a case so the resolution path (uid -> name ->
// class) runs for real against identities the test controls.
const authzPasswd5278 = `root:x:0:0:root:/root:/bin/bash
opsuser:x:4242:4242::/home/opsuser:/bin/bash
opuser:x:4243:4243::/home/opuser:/bin/bash
adminuser:x:4244:4244::/home/adminuser:/bin/bash
stranger:x:4245:4245::/home/stranger:/bin/bash
`

// usePasswdFixture5278 points the shared uid resolver at authzPasswd5278.
func usePasswdFixture5278(t *testing.T) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "passwd")
	if err := os.WriteFile(path, []byte(authzPasswd5278), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(authz.SetPasswdPathForTest(path))
}

// authzStore5278 returns a store whose ACTIVE config is `text`, committed
// through the real configure/load/commit path so the login model the gate reads
// is a genuinely compiled one.
func authzStore5278(t *testing.T, text string) *configstore.Store {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
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
	if store.ActiveConfig() == nil {
		t.Fatal("store has no active config after commit")
	}
	return store
}

// fixedPeerUID5278 builds a resolver that attributes every connection to uid,
// the way an attributed kernel lookup would.
func fixedPeerUID5278(uid uint32) func(client, server net.Addr) authz.PeerIdentity {
	return func(net.Addr, net.Addr) authz.PeerIdentity {
		return authz.PeerIdentity{UID: uid, OK: true, Local: true}
	}
}

// runPrimaryListener starts the PRODUCTION primary listener on an ephemeral
// loopback port and returns a client dialed to it.
func runPrimaryListener(t *testing.T, cfg Config) pb.BpfrxServiceClient {
	t.Helper()
	return dialPrimary(t, serveAndWait(t, NewServer("127.0.0.1:0", cfg)))
}

// serveAndWait runs s.Run (the production path: clamp, bind, buildPrimaryServer,
// serve) and returns the address it actually bound.
func serveAndWait(t *testing.T, s *Server) string {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = s.Run(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Error("primary gRPC listener did not shut down")
		}
	})

	// Wait for the bind. EffectiveListener reports the requested address while
	// pre-bind, so poll until it reports a bound one.
	var addr string
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		l := s.EffectiveListener()
		if l.State == sysservices.StateListening && l.Addr != "127.0.0.1:0" {
			addr = l.Addr
			break
		}
		if l.State == sysservices.StateFailed {
			t.Fatalf("primary gRPC listener failed to bind (%s)", l.Addr)
		}
		time.Sleep(2 * time.Millisecond)
	}
	if addr == "" {
		t.Fatal("primary gRPC listener never reported a bound address")
	}
	return addr
}

// dialPrimary opens ONE new client connection to addr. Each call is a separate
// TCP connection, which is what lets a case observe per-connection identity.
func dialPrimary(t *testing.T, addr string) pb.BpfrxServiceClient {
	t.Helper()
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return pb.NewBpfrxServiceClient(conn)
}

// stubPowerActions replaces the reboot/halt/power-off scheduler so an ADMITTED
// destructive call proves admission without taking the host down.
func stubPowerActions(t *testing.T) *[]string {
	t.Helper()
	orig := schedulePowerAction
	t.Cleanup(func() { schedulePowerAction = orig })
	var fired []string
	schedulePowerAction = func(arg string) { fired = append(fired, arg) }
	return &fired
}

// callCtx bounds every RPC so a wedged gate fails the test instead of hanging it.
func callCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// assertDenied fails unless err is a PermissionDenied naming the login model.
func assertDenied(t *testing.T, what string, err error) {
	t.Helper()
	st, ok := status.FromError(err)
	if !ok || st.Code() != codes.PermissionDenied {
		t.Fatalf("%s: got err=%v (code %v), want PermissionDenied — the caller's "+
			"login class does not hold the permission this RPC requires (#5278)",
			what, err, status.Code(err))
	}
	if !strings.Contains(st.Message(), "permission denied") {
		t.Errorf("%s: denial message %q does not say permission denied", what, st.Message())
	}
	if !strings.Contains(st.Message(), "system login user") {
		t.Errorf("%s: denial message %q does not name the remedy (the `system "+
			"login user <name> class <class>` stanza an operator must change)",
			what, st.Message())
	}
}

// assertNotDenied fails only on PermissionDenied. A handler may legitimately
// fail for an unrelated reason (no dataplane, no cluster, nothing staged) —
// what this asserts is that the GATE admitted the call.
func assertNotDenied(t *testing.T, what string, err error) {
	t.Helper()
	if status.Code(err) == codes.PermissionDenied {
		t.Fatalf("%s: got PermissionDenied (%v); this principal holds the "+
			"permission and must be admitted — a blanket-deny gate would also "+
			"pass every denial assertion in this file (#5278)", what, err)
	}
}

// TestReadOnlyClassIsDeniedDestructiveRPCs_5278 is the issue: a `read-only`
// login-class holder with a provisioned shell dials 127.0.0.1:50051 directly
// and must NOT be able to zeroize, commit, delete or roll back.
//
// RED on revert: remove the interceptors from buildPrimaryServer (every case
// admits), or price any of these methods at PermView.
func TestReadOnlyClassIsDeniedDestructiveRPCs_5278(t *testing.T) {
	usePasswdFixture5278(t)
	client := runPrimaryListener(t, Config{
		Store:        authzStore5278(t, authzConfig5278),
		PeerLookupFn: fixedPeerUID5278(authzUIDReadOnly),
	})
	ctx := callCtx(t)

	// SystemAction{zeroize} is safe to issue here precisely because it must be
	// DENIED: a denial never reaches the handler, so no wipe runs. The admitted
	// direction is proven with the stubbed reboot verb below.
	_, err := client.SystemAction(ctx, &pb.SystemActionRequest{Action: "zeroize"})
	assertDenied(t, "SystemAction{zeroize}", err)

	_, err = client.Commit(ctx, &pb.CommitRequest{})
	assertDenied(t, "Commit", err)

	_, err = client.Rollback(ctx, &pb.RollbackRequest{})
	assertDenied(t, "Rollback", err)

	_, err = client.Delete(ctx, &pb.DeleteRequest{Input: "system host-name"})
	assertDenied(t, "Delete", err)

	_, err = client.EnterConfigure(ctx, &pb.EnterConfigureRequest{})
	assertDenied(t, "EnterConfigure", err)
}

// TestReadOnlyClassIsAllowedAViewRPC_5278 is the negative control for the case
// above. Without it, a gate that denied EVERYTHING would pass every denial
// assertion in this file and read as a working fix.
func TestReadOnlyClassIsAllowedAViewRPC_5278(t *testing.T) {
	usePasswdFixture5278(t)
	client := runPrimaryListener(t, Config{
		Store:        authzStore5278(t, authzConfig5278),
		PeerLookupFn: fixedPeerUID5278(authzUIDReadOnly),
	})
	ctx := callCtx(t)

	_, err := client.GetStatus(ctx, &pb.GetStatusRequest{})
	assertNotDenied(t, "GetStatus", err)

	// #9324 SPLIT THIS ASSERTION rather than inverting it. This cell's stated
	// job — "without it, a gate that denied EVERYTHING would pass every denial
	// assertion in this file" — is unchanged and still needs a ShowConfig that
	// SUCCEEDS. What changed is which ShowConfig a read-only class is entitled
	// to: ConfigTarget's proto3 zero value is CANDIDATE, so the bare
	// `&pb.ShowConfigRequest{}` this line used to send was a request for another
	// session's UNCOMMITTED configuration. Naming ACTIVE keeps the control doing
	// exactly what it was written to do, on the request a read-only principal is
	// actually entitled to.
	_, err = client.ShowConfig(ctx, &pb.ShowConfigRequest{Target: pb.ConfigTarget_ACTIVE})
	assertNotDenied(t, "ShowConfig{ACTIVE}", err)

	// The other half of the split: the request this line used to send is now
	// refused. Kept HERE, beside the control it came from, so the two cannot
	// drift apart — a later edit that relaxes the gate reds this, and a later
	// edit that broadens it reds the arm above.
	_, err = client.ShowConfig(ctx, &pb.ShowConfigRequest{})
	assertDenied(t, "ShowConfig{omitted target == CANDIDATE}", err)

	_, err = client.Complete(ctx, &pb.CompleteRequest{Line: "show "})
	assertNotDenied(t, "Complete", err)
}

// TestSuperUserClassIsAllowedDestructiveRPCs_5278 pins that the fix does not
// cost a legitimate administrator anything.
func TestSuperUserClassIsAllowedDestructiveRPCs_5278(t *testing.T) {
	usePasswdFixture5278(t)
	fired := stubPowerActions(t)
	client := runPrimaryListener(t, Config{
		Store:        authzStore5278(t, authzConfig5278),
		PeerLookupFn: fixedPeerUID5278(authzUIDSuperuser),
	})
	ctx := callCtx(t)

	resp, err := client.SystemAction(ctx, &pb.SystemActionRequest{Action: "reboot"})
	assertNotDenied(t, "SystemAction{reboot}", err)
	if err != nil {
		t.Fatalf("SystemAction{reboot}: %v", err)
	}
	if resp.GetMessage() == "" {
		t.Error("SystemAction{reboot} returned no message; the handler did not run")
	}
	if len(*fired) != 1 || (*fired)[0] != "reboot" {
		t.Errorf("power action scheduler fired %v, want exactly [reboot] — the "+
			"admitted call must reach the handler, not merely avoid a denial", *fired)
	}

	_, err = client.EnterConfigure(ctx, &pb.EnterConfigureRequest{})
	assertNotDenied(t, "EnterConfigure", err)
	_, err = client.Commit(ctx, &pb.CommitRequest{})
	assertNotDenied(t, "Commit", err)
	_, err = client.Rollback(ctx, &pb.RollbackRequest{})
	assertNotDenied(t, "Rollback", err)
	_, err = client.Delete(ctx, &pb.DeleteRequest{Input: "system host-name"})
	assertNotDenied(t, "Delete", err)
}

// TestSuperUserIsAdmittedForZeroizeAtTheGate_5278 covers the one verb the
// end-to-end test above deliberately will not issue in the admitted direction:
// an ADMITTED zeroize really does erase the config root and schedule a daemon
// stop, so admission is asserted at the gate instead of through the handler.
// The gate is the whole subject of #5278; the handler's behaviour is #5281's.
func TestSuperUserIsAdmittedForZeroizeAtTheGate_5278(t *testing.T) {
	usePasswdFixture5278(t)
	s := NewServer("127.0.0.1:0", Config{Store: authzStore5278(t, authzConfig5278)})
	full := "/" + pb.BpfrxService_ServiceDesc.ServiceName + "/SystemAction"
	req := &pb.SystemActionRequest{Action: "zeroize"}

	ctx := ctxWithPeerUID(authzUIDSuperuser)
	if err := s.authorizeRPC(ctx, full, req); err != nil {
		t.Fatalf("super-user SystemAction{zeroize}: %v, want admitted", err)
	}
	if err := s.authorizeRPC(ctxWithPeerUID(authzUIDReadOnly), full, req); err == nil {
		t.Fatal("read-only SystemAction{zeroize} was admitted at the gate")
	}
	if err := s.authorizeRPC(ctxWithPeerUID(authzUIDOperator), full, req); err == nil {
		t.Fatal("operator SystemAction{zeroize} was admitted at the gate; the " +
			"operator class deliberately holds no maintenance permission (#4108 F21)")
	}
}

// ctxWithPeerUID builds the context TagConn would have produced for a
// connection the kernel attributed to uid.
func ctxWithPeerUID(uid uint32) context.Context {
	return context.WithValue(context.Background(), connPeerKey{}, &connPeer{
		id: authz.PeerIdentity{UID: uid, OK: true, Local: true},
	})
}

// TestRootIsAllowed_5278 pins the shipped pkg/authz contract: uid 0 authorizes
// unconditionally, without consulting /etc/passwd or the config. Denying root
// would be theater — it owns the config DB on disk and the daemon process — and
// the in-daemon tooling that dials 127.0.0.1:50051 (pkg/upgrade's rolling and
// kernel upgrade driver) runs as root and must keep working.
func TestRootIsAllowed_5278(t *testing.T) {
	usePasswdFixture5278(t)
	fired := stubPowerActions(t)
	client := runPrimaryListener(t, Config{
		Store:        authzStore5278(t, authzConfig5278),
		PeerLookupFn: fixedPeerUID5278(0),
	})
	ctx := callCtx(t)

	_, err := client.SystemAction(ctx, &pb.SystemActionRequest{Action: "halt"})
	assertNotDenied(t, "root SystemAction{halt}", err)
	if len(*fired) != 1 {
		t.Errorf("root's halt did not reach the handler (scheduler fired %v)", *fired)
	}
	_, err = client.ShowText(ctx, &pb.ShowTextRequest{Topic: "version"})
	assertNotDenied(t, "root ShowText", err)
}

// TestRootIsAllowedWithNoActiveConfig_5278 pins the boot-window half of that
// contract: uid 0 must not depend on a config snapshot existing, or the first
// RPC on a box whose config has not loaded yet would be refused.
func TestRootIsAllowedWithNoActiveConfig_5278(t *testing.T) {
	s := NewServer("127.0.0.1:0", Config{}) // no store at all
	full := "/" + pb.BpfrxService_ServiceDesc.ServiceName + "/Commit"
	if err := s.authorizeRPC(ctxWithPeerUID(0), full, nil); err != nil {
		t.Fatalf("uid 0 with no active config: %v, want admitted", err)
	}
	if err := s.authorizeRPC(ctxWithPeerUID(authzUIDReadOnly), full, nil); err == nil {
		t.Fatal("a non-root uid was admitted with no active config; with no " +
			"login model, no class governs the caller and it must be denied")
	}
}

// TestOperatorClassKeepsClearVerbsButNotMaintenance_5278 pins the SystemAction
// verb table: ONE method multiplexes three permission tiers, and folding it up
// to its destructive floor would take `clear interfaces statistics` away from
// the `operator` class that holds it today.
//
// RED on revert: make methodPermission ignore the request and return the
// method-level PermMaint for every SystemAction (the clear verb is denied), or
// price the maintenance verbs below PermMaint (reboot is admitted).
func TestOperatorClassKeepsClearVerbsButNotMaintenance_5278(t *testing.T) {
	usePasswdFixture5278(t)
	fired := stubPowerActions(t)
	client := runPrimaryListener(t, Config{
		Store:        authzStore5278(t, authzConfig5278),
		PeerLookupFn: fixedPeerUID5278(authzUIDOperator),
	})
	ctx := callCtx(t)

	// clear-interfaces-statistics is PermClear and has NO side effect (the
	// handler only reports that kernel counters are cumulative), so admission
	// can be asserted through the real handler.
	resp, err := client.SystemAction(ctx, &pb.SystemActionRequest{Action: "clear-interfaces-statistics"})
	assertNotDenied(t, "operator SystemAction{clear-interfaces-statistics}", err)
	if err != nil {
		t.Fatalf("operator clear verb: %v", err)
	}
	if resp.GetMessage() == "" {
		t.Error("operator clear verb returned no message; the handler did not run")
	}

	_, err = client.SystemAction(ctx, &pb.SystemActionRequest{Action: "reboot"})
	assertDenied(t, "operator SystemAction{reboot}", err)
	if len(*fired) != 0 {
		t.Errorf("a DENIED reboot still reached the handler (scheduler fired %v)", *fired)
	}

	// Same method, config tier: operator holds no configure permission.
	_, err = client.Commit(ctx, &pb.CommitRequest{})
	assertDenied(t, "operator Commit", err)
}

// TestReadOnlyIsDeniedTheClearTier_5278 completes the tier discrimination from
// the other side: read-only holds PermView only, so the SAME clear verb the
// operator keeps is refused.
func TestReadOnlyIsDeniedTheClearTier_5278(t *testing.T) {
	usePasswdFixture5278(t)
	client := runPrimaryListener(t, Config{
		Store:        authzStore5278(t, authzConfig5278),
		PeerLookupFn: fixedPeerUID5278(authzUIDReadOnly),
	})
	ctx := callCtx(t)

	_, err := client.SystemAction(ctx, &pb.SystemActionRequest{Action: "clear-interfaces-statistics"})
	assertDenied(t, "read-only SystemAction{clear-interfaces-statistics}", err)
	_, err = client.ClearSessions(ctx, &pb.ClearSessionsRequest{})
	assertDenied(t, "read-only ClearSessions", err)
}

// TestUnattributablePeerIsDenied_5278 pins the fail-closed direction the
// accept-time capture exists for: a connection whose owning account the kernel
// would not name gets NO access, and the denial says why.
//
// Both PeerIdentity rows that carry OK=false are covered — "local but
// unattributable" and "not on this host" — because this listener has no weaker
// identity to fall through to and must treat them identically.
func TestUnattributablePeerIsDenied_5278(t *testing.T) {
	for _, tc := range []struct {
		name string
		id   authz.PeerIdentity
		want string
	}{
		{
			name: "local but unattributable",
			id:   authz.PeerIdentity{Local: true, Detail: "peer socket is in TCP state 6, not established"},
			want: "not established",
		},
		{
			name: "no socket on this host",
			id:   authz.PeerIdentity{Detail: "peer 10.0.0.9 is not on this host"},
			want: "not on this host",
		},
		{
			name: "socket table unreadable",
			id:   authz.PeerIdentity{Local: true, Detail: "socket table unreadable: permission denied"},
			want: "socket table unreadable",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			usePasswdFixture5278(t)
			id := tc.id
			client := runPrimaryListener(t, Config{
				Store: authzStore5278(t, authzConfig5278),
				PeerLookupFn: func(net.Addr, net.Addr) authz.PeerIdentity {
					return id
				},
			})
			ctx := callCtx(t)

			_, err := client.SystemAction(ctx, &pb.SystemActionRequest{Action: "zeroize"})
			assertDenied(t, "unattributable SystemAction{zeroize}", err)

			// The fail-closed direction must reach the READ surface too: an
			// unattributed caller is not a read-only user, it is nobody.
			_, err = client.GetStatus(ctx, &pb.GetStatusRequest{})
			assertDenied(t, "unattributable GetStatus", err)

			st, _ := status.FromError(err)
			if !strings.Contains(st.Message(), tc.want) {
				t.Errorf("denial message %q does not carry the lookup's reason "+
					"(%q); an operator diagnosing a lockout has nothing else to "+
					"go on", st.Message(), tc.want)
			}
			if !strings.Contains(st.Message(), "could not establish who is calling") {
				t.Errorf("denial message %q does not say the identity was never "+
					"established — that is a different operator problem from a "+
					"class that lacks a permission", st.Message())
			}
		})
	}
}

// TestConnectionIdentityNotCapturedAtAcceptDenies_5278 pins the OTHER
// fail-closed edge: an RPC whose connection never ran TagConn (a server built
// without the stats handler, or a direct in-process call) must be refused, not
// admitted on the strength of an absent identity.
//
// RED on revert: make principalFromContext return a permissive principal — or
// make authorizeRPC skip authorization — when the context carries no connPeer.
func TestConnectionIdentityNotCapturedAtAcceptDenies_5278(t *testing.T) {
	usePasswdFixture5278(t)
	s := NewServer("127.0.0.1:0", Config{Store: authzStore5278(t, authzConfig5278)})

	for _, method := range []string{"SystemAction", "Commit", "GetStatus"} {
		full := "/" + pb.BpfrxService_ServiceDesc.ServiceName + "/" + method
		err := s.authorizeRPC(context.Background(), full, nil)
		if status.Code(err) != codes.PermissionDenied {
			t.Fatalf("%s with no accept-time identity: err=%v, want PermissionDenied", method, err)
		}
		if !strings.Contains(status.Convert(err).Message(), "not captured at accept") {
			t.Errorf("%s denial %q does not name the missing accept-time capture",
				method, status.Convert(err).Message())
		}
	}
}

// TestAccountOutsideTheLoginModelIsDenied_5278 pins the row that is easy to get
// wrong: a REAL, resolvable OS account that no `system login user` stanza
// covers. "Not in the RBAC model" is a reason to deny, not a reason to pick a
// default class.
func TestAccountOutsideTheLoginModelIsDenied_5278(t *testing.T) {
	usePasswdFixture5278(t)
	client := runPrimaryListener(t, Config{
		Store:        authzStore5278(t, authzConfig5278),
		PeerLookupFn: fixedPeerUID5278(authzUIDStranger),
	})
	ctx := callCtx(t)

	_, err := client.GetStatus(ctx, &pb.GetStatusRequest{})
	assertDenied(t, "stranger GetStatus", err)
	if msg := status.Convert(err).Message(); !strings.Contains(msg, "stranger") {
		t.Errorf("denial %q does not name the caller's own account", msg)
	}
}

// TestUnmappedMethodIsDeniedForANonSuperClass_5278 drives the fail-closed
// default through the real gate rather than through the table lookup alone: a
// method name with no entry cannot be reached by the population #5278
// constrains. It is exercised at the gate because grpc-go answers an
// unregistered method with Unimplemented before any interceptor runs, so an
// end-to-end call could not observe the default at all.
func TestUnmappedMethodIsDeniedForANonSuperClass_5278(t *testing.T) {
	usePasswdFixture5278(t)
	s := NewServer("127.0.0.1:0", Config{Store: authzStore5278(t, authzConfig5278)})
	full := "/" + pb.BpfrxService_ServiceDesc.ServiceName + "/FutureDestructiveRPC"

	for _, uid := range []uint32{authzUIDReadOnly, authzUIDOperator} {
		if err := s.authorizeRPC(ctxWithPeerUID(uid), full, nil); status.Code(err) != codes.PermissionDenied {
			t.Fatalf("uid %d on an unmapped method: err=%v, want PermissionDenied "+
				"(an RPC nobody priced must not default open) (#5278)", uid, err)
		}
	}
	// The negative control: a super-user is not locked out of a method whose
	// table row someone forgot, so a missing row is a restriction rather than a
	// dead RPC. The build-time completeness test is what stops it shipping.
	if err := s.authorizeRPC(ctxWithPeerUID(authzUIDSuperuser), full, nil); err != nil {
		t.Fatalf("super-user on an unmapped method: %v, want admitted", err)
	}
}

// TestFabricListenerDoesNotApplyThePrincipalGate_5278 is the behavioural half
// of the chain split (TestPrimaryAndFabricChainsAreDistinct_5278 is the
// structural half): the SAME unattributable peer that the primary listener
// denies must still be served by the fabric listener, whose caller is a cluster
// NODE with no uid on this host.
//
// Without this, "do not touch the fabric listener" would be an assertion about
// source text only, and installing the principal chain on both would break HA
// (every cross-node monitor/show/clear/failover proxy would be denied).
func TestFabricListenerDoesNotApplyThePrincipalGate_5278(t *testing.T) {
	usePasswdFixture5278(t)
	cfg := Config{
		Store: authzStore5278(t, authzConfig5278),
		// The identity the primary listener refuses.
		PeerLookupFn: func(net.Addr, net.Addr) authz.PeerIdentity {
			return authz.PeerIdentity{Local: true, Detail: "local peer has no established socket"}
		},
	}
	s := NewServer("127.0.0.1:0", cfg)

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		// The PRODUCTION fabric server construction.
		_ = s.serveUntilDone(ctx, s.buildFabricServer(), lis)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})

	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial fabric: %v", err)
	}
	defer conn.Close()

	// Without a configured PSK, only GetStatus remains available on the
	// network-exposed fabric listener as its health probe (#10698). This call
	// also proves the principal gate is not installed there: the peer is a
	// cluster node, not a local uid on this host.
	client := pb.NewBpfrxServiceClient(conn)
	if _, err = client.GetStatus(callCtx(t), &pb.GetStatusRequest{}); err != nil {
		t.Fatalf("unkeyed fabric GetStatus health probe was denied: %v", err)
	}
	if _, err = client.ClearSessions(callCtx(t), &pb.ClearSessionsRequest{}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("unkeyed fabric ClearSessions err=%v (%s), want Unauthenticated",
			err, status.Code(err))
	}
	failoverReq := &pb.SystemActionRequest{Action: "cluster-failover:1:node1"}
	if _, err = client.SystemAction(callCtx(t), failoverReq); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("unkeyed fabric cluster-failover err=%v (%s), want Unauthenticated",
			err, status.Code(err))
	}
}

// TestProductionServerEnforcesRealPeerIdentity_5278 closes the injection loop:
// no PeerLookupFn, so the gate reads THIS process's connection out of the real
// kernel socket table and evaluates the result against a real committed config.
//
// It is the only case that proves the production resolver is wired at all — the
// injected cases would all pass against a Server that never called
// authz.LookupPeer.
//
// It does NOT skip under root, and that is deliberate. An earlier revision did,
// which made it silently vacuous in exactly the environment most CI runs in: a
// test that disappears where it actually executes is not coverage, it is a
// green line. Both arms below assert that the KERNEL attributed the connection
// to this process's real uid; they differ only in which verdict that uid earns,
// because uid 0 short-circuits to a superuser principal by the shipped
// pkg/authz contract. The arm that ran is logged, and the class-decision arm is
// reached under root too — through the gate, with a synthetic non-root uid — so
// no arm of the policy goes unasserted whoever runs the suite.
func TestProductionServerEnforcesRealPeerIdentity_5278(t *testing.T) {
	uid := os.Getuid()
	if uid == 0 {
		t.Log("suite runs as ROOT: asserting the production resolver attributes " +
			"the connection to uid 0 and that uid 0 is admitted (the shipped " +
			"pkg/authz contract), plus the class-decision arm at the gate")
		usePasswdFixture5278(t)
		client := runPrimaryListener(t, Config{
			Store: authzStore5278(t, authzConfig5278),
		})
		ctx := callCtx(t)

		// The production resolver ran and reported uid 0: a superuser principal
		// is admitted. If LookupPeer were NOT wired, the connection would carry
		// no identity at all and this would be PermissionDenied.
		_, err := client.Commit(ctx, &pb.CommitRequest{})
		assertNotDenied(t, "root real-identity Commit", err)

		// And the class machinery is still asserted, so the root arm is not a
		// weaker test: a read-only uid is refused the same RPC.
		s := NewServer("127.0.0.1:0", Config{Store: authzStore5278(t, authzConfig5278)})
		full := "/" + pb.BpfrxService_ServiceDesc.ServiceName + "/Commit"
		if err := s.authorizeRPC(ctxWithPeerUID(authzUIDReadOnly), full, nil); status.Code(err) != codes.PermissionDenied {
			t.Fatalf("read-only Commit under the root arm: err=%v, want PermissionDenied", err)
		}
		return
	}
	t.Logf("suite runs as uid %d: asserting the full end-to-end class decision", uid)

	// A passwd database naming THIS uid, plus a config that gives that account
	// the read-only class.
	name := "suiteuser"
	passwd := "root:x:0:0:root:/root:/bin/bash\n" +
		name + ":x:" + itoa(uid) + ":" + itoa(uid) + "::/home/" + name + ":/bin/bash\n"
	path := filepath.Join(t.TempDir(), "passwd")
	if err := os.WriteFile(path, []byte(passwd), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(authz.SetPasswdPathForTest(path))

	// Sanity: the shared resolver must name this uid from the fixture, or the
	// case below would be asserting against an unresolved identity for the
	// wrong reason.
	if got := osident.ForUID(uid); got.Name != name {
		t.Fatalf("passwd fixture does not name uid %d: got %+v", uid, got)
	}

	client := runPrimaryListener(t, Config{
		Store: authzStore5278(t, "\nsystem {\n    host-name real-peer;\n    login {\n        user "+
			name+" {\n            class read-only;\n        }\n    }\n}\n"),
	})
	ctx := callCtx(t)

	_, err := client.Commit(ctx, &pb.CommitRequest{})
	assertDenied(t, "real-identity Commit", err)
	if msg := status.Convert(err).Message(); !strings.Contains(msg, name) {
		t.Errorf("denial %q does not name the account the KERNEL reported; the "+
			"production resolver may not be wired", msg)
	}

	_, err = client.GetStatus(ctx, &pb.GetStatusRequest{})
	assertNotDenied(t, "real-identity GetStatus", err)
}

// itoa avoids importing strconv for two call sites in one test.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// TestStreamingRPCsAreGated_5278 binds the STREAM interceptor. Every streaming
// RPC on this service is view-tier, so no login class discriminates between
// them — the caller that must be refused is one with no class at all.
//
// The error surfaces on the first Recv, not on the call: grpc-go returns a
// stream handle before the server has said anything.
//
// RED on revert: drop grpc.ChainStreamInterceptor from buildPrimaryServer. The
// unary cases elsewhere in this file all keep passing, which is the point of
// giving the stream chain its own binding.
func TestStreamingRPCsAreGated_5278(t *testing.T) {
	usePasswdFixture5278(t)
	client := runPrimaryListener(t, Config{
		Store:        authzStore5278(t, authzConfig5278),
		PeerLookupFn: fixedPeerUID5278(authzUIDStranger), // real account, no class
	})
	ctx := callCtx(t)

	ps, err := client.Ping(ctx, &pb.PingRequest{Target: "127.0.0.1", Count: 1})
	if err == nil {
		_, err = ps.Recv()
	}
	assertDenied(t, "stranger Ping (server stream)", err)

	ms, err := client.MonitorInterface(ctx, &pb.MonitorInterfaceRequest{})
	if err == nil {
		_, err = ms.Recv()
	}
	assertDenied(t, "stranger MonitorInterface (server stream)", err)
}

// TestStreamingRPCsAreAdmittedForAViewClass_5278 is the stream chain's negative
// control: the same two streams must still open for a class that holds view.
func TestStreamingRPCsAreAdmittedForAViewClass_5278(t *testing.T) {
	usePasswdFixture5278(t)
	client := runPrimaryListener(t, Config{
		Store:        authzStore5278(t, authzConfig5278),
		PeerLookupFn: fixedPeerUID5278(authzUIDReadOnly),
	})
	ctx := callCtx(t)

	ps, err := client.Ping(ctx, &pb.PingRequest{Target: "127.0.0.1", Count: 1})
	if err == nil {
		_, err = ps.Recv()
	}
	assertNotDenied(t, "read-only Ping (server stream)", err)
}

// TestPeerIdentityIsResolvedOncePerConnectionAtAccept_5278 pins WHERE the
// identity comes from, which is the property the whole gate rests on.
//
// Two things are asserted, and each has its own failure:
//
//  1. The resolver runs ONCE per connection, not once per RPC. A gate that
//     resolved per RPC would work — and would put a /proc/net/tcp read on every
//     call of every long-lived CLI session.
//  2. The verdict is drawn from the observation made at CONNECTION SETUP. The
//     resolver's answer is CHANGED after the connection is up, and the calls
//     that follow must still be governed by the original answer. A caller can
//     take its own socket out of TCP_ESTABLISHED while keeping the connection
//     usable (shutdown(fd, SHUT_WR)), so a gate that looked at RPC time would
//     let the caller choose the moment its identity is read.
//
// RED on revert: move the lookup out of TagConn into authorizeRPC (the count
// assertion fires immediately, and the post-swap call is denied).
func TestPeerIdentityIsResolvedOncePerConnectionAtAccept_5278(t *testing.T) {
	usePasswdFixture5278(t)

	var mu sync.Mutex
	calls := 0
	answer := authz.PeerIdentity{UID: authzUIDSuperuser, OK: true, Local: true}
	resolver := func(net.Addr, net.Addr) authz.PeerIdentity {
		mu.Lock()
		defer mu.Unlock()
		calls++
		return answer
	}
	swap := func(id authz.PeerIdentity) {
		mu.Lock()
		defer mu.Unlock()
		answer = id
	}
	count := func() int {
		mu.Lock()
		defer mu.Unlock()
		return calls
	}

	client := runPrimaryListener(t, Config{
		Store:        authzStore5278(t, authzConfig5278),
		PeerLookupFn: resolver,
	})
	ctx := callCtx(t)

	_, err := client.GetStatus(ctx, &pb.GetStatusRequest{})
	assertNotDenied(t, "super-user GetStatus", err)
	if got := count(); got != 1 {
		t.Fatalf("peer resolver ran %d times for the first RPC on a connection, "+
			"want exactly 1 (at accept)", got)
	}

	// The caller's socket "leaves" ESTABLISHED. The connection is still up and
	// still usable, which is exactly the window a hostile client engineers.
	swap(authz.PeerIdentity{Local: true, Detail: "local peer has no established socket"})

	_, err = client.Commit(ctx, &pb.CommitRequest{})
	assertNotDenied(t, "Commit after the peer answer changed", err)
	_, err = client.EnterConfigure(ctx, &pb.EnterConfigureRequest{})
	assertNotDenied(t, "EnterConfigure after the peer answer changed", err)

	if got := count(); got != 1 {
		t.Fatalf("peer resolver ran %d times across three RPCs on ONE connection, "+
			"want exactly 1 — the identity must be fixed at accept, not "+
			"re-derived per RPC (#5278)", got)
	}
}

// TestANewConnectionGetsAFreshIdentity_5278 is the counterpart of the test
// above: "once per connection" must not degrade into "once per process". A
// second connection re-resolves, so a revoked or changed peer identity governs
// every connection made after it.
func TestANewConnectionGetsAFreshIdentity_5278(t *testing.T) {
	usePasswdFixture5278(t)

	var mu sync.Mutex
	answer := authz.PeerIdentity{UID: authzUIDSuperuser, OK: true, Local: true}
	resolver := func(net.Addr, net.Addr) authz.PeerIdentity {
		mu.Lock()
		defer mu.Unlock()
		return answer
	}

	s := NewServer("127.0.0.1:0", Config{
		Store:        authzStore5278(t, authzConfig5278),
		PeerLookupFn: resolver,
	})
	addr := serveAndWait(t, s)

	first := dialPrimary(t, addr)
	ctx := callCtx(t)
	_, err := first.Commit(ctx, &pb.CommitRequest{})
	assertNotDenied(t, "first connection (super-user) Commit", err)

	mu.Lock()
	answer = authz.PeerIdentity{UID: authzUIDReadOnly, OK: true, Local: true}
	mu.Unlock()

	second := dialPrimary(t, addr)
	_, err = second.Commit(ctx, &pb.CommitRequest{})
	assertDenied(t, "second connection (read-only) Commit", err)

	// And the FIRST connection keeps its accept-time identity.
	_, err = first.Commit(ctx, &pb.CommitRequest{})
	assertNotDenied(t, "first connection Commit after the answer changed", err)
}

// TestReadOnlyIsDeniedTheTestFamilyOverShowText_5278 drives the ShowText topic
// tier through the REAL gate, end to end.
//
// It is the behavioural half of the correction: `test policy`, `test routing`
// and `test security-zone` reach the server as ShowText TOPICS, and pricing the
// method flat at view let a read-only class run policy reconnaissance — ask
// which rule matches a given 5-tuple — over gRPC.
//
// The `show` topic in the same run is the load-bearing control. Without it,
// pricing every ShowText topic at control would pass every assertion above and
// silently take `show chassis cluster` away from read-only, which is a
// regression wearing the shape of a fix.
//
// RED on revert: move any test-* key from showTextElevatedTopics back to
// showTextViewTopics — the denial arm reds and the control arm stays green,
// which is what localises the failure to the tier rather than to the gate.
func TestReadOnlyIsDeniedTheTestFamilyOverShowText_5278(t *testing.T) {
	usePasswdFixture5278(t)
	client := runPrimaryListener(t, Config{
		Store:        authzStore5278(t, authzConfig5278),
		PeerLookupFn: fixedPeerUID5278(authzUIDReadOnly),
	})
	ctx := callCtx(t)

	for _, topic := range []string{
		"test-policy:from=trust,to=untrust,src=10.0.1.5,dst=10.0.2.5,proto=tcp,port=443",
		"test-routing:dest=10.0.0.0/24",
		"test-zone:interface=ge-0/0/0.0",
	} {
		_, err := client.ShowText(ctx, &pb.ShowTextRequest{Topic: topic})
		assertDenied(t, "read-only ShowText{"+topic+"}", err)
	}

	// CONTROL: the same method, a `show` topic, same connection, same class.
	_, err := client.ShowText(ctx, &pb.ShowTextRequest{Topic: "version"})
	assertNotDenied(t, "read-only ShowText{version}", err)
}

// TestOperatorKeepsTheTestFamilyOverShowText_5278 is the other side of that
// tier: `operator` holds PermControl, so the test family must still work for
// it. A correction that priced the topics at maintenance would pass the
// read-only denial above and break the class that legitimately has them.
func TestOperatorKeepsTheTestFamilyOverShowText_5278(t *testing.T) {
	usePasswdFixture5278(t)
	client := runPrimaryListener(t, Config{
		Store:        authzStore5278(t, authzConfig5278),
		PeerLookupFn: fixedPeerUID5278(authzUIDOperator),
	})
	ctx := callCtx(t)

	for _, topic := range []string{
		"test-routing:dest=10.0.0.0/24",
		"test-zone:interface=ge-0/0/0.0",
	} {
		_, err := client.ShowText(ctx, &pb.ShowTextRequest{Topic: topic})
		assertNotDenied(t, "operator ShowText{"+topic+"}", err)
	}
}
