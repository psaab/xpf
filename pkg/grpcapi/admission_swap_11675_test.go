package grpcapi

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/authz"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

const admissionSwapConfig11675 = `system {
    login {
        class planter { permissions [ view configure ]; }
        user opuser { class planter; }
        user plantop { class planter; }
        user superop { class super-user; }
    }
}`

// TestGRPCAdmissionSwapKeepsJournalAndEventStampClass11675 drives the exact
// admission-to-handler window: Set and Commit are each admitted as planter,
// and the peer's class is changed to super-user before the admitted handler
// runs. The deferred event-options payload and durable commit journal must
// retain the admitted class rather than resolving separate live snapshots.
//
// The peer's class resolves uid -> account (passwd) -> class (the ACTIVE login
// model). A handler that re-resolved it could go wrong through either link,
// so the two legs reclass through different links (#19049):
//
//   - SET leg: through the LOGIN MODEL. After admission, opuser's class is
//     changed in the active config (LoadOverride + Commit) and the handler
//     runs. A handler that re-reads the class from the live config, by uid or
//     by the admitted username, stamps super-user. Set is not bound to a
//     candidate generation, so moving the candidate here is allowed.
//   - COMMIT leg: through the ACCOUNT. Since #16611 (a246314472) a Commit is
//     bound to the candidate generation its admission priced, and promotion
//     refuses it when the candidate moved, so a login-model reload between
//     admission and handling is no longer possible there. (This test used to
//     reload for both legs after admitting both, and was red on every run
//     from #16611 on.) Instead uid authzUIDOperator resolves to plantop
//     (planter) at admission and to superop (super-user, same active config)
//     when the handler runs, with the candidate untouched.
//
// Each leg asserts its premise (the live class really changed) before the
// handler runs.
func TestGRPCAdmissionSwapKeepsJournalAndEventStampClass11675(t *testing.T) {
	passwdPath := filepath.Join(t.TempDir(), "passwd")
	accountFor := func(name string) string {
		if name == "opuser" {
			return authzPasswd5278
		}
		return strings.Replace(authzPasswd5278,
			"opuser:x:4243:4243::/home/opuser:", name+":x:4243:4243::/home/"+name+":", 1)
	}
	resolveAs := func(name string) {
		t.Helper()
		passwd := accountFor(name)
		if name != "opuser" && passwd == authzPasswd5278 {
			t.Fatalf("fixture: the passwd remap to %s did not change uid 4243's account", name)
		}
		if err := os.WriteFile(passwdPath, []byte(passwd), 0o600); err != nil {
			t.Fatalf("resolve uid 4243 as %s: %v", name, err)
		}
	}
	resolveAs("opuser")
	t.Cleanup(authz.SetPasswdPathForTest(passwdPath))

	store := authzStore5278(t, admissionSwapConfig11675)
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}

	s := &Server{
		store: store,
		commitFn: func(_ context.Context, authority configstore.CommitAuthority, comment string) (*config.Config, error) {
			_, generation, err := store.CompileCandidateGen()
			if err != nil {
				return nil, err
			}
			return store.CommitWithDescriptionGenAs(authority, comment, generation)
		},
	}
	// liveClass is what a handler that RE-RESOLVED the peer would see now —
	// the premise each reclass below must establish, asserted rather than
	// assumed.
	liveClass := func() string {
		return principalFromContext(ctxWithPeerUID(authzUIDOperator), store.ActiveConfig()).Class
	}
	if got := liveClass(); got != "planter" {
		t.Fatalf("premise: the peer resolves to class %q before any reclass, want planter", got)
	}

	// SET leg: admitted as opuser/planter, reclassed in the LOGIN MODEL.
	setReq := &pb.SetRequest{Input: `event-options policy p then change-configuration commands "set system host-name grpc-stamped"`}
	setCtx, err := s.authorizeRPCContext(ctxWithPeerUID(authzUIDOperator), pb.BpfrxService_Set_FullMethodName, setReq)
	if err != nil {
		t.Fatalf("admit Set as planter: %v", err)
	}
	reclassed := strings.Replace(admissionSwapConfig11675, "user opuser { class planter; }", "user opuser { class super-user; }", 1)
	if reclassed == admissionSwapConfig11675 {
		t.Fatal("fixture: the login-model reclass did not change opuser's class")
	}
	if err := store.LoadOverride(reclassed); err != nil {
		t.Fatalf("LoadOverride reclassed login model: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit reclassed login model: %v", err)
	}
	if got := liveClass(); got != "super-user" {
		t.Fatalf("premise: the login-model reclass left the live class at %q, want super-user", got)
	}
	if _, err := s.Set(setCtx, setReq); err != nil {
		t.Fatalf("Set admitted before reclassification: %v", err)
	}

	// COMMIT leg: admitted as plantop/planter on the candidate the Set
	// produced, reclassed through the ACCOUNT so that candidate stays put.
	resolveAs("plantop")
	if got := liveClass(); got != "planter" {
		t.Fatalf("premise: uid 4243 as plantop resolves to %q, want planter", got)
	}
	commitCtx, err := s.authorizeRPCContext(ctxWithPeerUID(authzUIDOperator), pb.BpfrxService_Commit_FullMethodName, &pb.CommitRequest{})
	if err != nil {
		t.Fatalf("admit Commit as planter: %v", err)
	}
	resolveAs("superop")
	if got := liveClass(); got != "super-user" {
		t.Fatalf("premise: the account reclass left the live class at %q, want super-user", got)
	}

	const journalDetail = "admission-swap-11675"
	if _, err := s.Commit(commitCtx, &pb.CommitRequest{Comment: journalDetail}); err != nil {
		t.Fatalf("Commit admitted before reclassification: %v", err)
	}

	active := store.ActiveConfig()
	var stamp string
	for _, policy := range active.EventOptions {
		if policy != nil && policy.Name == "p" {
			stamp = policy.PlantClass
			break
		}
	}
	if stamp == "" {
		t.Fatal("committed config has no plant-class stamp for event policy p")
	}
	entries, err := store.ListCommitHistory(10)
	if err != nil {
		t.Fatalf("ListCommitHistory: %v", err)
	}
	var journalClass string
	journalRows := 0
	for _, entry := range entries {
		if entry.Action != "commit" || entry.Detail != journalDetail {
			continue
		}
		journalRows++
		for _, field := range strings.Split(entry.Principal, ";") {
			if strings.HasPrefix(field, "class=") {
				journalClass = strings.TrimPrefix(field, "class=")
				break
			}
		}
	}
	if journalRows != 1 {
		t.Fatalf("journal rows with detail %q = %d, want exactly 1", journalDetail, journalRows)
	}
	if journalClass == "" {
		t.Fatalf("the commit journal row with detail %q has no class attribution", journalDetail)
	}
	if journalClass != stamp {
		t.Fatalf("admitted journal class %q differs from event-options PlantClass stamp %q", journalClass, stamp)
	}
	if journalClass != "planter" {
		t.Fatalf("admission snapshot class = %q, want planter", journalClass)
	}
}
