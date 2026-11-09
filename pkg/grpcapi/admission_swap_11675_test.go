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
        user superop { class super-user; }
    }
}`

// TestGRPCAdmissionSwapKeepsJournalAndEventStampClass11675 drives the exact
// admission-to-handler window: Set and Commit are each admitted as planter,
// and the live login model then resolves the same peer as super-user before
// the admitted handler runs. The deferred event-options payload and durable
// commit journal must retain the admitted class rather than resolving
// separate live snapshots.
//
// HOW THE PEER IS RECLASSED, and why it changed (#19049). This test used to
// admit BOTH RPCs, then reclass by loading and committing a new login model
// (LoadOverride + Commit), then run both handlers. Since #16611 (a246314472)
// a Commit is bound to the candidate generation its admission priced, and
// promotion refuses it when the candidate moved — which that sequence did
// twice (the reload, then the admitted Set). The commit was refused, re-priced
// against the planter class, and the test went red on every run from then on
// for a reason unrelated to the property below.
//
// The reclass therefore must not move the candidate. The peer's class is
// resolved uid -> account (passwd) -> class (active login model), so the
// reclass rewrites the account side: uid authzUIDOperator resolves to opuser
// (class planter) at admission and to superop (class super-user, in the same
// active config) when the handler runs. The pre-#11675 handlers re-resolved
// the principal from that same live chain, so they stamp super-user here
// exactly as they did under the config reclass.
//
// Each RPC is admitted on planter and handled on super-user, in the order
// #16611 permits: Set is admitted and handled first; then Commit is admitted
// on the candidate the Set produced, so its priced generation is the one it
// promotes.
func TestGRPCAdmissionSwapKeepsJournalAndEventStampClass11675(t *testing.T) {
	passwdPath := filepath.Join(t.TempDir(), "passwd")
	asPlanter := authzPasswd5278
	asSuperUser := strings.Replace(authzPasswd5278,
		"opuser:x:4243:4243::/home/opuser:", "superop:x:4243:4243::/home/superop:", 1)
	if asSuperUser == asPlanter {
		t.Fatal("fixture: the passwd remap did not change uid 4243's account")
	}
	resolveAs := func(what, passwd string) {
		t.Helper()
		if err := os.WriteFile(passwdPath, []byte(passwd), 0o600); err != nil {
			t.Fatalf("%s: %v", what, err)
		}
	}
	resolveAs("resolve the peer as opuser (planter)", asPlanter)
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

	setReq := &pb.SetRequest{Input: `event-options policy p then change-configuration commands "set system host-name grpc-stamped"`}
	setCtx, err := s.authorizeRPCContext(ctxWithPeerUID(authzUIDOperator), pb.BpfrxService_Set_FullMethodName, setReq)
	if err != nil {
		t.Fatalf("admit Set as planter: %v", err)
	}
	// The reclassification lands after Set was admitted but before its
	// handler runs. The old handler re-resolves this peer as super-user here.
	resolveAs("reclass the peer to superop (super-user) before the Set handler", asSuperUser)
	if got := liveClass(); got != "super-user" {
		t.Fatalf("premise: the reclass left the live class at %q, want super-user", got)
	}
	if _, err := s.Set(setCtx, setReq); err != nil {
		t.Fatalf("Set admitted before reclassification: %v", err)
	}

	// Commit is admitted as planter on the candidate the Set produced, then
	// the same reclassification lands before its handler runs.
	resolveAs("restore the peer to opuser (planter) for the Commit admission", asPlanter)
	commitCtx, err := s.authorizeRPCContext(ctxWithPeerUID(authzUIDOperator), pb.BpfrxService_Commit_FullMethodName, &pb.CommitRequest{})
	if err != nil {
		t.Fatalf("admit Commit as planter: %v", err)
	}
	resolveAs("reclass the peer to superop (super-user) before the Commit handler", asSuperUser)
	if got := liveClass(); got != "super-user" {
		t.Fatalf("premise: the reclass left the live class at %q, want super-user", got)
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
