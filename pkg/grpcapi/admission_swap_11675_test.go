package grpcapi

import (
	"context"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

const admissionSwapConfig11675 = `system {
    login {
        class planter { permissions [ view configure ]; }
        user opuser { class planter; }
    }
}`

// TestGRPCAdmissionSwapKeepsJournalAndEventStampClass11675 drives the exact
// admission-to-handler window: Set and Commit are both admitted as planter,
// then the active login model reclasses the peer to super-user before either
// handler runs. The deferred event-options payload and durable commit journal
// must retain the same admitted class rather than resolving separate live
// snapshots.
func TestGRPCAdmissionSwapKeepsJournalAndEventStampClass11675(t *testing.T) {
	usePasswdFixture5278(t)
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
	setReq := &pb.SetRequest{Input: `event-options policy p then change-configuration commands "set system host-name grpc-stamped"`}
	setCtx, err := s.authorizeRPCContext(ctxWithPeerUID(authzUIDOperator), pb.BpfrxService_Set_FullMethodName, setReq)
	if err != nil {
		t.Fatalf("admit Set as planter: %v", err)
	}
	commitCtx, err := s.authorizeRPCContext(ctxWithPeerUID(authzUIDOperator), pb.BpfrxService_Commit_FullMethodName, &pb.CommitRequest{})
	if err != nil {
		t.Fatalf("admit Commit as planter: %v", err)
	}

	// The reclassification lands after both RPCs were admitted but before their
	// handlers run. The old handler re-resolves this peer as super-user here.
	updatedConfig := strings.Replace(admissionSwapConfig11675, "class planter;", "class super-user;", 1)
	if err := store.LoadOverride(updatedConfig); err != nil {
		t.Fatalf("LoadOverride updated active login model: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit updated active login model: %v", err)
	}

	if _, err := s.Set(setCtx, setReq); err != nil {
		t.Fatalf("Set admitted before reclassification: %v", err)
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
