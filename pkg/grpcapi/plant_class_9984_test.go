package grpcapi

import (
	"testing"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

func TestGRPCMutationCarriesAuthenticatedPlantClass9984(t *testing.T) {
	usePasswdFixture5278(t)
	store := authzStore5278(t, authzConfig5278)
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	defer store.ExitConfigure()
	s := &Server{store: store}
	ctx := ctxWithPeerUID(authzUIDOperator)
	for _, input := range []string{
		`event-options policy p events ping_test_failed`,
		`event-options policy p then change-configuration commands "set system host-name grpc-stamped"`,
	} {
		if _, err := s.Set(ctx, &pb.SetRequest{Input: input}); err != nil {
			t.Fatalf("Set(%q): %v", input, err)
		}
	}
	cfg, err := store.CompileCandidate()
	if err != nil {
		t.Fatalf("CompileCandidate: %v", err)
	}
	for _, policy := range cfg.EventOptions {
		if policy != nil && policy.Name == "p" {
			if policy.PlantClass != "operator" {
				t.Fatalf("gRPC planted class=%q, want operator", policy.PlantClass)
			}
			return
		}
	}
	t.Fatal("gRPC candidate did not contain event policy p")
}
