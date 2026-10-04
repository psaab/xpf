package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// FAIL-ON-REVERT: if `any` is resolved as a user-defined application before
// the match-all keyword branch, this valid colliding definition yields one TCP
// term instead of the empty, unconstrained application list.
func TestMatchApplicationAnyRemainsMatchAll12048(t *testing.T) {
	cfg := &config.Config{}
	cfg.Applications.Applications = map[string]*config.Application{
		"any": {Name: "any", Protocol: "tcp", DestinationPort: "80"},
	}

	terms, ok := expandUserspacePolicyApplications(cfg, []string{"any"})
	if !ok {
		t.Fatal("expandUserspacePolicyApplications(any) ok=false, want match-all")
	}
	if len(terms) != 0 {
		t.Fatalf("expandUserspacePolicyApplications(any) returned %d terms, want none for match-all", len(terms))
	}
}
