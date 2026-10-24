package grpcapi

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #16078: gRPC ShowText surface must name configured user-identification
// stanzas INERT, via the shared pkg/config renderer.
func TestShowUserIdentificationStatus16078(t *testing.T) {
	cfg, err := config.CompileConfig(mustTree16078(t))
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	for _, topic := range []string{"user-identification-status", "security-user-identification-status"} {
		var buf strings.Builder
		// Drive through the dispatcher topic by calling the renderer the
		// case arm calls; topic dispatch itself is covered by census tests.
		_ = topic
		(&Server{}).showUserIdentificationStatus(cfg, &buf)
		out := buf.String()
		for _, want := range []string{"User identification status:", "INERT", "active-directory-access", "no runtime effect"} {
			if !strings.Contains(out, want) {
				t.Errorf("topic %s render missing %q:\n%s", topic, want, out)
			}
		}
		if strings.Contains(out, "enabled") {
			t.Errorf("render must not claim enabled:\n%s", out)
		}
	}
}

func mustTree16078(t *testing.T) *config.ConfigTree {
	t.Helper()
	tree, errs := config.NewParser("services { user-identification { active-directory-access { domain-name corp.example; } } }").Parse()
	if len(errs) > 0 {
		t.Fatalf("parse: %v", errs)
	}
	return tree
}
