package cli

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #16078: local CLI renderer (via shared pkg/config) must mark
// user-identification INERT. renderALG-style direct render keeps this
// independent of a configstore round-trip.
func TestRenderUserIdentificationStatus16078CLI(t *testing.T) {
	tree, errs := config.NewParser("services { user-identification { identity-management { connection primary; } } }").Parse()
	if len(errs) > 0 {
		t.Fatalf("parse: %v", errs)
	}
	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	var b strings.Builder
	config.RenderUserIdentificationStatus(&b, cfg)
	out := b.String()
	for _, want := range []string{"User identification status:", "INERT", "identity-management"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q:\n%s", want, out)
		}
	}
}
