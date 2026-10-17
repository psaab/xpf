package frr

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #14414 (DR14-H1): an inline packed OSPF `authentication md5 1;` leaf
// beside a group-supplied `authentication { md5 1 { key ...; } }`
// container must render MD5 authentication. Before the fix the #4325
// group-merge guard dropped the container, so no auth line rendered
// while the interface activated unauthenticated.

func renderOSPFGroup14414(t *testing.T, text string) string {
	t.Helper()
	tree, perrs := config.NewParser(text).Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse: %v", perrs)
	}
	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	return New().buildManagedSection(&FullConfig{OSPF: cfg.Protocols.OSPF})
}

func TestGroupOSPFContainerRendersMD5_14414(t *testing.T) {
	got := renderOSPFGroup14414(t, `
groups { G { protocols { ospf { area 0.0.0.0 { interface ge-0/0/0.0 {
  authentication { md5 1 { key SECRET1; } }
} } } } } }
protocols { ospf { area 0.0.0.0 { interface ge-0/0/0.0 {
  authentication md5 1;
} } } }
apply-groups G;
`)
	for _, want := range []string{
		"ip ospf authentication message-digest",
		"ip ospf message-digest-key 1 md5 SECRET1",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("rendered FRR missing %q — group OSPF auth key dropped (#14414):\n%s", want, got)
		}
	}
}

func TestGroupOSPFMD5NotDowngradedRender14414(t *testing.T) {
	got := renderOSPFGroup14414(t, `
groups { G { protocols { ospf { area 0.0.0.0 { interface ge-0/0/0.0 {
  authentication { md5 1 { key K2; } }
} } } } } }
protocols { ospf { area 0.0.0.0 { interface ge-0/0/0.0 {
  authentication simple-password K;
} } } }
apply-groups G;
`)
	if !strings.Contains(got, "ip ospf authentication message-digest") ||
		!strings.Contains(got, "ip ospf message-digest-key 1 md5 K2") {
		t.Fatalf("group md5 must render, not simple downgrade (#14414):\n%s", got)
	}
	if strings.Contains(got, "ip ospf authentication-key K\n") {
		t.Fatalf("simple-password rendered instead of group md5 (#14414):\n%s", got)
	}
}
