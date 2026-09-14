package configstore

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #9820 (Path C): the store ingress split for area IDs. Strict ingress
// (schema-then-compile) refuses mapped/padded areas; tolerant ingress
// compiles and logs a schema `slog` warning (NOT a cfg.Warnings entry).

func areaTree9820(t *testing.T, cmds ...string) *config.ConfigTree {
	t.Helper()
	tree := &config.ConfigTree{}
	for _, cmd := range cmds {
		path, err := config.ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	return tree
}

func TestOSPFAreaStrictIngressRefuses_9820(t *testing.T) {
	tree := areaTree9820(t, "set protocols ospf area ::ffff:192.0.2.1")
	if _, err := compileTreeStrict(tree, -1); err == nil ||
		!strings.Contains(err.Error(), "IPv4-mapped") {
		t.Fatalf("strict ingress must refuse the mapped area, got: %v", err)
	}
}

func TestOSPFAreaTolerantIngressWarns_9820(t *testing.T) {
	buf := captureWarnLogs(t)
	s := newTestStore(t)
	tree := areaTree9820(t, "set protocols ospf area ::ffff:192.0.2.1")
	cfg, err := s.compileTreeLenient(tree)
	if err != nil {
		t.Fatalf("tolerant ingress must NOT fail, got: %v", err)
	}
	// The raw value is retained for the render belt.
	if cfg.Protocols.OSPF == nil || len(cfg.Protocols.OSPF.Areas) != 1 ||
		cfg.Protocols.OSPF.Areas[0].ID != "::ffff:192.0.2.1" {
		t.Fatalf("tolerant compile must retain the raw area id: %+v", cfg.Protocols.OSPF)
	}
	logged := buf.String()
	if !strings.Contains(logged, "typed-leaf schema violation") {
		t.Fatalf("tolerant ingress must log the schema warning, got:\n%s", logged)
	}
}
