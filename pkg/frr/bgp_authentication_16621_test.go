package frr

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #16621 render leg: a top-level `protocols bgp authentication-key`
// inherited by a peer must render `neighbor 10.0.0.2 password ...`
// (TCP-MD5). Before the fix the key was dropped at compile, so the
// rendered stanza carried no password line at all.
func TestBGPTopLevelAuthKeyRendersPassword16621(t *testing.T) {
	tree, perrs := config.NewParser(`protocols { bgp { local-as 65001; authentication-key topsecret; group G { peer-as 65002; neighbor 10.0.0.2; } } }`).Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse: %v", perrs)
	}
	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if len(cfg.Protocols.BGP.Neighbors) != 1 || cfg.Protocols.BGP.Neighbors[0].AuthPassword.Reveal() != "topsecret" {
		t.Fatalf("compiled neighbors = %+v, want one with inherited topsecret", cfg.Protocols.BGP.Neighbors)
	}
	section := New().buildManagedSection(&FullConfig{BGP: cfg.Protocols.BGP, PolicyOptions: &cfg.PolicyOptions})
	if !strings.Contains(section, "neighbor 10.0.0.2 password topsecret") {
		t.Errorf("rendered section missing inherited password line:\n%s", section)
	}

	// Most-specific wins at render: neighbor key beats top-level.
	tree2, perrs := config.NewParser(`protocols { bgp { local-as 65001; authentication-key topsecret; group G { peer-as 65002; neighbor 10.0.0.2 { authentication-key neighborsecret; } } } }`).Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse2: %v", perrs)
	}
	cfg2, err := config.CompileConfig(tree2)
	if err != nil {
		t.Fatalf("compile2: %v", err)
	}
	section2 := New().buildManagedSection(&FullConfig{BGP: cfg2.Protocols.BGP, PolicyOptions: &cfg2.PolicyOptions})
	if !strings.Contains(section2, "neighbor 10.0.0.2 password neighborsecret") {
		t.Errorf("rendered section missing neighbor password line:\n%s", section2)
	}
	if strings.Contains(section2, "password topsecret") {
		t.Errorf("rendered section must not carry overridden top-level key:\n%s", section2)
	}

	// Control: no key anywhere renders no password line.
	tree3, perrs := config.NewParser(`protocols { bgp { local-as 65001; group G { peer-as 65002; neighbor 10.0.0.2; } } }`).Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse3: %v", perrs)
	}
	cfg3, err := config.CompileConfig(tree3)
	if err != nil {
		t.Fatalf("compile3: %v", err)
	}
	section3 := New().buildManagedSection(&FullConfig{BGP: cfg3.Protocols.BGP, PolicyOptions: &cfg3.PolicyOptions})
	if strings.Contains(section3, "password") {
		t.Errorf("no-key control must render no password line:\n%s", section3)
	}
}
