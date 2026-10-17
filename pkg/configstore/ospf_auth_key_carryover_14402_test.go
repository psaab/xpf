package configstore

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #14402: strict refuses OSPF interface authentication-key; tolerant warns named.

const ospfAuthKeyCfg14402 = `protocols {
    ospf {
        area 0.0.0.0 {
            interface ge-0/0/0.0 {
                authentication-key secret1;
            }
        }
    }
}`

func TestOSPFAuthKeyStrictRefusedTolerantWarns14402(t *testing.T) {
	if _, err := CheckText(ospfAuthKeyCfg14402, -1); err == nil {
		t.Fatal("strict CheckText accepted OSPF authentication-key carryover")
	} else {
		if !strings.Contains(err.Error(), "authentication-key") {
			t.Fatalf("strict error must name leaf: %v", err)
		}
		if !strings.Contains(err.Error(), "authentication {") {
			t.Fatalf("strict error must name nested grammar: %v", err)
		}
		if strings.Contains(err.Error(), "secret1") {
			t.Fatalf("strict error leaks secret: %v", err)
		}
	}
	tree, errs := config.NewParser(ospfAuthKeyCfg14402).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse: %v", errs)
	}
	compiled, err := newTestStore(t).compileTreeLenient(tree)
	if err != nil {
		t.Fatalf("tolerant must boot: %v", err)
	}
	if compiled == nil {
		t.Fatal("nil compiled")
	}
	// Must have a NAMED warning (typed-leaf tolerated) naming authentication-key, not only generic #10707
	foundNamed := false
	foundGenericOnly := true
	for _, w := range compiled.Warnings {
		if strings.Contains(w, "authentication-key") && strings.Contains(w, "authentication {") {
			foundNamed = true
		}
		if strings.Contains(w, "authentication-key") && !strings.Contains(w, "#10707") {
			foundGenericOnly = false
		}
	}
	if !foundNamed {
		t.Fatalf("tolerant warnings must name authentication-key + nested grammar, got %v", compiled.Warnings)
	}
	_ = foundGenericOnly
	// Valid controls still strict-commit
	for _, txt := range []string{
		"protocols { ospf { area 0.0.0.0 { interface ge-0/0/0.0 { authentication { md5 1 { key \"SEKRIT\"; } } } } } }",
		"protocols { ospf { area 0.0.0.0 { interface ge-0/0/0.0 { authentication { simple-password \"SEKRIT\"; } } } } }",
	} {
		if _, err := CheckText(txt, -1); err != nil {
			t.Fatalf("control must commit: %v", err)
		}
	}
}
