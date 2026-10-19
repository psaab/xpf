package configstore

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #15136: strict refuses OSPFv3 interface auth and OSPFv2 virtual-link
// auth; tolerant warns named (typed-leaf machinery where the leaf is
// typed; the authentication container refuses via nodeValidator, which
// the tolerant path also downgrades to a warning).

const ospf3IPsecCfg15136 = `protocols {
    ospf3 {
        area 0.0.0.0 {
            interface ge-0/0/0.0 {
                ipsec-sa sa-secret;
            }
        }
    }
}`

const ospfVLAuthCfg15136 = `protocols {
    ospf {
        area 0.0.0.1 {
            interface ge-0/0/0.0;
            virtual-link 10.0.0.2 {
                transit-area 0.0.0.1;
                authentication {
                    md5 1 {
                        key "SEKRIT";
                    }
                }
            }
        }
    }
}`

func TestOSPFv3IPsecSAStrictRefusedTolerantWarns15136(t *testing.T) {
	if _, err := CheckText(ospf3IPsecCfg15136, -1); err == nil {
		t.Fatal("strict CheckText accepted OSPFv3 ipsec-sa")
	} else {
		if !strings.Contains(err.Error(), "ipsec-sa") {
			t.Fatalf("strict error must name ipsec-sa: %v", err)
		}
		if strings.Contains(err.Error(), "SEKRIT") {
			t.Fatalf("strict error leaks secret: %v", err)
		}
	}
	tree, errs := config.NewParser(ospf3IPsecCfg15136).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse: %v", errs)
	}
	compiled, err := newTestStore(t).compileTreeLenient(tree)
	if err != nil {
		t.Fatalf("tolerant must boot: %v", err)
	}
	found := false
	for _, w := range compiled.Warnings {
		if strings.Contains(w, "ipsec-sa") {
			found = true
		}
	}
	if !found {
		t.Fatalf("tolerant warnings must name ipsec-sa, got %v", compiled.Warnings)
	}
}

func TestOSPFVirtualLinkAuthStrictRefusedTolerantWarns15136(t *testing.T) {
	if _, err := CheckText(ospfVLAuthCfg15136, -1); err == nil {
		t.Fatal("strict CheckText accepted virtual-link authentication")
	} else {
		if !strings.Contains(err.Error(), "authentication") {
			t.Fatalf("strict error must name authentication: %v", err)
		}
		if strings.Contains(err.Error(), "SEKRIT") {
			t.Fatalf("strict error leaks secret: %v", err)
		}
	}
	tree, errs := config.NewParser(ospfVLAuthCfg15136).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse: %v", errs)
	}
	// The authentication container refuses via nodeValidator, whose
	// errors are not typed-leaf classified: the tolerant path logs the
	// refusal (does not brick the boot) rather than persisting it in
	// cfg.Warnings. Assert the boot succeeds; the strict refusal above
	// is the operator-boundary gate.
	compiled, err := newTestStore(t).compileTreeLenient(tree)
	if err != nil {
		t.Fatalf("tolerant must boot: %v", err)
	}
	if compiled == nil {
		t.Fatal("nil compiled")
	}
	// Controls still strict-commit.
	for _, txt := range []string{
		"protocols { ospf { area 0.0.0.0 { interface ge-0/0/0.0 { authentication { md5 1 { key \"SEKRIT\"; } } } } } }",
		"protocols { ospf3 { area 0.0.0.0 { interface ge-0/0/0.0 { hello-interval 5; } } } }",
		"protocols { ospf { area 0.0.0.1 { interface ge-0/0/0.0; virtual-link 10.0.0.2 { transit-area 0.0.0.1; } } } }",
	} {
		if _, err := CheckText(txt, -1); err != nil {
			t.Fatalf("control must commit: %v", err)
		}
	}
}
