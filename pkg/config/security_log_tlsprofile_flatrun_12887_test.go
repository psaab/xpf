package config

import (
	"strings"
	"testing"
)

// #12887: the tls-profile gate must read the same flat-run expansion as
// compileLog; an elided stream (body carried in the node's own Keys) must
// not slip past the validator on the raw tree.
func TestSecurityLogTLSProfileFlatRunRejected12887(t *testing.T) {
	text := "security { log { stream audit host 192.0.2.10 transport tls-profile P1; } }"
	tree, perrs := NewParser(text).Parse()
	if len(perrs) != 0 {
		t.Fatalf("parse: %v", perrs)
	}
	if _, err := validateSecurityLogStreamTLSProfileAST(tree.Children, "", false); err == nil ||
		!strings.Contains(err.Error(), "tls-profile") {
		t.Fatalf("elided tls-profile must be rejected by the validator, got err=%v", err)
	}
	warns, err := validateSecurityLogStreamTLSProfileAST(tree.Children, "", true)
	if err != nil || len(warns) == 0 {
		t.Fatalf("lenient validator must warn on elided tls-profile, warns=%v err=%v", warns, err)
	}
	// Control: protocol tls alone produces no gate output.
	text3 := "security { log { stream audit { host 192.0.2.10; transport protocol tls; } } }"
	tree3, perrs := NewParser(text3).Parse()
	if len(perrs) != 0 {
		t.Fatalf("parse3: %v", perrs)
	}
	if _, err := validateSecurityLogStreamTLSProfileAST(tree3.Children, "", false); err != nil {
		t.Fatalf("plain tls stream must pass the validator, got %v", err)
	}
}
