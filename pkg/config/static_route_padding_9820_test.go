package config

import (
	"strings"
	"testing"
)

// #9820 GPT-P2: the schema gate refuses space-padded static destinations
// and next-hops. The compiler stores the RAW token and the renderer drops
// a padded one silently, while the validators checked the TRIMMED form —
// so quoted padding committed clean and installed nothing. Quoted padding
// survives the lexer in both flat and hierarchical ingress (parser and
// lexer preserve quoted-string contents verbatim); these cells use
// hierarchical quoted text.

func schemaErrPadding9820(t *testing.T, src string) error {
	t.Helper()
	tree, perrs := NewParser(src).Parse()
	if len(perrs) != 0 {
		t.Fatalf("parse errors: %v", perrs)
	}
	return SchemaValidate(tree)
}

func TestStaticRoutePaddedDestinationRefused_9820(t *testing.T) {
	err := schemaErrPadding9820(t, `
routing-options {
    static {
        route " 2001:db8::/32 " {
            next-hop 2001:db8::1;
        }
    }
}`)
	if err == nil || !strings.Contains(err.Error(), "must not have leading or trailing whitespace") {
		t.Fatalf("padded destination must be refused with the padding reason, got: %v", err)
	}
	// Direct call: padding refusal is central (#17177), so the bare
	// validator retains its trimmed grammar leniency; the
	// SchemaValidate cell above pins the commit-path refusal.
	// (The unpadded control is asserted just below.)
	if err := ValidateRouteDestination("10.0.0.0/8"); err != nil {
		t.Fatalf("unpadded destination must be accepted, got: %v", err)
	}
}

func TestStaticNextHopPaddedRefused_9820(t *testing.T) {
	err := schemaErrPadding9820(t, `
routing-options {
    static {
        route 2001:db8::/32 {
            next-hop " 2001:db8::1 ";
        }
    }
}`)
	if err == nil || !strings.Contains(err.Error(), "must not have leading or trailing whitespace") {
		t.Fatalf("padded next-hop must be refused with the padding reason, got: %v", err)
	}
	// Direct calls: padding refusal is central (#17177), so the bare
	// validator retains trimmed leniency for some forms; the
	// SchemaValidate cell above pins the commit-path refusal. A tab-
	// padded interface name still fails the bare grammar.
	if err := ValidateStaticNextHop("\tge-0/0/1.0"); err == nil {
		t.Errorf("ValidateStaticNextHop(tab-padded) accepted, want rejection")
	}
	for _, ok := range []string{"192.0.2.1", "2001:db8::1", "2001:db8::1@eth0", "@eth0", "reth0.50"} {
		if err := ValidateStaticNextHop(ok); err != nil {
			t.Errorf("ValidateStaticNextHop(%q) = %v, want nil", ok, err)
		}
	}
}
