package config

import (
	"strings"
	"testing"
)

// #9820 GPT-P2: the schema gate refuses space-padded static destinations
// and next-hops. The compiler stores the RAW token and the renderer drops
// a padded one silently, while the validators checked the TRIMMED form —
// so quoted padding committed clean and installed nothing. Flat `set`
// field-splits padding away, so these cells use hierarchical quoted text
// (the only ordinary ingress that preserves it).

func schemaErrPadding9820(t *testing.T, src string) error {
	t.Helper()
	tree, perrs := NewParser(src).Parse()
	if len(perrs) != 0 {
		t.Fatalf("parse errors: %v", perrs)
	}
	return SchemaValidate(tree, nil)
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
	if err == nil || !strings.Contains(err.Error(), "whitespace is not allowed") {
		t.Fatalf("padded destination must be refused with the padding reason, got: %v", err)
	}
	if err := ValidateRouteDestination(" 10.0.0.0/8 ", nil); err == nil {
		t.Fatal("ValidateRouteDestination accepted padding")
	}
	if err := ValidateRouteDestination("10.0.0.0/8", nil); err != nil {
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
	if err == nil || !strings.Contains(err.Error(), "whitespace is not allowed") {
		t.Fatalf("padded next-hop must be refused with the padding reason, got: %v", err)
	}
	for _, bad := range []string{" 192.0.2.1 ", "\tge-0/0/1.0", "2001:db8::1@eth0 "} {
		if err := ValidateStaticNextHop(bad, nil); err == nil {
			t.Errorf("ValidateStaticNextHop(%q) accepted, want rejection", bad)
		}
	}
	for _, ok := range []string{"192.0.2.1", "2001:db8::1", "2001:db8::1@eth0", "@eth0", "reth0.50"} {
		if err := ValidateStaticNextHop(ok, nil); err != nil {
			t.Errorf("ValidateStaticNextHop(%q) = %v, want nil", ok, err)
		}
	}
}
