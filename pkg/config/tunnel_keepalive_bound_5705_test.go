package config

import (
	"strings"
	"testing"
)

// TestTunnelKeepaliveInterval_SchemaGate_5705 proves the #5705 admission
// fix: the tunnel `keepalive` VALUE is a typed integer bounded to
// 0..32767 seconds, so a value that would overflow
// time.Duration(sec)*time.Second (int64 ns) at the runtime probe/ticker
// multiply is REJECTED at the commit-check gate (SchemaValidate) instead
// of reaching the dataplane and panicking xpfd via time.NewTicker.
//
// FAIL-ON-REVERT: dropping `valueType: ValueInteger, validator:
// ValidateInteger(0, 32767)` from the keepalive leaf makes the untyped
// leaf accept any token again, so the reject assertions below fire RED.
func TestTunnelKeepaliveInterval_SchemaGate_5705(t *testing.T) {
	// The tunnel stanza appears at both interface level and unit level;
	// both share tunnelSchemaChildren(), so validate each position.
	prefixes := []string{
		"set interfaces gr-0/0/0 tunnel keepalive",
		"set interfaces gr-0/0/0 unit 0 tunnel keepalive",
	}
	// Values that MUST be rejected at commit: the huge int64-overflowing
	// values are the actual #5705 crash trigger; negatives and non-ints
	// are rejected as a side effect of typing the leaf.
	bad := []string{
		"banana",
		"-1",
		"-5",
		"32768",                   // one past the ceiling
		"10000000000",             // 1e10 s * 1e9 ns overflows int64 → wraps negative → NewTicker panic
		"9223372036854775807",     // int64 max
		"99999999999999999999999", // not representable
	}
	// Values that MUST be accepted (0 = disabled, plus the ceiling).
	good := []string{"0", "1", "10", "30", "300", "32767"}

	for _, pfx := range prefixes {
		for _, v := range bad {
			tree := flatTreeFromSets(t, pfx+" "+v)
			if err := SchemaValidate(tree); err == nil {
				t.Fatalf("%s %q: expected SchemaValidate to reject, got nil", pfx, v)
			}
		}
		for _, v := range good {
			tree := flatTreeFromSets(t, pfx+" "+v)
			if err := SchemaValidate(tree); err != nil {
				t.Fatalf("%s %q: expected SchemaValidate to accept, got %v", pfx, v, err)
			}
		}
	}
}

// TestTunnelKeepaliveInterval_ErrorNamesValue_5705 confirms the reject
// error names the offending token so the operator sees which value the
// commit-check refused.
func TestTunnelKeepaliveInterval_ErrorNamesValue_5705(t *testing.T) {
	tree := flatTreeFromSets(t, "set interfaces gr-0/0/0 unit 0 tunnel keepalive 10000000000")
	err := SchemaValidate(tree)
	if err == nil {
		t.Fatal("expected an int64-overflowing keepalive to be rejected at commit-check")
	}
	if !strings.Contains(err.Error(), "10000000000") {
		t.Fatalf("error %q must name the offending value", err.Error())
	}
}

// TestTunnelKeepaliveInterval_HierarchicalGate_5705 exercises the
// hierarchical AST shape (as `load merge` / a saved config produces) in
// addition to flat-set.
func TestTunnelKeepaliveInterval_HierarchicalGate_5705(t *testing.T) {
	reject := hierTree(t, `interfaces {
    gr-0/0/0 {
        unit 0 {
            tunnel {
                keepalive 10000000000;
            }
        }
    }
}`)
	if err := SchemaValidate(reject); err == nil {
		t.Fatal("hierarchical overflowing keepalive must be rejected at commit-check")
	}

	accept := hierTree(t, `interfaces {
    gr-0/0/0 {
        unit 0 {
            tunnel {
                keepalive 30;
            }
        }
    }
}`)
	if err := SchemaValidate(accept); err != nil {
		t.Fatalf("hierarchical valid keepalive must pass commit-check, got %v", err)
	}
}
