package config

import (
	"strings"
	"testing"
)

// TestDPDIntervalThreshold_SchemaGate_4878 proves the #4878 fix: the IKE /
// IPsec-gateway `dead-peer-detection interval` and `threshold` VALUES are typed
// integers, so a non-numeric token, a non-positive value, or an
// int64-overflowing value is REJECTED at the commit-check gate (SchemaValidate)
// instead of being silently swallowed (the compiler's strconv.Atoi error was
// ignored → the field stayed 0 → strongSwan default; a huge value overflowed
// the rendered dpd_timeout).
//
// FAIL-ON-REVERT: dropping `valueType: ValueInteger, validator:
// ValidateInteger(...)` from the two DPD leaves makes the untyped leaf accept
// any token again, so the reject assertions below fire RED.
func TestDPDIntervalThreshold_SchemaGate_4878(t *testing.T) {
	// Both closed-world DPD copies: security ike gateway AND security ipsec
	// gateway. The value slot is validated identically on each.
	prefixes := []string{
		"set security ike gateway gw1 dead-peer-detection",
		"set security ipsec gateway gw1 dead-peer-detection",
	}
	// value tokens that must be REJECTED at commit.
	bad := []string{"banana", "0", "-1", "-5", "9223372036854775807", "99999999999999999999999", "3.5"}
	// value tokens that must be ACCEPTED.
	good := []string{"1", "5", "10", "30", "60", "3600"}
	goodThreshold := []string{"1", "3", "5", "100"}

	for _, pfx := range prefixes {
		for _, leaf := range []string{"interval", "threshold"} {
			vals := good
			if leaf == "threshold" {
				vals = goodThreshold
			}
			for _, v := range bad {
				tree := flatTreeFromSets(t, pfx+" "+leaf+" "+v)
				if err := SchemaValidate(tree); err == nil {
					t.Fatalf("%s %s %q: expected SchemaValidate to reject, got nil", pfx, leaf, v)
				}
			}
			for _, v := range vals {
				tree := flatTreeFromSets(t, pfx+" "+leaf+" "+v)
				if err := SchemaValidate(tree); err != nil {
					t.Fatalf("%s %s %q: expected SchemaValidate to accept, got %v", pfx, leaf, v, err)
				}
			}
		}
	}
}

// TestDPDIntervalThreshold_ErrorNamesValue_4878 confirms the reject error names
// the offending token so the operator sees which value was bad.
func TestDPDIntervalThreshold_ErrorNamesValue_4878(t *testing.T) {
	tree := flatTreeFromSets(t, "set security ike gateway gw1 dead-peer-detection interval banana")
	err := SchemaValidate(tree)
	if err == nil {
		t.Fatal("expected `interval banana` to be rejected at commit-check")
	}
	if !strings.Contains(err.Error(), "banana") {
		t.Fatalf("error %q must name the offending value 'banana'", err.Error())
	}
}

// TestDPDIntervalThreshold_HierarchicalGate_4878 exercises the hierarchical AST
// shape (as `load merge` / a saved config produces) in addition to flat-set.
func TestDPDIntervalThreshold_HierarchicalGate_4878(t *testing.T) {
	rejectHier := hierTree(t, `security {
    ike {
        gateway gw1 {
            dead-peer-detection {
                interval banana;
            }
        }
    }
}`)
	if err := SchemaValidate(rejectHier); err == nil {
		t.Fatal("hierarchical `interval banana` must be rejected at commit-check")
	}

	acceptHier := hierTree(t, `security {
    ike {
        gateway gw1 {
            dead-peer-detection {
                interval 30;
                threshold 3;
            }
        }
    }
}`)
	if err := SchemaValidate(acceptHier); err != nil {
		t.Fatalf("hierarchical valid DPD values must pass commit-check, got %v", err)
	}
}

// TestDPDIntervalThreshold_ValidCompiles_4878 proves a valid DPD config still
// compiles and the typed interval/threshold reach the compiled gateway (so the
// gate does not disturb the happy path).
func TestDPDIntervalThreshold_ValidCompiles_4878(t *testing.T) {
	tree := flatTreeFromSets(t,
		"set security ike gateway gw1 dead-peer-detection interval 30",
		"set security ike gateway gw1 dead-peer-detection threshold 3",
	)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("valid DPD config must compile: %v", err)
	}
	gw := cfg.Security.IPsec.Gateways["gw1"]
	if gw == nil {
		t.Fatal("expected gateway gw1 in the compiled config")
	}
	if gw.DPDInterval != 30 {
		t.Fatalf("DPDInterval = %d, want 30", gw.DPDInterval)
	}
	if gw.DPDThreshold != 3 {
		t.Fatalf("DPDThreshold = %d, want 3", gw.DPDThreshold)
	}
}
