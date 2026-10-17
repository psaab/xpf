package config

import (
	"strings"
	"testing"
)

// TestDynamicAddressInterval_SchemaGate_4879 proves the #4879 fix: the
// `security dynamic-address feed-server <s> update-interval` / `hold-interval`
// VALUES are typed integers, so a non-numeric token (`2h`, `fast`), a
// non-positive value, or an int64-overflowing value is REJECTED at the
// commit-check gate (SchemaValidate) instead of being silently swallowed. The
// compiler's strconv.Atoi error was ignored → the field stayed 0 → the runtime
// substituted its defaults (update→3600s, hold→retain-forever), so the operator
// intent was dropped without any commit error.
//
// FAIL-ON-REVERT: dropping `valueType: ValueInteger, validator:
// ValidateInteger(1, MaxDurationSeconds)` from the two leaves in
// schema_security.go makes the untyped leaf accept any token again, so the
// reject assertions below fire RED.
func TestDynamicAddressInterval_SchemaGate_4879(t *testing.T) {
	prefix := "set security dynamic-address feed-server threat"
	// tokens that must be REJECTED at commit.
	bad := []string{"2h", "fast", "banana", "0", "-1", "-3600", "9999999999999999999", "3.5", "1_000"}
	// tokens that must be ACCEPTED.
	good := []string{"1", "60", "300", "3600", "86400"}

	for _, leaf := range []string{"update-interval", "hold-interval"} {
		for _, v := range bad {
			tree := flatTreeFromSets(t, prefix+" "+leaf+" "+v)
			if err := SchemaValidate(tree, nil); err == nil {
				t.Fatalf("%s %s %q: expected SchemaValidate to reject, got nil", prefix, leaf, v)
			}
		}
		for _, v := range good {
			tree := flatTreeFromSets(t, prefix+" "+leaf+" "+v)
			if err := SchemaValidate(tree, nil); err != nil {
				t.Fatalf("%s %s %q: expected SchemaValidate to accept, got %v", prefix, leaf, v, err)
			}
		}
	}
}

// TestDynamicAddressInterval_ErrorNamesValue_4879 confirms the reject error
// names the offending token so the operator sees which value was bad.
func TestDynamicAddressInterval_ErrorNamesValue_4879(t *testing.T) {
	tree := flatTreeFromSets(t, "set security dynamic-address feed-server threat hold-interval 2h")
	err := SchemaValidate(tree, nil)
	if err == nil {
		t.Fatal("expected `hold-interval 2h` to be rejected at commit-check")
	}
	if !strings.Contains(err.Error(), "2h") {
		t.Fatalf("error %q must name the offending value '2h'", err.Error())
	}
}

// TestDynamicAddressInterval_HierarchicalGate_4879 exercises the hierarchical
// AST shape (as `load merge` / a saved config produces) in addition to flat-set,
// since the lenient load path walks the same schema.
func TestDynamicAddressInterval_HierarchicalGate_4879(t *testing.T) {
	rejectHier := hierTree(t, `security {
    dynamic-address {
        feed-server threat {
            update-interval fast;
        }
    }
}`)
	if err := SchemaValidate(rejectHier, nil); err == nil {
		t.Fatal("hierarchical `update-interval fast` must be rejected at commit-check")
	}

	acceptHier := hierTree(t, `security {
    dynamic-address {
        feed-server threat {
            update-interval 300;
            hold-interval 86400;
        }
    }
}`)
	if err := SchemaValidate(acceptHier, nil); err != nil {
		t.Fatalf("hierarchical valid interval values must pass commit-check, got %v", err)
	}
}

// TestDynamicAddressInterval_ValidCompiles_4879 proves a valid config still
// compiles and the typed intervals reach the compiled feed server (so the gate
// does not disturb the happy path).
func TestDynamicAddressInterval_ValidCompiles_4879(t *testing.T) {
	tree := flatTreeFromSets(t,
		"set security dynamic-address feed-server threat url https://feeds.example.net/list",
		"set security dynamic-address feed-server threat update-interval 300",
		"set security dynamic-address feed-server threat hold-interval 86400",
	)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("valid dynamic-address config must compile: %v", err)
	}
	fs := cfg.Security.DynamicAddress.FeedServers["threat"]
	if fs == nil {
		t.Fatal("expected feed-server threat in the compiled config")
	}
	if fs.UpdateInterval != 300 {
		t.Fatalf("UpdateInterval = %d, want 300", fs.UpdateInterval)
	}
	if fs.HoldInterval != 86400 {
		t.Fatalf("HoldInterval = %d, want 86400", fs.HoldInterval)
	}
}
