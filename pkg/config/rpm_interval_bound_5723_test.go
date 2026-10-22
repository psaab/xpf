package config

import (
	"testing"
)

// TestRPMIntervalSchemaGate_5723 proves the #5723 admission fix: the RPM
// `test-interval` and `probe-interval` VALUES are typed integers bounded to
// 1..MaxDurationSeconds, so a value that would overflow
// time.Duration(sec)*time.Second (int64 ns) at the runtime probe loop's
// time.NewTicker / time.After is REJECTED at the commit-check gate
// (SchemaValidate) instead of reaching pkg/rpm and panicking xpfd. Sibling of
// the #5705 tunnel-keepalive crash.
//
// FAIL-ON-REVERT: restoring `validator: ValidateIntegerMin(1)` (no upper bound)
// on either leaf makes the huge-value reject assertions below fire RED.
func TestRPMIntervalSchemaGate_5723(t *testing.T) {
	prefixes := []string{
		"set services rpm probe p1 test t1 test-interval",
		"set services rpm probe p1 test t1 probe-interval",
	}
	// Values that MUST be rejected at commit: the huge int64-overflowing values
	// are the actual #5723 crash trigger; negatives / non-ints are rejected as a
	// side effect of typing the leaf.
	bad := []string{
		"banana",
		"0",  // below the 1s minimum
		"-1", // negative
		// MaxDurationSeconds is math.MaxInt64/1e9 ≈ 9223372036; one past it
		// overflows the *time.Second multiply.
		"9223372037",           // MaxDurationSeconds + 1
		"9999999999",           // ~1e10 s * 1e9 ns overflows int64 → non-positive Duration → NewTicker panic
		"9223372036854775807",  // int64 max
		"99999999999999999999", // not representable as int64
	}
	// Values that MUST be accepted (1 = min, plus a large-but-safe value and the
	// exact ceiling).
	good := []string{"1", "5", "30", "3600", "9223372036"} // last == MaxDurationSeconds

	for _, pfx := range prefixes {
		for _, v := range bad {
			tree := flatTreeFromSets(t, pfx+" "+v)
			if err := SchemaValidate(tree); err == nil {
				t.Errorf("%s %q: expected SchemaValidate to reject, got nil", pfx, v)
			}
		}
		for _, v := range good {
			tree := flatTreeFromSets(t, pfx+" "+v)
			if err := SchemaValidate(tree); err != nil {
				t.Errorf("%s %q: expected SchemaValidate to accept, got %v", pfx, v, err)
			}
		}
	}
}
