package config

import (
	"strings"
	"testing"
)

// #4596: protocols lldp transmit-interval / hold-multiplier were untyped
// (bare Atoi, no validator), so an out-of-range value committed and — with the
// pre-clamp encodeTTL — could wrap the LLDP TTL to 0, immediately expiring the
// neighbor. The two leaves now carry the IEEE 802.1AB LLDP-MIB ranges
// (msgTxInterval 5..32768, msgTxHold 2..10) that Junos also enforces.
//
// RED on revert: an untyped leaf stores the value and SchemaValidate returns
// nil.
func TestLLDPTransmitIntervalRange_4596(t *testing.T) {
	// Above the 32768 max — rejected.
	bad := flatTreeFromSets(t, "set protocols lldp transmit-interval 40000")
	if err := SchemaValidate(bad); err == nil ||
		!strings.Contains(err.Error(), "40000") {
		t.Fatalf("out-of-range transmit-interval must be rejected naming the value, got: %v", err)
	}
	// Below the 5 min — rejected.
	low := flatTreeFromSets(t, "set protocols lldp transmit-interval 0")
	if err := SchemaValidate(low); err == nil {
		t.Fatal("transmit-interval 0 must be rejected (below the 5s minimum)")
	}
	// In-range values commit clean, including the boundaries.
	for _, v := range []string{"5", "30", "16384", "32768"} {
		ok := flatTreeFromSets(t, "set protocols lldp transmit-interval "+v)
		if err := SchemaValidate(ok); err != nil {
			t.Errorf("valid transmit-interval %s rejected: %v", v, err)
		}
	}
}

func TestLLDPHoldMultiplierRange_4596(t *testing.T) {
	// Above the 10 max — rejected.
	bad := flatTreeFromSets(t, "set protocols lldp hold-multiplier 20")
	if err := SchemaValidate(bad); err == nil ||
		!strings.Contains(err.Error(), "20") {
		t.Fatalf("out-of-range hold-multiplier must be rejected naming the value, got: %v", err)
	}
	// Below the 2 min — rejected.
	low := flatTreeFromSets(t, "set protocols lldp hold-multiplier 1")
	if err := SchemaValidate(low); err == nil {
		t.Fatal("hold-multiplier 1 must be rejected (below the 2 minimum)")
	}
	// In-range values commit clean, including the boundaries.
	for _, v := range []string{"2", "4", "10"} {
		ok := flatTreeFromSets(t, "set protocols lldp hold-multiplier "+v)
		if err := SchemaValidate(ok); err != nil {
			t.Errorf("valid hold-multiplier %s rejected: %v", v, err)
		}
	}
}
