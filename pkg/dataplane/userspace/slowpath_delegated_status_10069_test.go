package userspace

import (
	"encoding/json"
	"testing"
)

// #10069 Gap 2: the delegated slow-path outlet surfaces next to the trusted
// outlet on the status wire. A new helper reports slow_path_delegated with
// the outlet's live MTU, degraded flag and counters; an old helper omits the
// key and it decodes to the zero value (additive, skew-safe).
func TestSlowPathDelegatedDecodesNextToTrusted10069(t *testing.T) {
	var cur ProcessStatus
	if err := json.Unmarshal([]byte(`{"slow_path":{"active":true,"live_mtu":9000},`+
		`"slow_path_delegated":{"active":true,"degraded":true,"live_mtu":1500,`+
		`"device_name":"xpf-usp1","injected_packets":7,"mtu_dropped_packets":3}}`), &cur); err != nil {
		t.Fatalf("decode current payload: %v", err)
	}
	// POSITIVE CONTROL: the trusted outlet decoded, so a zero delegated
	// outlet below is about the missing field, not a failed unmarshal.
	if !cur.SlowPath.Active || cur.SlowPath.LiveMTU != 9000 {
		t.Fatalf("control: trusted outlet did not decode (active=%t live_mtu=%d); "+
			"the delegated assertions below would prove nothing",
			cur.SlowPath.Active, cur.SlowPath.LiveMTU)
	}
	d := cur.SlowPathDelegated
	if !d.Active || !d.Degraded || d.LiveMTU != 1500 {
		t.Errorf("delegated outlet = active=%t degraded=%t live_mtu=%d, "+
			"want active=true degraded=true live_mtu=1500",
			d.Active, d.Degraded, d.LiveMTU)
	}
	if d.DeviceName != "xpf-usp1" || d.InjectedPackets != 7 || d.MTUDroppedPackets != 3 {
		t.Errorf("delegated outlet device/counters not decoded: %+v", d)
	}

	// An OLD helper omits the key: decodes to zero, never fails.
	var old ProcessStatus
	if err := json.Unmarshal([]byte(`{"slow_path":{"active":true}}`), &old); err != nil {
		t.Fatalf("decode old payload: %v", err)
	}
	if old.SlowPathDelegated != (SlowPathStatus{}) {
		t.Errorf("absent slow_path_delegated must decode to zero, got %+v",
			old.SlowPathDelegated)
	}
}
