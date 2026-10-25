package routing

import "testing"

// TestVRFDeviceName16664 locks the unconditional instance->device
// mapping (#16664): the daemon creates instance N as "vrf-"+N with no
// canonicalisation, so a vrf- prefixed instance name must gain the
// prefix again. The #2143 exactly-once guard in diagcmd resolved
// instance "vrf-cust" onto sibling instance "cust" for ping/DDNS/HA.
func TestVRFDeviceName16664(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"empty stays empty", "", ""},
		{"bare name gets prefix", "cust", "vrf-cust"},
		{"vrf-prefixed instance gets prefix again", "vrf-cust", "vrf-vrf-cust"},
		{"vrf-mgmt instance does not map onto management VRF", "vrf-mgmt", "vrf-vrf-mgmt"},
		{"mgmt instance is the management VRF (control)", "mgmt", "vrf-mgmt"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := VRFDeviceName(tt.in); got != tt.want {
				t.Fatalf("VRFDeviceName(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// TestCreateVRFForPrefixedInstance16664 is the creator-side control:
// creating instance "vrf-cust" must materialise device "vrf-vrf-cust"
// (and leave sibling "cust"'s "vrf-cust" untouched), matching what the
// consumers now resolve.
func TestCreateVRFForPrefixedInstance16664(t *testing.T) {
	ops := newFakeVRFOps()
	vm := &vrfManager{ops: ops}
	if err := vm.Create("vrf-cust", 101); err != nil {
		t.Fatalf("Create(vrf-cust): %v", err)
	}
	if _, ok := ops.links["vrf-vrf-cust"]; !ok {
		t.Fatalf("links = %v, want device vrf-vrf-cust for instance vrf-cust", keysOf(ops.links))
	}
	if _, ok := ops.links["vrf-cust"]; ok {
		t.Fatalf("instance vrf-cust must not materialise sibling device vrf-cust")
	}
	if !vm.IsManaged("vrf-cust") {
		t.Fatalf("IsManaged(vrf-cust) = false, want true")
	}
	// Sibling control: instance "cust" still maps to "vrf-cust".
	if err := vm.Create("cust", 102); err != nil {
		t.Fatalf("Create(cust): %v", err)
	}
	if _, ok := ops.links["vrf-cust"]; !ok {
		t.Fatalf("links = %v, want device vrf-cust for instance cust", keysOf(ops.links))
	}
}

func keysOf[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
