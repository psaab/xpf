package userspace

import (
	"strings"
	"testing"
)

// STEP-0 RED cells for psaab/xpf#9915 F-124: the CLI/gRPC slot grammar must
// agree with the helper seam on the slot dimension (4096, not 1048576), and the
// emit-on-wire uint16 source-port derivation must run AFTER slot validation.
// Each cell fails on base and is kept as regression coverage.
func TestParseBindingSlotRejectsAboveSlotDimension_9915(t *testing.T) {
	for _, arg := range []string{"4096", "5000", "1048575", "1048576"} {
		if _, err := parseBindingSlot(arg); err == nil {
			t.Errorf("parseBindingSlot(%q) accepted, want out-of-range error; "+
				"the grammar admits 256x the addressable slot dimension (F-124)", arg)
		}
	}
	for _, arg := range []string{"0", "4095"} {
		if _, err := parseBindingSlot(arg); err != nil {
			t.Errorf("CONTROL: parseBindingSlot(%q) rejected: %v", arg, err)
		}
	}
}

func TestBuildInjectRejectsSlotBeforePortDerivation_9915(t *testing.T) {
	extra := map[string]string{
		"destination-ip": "172.16.80.200",
		"emit-on-wire":   "true",
		"source-ip":      "172.16.80.8",
	}
	status := ProcessStatus{InjectPacketTupleProtocolVersion: InjectPacketTupleProtocolVersion}
	if _, err := BuildInjectPacketRequest(70000, "valid", extra, status); err == nil {
		t.Fatal("BuildInjectPacketRequest(slot=70000) succeeded, baking uint16(70000)=4464 " +
			"as the source port; the slot must be validated before derivation (F-124)")
	} else if !strings.Contains(err.Error(), "out of range") {
		t.Fatalf("slot 70000 rejected for the wrong reason: %v", err)
	}

	if _, err := BuildInjectPacketRequest(7, "valid", extra, status); err != nil {
		t.Fatalf("CONTROL: addressable slot 7 must still build: %v", err)
	}
}
