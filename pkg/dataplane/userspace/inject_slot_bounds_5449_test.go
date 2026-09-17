package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

// Tests for #5449: the binding-slot parses (inject-packet and binding
// commands) and the inject validate seam must reject negative and
// out-of-range slot indices instead of wrapping them into a huge uint32.
//
// RED-on-revert: reverting parseBindingSlot's bounds check makes the
// unguarded strconv.Atoi + uint32() cast return 4294967295 for "slot -1"
// (and accept 4096, one past the slot dimension). The "-1 rejected" and
// "at-bound rejected" assertions below then fail because a non-nil error
// is expected but the wrapped/oversized slot is returned instead.
// Likewise, dropping the validateInjectPacketRequestForHelper slot guard
// makes the Slot=4294967295 request pass the slot check.

func TestParseInjectPacketCommandSlotBounds(t *testing.T) {
	tests := []struct {
		name     string
		slotArg  string
		wantErr  bool
		wantSlot uint32
	}{
		{name: "negative wraps", slotArg: "-1", wantErr: true},
		{name: "at-bound", slotArg: "4096", wantErr: true}, // == BindingSlotMapMaxEntries (#9915 F-124)
		{name: "over-bound", slotArg: "2000000", wantErr: true},
		{name: "zero", slotArg: "0", wantErr: false, wantSlot: 0},
		{name: "mid-range", slotArg: "5", wantErr: false, wantSlot: 5},
		{name: "max-valid", slotArg: "4095", wantErr: false, wantSlot: 4095}, // BindingSlotMapMaxEntries-1
		{name: "not-a-number", slotArg: "abc", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			slot, mode, extra, err := ParseInjectPacketCommand(
				[]string{"inject-packet", "slot", tt.slotArg, "valid"})
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ParseInjectPacketCommand(slot %s) = nil error, want error", tt.slotArg)
				}
				if slot != 0 {
					t.Fatalf("ParseInjectPacketCommand(slot %s) returned slot %d on error, want 0 (must NOT return wrapped uint32)", tt.slotArg, slot)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseInjectPacketCommand(slot %s) error = %v", tt.slotArg, err)
			}
			if slot != tt.wantSlot {
				t.Fatalf("ParseInjectPacketCommand(slot %s) slot = %d, want %d", tt.slotArg, slot, tt.wantSlot)
			}
			if mode != "valid" {
				t.Fatalf("ParseInjectPacketCommand(slot %s) mode = %q, want valid", tt.slotArg, mode)
			}
			if extra == nil {
				t.Fatalf("ParseInjectPacketCommand(slot %s) extra = nil, want non-nil map", tt.slotArg)
			}
		})
	}
}

func TestParseBindingCommandSlotBounds(t *testing.T) {
	tests := []struct {
		name     string
		slotArg  string
		wantErr  bool
		wantSlot uint32
	}{
		{name: "negative wraps", slotArg: "-1", wantErr: true},
		{name: "at-bound", slotArg: "4096", wantErr: true}, // == BindingSlotMapMaxEntries (#9915 F-124)
		{name: "over-bound", slotArg: "9999999", wantErr: true},
		{name: "zero", slotArg: "0", wantErr: false, wantSlot: 0},
		{name: "mid-range", slotArg: "7", wantErr: false, wantSlot: 7},
		{name: "max-valid", slotArg: "4095", wantErr: false, wantSlot: 4095}, // BindingSlotMapMaxEntries-1
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			slot, registered, armed, err := ParseBindingCommand(
				[]string{"binding", "slot", tt.slotArg, "register"})
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ParseBindingCommand(slot %s) = nil error, want error", tt.slotArg)
				}
				if slot != 0 {
					t.Fatalf("ParseBindingCommand(slot %s) returned slot %d on error, want 0 (must NOT return wrapped uint32)", tt.slotArg, slot)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseBindingCommand(slot %s) error = %v", tt.slotArg, err)
			}
			if slot != tt.wantSlot {
				t.Fatalf("ParseBindingCommand(slot %s) slot = %d, want %d", tt.slotArg, slot, tt.wantSlot)
			}
			if !registered || armed {
				t.Fatalf("ParseBindingCommand(slot %s) = (reg %t, armed %t), want (true,false)", tt.slotArg, registered, armed)
			}
		})
	}
}

func TestValidateInjectPacketRequestForHelperSlotBounds(t *testing.T) {
	status := ProcessStatus{}

	// A request built directly (bypassing parseBindingSlot) with the
	// wrapped -1 value must be rejected at the helper seam.
	oob := InjectPacketRequest{Slot: 4294967295, EmitOnWire: false}
	if err := validateInjectPacketRequestForHelper(oob, status); err == nil {
		t.Fatal("validateInjectPacketRequestForHelper(Slot=4294967295) = nil error, want out-of-range error")
	}

	// The at-bound value (== BindingArrayMaxEntries) is also out of range.
	atBound := InjectPacketRequest{Slot: dataplane.BindingArrayMaxEntries, EmitOnWire: false}
	if err := validateInjectPacketRequestForHelper(atBound, status); err == nil {
		t.Fatalf("validateInjectPacketRequestForHelper(Slot=%d) = nil error, want out-of-range error", dataplane.BindingArrayMaxEntries)
	}

	// A valid in-range slot passes the slot check. With EmitOnWire=false
	// the function returns nil once the slot check is satisfied.
	valid := InjectPacketRequest{Slot: 5, EmitOnWire: false}
	if err := validateInjectPacketRequestForHelper(valid, status); err != nil {
		t.Fatalf("validateInjectPacketRequestForHelper(Slot=5) error = %v, want nil", err)
	}
}
