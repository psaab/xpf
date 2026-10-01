package userspace

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestBuildInterfaceSnapshotsCarriesNativeVLANID11434(t *testing.T) {
	cfg := &config.Config{
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"ge-0/0/1": {
					Name:         "ge-0/0/1",
					NativeVlanID: 100,
					Units: map[int]*config.InterfaceUnit{
						0:   {Number: 0, VlanID: 0},
						100: {Number: 100, VlanID: 100},
					},
				},
			},
		},
	}

	snapshots := buildInterfaceSnapshotsFrom(cfg, nil)
	var base, native *InterfaceSnapshot
	for i := range snapshots {
		snapshot := &snapshots[i]
		if snapshot.Name == "ge-0/0/1" {
			base = snapshot
		}
		if snapshot.Name == "ge-0/0/1.100" {
			native = snapshot
		}
	}
	if base == nil || native == nil {
		t.Fatalf("snapshot rows missing base or native VLAN unit: base=%v native=%v", base, native)
	}
	if base.NativeVLANID != 100 {
		t.Fatalf("base NativeVLANID = %d, want 100", base.NativeVLANID)
	}
	if native.VLANID != 100 {
		t.Fatalf("native unit VLANID = %d, want 100", native.VLANID)
	}
	if native.NativeVLANID != 0 {
		t.Fatalf("unit NativeVLANID = %d, want only base rows to carry it", native.NativeVLANID)
	}
}

func TestNativeVLANWireKeyMatchesRust11434(t *testing.T) {
	goKey := jsonKeyOf(t, reflect.TypeOf(InterfaceSnapshot{}), "NativeVLANID")
	path := filepath.Join("..", "..", "..", "userspace-dp", "src", "protocol", "snapshot.rs")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read Rust snapshot definition: %v", err)
	}
	body := rustStructBody(t, string(raw), "InterfaceSnapshot")
	rustKey := rustSerdeRenameOf(t, body, "native_vlan_id")
	if goKey != rustKey {
		t.Fatalf("native VLAN wire key mismatch: Go emits %q, Rust reads %q", goKey, rustKey)
	}
}
