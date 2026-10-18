package config

import (
	"strings"
	"testing"
)

// #14685 D9-05: the compact single-node spelling
//
//	set chassis device-map interface ge-0/0/3 key pci pci 0000:01:00.0
//
// packs every token into the instance node's Keys (or into a deepest
// leaf's Keys). collectDeviceMapProps stepped i++ over Keys with
// first-write-wins, so the VALUE of `key` ("pci"/"mac") was re-read as
// a property keyword and captured the following keyword as its value:
//
//	  key pci pci 0000:01:00.0  ->  KeyOrder="pci" PCIAddr="pci"
//	  key mac mac 00:11:... pci 0000:01:00.0
//	                            ->  KeyOrder="mac" MAC="mac" PCIAddr="0000:01:00.0"
//
// The real address was never recorded, yet validateDeviceMapStrict
// passed (PCIAddr "pci" is non-empty) and SchemaValidate's 1+args
// stepping also validated the intended pairs cleanly, so the device-map
// resolver searched for PCI "pci" / MAC "mac" and could not bind.

func TestDeviceMapCompactKeyPCIConsersTail14685(t *testing.T) {
	tree := hierTree(t, `chassis { device-map { interface ge-0/0/3 key pci pci 0000:01:00.0; } }`)
	if err := SchemaValidate(tree, nil); err != nil {
		t.Fatalf("SchemaValidate compact key pci: %v", err)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig compact key pci: %v", err)
	}
	if cfg == nil || cfg.Chassis.DeviceMap == nil || len(cfg.Chassis.DeviceMap.Entries) != 1 {
		t.Fatalf("want 1 entry, got %+v", cfg)
	}
	e := cfg.Chassis.DeviceMap.Entries[0]
	if e.KeyOrder != "pci" || e.PCIAddr != "0000:01:00.0" || e.MAC != "" {
		t.Fatalf("compact key pci corrupted: got KeyOrder=%q PCIAddr=%q MAC=%q, want KeyOrder=%q PCIAddr=%q MAC=%q",
			e.KeyOrder, e.PCIAddr, e.MAC, "pci", "0000:01:00.0", "")
	}
}

func TestDeviceMapCompactKeyMACConsersTail14685(t *testing.T) {
	tree := hierTree(t, `chassis { device-map { interface ge-0/0/3 key mac mac 00:11:22:33:44:55 pci 0000:01:00.0; } }`)
	if err := SchemaValidate(tree, nil); err != nil {
		t.Fatalf("SchemaValidate compact key mac: %v", err)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig compact key mac: %v", err)
	}
	if cfg == nil || cfg.Chassis.DeviceMap == nil || len(cfg.Chassis.DeviceMap.Entries) != 1 {
		t.Fatalf("want 1 entry, got %+v", cfg)
	}
	e := cfg.Chassis.DeviceMap.Entries[0]
	if e.KeyOrder != "mac" || e.MAC != "00:11:22:33:44:55" || e.PCIAddr != "0000:01:00.0" {
		t.Fatalf("compact key mac corrupted: got KeyOrder=%q PCIAddr=%q MAC=%q, want KeyOrder=%q PCIAddr=%q MAC=%q",
			e.KeyOrder, e.PCIAddr, e.MAC, "mac", "0000:01:00.0", "00:11:22:33:44:55")
	}
}

func TestDeviceMapCompactKeyPCIThenMACControl14685(t *testing.T) {
	// Control: a key value that is not itself a prop keyword must keep
	// compiling exactly as before.
	tree := buildTree(t, []string{
		"set chassis device-map interface ge-0/0/3 pci 0000:01:00.0 mac 00:11:22:33:44:55 key pci-then-mac",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig control: %v", err)
	}
	e := cfg.Chassis.DeviceMap.Entries[0]
	if e.KeyOrder != "pci-then-mac" || e.PCIAddr != "0000:01:00.0" || e.MAC != "00:11:22:33:44:55" {
		t.Fatalf("control corrupted: %+v", e)
	}
}

func TestDeviceMapCompactKeyMacThenPCIControl14685(t *testing.T) {
	tree := buildTree(t, []string{
		"set chassis device-map interface ge-0/0/3 key mac-then-pci pci 0000:01:00.0 mac 00:11:22:33:44:55",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig control mac-then-pci first: %v", err)
	}
	e := cfg.Chassis.DeviceMap.Entries[0]
	if e.KeyOrder != "mac-then-pci" || e.PCIAddr != "0000:01:00.0" || e.MAC != "00:11:22:33:44:55" {
		t.Fatalf("control mac-then-pci corrupted: %+v", e)
	}
}

func TestDeviceMapInvalidIdentityStrict14685(t *testing.T) {
	// Decisive regression (second half): an identity value that is not a
	// valid PCI/MAC must fail the STRICT compile even when it bypasses
	// SchemaValidate (direct CompileConfig callers).
	for _, tc := range []struct {
		name string
		line string
		want string
	}{
		{"pci keyword as address", "set chassis device-map interface ge-0/0/3 pci pci", "pci"},
		{"mac keyword as address", "set chassis device-map interface ge-0/0/3 mac mac", "mac"},
		{"garbage pci", "set chassis device-map interface ge-0/0/3 pci not-a-pci-addr", "pci"},
		{"garbage mac", "set chassis device-map interface ge-0/0/3 mac not-a-mac", "mac"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree := buildTree(t, []string{tc.line})
			if _, err := CompileConfig(tree); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("strict CompileConfig(%q) = %v, want error naming %q", tc.line, err, tc.want)
			}
		})
	}
}

func TestDeviceMapInvalidIdentityLenientWarns14685(t *testing.T) {
	// The tolerant path must downgrade the same invalid identity to a
	// warning (V-1), not hard-fail — a peer-persisted bad entry still boots.
	tree := buildTree(t, []string{
		"set chassis device-map interface ge-0/0/3 pci pci",
	})
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile must not hard-fail: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "device-map") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected downgraded device-map warning, got %v", cfg.Warnings)
	}
}

func TestDeviceMapCompactKeyPCIOrdinaryOrderStillWorks14685(t *testing.T) {
	// The ordinary spellings that already worked must stay green: the
	// identity keyword precedes `key`, so its value is not a prop keyword.
	tree := buildTree(t, []string{
		"set chassis device-map interface ge-0/0/3 pci 0000:09:00.0 key pci",
		"set chassis device-map interface ge-0/0/4 mac 00:11:22:33:44:55 key mac",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("ordinary pci/key and mac/key: %v", err)
	}
	if cfg.Chassis.DeviceMap.Entries[0].PCIAddr != "0000:09:00.0" || cfg.Chassis.DeviceMap.Entries[0].KeyOrder != "pci" {
		t.Fatalf("entry0 wrong: %+v", cfg.Chassis.DeviceMap.Entries[0])
	}
	if cfg.Chassis.DeviceMap.Entries[1].MAC != "00:11:22:33:44:55" || cfg.Chassis.DeviceMap.Entries[1].KeyOrder != "mac" {
		t.Fatalf("entry1 wrong: %+v", cfg.Chassis.DeviceMap.Entries[1])
	}
}
