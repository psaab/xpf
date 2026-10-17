package daemon

import (
	"os"
	"path/filepath"
	"testing"
)

// writeUSBXHCISysfs14595 builds a fake /sys/class/net tree:
//
//	<root>/enp8s0/device            -> <root>/devices/pci0000:00/0000:08:00.0 (real PCI NIC)
//	<root>/enx001122334455/device   -> <root>/devices/pci0000:00/0000:00:14.0/usb2/2-1/2-1:1.0 (USB NIC behind xHCI)
//	<root>/<name>/device/driver     -> ../drivers/<driver>
//
// Each device dir carries the `driver` symlink enumeratePCINICs reads.
func writeUSBXHCISysfs14595(t *testing.T) string {
	t.Helper()
	base := t.TempDir()
	root := filepath.Join(base, "class", "net")
	devs := []struct{ name, hw, driver string }{
		{"enp8s0", filepath.Join(base, "devices", "pci0000:00", "0000:08:00.0"), "igb"},
		{"enx001122334455", filepath.Join(base, "devices", "pci0000:00", "0000:00:14.0", "usb2", "2-1", "2-1:1.0"), "r8152"},
	}
	for _, d := range devs {
		if err := os.MkdirAll(d.hw, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Join(root, d.name), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(d.hw, filepath.Join(root, d.name, "device")); err != nil {
			t.Fatal(err)
		}
		drvDir := filepath.Join(base, "drivers", d.driver)
		if err := os.MkdirAll(drvDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(drvDir, filepath.Join(root, d.name, "device", "driver")); err != nil {
			if !os.IsExist(err) {
				t.Fatal(err)
			}
		}
	}
	return root
}

// #14595 (Y10-03): linksetup's extractPCIAddr gets the same treatment as
// devicemap.ExtractPCIAddr. The pre-fix walk returned the LAST
// DDDD:BB:DD.F component, so a netdev on a non-PCI bus below a PCI
// ancestor (…/0000:00:14.0/usb2/2-1/2-1:1.0 behind an xHCI controller)
// was reported under the ancestor's BDF — every device behind one
// controller shared one "PCI address". Only a path whose LAST component
// is the BDF names a PCI device (callers pass the resolved `device`
// symlink target, which ends in the device's own BDF for a PCI netdev).
//
// FAIL-ON-REVERT: restoring the last-match walk makes the usb rows
// return 0000:00:14.0 again and fails
// TestExtractPCIAddrLinksetupNonPCITail14595 /
// TestExtractPCIAddrLinksetupBootstrapUSBNIC14595.

// TestExtractPCIAddrLinksetupNonPCITail14595 pins the daemon copy of the
// extractor directly: PCI controls keep their BDF, non-PCI tails yield "".
func TestExtractPCIAddrLinksetupNonPCITail14595(t *testing.T) {
	cases := []struct {
		name, path, want string
	}{
		{"direct pci", "/sys/devices/pci0000:00/0000:00:1c.4/0000:08:00.0", "0000:08:00.0"},
		{"bridge pci", "/sys/devices/pci0000:64/0000:64:03.0/0000:67:00.1", "0000:67:00.1"},
		{"sriov vf", "/sys/devices/pci0000:b2/0000:b2:00.0/0000:b3:00.0/0000:b4:03.0/0000:b7:02.0", "0000:b7:02.0"},
		{"bare bdf", "0000:09:00.0", "0000:09:00.0"},
		{"usb xhci", "/sys/devices/pci0000:00/0000:00:14.0/usb2/2-1/2-1:1.0", ""},
		{"usb hub", "/sys/devices/pci0000:00/0000:00:14.0/usb1/1-1/1-1.4/1-1.4:1.0", ""},
		{"usb platform root hub", "/sys/devices/platform/soc/1c1b000.usb/usb1/1-1/1-1:1.0", ""},
		// Control: virtioN is a 1:1 channel to its PCI function, so the
		// parent BDF still names this device (enumeratePCINICs requires
		// it: the virtio-first sortKey is unreachable without it).
		{"virtio pci", "/sys/devices/pci0000:00/0000:03:00.0/virtio0", "0000:03:00.0"},
		{"virtio pci 2digit", "/sys/devices/pci0000:00/0000:03:00.0/virtio12", "0000:03:00.0"},
		{"virtio net child", "/sys/devices/pci0000:00/0000:03:00.0/virtio0/net/eth0", ""},
		{"virtio mmio", "/sys/devices/platform/4010000000.virtio_mmio/virtio0", ""},
		{"platform soc", "/sys/devices/platform/soc@0/30be0000.ethernet", ""},
		{"empty", "", ""},
		{"garbage", "/sys/devices/foo/bar", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := extractPCIAddr(tc.path); got != tc.want {
				t.Fatalf("extractPCIAddr(%q) = %q, want %q", tc.path, got, tc.want)
			}
		})
	}
}

// TestExtractPCIAddrLinksetupBootstrapUSBNIC14595 exercises the composed
// bootstrap path: pciAddrForInterface reads the LIVE /sys, which is
// unavailable as a fixture, so this pins the seam the bootstrap actually
// consults — extractPCIAddr over the EvalSymlinks target shape a USB
// NIC behind xHCI produces. A USB management NIC must yield NO PCI
// component, so lifelineRecordFromParts records it MAC-only (#4815)
// instead of pinning it to its host controller.
func TestExtractPCIAddrLinksetupBootstrapUSBNIC14595(t *testing.T) {
	usbPath := filepath.Join("/sys", "devices", "pci0000:00", "0000:00:14.0", "usb2", "2-1", "2-1:1.0")
	if got := extractPCIAddr(usbPath); got != "" {
		t.Fatalf("bootstrap extractPCIAddr(%q) = %q, want \"\" (xHCI controller BDF)", usbPath, got)
	}
	rec, ok := lifelineRecordFromParts(extractPCIAddr(usbPath), "00:11:22:33:44:55")
	if !ok || rec.PCIAddr != "" || rec.MAC != "00:11:22:33:44:55" {
		t.Fatalf("USB lifeline must be a MAC-only record, got %+v ok=%v", rec, ok)
	}
}

// TestEnumeratePCINICsSkipsUSBNIC14595 is the acceptance cell for
// enumeratePCINICs: a USB NIC behind xHCI has no PCI positional identity
// and must be skipped, while a real PCI NIC in the same tree is still
// enumerated under its own BDF. Pre-fix, the USB entry was enrolled at
// 0000:00:14.0 and shifted the positional naming of every later NIC.
func TestEnumeratePCINICsSkipsUSBNIC14595(t *testing.T) {
	root := writeUSBXHCISysfs14595(t)
	old := sysClassNetRoot
	sysClassNetRoot = root
	t.Cleanup(func() { sysClassNetRoot = old })

	nics, err := enumeratePCINICs()
	if err != nil {
		t.Fatalf("enumeratePCINICs: %v", err)
	}
	if len(nics) != 1 {
		t.Fatalf("want exactly the one PCI NIC enumerated, got %+v", nics)
	}
	if nics[0].name != "enp8s0" || nics[0].busAddr != "0000:08:00.0" {
		t.Fatalf("wrong NIC/busAddr enumerated: %+v", nics[0])
	}
}

// TestEnumeratePCINICsUSBRenameSkipped14595 pins the positional-rename
// consequence end to end over the xHCI fixture: the USB NIC is skipped
// by enumeratePCINICs, so a renamePositional pass over the enumeration
// assigns names by PCI order alone and never renames the USB dongle
// positionally. Pre-fix, the dongle enrolled at the controller BDF
// 0000:00:14.0 ahead of 0000:08:00.0 and stole the earlier slot.
// linkDir is redirected so the .link writes land in a temp dir.
func TestEnumeratePCINICsUSBRenameSkipped14595(t *testing.T) {
	root := writeUSBXHCISysfs14595(t)
	old := sysClassNetRoot
	sysClassNetRoot = root
	t.Cleanup(func() { sysClassNetRoot = old })
	oldDir := linkDir
	linkDir = t.TempDir()
	t.Cleanup(func() { linkDir = oldDir })

	nics, err := enumeratePCINICs()
	if err != nil {
		t.Fatalf("enumeratePCINICs: %v", err)
	}
	var renamed [][2]string
	_, errs := renamePositional(nics, 0, false, func(from, to string) error {
		renamed = append(renamed, [2]string{from, to})
		return nil
	})
	if len(errs) != 0 {
		t.Fatalf("renamePositional: %v", errs)
	}
	if len(renamed) != 1 || renamed[0] != [2]string{"enp8s0", "fxp0"} {
		t.Fatalf("want only enp8s0->fxp0 renamed, got %v", renamed)
	}
}
