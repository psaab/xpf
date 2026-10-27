package devicemap

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
)

// #14595 (Y10-03) / #17119: on x86 a USB NIC hangs off a PCI xHCI
// controller: /sys/devices/pci0000:00/0000:00:14.0/usb2/2-1/2-1:1.0.
// The pre-fix extractor returned the LAST DDDD:BB:DD.F component with
// no bus/subsystem check, so the USB interface component 2-1:1.0
// failed the pattern and the xHCI BDF won — every device behind one
// controller shared one "PCI address". That violates the docs
// contract (docs/bare-metal-device-map.md: a USB NIC has no PCI
// address; an empty PCI column; `pci` is unavailable) and the #1956
// identity invariant (one identity names one device): a pci+mac entry
// refused when a second dongle appeared, and a pci-only entry bound a
// foreign dongle as "PCI-only, unverified" despite it having a
// permanent MAC. The extractor itself now lives once in pkg/netname
// (#17119); its direct table is TestPCIAddrFromDevicePath17119 there.
//
// Probe evidence (verify/z3/probe_y10-03_test.go, issue #14595):
//   both USB NICs: pci="0000:00:14.0"; pci+mac entry with two USB NICs
//   -> REFUSED (topology changed ...); mac-only control binds; pci-only
//   entry binds the foreign dongle unverified.
//
// FAIL-ON-REVERT: reverting the non-PCI tail guard in
// netname.PCIAddrFromDevicePath (or restoring the unconditional
// last-match walk) makes TestEnumerateUSBNICsX86ReportEmptyPCI14595
// and TestClassifyNetdevUSBBehindXHCINoPCI14595 fail with
// pci="0000:00:14.0" again, and TestPCIAddrFromDevicePath17119 fail on
// the usb/xhci rows.

// x86USBSysfs14595 builds a hermetic sysfs tree mirroring the probe
// fixture: two USB NICs behind one xHCI controller at 0000:00:14.0.
func x86USBSysfs14595(t *testing.T) (root string, macs map[string]string) {
	t.Helper()
	base := t.TempDir()
	root = filepath.Join(base, "class", "net")
	usb := map[string]string{
		"enx001122334455": filepath.Join(base, "devices", "pci0000:00", "0000:00:14.0", "usb2", "2-1", "2-1:1.0"),
		"enx66778899aabb": filepath.Join(base, "devices", "pci0000:00", "0000:00:14.0", "usb2", "2-2", "2-2:1.0"),
	}
	macs = map[string]string{
		"enx001122334455": "00:11:22:33:44:55",
		"enx66778899aabb": "66:77:88:99:aa:bb",
	}
	for n, hw := range usb {
		if err := os.MkdirAll(hw, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Join(root, n), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(hw, filepath.Join(root, n, "device")); err != nil {
			t.Fatal(err)
		}
	}
	saved, savedL := sysClassNetDir, linkByName
	sysClassNetDir = root
	linkByName = func(name string) (netlink.Link, error) {
		hw, _ := net.ParseMAC(macs[name])
		return &netlink.Device{LinkAttrs: netlink.LinkAttrs{Name: name, HardwareAddr: hw, PermHWAddr: hw}}, nil
	}
	t.Cleanup(func() { sysClassNetDir, linkByName = saved, savedL })
	return root, macs
}

// TestEnumerateUSBNICsX86ReportEmptyPCI14595 is the acceptance cell from
// the issue: with the probe's x86 USB sysfs fixture, EnumeratePresentNICs
// reports PCIAddr="" for both USB NICs (the docs contract: empty PCI
// column, `pci` unavailable) while keeping their permanent MACs so a
// `key mac` entry can still bind them (#4884).
func TestEnumerateUSBNICsX86ReportEmptyPCI14595(t *testing.T) {
	x86USBSysfs14595(t)

	nics, err := EnumeratePresentNICs()
	if err != nil {
		t.Fatalf("EnumeratePresentNICs: %v", err)
	}
	if len(nics) != 2 {
		t.Fatalf("want 2 USB NICs enumerated, got %d: %+v", len(nics), nics)
	}
	for _, n := range nics {
		if n.PCIAddr != "" {
			t.Fatalf("USB NIC %s reports PCIAddr=%q; want \"\" (the xHCI "+
				"controller BDF 0000:00:14.0 is not this NIC's address)", n.Name, n.PCIAddr)
		}
		if n.PermMAC == "" {
			t.Fatalf("USB NIC %s lost its permanent MAC; `key mac` binding (#4884) must keep working", n.Name)
		}
	}

	// The issue's decisive consequence: the operator's copied pci+mac
	// entry no longer refuses when a second dongle appears. After the
	// fix the PCI key is unavailable, so the entry must be authored on
	// MAC; resolve a mac-keyed entry against both present NICs and
	// require a clean bind to the right dongle.
	entries := []config.DeviceMapEntry{
		{LogicalName: "ge-0/0/1", MAC: "00:11:22:33:44:55", KeyOrder: config.DeviceMapKeyMAC},
	}

	b := Resolve(entries, nics, nil)
	if len(b) != 1 || !b[0].Status.Bound() {
		t.Fatalf("mac entry with two USB NICs present must bind, got %+v", b)
	}
	if b[0].CurrentNIC != "enx001122334455" {
		t.Fatalf("mac entry bound wrong NIC: %+v", b[0])
	}

	// And the foreign-dongle hazard is gone: a pci-only entry for the
	// old controller BDF matches nothing (no NIC carries that identity),
	// so it cannot bind a stranger as "PCI-only, unverified".
	b = Resolve([]config.DeviceMapEntry{
		{LogicalName: "ge-0/0/1", PCIAddr: "0000:00:14.0"},
	}, nics, nil)
	if len(b) != 1 || b[0].Status != BindUnbound {
		t.Fatalf("pci-only entry for controller BDF must be UNBOUND, got %+v", b)
	}
}

// TestClassifyNetdevUSBBehindXHCINoPCI14595 pins the classifyNetdev seam:
// an x86 USB NIC (non-PCI bus below the last PCI component) is KEPT with
// an empty PCI address, exactly like the ARM/platform USB shape (#4884).
func TestClassifyNetdevUSBBehindXHCINoPCI14595(t *testing.T) {
	pci, keep := classifyNetdev("enx001122334455",
		"/sys/devices/pci0000:00/0000:00:14.0/usb2/2-1/2-1:1.0", nil)
	if !keep {
		t.Fatal("x86 USB NIC must be kept (physical NIC, #4884)")
	}
	if pci != "" {
		t.Fatalf("x86 USB NIC pci = %q, want \"\" (0000:00:14.0 is the xHCI controller)", pci)
	}
}
