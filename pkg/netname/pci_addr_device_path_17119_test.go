package netname

import "testing"

// #17119 (R4-Q47-06) / #14595 (Y10-03): the sysfs NIC→PCI-address step
// existed four times — daemon.extractPCIAddr and devicemap.ExtractPCIAddr
// byte-identical, daemon.pciAddrFromPath divergent, and the dataplane
// Readlink-basename with no shape check or virtio walk. It now lives
// once here. This table folds the two #14595 tables
// (TestExtractPCIAddrNonPCITail14595 in pkg/devicemap and
// TestExtractPCIAddrLinksetupNonPCITail14595 in pkg/daemon, identical
// rows) and adds the virtio acceptance row from #17119
// (…/0000:05:00.0/virtio2).
//
// FAIL-ON-REVERT: restoring an unconditional last-match walk (or
// dropping the non-PCI tail guard) makes the usb/xhci rows return the
// xHCI controller BDF 0000:00:14.0 again; dropping the virtio parent
// walk makes the virtio rows return "".
func TestPCIAddrFromDevicePath17119(t *testing.T) {
	cases := []struct {
		name, path, want string
	}{
		// Controls: a PCI device itself (direct, through bridges, VF)
		// keeps its own BDF — only the LAST component is the device.
		{"direct pci", "/sys/devices/pci0000:00/0000:00:1c.4/0000:08:00.0", "0000:08:00.0"},
		{"bridge pci", "/sys/devices/pci0000:64/0000:64:03.0/0000:67:00.1", "0000:67:00.1"},
		{"sriov vf", "/sys/devices/pci0000:b2/0000:b2:00.0/0000:b3:00.0/0000:b4:03.0/0000:b7:02.0", "0000:b7:02.0"},
		{"bare bdf", "0000:09:00.0", "0000:09:00.0"},
		// Non-PCI tails: the BDF above belongs to the host controller /
		// parent, not to this netdev.
		{"usb xhci", "/sys/devices/pci0000:00/0000:00:14.0/usb2/2-1/2-1:1.0", ""},
		{"usb hub", "/sys/devices/pci0000:00/0000:00:14.0/usb1/1-1/1-1.4/1-1.4:1.0", ""},
		{"usb platform root hub", "/sys/devices/platform/soc/1c1b000.usb/usb1/1-1/1-1:1.0", ""},
		// Control: virtioN is a 1:1 channel to its PCI function, so the
		// parent BDF still names this device.
		{"virtio pci", "/sys/devices/pci0000:00/0000:03:00.0/virtio0", "0000:03:00.0"},
		{"virtio pci 2digit", "/sys/devices/pci0000:00/0000:03:00.0/virtio12", "0000:03:00.0"},
		{"virtio acceptance 17119", "/sys/devices/pci0000:00/0000:05:00.0/virtio2", "0000:05:00.0"},
		{"virtio net child", "/sys/devices/pci0000:00/0000:03:00.0/virtio0/net/eth0", ""},
		{"virtio mmio", "/sys/devices/platform/4010000000.virtio_mmio/virtio0", ""},
		{"platform soc", "/sys/devices/platform/soc@0/30be0000.ethernet", ""},
		{"empty", "", ""},
		{"garbage", "/sys/devices/foo/bar", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := PCIAddrFromDevicePath(tc.path); got != tc.want {
				t.Fatalf("PCIAddrFromDevicePath(%q) = %q, want %q", tc.path, got, tc.want)
			}
		})
	}
}

// TestPCIAddrForNetdevUnknown17119 pins the netdev wrapper's fail-empty
// contract: a name with no /sys/class/net/<name>/device yields ""
// rather than a panic or a fabricated address.
func TestPCIAddrForNetdevUnknown17119(t *testing.T) {
	if got := PCIAddrForNetdev("definitely-not-a-real-iface-17119"); got != "" {
		t.Fatalf("PCIAddrForNetdev(unknown) = %q, want \"\"", got)
	}
}
