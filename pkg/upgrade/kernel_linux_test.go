package upgrade

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestBootEntryRegex locks the efibootmgr line parse against the two bugs found
// during live #1930 validation: (1) the label is followed by a TAB + loader
// path, NOT line-end, so a greedy (.+) folded the whole path into the key; and
// (2) entries with no loader path (UiApp) must still parse.
func TestBootEntryRegex(t *testing.T) {
	cases := []struct{ line, id, label string }{
		{"Boot0003* xpf-A\tHD(1,GPT,8a827350)/\\EFI\\xpf-A\\shimx64.efi", "0003", "xpf-A"},
		{"Boot0004* xpf-B\tHD(1,GPT,abc)/\\EFI\\xpf-B\\shimx64.efi", "0004", "xpf-B"},
		{"Boot0002* Ubuntu\tHD(1,GPT,xyz)/\\EFI\\ubuntu\\shimx64.efi", "0002", "Ubuntu"},
		{"Boot0000* UiApp", "0000", "UiApp"},                                 // no loader path
		{"Boot0001  inactive-entry\tPciRoot(0x0)", "0001", "inactive-entry"}, // no '*'
	}
	for _, c := range cases {
		m := bootEntryRE.FindStringSubmatch(c.line)
		if len(m) != 3 {
			t.Fatalf("no match for %q", c.line)
		}
		if m[1] != c.id || m[2] != c.label {
			t.Errorf("line %q -> id=%q label=%q, want id=%q label=%q", c.line, m[1], m[2], c.id, c.label)
		}
	}
}

func TestBootCurrentRegex(t *testing.T) {
	m := bootCurrentRE.FindStringSubmatch("BootCurrent: 0001")
	if len(m) != 2 || m[1] != "0001" {
		t.Fatalf("BootCurrent parse failed: %v", m)
	}
}

func TestSlotSelectorRegex(t *testing.T) {
	sel := []byte("set xpf_slot_kernel=\"vmlinuz-7.0.0-22-generic\"\nset xpf_slot_initrd=\"initrd.img-7.0.0-22-generic\"\n")
	m := slotSelectorKernelRE.FindSubmatch(sel)
	if len(m) != 2 || string(m[1]) != "7.0.0-22-generic" {
		t.Fatalf("selector parse failed: %v", m)
	}
}

// TestDefaultGatewayParse locks the `ip -4 route show default` parse used by
// ForwardBeacon's fallback target discovery (r2 Codex Critical fix).
//
// #7157: this used to MIMIC defaultGateway()'s field scan with a copy of the
// loop written inside the test — so it pinned the copy, and a change to the
// production parse left it green. It now calls parseDefaultRoute, the function
// defaultGateway() actually uses. The measured real-world shapes (the FRR
// nexthop-group form and the HA-secondary blackhole, neither of which appeared
// in the table below) are in TestParseDefaultRoute_7157.
func TestDefaultGatewayParseLogic(t *testing.T) {
	cases := []struct{ out, want string }{
		{"default via 10.0.0.1 dev eth0 proto dhcp", "10.0.0.1"},
		{"default via 192.168.1.254 dev ens3", "192.168.1.254"},
		{"", ""},
		{"default dev wg0 scope link", ""}, // no via (point-to-point)
	}
	for _, c := range cases {
		if got, _ := parseDefaultRoute(c.out); got != c.want {
			t.Errorf("parseDefaultRoute(%q) = %q, want %q", c.out, got, c.want)
		}
	}
}

// TestBootEntriesBoundsFirmwareNVRAMRead10761 drives the production BootEntries
// path through a fake efibootmgr that does not respond before the short deadline.
// The kernel-promote unit must get a timeout error soon enough to persist the
// revert attempt before systemd's TimeoutStartSec / uncounted OnFailure reboot.
func TestBootEntriesBoundsFirmwareNVRAMRead10761(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "efibootmgr")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\nexec /bin/sleep 0.5\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	oldTimeout := kernelNVRAMTimeout
	kernelNVRAMTimeout = 20 * time.Millisecond
	t.Cleanup(func() { kernelNVRAMTimeout = oldTimeout })

	_, err := (&realKernelSystem{}).BootEntries()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("BootEntries error = %v, want bounded NVRAM timeout", err)
	}
}
