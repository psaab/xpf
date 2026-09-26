package devicemap

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
)

// pinnedEntry is a device-map entry that pins BOTH a PCI address and a MAC —
// the shape an operator authors when they want the card-swap check.
func pinnedEntry(mac string) config.DeviceMapEntry {
	return config.DeviceMapEntry{LogicalName: "ge-0/0/3", PCIAddr: "0000:09:00.0", MAC: mac}
}

// TestPinnedMACRefusesWhenPermanentMACCannotBeVerified covers unread identity
// (#6786) and known-absent permanent MAC (#10905) for MAC-pinned entries.
//
// EnumeratePresentNICs used to discard LinkByName errors, so a failed read left
// PermMAC == "" — the SAME value hardware with no permanent-MAC attribute
// produces. That bound the pinned entry as PCI-only and could rename an
// unchecked card into the operator's logical name. Both states now refuse,
// with distinct statuses because one is unknown and the other is known-absent.
//
// The PCI-only control remains in TestResolvePCIOnlyWhenNoPermMAC: an entry
// that does not pin a MAC must still bind on PCI when no permanent MAC exists
// (#4884).
func TestPinnedMACRefusesWhenPermanentMACCannotBeVerified(t *testing.T) {
	const pinned = "aa:bb:cc:dd:ee:01"
	tests := []struct {
		name     string
		nic      PresentNIC
		keyOrder string
		want     BindStatus
	}{
		{
			// The #6786 defect: the read FAILED, so the permanent MAC is
			// UNKNOWN and the pinned MAC cannot be verified. Must refuse.
			name: "identity-unread",
			nic:  PresentNIC{Name: "enp9s0", PCIAddr: "0000:09:00.0", IdentityUnread: true},
			want: BindRefusedIdentityUnknown,
		},
		{
			// #10905: the read succeeded, but the hardware reports no
			// permanent MAC. A pinned entry must not silently degrade to the
			// PCI-only bind; its MAC identity remains unverifiable.
			name: "known-absent-perm-mac",
			nic:  PresentNIC{Name: "enp9s0", PCIAddr: "0000:09:00.0"},
			want: BindRefusedPinnedMACAbsent,
		},
		{
			// The order-independent guard must also protect MAC-first entries,
			// whose key loop could otherwise bind via PCI after a MAC miss.
			name:     "known-absent-perm-mac-mac-first",
			nic:      PresentNIC{Name: "enp9s0", PCIAddr: "0000:09:00.0"},
			keyOrder: config.DeviceMapKeyMACThenPCI,
			want:     BindRefusedPinnedMACAbsent,
		},
		{
			// The read succeeded and the MAC matches the pin.
			name: "perm-mac-matches",
			nic:  PresentNIC{Name: "enp9s0", PCIAddr: "0000:09:00.0", PermMAC: pinned},
			want: BindBound,
		},
		{
			// The read succeeded and a DIFFERENT card is in the slot. This is
			// the refusal #6786 restores for the unreadable case; it must keep
			// its own, distinct status so the operator remedies differ.
			name: "perm-mac-differs",
			nic:  PresentNIC{Name: "enp9s0", PCIAddr: "0000:09:00.0", PermMAC: "aa:bb:cc:dd:ee:99"},
			want: BindRefusedAmbig,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			entry := pinnedEntry(pinned)
			entry.KeyOrder = tc.keyOrder
			got := Resolve([]config.DeviceMapEntry{entry}, []PresentNIC{tc.nic}, nil)
			if len(got) != 1 {
				t.Fatalf("Resolve returned %d bindings, want 1", len(got))
			}
			if got[0].Status != tc.want {
				t.Errorf("status = %v (%s), want %v (%s)",
					got[0].Status, got[0].Status.String(), tc.want, tc.want.String())
			}
			if got[0].Status == BindRefusedPinnedMACAbsent {
				display := got[0].Status.String()
				if !strings.Contains(display, "REFUSED") ||
					!strings.Contains(display, "no permanent MAC") ||
					display == BindRefusedIdentityUnknown.String() {
					t.Errorf("known-absent refusal status display = %q, want a distinct refusal reason", display)
				}
			}
			// A refusal must carry NO binding: an entry that refuses and still
			// names a NIC would be renamed by the daemon's rename loop, which
			// keys on CurrentNIC.
			if tc.want.Refused() && (got[0].CurrentNIC != "" || got[0].Logical != "") {
				t.Errorf("a refused binding must name no NIC and no logical name, got CurrentNIC=%q Logical=%q",
					got[0].CurrentNIC, got[0].Logical)
			}
		})
	}
}

// TestUnreadIdentityDoesNotRefusePCIOnlyEntry6786 is the ANTI-OVER-REACH
// control, and it guards the decision that keeps this fix from causing an
// outage of its own.
//
// The refusal is scoped to entries that pin a MAC, because those are the only
// entries whose stated identity the failed read actually damaged. An entry
// keyed on PCI alone has its identity from sysfs — which succeeded — so
// nothing it asked for is unknown. Refusing it too would let ONE transient
// netlink failure refuse every mapped interface on the box, including a
// management NIC whose operator never requested MAC verification.
//
// FAIL-ON-REVERT: widening the guard to `pm[0].IdentityUnread` without the
// `e.MAC != ""` conjunct reds this.
func TestUnreadIdentityDoesNotRefusePCIOnlyEntry6786(t *testing.T) {
	entry := config.DeviceMapEntry{LogicalName: "ge-0/0/3", PCIAddr: "0000:09:00.0"} // no MAC pinned
	nic := PresentNIC{Name: "enp9s0", PCIAddr: "0000:09:00.0", IdentityUnread: true}

	got := Resolve([]config.DeviceMapEntry{entry}, []PresentNIC{nic}, nil)
	if len(got) != 1 {
		t.Fatalf("Resolve returned %d bindings, want 1", len(got))
	}
	if got[0].Status.Refused() {
		t.Fatalf("a PCI-only entry must NOT be refused because some OTHER attribute was unreadable: "+
			"its identity is the PCI address, which was read successfully. Refusing it lets one "+
			"transient netlink failure strand every mapped interface, management included. status=%s",
			got[0].Status.String())
	}
	if got[0].CurrentNIC != "enp9s0" {
		t.Errorf("PCI-only entry must still bind its NIC, got CurrentNIC=%q status=%s",
			got[0].CurrentNIC, got[0].Status.String())
	}
}

// TestRefusedAgreesWithStatusString6786 binds the AGREEMENT between the two
// spellings of "this status is a refusal" rather than pinning either one.
//
// Refused() is an explicit disjunction and every hard-stop in the daemon
// (deviceMapStrandsManagement, the boot re-check) routes through it — the
// #6546 comment on it says a new refusal reason must not be able to slip past
// as a clean result, but the implementation still requires each one to be
// added by hand. Comparing it against String()'s own "REFUSED" prefix is what
// makes that promise checkable: adding a refusal status and forgetting
// Refused() reds here instead of silently becoming a commit-time pass.
func TestRefusedAgreesWithStatusString6786(t *testing.T) {
	all := []BindStatus{
		BindBound, BindBoundPCIOnly, BindBoundViaMAC, BindUnbound,
		BindRefusedAmbig, BindRefusedDupName, BindRefusedIdentityUnknown,
		BindRefusedPinnedMACAbsent,
	}
	// Premise: the list covers every declared status, so a new one added
	// without updating this test cannot hide behind a short list.
	if got := len(all); BindStatus(got-1) != BindRefusedPinnedMACAbsent {
		t.Fatalf("premise broken: %d statuses listed but the last declared one is %d — "+
			"a status was added without extending this table", got, BindRefusedPinnedMACAbsent)
	}
	for _, s := range all {
		saysRefused := strings.HasPrefix(s.String(), "REFUSED")
		if saysRefused != s.Refused() {
			t.Errorf("status %d disagrees with itself: String()=%q (REFUSED prefix=%v) but Refused()=%v. "+
				"Every daemon hard-stop routes through Refused(), so a refusal it does not report "+
				"is silently treated as a clean result", int(s), s.String(), saysRefused, s.Refused())
		}
	}
}

// TestCandidateDisplayDistinguishesUnknownFromNone6786 pins the diagnostics
// half. "(none)" is a positive claim — the hardware has no permanent-MAC
// attribute, so this NIC cannot be MAC-pinned. Printing it for a NIC whose
// read FAILED tells the operator something that may be false, and hides why a
// MAC-pinned entry for that NIC now refuses to bind. Same for reporting an
// unread NIC's link as "down", which sends them hunting a cabling fault.
func TestCandidateDisplayDistinguishesUnknownFromNone6786(t *testing.T) {
	tests := []struct {
		name     string
		nic      PresentNIC
		wantPerm string
		wantLink string
	}{
		{"unread", PresentNIC{IdentityUnread: true}, "(unknown)", "unknown"},
		{"unread-down-looking", PresentNIC{IdentityUnread: true, LinkUp: false}, "(unknown)", "unknown"},
		{"hardware-has-none", PresentNIC{}, "(none)", "down"},
		{"has-mac-up", PresentNIC{PermMAC: "aa:bb:cc:dd:ee:01", LinkUp: true}, "aa:bb:cc:dd:ee:01", "up"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.nic.PermMACDisplay(); got != tc.wantPerm {
				t.Errorf("PermMACDisplay() = %q, want %q", got, tc.wantPerm)
			}
			if got := tc.nic.LinkDisplay(); got != tc.wantLink {
				t.Errorf("LinkDisplay() = %q, want %q", got, tc.wantLink)
			}
		})
	}
}

// fakeSysClassNet builds a hermetic /sys/class/net-shaped tree containing one
// entry per name, each with a `device` symlink (which is what marks a netdev as
// backed by real hardware) pointing at a real directory so EvalSymlinks
// resolves. It points the enumerator's sysfs seam at it.
func fakeSysClassNet(t *testing.T, names ...string) {
	t.Helper()
	root := t.TempDir()
	hw := filepath.Join(root, "hw")
	if err := os.MkdirAll(hw, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, n := range names {
		nd := filepath.Join(root, n)
		if err := os.MkdirAll(nd, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(hw, filepath.Join(nd, "device")); err != nil {
			t.Fatal(err)
		}
	}
	saved := sysClassNetDir
	sysClassNetDir = root
	t.Cleanup(func() { sysClassNetDir = saved })
}

// TestEnumeratorRecordsIdentityReadFailure6786 binds the WIRING, which the
// resolver tests above cannot reach.
//
// Every other test in this file constructs PresentNIC by hand, so they pin how
// Resolve TREATS IdentityUnread while leaving the code that SETS it covered by
// nothing — and that code is the actual defect: the discarded `err` from the
// per-NIC read. Deleting the assignment would leave every hand-built fixture
// green. These two cells run the real EnumeratePresentNICs against a hermetic
// sysfs tree with the netlink read stubbed, so the flag's producer is bound to
// the same property its consumers rely on.
//
// The PAIR is what proves it: the failing read must set the flag, and the
// SUCCEEDING read must clear it. A cell that only checked the failure case
// would stay green under a fix that hard-codes IdentityUnread = true, which
// would refuse every MAC-pinned entry on every box.
func TestEnumeratorRecordsIdentityReadFailure6786(t *testing.T) {
	t.Run("read-fails-marks-unread", func(t *testing.T) {
		fakeSysClassNet(t, "enp9s0")
		saved := linkByName
		linkByName = func(string) (netlink.Link, error) {
			return nil, errors.New("injected: netlink LinkByName failure")
		}
		t.Cleanup(func() { linkByName = saved })

		nics, err := EnumeratePresentNICs()
		if err != nil {
			t.Fatalf("EnumeratePresentNICs: %v", err)
		}
		if len(nics) != 1 {
			t.Fatalf("got %d NICs, want 1 (the NIC is present in sysfs and must NOT be dropped — "+
				"dropping it would make a real NIC vanish from `candidates`)", len(nics))
		}
		if !nics[0].IdentityUnread {
			t.Error("a FAILED per-NIC identity read must set IdentityUnread. Leaving it false makes " +
				"the failure indistinguishable from hardware that simply has no permanent MAC, " +
				"which is what silently disabled the card-swap refusal (#6786)")
		}
		if nics[0].PermMAC != "" {
			t.Errorf("a failed read must not invent a permanent MAC, got %q", nics[0].PermMAC)
		}
	})

	t.Run("read-succeeds-leaves-known", func(t *testing.T) {
		fakeSysClassNet(t, "enp9s0")
		mac, err := net.ParseMAC("aa:bb:cc:dd:ee:01")
		if err != nil {
			t.Fatal(err)
		}
		saved := linkByName
		linkByName = func(name string) (netlink.Link, error) {
			return &netlink.Device{LinkAttrs: netlink.LinkAttrs{
				Name:         name,
				PermHWAddr:   mac,
				HardwareAddr: mac,
			}}, nil
		}
		t.Cleanup(func() { linkByName = saved })

		nics, err := EnumeratePresentNICs()
		if err != nil {
			t.Fatalf("EnumeratePresentNICs: %v", err)
		}
		if len(nics) != 1 {
			t.Fatalf("got %d NICs, want 1", len(nics))
		}
		if nics[0].IdentityUnread {
			t.Error("a SUCCESSFUL identity read must leave IdentityUnread false — hard-coding it " +
				"true would refuse every MAC-pinned device-map entry on every box")
		}
		if nics[0].PermMAC != "aa:bb:cc:dd:ee:01" {
			t.Errorf("PermMAC = %q, want the permanent MAC the read returned", nics[0].PermMAC)
		}
	})
}
