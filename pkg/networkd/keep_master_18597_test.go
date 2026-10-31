package networkd

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

// #18597: on master every config commit took em0 — the cluster control link
// and heartbeat interface — down and up on both nodes. Two networkd behaviours
// combined:
//
//  1. A vrf-mgmt member rendered `VRF=vrf-mgmt`. vrf-mgmt is created by
//     pkg/routing over netlink, not as a networkd NetDev, so networkd logs
//     "vrf-mgmt NetDev could not be found, ignoring assignment" and treats the
//     link as having NO master: a reconfigure sets IFLA_MASTER=0, the kernel
//     VRF driver cycles the link, and its addresses are removed and re-added.
//     Measured on systemd 259 against a netlink VRF (docs/log/18597.md): with
//     VRF= a forced reconfigure detached the link, cycled it DOWN/UP and
//     removed its IPv4 address; with KeepMaster=yes the master, carrier and
//     address were all untouched.
//  2. Every Apply that changed ANY file reconfigured EVERY managed interface,
//     so `set interfaces fxp0 description X` (a .link change on fxp0)
//     reconfigured em0.
//
// FAIL-ON-REVERT: render VRF= again and the render cell reds; restore the
// reconfigure-every-interface tail and the unrelated-commit cell reds.

func TestManagementVRFRowRendersKeepMaster18597(t *testing.T) {
	m := New()
	cases := []struct {
		name           string
		ifc            InterfaceConfig
		wantKeepMaster bool
		wantLine       string
	}{
		{"control link", InterfaceConfig{Name: "em0", Addresses: []string{"10.99.12.1/30"}, VRFName: "vrf-mgmt"}, true, ""},
		{"fabric bond", InterfaceConfig{Name: "fab0", IsBond: true, Addresses: []string{"10.99.1.1/30"}, VRFName: "vrf-mgmt"}, true, ""},
		{"vlan parent", InterfaceConfig{Name: "fxp0", IsVLANParent: true, VRFName: "vrf-mgmt"}, true, ""},
		{"dhcp mgmt", InterfaceConfig{Name: "fxp0", DHCPv4: true, VRFName: "vrf-mgmt"}, true, ""},
		// KeepMaster makes networkd ignore Bond=/Bridge=, so a row whose
		// master is a networkd-owned bond or bridge keeps that directive.
		{"bond member", InterfaceConfig{Name: "em1", BondMaster: "fab0", VRFName: "vrf-mgmt"}, false, "Bond=fab0\n"},
		{"bridge member", InterfaceConfig{Name: "em2", BridgeMaster: "br-bd0", VRFName: "vrf-mgmt"}, false, "Bridge=br-bd0\n"},
		{"data link", InterfaceConfig{Name: "ge-0-0-1", Addresses: []string{"10.0.1.1/24"}}, false, ""},
	}
	for _, tc := range cases {
		got := m.generateNetwork(tc.ifc)
		if strings.Contains(got, "VRF=") {
			t.Errorf("%s: rendered a VRF= line networkd cannot resolve (it detaches the link on reconfigure):\n%s", tc.name, got)
		}
		if has := strings.Contains(got, "KeepMaster=yes\n"); has != tc.wantKeepMaster {
			t.Errorf("%s: KeepMaster=yes rendered=%v, want %v:\n%s", tc.name, has, tc.wantKeepMaster, got)
		}
		if tc.wantLine != "" && !strings.Contains(got, tc.wantLine) {
			t.Errorf("%s: missing %q:\n%s", tc.name, tc.wantLine, got)
		}
	}
}

// controlLinkIfaces18597 is the loss-cluster shape that matters here: fxp0
// (DHCP, vrf-mgmt), em0 (control link, vrf-mgmt), and a data link.
func controlLinkIfaces18597(fxp0Description string) []InterfaceConfig {
	return []InterfaceConfig{
		{Name: "fxp0", MACAddress: "52:54:00:00:00:01", DHCPv4: true, VRFName: "vrf-mgmt", Description: fxp0Description},
		{Name: "em0", MACAddress: "52:54:00:00:00:02", Addresses: []string{"10.99.12.1/30"}, VRFName: "vrf-mgmt"},
		{Name: "ge-0-0-1", MACAddress: "52:54:00:00:00:03", Addresses: []string{"10.0.61.1/24"}},
	}
}

type networkctlRecorder18597 struct {
	reloads     int
	reconfigure []string
	failReload  bool
	failReconf  map[string]bool
}

func stubNetworkctl18597(t *testing.T) *networkctlRecorder18597 {
	t.Helper()
	rec := &networkctlRecorder18597{failReconf: map[string]bool{}}
	orig := runNetworkctl
	runNetworkctl = func(args ...string) error {
		switch {
		case len(args) == 1 && args[0] == "reload":
			rec.reloads++
			if rec.failReload {
				return errors.New("reload failed")
			}
		case len(args) == 3 && args[0] == "reconfigure" && args[1] == "--":
			rec.reconfigure = append(rec.reconfigure, args[2])
			if rec.failReconf[args[2]] {
				return errors.New("reconfigure failed")
			}
		default:
			t.Errorf("unexpected networkctl argv %v", args)
		}
		return nil
	}
	t.Cleanup(func() { runNetworkctl = orig })
	return rec
}

func TestUnrelatedCommitDoesNotReconfigureControlLink18597(t *testing.T) {
	resetReloadDebtForTest(t)
	rpFilterFixture(t)
	rec := stubNetworkctl18597(t)
	m := NewInDir(t.TempDir())

	if err := m.Apply(controlLinkIfaces18597("")); err != nil {
		t.Fatalf("first Apply: %v", err)
	}
	if want := []string{"fxp0", "em0", "ge-0-0-1"}; !slices.Equal(rec.reconfigure, want) {
		t.Fatalf("precondition: first Apply (all files new) reconfigured %v, want %v", rec.reconfigure, want)
	}

	// The soak's commit: only fxp0's description changes (its .link file).
	rec.reconfigure, rec.reloads = nil, 0
	if err := m.Apply(controlLinkIfaces18597("hb-soak-1")); err != nil {
		t.Fatalf("description Apply: %v", err)
	}
	if rec.reloads != 1 {
		t.Fatalf("precondition: a changed .link file ran %d reloads, want 1", rec.reloads)
	}
	if want := []string{"fxp0"}; !slices.Equal(rec.reconfigure, want) {
		t.Fatalf("an fxp0-only commit reconfigured %v, want %v: reconfiguring em0 is what bounced the "+
			"cluster control link on every commit (#18597)", rec.reconfigure, want)
	}

	// Steady state: nothing changed, nothing owed, networkd is not touched.
	rec.reconfigure, rec.reloads = nil, 0
	if err := m.Apply(controlLinkIfaces18597("hb-soak-1")); err != nil {
		t.Fatalf("identical Apply: %v", err)
	}
	if rec.reloads != 0 || len(rec.reconfigure) != 0 {
		t.Fatalf("identical Apply ran reload=%d reconfigure=%v, want none", rec.reloads, rec.reconfigure)
	}
}

// A pass that inherits an obligation from an earlier call cannot know which
// files changed back then, so it keeps the old reconfigure-everything tail.
func TestInheritedReloadDebtStillReconfiguresEveryLink18597(t *testing.T) {
	resetReloadDebtForTest(t)
	rpFilterFixture(t)
	rec := stubNetworkctl18597(t)
	m := NewInDir(t.TempDir())

	if err := m.Apply(controlLinkIfaces18597("")); err != nil {
		t.Fatalf("first Apply: %v", err)
	}
	rec.failReload = true
	if err := m.Apply(controlLinkIfaces18597("hb-soak-1")); err == nil {
		t.Fatal("precondition: Apply with a failing reload returned nil")
	}
	rec.failReload = false
	rec.reconfigure = nil
	if err := m.Apply(controlLinkIfaces18597("hb-soak-1")); err != nil {
		t.Fatalf("retry Apply: %v", err)
	}
	if want := []string{"fxp0", "em0", "ge-0-0-1"}; !slices.Equal(rec.reconfigure, want) {
		t.Fatalf("retry after a failed reload reconfigured %v, want every managed link %v", rec.reconfigure, want)
	}
}

// A name whose own reconfigure failed is retried on the next Apply even with
// unchanged files, and only that name is (#4954 per-name debt).
func TestFailedReconfigureRetriesOnlyItsOwnLink18597(t *testing.T) {
	resetReloadDebtForTest(t)
	rpFilterFixture(t)
	rec := stubNetworkctl18597(t)
	m := NewInDir(t.TempDir())

	if err := m.Apply(controlLinkIfaces18597("")); err != nil {
		t.Fatalf("first Apply: %v", err)
	}
	rec.failReconf["fxp0"] = true
	rec.reconfigure = nil
	if err := m.Apply(controlLinkIfaces18597("hb-soak-1")); err != nil {
		t.Fatalf("description Apply: %v", err)
	}
	rec.failReconf["fxp0"] = false
	rec.reconfigure = nil
	if err := m.Apply(controlLinkIfaces18597("hb-soak-1")); err != nil {
		t.Fatalf("retry Apply: %v", err)
	}
	if want := []string{"fxp0"}; !slices.Equal(rec.reconfigure, want) {
		t.Fatalf("retry reconfigured %v, want only the owed link %v", rec.reconfigure, want)
	}
	rec.reconfigure = nil
	if err := m.Apply(controlLinkIfaces18597("hb-soak-1")); err != nil {
		t.Fatalf("settled Apply: %v", err)
	}
	if len(rec.reconfigure) != 0 {
		t.Fatalf("debt did not clear after a successful retry: reconfigured %v", rec.reconfigure)
	}
}
