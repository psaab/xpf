package networkd

import (
	"context"
	"errors"
	"os"
	"path/filepath"
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

// AG2: KeepMaster=yes flips networkd's LinkLocalAddressing DEFAULT to "no"
// (systemd.network(5)), so every management-class row must keep rendering the
// explicit LinkLocalAddressing=ipv6 beside it. A refactor that drops the
// explicit line would silently remove IPv6 link-local from em0/fxp0/fab*.
func TestKeepMasterRowsKeepExplicitLinkLocal18597(t *testing.T) {
	m := New()
	rows := []InterfaceConfig{
		{Name: "em0", Addresses: []string{"10.99.12.1/30"}, VRFName: "vrf-mgmt"},
		{Name: "fxp0", DHCPv4: true, VRFName: "vrf-mgmt"},
		{Name: "fxp0", IsVLANParent: true, VRFName: "vrf-mgmt"},
		{Name: "fab0", IsBond: true, Addresses: []string{"10.99.1.1/30"}, VRFName: "vrf-mgmt"},
		{Name: "fab0", Addresses: []string{"10.99.1.1/30"}, VRFName: "vrf-mgmt", KeepAddresses: true, MTU: 9000},
		{Name: "em0.100", Addresses: []string{"10.99.13.1/30"}, VRFName: "vrf-mgmt", MTU: 1500},
	}
	for _, ifc := range rows {
		got := m.generateNetwork(ifc)
		if !strings.Contains(got, "KeepMaster=yes\n") {
			t.Fatalf("precondition: %s row did not render KeepMaster=yes:\n%s", ifc.Name, got)
		}
		if !strings.Contains(got, "LinkLocalAddressing=ipv6\n") {
			t.Errorf("%s: KeepMaster=yes without an explicit LinkLocalAddressing=ipv6 (KeepMaster makes "+
				"the default \"no\"):\n%s", ifc.Name, got)
		}
	}
}

// AG1: the narrowed tail must still retry a link networkd marked "failed".
func TestFailedLinkIsReconfiguredOnAnUnrelatedCommit18597(t *testing.T) {
	resetReloadDebtForTest(t)
	rpFilterFixture(t)
	rec := stubNetworkctl18597(t)
	m := NewInDir(t.TempDir())
	if err := m.Apply(controlLinkIfaces18597("")); err != nil {
		t.Fatalf("first Apply: %v", err)
	}

	orig := networkdFailedLinks
	networkdFailedLinks = func() (map[string]bool, error) {
		return map[string]bool{"ge-0-0-1": true, "lo": true}, nil
	}
	t.Cleanup(func() { networkdFailedLinks = orig })
	rec.reconfigure = nil
	if err := m.Apply(controlLinkIfaces18597("hb-soak-1")); err != nil {
		t.Fatalf("description Apply: %v", err)
	}
	if want := []string{"fxp0", "ge-0-0-1"}; !slices.Equal(rec.reconfigure, want) {
		t.Fatalf("reconfigured %v, want %v: the old every-link tail retried a failed link on any changed "+
			"commit, and only managed links (not lo) may be added", rec.reconfigure, want)
	}
}

// AG1 floor: a link-state query that fails must not be read as "nothing
// failed"; the tail falls back to the full pass.
func TestFailedLinkQueryErrorFallsBackToFullPass18597(t *testing.T) {
	resetReloadDebtForTest(t)
	rpFilterFixture(t)
	rec := stubNetworkctl18597(t)
	m := NewInDir(t.TempDir())
	if err := m.Apply(controlLinkIfaces18597("")); err != nil {
		t.Fatalf("first Apply: %v", err)
	}
	orig := networkdFailedLinks
	networkdFailedLinks = func() (map[string]bool, error) { return nil, errors.New("dbus stall") }
	t.Cleanup(func() { networkdFailedLinks = orig })
	rec.reconfigure = nil
	if err := m.Apply(controlLinkIfaces18597("hb-soak-1")); err != nil {
		t.Fatalf("description Apply: %v", err)
	}
	if want := []string{"fxp0", "em0", "ge-0-0-1"}; !slices.Equal(rec.reconfigure, want) {
		t.Fatalf("query error reconfigured %v, want the full pass %v", rec.reconfigure, want)
	}
}

// The parser reads the systemd 259 table (from tcp fw0) and refuses output it
// cannot rely on, so the tail falls back to the full pass.
func TestParseNetworkdFailedLinks18597(t *testing.T) {
	table := `  1 lo          loopback carrier  unmanaged
  2 fxp0        ether    routable configured
  3 em0         ether    routable configured
 14 fab0        ether    off      failed
 10 ge-0-0-2.50 vlan     routable configured
`
	got, err := parseNetworkdFailedLinks([]byte(table))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(got) != 1 || !got["fab0"] {
		t.Fatalf("failed links = %v, want {fab0}", got)
	}
	for _, bad := range []string{
		"",                                    // nothing listed (there is always lo)
		"IDX LINK TYPE OPERATIONAL SETUP\n",   // a header: --no-legend not honoured
		"  1 lo loopback carrier\n",           // a column missing
		"  x lo loopback carrier unmanaged\n", // not a table row
		`{"Interfaces":[]}`,                   // the JSON form
		"  14 fab0 ether off \x1b[0;1;31mfailed\x1b[0m\n", // coloured SETUP cell
	} {
		if _, err := parseNetworkdFailedLinks([]byte(bad)); err == nil {
			t.Errorf("parse(%q) = nil error, want an error so the tail falls back to the full pass", bad)
		}
	}
}

// AG3(a): an EXTERNAL reload owner whose reload fails records process-wide
// reload debt; the next Apply with identical files must take the full pass.
func TestExternalReloadFailureForcesFullPass18597(t *testing.T) {
	resetReloadDebtForTest(t)
	rpFilterFixture(t)
	rec := stubNetworkctl18597(t)
	m := NewInDir(t.TempDir())
	if err := m.Apply(controlLinkIfaces18597("")); err != nil {
		t.Fatalf("first Apply: %v", err)
	}
	epoch := BeginReload()
	NoteReloadResult(epoch, errors.New("device-map reload failed"))
	rec.reconfigure = nil
	if err := m.Apply(controlLinkIfaces18597("")); err != nil {
		t.Fatalf("identical Apply: %v", err)
	}
	if want := []string{"fxp0", "em0", "ge-0-0-1"}; !slices.Equal(rec.reconfigure, want) {
		t.Fatalf("after an external reload failure the identical Apply reconfigured %v, want the full "+
			"pass %v (debtOwed)", rec.reconfigure, want)
	}
}

// AG3(b): an Apply whose file write fails but whose reload succeeds leaves the
// tail unrun (activationPending); the next Apply must take the full pass even
// though only the previously blocked file changes.
func TestWriteFailureWithSuccessfulReloadForcesFullPass18597(t *testing.T) {
	resetReloadDebtForTest(t)
	rpFilterFixture(t)
	rec := stubNetworkctl18597(t)
	dir := t.TempDir()
	m := NewInDir(dir)
	if err := m.Apply(controlLinkIfaces18597("")); err != nil {
		t.Fatalf("first Apply: %v", err)
	}
	blocked := filepath.Join(dir, filePrefix+"ge-0-0-2.network")
	if err := os.Mkdir(blocked, 0o755); err != nil {
		t.Fatal(err)
	}
	ifaces := append(controlLinkIfaces18597("hb-soak-1"),
		InterfaceConfig{Name: "ge-0-0-2", MACAddress: "52:54:00:00:00:04", Addresses: []string{"10.0.62.1/24"}})
	rec.reloads, rec.reconfigure = 0, nil
	if err := m.Apply(ifaces); err == nil {
		t.Fatal("precondition: Apply with a blocked .network returned nil")
	}
	if rec.reloads != 1 || len(rec.reconfigure) != 0 {
		t.Fatalf("precondition: failed-write Apply ran reloads=%d reconfigure=%v, want 1 and none",
			rec.reloads, rec.reconfigure)
	}
	if err := os.Remove(blocked); err != nil {
		t.Fatal(err)
	}
	rec.reconfigure = nil
	if err := m.Apply(ifaces); err != nil {
		t.Fatalf("retry Apply: %v", err)
	}
	if want := []string{"fxp0", "em0", "ge-0-0-1", "ge-0-0-2"}; !slices.Equal(rec.reconfigure, want) {
		t.Fatalf("retry after the unrun tail reconfigured %v, want the full pass %v (activationOwed)",
			rec.reconfigure, want)
	}
}

// #6912 term: an EXTERNAL reload that succeeds leaves the tail owed; the next
// Apply with identical files must take the full pass.
func TestExternalReloadSuccessForcesFullPass18597(t *testing.T) {
	resetReloadDebtForTest(t)
	rpFilterFixture(t)
	rec := stubNetworkctl18597(t)
	m := NewInDir(t.TempDir())
	if err := m.Apply(controlLinkIfaces18597("")); err != nil {
		t.Fatalf("first Apply: %v", err)
	}
	epoch := BeginReload()
	NoteReloadResult(epoch, nil)
	rec.reconfigure = nil
	if err := m.Apply(controlLinkIfaces18597("")); err != nil {
		t.Fatalf("identical Apply: %v", err)
	}
	if want := []string{"fxp0", "em0", "ge-0-0-1"}; !slices.Equal(rec.reconfigure, want) {
		t.Fatalf("after an external reload the identical Apply reconfigured %v, want the full pass %v "+
			"(externalTailOwed)", rec.reconfigure, want)
	}
}

// The query runs with SYSTEMD_COLORS=0: networkctl colours the SETUP cell when
// it believes its output is a terminal or SYSTEMD_COLORS asks it to, and a
// coloured "failed" would otherwise read as not failed.
func TestNetworkctlListQueryDisablesColour18597(t *testing.T) {
	t.Setenv("SYSTEMD_COLORS", "1")
	cmd := networkctlListCmd(context.Background())
	if want := []string{"networkctl", "list", "--no-legend", "--no-pager"}; !slices.Equal(cmd.Args, want) {
		t.Fatalf("argv = %v, want %v", cmd.Args, want)
	}
	last := ""
	for _, kv := range cmd.Env {
		if strings.HasPrefix(kv, "SYSTEMD_COLORS=") {
			last = kv
		}
	}
	if last != "SYSTEMD_COLORS=0" {
		t.Fatalf("the effective SYSTEMD_COLORS in the query's environment is %q, want SYSTEMD_COLORS=0 "+
			"(the last assignment wins, and the daemon's own environment asked for colour)", last)
	}
}
