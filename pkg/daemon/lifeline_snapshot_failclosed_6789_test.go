package daemon

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/vishvananda/netlink"
)

// lifelineSeamState captures everything setupBootstrapLifeline can MUTATE, so a
// test can assert zero side effects rather than only a missing file.
type lifelineSeamState struct {
	linkDir  string
	renamed  *bool
	reloaded *bool
}

// staticLifelineSeams points the bootstrap lifeline at a NIC that is selected
// BY DEFAULT ROUTE (the evidence-bearing case) and stubs every mutating seam.
// The netlink observation seams are left for the caller to set.
func staticLifelineSeams(t *testing.T) lifelineSeamState {
	t.Helper()
	dir := t.TempDir()
	netDir := filepath.Join(dir, "network")
	if err := os.MkdirAll(netDir, 0o755); err != nil {
		t.Fatal(err)
	}

	oldLinkDir, oldDetect := linkDir, detectLifelineInterfaceFn
	oldEnum, oldRename, oldReload := enumeratePCINICsFn, renameInterfaceFn, networkctlReloadFn
	oldNetworkd := networkdActiveFn
	oldRecord := lifelineRecordFileForTest
	oldLink, oldAddr, oldRoute := lifelineLinkByName, lifelineAddrList, lifelineRouteList
	t.Cleanup(func() {
		linkDir, detectLifelineInterfaceFn = oldLinkDir, oldDetect
		enumeratePCINICsFn, renameInterfaceFn, networkctlReloadFn = oldEnum, oldRename, oldReload
		networkdActiveFn = oldNetworkd
		lifelineRecordFileForTest = oldRecord
		lifelineLinkByName, lifelineAddrList, lifelineRouteList = oldLink, oldAddr, oldRoute
	})

	linkDir = netDir
	lifelineRecordFileForTest = filepath.Join(dir, "lifeline.json")
	// A DEFAULT ROUTE names the management NIC: this is the evidence-bearing
	// selection path, the one where a failed addressing read is a real loss.
	networkdActiveFn = func() error { return nil }
	detectLifelineInterfaceFn = func() (string, bool, error) { return defaultMgmtInterface, true, nil }
	enumeratePCINICsFn = func() ([]pciNIC, error) {
		return []pciNIC{{sortKey: 0, busAddr: "0000:05:00.0", name: defaultMgmtInterface}}, nil
	}
	renamed, reloaded := false, false
	renameInterfaceFn = func(_, _ string) error { renamed = true; return nil }
	networkctlReloadFn = func() error { reloaded = true; return nil }

	return lifelineSeamState{linkDir: netDir, renamed: &renamed, reloaded: &reloaded}
}

// okLink is a minimal netlink.Link for the observation seams.
func okLink() netlink.Link {
	return &netlink.Device{LinkAttrs: netlink.LinkAttrs{Name: defaultMgmtInterface, Index: 2}}
}

// staticAddr is a PERMANENT (ValidLft == forever) global address — a static
// address, the kind whose loss the DHCP branch would cause.
func staticAddr(cidr string) netlink.Addr {
	ip, ipnet, _ := net.ParseCIDR(cidr)
	ipnet.IP = ip
	return netlink.Addr{IPNet: ipnet, ValidLft: 0xffffffff}
}

// TestLifelineObservationFailureProducesZeroSideEffects6789 is the #6789
// fail-on-revert test, and it asserts SIDE EFFECTS rather than a return value.
//
// setupBootstrapLifeline is a chain of fail-closed refusals: no default route,
// NIC enumeration failed, and not-enumeration-index-0 each log and return
// having touched NOTHING. The addressing snapshot was the one observation that
// GUESSED instead. interfaceAddrSnapshot returned empty slices on a LinkByName
// failure and discarded the AddrList error, and the writer asked
// `isDHCPManaged(x) || (len(v4) == 0 && len(v6) == 0)` — so the very failure
// that made isDHCPManaged fail SAFE (toward static, as its comment documents)
// also emptied the address list and drove the OR into the DHCP branch. A
// statically-addressed management NIC then got a `DHCP=yes` .network and was
// renamed, and the rename cycles the link: the static address goes away on a
// box that is reachable only over that NIC, in bootstrap, with no committed
// config to roll back to.
//
// Each arm fails ONE observation. What must be true in every arm is that
// nothing was mutated: no .network written, no rename, no networkctl reload.
//
// FAIL-ON-REVERT: folding any of these errors back into an empty snapshot makes
// the writer emit a DHCP .network and the rename+reload run, reddening all
// three assertions in that arm.
func TestLifelineObservationFailureProducesZeroSideEffects6789(t *testing.T) {
	injected := errors.New("injected: netlink observation failure")

	tests := []struct {
		name  string
		seams func()
	}{
		{
			// The link itself cannot be resolved.
			name: "link-read-fails",
			seams: func() {
				lifelineLinkByName = func(string) (netlink.Link, error) { return nil, injected }
			},
		},
		{
			// The link resolves but its addresses cannot be listed. This is the
			// arm the old code could not distinguish from "has no addresses".
			name: "address-list-fails",
			seams: func() {
				lifelineLinkByName = func(string) (netlink.Link, error) { return okLink(), nil }
				lifelineAddrList = func(netlink.Link, int) ([]netlink.Addr, error) { return nil, injected }
			},
		},
		{
			// Addresses read fine, but the route dump for a family we HAVE
			// addresses in failed — so a Gateway= line would have been written
			// and its absence leaves management reachable on-link only.
			name: "route-list-fails-for-a-family-with-addresses",
			seams: func() {
				lifelineLinkByName = func(string) (netlink.Link, error) { return okLink(), nil }
				lifelineAddrList = func(netlink.Link, int) ([]netlink.Addr, error) {
					return []netlink.Addr{staticAddr("192.0.2.10/24")}, nil
				}
				lifelineRouteList = func(_ netlink.Link, family int) ([]netlink.Route, error) {
					if family == netlink.FAMILY_V4 {
						return nil, injected
					}
					return nil, nil
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			st := staticLifelineSeams(t)
			tc.seams()

			d := &Daemon{store: newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))}
			d.setupBootstrapLifeline()

			netPath := filepath.Join(st.linkDir, linkPrefix+"fxp0.network")
			if data, err := os.ReadFile(netPath); err == nil {
				t.Errorf("a bootstrap fxp0 .network was written from an INCOMPLETE addressing "+
					"observation; a failed read must never be treated as 'no addresses', because "+
					"the address-less case writes DHCP=yes over a statically-addressed management "+
					"NIC (#6789). content:\n%s", data)
			}
			if *st.renamed {
				t.Error("the management NIC was RENAMED after a failed addressing observation. The " +
					"rename cycles the link, so on a box reached only over that NIC this is the " +
					"lockout (#6789)")
			}
			if *st.reloaded {
				t.Error("networkctl reload ran after a failed addressing observation; every other " +
					"observation failure in setupBootstrapLifeline refuses without touching anything")
			}
		})
	}
}

// TestCompleteObservationStillWritesAndRenames6789 is the tightening control.
// Without it, a fix that refuses on EVERY snapshot — or simply never writes —
// satisfies every assertion above while disabling the bootstrap lifeline
// entirely, which strands management under its kernel name on every boot.
//
// It uses the SAME seams with the only difference being that the observations
// SUCCEED, and asserts the static snapshot is what gets written (not DHCP), so
// it also pins that a permanent address is still classified as static.
func TestCompleteObservationStillWritesAndRenames6789(t *testing.T) {
	st := staticLifelineSeams(t)
	lifelineLinkByName = func(string) (netlink.Link, error) { return okLink(), nil }
	lifelineAddrList = func(netlink.Link, int) ([]netlink.Addr, error) {
		return []netlink.Addr{staticAddr("192.0.2.10/24")}, nil
	}
	lifelineRouteList = func(_ netlink.Link, family int) ([]netlink.Route, error) {
		if family == netlink.FAMILY_V4 {
			return []netlink.Route{{Gw: net.ParseIP("192.0.2.1")}}, nil
		}
		return nil, nil
	}

	d := &Daemon{store: newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))}
	d.setupBootstrapLifeline()

	netPath := filepath.Join(st.linkDir, linkPrefix+"fxp0.network")
	data, err := os.ReadFile(netPath)
	if err != nil {
		t.Fatalf("a COMPLETE observation must still write the bootstrap fxp0 .network: %v", err)
	}
	got := string(data)
	if !contains6789(got, "Address=192.0.2.10/24") {
		t.Errorf("the static address must be snapshotted into the .network; got:\n%s", got)
	}
	if !contains6789(got, "Gateway=192.0.2.1") {
		t.Errorf("the default gateway must be snapshotted; got:\n%s", got)
	}
	if contains6789(got, "DHCP=yes") {
		t.Errorf("a PERMANENT (ValidLft==forever) address is STATIC and must not produce a DHCP "+
			".network — that substitution is the lockout #6789 closes; got:\n%s", got)
	}
	if !*st.reloaded {
		t.Error("a complete observation must still reload networkd")
	}
}

// TestRouteFailureForAFamilyWithNoAddressesDoesNotRefuse6789 is the
// ANTI-OVER-REACH control, and it guards the scoping decision.
//
// A route-dump failure only matters when a Gateway= line for that family would
// have been written. Refusing because the IPv6 route dump errored on a box with
// no IPv6 addresses would strand the lifeline over an observation that could
// not have changed a single byte of the output — the kind of over-broad
// fail-closed that turns a conditional hazard into an unconditional outage.
//
// FAIL-ON-REVERT: dropping the `haveAddrs` scope in snapshotLifelineAddrs makes
// this refuse and reds the write/rename assertions.
func TestRouteFailureForAFamilyWithNoAddressesDoesNotRefuse6789(t *testing.T) {
	st := staticLifelineSeams(t)
	injected := errors.New("injected: v6 route dump failed")
	lifelineLinkByName = func(string) (netlink.Link, error) { return okLink(), nil }
	lifelineAddrList = func(netlink.Link, int) ([]netlink.Addr, error) {
		// v4 only — nothing in the v6 family to write a Gateway= for.
		return []netlink.Addr{staticAddr("192.0.2.10/24")}, nil
	}
	lifelineRouteList = func(_ netlink.Link, family int) ([]netlink.Route, error) {
		if family == netlink.FAMILY_V6 {
			return nil, injected
		}
		return []netlink.Route{{Gw: net.ParseIP("192.0.2.1")}}, nil
	}

	d := &Daemon{store: newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))}
	d.setupBootstrapLifeline()

	netPath := filepath.Join(st.linkDir, linkPrefix+"fxp0.network")
	if _, err := os.ReadFile(netPath); err != nil {
		t.Fatalf("a v6 route-dump failure on a box with NO v6 addresses must NOT refuse the "+
			"lifeline: nothing it could have observed would appear in the output. err=%v", err)
	}
	if !*st.reloaded {
		t.Error("the lifeline must still complete when the failed observation is irrelevant")
	}
}

func contains6789(h, n string) bool {
	for i := 0; i+len(n) <= len(h); i++ {
		if h[i:i+len(n)] == n {
			return true
		}
	}
	return false
}

// TestApplianceFactoryBootIsNotRefusedByASnapshotFailure6789 binds the OTHER
// half of the scoping decision, and it is the one that keeps this fix from
// breaking the factory image.
//
// The refusal is conditioned on the lifeline having been chosen BY DEFAULT
// ROUTE, because that is positive evidence the NIC carries live addressing the
// rename must reproduce. The #7114 appliance factory lifeline is chosen
// precisely when there is NO default route — the bake purges cloud-init and
// netplan, so nothing has brought a NIC up — and DHCP is that image's
// documented vNIC#1 -> fxp0 contract. A failed observation there cannot change
// a single byte of what gets written, so refusing would break the factory boot
// to protect information that was never going to be used.
//
// This was not a hypothetical: the first version of the fix refused
// unconditionally and reddened the pre-existing
// TestSetupBootstrapLifelineAppliance.
//
// FAIL-ON-REVERT: removing the hasRouteEvidence scope makes the appliance boot
// refuse and reds the "DHCP .network written" assertion.
func TestApplianceFactoryBootIsNotRefusedByASnapshotFailure6789(t *testing.T) {
	st := staticLifelineSeams(t)
	// #7114 precondition: NO default route, plus the appliance marker.
	detectLifelineInterfaceFn = func() (string, bool, error) { return "", false, nil }

	dir := t.TempDir()
	oldMarker := applianceMarkerFile
	applianceMarkerFile = filepath.Join(dir, "appliance")
	t.Cleanup(func() { applianceMarkerFile = oldMarker })
	if err := os.WriteFile(applianceMarkerFile, []byte("appliance\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// And the addressing observation fails, exactly as in the refusing arms.
	lifelineLinkByName = func(string) (netlink.Link, error) {
		return nil, errors.New("injected: netlink observation failure")
	}

	d := &Daemon{store: newConfigStore(t, filepath.Join(dir, "xpf.conf"))}
	if d.store.EverCommitted() {
		t.Fatal("premise: a fresh store must report EverCommitted()==false")
	}
	d.setupBootstrapLifeline()

	netPath := filepath.Join(st.linkDir, linkPrefix+"fxp0.network")
	data, err := os.ReadFile(netPath)
	if err != nil {
		t.Fatalf("an appliance FACTORY boot must still claim vNIC#1 as fxp0 with the image's DHCP "+
			".network even when the addressing observation fails: there is no default route and no "+
			"addressing to reproduce, so nothing observable could have changed the output. "+
			"Refusing here breaks the factory image (#7114/#6789). err=%v", err)
	}
	if !contains6789(string(data), "DHCP=yes") {
		t.Errorf("the appliance factory .network must be the DHCP form; got:\n%s", data)
	}
}

// filesIn lists the files written into the bootstrap link dir, so a test can
// assert that NOTHING was produced (neither the .network nor the .link).
func filesIn(t *testing.T, dir string) []string {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read link dir: %v", err)
	}
	var out []string
	for _, e := range ents {
		out = append(out, e.Name())
	}
	return out
}

// TestUnreadableRouteTableClaimsNothingOnAppliance6789 is the SECOND defect in
// this issue, and it is the dangerous one.
//
// detectLifelineInterface dumped routes with `routes, err := netlink.RouteList(
// nil, family); if err != nil { continue }` — the error DISCARDED — and a failed
// dump returns a nil slice, which is byte-for-byte what "this box has no default
// route" looks like. The caller then BRANCHES on exactly that distinction:
//
//	applianceFactory := routeIface == "" && d.applianceFactoryBoot()
//
// So on a box carrying /etc/xpf/appliance that has never committed, a netlink
// error silently flips the selection from "use the NIC that holds the default
// route" to "claim the FIRST ENUMERATED NIC" — which is then renamed, and
// renameInterface is an explicit LinkSetDown -> LinkSetName -> LinkSetUp. If the
// real management NIC is not enumeration index 0, the wrong NIC is claimed and
// the management NIC is cycled, on a box reachable only over it.
//
// It is reachable on a REAL factory box: the previous boot's bootstrap lifeline
// writes an fxp0 DHCP .network, so the next boot genuinely has a default route
// while EverCommitted() is still false.
//
// Note the asymmetry this cell exists to pin: on a NON-appliance box the same
// error is harmless (empty routeIface -> chooseBootstrapLifeline refuses ->
// console-only). The appliance marker is what turns a swallowed netlink error
// into a claimed and cycled NIC.
//
// FAIL-ON-REVERT: swallowing the RouteList error again (or dropping the
// routeErr check at the call site) arms the appliance fallback, and the .link /
// rename / reload assertions all go RED.
func TestUnreadableRouteTableClaimsNothingOnAppliance6789(t *testing.T) {
	st := staticLifelineSeams(t)

	dir := t.TempDir()
	oldMarker := applianceMarkerFile
	applianceMarkerFile = filepath.Join(dir, "appliance")
	t.Cleanup(func() { applianceMarkerFile = oldMarker })
	if err := os.WriteFile(applianceMarkerFile, []byte("appliance\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// The route table cannot be read. Drive the REAL detectLifelineInterface
	// through its netlink seam rather than stubbing the detector, so this cell
	// binds the actual error-swallowing site.
	oldDetect := detectLifelineInterfaceFn
	detectLifelineInterfaceFn = detectLifelineInterface
	t.Cleanup(func() { detectLifelineInterfaceFn = oldDetect })
	lifelineRouteList = func(netlink.Link, int) ([]netlink.Route, error) {
		return nil, errors.New("injected: route dump failed")
	}

	d := &Daemon{store: newConfigStore(t, filepath.Join(dir, "xpf.conf"))}
	if d.store.EverCommitted() {
		t.Fatal("premise: a fresh store must report EverCommitted()==false")
	}
	d.setupBootstrapLifeline()

	if got := filesIn(t, st.linkDir); len(got) != 0 {
		t.Errorf("an UNREADABLE route table must claim NOTHING, but files were written: %v. "+
			"A failed route dump is indistinguishable from 'no default route', and an empty "+
			"routeIface is what arms the #7114 appliance first-NIC fallback (#6789)", got)
	}
	if *st.renamed {
		t.Error("the first enumerated NIC was RENAMED because a netlink error was read as " +
			"'no default route'. renameInterface does LinkSetDown -> LinkSetName -> LinkSetUp, " +
			"so this cycles a NIC that may not be the management NIC at all (#6789)")
	}
	if *st.reloaded {
		t.Error("networkctl reload ran on a box that must have claimed nothing")
	}
}

// TestApplianceFallbackStillFiresWhenRoutesAreReadable6789 is the tightening
// control for the cell above, and it pins the DISCRIMINATOR.
//
// The refusal must key on the route observation having FAILED, not on
// routeIface being empty — those are the two states the old code conflated, and
// a fix that refuses whenever routeIface is empty would disable the #7114
// appliance factory contract entirely, stranding every factory image
// console-only on first boot.
//
// Same fixture as above, one difference: the route dump SUCCEEDS and genuinely
// returns no default route.
//
// FAIL-ON-REVERT: changing the call-site guard from `routeIface == "" &&
// routeErr != nil` to `routeIface == ""` reds this.
func TestApplianceFallbackStillFiresWhenRoutesAreReadable6789(t *testing.T) {
	st := staticLifelineSeams(t)

	dir := t.TempDir()
	oldMarker := applianceMarkerFile
	applianceMarkerFile = filepath.Join(dir, "appliance")
	t.Cleanup(func() { applianceMarkerFile = oldMarker })
	if err := os.WriteFile(applianceMarkerFile, []byte("appliance\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	oldDetect := detectLifelineInterfaceFn
	detectLifelineInterfaceFn = detectLifelineInterface
	t.Cleanup(func() { detectLifelineInterfaceFn = oldDetect })
	// Readable, and genuinely empty — the real factory-boot state.
	lifelineRouteList = func(netlink.Link, int) ([]netlink.Route, error) { return nil, nil }
	lifelineLinkByName = func(string) (netlink.Link, error) { return okLink(), nil }
	lifelineAddrList = func(netlink.Link, int) ([]netlink.Addr, error) { return nil, nil }

	d := &Daemon{store: newConfigStore(t, filepath.Join(dir, "xpf.conf"))}
	d.setupBootstrapLifeline()

	netPath := filepath.Join(st.linkDir, linkPrefix+"fxp0.network")
	data, err := os.ReadFile(netPath)
	if err != nil {
		t.Fatalf("a READABLE route table that genuinely holds no default route must still arm the "+
			"#7114 appliance factory fallback: the refusal keys on the observation FAILING, not on "+
			"routeIface being empty. Keying on empty would strand every factory image console-only "+
			"on first boot. err=%v", err)
	}
	if !contains6789(string(data), "DHCP=yes") {
		t.Errorf("the appliance factory .network must be the DHCP form; got:\n%s", data)
	}
}

// TestDetectLifelineInterfaceReportsObservationFailures6789 unit-binds the
// producer. The cells above drive it through setupBootstrapLifeline, which
// proves the CONSEQUENCE; this proves the distinction the consequence rests on,
// and it covers the second swallowed error (LinkByIndex) that no end-to-end
// cell reaches.
//
// The table is a PAIR per row: an observation failure must report an error, and
// the corresponding success must report none. Without the success rows, a fix
// that always returns an error would pass — and would strand every box.
func TestDetectLifelineInterfaceReportsObservationFailures6789(t *testing.T) {
	injected := errors.New("injected")
	oldRoute, oldIdx := lifelineRouteList, lifelineLinkByIndex
	t.Cleanup(func() { lifelineRouteList, lifelineLinkByIndex = oldRoute, oldIdx })

	defaultRoute := []netlink.Route{{LinkIndex: 2}}

	tests := []struct {
		name    string
		route   func(netlink.Link, int) ([]netlink.Route, error)
		byIndex func(int) (netlink.Link, error)
		wantOK  bool
		wantErr bool
	}{
		{
			name:    "route-dump-fails-is-UNKNOWN-not-none",
			route:   func(netlink.Link, int) ([]netlink.Route, error) { return nil, injected },
			byIndex: func(int) (netlink.Link, error) { return okLink(), nil },
			wantOK:  false, wantErr: true,
		},
		{
			name:    "readable-and-genuinely-empty-is-none",
			route:   func(netlink.Link, int) ([]netlink.Route, error) { return nil, nil },
			byIndex: func(int) (netlink.Link, error) { return okLink(), nil },
			wantOK:  false, wantErr: false,
		},
		{
			// A default route exists but its link cannot be resolved: still
			// UNKNOWN, and the old code swallowed this one too.
			name:    "route-found-but-link-unresolvable-is-UNKNOWN",
			route:   func(_ netlink.Link, _ int) ([]netlink.Route, error) { return defaultRoute, nil },
			byIndex: func(int) (netlink.Link, error) { return nil, injected },
			wantOK:  false, wantErr: true,
		},
		{
			name:    "route-found-and-resolvable-is-positive-identification",
			route:   func(_ netlink.Link, _ int) ([]netlink.Route, error) { return defaultRoute, nil },
			byIndex: func(int) (netlink.Link, error) { return okLink(), nil },
			wantOK:  true, wantErr: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			lifelineRouteList = tc.route
			lifelineLinkByIndex = tc.byIndex

			name, ok, err := detectLifelineInterface()
			if ok != tc.wantOK {
				t.Errorf("ok = %v (name %q), want %v", ok, name, tc.wantOK)
			}
			if (err != nil) != tc.wantErr {
				t.Errorf("err = %v, want error: %v. A swallowed observation error is reported as "+
					"a confident 'no default route', which is what arms the appliance first-NIC "+
					"fallback (#6789)", err, tc.wantErr)
			}
		})
	}
}

// TestPartialRouteErrorStillUsesAFoundRoute6789 is the anti-over-reach control
// for the producer: one family's dump fails, the other finds a default route.
// A FOUND route is positive identification, so the partial error must not
// discard it — the error only matters when it could have hidden the answer.
//
// FAIL-ON-REVERT: returning firstErr unconditionally (before the found-route
// return) makes this refuse a box whose management NIC was positively
// identified.
func TestPartialRouteErrorStillUsesAFoundRoute6789(t *testing.T) {
	oldRoute, oldIdx := lifelineRouteList, lifelineLinkByIndex
	t.Cleanup(func() { lifelineRouteList, lifelineLinkByIndex = oldRoute, oldIdx })

	lifelineRouteList = func(_ netlink.Link, family int) ([]netlink.Route, error) {
		if family == netlink.FAMILY_V4 {
			return nil, errors.New("injected: v4 dump failed")
		}
		return []netlink.Route{{LinkIndex: 2}}, nil
	}
	lifelineLinkByIndex = func(int) (netlink.Link, error) { return okLink(), nil }

	name, ok, err := detectLifelineInterface()
	if !ok || err != nil {
		t.Fatalf("a default route that WAS found and resolved is positive identification and must "+
			"be used even though another family's dump errored; got name=%q ok=%v err=%v",
			name, ok, err)
	}
	if name != defaultMgmtInterface {
		t.Errorf("name = %q, want %q", name, defaultMgmtInterface)
	}
}
