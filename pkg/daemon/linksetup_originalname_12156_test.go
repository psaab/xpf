package daemon

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vishvananda/netlink"
)

// #12156. recoverOriginalName matches Name=<current> and returns the current
// name when the .link carries NO OriginalName= line. networkd renders exactly
// such a MAC-form fxp0 .link when OriginalName is empty (networkd.go
// generateLink), so on the next naming pass the positional capture
// (linksetup.go renamePositional) and the bootstrap lifeline (bootstrap.go
// setupBootstrapLifeline) both "recover" fxp0 and persist
// OriginalName=fxp0 / Name=fxp0 — a .link udev can never match, because udev
// never presents the logical name as the kernel original. The device-map path
// has the #6678 guard; this regression covers the corresponding missing
// positional/bootstrap guard.
//
// The fix contract, mirrored on #6678: when no kernel original name is
// recorded and the NIC already wears its final name, the pass must NOT
// persist the logical name as OriginalName=. It retains the existing
// MAC-form link (which still matches — the MAC is stable for non-RETH NICs)
// and reports the unestablished persistence loudly instead of writing a file
// that silently never matches.

// macFormFxp0Link is what networkd's generateLink renders for fxp0 when
// OriginalName is empty: MAC match, no OriginalName= line.
const macFormFxp0Link12156 = `# Managed by xpfd — do not edit
[Match]
MACAddress=52:54:00:12:34:56

[Link]
Name=fxp0
`

func writeMACFormFxp0Link12156(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, linkPrefix+"fxp0.link")
	if err := os.WriteFile(path, []byte(macFormFxp0Link12156), 0644); err != nil {
		t.Fatalf("write MAC-form fixture: %v", err)
	}
	return path
}

func assertNoSelfOriginal12156(t *testing.T, path string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	got := string(data)
	if strings.Contains(got, "OriginalName=fxp0") {
		t.Fatalf("an unmatchable self-referential OriginalName=fxp0 was persisted:\n%s", got)
	}
	if !strings.Contains(got, "MACAddress=") {
		t.Fatalf("the MAC-form link was not retained (MAC match line lost):\n%s", got)
	}
}

// TestRenamePositionalRetainsMACFormLink12156 drives the real positional pass
// with a NIC already wearing fxp0 and only a MAC-form .link on disk. The
// pass must leave that file alone — no OriginalName=fxp0 — while positional
// naming continues without refusing an already-named interface.
//
// FAIL-ON-REVERT: restoring the unconditional recoverOriginalName capture
// makes the pass overwrite the MAC-form file with OriginalName=fxp0.
func TestRenamePositionalRetainsMACFormLink12156(t *testing.T) {
	dir := withTempLinkDir(t)
	linkPath := writeMACFormFxp0Link12156(t, dir)

	nics := []pciNIC{{sortKey: 1, busAddr: "0000:05:00.0", name: "fxp0"}}
	renameCalls := 0
	_, errs := renamePositional(nics, 0, false, func(from, to string) error {
		renameCalls++
		return nil
	})

	assertNoSelfOriginal12156(t, linkPath)
	if renameCalls != 0 {
		t.Fatalf("a NIC already wearing its final name must not be renamed, got %d rename calls", renameCalls)
	}
	if len(errs) != 0 {
		t.Fatalf("skipping an unmatchable .link must not refuse positional naming: %v", errs)
	}
}

// TestBootstrapLifelineRetainsMACFormLink12156 drives the real bootstrap
// lifeline with the management NIC already wearing fxp0 (a second+ boot
// whose .link is the MAC form networkd re-rendered). The lifeline must not
// rewrite it as OriginalName=fxp0 / Name=fxp0.
//
// FAIL-ON-REVERT: restoring the bare recoverOriginalName call at the
// bootstrap write site overwrites the MAC-form file with OriginalName=fxp0.
func TestBootstrapLifelineRetainsMACFormLink12156(t *testing.T) {
	st := staticLifelineSeams(t)
	linkPath := writeMACFormFxp0Link12156(t, st.linkDir)

	// Complete addressing observation, so the #6789 refusal does not fire
	// and the test reaches the .link write it pins.
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

	assertNoSelfOriginal12156(t, linkPath)
	if !*st.reloaded {
		t.Error("the lifeline must still complete (reload networkd) when it retains the MAC-form link")
	}
}

// TestBootstrapFactoryFallbackRetainsMACFormLink12156 covers the same guard
// when bootstrap selects the first NIC through the appliance factory fallback
// rather than a default route. Both selection sources converge on the same
// bootstrap .link write site, which must retain the MAC match.
func TestBootstrapFactoryFallbackRetainsMACFormLink12156(t *testing.T) {
	st := staticLifelineSeams(t)
	linkPath := writeMACFormFxp0Link12156(t, st.linkDir)

	// The appliance factory path is selected only when route detection
	// succeeds with no default route and the uncommitted appliance marker exists.
	detectLifelineInterfaceFn = func() (string, bool, error) { return "", false, nil }
	dir := t.TempDir()
	oldMarker := applianceMarkerFile
	applianceMarkerFile = filepath.Join(dir, "appliance")
	t.Cleanup(func() { applianceMarkerFile = oldMarker })
	if err := os.WriteFile(applianceMarkerFile, []byte("appliance\n"), 0644); err != nil {
		t.Fatalf("write appliance marker: %v", err)
	}

	// The fresh factory NIC has not been brought up yet, so its successful
	// observation is empty and the bootstrap contract is DHCP.
	lifelineLinkByName = func(string) (netlink.Link, error) { return okLink(), nil }
	lifelineAddrList = func(netlink.Link, int) ([]netlink.Addr, error) { return nil, nil }
	lifelineRouteList = func(_ netlink.Link, _ int) ([]netlink.Route, error) { return nil, nil }

	d := &Daemon{store: newConfigStore(t, filepath.Join(dir, "xpf.conf"))}
	d.setupBootstrapLifeline()

	assertNoSelfOriginal12156(t, linkPath)
	networkPath := filepath.Join(st.linkDir, linkPrefix+defaultMgmtInterface+".network")
	if data, err := os.ReadFile(networkPath); err != nil {
		t.Fatalf("the appliance factory lifeline must still write its DHCP .network: %v", err)
	} else if !strings.Contains(string(data), "DHCP=yes") {
		t.Fatalf("the appliance factory lifeline must retain DHCP behavior, got:\n%s", data)
	}
	if !*st.reloaded {
		t.Error("the factory lifeline must still complete (reload networkd) when it retains the MAC-form link")
	}
	if *st.renamed {
		t.Error("a NIC already wearing fxp0 must not be renamed")
	}
}

// TestRenamePositionalWritesGenuineKernelName12156 is the positive control:
// a NIC that does NOT yet wear its final name is genuinely pre-rename, so
// its current name IS the kernel original and the pass must persist it.
// Without this, the tests above could pass because the harness never writes
// a .link at all — a green that proves nothing.
func TestRenamePositionalWritesGenuineKernelName12156(t *testing.T) {
	dir := withTempLinkDir(t) // empty: no .link records any original

	nics := []pciNIC{{sortKey: 1, busAddr: "0000:05:00.0", name: "enp5s0"}}
	var renamed [][2]string
	_, errs := renamePositional(nics, 0, false, func(from, to string) error {
		renamed = append(renamed, [2]string{from, to})
		return nil
	})
	for _, err := range errs {
		t.Fatalf("the genuine-kernel-name control must be error-free, got %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, linkPrefix+"fxp0.link"))
	if err != nil {
		t.Fatalf("a pre-rename NIC must still get its boot-persistence .link: %v", err)
	}
	got := string(data)
	if !strings.Contains(got, "OriginalName=enp5s0") {
		t.Fatalf("the genuine kernel name must be persisted as OriginalName=, got:\n%s", got)
	}
	if len(renamed) != 1 || renamed[0] != [2]string{"enp5s0", "fxp0"} {
		t.Fatalf("expected exactly the enp5s0->fxp0 rename, got %v", renamed)
	}
}

// TestRenamePositionalRecoversVerifiedOriginal12156 is the second positive
// control: a NIC wearing its final name whose .link DOES record a genuine
// kernel OriginalName= keeps that chain — the fix must only refuse the
// unverified self-name, never a verified original.
func TestRenamePositionalRecoversVerifiedOriginal12156(t *testing.T) {
	dir := withTempLinkDir(t)
	chained := "# Managed by xpfd — do not edit\n[Match]\nOriginalName=enp5s0\n\n[Link]\nName=fxp0"
	linkPath := filepath.Join(dir, linkPrefix+"fxp0.link")
	if err := os.WriteFile(linkPath, []byte(chained), 0644); err != nil {
		t.Fatalf("write chained fixture: %v", err)
	}

	nics := []pciNIC{{sortKey: 1, busAddr: "0000:05:00.0", name: "fxp0"}}
	changed, errs := renamePositional(nics, 0, false, func(from, to string) error {
		t.Fatalf("unexpected rename %s->%s", from, to)
		return nil
	})
	for _, err := range errs {
		t.Fatalf("the verified-original control must be error-free, got %v", err)
	}
	if changed {
		t.Fatal("re-rendering an identical verified .link must be a no-op (no churn)")
	}
	data, err := os.ReadFile(linkPath)
	if err != nil || string(data) != chained {
		t.Fatalf("the verified .link must be byte-identical, got %q err=%v", data, err)
	}
}
