package daemon

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vishvananda/netlink"
)

// #12550: a retained MAC-form .link (Name=<current>, MACAddress=, no
// OriginalName=) must be verified against the NIC currently wearing that
// name before it is preserved. A stale file whose MAC belongs to another
// NIC would otherwise claim the logical name for the wrong device on the
// next boot.

func stubIdentity12550(t *testing.T, mac string, err error) {
	t.Helper()
	old := nicIdentityMACFn
	nicIdentityMACFn = func(string) (string, error) { return mac, err }
	t.Cleanup(func() { nicIdentityMACFn = old })
}

func writeMACFormLink12550(t *testing.T, dir, name, mac string) string {
	t.Helper()
	path := filepath.Join(dir, linkPrefix+name+".link")
	content := "# Managed by xpfd — do not edit\n[Match]\nMACAddress=" + mac + "\n\n[Link]\nName=" + name + "\n"
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return path
}

func TestRenamePositionalNeutralizesStaleMACFormLink12550(t *testing.T) {
	logs := captureLogs12156(t)
	dir := withTempLinkDir(t)
	linkPath := writeMACFormLink12550(t, dir, "fxp0", "52:54:00:aa:bb:cc")
	stubIdentity12550(t, "52:54:00:12:34:56", nil)

	_, errs := renamePositional([]pciNIC{{sortKey: 1, busAddr: "0000:05:00.0", name: "fxp0"}}, 0, false,
		func(string, string) error { return nil })
	if _, err := os.Stat(linkPath); !os.IsNotExist(err) {
		t.Fatalf("stale MAC-form link must be neutralized, stat err=%v", err)
	}
	if len(errs) == 0 {
		t.Fatal("stale MAC-form link must surface an error")
	}
	if got := logs.String(); !strings.Contains(got, "level=ERROR") || !strings.Contains(strings.ToLower(got), "mismatch") {
		t.Fatalf("mismatch must log ERROR mentioning mismatch, got:\n%s", got)
	}
}

func TestRenamePositionalUnreadableIdentityNeutralizes12550(t *testing.T) {
	logs := captureLogs12156(t)
	dir := withTempLinkDir(t)
	linkPath := writeMACFormLink12550(t, dir, "fxp0", "52:54:00:12:34:56")
	stubIdentity12550(t, "", errors.New("injected identity read failure"))

	_, errs := renamePositional([]pciNIC{{sortKey: 1, busAddr: "0000:05:00.0", name: "fxp0"}}, 0, false,
		func(string, string) error { return nil })
	if _, err := os.Stat(linkPath); !os.IsNotExist(err) {
		t.Fatalf("unverifiable MAC-form link must be neutralized, stat err=%v", err)
	}
	if len(errs) == 0 {
		t.Fatal("unreadable identity must surface an error")
	}
	got := strings.ToLower(logs.String())
	if !strings.Contains(got, "unreadable") && !strings.Contains(got, "could not read") && !strings.Contains(got, "cannot verify") {
		t.Fatalf("unreadable identity must be logged distinctly, got:\n%s", logs.String())
	}
	if strings.Contains(got, "mismatch") {
		t.Fatalf("unreadable must be distinct from mismatch, got:\n%s", logs.String())
	}
}

// Permanent MAC is preferred over the running MAC: running differs (e.g.
// administratively set) but permanent matches the retained file.
func TestRetainedMACPrefersPermanentMAC12550(t *testing.T) {
	dir := withTempLinkDir(t)
	writeMACFormLink12550(t, dir, "fxp0", "52:54:00:12:34:56")
	oldByName := nlLinkByName
	nlLinkByName = func(string) (netlink.Link, error) {
		return &netlink.Device{LinkAttrs: netlink.LinkAttrs{
			Name:         "fxp0",
			HardwareAddr: net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01},
			PermHWAddr:   net.HardwareAddr{0x52, 0x54, 0x00, 0x12, 0x34, 0x56},
		}}, nil
	}
	t.Cleanup(func() { nlLinkByName = oldByName })
	// Use the real identity reader (restore default explicitly).
	oldID := nicIdentityMACFn
	nicIdentityMACFn = readNICIdentityMAC
	t.Cleanup(func() { nicIdentityMACFn = oldID })

	if v := verifyRetainedMACLink("fxp0"); v != retainedMACMatch {
		t.Fatalf("permanent MAC match must verify, got verdict %v", v)
	}
}

func TestRetainedMACFallsBackToRunningWhenNoPermanent12550(t *testing.T) {
	dir := withTempLinkDir(t)
	writeMACFormLink12550(t, dir, "fxp0", "52:54:00:12:34:56")
	oldByName := nlLinkByName
	nlLinkByName = func(string) (netlink.Link, error) {
		return &netlink.Device{LinkAttrs: netlink.LinkAttrs{
			Name:         "fxp0",
			HardwareAddr: net.HardwareAddr{0x52, 0x54, 0x00, 0x99, 0x99, 0x99},
		}}, nil
	}
	t.Cleanup(func() { nlLinkByName = oldByName })
	oldID := nicIdentityMACFn
	nicIdentityMACFn = readNICIdentityMAC
	t.Cleanup(func() { nicIdentityMACFn = oldID })

	if v := verifyRetainedMACLink("fxp0"); v != retainedMACMismatch {
		t.Fatalf("running-MAC mismatch with no permanent MAC must be mismatch, got %v", v)
	}
}

func TestRetainedMACMatchPreservesFile12550(t *testing.T) {
	dir := withTempLinkDir(t)
	path := writeMACFormLink12550(t, dir, "fxp0", "52:54:00:12:34:56")
	stubIdentity12550(t, "52:54:00:12:34:56", nil)
	_, errs := renamePositional([]pciNIC{{sortKey: 1, busAddr: "0000:05:00.0", name: "fxp0"}}, 0, false,
		func(string, string) error { return nil })
	if len(errs) != 0 {
		t.Fatalf("verified retained MAC must not fail naming: %v", errs)
	}
	got, err := os.ReadFile(path)
	if err != nil || !strings.Contains(string(got), "MACAddress=52:54:00:12:34:56") ||
		strings.Contains(string(got), "OriginalName=") {
		t.Fatalf("verified MAC-form link must be retained byte-for-byte, got %q err=%v", got, err)
	}
}

func TestRetainedMACCheckIgnoresOriginalNameAndNoMAC12550(t *testing.T) {
	dir := withTempLinkDir(t)
	if err := os.WriteFile(filepath.Join(dir, linkPrefix+"fxp0.link"),
		[]byte("[Match]\nOriginalName=enp5s0\n[Link]\nName=fxp0\n"), 0644); err != nil {
		t.Fatal(err)
	}
	stubIdentity12550(t, "", errors.New("must not be called"))
	if got := verifyRetainedMACLink("fxp0"); got != retainedMACAbsent {
		t.Fatalf("OriginalName link should not enter retained-MAC verification, got %v", got)
	}
	if err := os.WriteFile(filepath.Join(dir, linkPrefix+"fxp0.link"),
		[]byte("[Match]\nName=fxp0\n[Link]\nName=fxp0\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if got := verifyRetainedMACLink("fxp0"); got != retainedMACAbsent {
		t.Fatalf("name-only link without MAC should not enter identity check, got %v", got)
	}
}

func TestBootstrapLifelineNeutralizesStaleMACFormLink12550(t *testing.T) {
	logs := captureLogs12156(t)
	st := staticLifelineSeams(t)
	linkPath := writeMACFormFxp0Link12156(t, st.linkDir)
	stubIdentity12550(t, "52:54:00:99:99:99", nil)
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
	if _, err := os.Stat(linkPath); !os.IsNotExist(err) {
		t.Fatalf("bootstrap stale MAC-form fxp0 link must be neutralized, stat err=%v", err)
	}
	if got := logs.String(); !strings.Contains(got, "level=ERROR") || !strings.Contains(strings.ToLower(got), "mismatch") {
		t.Fatalf("bootstrap mismatch must log ERROR mentioning mismatch, got:\n%s", got)
	}
}

func TestBootstrapLifelineUnreadableIdentityNeutralizes12550(t *testing.T) {
	logs := captureLogs12156(t)
	st := staticLifelineSeams(t)
	linkPath := writeMACFormFxp0Link12156(t, st.linkDir)
	stubIdentity12550(t, "", errors.New("injected identity read failure"))
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
	if _, err := os.Stat(linkPath); !os.IsNotExist(err) {
		t.Fatalf("bootstrap unverifiable fxp0 link must be neutralized, stat err=%v", err)
	}
	got := strings.ToLower(logs.String())
	if !strings.Contains(got, "unreadable") && !strings.Contains(got, "could not read") && !strings.Contains(got, "cannot verify") {
		t.Fatalf("bootstrap unreadable must be logged distinctly, got:\n%s", logs.String())
	}
}
