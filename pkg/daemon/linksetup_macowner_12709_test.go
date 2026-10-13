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

// #12709: the target-change neutralize (MAJOR-1) deletes .link files by
// FILENAME without checking their MACAddress=. A file filed under the
// neutralizing NIC's old/new logical name whose MACAddress= names a
// DIFFERENT NIC (the case where the filename's owner was temp-renamed or
// enumeration shifted) must survive: it is that other NIC's correct claim,
// and only a later boot can re-derive it once the other NIC's original is
// forgotten. Filename equality is not an ownership invariant — nothing pins
// a MAC-form file's [Match] MACAddress= to the NIC whose logical name spells
// its filename.

// stubIdentityByName12709 replaces the identity seam with a per-name map;
// names absent from the map report an unreadable identity.
func stubIdentityByName12709(t *testing.T, byName map[string]string) {
	t.Helper()
	old := nicIdentityMACFn
	nicIdentityMACFn = func(name string) (string, error) {
		if mac, ok := byName[name]; ok {
			return mac, nil
		}
		return "", errors.New("no stub identity for " + name)
	}
	t.Cleanup(func() { nicIdentityMACFn = old })
}

func writeLink12709(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, linkPrefix+name+".link")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write fixture %s: %v", path, err)
	}
	return path
}

func macForm12709(mac, name string) string {
	return "# Managed by xpfd — do not edit\n[Match]\nMACAddress=" + mac + "\n\n[Link]\nName=" + name + "\n"
}

// The unknown NIC U wears ge-0-0-0 via a link naming U's own MAC and must
// rename to fxp0. The stale fxp0.link is a MAC-form file whose MAC belongs
// to a DIFFERENT NIC (the real fxp0 claimant V). Deleting it by filename
// robs V of its correct claim; it must survive.
func TestTargetChangePreservesForeignMACLink12709(t *testing.T) {
	dir := withTempLinkDir(t)
	writeLink12709(t, dir, "ge-0-0-0", macForm12709("52:54:00:00:00:0b", "ge-0-0-0"))
	foreign := writeLink12709(t, dir, "fxp0", macForm12709("52:54:00:00:00:99", "fxp0"))
	// U's live identity (current legal name ge-0-0-0) matches its own link;
	// the fxp0 file's MAC belongs to V, not to U.
	stubIdentityByName12709(t, map[string]string{"ge-0-0-0": "52:54:00:00:00:0b"})

	_, errs := renamePositional([]pciNIC{{sortKey: 1, busAddr: "0000:05:00.0", name: "ge-0-0-0"}}, 0, false,
		func(string, string) error { return nil })
	if len(errs) != 0 {
		t.Fatalf("preserving a foreign claim must not fail the pass: %v", errs)
	}
	got, err := os.ReadFile(foreign)
	if err != nil {
		t.Fatalf("foreign MAC-form fxp0.link (MAC of another NIC) must survive the target-change neutralize: %v", err)
	}
	if !strings.Contains(string(got), "MACAddress=52:54:00:00:00:99") {
		t.Fatalf("surviving foreign link must be byte-identical, got:\n%s", got)
	}
	// U's own link (MAC matches U) still goes.
	if _, err := os.Stat(filepath.Join(dir, linkPrefix+"ge-0-0-0.link")); !os.IsNotExist(err) {
		t.Fatalf("the neutralizing NIC's own matching link must be removed, stat err=%v", err)
	}
}

// Both deletion slots hold MAC-form files of other NICs: O.link's MAC names
// another NIC entirely (not the neutralizing NIC), and T.link's MAC names
// yet another. Both must survive; the rename still happens.
func TestTargetChangePreservesBothForeignMACSlots12709(t *testing.T) {
	dir := withTempLinkDir(t)
	own := writeLink12709(t, dir, "ge-0-0-0", macForm12709("52:54:00:00:00:77", "ge-0-0-0"))
	target := writeLink12709(t, dir, "fxp0", macForm12709("52:54:00:00:00:99", "fxp0"))
	stubIdentityByName12709(t, map[string]string{"ge-0-0-0": "52:54:00:00:00:0b"})

	var renamed [][2]string
	_, errs := renamePositional([]pciNIC{{sortKey: 1, busAddr: "0000:05:00.0", name: "ge-0-0-0"}}, 0, false,
		func(from, to string) error { renamed = append(renamed, [2]string{from, to}); return nil })
	if len(errs) != 0 {
		t.Fatalf("preserving foreign claims must not fail the pass: %v", errs)
	}
	for _, path := range []string{own, target} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("foreign MAC-form link %s must survive, stat err=%v", path, err)
		}
	}
	if len(renamed) != 1 || renamed[0] != [2]string{"ge-0-0-0", "fxp0"} {
		t.Fatalf("the required rename must still run, got %v", renamed)
	}
}

// Positive control: a MAC-form T.link whose MAC matches the neutralizing
// NIC is its own misfiled claim and still goes (the #12156 MAJOR-1 shape,
// where the file under the target name carries the mover's MAC).
func TestTargetChangeRemovesMatchingMACLink12709(t *testing.T) {
	dir := withTempLinkDir(t)
	writeLink12709(t, dir, "ge-0-0-0", macForm12709("52:54:00:00:00:0b", "ge-0-0-0"))
	target := writeLink12709(t, dir, "fxp0", macForm12709("52:54:00:00:00:0b", "fxp0"))
	stubIdentityByName12709(t, map[string]string{"ge-0-0-0": "52:54:00:00:00:0b"})

	_, errs := renamePositional([]pciNIC{{sortKey: 1, busAddr: "0000:05:00.0", name: "ge-0-0-0"}}, 0, false,
		func(string, string) error { return nil })
	if len(errs) != 0 {
		t.Fatalf("removing own claims must not fail the pass: %v", errs)
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatalf("a T.link carrying the neutralizing NIC's own MAC must be removed, stat err=%v", err)
	}
}

// Case/format variants: MAC comparison must follow #12550's ParseMAC
// semantics, not string equality. An upper-case/hyphen-spelled file MAC
// equal to the NIC's MAC is a match (removed); a genuinely different MAC
// spelled differently is still foreign (preserved).
func TestTargetChangeMACFormatVariants12709(t *testing.T) {
	dir := withTempLinkDir(t)
	writeLink12709(t, dir, "ge-0-0-0", macForm12709("52:54:00:00:00:0b", "ge-0-0-0"))
	matching := writeLink12709(t, dir, "fxp0", macForm12709("52-54-00-00-00-0B", "fxp0"))
	stubIdentityByName12709(t, map[string]string{"ge-0-0-0": "52:54:00:00:00:0b"})
	_, errs := renamePositional([]pciNIC{{sortKey: 1, busAddr: "0000:05:00.0", name: "ge-0-0-0"}}, 0, false,
		func(string, string) error { return nil })
	if len(errs) != 0 {
		t.Fatalf("format-variant match must not fail the pass: %v", errs)
	}
	if _, err := os.Stat(matching); !os.IsNotExist(err) {
		t.Fatalf("hyphen/upper-case spelling of the NIC's own MAC must count as a match and be removed, stat err=%v", err)
	}
}

// Identity of the neutralizing NIC unreadable: ownership of a MAC-form file
// cannot be verified, so it must survive (preserve = defer to the file's own
// verified lifecycle) and the pass must surface the unverifiable claim.
func TestTargetChangeUnreadableIdentityPreserves12709(t *testing.T) {
	dir := withTempLinkDir(t)
	writeLink12709(t, dir, "ge-0-0-0", macForm12709("52:54:00:00:00:0b", "ge-0-0-0"))
	target := writeLink12709(t, dir, "fxp0", macForm12709("52:54:00:00:00:99", "fxp0"))
	stubIdentityByName12709(t, map[string]string{}) // every lookup fails

	_, errs := renamePositional([]pciNIC{{sortKey: 1, busAddr: "0000:05:00.0", name: "ge-0-0-0"}}, 0, false,
		func(string, string) error { return nil })
	if _, err := os.Stat(target); err != nil {
		t.Fatalf("unverifiable MAC-form link must survive (fail-closed on delete), stat err=%v", err)
	}
	if len(errs) == 0 {
		t.Fatal("an unverifiable claim left in place must surface an error, not pass silently")
	}
}

// A MAC-form file whose MACAddress= is malformed cannot be verified either:
// it must survive and surface an error.
func TestTargetChangeMalformedMACPreserves12709(t *testing.T) {
	dir := withTempLinkDir(t)
	writeLink12709(t, dir, "ge-0-0-0", macForm12709("52:54:00:00:00:0b", "ge-0-0-0"))
	target := writeLink12709(t, dir, "fxp0", macForm12709("not-a-mac", "fxp0"))
	stubIdentityByName12709(t, map[string]string{"ge-0-0-0": "52:54:00:00:00:0b"})

	_, errs := renamePositional([]pciNIC{{sortKey: 1, busAddr: "0000:05:00.0", name: "ge-0-0-0"}}, 0, false,
		func(string, string) error { return nil })
	if _, err := os.Stat(target); err != nil {
		t.Fatalf("malformed-MAC link must survive (cannot verify ownership), stat err=%v", err)
	}
	if len(errs) == 0 {
		t.Fatal("a malformed-MAC claim left in place must surface an error")
	}
}

// Missing files stay a no-op (the pre-existing neutralize contract), and a
// name-only link without any MACAddress= carries no MAC claim to verify:
// it is removed exactly as before.
func TestTargetChangeMissingAndNoMACUnchanged12709(t *testing.T) {
	dir := withTempLinkDir(t)
	// O.link: name-only, no MAC. T.link: absent entirely.
	writeLink12709(t, dir, "ge-0-0-0", "[Match]\nName=ge-0-0-0\n\n[Link]\nName=ge-0-0-0\n")
	stubIdentityByName12709(t, map[string]string{"ge-0-0-0": "52:54:00:00:00:0b"})

	_, errs := renamePositional([]pciNIC{{sortKey: 1, busAddr: "0000:05:00.0", name: "ge-0-0-0"}}, 0, false,
		func(string, string) error { return nil })
	if len(errs) != 0 {
		t.Fatalf("missing/no-MAC neutralize must stay error-free: %v", errs)
	}
	if _, err := os.Stat(filepath.Join(dir, linkPrefix+"ge-0-0-0.link")); !os.IsNotExist(err) {
		t.Fatalf("name-only link without MAC must still be removed, stat err=%v", err)
	}
}

// Temp-fail parity (master): the unknown NIC's temp rename FAILS, so it
// still wears ge-0-0-0 (another NIC's final). The known owner A rewrites its
// own ge-0-0-0.link after the neutralize; but the foreign fxp0.link whose
// MAC belongs to a third NIC must survive B's neutralize — previously the
// filename-only delete removed it even though A never rewrites fxp0.link.
func TestTargetChangeTempFailPreservesForeignTarget12709(t *testing.T) {
	dir := withTempLinkDir(t)
	// fxp0.link here is the FOREIGN MAC-form claim, not A's chain: A's chain
	// is filed under ge-0-0-0 (its final), fxp0.link carries V's MAC.
	foreign := writeLink12709(t, dir, "fxp0", macForm12709("52:54:00:00:00:99", "fxp0"))
	writeLink12709(t, dir, "ge-0-0-0", macForm12709("52:54:00:00:00:0b", "ge-0-0-0"))
	stubIdentityByName12709(t, map[string]string{"ge-0-0-0": "52:54:00:00:00:0b", "fxp0": "52:54:00:00:00:0c"})

	nics := []pciNIC{
		{sortKey: 1, busAddr: "0000:05:00.0", name: "ge-0-0-0"},
		{sortKey: 1, busAddr: "0000:06:00.0", name: "fxp0"},
	}
	_, errs := renamePositional(nics, 0, false, func(from, to string) error {
		if from == "ge-0-0-0" && strings.HasPrefix(to, "xpf-tmp-") {
			return errors.New("injected temp failure")
		}
		return nil
	})
	if len(errs) == 0 {
		t.Fatal("the stranded rename must report the #7205 unfreed error")
	}
	if _, err := os.Stat(foreign); err != nil {
		t.Fatalf("foreign MAC-form fxp0.link must survive the temp-fail neutralize, stat err=%v", err)
	}
}

// Bootstrap parity: the lifeline renames ge-0-0-0 -> fxp0 with an unknown
// original. A MAC-form fxp0.link belonging to another NIC must survive the
// bootstrap neutralize exactly as on the positional path.
func TestBootstrapTargetChangePreservesForeignMAC12709(t *testing.T) {
	st := staticLifelineSeams(t)
	detectLifelineInterfaceFn = func() (string, bool, error) { return "ge-0-0-0", true, nil }
	enumeratePCINICsFn = func() ([]pciNIC, error) {
		return []pciNIC{{sortKey: 0, busAddr: "0000:05:00.0", name: "ge-0-0-0"}}, nil
	}
	writeLink12709(t, st.linkDir, "ge-0-0-0", macForm12709("52:54:00:00:00:0b", "ge-0-0-0"))
	foreign := writeLink12709(t, st.linkDir, "fxp0", macForm12709("52:54:00:00:00:99", "fxp0"))
	stubIdentityByName12709(t, map[string]string{"ge-0-0-0": "52:54:00:00:00:0b"})
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
	if _, err := os.Stat(foreign); err != nil {
		t.Fatalf("bootstrap: foreign MAC-form fxp0.link must survive, stat err=%v", err)
	}
	if !*st.renamed {
		t.Error("the lifeline must still attempt the rename to fxp0")
	}
}

// Temp-OK snapshot pin (GLM R2 F2): U wears fxp0 via a MAC-form claim
// and targets ge-0-0-0, which the other NIC currently wears — so U is
// temp-renamed before the neutralize runs. The identity stub only knows
// PRE-temp names; a late lookup under the temp name errors. U's own
// claim (filed under fxp0) must still be removed via the phase-0
// snapshot — a late-lookup implementation preserves it and reports a
// spurious error.
func TestTargetChangeTempOKUsesPhase0Snapshot12709(t *testing.T) {
	dir := withTempLinkDir(t)
	own := writeLink12709(t, dir, "fxp0", macForm12709("52:54:00:00:00:0b", "fxp0"))
	writeLink12709(t, dir, "ge-0-0-0", macForm12709("52:54:00:00:00:0c", "ge-0-0-0"))
	// Identity follows the NIC across renames (as sysfs does): the stub
	// resolves only currently-worn names, so a late lookup by the
	// pre-temp name fails once phase 1 has moved the NIC.
	worn := map[string]string{"fxp0": "52:54:00:00:00:0b", "ge-0-0-0": "52:54:00:00:00:0c"}
	oldIdentity := nicIdentityMACFn
	nicIdentityMACFn = func(name string) (string, error) {
		if mac, ok := worn[name]; ok {
			return mac, nil
		}
		return "", errors.New("no interface wears " + name)
	}
	t.Cleanup(func() { nicIdentityMACFn = oldIdentity })

	// Index assigns targets: idx0 -> fxp0, idx1 -> ge-0-0-0. U (idx1)
	// wears fxp0 and targets the name idx0's NIC currently wears.
	nics := []pciNIC{
		{sortKey: 1, busAddr: "0000:05:00.0", name: "ge-0-0-0"},
		{sortKey: 1, busAddr: "0000:06:00.0", name: "fxp0"},
	}
	var renamed []string
	_, errs := renamePositional(nics, 0, false, func(from, to string) error {
		renamed = append(renamed, from+"->"+to)
		worn[to] = worn[from]
		delete(worn, from)
		return nil
	})
	t.Logf("renames: %v", renamed)
	if len(errs) != 0 {
		t.Fatalf("swap with snapshot identities must not error: %v", errs)
	}
	if _, err := os.Stat(own); !os.IsNotExist(err) {
		t.Fatalf("own MAC-form claim under pre-temp name must be removed via phase-0 snapshot, stat err=%v", err)
	}
}
