package daemon

import (
	"bytes"
	"errors"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vishvananda/netlink"
)

// #12156. recoverOriginalName previously returned currentName both when no
// .link existed and when a 10-xpf .link assigned Name=current without an
// OriginalName=. The latter is evidence that currentName is logical, not the
// kernel original, regardless of the next positional/bootstrap target. These
// regressions require the code to retain MAC-form links on the same-name path,
// neutralize the resurrectable O.link + stale T.link on a target change
// (MAJOR-1), avoid inventing an OriginalName, and still perform a required
// rename.

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

func captureLogs12156(t *testing.T) *bytes.Buffer {
	t.Helper()
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(previous) })
	return &logs
}

// TestRenamePositionalRetainsMACFormLink12156 drives the real positional pass
// with a NIC already wearing fxp0 and only a MAC-form .link on disk. The
// pass must leave that file alone — no OriginalName=fxp0 — while positional
// naming continues without refusing an already-named interface.
//
// FAIL-ON-REVERT: restoring the unconditional recoverOriginalName capture
// makes the pass overwrite the MAC-form file with OriginalName=fxp0.
func TestRenamePositionalRetainsMACFormLink12156(t *testing.T) {
	logs := captureLogs12156(t)
	stubIdentity12550(t, "52:54:00:12:34:56", nil)
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
	if got := logs.String(); !strings.Contains(got, "level=INFO") ||
		!strings.Contains(got, "existing MAC-form .link found") ||
		strings.Contains(got, "level=WARN") {
		t.Fatalf("a matching healthy MAC-form link must log at Info only, got:\n%s", got)
	}
}

func TestRenamePositionalWarnsWhenPersistenceIsAbsent12156(t *testing.T) {
	dir := withTempLinkDir(t)
	logs := captureLogs12156(t)
	_, errs := renamePositional(
		[]pciNIC{{sortKey: 1, busAddr: "0000:05:00.0", name: "fxp0"}},
		0, false, func(string, string) error { return nil },
	)
	if len(errs) != 0 {
		t.Fatalf("unknown original without a persistence file must not fail the pass: %v", errs)
	}
	if got := logs.String(); !strings.Contains(got, "level=WARN") ||
		!strings.Contains(got, "no usable .link exists") ||
		strings.Contains(got, "retaining the existing") {
		t.Fatalf("missing persistence must produce a warning, got logs:\n%s", got)
	}
	if _, err := os.Stat(filepath.Join(dir, linkPrefix+"fxp0.link")); !os.IsNotExist(err) {
		t.Fatalf("a missing original must not create a persistence file, stat err=%v", err)
	}
}

// TestRenamePositionalNeutralizesResurrectableLinksAfterShift12156 covers the
// lower-PCI insertion case: a MAC-form .link assigned the current logical name,
// but positional order now requires a different target. MAJOR-1: the NIC's own
// name-only O.link (MAC still matches it) plus any stale T.link would each
// resurrect a WRONG identity next boot — both are neutralized so the next boot
// falls back to kernel names (fail-closed), while the NIC still renames.
func TestRenamePositionalNeutralizesResurrectableLinksAfterShift12156(t *testing.T) {
	dir := withTempLinkDir(t)
	linkPath := filepath.Join(dir, linkPrefix+"ge-0-0-0.link")
	chained := `# Managed by xpfd — do not edit
[Match]
MACAddress=52:54:00:00:00:01

[Link]
Name=ge-0-0-0
`
	if err := os.WriteFile(linkPath, []byte(chained), 0644); err != nil {
		t.Fatalf("write MAC-form logical-name fixture: %v", err)
	}

	nics := []pciNIC{{sortKey: 1, busAddr: "0000:05:00.0", name: "ge-0-0-0"}}
	var renamed [][2]string
	changed, errs := renamePositional(nics, 0, false, func(from, to string) error {
		renamed = append(renamed, [2]string{from, to})
		return nil
	})
	if len(errs) != 0 {
		t.Fatalf("unknown original must not refuse the required rename: %v", errs)
	}
	if !changed || len(renamed) != 1 || renamed[0] != [2]string{"ge-0-0-0", "fxp0"} {
		t.Fatalf("shifted NIC must still rename to fxp0, changed=%v renames=%v", changed, renamed)
	}
	if _, err := os.Stat(linkPath); !os.IsNotExist(err) {
		t.Fatalf("the resurrectable O.link must be neutralized, stat err=%v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, linkPrefix+"fxp0.link")); !os.IsNotExist(err) {
		t.Fatalf("an unmatchable fxp0 .link must not be written, stat err=%v", err)
	}
}

// TestRenamePositionalCarriesUnknownOriginalAcrossCollision12156 verifies the
// phase-1 temp rename does not turn an unknown original into OriginalName=xpf-tmp-N.
// The existing MAC-form fxp0.link is necessarily replaced by the other NIC's
// new fxp0 assignment; the unknown NIC still must rename to ge-0-0-0 without
// writing a temp-name link.
func TestRenamePositionalCarriesUnknownOriginalAcrossCollision12156(t *testing.T) {
	dir := withTempLinkDir(t)
	macForm := `# Managed by xpfd — do not edit
[Match]
MACAddress=52:54:00:00:00:02

[Link]
Name=fxp0
`
	if err := os.WriteFile(filepath.Join(dir, linkPrefix+"fxp0.link"), []byte(macForm), 0644); err != nil {
		t.Fatalf("write colliding MAC-form fixture: %v", err)
	}

	nics := []pciNIC{
		{sortKey: 1, busAddr: "0000:05:00.0", name: "enp5s0"},
		{sortKey: 1, busAddr: "0000:06:00.0", name: "fxp0"},
	}
	var renamed [][2]string
	changed, errs := renamePositional(nics, 0, false, func(from, to string) error {
		renamed = append(renamed, [2]string{from, to})
		return nil
	})
	if len(errs) != 0 || !changed {
		t.Fatalf("collision pass must finish without errors, changed=%v errs=%v", changed, errs)
	}
	seen := make(map[string]bool, len(renamed))
	for _, pair := range renamed {
		seen[pair[0]+"->"+pair[1]] = true
	}
	for _, want := range []string{
		"fxp0->xpf-tmp-0",
		"enp5s0->fxp0",
		"xpf-tmp-0->ge-0-0-0",
	} {
		if !seen[want] {
			t.Errorf("collision-safe naming did not perform %s; renames=%v", want, renamed)
		}
	}
	if len(renamed) != 3 {
		t.Fatalf("unexpected extra or missing rename calls: %v", renamed)
	}
	fxp0, err := os.ReadFile(filepath.Join(dir, linkPrefix+"fxp0.link"))
	if err != nil || !strings.Contains(string(fxp0), "OriginalName=enp5s0") {
		t.Fatalf("fxp0 persistence must belong to the new index-0 NIC, got %q err=%v", fxp0, err)
	}
	if _, err := os.Stat(filepath.Join(dir, linkPrefix+"ge-0-0-0.link")); !os.IsNotExist(err) {
		t.Fatalf("the unknown-original NIC must not get a link with a temp name, stat err=%v", err)
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
	logs := captureLogs12156(t)
	stubIdentity12550(t, "52:54:00:12:34:56", nil)
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
	if got := logs.String(); !strings.Contains(got, "level=INFO") ||
		!strings.Contains(got, "bootstrap: existing MAC-form .link found") ||
		strings.Contains(got, "level=ERROR") {
		t.Fatalf("bootstrap MAC-form detection must log at Info without Error, got:\n%s", got)
	}
}

// TestBootstrapFactoryFallbackRetainsMACFormLink12156 covers the same guard
// when bootstrap selects the first NIC through the appliance factory fallback
// rather than a default route. Both selection sources converge on the same
// bootstrap .link write site, which must retain the MAC match.
func TestBootstrapFactoryFallbackRetainsMACFormLink12156(t *testing.T) {
	stubIdentity12550(t, "52:54:00:12:34:56", nil)
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

// TestBootstrapFirstRenameWritesKernelOriginal12156 is the bootstrap positive
// control: an index-0 lifeline still under its kernel name, with an empty link
// directory, must receive an fxp0 .link recording that kernel name.
func TestBootstrapFirstRenameWritesKernelOriginal12156(t *testing.T) {
	st := staticLifelineSeams(t)
	detectLifelineInterfaceFn = func() (string, bool, error) { return "enp5s0", true, nil }
	enumeratePCINICsFn = func() ([]pciNIC, error) {
		return []pciNIC{{sortKey: 0, busAddr: "0000:05:00.0", name: "enp5s0"}}, nil
	}
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
	data, err := os.ReadFile(filepath.Join(st.linkDir, linkPrefix+"fxp0.link"))
	if err != nil || !strings.Contains(string(data), "OriginalName=enp5s0") {
		t.Fatalf("bootstrap first rename must persist OriginalName=enp5s0, got %q err=%v", data, err)
	}
	if !*st.renamed || !*st.reloaded {
		t.Fatalf("bootstrap first rename must rename+reload: renamed=%v reloaded=%v", *st.renamed, *st.reloaded)
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
// kernel OriginalName= must rewrite a non-canonical chain to the canonical
// rendering. This distinguishes honoring the recorded original from skipping
// the write as though the original were unknown.
func TestRenamePositionalRecoversVerifiedOriginal12156(t *testing.T) {
	dir := withTempLinkDir(t)
	chained := "# Managed by xpfd — do not edit\n[Match]\nOriginalName=enp5s0\n\n[Link]\nName=fxp0\n"
	linkPath := filepath.Join(dir, linkPrefix+"fxp0.link")
	if err := os.WriteFile(linkPath, []byte(chained), 0644); err != nil {
		t.Fatalf("write non-canonical recorded-original fixture: %v", err)
	}

	nics := []pciNIC{{sortKey: 1, busAddr: "0000:05:00.0", name: "fxp0"}}
	changed, errs := renamePositional(nics, 0, false, func(from, to string) error {
		t.Fatalf("unexpected rename %s->%s", from, to)
		return nil
	})
	for _, err := range errs {
		t.Fatalf("the verified-original control must be error-free, got %v", err)
	}
	if !changed {
		t.Fatal("a non-canonical verified .link must be rewritten, not skipped")
	}
	const canonical = `# Managed by xpfd — do not edit
[Match]
OriginalName=enp5s0

[Link]
Name=fxp0`
	data, err := os.ReadFile(linkPath)
	if err != nil || string(data) != canonical {
		t.Fatalf("the verified .link must be normalized with the recorded original, got %q err=%v", data, err)
	}
}

// TestRenamePositionalUnknownTargetChangeLeavesNoResurrectableClaim12156 pins
// MAJOR-1: an unknown NIC renaming O→T must neutralize both its own name-only
// O.link and any stale T.link, so the next boot falls back to kernel names
// instead of resurrecting another NIC's identity. Reproduces the reviewer
// swap shape (pre-fold: both files retained → wrong identity next boot).
func TestRenamePositionalUnknownTargetChangeLeavesNoResurrectableClaim12156(t *testing.T) {
	logs := captureLogs12156(t)
	dir := withTempLinkDir(t)
	ownLink := `# Managed by xpfd — do not edit
[Match]
MACAddress=52:54:00:00:00:01

[Link]
Name=ge-0-0-0
`
	staleTarget := `# Managed by xpfd — do not edit
[Match]
OriginalName=enp9s0

[Link]
Name=fxp0
`
	if err := os.WriteFile(filepath.Join(dir, linkPrefix+"ge-0-0-0.link"), []byte(ownLink), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, linkPrefix+"fxp0.link"), []byte(staleTarget), 0644); err != nil {
		t.Fatal(err)
	}
	nics := []pciNIC{{sortKey: 1, busAddr: "0000:05:00.0", name: "ge-0-0-0"}}
	var renamed [][2]string
	changed, errs := renamePositional(nics, 0, false, func(from, to string) error {
		renamed = append(renamed, [2]string{from, to})
		return nil
	})
	if len(errs) != 0 {
		t.Fatalf("unknown original must not refuse the required rename: %v", errs)
	}
	if !changed || len(renamed) != 1 || renamed[0] != [2]string{"ge-0-0-0", "fxp0"} {
		t.Fatalf("NIC must still rename to fxp0, changed=%v renames=%v", changed, renamed)
	}
	// Both resurrectable claims are gone: neither file may re-apply next boot.
	for _, name := range []string{"ge-0-0-0", "fxp0"} {
		if _, err := os.Stat(filepath.Join(dir, linkPrefix+name+".link")); !os.IsNotExist(err) {
			t.Fatalf("resurrectable %s.link survived the unknown-target rename, stat err=%v", name, err)
		}
	}
	// The neutralize log LINE itself must carry level=ERROR (kills N7: a
	// split assertion is satisfied by the phase-0 F1 ERROR even when the
	// neutralize log is demoted). The phase-0 F1 line itself must also be
	// ERROR (kills N5).
	foundNeutralize, foundPhase0 := false, false
	for _, line := range strings.Split(logs.String(), "\n") {
		if strings.Contains(line, "level=ERROR") && strings.Contains(line, "neutralized retained .link claims") {
			foundNeutralize = true
		}
		if strings.Contains(line, "level=ERROR") && strings.Contains(line, "no persistence exists for the target") {
			foundPhase0 = true
		}
	}
	if !foundNeutralize {
		t.Fatalf("positional neutralize must log its own ERROR line, got:\n%s", logs.String())
	}
	if !foundPhase0 {
		t.Fatalf("phase-0 F1 skip must log its own ERROR line, got:\n%s", logs.String())
	}
}

// TestBootstrapLifelineNeutralizesResurrectableLinksOnRename12156 pins
// finding A: the bootstrap half of the MAJOR-1 neutralize. The B1 shape —
// the lifeline wears ge-0-0-0 via a MAC-form link while a stale fxp0.link
// (another NIC's claim) exists — must remove BOTH links, attempt the rename
// to fxp0, and log ERROR. Pre-fold this left the other NIC holding fxp0
// forever with no ERROR; a revert of the bootstrap branch must fail here.
func TestBootstrapLifelineNeutralizesResurrectableLinksOnRename12156(t *testing.T) {
	logs := captureLogs12156(t)
	st := staticLifelineSeams(t)
	// The lifeline is NOT fxp0 (it must rename), and it wears its name via
	// a MAC-form link (unknown original).
	detectLifelineInterfaceFn = func() (string, bool, error) { return "ge-0-0-0", true, nil }
	enumeratePCINICsFn = func() ([]pciNIC, error) {
		return []pciNIC{{sortKey: 0, busAddr: "0000:05:00.0", name: "ge-0-0-0"}}, nil
	}
	ownLink := filepath.Join(st.linkDir, linkPrefix+"ge-0-0-0.link")
	ownContent := strings.Replace(macFormFxp0Link12156, "Name=fxp0", "Name=ge-0-0-0", 1)
	if err := os.WriteFile(ownLink, []byte(ownContent), 0644); err != nil {
		t.Fatalf("write own MAC-form fixture: %v", err)
	}
	staleLink := filepath.Join(st.linkDir, linkPrefix+"fxp0.link")
	staleContent := strings.Replace(macFormFxp0Link12156, "52:54:00:12:34:56", "52:54:00:99:99:99", 1)
	if err := os.WriteFile(staleLink, []byte(staleContent), 0644); err != nil {
		t.Fatalf("write stale fxp0 fixture: %v", err)
	}
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
	if _, err := os.Stat(ownLink); !os.IsNotExist(err) {
		t.Fatalf("own MAC-form ge-0-0-0.link survived the unknown rename (stat err=%v)", err)
	}
	if _, err := os.Stat(staleLink); !os.IsNotExist(err) {
		t.Fatalf("stale fxp0.link survived the unknown rename (stat err=%v)", err)
	}
	if !*st.renamed {
		t.Error("the lifeline must still attempt the rename to fxp0 after neutralizing")
	}
	// The neutralize log LINE itself must carry level=ERROR: a split
	// assertion (level=ERROR somewhere + neutralize text somewhere) is
	// satisfied by logUnknownOriginalLinkSkip's own F1 ERROR even when the
	// neutralize log is demoted (N10/N5 survive). Match both on one line.
	found := false
	for _, line := range strings.Split(logs.String(), "\n") {
		if strings.Contains(line, "level=ERROR") && strings.Contains(line, "neutralized retained .link claims") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("bootstrap neutralize must log its own ERROR line, got:\n%s", logs.String())
	}
}

// TestRenamePositionalUnfreedKeepsOwnerChain12156 pins the unknowns-first
// ordering: an unknown NIC that failed ITS OWN temp rename still wears
// another NIC's final name. NIC B (unknown, MAC-form ge-0-0-0 claim) wants
// fxp0; NIC A (known enp5s0, chain fxp0.link, currently fxp0) wants
// ge-0-0-0. B's temp rename fails, so ge-0-0-0 (B's CURRENT name, A's
// final) is unfreed. B neutralizes BOTH its current and stale-final links;
// with the unknowns-first ordering, A rewrites ge-0-0-0.link with its
// verified chain AFTER every neutralize, so the chain survives in 200/200
// runs regardless of map order within each class (map-order loop without
// ordering loses it ~20/200; knowns-first loses 200/200 — either mutant
// FAILS this test). The pass still reports the #7205 unfreed error.
func TestRenamePositionalUnfreedKeepsOwnerChain12156(t *testing.T) {
	chain := "# Managed by xpfd \u2014 do not edit\n[Match]\nOriginalName=enp5s0\n\n[Link]\nName=fxp0"
	macForm := "# Managed by xpfd \u2014 do not edit\n[Match]\nMACAddress=52:54:00:00:00:0b\n\n[Link]\nName=ge-0-0-0\nMTUBytes=1500\n"
	for i := 0; i < 200; i++ {
		dir := withTempLinkDir(t)
		if err := os.WriteFile(filepath.Join(dir, linkPrefix+"fxp0.link"), []byte(chain), 0644); err != nil {
			t.Fatal(err)
		}
		ownerPath := filepath.Join(dir, linkPrefix+"ge-0-0-0.link")
		if err := os.WriteFile(ownerPath, []byte(macForm), 0644); err != nil {
			t.Fatal(err)
		}
		// Slice order: B (unknown, wears ge-0-0-0, wants fxp0) sorts
		// first; A (known enp5s0, wears fxp0, wants ge-0-0-0) second.
		// B's temp rename fails, so ge-0-0-0 is unfreed. B neutralizes
		// both links; unknowns-first ordering lets A rewrite its own
		// name with its chain after every neutralize.
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
		got, err := os.ReadFile(ownerPath)
		if err != nil {
			t.Fatalf("iter %d: owner's ge-0-0-0.link was neutralized: %v", i, err)
		}
		if !strings.Contains(string(got), "OriginalName=enp5s0") {
			t.Fatalf("iter %d: owner's link lacks the verified chain:\n%s", i, got)
		}
		// The stale T.link ALWAYS goes, even with an unfreed current.
		// Sparing it resurrects the occupant under the unknown NIC's
		// target (B-REG: 26 wrong boots in the temp-fail matrix).
		if _, err := os.Stat(filepath.Join(dir, linkPrefix+"fxp0.link")); !os.IsNotExist(err) {
			t.Fatalf("iter %d: stale fxp0.link survived (B-REG resurrection), stat err=%v", i, err)
		}
	}
}

// TestRenamePositionalUnfreedFinalStillNeutralizesTarget12156 pins the
// unfreed-final rule: U (unknown, wears ge-0-0-1 via MAC-form) wants fxp0;
// K (known enp6s0, wears fxp0 via chain) wants ge-0-0-0, but K's temp rename
// fails — so fxp0 (U's FINAL) is unfreed. K writes ge-0-0-0.link (its own
// final), never fxp0.link: nobody else touches the stale claim, and sparing
// it resurrects K under U's target (8 wrong boots + 6/6 reorder cases in
// the temp-fail matrix). fxp0.link MUST go.
func TestRenamePositionalUnfreedFinalStillNeutralizesTarget12156(t *testing.T) {
	macForm := "# Managed by xpfd \u2014 do not edit\n[Match]\nMACAddress=52:54:00:00:00:0b\n\n[Link]\nName=ge-0-0-1\nMTUBytes=1500\n"
	chain := "# Managed by xpfd \u2014 do not edit\n[Match]\nOriginalName=enp6s0\n\n[Link]\nName=fxp0"
	for i := 0; i < 200; i++ {
		dir := withTempLinkDir(t)
		if err := os.WriteFile(filepath.Join(dir, linkPrefix+"fxp0.link"), []byte(chain), 0644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, linkPrefix+"ge-0-0-1.link"), []byte(macForm), 0644); err != nil {
			t.Fatal(err)
		}
		nics := []pciNIC{
			{sortKey: 0, busAddr: "0000:04:00.0", name: "ge-0-0-1"},
			{sortKey: 1, busAddr: "0000:06:00.0", name: "fxp0"},
		}
		_, errs := renamePositional(nics, 0, false, func(from, to string) error {
			if from == "fxp0" && strings.HasPrefix(to, "xpf-tmp-") {
				return errors.New("injected temp failure")
			}
			return nil
		})
		if len(errs) == 0 {
			t.Fatal("the stranded rename must report the #7205 unfreed error")
		}
		if _, err := os.Stat(filepath.Join(dir, linkPrefix+"fxp0.link")); !os.IsNotExist(err) {
			t.Fatalf("iter %d: B-REG: unfreed-final fxp0.link (K's chain) survived, stat err=%v", i, err)
		}
	}
}

// TestRenamePositionalUnfreedOwnerWriteFailStaysFailClosed12156 pins the
// fail-closed property: same shape as the ordering test, but the owner chain
// carries a glob (OriginalName=enp5s0*) so A's rewrite is refused (#10089)
// AND B's temp rename fails. B's MAC-form claim is already deleted before
// A's write fails — both links absent, errs holds the refusal + the #7205
// error. Sparing the current link instead would leave B's claim behind
// (fail-open, 200/200 wrong next boot) — this test FAILS then.
func TestRenamePositionalUnfreedOwnerWriteFailStaysFailClosed12156(t *testing.T) {
	// A's recorded original carries a glob, so its rewrite is refused (#10089).
	chain := "# Managed by xpfd \u2014 do not edit\n[Match]\nOriginalName=enp5s0*\n\n[Link]\nName=fxp0"
	macForm := "# Managed by xpfd \u2014 do not edit\n[Match]\nMACAddress=52:54:00:00:00:0b\n\n[Link]\nName=ge-0-0-0\nMTUBytes=1500\n"
	for i := 0; i < 200; i++ {
		dir := withTempLinkDir(t)
		if err := os.WriteFile(filepath.Join(dir, linkPrefix+"fxp0.link"), []byte(chain), 0644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, linkPrefix+"ge-0-0-0.link"), []byte(macForm), 0644); err != nil {
			t.Fatal(err)
		}
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
		if len(errs) < 2 {
			t.Fatalf("iter %d: want the refused owner write AND the #7205 unfreed error, got %v", i, errs)
		}
		if _, err := os.Stat(filepath.Join(dir, linkPrefix+"ge-0-0-0.link")); !os.IsNotExist(err) {
			t.Fatalf("iter %d: B's MAC-form claim to A's target survived a refused owner write (fail-open), stat err=%v", i, err)
		}
		if _, err := os.Stat(filepath.Join(dir, linkPrefix+"fxp0.link")); !os.IsNotExist(err) {
			t.Fatalf("iter %d: stale fxp0.link survived, stat err=%v", i, err)
		}
	}
}
