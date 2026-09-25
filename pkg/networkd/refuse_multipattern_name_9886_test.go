package networkd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// stubNetworkctl9886 makes Apply hermetic: reload/reconfigure succeed without a
// real systemd. Refusal tests must not depend on the sandbox's networkctl.
// The rp_filter fixture + debt reset are load-bearing, not hygiene: a stubbed
// successful reload reaches restoreSlowPathRPFilter, which writes REAL
// /proc/sys/net/ipv4 sysctls unless procSysNetRoot is redirected, and the
// reload/tail debt is process-global across the package's tests.
func stubNetworkctl9886(t *testing.T) {
	t.Helper()
	resetReloadDebtForTest(t)
	rpFilterFixture(t)
	orig := runNetworkctl
	runNetworkctl = func(args ...string) error { return nil }
	t.Cleanup(func() { runNetworkctl = orig })
}

// #9886: Apply must refuse a name that is not render-safe — write NO file for
// it — while well-formed siblings are byte-identical to a clean run. Mirrors
// confine_name_9494_test.go. The refused fixtures cover all three generated
// suffixes (bond → .netdev, bridge → .netdev, MAC → .link, all → .network) so
// no absence assertion below is vacuous.
func TestApplyRefusesMultiPatternInterfaceName_9886(t *testing.T) {
	stubNetworkctl9886(t)
	dir := t.TempDir()
	m := &Manager{networkDir: dir}
	err := m.Apply([]InterfaceConfig{
		{Name: "fab0", MACAddress: "52:54:00:aa:bb:cc", Addresses: []string{"10.0.1.10/24"}},
		{Name: "ae1", IsBond: true, BondMode: "active-backup", Addresses: []string{"10.0.2.10/24"}},
		{Name: "ge 0", IsBond: true, BondMode: "active-backup", Addresses: []string{"10.0.0.1/24"}},
		{Name: "ge-0-0-0 eth0", IsBridge: true, Addresses: []string{"10.0.0.2/24"}},
		{Name: "ge\t0", MACAddress: "52:54:00:aa:bb:cd", Addresses: []string{"10.0.0.3/24"}},
	})
	if err == nil {
		t.Fatal("#9886: Apply must fail on multi-pattern interface names, got nil")
	}
	for _, want := range []string{"refusing interface name", "[Match] Name=", "#9886"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("#9886: Apply error must mention %q, got %v", want, err)
		}
	}

	// No file for any refused name, in any suffix.
	for _, name := range []string{"ge 0", "ge-0-0-0 eth0", "ge\t0"} {
		for _, suf := range []string{".link", ".network", ".netdev"} {
			if p := filepath.Join(dir, filePrefix+name+suf); fileExists9886(p) {
				t.Errorf("#9886: refused name %q must write no file, but %s exists", name, p)
			}
		}
	}

	// Control: the well-formed siblings are still written, byte-identical to a
	// clean run — including the bond's .netdev, which the refused bond's
	// absence assertion above is measured against.
	cleanDir := t.TempDir()
	_ = (&Manager{networkDir: cleanDir}).Apply([]InterfaceConfig{
		{Name: "fab0", MACAddress: "52:54:00:aa:bb:cc", Addresses: []string{"10.0.1.10/24"}},
		{Name: "ae1", IsBond: true, BondMode: "active-backup", Addresses: []string{"10.0.2.10/24"}},
	})
	for _, tc := range []struct{ name, suf string }{
		{"fab0", ".link"}, {"fab0", ".network"}, {"ae1", ".netdev"}, {"ae1", ".network"},
	} {
		got, rerr := os.ReadFile(filepath.Join(dir, filePrefix+tc.name+tc.suf))
		if rerr != nil {
			t.Fatalf("control %s%s missing beside the refused names: %v", tc.name, tc.suf, rerr)
		}
		want, rerr := os.ReadFile(filepath.Join(cleanDir, filePrefix+tc.name+tc.suf))
		if rerr != nil {
			t.Fatal(rerr)
		}
		if string(got) != string(want) {
			t.Fatalf("control %s%s differs from a clean run:\n got=%q\nwant=%q", tc.name, tc.suf, got, want)
		}
	}

	// A second identical Apply fails identically: the refusal is stateless, not
	// debt the first failure discharges.
	if err2 := m.Apply([]InterfaceConfig{
		{Name: "fab0", MACAddress: "52:54:00:aa:bb:cc", Addresses: []string{"10.0.1.10/24"}},
		{Name: "ge 0", MACAddress: "52:54:00:aa:bb:cd", Addresses: []string{"10.0.0.1/24"}},
	}); err2 == nil || !strings.Contains(err2.Error(), "#9886") {
		t.Fatalf("#9886: second identical Apply must fail identically, got %v", err2)
	}
}

// #9886: the refused name behaves like a DELETED interface — a poisoned unit a
// previous apply rendered is swept, not pinned in `expected`. This is the
// assertion that distinguishes the pre-expected placement from a write-loop
// refusal, which would keep the poison on disk forever.
func TestApplySweepsStalePoisonedUnitsForRefusedName_9886(t *testing.T) {
	stubNetworkctl9886(t)
	dir := t.TempDir()
	poisonLink := "[Match]\nMACAddress=52:54:00:aa:bb:cd\n\n[Link]\nName=ge 0\n"
	poisonNet := "[Match]\nName=ge 0\n"
	poisonNetdev := "[NetDev]\nName=ge 0\nKind=bond\n"
	if err := os.WriteFile(filepath.Join(dir, filePrefix+"ge 0.link"), []byte(poisonLink), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, filePrefix+"ge 0.network"), []byte(poisonNet), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, filePrefix+"ge 0.netdev"), []byte(poisonNetdev), 0o644); err != nil {
		t.Fatal(err)
	}
	m := &Manager{networkDir: dir}
	err := m.Apply([]InterfaceConfig{
		{Name: "fab0", MACAddress: "52:54:00:aa:bb:cc", Addresses: []string{"10.0.1.10/24"}},
		{Name: "ge 0", IsBond: true, BondMode: "active-backup", Addresses: []string{"10.0.0.1/24"}},
	})
	if err == nil || !strings.Contains(err.Error(), "#9886") {
		t.Fatalf("#9886: Apply must fail on the refused name, got %v", err)
	}
	for _, suf := range []string{".link", ".network", ".netdev"} {
		if p := filepath.Join(dir, filePrefix+"ge 0"+suf); fileExists9886(p) {
			t.Errorf("#9886: stale poisoned %s must be swept, but it survives", p)
		}
	}
	if p := filepath.Join(dir, filePrefix+"fab0.network"); !fileExists9886(p) {
		t.Errorf("#9886: the sweep must not take the well-formed sibling's files (%s missing)", p)
	}
}

// #9886: a name failing BOTH the one-pattern predicate and confinedInterfaceName
// (slash plus space) is refused exactly ONCE — at the pre-expected belt, never
// reaching #9494. Both messages share the "refusing interface name" stem, so a
// count of 1 proves exactly-once across both checks.
func TestApplyRefusesSlashPlusSpaceExactlyOnce_9886(t *testing.T) {
	stubNetworkctl9886(t)
	m := &Manager{networkDir: t.TempDir()}
	err := m.Apply([]InterfaceConfig{{Name: "a b/c", IsBond: true}})
	if err == nil {
		t.Fatal("#9886: Apply must fail on a slash-plus-space name, got nil")
	}
	if n := strings.Count(err.Error(), "refusing interface name"); n != 1 {
		t.Fatalf("#9886: want exactly 1 refusal for \"a b/c\", got %d in %v", n, err)
	}
	if !strings.Contains(err.Error(), "#9886") || strings.Contains(err.Error(), "#9494") {
		t.Fatalf("#9886: the refusal must be the #9886 belt, not #9494: %v", err)
	}
}

// #9886: skip-first ordering — an unmanaged interface with an external config is
// never rendered by xpf, so even a multi-pattern name there must not trip the
// belt. Silent skip, no error contribution.
func TestApplySkipsExternallyManagedMultiPatternName_9886(t *testing.T) {
	stubNetworkctl9886(t)
	dir := t.TempDir()
	external := "[Match]\nName=ge 0\n\n[Network]\nDHCP=yes\n"
	if err := os.WriteFile(filepath.Join(dir, "zz-external.network"), []byte(external), 0o644); err != nil {
		t.Fatal(err)
	}
	m := &Manager{networkDir: dir}
	if err := m.Apply([]InterfaceConfig{{Name: "ge 0", Unmanaged: true}}); err != nil {
		t.Fatalf("#9886: externally-managed skip must not trip the belt, got %v", err)
	}
	if got, _ := os.ReadFile(filepath.Join(dir, "zz-external.network")); string(got) != external {
		t.Fatalf("external file disturbed: got %q", got)
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), filePrefix) {
			t.Fatalf("#9886: skip must write no xpf files, found %s", e.Name())
		}
	}
}

// #9886: a refused name that is ALSO in the protected set keeps its files —
// lifeline wins over the sweep — while the refusal still fails the commit.
func TestApplyProtectedPlusPoisonedKeepsFilesAndFails_9886(t *testing.T) {
	stubNetworkctl9886(t)
	dir := t.TempDir()
	poisonNet := "[Match]\nName=ge 0\n"
	p := filepath.Join(dir, filePrefix+"ge 0.network")
	if err := os.WriteFile(p, []byte(poisonNet), 0o644); err != nil {
		t.Fatal(err)
	}
	m := &Manager{networkDir: dir}
	m.SetProtectedResolver(func() map[string]bool { return map[string]bool{"ge 0": true} })
	err := m.Apply([]InterfaceConfig{
		{Name: "ge 0", Addresses: []string{"10.0.0.1/24"}},
	})
	if err == nil || !strings.Contains(err.Error(), "#9886") {
		t.Fatalf("#9886: protected-plus-poisoned must still fail the commit, got %v", err)
	}
	if got, rerr := os.ReadFile(p); rerr != nil || string(got) != poisonNet {
		t.Fatalf("#9886: lifeline wins — the protected file must be preserved byte-identical, got %q, err %v", got, rerr)
	}
}

// #9886: empty is zero slots, not one — refused. (Previously the #9494 empty
// arm caught it in the write loop; the belt fires first now. Either way the
// name never renders.)
func TestApplyRefusesEmptyInterfaceName_9886(t *testing.T) {
	stubNetworkctl9886(t)
	m := &Manager{networkDir: t.TempDir()}
	err := m.Apply([]InterfaceConfig{{Name: ""}})
	if err == nil || !strings.Contains(err.Error(), "refusing interface name") {
		t.Fatalf("#9886: Apply must refuse an empty interface name, got %v", err)
	}
}

// #9886: control bytes that are NOT whitespace (\x01, DEL) are one pattern but
// still refused at render — what systemd makes of a raw control byte in a unit
// file is version-dependent and unanalyzed, so no file may carry one.
func TestApplyRefusesControlByteInterfaceName_9886(t *testing.T) {
	stubNetworkctl9886(t)
	dir := t.TempDir()
	m := &Manager{networkDir: dir}
	err := m.Apply([]InterfaceConfig{
		{Name: "ge\x010", MACAddress: "52:54:00:aa:bb:cc", Addresses: []string{"10.0.0.1/24"}},
		{Name: "ge\x7f0", Addresses: []string{"10.0.0.2/24"}},
	})
	if err == nil {
		t.Fatal("#9886: Apply must fail on control-byte interface names, got nil")
	}
	for _, want := range []string{"refusing interface name", "#9886"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("#9886: Apply error must mention %q, got %v", want, err)
		}
	}
	for _, name := range []string{"ge\x010", "ge\x7f0"} {
		for _, suf := range []string{".link", ".network"} {
			if p := filepath.Join(dir, filePrefix+name+suf); fileExists9886(p) {
				t.Errorf("#9886: refused name %q must write no file, but %s exists", name, p)
			}
		}
	}
}

// #9886: the .link's [Match] OriginalName= is itself a whitespace-separated
// match list, so a render-unsafe OriginalName is refused with the row — while
// a clean set-but-present OriginalName still renders (no over-refusal).
func TestApplyRefusesUnsafeOriginalName_9886(t *testing.T) {
	stubNetworkctl9886(t)
	dir := t.TempDir()
	m := &Manager{networkDir: dir}
	err := m.Apply([]InterfaceConfig{
		{Name: "ge-0-0-0", OriginalName: "enp 0s0", MACAddress: "52:54:00:aa:bb:cc"},
		{Name: "ge-0-0-1", OriginalName: "enp\x010s0"},
		{Name: "ge-0-0-3", OriginalName: "enp0s3\\", MACAddress: "52:54:00:aa:bb:ce"},
		{Name: "ge-0-0-2", OriginalName: "enp0s2", MACAddress: "52:54:00:aa:bb:cd"},
	})
	if err == nil {
		t.Fatal("#9886: Apply must fail on render-unsafe OriginalName values, got nil")
	}
	for _, want := range []string{"refusing OriginalName", "[Match] OriginalName=", "#9886"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("#9886: Apply error must mention %q, got %v", want, err)
		}
	}
	for _, name := range []string{"ge-0-0-0", "ge-0-0-1", "ge-0-0-3"} {
		for _, suf := range []string{".link", ".network"} {
			if p := filepath.Join(dir, filePrefix+name+suf); fileExists9886(p) {
				t.Errorf("#9886/#10718: refused row %q must write no file, but %s exists", name, p)
			}
		}
	}
	got, rerr := os.ReadFile(filepath.Join(dir, filePrefix+"ge-0-0-2.link"))
	if rerr != nil {
		t.Fatalf("clean OriginalName row must still render its .link: %v", rerr)
	}
	if !strings.Contains(string(got), "OriginalName=enp0s2") {
		t.Fatalf("clean .link must carry OriginalName=enp0s2, got:\n%s", got)
	}
}

// TestApplyRefusesAndSweepsLineContinuationInterfaceName_10718 covers the
// existing Name= belt's systemd.syntax(7) continuation boundary. The seeded
// file models a pre-belt apply; refusal must sweep it before it remains loaded.
func TestApplyRefusesAndSweepsLineContinuationInterfaceName_10718(t *testing.T) {
	stubNetworkctl9886(t)
	dir := t.TempDir()
	name := "ge-0-0-0\\"
	poisonPath := filepath.Join(dir, filePrefix+name+".network")
	if err := os.WriteFile(poisonPath, []byte("[Match]\nName="+name+"\n[Network]\n"), 0600); err != nil {
		t.Fatal(err)
	}

	err := NewInDir(dir).Apply([]InterfaceConfig{{Name: name}})
	if err == nil || !strings.Contains(err.Error(), "#10718") || !strings.Contains(err.Error(), "line continuation") {
		t.Fatalf("Apply must refuse a Name= line continuation, got %v", err)
	}
	if fileExists9886(poisonPath) {
		t.Fatalf("refused trailing-backslash interface kept its poisoned unit: %s", poisonPath)
	}
}

func fileExists9886(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// TestApplyRefusesUnsafeUnitFieldsAndSweeps_10718 drives every generated
// single-token field through Apply, the renderer boundary tolerant load,
// peer-sync and rollback paths share. Each row first writes a clean unit, then
// presents one poisoned field; refusal must fail Apply and sweep every prior
// unit for that interface while leaving an unrelated managed interface intact.
//
// FAIL-ON-REVERT: remove the #10718 field check and its row is accepted, the
// poisoned field is written, and its previous unit is not swept.
func TestApplyRefusesUnsafeUnitFieldsAndSweeps_10718(t *testing.T) {
	for _, tc := range []struct {
		name       string
		field      string
		base       InterfaceConfig
		poison     func(*InterfaceConfig)
		beforeWant string
	}{
		{
			name: "VRF", field: "VRF",
			base: InterfaceConfig{Name: "ge-0-0-0", MACAddress: "52:54:00:aa:bb:cc",
				Addresses: []string{"10.0.0.1/24"}, VRFName: "vrf-mgmt"},
			poison: func(ifc *InterfaceConfig) { ifc.VRFName = "vrf-mgmt\nDHCP=yes" },
		},
		{
			name: "Bond", field: "Bond",
			base: InterfaceConfig{Name: "ge-0-0-0", MACAddress: "52:54:00:aa:bb:cc",
				Addresses: []string{"10.0.0.1/24"}, BondMaster: "ae0"},
			poison: func(ifc *InterfaceConfig) { ifc.BondMaster = "ae0 member" },
		},
		{
			name: "Bridge", field: "Bridge",
			base: InterfaceConfig{Name: "ge-0-0-0", MACAddress: "52:54:00:aa:bb:cc",
				Addresses: []string{"10.0.0.1/24"}, BridgeMaster: "br0"},
			poison: func(ifc *InterfaceConfig) { ifc.BridgeMaster = "br0\x01" },
		},
		{
			name: "BridgeBackslashContinuation", field: "Bridge",
			base: InterfaceConfig{Name: "ge-0-0-0", MACAddress: "52:54:00:aa:bb:cc",
				Addresses: []string{"10.0.0.1/24"}, BridgeMaster: "br0", DADDisable: true},
			poison:     func(ifc *InterfaceConfig) { ifc.BridgeMaster = "br0\\" },
			beforeWant: "Bridge=br0\nIPv6DuplicateAddressDetection=0\n",
		},
		{
			name: "Duplex", field: "Duplex",
			base: InterfaceConfig{Name: "ge-0-0-0", MACAddress: "52:54:00:aa:bb:cc",
				Addresses: []string{"10.0.0.1/24"}, Duplex: "full"},
			poison: func(ifc *InterfaceConfig) { ifc.Duplex = "full\nDHCP=yes" },
		},
		{
			name: "MACAddress", field: "MACAddress",
			base: InterfaceConfig{Name: "ge-0-0-0", MACAddress: "52:54:00:aa:bb:cc",
				Addresses: []string{"10.0.0.1/24"}},
			poison: func(ifc *InterfaceConfig) { ifc.MACAddress = "52:54:00:aa:bb:cc forged" },
		},
		{
			name: "Address", field: "Address",
			base: InterfaceConfig{Name: "ge-0-0-0", MACAddress: "52:54:00:aa:bb:cc",
				Addresses: []string{"10.0.0.1/24"}},
			poison: func(ifc *InterfaceConfig) { ifc.Addresses = []string{"10.0.0.1/24\nDHCP=yes"} },
		},
		{
			name: "VLANParentAddress", field: "Address",
			base: InterfaceConfig{Name: "ge-0-0-0", IsVLANParent: true,
				VLANParentAddresses: []string{"169.254.1.1/32"}},
			poison: func(ifc *InterfaceConfig) { ifc.VLANParentAddresses = []string{"169.254.1.1/32\nDHCP=yes"} },
		},
		{
			name: "Mode", field: "Mode",
			base: InterfaceConfig{Name: "bond0", IsBond: true, BondMode: "active-backup"},
			poison: func(ifc *InterfaceConfig) { ifc.BondMode = "active-backup\nDHCP=yes" },
		},
		{
			name: "ModeOnDisabledBond", field: "Mode",
			base: InterfaceConfig{Name: "bond0", IsBond: true, Disable: true, BondMode: "active-backup"},
			poison: func(ifc *InterfaceConfig) { ifc.BondMode = "active-backup\nDHCP=yes" },
		},
		{
			name: "LACPTransmitRate", field: "LACPTransmitRate",
			base: InterfaceConfig{Name: "bond0", IsBond: true, BondMode: "802.3ad", LACPRate: "fast"},
			poison: func(ifc *InterfaceConfig) { ifc.LACPRate = "fast\nDHCP=yes" },
		},
		{
			name: "BitsPerSecond", field: "BitsPerSecond",
			base: InterfaceConfig{Name: "ge-0-0-0", MACAddress: "52:54:00:aa:bb:cc",
				Addresses: []string{"10.0.0.1/24"}, Speed: "1g"},
			poison: func(ifc *InterfaceConfig) { ifc.Speed = "1g 999999999999" },
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stubNetworkctl9886(t)
			dir := t.TempDir()
			m := NewInDir(dir)
			good := InterfaceConfig{Name: "good0", Addresses: []string{"192.0.2.1/24"}}
			if err := m.Apply([]InterfaceConfig{tc.base, good}); err != nil {
				t.Fatalf("clean control Apply failed: %v", err)
			}

			suffixes := []string{".network"}
			if tc.base.MACAddress != "" && !tc.base.Unmanaged {
				suffixes = append(suffixes, ".link")
			}
			if tc.base.IsBond || tc.base.IsBridge {
				suffixes = append(suffixes, ".netdev")
			}
			for _, suffix := range suffixes {
				path := filepath.Join(dir, filePrefix+tc.base.Name+suffix)
				if !fileExists9886(path) {
					t.Fatalf("clean control %s is missing; refusal assertion would be vacuous", path)
				}
			}
			if tc.beforeWant != "" {
				raw, err := os.ReadFile(filepath.Join(dir, filePrefix+tc.base.Name+".network"))
				if err != nil {
					t.Fatalf("clean control .network is missing: %v", err)
				}
				if !strings.Contains(string(raw), tc.beforeWant) {
					t.Fatalf("clean control lacks continuation target %q:\n%s", tc.beforeWant, raw)
				}
			}

			poisoned := tc.base
			tc.poison(&poisoned)
			err := m.Apply([]InterfaceConfig{poisoned, good})
			if err == nil || !strings.Contains(err.Error(), "#10718") || !strings.Contains(err.Error(), tc.field) {
				t.Fatalf("Apply must refuse poisoned %s= and name the field, got %v", tc.field, err)
			}
			for _, suffix := range suffixes {
				path := filepath.Join(dir, filePrefix+tc.base.Name+suffix)
				if fileExists9886(path) {
					t.Errorf("refused %s= left its previous unit on disk: %s", tc.field, path)
				}
			}
			goodPath := filepath.Join(dir, filePrefix+"good0.network")
			if !fileExists9886(goodPath) {
				t.Errorf("refusing %s= swept unrelated good interface unit %s", tc.field, goodPath)
			}
			if raw, err := os.ReadFile(goodPath); err != nil || !strings.Contains(string(raw), "Address=192.0.2.1/24\n") {
				t.Errorf("unrelated good interface was not preserved: read err=%v content=%q", err, raw)
			}
		})
	}
}

// TestApplySkipsDHCPOwnedUnsafeAddress_10718 pins the generator/token-guard
// agreement: an address owned by that family's DHCP client is not emitted and
// must not cause a refusal, while the opposite family's static address remains.
//
// FAIL-ON-REVERT: removing the per-family skip from renderedUnitTokenError
// refuses the poisoned DHCP-owned address and sweeps the still-valid unit.
func TestApplySkipsDHCPOwnedUnsafeAddress_10718(t *testing.T) {
	for _, tc := range []struct {
		name       string
		seed       InterfaceConfig
		poisoned   InterfaceConfig
		staticWant string
	}{
		{
			name: "DHCPv4",
			seed: InterfaceConfig{Name: "dhcp4", DHCPv4: true, Addresses: []string{"2001:db8::1/64"}},
			poisoned: InterfaceConfig{Name: "dhcp4", DHCPv4: true,
				Addresses: []string{"10.0.0.1/24\nDHCP=yes", "2001:db8::1/64"}},
			staticWant: "Address=2001:db8::1/64\n",
		},
		{
			name: "DHCPv6",
			seed: InterfaceConfig{Name: "dhcp6", DHCPv6: true, Addresses: []string{"192.0.2.1/24"}},
			poisoned: InterfaceConfig{Name: "dhcp6", DHCPv6: true,
				Addresses: []string{"192.0.2.1/24", "2001:db8::1/64\nDHCP=yes"}},
			staticWant: "Address=192.0.2.1/24\n",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stubNetworkctl9886(t)
			dir := t.TempDir()
			m := NewInDir(dir)
			path := filepath.Join(dir, filePrefix+tc.seed.Name+".network")
			if err := m.Apply([]InterfaceConfig{tc.seed}); err != nil {
				t.Fatalf("clean seed Apply failed: %v", err)
			}
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("clean seed unit missing: %v", err)
			}

			if err := m.Apply([]InterfaceConfig{tc.poisoned}); err != nil {
				t.Fatalf("Apply refused an address suppressed by its DHCP family: %v", err)
			}
			after, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("DHCP-owned address caused the valid unit to be swept: %v", err)
			}
			if string(after) != string(before) {
				t.Fatalf("a DHCP-owned address changed the rendered unit:\n before:\n%s\n after:\n%s", before, after)
			}
			if !strings.Contains(string(after), tc.staticWant) {
				t.Fatalf("opposite-family static address was lost:\n%s", after)
			}
			if strings.Contains(string(after), "DHCP=yes") {
				t.Fatalf("poisoned DHCP-owned address reached the unit:\n%s", after)
			}
		})
	}
}
