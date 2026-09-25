package networkd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenerateLink(t *testing.T) {
	m := New()
	ifc := InterfaceConfig{
		Name:       "trust0",
		MACAddress: "52:54:00:aa:bb:cc",
	}
	got := m.generateLink(ifc)
	if !strings.Contains(got, "[Match]\n") {
		t.Error("missing [Match] section")
	}
	if !strings.Contains(got, "MACAddress=52:54:00:aa:bb:cc\n") {
		t.Error("missing MACAddress")
	}
	if !strings.Contains(got, "[Link]\n") {
		t.Error("missing [Link] section")
	}
	if !strings.Contains(got, "Name=trust0\n") {
		t.Error("missing Name")
	}
}

func TestGenerateNetwork_Static(t *testing.T) {
	m := New()
	ifc := InterfaceConfig{
		Name:      "trust0",
		Addresses: []string{"10.0.1.10/24", "2001:db8::1/64"},
	}
	got := m.generateNetwork(ifc)
	if !strings.Contains(got, "Name=trust0\n") {
		t.Error("missing Name")
	}
	if !strings.Contains(got, "IPv6AcceptRA=no\n") {
		t.Error("missing RA disable")
	}
	if !strings.Contains(got, "LinkLocalAddressing=ipv6\n") {
		t.Error("missing LinkLocalAddressing")
	}
	if !strings.Contains(got, "Address=10.0.1.10/24\n") {
		t.Error("missing IPv4 address")
	}
	if !strings.Contains(got, "Address=2001:db8::1/64\n") {
		t.Error("missing IPv6 address")
	}
}

func TestGenerateNetwork_Unmanaged(t *testing.T) {
	m := New()
	ifc := InterfaceConfig{
		Name:      "unused0",
		Unmanaged: true,
	}
	got := m.generateNetwork(ifc)
	if !strings.Contains(got, "ActivationPolicy=always-down\n") {
		t.Error("missing ActivationPolicy=always-down")
	}
	if !strings.Contains(got, "RequiredForOnline=no\n") {
		t.Error("missing RequiredForOnline=no")
	}
	if !strings.Contains(got, "DHCP=no\n") {
		t.Error("missing DHCP=no")
	}
	if !strings.Contains(got, "LinkLocalAddressing=no\n") {
		t.Error("missing LinkLocalAddressing=no for unmanaged")
	}
	// Should NOT have any Address= lines
	if strings.Contains(got, "Address=") {
		t.Error("unmanaged interface should not have addresses")
	}
}

func TestGenerateNetwork_VLANParent(t *testing.T) {
	m := New()
	ifc := InterfaceConfig{
		Name:         "wan0",
		IsVLANParent: true,
		Addresses:    []string{"172.16.50.5/24"}, // should be ignored
	}
	got := m.generateNetwork(ifc)
	if !strings.Contains(got, "RequiredForOnline=no\n") {
		t.Error("missing RequiredForOnline=no for VLAN parent")
	}
	if !strings.Contains(got, "DHCP=no\n") {
		t.Error("missing DHCP=no for VLAN parent")
	}
	if strings.Contains(got, "Address=") {
		t.Error("VLAN parent should not have addresses (they go on sub-interface)")
	}
}

func TestGenerateNetwork_DHCP(t *testing.T) {
	m := New()
	ifc := InterfaceConfig{
		Name:   "mgmt0",
		DHCPv4: true,
	}
	got := m.generateNetwork(ifc)
	// DHCP interfaces should NOT have static Address= lines
	if strings.Contains(got, "Address=") {
		t.Error("DHCP interface should not have static addresses")
	}
	// But should still have link-local and RA settings
	if !strings.Contains(got, "IPv6AcceptRA=no\n") {
		t.Error("missing RA disable for DHCP interface")
	}
	if !strings.Contains(got, "LinkLocalAddressing=ipv6\n") {
		t.Error("missing LinkLocalAddressing for DHCP interface")
	}
}

func TestFindExternallyManaged(t *testing.T) {
	dir := t.TempDir()

	// Write a non-xpf .network file
	external := "[Match]\nName=eth0\n\n[Network]\nDHCP=yes\n"
	os.WriteFile(filepath.Join(dir, "50-mgmt.network"), []byte(external), 0644)

	// Write a xpf-managed .network file (should be ignored)
	xpf := "[Match]\nName=trust0\n\n[Network]\nAddress=10.0.1.10/24\n"
	os.WriteFile(filepath.Join(dir, filePrefix+"trust0.network"), []byte(xpf), 0644)

	// Write a .link file (not .network, should be ignored)
	os.WriteFile(filepath.Join(dir, "99-custom.link"), []byte("[Match]\nName=foo\n"), 0644)

	result := FindExternallyManaged(dir)
	if !result["eth0"] {
		t.Error("eth0 should be externally managed")
	}
	if result["trust0"] {
		t.Error("trust0 should not be externally managed (has xpf prefix)")
	}
	if result["foo"] {
		t.Error("foo should not match (was .link, not .network)")
	}
}

func TestWriteIfChanged(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.network")

	// First write — should return changed=true, no error
	if ch, err := writeIfChanged(path, "content1"); !ch || err != nil {
		t.Errorf("first write: got changed=%v err=%v, want true/nil", ch, err)
	}
	data, _ := os.ReadFile(path)
	if string(data) != "content1" {
		t.Errorf("got %q, want %q", string(data), "content1")
	}

	// Same content — should return changed=false, no error
	if ch, err := writeIfChanged(path, "content1"); ch || err != nil {
		t.Errorf("same content: got changed=%v err=%v, want false/nil", ch, err)
	}

	// Different content — should return changed=true, no error
	if ch, err := writeIfChanged(path, "content2"); !ch || err != nil {
		t.Errorf("different content: got changed=%v err=%v, want true/nil", ch, err)
	}
	data, _ = os.ReadFile(path)
	if string(data) != "content2" {
		t.Errorf("got %q, want %q", string(data), "content2")
	}
}

func TestGenerateLink_MTU(t *testing.T) {
	m := New()
	ifc := InterfaceConfig{
		Name:       "trust0",
		MACAddress: "52:54:00:aa:bb:cc",
		MTU:        1400,
	}
	got := m.generateLink(ifc)
	if !strings.Contains(got, "MTUBytes=1400\n") {
		t.Error("missing MTUBytes=1400 in .link file")
	}

	// MTU=0 should not produce MTUBytes
	ifc.MTU = 0
	got = m.generateLink(ifc)
	if strings.Contains(got, "MTUBytes") {
		t.Error("MTU=0 should not produce MTUBytes line")
	}
}

func TestGenerateNetwork_PrimaryAddress(t *testing.T) {
	m := New()
	ifc := InterfaceConfig{
		Name:           "trust0",
		Addresses:      []string{"10.0.1.10/24", "10.0.1.20/24", "10.0.1.30/24"},
		PrimaryAddress: "10.0.1.20/24",
	}
	got := m.generateNetwork(ifc)
	// Primary address should appear first
	idx1 := strings.Index(got, "Address=10.0.1.20/24")
	idx2 := strings.Index(got, "Address=10.0.1.10/24")
	idx3 := strings.Index(got, "Address=10.0.1.30/24")
	if idx1 < 0 || idx2 < 0 || idx3 < 0 {
		t.Fatalf("missing addresses in output:\n%s", got)
	}
	if idx1 > idx2 || idx1 > idx3 {
		t.Errorf("primary address should be first, got:\n%s", got)
	}
}

func TestGenerateNetwork_PreferredAddress(t *testing.T) {
	m := New()
	ifc := InterfaceConfig{
		Name:             "trust0",
		Addresses:        []string{"10.0.1.10/24", "10.0.1.20/24"},
		PreferredAddress: "10.0.1.20/24",
	}
	got := m.generateNetwork(ifc)
	// Should use [Address] sections
	if !strings.Contains(got, "[Address]\n") {
		t.Fatalf("expected [Address] sections, got:\n%s", got)
	}
	// Preferred address should have PreferredLifetime=forever
	if !strings.Contains(got, "Address=10.0.1.20/24\nPreferredLifetime=forever\n") {
		t.Errorf("preferred address should have PreferredLifetime=forever, got:\n%s", got)
	}
	// Non-preferred address should NOT have PreferredLifetime
	// Find the [Address] section for 10.0.1.10
	sections := strings.Split(got, "[Address]\n")
	for _, sec := range sections {
		if strings.HasPrefix(sec, "Address=10.0.1.10/24\n") {
			if strings.Contains(sec, "PreferredLifetime") {
				t.Errorf("non-preferred address should not have PreferredLifetime")
			}
		}
	}
}

func TestGenerateNetwork_PrimaryAndPreferred(t *testing.T) {
	m := New()
	ifc := InterfaceConfig{
		Name:             "trust0",
		Addresses:        []string{"10.0.1.10/24", "10.0.1.20/24", "2001:db8::1/64"},
		PrimaryAddress:   "10.0.1.20/24",
		PreferredAddress: "10.0.1.20/24",
	}
	got := m.generateNetwork(ifc)
	// Primary should be first [Address] section
	sections := strings.Split(got, "[Address]\n")
	if len(sections) < 2 {
		t.Fatalf("expected [Address] sections, got:\n%s", got)
	}
	// First [Address] section should be the primary+preferred
	if !strings.HasPrefix(sections[1], "Address=10.0.1.20/24\nPreferredLifetime=forever\n") {
		t.Errorf("first address section should be primary+preferred, got:\n%s", got)
	}
}

func TestOrderAddresses(t *testing.T) {
	addrs := []string{"10.0.1.10/24", "10.0.1.20/24", "10.0.1.30/24"}

	// Primary reorders
	got := orderAddresses(addrs, "10.0.1.20/24")
	if got[0] != "10.0.1.20/24" {
		t.Errorf("expected primary first, got %v", got)
	}
	if len(got) != 3 {
		t.Errorf("expected 3 addresses, got %d", len(got))
	}

	// No primary = no change
	got = orderAddresses(addrs, "")
	if got[0] != "10.0.1.10/24" {
		t.Errorf("expected original order, got %v", got)
	}

	// Primary not in list = no change
	got = orderAddresses(addrs, "192.168.1.1/24")
	if got[0] != "10.0.1.10/24" {
		t.Errorf("expected original order for missing primary, got %v", got)
	}
}

func TestGenerateNetdev_Bond(t *testing.T) {
	m := New()
	ifc := InterfaceConfig{
		Name:        "ae0",
		IsBond:      true,
		BondMode:    "802.3ad",
		LACPRate:    "fast",
		MinLinks:    2,
		Description: "LAG to switch",
		MTU:         9000,
	}
	got := m.generateNetdev(ifc)
	if !strings.Contains(got, "[NetDev]\n") {
		t.Error("missing [NetDev] section")
	}
	if !strings.Contains(got, "Name=ae0\n") {
		t.Error("missing Name=ae0")
	}
	if !strings.Contains(got, "Kind=bond\n") {
		t.Error("missing Kind=bond")
	}
	if !strings.Contains(got, "Description=LAG to switch\n") {
		t.Error("missing Description")
	}
	if !strings.Contains(got, "MTUBytes=9000\n") {
		t.Error("missing MTUBytes")
	}
	if !strings.Contains(got, "[Bond]\n") {
		t.Error("missing [Bond] section")
	}
	if !strings.Contains(got, "Mode=802.3ad\n") {
		t.Error("missing Mode=802.3ad")
	}
	if !strings.Contains(got, "LACPTransmitRate=fast\n") {
		t.Error("missing LACPTransmitRate=fast")
	}
	if !strings.Contains(got, "MinLinks=2\n") {
		t.Error("missing MinLinks=2")
	}
	if !strings.Contains(got, "TransmitHashPolicy=layer3+4\n") {
		t.Error("missing TransmitHashPolicy")
	}
}

func TestGenerateNetdev_BondDefaults(t *testing.T) {
	m := New()
	ifc := InterfaceConfig{
		Name:   "ae0",
		IsBond: true,
	}
	got := m.generateNetdev(ifc)
	// Default mode should be 802.3ad
	if !strings.Contains(got, "Mode=802.3ad\n") {
		t.Error("default mode should be 802.3ad")
	}
	// Default LACP rate should be fast
	if !strings.Contains(got, "LACPTransmitRate=fast\n") {
		t.Error("default LACP rate should be fast")
	}
	// No MinLinks when 0
	if strings.Contains(got, "MinLinks=") {
		t.Error("MinLinks=0 should not produce MinLinks line")
	}
	// No Description when empty
	if strings.Contains(got, "Description=") {
		t.Error("empty description should not produce Description line")
	}
	// No MTUBytes when 0
	if strings.Contains(got, "MTUBytes=") {
		t.Error("MTU=0 should not produce MTUBytes line")
	}
}

func TestGenerateNetwork_BondMember(t *testing.T) {
	m := New()
	ifc := InterfaceConfig{
		Name:       "ge-0/0/0",
		BondMaster: "ae0",
	}
	got := m.generateNetwork(ifc)
	if !strings.Contains(got, "Bond=ae0\n") {
		t.Errorf("missing Bond=ae0 in output:\n%s", got)
	}
	// Bond member should still have basic network settings
	if !strings.Contains(got, "IPv6AcceptRA=no\n") {
		t.Error("missing RA disable for bond member")
	}
}

func TestFabricBondNetdev(t *testing.T) {
	m := New()
	ifc := InterfaceConfig{
		Name:        "fab0",
		IsBond:      true,
		BondMode:    "active-backup",
		Description: "Fabric HA link",
		MTU:         9000,
	}
	got := m.generateNetdev(ifc)
	if !strings.Contains(got, "Name=fab0\n") {
		t.Error("missing Name=fab0")
	}
	if !strings.Contains(got, "Kind=bond\n") {
		t.Error("missing Kind=bond")
	}
	if !strings.Contains(got, "Mode=active-backup\n") {
		t.Error("missing Mode=active-backup")
	}
	if !strings.Contains(got, "MIIMonitorSec=100ms\n") {
		t.Error("missing MIIMonitorSec=100ms for active-backup mode")
	}
	if !strings.Contains(got, "Description=Fabric HA link\n") {
		t.Error("missing Description")
	}
	if !strings.Contains(got, "MTUBytes=9000\n") {
		t.Error("missing MTUBytes")
	}
	// Active-backup should NOT have LACP settings
	if strings.Contains(got, "LACPTransmitRate") {
		t.Error("active-backup should not have LACPTransmitRate")
	}
	if strings.Contains(got, "TransmitHashPolicy") {
		t.Error("active-backup should not have TransmitHashPolicy")
	}
}

func TestFabricBondMembers(t *testing.T) {
	m := New()

	// Member interface should reference bond master
	member := InterfaceConfig{
		Name:       "enp6s0",
		MACAddress: "52:54:00:fa:b0:01",
		BondMaster: "fab0",
	}
	got := m.generateNetwork(member)
	if !strings.Contains(got, "Bond=fab0\n") {
		t.Errorf("missing Bond=fab0 in member .network:\n%s", got)
	}
	// Member should still have basic settings
	if !strings.Contains(got, "IPv6AcceptRA=no\n") {
		t.Error("missing RA disable for fabric member")
	}
	if !strings.Contains(got, "LinkLocalAddressing=ipv6\n") {
		t.Error("missing LinkLocalAddressing for fabric member")
	}

	// Member .link should rename by MAC
	link := m.generateLink(member)
	if !strings.Contains(link, "MACAddress=52:54:00:fa:b0:01\n") {
		t.Errorf("missing MAC in member .link:\n%s", link)
	}
	if !strings.Contains(link, "Name=enp6s0\n") {
		t.Errorf("missing Name in member .link:\n%s", link)
	}
}

func TestFabricBondNetworkAddresses(t *testing.T) {
	m := New()
	// Bond device itself should get fabric addresses
	bond := InterfaceConfig{
		Name:      "fab0",
		IsBond:    true,
		BondMode:  "active-backup",
		Addresses: []string{"10.99.1.1/30"},
		VRFName:   "vrf-mgmt",
	}
	got := m.generateNetwork(bond)
	if !strings.Contains(got, "Address=10.99.1.1/30\n") {
		t.Errorf("missing fabric address in bond .network:\n%s", got)
	}
	if !strings.Contains(got, "VRF=vrf-mgmt\n") {
		t.Errorf("missing VRF=vrf-mgmt in bond .network:\n%s", got)
	}
}

func TestGenerateBridgeNetdev(t *testing.T) {
	m := New()
	ifc := InterfaceConfig{
		Name:     "br-bd0",
		IsBridge: true,
	}
	got := m.generateBridgeNetdev(ifc)
	if !strings.Contains(got, "[NetDev]\n") {
		t.Error("missing [NetDev] section")
	}
	if !strings.Contains(got, "Name=br-bd0\n") {
		t.Error("missing Name=br-bd0")
	}
	if !strings.Contains(got, "Kind=bridge\n") {
		t.Error("missing Kind=bridge")
	}
}

func TestGenerateBridgeNetdev_WithMTU(t *testing.T) {
	m := New()
	ifc := InterfaceConfig{
		Name:        "br-bd0",
		IsBridge:    true,
		MTU:         9000,
		Description: "VLAN 100+200 bridge",
	}
	got := m.generateBridgeNetdev(ifc)
	if !strings.Contains(got, "MTUBytes=9000\n") {
		t.Error("missing MTU")
	}
	if !strings.Contains(got, "Description=VLAN 100+200 bridge\n") {
		t.Error("missing Description")
	}
}

func TestGenerateNetwork_BridgeMaster(t *testing.T) {
	m := New()
	ifc := InterfaceConfig{
		Name:         "trust0.100",
		BridgeMaster: "br-bd0",
	}
	got := m.generateNetwork(ifc)
	if !strings.Contains(got, "Bridge=br-bd0\n") {
		t.Errorf("missing Bridge=br-bd0:\n%s", got)
	}
}

func TestGenerateNetwork_BridgeDevice(t *testing.T) {
	m := New()
	ifc := InterfaceConfig{
		Name:      "br-bd0",
		IsBridge:  true,
		Addresses: []string{"10.0.100.1/24", "2001:db8:100::1/64"},
	}
	got := m.generateNetwork(ifc)
	if !strings.Contains(got, "Name=br-bd0\n") {
		t.Error("missing bridge device Name match")
	}
	if !strings.Contains(got, "Address=10.0.100.1/24\n") {
		t.Error("missing IPv4 address on bridge device")
	}
	if !strings.Contains(got, "Address=2001:db8:100::1/64\n") {
		t.Error("missing IPv6 address on bridge device")
	}
}

func TestApply_UnmanagedNoLinkFile(t *testing.T) {
	dir := t.TempDir()
	m := &Manager{networkDir: dir}

	// Pre-create a stale .link file for an unmanaged interface (simulates
	// old daemon behavior that wrote .link files for unmanaged interfaces).
	staleLinkPath := filepath.Join(dir, filePrefix+"ge-0-0-0.link")
	os.WriteFile(staleLinkPath, []byte("stale"), 0644)

	interfaces := []InterfaceConfig{
		{
			Name:       "ge-0-0-0",
			MACAddress: "10:66:6a:eb:3b:ba",
			Unmanaged:  true,
		},
	}

	_ = m.Apply(interfaces)

	// Stale .link file should be removed (unmanaged interfaces don't get .link files)
	if _, err := os.Stat(staleLinkPath); !os.IsNotExist(err) {
		t.Error("stale .link file for unmanaged interface should be removed")
	}

	// .network file should still exist
	networkPath := filepath.Join(dir, filePrefix+"ge-0-0-0.network")
	if _, err := os.Stat(networkPath); os.IsNotExist(err) {
		t.Error("missing .network file for unmanaged interface")
	}

	// .network should have ActivationPolicy=always-down
	data, _ := os.ReadFile(networkPath)
	if !strings.Contains(string(data), "ActivationPolicy=always-down") {
		t.Error("missing ActivationPolicy=always-down in unmanaged .network")
	}
}

func TestApply_BridgeExpectedFiles(t *testing.T) {
	dir := t.TempDir()
	m := &Manager{networkDir: dir}

	interfaces := []InterfaceConfig{
		{
			Name:     "br-bd0",
			IsBridge: true,
		},
		{
			Name:         "trust0.100",
			BridgeMaster: "br-bd0",
		},
	}

	// Apply should not fail (networkctl won't work in test, but file generation should)
	_ = m.Apply(interfaces)

	// Verify expected files exist
	netdevPath := filepath.Join(dir, filePrefix+"br-bd0.netdev")
	if _, err := os.Stat(netdevPath); os.IsNotExist(err) {
		t.Error("missing bridge .netdev file")
	}
	networkPath := filepath.Join(dir, filePrefix+"br-bd0.network")
	if _, err := os.Stat(networkPath); os.IsNotExist(err) {
		t.Error("missing bridge .network file")
	}
	memberPath := filepath.Join(dir, filePrefix+"trust0.100.network")
	if _, err := os.Stat(memberPath); os.IsNotExist(err) {
		t.Error("missing bridge member .network file")
	}
}

// #1798 belt test: a description carrying an embedded newline must not
// inject extra directives into any generated unit, even if commit-time
// validation were bypassed.
func TestGenerateUnits_NewlineDescriptionDoesNotInject(t *testing.T) {
	m := New()
	desc := "lan\nDHCP=ipv4"

	cases := map[string]string{
		"netdev": m.generateNetdev(InterfaceConfig{Name: "reth0", Description: desc}),
		"bridge": m.generateBridgeNetdev(InterfaceConfig{Name: "br0", Description: desc}),
		"link": m.generateLink(InterfaceConfig{
			Name: "trust0", MACAddress: "52:54:00:aa:bb:cc", Description: desc,
		}),
	}
	for name, got := range cases {
		for _, line := range strings.Split(got, "\n") {
			if strings.TrimSpace(line) == "DHCP=ipv4" {
				t.Errorf("%s: injected directive leaked into unit:\n%s", name, got)
			}
		}
		if !strings.Contains(got, "Description=lan DHCP=ipv4\n") {
			t.Errorf("%s: sanitized description missing:\n%s", name, got)
		}
	}
}

// TestGenerateUnits_TrailingDescriptionBackslashDoesNotContinue_10718 pins
// systemd.syntax(7)'s line-continuation byte on all Description= renderers.
func TestGenerateUnits_TrailingDescriptionBackslashDoesNotContinue_10718(t *testing.T) {
	m := New()
	desc := "lan\\"
	cases := map[string]string{
		"netdev": m.generateNetdev(InterfaceConfig{Name: "reth0", Description: desc, MTU: 9000}),
		"bridge": m.generateBridgeNetdev(InterfaceConfig{Name: "br0", Description: desc, MTU: 9000}),
		"link": m.generateLink(InterfaceConfig{
			Name: "trust0", MACAddress: "52:54:00:aa:bb:cc", Description: desc, MTU: 9000,
		}),
	}
	for name, got := range cases {
		for _, line := range strings.Split(got, "\n") {
			if strings.HasPrefix(line, "Description=") && strings.HasSuffix(line, "\\") {
				t.Errorf("%s: Description retains systemd's line-continuation backslash:\n%s", name, got)
			}
		}
		if !strings.Contains(got, "Description=lan \n") {
			t.Errorf("%s: trailing description backslash was not neutralized:\n%s", name, got)
		}
		if !strings.Contains(got, "MTUBytes=9000\n") {
			t.Errorf("%s: following unit directives were lost:\n%s", name, got)
		}
	}
}

func TestSanitizeUnitValue(t *testing.T) {
	if got := sanitizeUnitValue("plain"); got != "plain" {
		t.Errorf("clean value altered: %q", got)
	}
	if got := sanitizeUnitValue("a\nb\rc\x7f"); got != "a b c " {
		t.Errorf("control chars not stripped: %q", got)
	}
}

// TestApplyPreservesProtectedFiles is the #1956 AGY r3 CRITICAL regression:
// Apply's stale-file sweep must NOT delete a #1922-protected interface's
// 10-xpf-*.{link,network} even when that interface is absent from the
// compiled config (it is exempt from the unmanaged bring-down, so it never
// appears in ManagedInterfaces). Sweeping it would strip the live management
// NIC's rename + addressing on reload -> instant lockout.
func TestApplyPreservesProtectedFiles(t *testing.T) {
	dir := t.TempDir()
	// Pre-existing protected mgmt files (as written by the rename path).
	mustWrite := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0644); err != nil {
			t.Fatal(err)
		}
	}
	mustWrite("10-xpf-fxp0.link", "[Match]\nOriginalName=enp5s0\n\n[Link]\nName=fxp0\n")
	mustWrite("10-xpf-fxp0.network", "[Match]\nName=fxp0\n\n[Network]\nDHCP=yes\n")
	// A genuinely stale file that SHOULD be swept.
	mustWrite("10-xpf-ge-0-0-9.link", "[Match]\nOriginalName=enp99s0\n\n[Link]\nName=ge-0-0-9\n")

	m := NewInDir(dir)
	m.SetProtectedResolver(func() map[string]bool { return map[string]bool{"fxp0": true} })

	// Apply a config that manages only ge-0-0-3 — fxp0 is NOT in the list
	// (protected, exempt from the compiled set). Apply may return a
	// networkctl-reload error in the unit sandbox (no systemd); that is
	// environmental — the file-state assertions below are what matter.
	_ = m.Apply([]InterfaceConfig{
		{Name: "ge-0-0-3", MACAddress: "aa:bb:cc:dd:ee:01"},
	})

	// Protected fxp0 files MUST survive.
	for _, f := range []string{"10-xpf-fxp0.link", "10-xpf-fxp0.network"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Fatalf("protected file %s was swept (lockout!): %v", f, err)
		}
	}
	// The genuinely stale file MUST be removed.
	if _, err := os.Stat(filepath.Join(dir, "10-xpf-ge-0-0-9.link")); !os.IsNotExist(err) {
		t.Fatalf("stale ge-0-0-9 .link should have been swept")
	}
}

// stubNetworkctl replaces the runNetworkctl shell-out for the duration of a
// test (the unit sandbox has no systemd-networkd). It records the argument
// lists each call received and restores the original on cleanup.
func stubNetworkctl(t *testing.T) *[][]string {
	t.Helper()
	// The #4954 activation debt is process-scoped (#5718 fold F2), so start
	// every stubbed test from a clean debt: a leaked debt would make an
	// otherwise-unchanged Apply shell out an extra time.
	resetReloadDebtForTest(t)
	orig := runNetworkctl
	var calls [][]string
	runNetworkctl = func(args ...string) error {
		calls = append(calls, append([]string(nil), args...))
		return nil
	}
	t.Cleanup(func() { runNetworkctl = orig })
	return &calls
}

// TestGenerateNetwork_DHCPv4StaticIPv6 is the #2986 fail-on-revert: a WAN
// shape with DHCPv4 enabled AND a static IPv6 address must still install the
// static IPv6 (the v4 family's DHCP must not suppress the v6 static addr).
// With the pre-fix whole-interface gate (!DHCPv4 && !DHCPv6) the IPv6 line is
// dropped and this test fails RED.
func TestGenerateNetwork_DHCPv4StaticIPv6(t *testing.T) {
	m := New()
	ifc := InterfaceConfig{
		Name:      "wan0",
		DHCPv4:    true,
		Addresses: []string{"10.0.2.10/24", "2001:db8:2::10/64"},
	}
	got := m.generateNetwork(ifc)
	// DHCPv4 owns the v4 address — the static IPv4 must NOT be written.
	if strings.Contains(got, "Address=10.0.2.10/24") {
		t.Errorf("DHCPv4 interface should not write static IPv4 address:\n%s", got)
	}
	// The static IPv6 belongs to the non-DHCP family — it MUST be written.
	if !strings.Contains(got, "Address=2001:db8:2::10/64") {
		t.Errorf("DHCPv4+static-IPv6: static IPv6 address must be installed:\n%s", got)
	}
}

// TestGenerateNetwork_DHCPv6StaticIPv4 is the mirror of #2986: DHCPv6 enabled
// with a static IPv4 must still install the static IPv4.
func TestGenerateNetwork_DHCPv6StaticIPv4(t *testing.T) {
	m := New()
	ifc := InterfaceConfig{
		Name:      "wan0",
		DHCPv6:    true,
		Addresses: []string{"10.0.2.10/24", "2001:db8:2::10/64"},
	}
	got := m.generateNetwork(ifc)
	if !strings.Contains(got, "Address=10.0.2.10/24") {
		t.Errorf("DHCPv6+static-IPv4: static IPv4 address must be installed:\n%s", got)
	}
	if strings.Contains(got, "Address=2001:db8:2::10/64") {
		t.Errorf("DHCPv6 interface should not write static IPv6 address:\n%s", got)
	}
}

// TestApply_WriteErrorFailsCommit is the #2987 fail-on-revert: a write failure
// must propagate out of Apply rather than being swallowed as no-change-success.
// The .network path is pre-created as an unwritable DIRECTORY so the atomic
// writer's rename/create cannot succeed. With the pre-fix swallow
// (writeIfChanged logs + returns false) Apply returns nil and this test fails
// RED.
func TestApply_WriteErrorFailsCommit(t *testing.T) {
	stubNetworkctl(t)
	dir := t.TempDir()
	m := NewInDir(dir)

	// Make the target .network path un-writable by pre-creating a directory
	// where the file is expected — WriteFileAtomic cannot replace a dir.
	blocked := filepath.Join(dir, filePrefix+"trust0.network")
	if err := os.Mkdir(blocked, 0755); err != nil {
		t.Fatal(err)
	}

	err := m.Apply([]InterfaceConfig{
		{Name: "trust0", MACAddress: "52:54:00:aa:bb:cc", Addresses: []string{"10.0.1.10/24"}},
	})
	if err == nil {
		t.Fatal("Apply must fail when a generated file cannot be written (got nil)")
	}
	if !strings.Contains(err.Error(), "failed to write") &&
		!strings.Contains(err.Error(), "write ") {
		t.Errorf("Apply error should mention the write failure: %v", err)
	}
}

// TestApply_EmptySetSweepsStaleFiles is the #2988 fail-on-revert: removing the
// last managed interface (Apply with an empty desired set) must still sweep
// stale 10-xpf-* files and request a reload. With the pre-fix early return
// (len==0 -> return nil) the stale file survives and this test fails RED.
func TestApply_EmptySetSweepsStaleFiles(t *testing.T) {
	calls := stubNetworkctl(t)
	dir := t.TempDir()
	m := NewInDir(dir)

	stale := filepath.Join(dir, filePrefix+"old.network")
	if err := os.WriteFile(stale, []byte("[Match]\nName=old\n"), 0644); err != nil {
		t.Fatal(err)
	}

	if err := m.Apply(nil); err != nil {
		t.Fatalf("Apply(nil) should succeed: %v", err)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Errorf("stale 10-xpf-old.network should be swept on empty Apply")
	}
	// A reload must be requested because a file was removed.
	if len(*calls) == 0 || (*calls)[0][0] != "reload" {
		t.Errorf("empty Apply that removed files must request networkctl reload, got %v", *calls)
	}
}

// TestApply_EmptySetPreservesProtected ensures the #2988 empty-set sweep still
// honors the #1922/#1956 protected-set exemption — the lifeline files must NOT
// be swept even when the desired set is empty.
func TestApply_EmptySetPreservesProtected(t *testing.T) {
	stubNetworkctl(t)
	dir := t.TempDir()
	m := NewInDir(dir)
	m.SetProtectedResolver(func() map[string]bool { return map[string]bool{"fxp0": true} })

	if err := os.WriteFile(filepath.Join(dir, "10-xpf-fxp0.network"),
		[]byte("[Match]\nName=fxp0\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "10-xpf-fxp0.link"),
		[]byte("[Match]\nOriginalName=enp5s0\n"), 0644); err != nil {
		t.Fatal(err)
	}

	if err := m.Apply(nil); err != nil {
		t.Fatalf("Apply(nil) should succeed: %v", err)
	}
	for _, f := range []string{"10-xpf-fxp0.network", "10-xpf-fxp0.link"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Errorf("protected file %s swept on empty Apply (lockout!): %v", f, err)
		}
	}
}
