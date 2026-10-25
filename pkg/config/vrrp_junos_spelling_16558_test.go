package config

import (
	"reflect"
	"strings"
	"testing"
)

// #16558: the Juniper VRRP spelling commits on the strict path to the
// same VRRPGroup as the CIDR form; a bare VIP with no same-family
// enclosing prefix still rejects; inet6-advertise-interval maps (ms);
// virtual-link-local-address is name-refused (auto-derived, #5089).

func vrrpGroups16558(t *testing.T, cfg *Config, iface string) []*VRRPGroup {
	t.Helper()
	ifc := cfg.Interfaces.Interfaces[iface]
	if ifc == nil {
		t.Fatalf("no interface %s in %+v", iface, cfg.Interfaces.Interfaces)
	}
	var out []*VRRPGroup
	for _, u := range ifc.Units {
		for _, vg := range u.VRRPGroups {
			out = append(out, vg)
		}
	}
	return out
}

func TestJuniperBareVRRPCommitsSameAsCIDR16558(t *testing.T) {
	bare := []string{
		"set interfaces ge-0/0/0 unit 0 family inet address 192.168.1.2/24",
		"set interfaces ge-0/0/0 unit 0 family inet address 192.168.1.2/24 vrrp-group 1 virtual-address 192.168.1.15",
		"set interfaces ge-0/0/0 unit 0 family inet address 192.168.1.2/24 vrrp-group 1 priority 150",
	}
	cidr := []string{
		"set interfaces ge-0/0/0 unit 0 family inet address 192.168.1.2/24",
		"set interfaces ge-0/0/0 unit 0 family inet address 192.168.1.2/24 vrrp-group 1 virtual-address 192.168.1.15/24",
		"set interfaces ge-0/0/0 unit 0 family inet address 192.168.1.2/24 vrrp-group 1 priority 150",
	}
	if err := SchemaValidate(buildTree(t, bare)); err != nil {
		t.Fatalf("SchemaValidate must accept bare Junos VIP: %v", err)
	}
	bcfg, err := CompileConfig(buildTree(t, bare))
	if err != nil {
		t.Fatalf("strict bare Juniper example must commit: %v", err)
	}
	ccfg, err := CompileConfig(buildTree(t, cidr))
	if err != nil {
		t.Fatalf("strict CIDR control must commit: %v", err)
	}
	bg := vrrpGroups16558(t, bcfg, "ge-0/0/0")
	cg := vrrpGroups16558(t, ccfg, "ge-0/0/0")
	if len(bg) != 1 || len(cg) != 1 {
		t.Fatalf("want 1 group each, got bare=%v cidr=%v", bg, cg)
	}
	if !reflect.DeepEqual(bg[0], cg[0]) {
		t.Fatalf("Juniper bare must compile to same VRRPGroup as CIDR:\nbare=%+v\ncidr=%+v", bg[0], cg[0])
	}
	if bg[0].VirtualAddresses[0] != "192.168.1.15/24" {
		t.Fatalf("normalized VIP = %v, want 192.168.1.15/24", bg[0].VirtualAddresses)
	}
	// Hierarchical packed + braced spellings agree too.
	hier := "interfaces { ge-0/0/0 { unit 0 { family inet { address 192.168.1.2/24 { vrrp-group 1 { virtual-address 192.168.1.15; priority 150; } } } } } }"
	hcfg, err := CompileConfig(parseHierText(t, hier))
	if err != nil {
		t.Fatalf("hier bare must commit: %v", err)
	}
	hg := vrrpGroups16558(t, hcfg, "ge-0/0/0")
	if len(hg) != 1 || !reflect.DeepEqual(hg[0], cg[0]) {
		t.Fatalf("hier bare group = %+v, want %+v", hg, cg)
	}
	// Lenient agrees with strict.
	lcfg, err := CompileConfigLenient(buildTree(t, bare))
	if err != nil {
		t.Fatalf("lenient: %v", err)
	}
	lg := vrrpGroups16558(t, lcfg, "ge-0/0/0")
	if len(lg) != 1 || !reflect.DeepEqual(lg[0], cg[0]) {
		t.Fatalf("lenient group = %+v, want %+v", lg, cg)
	}
}

func TestJuniperBareInet6CommitsSameAsCIDR16558(t *testing.T) {
	bare := []string{
		"set interfaces reth0 unit 0 family inet6 address 2001:db8::10/64",
		"set interfaces reth0 unit 0 family inet6 address 2001:db8::10/64 vrrp-inet6-group 1 virtual-inet6-address 2001:db8::1",
		"set interfaces reth0 unit 0 family inet6 address 2001:db8::10/64 vrrp-inet6-group 1 priority 150",
	}
	cidr := []string{
		"set interfaces reth0 unit 0 family inet6 address 2001:db8::10/64",
		"set interfaces reth0 unit 0 family inet6 address 2001:db8::10/64 vrrp-inet6-group 1 virtual-inet6-address 2001:db8::1/64",
		"set interfaces reth0 unit 0 family inet6 address 2001:db8::10/64 vrrp-inet6-group 1 priority 150",
	}
	if err := SchemaValidate(buildTree(t, bare)); err != nil {
		t.Fatalf("SchemaValidate bare v6: %v", err)
	}
	bcfg, err := CompileConfig(buildTree(t, bare))
	if err != nil {
		t.Fatalf("strict bare v6 must commit: %v", err)
	}
	ccfg, err := CompileConfig(buildTree(t, cidr))
	if err != nil {
		t.Fatalf("cidr control: %v", err)
	}
	bg := vrrpGroups16558(t, bcfg, "reth0")
	cg := vrrpGroups16558(t, ccfg, "reth0")
	if len(bg) != 1 || len(cg) != 1 || !reflect.DeepEqual(bg[0], cg[0]) {
		t.Fatalf("bare v6 = %+v, cidr = %+v", bg, cg)
	}
}

func TestBareVIPNoEnclosingPrefixRejects16558(t *testing.T) {
	// v6 bare VIP on a v4-only unit: no same-family enclosing prefix.
	lines := []string{
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.1.2/24",
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.1.2/24 vrrp-group 1 virtual-address 2001:db8::1",
	}
	_, err := CompileConfig(buildTree(t, lines))
	if err == nil {
		t.Fatal("bare VIP with no same-family enclosing prefix must strict-reject")
	}
	if !strings.Contains(err.Error(), "2001:db8::1") || !strings.Contains(err.Error(), "no prefix") {
		t.Fatalf("error must name VIP + missing prefix, got: %v", err)
	}
	// Tolerant: boots with host prefix + warning (#1960).
	lcfg, err := CompileConfigLenient(buildTree(t, lines))
	if err != nil {
		t.Fatalf("lenient must boot: %v", err)
	}
	lg := vrrpGroups16558(t, lcfg, "ge-0/0/0")
	if len(lg) != 1 || len(lg[0].VirtualAddresses) != 1 || lg[0].VirtualAddresses[0] != "2001:db8::1/128" {
		t.Fatalf("lenient host fallback = %+v", lg)
	}
	// Garbage still rejects at SchemaValidate (not silently normalized).
	bad := []string{
		"set interfaces ge-0/0/0 unit 0 family inet address 192.168.1.2/24",
		"set interfaces ge-0/0/0 unit 0 family inet address 192.168.1.2/24 vrrp-group 1 virtual-address notanip",
	}
	if err := SchemaValidate(buildTree(t, bad)); err == nil {
		t.Fatal("garbage VIP must reject at SchemaValidate")
	}
	// Wrong family bare still rejects at SchemaValidate.
	wrongFam := []string{
		"set interfaces ge-0/0/0 unit 0 family inet address 192.168.1.2/24",
		"set interfaces ge-0/0/0 unit 0 family inet address 192.168.1.2/24 vrrp-group 1 virtual-address 2001:db8::1",
	}
	if err := SchemaValidate(buildTree(t, wrongFam)); err == nil {
		t.Fatal("v6 bare under inet schema must reject at SchemaValidate")
	}
}

func TestInet6AdvertiseIntervalMaps16558(t *testing.T) {
	base := []string{
		"set interfaces reth0 unit 0 family inet6 address 2001:db8::10/64",
		"set interfaces reth0 unit 0 family inet6 address 2001:db8::10/64 vrrp-inet6-group 1 virtual-inet6-address 2001:db8::1/64",
	}
	withInterval := append(append([]string{}, base...),
		"set interfaces reth0 unit 0 family inet6 address 2001:db8::10/64 vrrp-inet6-group 1 inet6-advertise-interval 500")
	if err := SchemaValidate(buildTree(t, withInterval)); err != nil {
		t.Fatalf("SchemaValidate inet6 interval: %v", err)
	}
	cfg, err := CompileConfig(buildTree(t, withInterval))
	if err != nil {
		t.Fatalf("inet6-advertise-interval must commit: %v", err)
	}
	g := vrrpGroups16558(t, cfg, "reth0")
	if len(g) != 1 || g[0].Inet6AdvertiseIntervalMS != 500 {
		t.Fatalf("Inet6AdvertiseIntervalMS = %+v, want 500", g)
	}
	// Hierarchical spelling.
	hier := "interfaces { reth0 { unit 0 { family inet6 { address 2001:db8::10/64 { vrrp-inet6-group 1 { virtual-inet6-address 2001:db8::1/64; inet6-advertise-interval 250; } } } } } }"
	hcfg, err := CompileConfig(parseHierText(t, hier))
	if err != nil {
		t.Fatalf("hier inet6 interval: %v", err)
	}
	if hg := vrrpGroups16558(t, hcfg, "reth0"); len(hg) != 1 || hg[0].Inet6AdvertiseIntervalMS != 250 {
		t.Fatalf("hier Inet6AdvertiseIntervalMS = %+v, want 250", hg)
	}
	// Out of Junos range rejects (schema + packed hierarchical via gate).
	for _, ms := range []string{"50", "50000"} {
		lines := append(append([]string{}, base...),
			"set interfaces reth0 unit 0 family inet6 address 2001:db8::10/64 vrrp-inet6-group 1 inet6-advertise-interval "+ms)
		if err := SchemaValidate(buildTree(t, lines)); err == nil {
			t.Fatalf("inet6-advertise-interval %s must reject at SchemaValidate", ms)
		}
	}
	packed := "interfaces { reth0 { unit 0 { family inet6 { address 2001:db8::10/64 { vrrp-inet6-group 1 virtual-inet6-address 2001:db8::1/64 inet6-advertise-interval 50000; } } } } }"
	if _, err := CompileConfig(parseHierText(t, packed)); err == nil || !strings.Contains(err.Error(), "inet6-advertise-interval") {
		t.Fatalf("packed out-of-range inet6 interval must reject naming leaf, got %v", err)
	}
	// v4 group keeps rejecting the v6-only leaf (#15046 children gate).
	v4 := []string{
		"set interfaces ge-0/0/0 unit 0 family inet address 192.168.1.2/24",
		"set interfaces ge-0/0/0 unit 0 family inet address 192.168.1.2/24 vrrp-group 1 virtual-address 192.168.1.15/24",
		"set interfaces ge-0/0/0 unit 0 family inet address 192.168.1.2/24 vrrp-group 1 inet6-advertise-interval 500",
	}
	if _, err := CompileConfig(buildTree(t, v4)); err == nil {
		t.Fatal("inet6-advertise-interval under vrrp-group (v4) must reject")
	}
}

func TestVirtualLinkLocalNameRefused16558(t *testing.T) {
	lines := []string{
		"set interfaces reth0 unit 0 family inet6 address 2001:db8::10/64",
		"set interfaces reth0 unit 0 family inet6 address 2001:db8::10/64 vrrp-inet6-group 1 virtual-inet6-address 2001:db8::1/64",
		"set interfaces reth0 unit 0 family inet6 address 2001:db8::10/64 vrrp-inet6-group 1 virtual-link-local-address fe80::1",
	}
	_, err := CompileConfig(buildTree(t, lines))
	if err == nil {
		t.Fatal("virtual-link-local-address must be name-refused, not silently dropped")
	}
	if !strings.Contains(err.Error(), "virtual-link-local-address") || !strings.Contains(err.Error(), "auto-derives") {
		t.Fatalf("refusal must name leaf + auto-derive reason, got: %v", err)
	}
	// Tolerant: boots, warns naming the leaf, does not actuate it.
	lcfg, err := CompileConfigLenient(buildTree(t, lines))
	if err != nil {
		t.Fatalf("lenient must boot: %v", err)
	}
	if !warningsContain(lcfg.Warnings, "virtual-link-local-address") {
		t.Fatalf("lenient must warn naming virtual-link-local-address; %v", lcfg.Warnings)
	}
	// Non-link-local value rejects at SchemaValidate via ValidateIPv6Address? (any v6 accepted there;
	// the name-refusal gate is the operative check — a v4 literal must schema-reject.)
	v4val := append(append([]string{}, lines[:2]...),
		"set interfaces reth0 unit 0 family inet6 address 2001:db8::10/64 vrrp-inet6-group 1 virtual-link-local-address 10.0.0.1")
	if err := SchemaValidate(buildTree(t, v4val)); err == nil {
		t.Fatal("v4 literal for virtual-link-local-address must schema-reject")
	}
}
