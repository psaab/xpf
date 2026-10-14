package config

import (
	"strings"
	"testing"
)

// #12842 (D3-05): `system-services any-service` is a packet-wide full admit
// (HostInboundFullAdmitService) — it admits every IP protocol, including
// OSPF/OSPFv3/RIP multicast. The #11571 strict gate ignored the effective
// system-services list and hard-rejected valid any-service configs. Padded
// routing refs (ge-0/0/1.00) missed the canonical zone map.
func TestManagedRoutingAnyServiceAdmission12842(t *testing.T) {
	base := []string{
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.1.1/24",
		"set interfaces ge-0/0/2 unit 0 family inet6 address 2001:db8::1/64",
		"set security zones security-zone trust interfaces ge-0/0/0.0",
		"set security zones security-zone trust interfaces ge-0/0/1.0",
		"set security zones security-zone trust interfaces ge-0/0/2.0",
		"set security zones security-zone trust host-inbound-traffic system-services any-service",
	}
	ospf := append(append([]string{}, base...), "set protocols ospf area 0.0.0.0 interface ge-0/0/0.0")
	if _, err := CompileConfig(buildTree(t, ospf)); err != nil {
		t.Fatalf("any-service + OSPF must compile: %v", err)
	}
	ospfv3 := append(append([]string{}, base...), "set protocols ospf3 area 0.0.0.0 interface ge-0/0/2.0")
	if _, err := CompileConfig(buildTree(t, ospfv3)); err != nil {
		t.Fatalf("any-service + OSPFv3 must compile: %v", err)
	}
	rip := append(append([]string{}, base...), "set protocols rip group g1 neighbor ge-0/0/1.0")
	if _, err := CompileConfig(buildTree(t, rip)); err != nil {
		t.Fatalf("any-service + RIP must compile: %v", err)
	}
	// Interface-override any-service also admits.
	override := []string{
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
		"set security zones security-zone trust interfaces ge-0/0/0.0",
		"set security zones security-zone trust interfaces ge-0/0/0.0 host-inbound-traffic system-services any-service",
		"set protocols ospf area 0.0.0.0 interface ge-0/0/0.0",
	}
	if _, err := CompileConfig(buildTree(t, override)); err != nil {
		t.Fatalf("interface any-service override + OSPF must compile: %v", err)
	}
}

func TestManagedRoutingPaddedRef12842(t *testing.T) {
	// Restrictive zone (no ospf token), OSPF on padded ref ge-0/0/1.00 -> must still be diagnosed (fail-closed), not silently skipped.
	padded := []string{
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.1.1/24",
		"set security zones security-zone trust interfaces ge-0/0/1.0",
		"set protocols ospf area 0.0.0.0 interface ge-0/0/1.00",
	}
	_, err := CompileConfig(buildTree(t, padded))
	if err == nil || !strings.Contains(err.Error(), `omits "ospf"`) {
		t.Fatalf("padded ref restrictive zone: strict error = %v, want omits ospf", err)
	}
	// Padded ref + any-service must compile.
	paddedOK := append(append([]string{}, padded...), "set security zones security-zone trust host-inbound-traffic system-services any-service")
	if _, err := CompileConfig(buildTree(t, paddedOK)); err != nil {
		t.Fatalf("padded ref + any-service must compile: %v", err)
	}
	// Padded ref + explicit ospf token must compile.
	paddedTok := append(append([]string{}, padded...), "set security zones security-zone trust host-inbound-traffic protocols ospf")
	if _, err := CompileConfig(buildTree(t, paddedTok)); err != nil {
		t.Fatalf("padded ref + ospf token must compile: %v", err)
	}
}

// Guard: missing any-service and missing token still rejected; `system-services all` is NOT full-admit (#3226) so must not silence gate.
func TestManagedRoutingStillFailsClosed12842(t *testing.T) {
	missing := []string{
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
		"set security zones security-zone trust interfaces ge-0/0/0.0",
		"set protocols ospf area 0.0.0.0 interface ge-0/0/0.0",
	}
	if _, err := CompileConfig(buildTree(t, missing)); err == nil {
		t.Fatalf("missing token must still reject")
	}
	allSvc := append(append([]string{}, missing...), "set security zones security-zone trust host-inbound-traffic system-services all")
	if _, err := CompileConfig(buildTree(t, allSvc)); err == nil || !strings.Contains(err.Error(), `omits "ospf"`) {
		t.Fatalf("system-services all must not silence ospf gate, err=%v", err)
	}
	// Interface override replacing zone any-service with restrictive set must reject (override replaces, #6515).
	replaced := []string{
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
		"set security zones security-zone trust interfaces ge-0/0/0.0",
		"set security zones security-zone trust host-inbound-traffic system-services any-service",
		"set security zones security-zone trust interfaces ge-0/0/0.0 host-inbound-traffic protocols bgp",
		"set protocols ospf area 0.0.0.0 interface ge-0/0/0.0",
	}
	if _, err := CompileConfig(buildTree(t, replaced)); err == nil {
		t.Fatalf("interface override replacing zone any-service must still reject")
	}
	// Tolerant: any-service produces no mismatch warning.
	cfg, err := CompileConfigLenient(buildTree(t, append(append([]string{}, missing...), "set security zones security-zone trust host-inbound-traffic system-services any-service")))
	if err != nil {
		t.Fatalf("lenient: %v", err)
	}
	if containsManagedAdmissionDiagnostic11571(cfg.Warnings) {
		t.Fatalf("any-service lenient must not warn mismatch: %v", cfg.Warnings)
	}
}
