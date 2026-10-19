package config

import (
	"strings"
	"testing"
)

// #15651: compilePortMirroring deduped ingress on LinuxIfName(v) only, so
// `ge-0/0/0` (bare) and `ge-0/0/0.0` (unit 0) — which ResolveKernelIfName
// maps to the same kernel device ge-0-0-0 — compiled as distinct sources
// in different instances, then collided on one ifindex in the builders.
// The post-section gate normalizes through ResolveKernelIfName (interfaces
// are compiled by then) and rejects the alias at commit.
func TestPortMirroringRejectsAliasedBareVsUnit0Ingress15651(t *testing.T) {
	_, err := compilePortMirroringSet(t,
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
		"set forwarding-options port-mirroring instance span1 input ingress interface ge-0/0/0",
		"set forwarding-options port-mirroring instance span1 output interface mon0",
		"set forwarding-options port-mirroring instance span2 input ingress interface ge-0/0/0.0",
		"set forwarding-options port-mirroring instance span2 output interface mon1",
	)
	if err == nil {
		t.Fatal("CompileConfig succeeded, want reject for aliased bare vs unit-0 ingress across instances")
	}
	if !strings.Contains(err.Error(), `"span1"`) || !strings.Contains(err.Error(), `"span2"`) {
		t.Fatalf("error = %v, want duplicate-ingress reject naming both instances", err)
	}
}

// Cross-spelling Junos vs Linux unit refs were already caught by
// LinuxIfName; keep them green as a control alongside the new alias.
func TestPortMirroringAliasedControlCompiles15651(t *testing.T) {
	cfg, err := compilePortMirroringSet(t,
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.1.1/24",
		"set forwarding-options port-mirroring instance span1 input ingress interface ge-0/0/0.0",
		"set forwarding-options port-mirroring instance span1 output interface mon0",
		"set forwarding-options port-mirroring instance span2 input ingress interface ge-0/0/1.0",
		"set forwarding-options port-mirroring instance span2 output interface mon1",
	)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if len(cfg.ForwardingOptions.PortMirroring.Instances) != 2 {
		t.Fatalf("instances = %+v, want 2", cfg.ForwardingOptions.PortMirroring.Instances)
	}
}
