package config

import (
	"strings"
	"testing"
)

func hasHostInboundToken12834(tokens []string, want string) bool {
	for _, token := range tokens {
		if strings.EqualFold(token, want) {
			return true
		}
	}
	return false
}

// #12834: zone poisoning (#11575/#12623 DroppedEnforcementChild) cleared
// Interfaces/ScreenProfile but retained InterfaceHostInbound. In
// ResolveInterfaceHostInbound the bare-physical arm wrote out[iface]
// first-sorted-writer-wins without any zone-membership check (unlike the
// unit arm, which checks owner + quarantine). So a poisoned zone alpha
// (sorts before healthy zulu) with `system-services all` on the bare
// physical could displace the healthy owner's admission, and its override
// remained visible through the stamped per-zone view too.
//
// These tests are the fail-on-revert guard: the poisoned override must not
// resolve onto the bare key or remain visible in zone-level lookup methods.
func poisonedZoneHostInboundLines12834(poison bool) []string {
	lines := []string{
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
		// Healthy owner of ge-0/0/0.0: admits only ssh at unit level.
		"set security zones security-zone zulu interfaces ge-0/0/0.0",
		"set security zones security-zone zulu interfaces ge-0/0/0.0 host-inbound-traffic system-services ssh",
		// Poisoned zone: bare-physical override authored on an interface
		// owned by zulu.
		"set security zones security-zone alpha interfaces ge-0/0/0 host-inbound-traffic system-services all",
	}
	if poison {
		lines = append(lines, "set security zones security-zone alpha bogus-child-keyword")
	}
	return lines
}

func TestPoisonedZoneBareHostInboundDoesNotDisplaceHealthyOwner12834(t *testing.T) {
	cfg, err := CompileConfigLenient(buildTree(t, poisonedZoneHostInboundLines12834(true)))
	if err != nil {
		t.Fatalf("lenient compile: %v", err)
	}
	alpha := cfg.Security.Zones["alpha"]
	if alpha == nil || !alpha.DroppedEnforcementChild {
		t.Fatalf("fixture: alpha must be poisoned, got %+v", alpha)
	}
	if len(alpha.Interfaces) != 0 {
		t.Fatalf("fixture: poisoned alpha must be unbound, got %v", alpha.Interfaces)
	}
	got := ResolveInterfaceHostInbound(cfg)
	if _, quarantined := QuarantinedZoneInterfaceKeys(cfg)["ge-0/0/0.0"]; !quarantined {
		t.Fatal("poisoned zone's contested unit-0 claim must quarantine ge-0/0/0.0")
	}
	for _, key := range []string{"ge-0/0/0", "ge-0/0/0.0"} {
		if hib := got[key]; hib != nil {
			t.Fatalf("contested interface %q must not resolve host-inbound admission, got %v", key, hib.SystemServices)
		}
	}
	for key, hib := range got {
		if hib != nil && hasHostInboundToken12834(hib.SystemServices, "all") {
			t.Fatalf("poisoned zone token leaked onto %q: %v", key, hib.SystemServices)
		}
	}
}

func TestPoisonedZoneStampedOverrideAbsent12834(t *testing.T) {
	cfg, err := CompileConfigLenient(buildTree(t, poisonedZoneHostInboundLines12834(true)))
	if err != nil {
		t.Fatalf("lenient compile: %v", err)
	}
	alpha := cfg.Security.Zones["alpha"]
	if alpha == nil {
		t.Fatal("alpha zone missing")
	}
	if _, _, declared := alpha.InterfaceHostInboundOverride("ge-0/0/0"); declared {
		t.Fatal("poisoned zone still declares bare host-inbound override")
	}
	if _, _, declared := alpha.InterfaceHostInboundOverride("ge-0/0/0.0"); declared {
		t.Fatal("poisoned zone still declares unit host-inbound override")
	}
	if svc, _, overridden := alpha.InterfaceHostInboundEffective("ge-0/0/0.0"); overridden || len(svc) != 0 {
		t.Fatalf("poisoned zone effective = %v overridden=%v, want empty/not overridden", svc, overridden)
	}
	// The poisoned zone's authored membership remains part of quarantine, so
	// the contested unit override must not leak through the healthy zone view.
	zulu := cfg.Security.Zones["zulu"]
	svc, _, overridden := zulu.InterfaceHostInboundEffective("ge-0/0/0.0")
	if overridden || len(svc) != 0 {
		t.Fatalf("contested zulu effective = %v overridden=%v, want no unit override", svc, overridden)
	}
}

func TestNonPoisonedZoneBareHostInboundStillResolves12834(t *testing.T) {
	cfg, err := CompileConfigLenient(buildTree(t, []string{
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
		"set security zones security-zone alpha interfaces ge-0/0/0",
		"set security zones security-zone alpha interfaces ge-0/0/0 host-inbound-traffic system-services all",
	}))
	if err != nil {
		t.Fatalf("lenient compile: %v", err)
	}
	got := ResolveInterfaceHostInbound(cfg)
	if hib := got["ge-0/0/0"]; hib == nil || !hasHostInboundToken12834(hib.SystemServices, "all") {
		t.Fatalf("non-poisoned alpha bare override = %v, want all (control must stay live)", got["ge-0/0/0"])
	}
}
