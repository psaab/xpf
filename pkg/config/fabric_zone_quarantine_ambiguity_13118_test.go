package config

import (
	"strings"
	"testing"
)

// #13118 (D1-14): validateFabricZoneRoutingInstanceAmbiguityStrict must
// honor the quarantine SSOTs (ZoneQuarantineExclusionsForConfig /
// QuarantinedZoneInterfaceKeys). A zone already quarantined by a zone-ID
// collision, or an interface already quarantined by multi-zone membership,
// must not emit a downstream "fabric zone routing-domain ambiguity"
// diagnostic on the tolerant path.

func fabricAmbiguityWarningFor13118(cfg *Config, zoneName string) (string, bool) {
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "fabric zone routing-domain ambiguity") &&
			strings.Contains(w, `"`+zoneName+`"`) {
			return w, true
		}
	}
	return "", false
}

// Quarantined-zone cell: z214 collides with z174 (frozen fold) and is the
// later-sorting loser, so ZoneQuarantineExclusionsForConfig quarantines it.
// Its two members span RI-A and MAIN. Pre-fix the gate still warned about
// z214 on CompileConfigLenient; post-fix it must stay silent for z214.
func TestFabricZoneQuarantinedByCollisionSkipsAmbiguityWarning13118(t *testing.T) {
	if StableZoneID("z174") != StableZoneID("z214") {
		t.Fatalf("test premise broken: z174/z214 no longer collide under the frozen fold")
	}
	tree := buildTree(t, []string{
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.0.1/24",
		"set interfaces ge-0/0/2 unit 0 family inet address 10.0.1.1/24",
		"set routing-instances RI-A instance-type virtual-router",
		"set routing-instances RI-A interface ge-0/0/1.0",
		"set security zones security-zone z174",
		"set security zones security-zone z214 interfaces ge-0/0/1.0",
		"set security zones security-zone z214 interfaces ge-0/0/2.0",
	})
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient rejected a quarantined cross-RI zone: %v", err)
	}
	if _, excluded := ZoneQuarantineExclusionsForConfig(cfg)["z214"]; !excluded {
		t.Fatalf("test premise broken: z214 not quarantined: %v", ZoneQuarantineExclusionsForConfig(cfg))
	}
	if w, found := fabricAmbiguityWarningFor13118(cfg, "z214"); found {
		t.Fatalf("quarantined zone z214 still emitted fabric routing-domain ambiguity warning: %q", w)
	}
	// Strict mode is unaffected: the zone-ID collision gate itself rejects.
	if _, err := CompileConfig(tree); err == nil {
		t.Fatal("strict compile accepted a colliding zone pair")
	}
}

// Contested-interface cell: ge-0/0/2.0 is claimed by both `shared` and
// `other`, so QuarantinedZoneInterfaceKeys quarantines that key. If the
// contested key is dropped from `shared`, shared collapses to a single
// routing context (RI-A) and must not warn. Pre-fix the gate counted the
// contested MAIN key and warned.
func TestFabricZoneContestedInterfaceSkippedInAmbiguityGate13118(t *testing.T) {
	tree := buildTree(t, []string{
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.0.1/24",
		"set interfaces ge-0/0/2 unit 0 family inet address 10.0.1.1/24",
		"set routing-instances RI-A instance-type virtual-router",
		"set routing-instances RI-A interface ge-0/0/1.0",
		"set security zones security-zone shared interfaces ge-0/0/1.0",
		"set security zones security-zone shared interfaces ge-0/0/2.0",
		"set security zones security-zone other interfaces ge-0/0/2.0",
	})
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient rejected a contested-interface zone: %v", err)
	}
	if _, quarantined := QuarantinedZoneInterfaceKeys(cfg)["ge-0/0/2.0"]; !quarantined {
		t.Fatalf("test premise broken: ge-0/0/2.0 not quarantined: %v", QuarantinedZoneInterfaceKeys(cfg))
	}
	if w, found := fabricAmbiguityWarningFor13118(cfg, "shared"); found {
		t.Fatalf("zone shared warned only via quarantined interface ge-0/0/2.0: %q", w)
	}
}

// Must-still-fire cell: a non-quarantined cross-RI zone keeps its warning,
// proving the quarantine filtering did not gut the gate.
func TestFabricZoneNonQuarantinedCrossRIStillWarns13118(t *testing.T) {
	tree := crossRIFabricZoneTree11061(t)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient rejected a cross-RI zone: %v", err)
	}
	if _, found := fabricAmbiguityWarningFor13118(cfg, "shared"); !found {
		t.Fatalf("non-quarantined cross-RI zone lost its fabric ambiguity warning: %v", cfg.Warnings)
	}
}
