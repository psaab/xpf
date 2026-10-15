package config

import (
	"strings"
	"testing"
)

// #13098 (D2-09): three defects in validateVRFOverlap.
//
//  1. addPrefix deduplicated seen[riName] by masked prefix alone, so a native
//     member prefix on riA silently dropped a PBR-steered claim for the same
//     prefix (filter f1 -> riA). The #9809 steeredAll pairing guard then saw
//     riA's entry as native (steered=false) and skipped it, so a cross-filter
//     match-all steer (filter f2 -> riB) that should refuse committed clean.
//  2. sawPBRRoutingInstance was set before the PBRDirectionSteers none check,
//     so a dead term (empty prefix-list — the builder installs no rule)
//     promoted a plain native overlap to a #7924 strict rejection and a
//     tolerant admission.
//  3. validateVRFOverlap runs in runTailGates BEFORE the tolerant RI
//     quarantines rewrite RoutingInstances, so cfg.Warnings described the
//     pre-quarantine membership while TolerantVRFOverlapAdmissions (re-run
//     on the returned config) described the post-quarantine one.
//
// Fail-on-revert: restoring the prefix-only dedup key reds subtest A;
// restoring the pre-check sawPBR assignment reds B; removing the primary-
// claim collection or the post-quarantine refresh reds C1/C2 respectively.

// vrfLines13098 joins set-lines for the 13098 fixtures via the shared
// buildTree helper (flat `set` commands, per the CLAUDE.md testing gotcha).

func TestVRFOverlapNativeDoesNotMaskSteered_13098(t *testing.T) {
	// riA carries 10.0.0.0/24 natively AND filter f1 steers 10.0.0.0/24 into
	// riA; filter f2 steers match-all into riB. The f1/f2 steered pair is a
	// cross-filter steeredAll collision and must refuse on strict compile.
	tree := buildTree(t, []string{
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
		"set routing-instances riA instance-type virtual-router",
		"set routing-instances riA interface ge-0/0/0.0",
		"set routing-instances riB instance-type virtual-router",
		"set firewall family inet filter f1 term t1 from source-address 10.0.0.0/24",
		"set firewall family inet filter f1 term t1 then routing-instance riA",
		"set firewall family inet filter f2 term t1 then routing-instance riB",
	})
	if _, err := CompileConfig(tree); err == nil {
		t.Fatal("strict compile accepted cross-filter PBR overlap: native 10.0.0.0/24 on riA masked the f1 steered claim, blinding the #9809 steeredAll check against f2 match-all into riB (#13098)")
	} else if !strings.Contains(err.Error(), "#7924") {
		t.Fatalf("rejection must cite #7924, got: %v", err)
	}
	// Tolerant path must record the admission (metric must not stay silent).
	lcfg, err := CompileConfigLenient(buildTree(t, []string{
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
		"set routing-instances riA instance-type virtual-router",
		"set routing-instances riA interface ge-0/0/0.0",
		"set routing-instances riB instance-type virtual-router",
		"set firewall family inet filter f1 term t1 from source-address 10.0.0.0/24",
		"set firewall family inet filter f1 term t1 then routing-instance riA",
		"set firewall family inet filter f2 term t1 then routing-instance riB",
	}))
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	if adm := TolerantVRFOverlapAdmissions(lcfg); len(adm) == 0 {
		t.Fatal("TolerantVRFOverlapAdmissions empty for a config strict refuses (#13098)")
	}
}

func TestVRFOverlapDeadPBRDoesNotReject_13098(t *testing.T) {
	// Native overlap on riA/riB plus a DEAD PBR term (empty prefix-list:
	// PBRDirectionSteers reports none, the builder installs no rule). The
	// dead term must not set sawPBRRoutingInstance: strict commits with the
	// plain overlap warning, and no tolerant admission is recorded.
	cmds := []string{
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.0.2/24",
		"set policy-options prefix-list empty-pl",
		"set routing-instances riA instance-type virtual-router",
		"set routing-instances riA interface ge-0/0/0.0",
		"set routing-instances riB instance-type virtual-router",
		"set routing-instances riB interface ge-0/0/1.0",
		"set firewall family inet filter dead-f term t1 from source-prefix-list empty-pl",
		"set firewall family inet filter dead-f term t1 then routing-instance riA",
	}
	cfg, err := CompileConfig(buildTree(t, cmds))
	if err != nil {
		t.Fatalf("dead (empty prefix-list) PBR term must not trigger #7924 rejection, got: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "NOT session-isolated") {
			found = true
		}
	}
	if !found {
		t.Fatalf("plain native overlap warning must survive, warnings=%v", cfg.Warnings)
	}
	lcfg, err := CompileConfigLenient(buildTree(t, cmds))
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	if adm := TolerantVRFOverlapAdmissions(lcfg); len(adm) != 0 {
		t.Fatalf("dead PBR term must not create a tolerant admission, got %+v", adm)
	}
}

func TestVRFOverlapTolerantSyncAfterDualClaimQuarantine_13098(t *testing.T) {
	// ge-0/0/0.0 dual-claimed by riA and riB (native 10.0.0.0/24) plus a live
	// PBR steer into riA. On the tolerant path the dual-claim quarantine
	// removes the contested membership from both instances, so the returned
	// config carries no overlap: cfg.Warnings must NOT keep the stale
	// pre-quarantine overlap advisory, and admissions stay empty — the two
	// surfaces must agree.
	cmds := []string{
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
		"set routing-instances riA instance-type virtual-router",
		"set routing-instances riA interface ge-0/0/0.0",
		"set routing-instances riB instance-type virtual-router",
		"set routing-instances riB interface ge-0/0/0.0",
		"set firewall family inet filter f1 term t1 from source-address 192.0.2.0/24",
		"set firewall family inet filter f1 term t1 then routing-instance riA",
	}
	cfg, err := CompileConfigLenient(buildTree(t, cmds))
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "NOT session-isolated") {
			t.Fatalf("stale pre-quarantine overlap warning survived dual-claim quarantine: %q (warnings=%v)", w, cfg.Warnings)
		}
	}
	if adm := TolerantVRFOverlapAdmissions(cfg); len(adm) != 0 {
		t.Fatalf("admissions must be empty after quarantine, got %+v", adm)
	}
}

func TestVRFOverlapPrimaryClaimCountsNatively_13098(t *testing.T) {
	// A retained primary claim (surviving fanout of a partially quarantined
	// bare member) is effective membership: its unit addresses must count
	// as native space for the instance. Build the post-quarantine shape
	// directly: riA's Interfaces empty, claim on ge-0/0/0 (unit 0 at
	// 10.0.0.1/24); riB member ge-0/0/1.0 at 10.0.0.2/24; live PBR steer.
	// Without claim collection the detector sees only riB and reports
	// nothing; with it the overlap surfaces as warning + admission.
	cfg := &Config{}
	cfg.Interfaces.Interfaces = map[string]*InterfaceConfig{
		"ge-0/0/0": {Name: "ge-0/0/0", Units: map[int]*InterfaceUnit{
			0: {Number: 0, Addresses: []string{"10.0.0.1/24"}},
		}},
		"ge-0/0/1": {Name: "ge-0/0/1", Units: map[int]*InterfaceUnit{
			0: {Number: 0, Addresses: []string{"10.0.0.2/24"}},
		}},
	}
	cfg.RoutingInstances = []*RoutingInstanceConfig{
		{Name: "riA", InstanceType: "virtual-router"},
		{Name: "riB", InstanceType: "virtual-router", Interfaces: []string{"ge-0/0/1.0"}},
	}
	cfg.QuarantinedRIMemberPrimaryClaims = []RoutingInstanceMemberPrimaryClaim{
		{Instance: "riA", InterfaceKey: "ge-0/0/0", LinuxName: "ge-0-0-0"},
	}
	cfg.Firewall.FiltersInet = map[string]*FirewallFilter{
		"f1": {Name: "f1", Terms: []*FirewallFilterTerm{
			{Name: "t1", RoutingInstance: "riA", SourceAddresses: []string{"192.0.2.0/24"}},
		}},
	}
	warnings, admissions, err := validateVRFOverlap(cfg, true)
	if err != nil {
		t.Fatalf("validateVRFOverlap: %v", err)
	}
	if len(warnings) == 0 || len(admissions) == 0 {
		t.Fatalf("retained primary claim address space invisible to detector: warnings=%v admissions=%v", warnings, admissions)
	}
}
