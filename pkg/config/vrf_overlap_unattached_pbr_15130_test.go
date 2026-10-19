package config

import (
	"bufio"
	"os"
	"strings"
	"testing"
)

// #15130 (A92-01): validateVRFOverlap source 2 counted `then routing-instance`
// terms of UNATTACHED filters. A dormant filter therefore set
// sawPBRRoutingInstance and contributed steered prefixes, so an unrelated
// native overlap was refused (and metered as a tolerant admission) even
// though the builder installs no rule for the dormant filter (#3430 moved
// the builder to attached-only). The shipped FBF lab overlay cannot commit
// on its documented base for exactly this reason: reth1.0 is rebound from
// sfmix-pbr to fbf-steer, leaving sfmix-pbr dormant while its steering term
// still counted.
//
// Fix direction: restrict source 2 to filters attached as interface-unit
// INPUT filters, including #11321 FBF-member clones (attached under their
// clone name) and apply-groups/${node} attachments (both are plain
// FilterInputV4/V6 bindings on the compiled config).

// unattached15130 fixture: native overlap on RI-A/RI-B plus a dormant PBR
// filter fbf (steers 10.0.0.0/24 into RI-A). attached adds the input
// attachment on an unrelated default-instance interface.
func unattachedLines15130(attached bool) []string {
	lines := []string{
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.0.1/24",
		"set interfaces ge-0/0/2 unit 0 family inet address 10.0.0.2/24",
		"set interfaces ge-0/0/3 unit 0 family inet address 192.168.3.1/24",
		"set routing-instances RI-A instance-type virtual-router",
		"set routing-instances RI-A interface ge-0/0/1.0",
		"set routing-instances RI-B instance-type virtual-router",
		"set routing-instances RI-B interface ge-0/0/2.0",
		"set firewall family inet filter fbf term t1 from source-address 10.0.0.0/24",
		"set firewall family inet filter fbf term t1 then routing-instance RI-A",
		"set firewall family inet filter fbf term d then accept",
	}
	if attached {
		lines = append(lines,
			"set interfaces ge-0/0/3 unit 0 family inet filter input fbf")
	}
	return lines
}

func TestVRFOverlapUnattachedPBRDoesNotReject_15130(t *testing.T) {
	// Unattached: <nil> — strict commits with the plain native-overlap
	// warning, and the tolerant path records no admission.
	refused, warnings, admissions := vrfVerdict9809(t, unattachedLines15130(false))
	if refused {
		t.Fatal("dormant (unattached) PBR filter must not trigger the #7924 rejection (#15130)")
	}
	if warnings != 1 {
		t.Fatalf("plain native overlap must still warn once, got %d warnings", warnings)
	}
	if admissions != 0 {
		t.Fatalf("dormant PBR filter must not create a tolerant admission, got %d", admissions)
	}

	// Attached twin: still refuses, and the tolerant path meters it.
	refused, _, admissions = vrfVerdict9809(t, unattachedLines15130(true))
	if !refused {
		t.Fatal("attached PBR filter must still trigger the #7924 rejection (#15130 control)")
	}
	if admissions == 0 {
		t.Fatal("attached PBR overlap must record a tolerant admission (#15130 control)")
	}
}

// Steered-space variant: the dormant filter alone creates the steered
// overlap (no native overlap pairs with it once it is ignored).
func TestVRFOverlapDormantSteeredSpaceInvisible_15130(t *testing.T) {
	lines := []string{
		"set interfaces ge-0/0/1 unit 0 family inet address 192.168.1.1/24",
		"set interfaces ge-0/0/2 unit 0 family inet address 192.168.2.1/24",
		"set routing-instances FA instance-type forwarding",
		"set routing-instances FB instance-type forwarding",
		"set firewall family inet filter fa term t from source-address 10.1.0.0/16",
		"set firewall family inet filter fa term t then routing-instance FA",
		"set firewall family inet filter fa term d then accept",
		"set firewall family inet filter fb term t from source-address 10.1.0.0/16",
		"set firewall family inet filter fb term t then routing-instance FB",
		"set firewall family inet filter fb term d then accept",
		"set interfaces ge-0/0/1 unit 0 family inet filter input fa",
		// fb deliberately NOT attached.
	}
	refused, warnings, admissions := vrfVerdict9809(t, lines)
	if refused || warnings != 0 || admissions != 0 {
		t.Fatalf("dormant fb steered space must be invisible: refused=%v warnings=%d admissions=%d",
			refused, warnings, admissions)
	}
	// Control: attach fb -> cross-filter steered overlap refuses.
	lines = append(lines, "set interfaces ge-0/0/2 unit 0 family inet filter input fb")
	refused, _, admissions = vrfVerdict9809(t, lines)
	if !refused || admissions == 0 {
		t.Fatalf("attached fb must refuse and meter: refused=%v admissions=%d", refused, admissions)
	}
}

// Output-only attachment is not FBF (#3432): the direction gate rejects it
// strictly, but the tolerant path keeps it compiled — the overlap detector
// must still not count it (the builder installs no steering rule for it).
func TestVRFOverlapOutputOnlyPBRDoesNotCount_15130(t *testing.T) {
	lines := unattachedLines15130(false)
	lines = append(lines,
		"set interfaces ge-0/0/3 unit 0 family inet filter output fbf")
	// The tolerant compile is the surface that matters here: the #3432
	// direction gate refuses this shape strictly, but lenient load keeps
	// it compiled — and the detector must record no admission for it.
	lcfg, err := CompileConfigLenient(buildTree(t, lines))
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	if adm := TolerantVRFOverlapAdmissions(lcfg); len(adm) != 0 {
		t.Fatalf("output-only PBR filter must not create a tolerant admission, got %+v", adm)
	}
}

// A filter attached via apply-groups (compiled FilterInputV4 binding) counts
// exactly like a directly attached one.
func TestVRFOverlapGroupAttachedPBRCounts_15130(t *testing.T) {
	lines := unattachedLines15130(false)
	lines = append(lines,
		"set groups g interfaces ge-0/0/3 unit 0 family inet filter input fbf",
		"set apply-groups g",
	)
	refused, _, admissions := vrfVerdict9809(t, lines)
	if !refused {
		t.Fatal("group-attached PBR must still trigger the #7924 rejection (#15130)")
	}
	if admissions == 0 {
		t.Fatal("group-attached PBR overlap must record a tolerant admission (#15130)")
	}
}

// Real-base pin: docs/ha-cluster-userspace.conf + the FBF overlay
// (test/incus/fbf-two-upstream-config.set) must commit on nodes 0 and 1.
// The overlay rebinds reth1.0 input to fbf-steer/fbf-steer6, leaving the
// base's sfmix-pbr (steers 10.255.192.40/30 into sfmix) dormant; sfmix's
// member gr-0/0/0.0 carries 10.255.192.42/30, so counting the dormant term
// manufactured the overlap+PBR refusal.
func TestFBFOverlayOnShippedBaseCommits_15130(t *testing.T) {
	raw, err := os.ReadFile("../../docs/ha-cluster-userspace.conf")
	if err != nil {
		t.Fatalf("read base: %v", err)
	}
	f, err := os.Open("../../test/incus/fbf-two-upstream-config.set")
	if err != nil {
		t.Fatalf("open overlay: %v", err)
	}
	defer f.Close()
	var overlay []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		overlay = append(overlay, line)
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}

	for _, nodeID := range []int{0, 1} {
		tree := hierTree(t, string(raw))
		for _, line := range overlay {
			path, err := ParseSetCommand(line)
			if err != nil {
				t.Fatalf("ParseSetCommand(%q): %v", line, err)
			}
			if err := tree.SetPath(path); err != nil {
				t.Fatalf("SetPath(%q): %v", line, err)
			}
		}
		cfg, err := CompileConfigForNode(tree, nodeID)
		if err != nil {
			t.Fatalf("node %d: shipped base + FBF overlay must commit: %v", nodeID, err)
		}
		// Preconditions: the overlay really rebound reth1.0 (so sfmix-pbr
		// really is dormant), and the dormant filter still exists.
		reth1 := cfg.Interfaces.Interfaces["reth1"]
		if reth1 == nil || reth1.Units[0] == nil ||
			reth1.Units[0].FilterInputV4 != "fbf-steer" ||
			reth1.Units[0].FilterInputV6 != "fbf-steer6" {
			t.Fatalf("node %d: overlay did not rebind reth1.0: %+v", nodeID, reth1)
		}
		if cfg.Firewall.FiltersInet["sfmix-pbr"] == nil {
			t.Fatalf("node %d: dormant sfmix-pbr filter missing", nodeID)
		}
		if adm := TolerantVRFOverlapAdmissions(cfg); len(adm) != 0 {
			t.Fatalf("node %d: dormant sfmix-pbr must not meter an admission: %+v", nodeID, adm)
		}
	}
}
