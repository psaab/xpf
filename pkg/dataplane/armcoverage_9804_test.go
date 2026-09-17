package dataplane

import (
	"strings"
	"testing"
)

// TestArmCoverageTreatsKnownRawL3AsReportedSkip9804 binds the #9804 decision:
// a healthy Ethernet surface is direct, while the #8279 raw-L3 refusal stays
// visible and counted but is excluded from the arm verdict. The refusal is
// StillForwarding because the kernel can route it; Unshimmable is the separate,
// closed classification that says an Ethernet parser cannot safely attach.
func TestArmCoverageTreatsKnownRawL3AsReportedSkip9804(t *testing.T) {
	r := newProofResult([]int{10})
	r.recordUnarmedSurface(nonEthernetSurfaceRecord("gr-0-0-0", 11, "none"))

	rep := classifyArmCoverage(r, lookupFrom(map[int]uint32{10: 7}, nil))
	if !rep.Ran || rep.Direct != 1 || rep.Skipped != 1 || rep.Uncovered != 0 || rep.WouldGate {
		t.Fatalf("healthy GRE report must be complete while retaining the refusal: %+v", rep)
	}
	if len(rep.Surfaces) != 2 {
		t.Fatalf("healthy GRE report lost a surface: %+v", rep.Surfaces)
	}
	var found *SurfaceCoverage
	for i := range rep.Surfaces {
		if rep.Surfaces[i].Name == "gr-0-0-0" {
			found = &rep.Surfaces[i]
		}
	}
	if found == nil {
		t.Fatalf("healthy GRE refusal was not reported: %q", rep.SurfaceSummary())
	}
	if found.Kind != CoverageSkipped {
		t.Fatalf("raw-L3 refusal must be a reported skip, got %+v", *found)
	}
	if !strings.Contains(rep.SurfaceSummary(), "gr-0-0-0:skipped/unshimmable") {
		t.Fatalf("surface summary must distinguish the unshimmable refusal: %q", rep.SurfaceSummary())
	}
	if !strings.Contains(found.Detail, "link-layer type none is not Ethernet") ||
		!strings.Contains(found.Detail, "#8279") {
		t.Fatalf("operator-facing refusal reason was lost: %q", found.Detail)
	}
}

// TestArmCoverageUnshimmableKindsAreClosed9804 prevents the GRE exemption from
// becoming an any-non-Ethernet escape hatch. Only the verified netlink values
// receive Unshimmable; a future spelling remains uncovered and fail-closed.
func TestArmCoverageUnshimmableKindsAreClosed9804(t *testing.T) {
	for _, tc := range []struct {
		encap string
		want  bool
	}{
		{encap: "none", want: true},
		{encap: "loopback", want: true},
		{encap: "sit", want: true},
		{encap: "ipip", want: true},
		{encap: "tunnel6", want: true},
		{encap: "gre", want: true},
		{encap: "tunnel", want: false},
		{encap: "ipgre", want: false},
		{encap: "ether", want: false},
		{encap: "future-raw-l3", want: false},
		{encap: "ip6gre", want: false},
		{encap: "ETHER", want: false},
	} {
		t.Run(tc.encap, func(t *testing.T) {
			r := newProofResult([]int{10})
			r.recordUnarmedSurface(nonEthernetSurfaceRecord("surface0", 11, tc.encap))
			rep := classifyArmCoverage(r, lookupFrom(map[int]uint32{10: 7}, nil))
			gotExempt := rep.Skipped == 1 && rep.Uncovered == 0 && !rep.WouldGate
			if gotExempt != tc.want {
				t.Fatalf("encap %q exemption=%v, want %v; report=%+v", tc.encap, gotExempt, tc.want, rep)
			}
		})
	}
}

// TestArmCoverageDuplicateUnknownRawL3CannotRemainExempt9804 prevents an
// unshimmable first sighting from masking a later, less-specific observation.
func TestArmCoverageDuplicateUnknownRawL3CannotRemainExempt9804(t *testing.T) {
	r := newProofResult([]int{10})
	r.recordUnarmedSurface(nonEthernetSurfaceRecord("surface0", 11, "none"))
	r.recordUnarmedSurface(nonEthernetSurfaceRecord("surface0", 11, "future-raw-l3"))

	rep := classifyArmCoverage(r, lookupFrom(map[int]uint32{10: 7}, nil))
	if rep.Uncovered != 1 || rep.Skipped != 0 || !rep.WouldGate {
		t.Fatalf("a conflicting duplicate must remain uncovered and gate: %+v", rep)
	}
}

// TestArmCoverageCleanThenRawL3CannotGainExemption9804 pins the replacement
// branch: a later forwarding sighting must not turn an earlier non-exempt
// observation into a skipped surface.
func TestArmCoverageCleanThenRawL3CannotGainExemption9804(t *testing.T) {
	r := newProofResult([]int{10})
	r.recordUnarmedSurface(UnarmedSurface{
		Name:    "surface0",
		Ifindex: 11,
		Reason:  "surface was proven down",
	})
	r.recordUnarmedSurface(nonEthernetSurfaceRecord("surface0", 11, "none"))

	rep := classifyArmCoverage(r, lookupFrom(map[int]uint32{10: 7}, nil))
	if rep.Uncovered != 1 || rep.Skipped != 0 || !rep.WouldGate {
		t.Fatalf("clean then raw-L3 sighting must remain uncovered and gate: %+v", rep)
	}
}

// TestArmCoverageUnknownNonEthernetStillGates9804 pins the fail-closed side of
// the closed match. A refusal carrying an unrecognised framing value is not
// silently promoted to a healthy GRE result.
func TestArmCoverageUnknownNonEthernetStillGates9804(t *testing.T) {
	r := newProofResult([]int{10})
	r.recordUnarmedSurface(nonEthernetSurfaceRecord("mystery0", 11, "future-raw-l3"))

	rep := classifyArmCoverage(r, lookupFrom(map[int]uint32{10: 7}, nil))
	if rep.Uncovered != 1 || rep.Skipped != 0 || !rep.WouldGate {
		t.Fatalf("unknown non-Ethernet framing must remain uncovered and gate: %+v", rep)
	}
}
