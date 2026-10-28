package config

import (
	"strings"
	"testing"
)

// #17177 fold (Rev18228 blockers): the validators consumed directly
// by strict compiler gates and render belts must refuse edge
// whitespace themselves, because those consumers run WITHOUT
// SchemaValidate (CompileConfig-only) or parse the RAW string
// (pkg/frr belts). The central refuseEdgeWhitespace gate covers the
// SchemaValidate commit path; these cells pin the direct path.
//
//   - ValidateRouteDestination: consumed by
//     generateRouteInvalidPrefixes / staticRouteInvalidPrefixes.
//   - ValidateOSPFArea: validFRROSPFArea documents commit==render
//     equivalence on this validator alone.
//   - ValidateBGPClusterID: validClusterID parses the raw string.
//   - ValidateStaticNextHop / ValidateDeviceMapLogicalName: the
//     compiler stores the raw token and downstream belts parse it
//     raw, so the validator itself refuses padding.
//   - ValidateBGPNeighborAddress is genuinely independent: it parses
//     the raw string with netip.ParseAddr (no trim), so padding
//     already fails its grammar — no local arm is needed and none is
//     added; the last cell documents that belt.

func TestStrictValidatorsRefusePaddingDirect17177(t *testing.T) {
	paddedCIDRs := []string{" 10.0.0.0/8 ", " 10.0.0.0/8", "10.0.0.0/8 ", "\t2001:db8::/32\t"}
	for _, v := range paddedCIDRs {
		if err := ValidateRouteDestination(v); err == nil {
			t.Errorf("ValidateRouteDestination(%q) = nil, want padded rejection", v)
		}
	}
	if err := ValidateRouteDestination("10.0.0.0/8"); err != nil {
		t.Errorf("ValidateRouteDestination(control) = %v, want nil", err)
	}
	for _, v := range []string{" 0.0.0.0 ", " 0", "0 ", "\t10.1.2.3\t"} {
		if err := ValidateOSPFArea(v); err == nil {
			t.Errorf("ValidateOSPFArea(%q) = nil, want padded rejection", v)
		}
	}
	for _, v := range []string{"0.0.0.0", "0"} {
		if err := ValidateOSPFArea(v); err != nil {
			t.Errorf("ValidateOSPFArea(control %q) = %v, want nil", v, err)
		}
	}
	for _, v := range []string{" 10.0.0.1 ", " 42 ", "42 "} {
		if err := ValidateBGPClusterID(v); err == nil {
			t.Errorf("ValidateBGPClusterID(%q) = nil, want padded rejection", v)
		}
	}
	if err := ValidateBGPClusterID("10.0.0.1"); err != nil {
		t.Errorf("ValidateBGPClusterID(control) = %v, want nil", err)
	}
	for _, v := range []string{" 192.0.2.1 ", " ge-0/0/1 ", "2001:db8::1@eth0 "} {
		if err := ValidateStaticNextHop(v); err == nil {
			t.Errorf("ValidateStaticNextHop(%q) = nil, want padded rejection", v)
		}
	}
	if err := ValidateStaticNextHop("192.0.2.1"); err != nil {
		t.Errorf("ValidateStaticNextHop(control) = %v, want nil", err)
	}
	for _, v := range []string{" ge-0/0/3 ", " fxp0", "fxp0 "} {
		if err := ValidateDeviceMapLogicalName(v); err == nil {
			t.Errorf("ValidateDeviceMapLogicalName(%q) = nil, want padded rejection", v)
		}
	}
	if err := ValidateDeviceMapLogicalName("ge-0/0/3"); err != nil {
		t.Errorf("ValidateDeviceMapLogicalName(control) = %v, want nil", err)
	}
	// Independent belt (no local arm needed): netip.ParseAddr on the
	// raw string already rejects padding.
	if err := ValidateBGPNeighborAddress(" 192.0.2.1 "); err == nil {
		t.Error("ValidateBGPNeighborAddress(padded) = nil, want rejection via raw netip grammar")
	}
	if err := ValidateBGPNeighborAddress("192.0.2.1"); err != nil {
		t.Errorf("ValidateBGPNeighborAddress(control) = %v, want nil", err)
	}
}

// CompileConfig-only (NO SchemaValidate): a padded generate or
// static CIDR must be refused by the strict compiler gates, and a
// bare control must compile. This is the Rev18228 B1 cell: before
// the fold, `route " 10.0.0.0/8 "` compiled, stored the raw prefix,
// and split FRR (omits) from userspace (helper refuses).
func TestCompileConfigPaddedCIDRRefused17177(t *testing.T) {
	// Padded generate route (hierarchical quoted spelling carries
	// the padding verbatim).
	genTree := parseHierText(t, "routing-options {\n generate {\n  route \" 10.0.0.0/8 \" {\n   discard;\n  }\n }\n}\n")
	if _, err := CompileConfig(genTree); err == nil {
		t.Fatal("CompileConfig accepted padded generate prefix without SchemaValidate")
	} else if !strings.Contains(err.Error(), "whitespace") {
		t.Fatalf("CompileConfig padded generate error must name the padding, got: %v", err)
	}
	// Tolerant path warns and keeps the route (#1960).
	lenient, err := CompileConfigLenient(genTree)
	if err != nil {
		t.Fatalf("tolerant compile rejected padded generate prefix: %v", err)
	}
	found := false
	for _, w := range lenient.Warnings {
		if strings.Contains(w, "generate-route prefix") {
			found = true
		}
	}
	if !found {
		t.Fatalf("tolerant compile missing generate-route prefix warning: %v", lenient.Warnings)
	}

	// Padded static destination.
	staticTree := parseHierText(t, "routing-options {\n static {\n  route \" 10.0.0.0/8 \" {\n   discard;\n  }\n }\n}\n")
	if _, err := CompileConfig(staticTree); err == nil {
		t.Fatal("CompileConfig accepted padded static destination without SchemaValidate")
	} else if !strings.Contains(err.Error(), "whitespace") {
		t.Fatalf("CompileConfig padded static error must name the padding, got: %v", err)
	}
	lenient2, err := CompileConfigLenient(staticTree)
	if err != nil {
		t.Fatalf("tolerant compile rejected padded static destination: %v", err)
	}
	found = false
	for _, w := range lenient2.Warnings {
		if strings.Contains(w, "static-route destination") {
			found = true
		}
	}
	if !found {
		t.Fatalf("tolerant compile missing static-route destination warning: %v", lenient2.Warnings)
	}

	// Bare controls compile strict.
	for name, src := range map[string]string{
		"generate": "routing-options {\n generate {\n  route 10.0.0.0/8 {\n   discard;\n  }\n }\n}\n",
		"static":   "routing-options {\n static {\n  route 10.0.0.0/8 {\n   discard;\n  }\n }\n}\n",
	} {
		if _, err := CompileConfig(parseHierText(t, src)); err != nil {
			t.Errorf("%s: bare control rejected by CompileConfig: %v", name, err)
		}
	}
}
