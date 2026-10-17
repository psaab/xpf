package config

import (
	"strings"
	"testing"
)

// #14377: a padded BGP cluster-id / local-address passes the validator (which
// trimmed before parsing) but is silently omitted by the renderer (which
// validates the RAW string: validClusterID / frrOperandOrOmit reject any
// whitespace). The route reflector therefore runs with no cluster-id (falls
// back to router-id, defeating RR loop prevention) and the BGP session loses
// its update-source, on a GREEN commit. Refuse padding at SchemaValidate so
// the operator fixes the spelling; controls (bare values) must stay green.
//
// Padding is authorable through ordinary ingress: quoted strings preserve
// their contents verbatim (`cluster-id " 10.0.0.1 "`), mirroring #9820.
//
// FAIL-ON-REVERT: dropping the `trimmed != raw` arm in ValidateBGPClusterID,
// or reverting either BGP `local-address` leaf to ValidateIPAddress (which
// trims), makes the padded cases below commit clean again -> RED.

func TestBGPPaddedClusterIDSchemaGate_14377(t *testing.T) {
	padded := []string{" 10.0.0.1 ", " 42 ", " 10.0.0.1", "42 ", "\t10.0.0.1\t"}
	for _, v := range padded {
		tree := flatTreeFromSets(t, "set protocols bgp local-as 65001",
			`set protocols bgp cluster-id "`+v+`"`)
		if err := SchemaValidate(tree, nil); err == nil {
			t.Errorf("cluster-id %q: expected SchemaValidate to reject padded value, got nil", v)
		}
		if err := ValidateBGPClusterID(v, nil); err == nil {
			t.Errorf("ValidateBGPClusterID(%q) = nil, want padded rejection", v)
		}
	}
	// Controls: bare valid forms still commit.
	for _, v := range []string{"10.0.0.1", "42", "1", "4294967295", "0.0.0.0"} {
		tree := flatTreeFromSets(t, "set protocols bgp local-as 65001",
			"set protocols bgp cluster-id "+v)
		if err := SchemaValidate(tree, nil); err != nil {
			t.Errorf("control cluster-id %q: expected accept, got %v", v, err)
		}
	}
	// Error names the padded value so the operator sees what to fix.
	tree := flatTreeFromSets(t, "set protocols bgp local-as 65001",
		`set protocols bgp cluster-id " 10.0.0.1 "`)
	err := SchemaValidate(tree, nil)
	if err == nil || !strings.Contains(err.Error(), " 10.0.0.1 ") {
		t.Errorf("padded cluster-id error must name the value, got %v", err)
	}
}

func TestBGPPaddedLocalAddressSchemaGate_14377(t *testing.T) {
	// Both BGP local-address leaves (group-level and neighbor-level) render
	// through frrOperandOrOmit, which drops a padded update-source silently.
	sets := [][]string{
		{"set protocols bgp local-as 65001", `set protocols bgp group G local-address " 10.0.0.1 "`},
		{"set protocols bgp local-as 65001", "set protocols bgp group G peer-as 65002",
			`set protocols bgp group G neighbor 10.0.0.2 local-address " 10.0.0.1 "`},
	}
	for _, s := range sets {
		tree := flatTreeFromSets(t, s...)
		if err := SchemaValidate(tree, nil); err == nil {
			t.Errorf("padded local-address %v: expected SchemaValidate to reject, got nil", s)
		}
	}
	// Direct validator cells.
	for _, v := range []string{" 10.0.0.1 ", " 10.0.0.1", "10.0.0.1 ", " 2001:db8::1 "} {
		if err := ValidateBGPLocalAddress(v, nil); err == nil {
			t.Errorf("ValidateBGPLocalAddress(%q) = nil, want padded rejection", v)
		}
	}
	// Controls: bare v4 and v6 addresses still validate (both leaves accept
	// either family through ValidateIPAddress).
	for _, v := range []string{"10.0.0.1", "2001:db8::1"} {
		if err := ValidateBGPLocalAddress(v, nil); err != nil {
			t.Errorf("control ValidateBGPLocalAddress(%q) = %v, want nil", v, err)
		}
		for _, s := range [][]string{
			{"set protocols bgp local-as 65001", "set protocols bgp group G local-address " + v},
			{"set protocols bgp local-as 65001", "set protocols bgp group G peer-as 65002",
				"set protocols bgp group G neighbor 10.0.0.2 local-address " + v},
		} {
			tree := flatTreeFromSets(t, s...)
			if err := SchemaValidate(tree, nil); err != nil {
				t.Errorf("control local-address %q %v: expected accept, got %v", v, s, err)
			}
		}
	}
	// Non-IP garbage still rejected by the wrapped validator.
	if err := ValidateBGPLocalAddress("not.an.ip", nil); err == nil {
		t.Error("ValidateBGPLocalAddress(not.an.ip) = nil, want error")
	}
	// The generic ValidateIPAddress keeps its prior trimmed leniency for its
	// many non-BGP leaves: this fix is scoped to the BGP leaves, so a padded
	// generic value is not re-litigated here.
	if err := ValidateIPAddress(" 10.0.0.1 ", nil); err != nil {
		t.Errorf("ValidateIPAddress padded = %v, want nil (scoped fix; other leaves unchanged)", err)
	}
}
