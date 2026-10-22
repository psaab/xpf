package config

import (
	"strings"
	"testing"
)

// TestBGPClusterID_SchemaGate_4919 proves the #4919 commit-check fix: the
// `protocols bgp cluster-id` value is typed so a token FRR/vtysh would reject
// (`not.an.ip`, an IPv6 literal, `0`, an out-of-range integer, or an
// embedded-space injection) is REJECTED at commit-check (SchemaValidate)
// instead of committing verbatim and poisoning the frr-reload. The two forms
// FRR accepts — an IPv4 dotted-quad and a 32-bit integer 1..4294967295 — pass.
//
// FAIL-ON-REVERT: dropping `valueType/validator: ValidateBGPClusterID` from the
// cluster-id leaf makes the untyped leaf accept any token again, so the reject
// assertions below fire RED.
func TestBGPClusterID_SchemaGate_4919(t *testing.T) {
	bad := []string{"not.an.ip", "2001:db8::1", "0", "4294967296", "10.0.0.256", "abc", "1 2"}
	good := []string{"10.0.0.1", "1", "4294967295", "0.0.0.0"}

	for _, v := range bad {
		tree := flatTreeFromSets(t, "set protocols bgp local-as 65001",
			"set protocols bgp cluster-id "+v)
		if err := SchemaValidate(tree); err == nil {
			t.Fatalf("cluster-id %q: expected SchemaValidate to reject, got nil", v)
		}
	}
	for _, v := range good {
		tree := flatTreeFromSets(t, "set protocols bgp local-as 65001",
			"set protocols bgp cluster-id "+v)
		if err := SchemaValidate(tree); err != nil {
			t.Fatalf("cluster-id %q: expected SchemaValidate to accept, got %v", v, err)
		}
	}
}

// TestBGPOrigin_SchemaGate_4919 proves the #4919 commit-check fix for the
// route-map `then origin` leaf: only igp | egp | incomplete are accepted; a
// non-control typo (`igpp`) that previously passed the #4498 sanitize belt and
// failed the FRR route-map grammar is now rejected at commit.
//
// FAIL-ON-REVERT: dropping the ValidateEnum validator from the origin leaf
// makes the untyped leaf accept `igpp` again → RED.
func TestBGPOrigin_SchemaGate_4919(t *testing.T) {
	base := "set policy-options policy-statement P term t1 "
	bad := []string{"igpp", "IGP", "internal", "0", "egpp"}
	good := []string{"igp", "egp", "incomplete"}

	for _, v := range bad {
		tree := flatTreeFromSets(t, base+"then origin "+v)
		if err := SchemaValidate(tree); err == nil {
			t.Fatalf("then origin %q: expected SchemaValidate to reject, got nil", v)
		}
	}
	for _, v := range good {
		tree := flatTreeFromSets(t, base+"then origin "+v)
		if err := SchemaValidate(tree); err != nil {
			t.Fatalf("then origin %q: expected SchemaValidate to accept, got %v", v, err)
		}
	}
}

// TestBGPClusterIDOrigin_ErrorNamesValue_4919 confirms the reject errors name
// the offending token.
func TestBGPClusterIDOrigin_ErrorNamesValue_4919(t *testing.T) {
	tree := flatTreeFromSets(t, "set protocols bgp local-as 65001",
		"set protocols bgp cluster-id not.an.ip")
	if err := SchemaValidate(tree); err == nil {
		t.Fatal("expected `cluster-id not.an.ip` to be rejected")
	} else if !strings.Contains(err.Error(), "not.an.ip") {
		t.Fatalf("cluster-id error %q must name 'not.an.ip'", err.Error())
	}

	tree = flatTreeFromSets(t, "set policy-options policy-statement P term t1 then origin igpp")
	if err := SchemaValidate(tree); err == nil {
		t.Fatal("expected `then origin igpp` to be rejected")
	} else if !strings.Contains(err.Error(), "igpp") {
		t.Fatalf("origin error %q must name 'igpp'", err.Error())
	}
}

// TestValidateBGPClusterID_Unit locks the validator's accept/reject set.
func TestValidateBGPClusterID_Unit(t *testing.T) {
	for _, v := range []string{"10.0.0.1", "192.0.2.255", "1", "65535", "4294967295", "0.0.0.0"} {
		if err := ValidateBGPClusterID(v); err != nil {
			t.Errorf("ValidateBGPClusterID(%q) = %v, want nil", v, err)
		}
	}
	for _, v := range []string{"", "not.an.ip", "2001:db8::1", "0", "4294967296", "-1", "10.0.0.1/32", "1.2.3"} {
		if err := ValidateBGPClusterID(v); err == nil {
			t.Errorf("ValidateBGPClusterID(%q) = nil, want error", v)
		}
	}
}
