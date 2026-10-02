package config

import (
	"encoding/json"
	"reflect"
	"testing"
)

func parseJSON11371(t *testing.T, source string) *ConfigTree {
	t.Helper()
	tree, errs := NewParser(source).Parse()
	if len(errs) != 0 {
		t.Fatalf("parse configuration: %v", errs)
	}
	return tree
}

func assertJSONEqual11371(t *testing.T, gotJSON, wantJSON string) {
	t.Helper()
	var got, want interface{}
	if err := json.Unmarshal([]byte(gotJSON), &got); err != nil {
		t.Fatalf("invalid rendered JSON: %v\n%s", err, gotJSON)
	}
	if err := json.Unmarshal([]byte(wantJSON), &want); err != nil {
		t.Fatalf("invalid expected JSON: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("display JSON does not preserve policy structure/order:\n got: %s\nwant: %s", gotJSON, wantJSON)
	}
}

func policyJSON11371(name, terminal string) string {
	return "policy " + name + ` { match { source-address any; destination-address any; application any; } then { ` + terminal + `; } }`
}

func TestFormatJSONZonePolicySiblingOrder11371(t *testing.T) {
	tree := parseJSON11371(t, `security { policies { from-zone trust to-zone untrust { `+
		policyJSON11371("z-deny", "deny")+` `+policyJSON11371("a-permit", "permit")+
		` } } }`)
	assertJSONEqual11371(t, tree.FormatJSON(), `{"security":{"policies":{"from-zone":{"trust to-zone untrust":{"policy":[{"z-deny":{"match":{"source-address":"any","destination-address":"any","application":"any"},"then":{"deny":true}}},{"a-permit":{"match":{"source-address":"any","destination-address":"any","application":"any"},"then":{"permit":true}}}]}}}}}`)
}

func TestFormatJSONGlobalPolicySiblingOrder11371(t *testing.T) {
	tree := parseJSON11371(t, `security { policies { global { `+
		policyJSON11371("z-global", "deny")+` `+policyJSON11371("a-global", "permit")+
		` } } }`)
	assertJSONEqual11371(t, tree.FormatJSON(), `{"security":{"policies":{"global":{"policy":[{"z-global":{"match":{"source-address":"any","destination-address":"any","application":"any"},"then":{"deny":true}}},{"a-global":{"match":{"source-address":"any","destination-address":"any","application":"any"},"then":{"permit":true}}}]}}}}`)
}

func TestFormatJSONSingletonPolicyArray11371(t *testing.T) {
	tree := parseJSON11371(t, `security { policies { from-zone trust to-zone untrust { `+
		policyJSON11371("only-policy", "deny")+` } } }`)
	assertJSONEqual11371(t, tree.FormatJSON(), `{"security":{"policies":{"from-zone":{"trust to-zone untrust":{"policy":[{"only-policy":{"match":{"source-address":"any","destination-address":"any","application":"any"},"then":{"deny":true}}}]}}}}}`)
}

func TestFormatPathJSONPolicySiblingOrder11371(t *testing.T) {
	tree := parseJSON11371(t, `security { policies { from-zone trust to-zone untrust { `+
		policyJSON11371("z-deny", "deny")+` `+policyJSON11371("a-permit", "permit")+
		` } } }`)
	got := tree.FormatPathJSON([]string{"security", "policies", "from-zone", "trust", "to-zone", "untrust", "policy"})
	assertJSONEqual11371(t, got, `{"policy":[{"z-deny":{"match":{"source-address":"any","destination-address":"any","application":"any"},"then":{"deny":true}}},{"a-permit":{"match":{"source-address":"any","destination-address":"any","application":"any"},"then":{"permit":true}}}]}`)
}

func TestFormatJSONRepeatedZonePolicyContextKeepsOrder11371(t *testing.T) {
	tree := parseJSON11371(t, `security { policies {
		from-zone trust to-zone untrust { `+policyJSON11371("z-deny", "deny")+` }
		from-zone trust to-zone untrust { `+policyJSON11371("a-permit", "permit")+` }
	} }`)
	assertJSONEqual11371(t, tree.FormatJSON(), `{"security":{"policies":{"from-zone":{"trust to-zone untrust":{"policy":[{"z-deny":{"match":{"source-address":"any","destination-address":"any","application":"any"},"then":{"deny":true}}},{"a-permit":{"match":{"source-address":"any","destination-address":"any","application":"any"},"then":{"permit":true}}}]}}}}}`)
}
