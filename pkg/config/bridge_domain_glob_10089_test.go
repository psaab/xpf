package config

import (
	"strings"
	"testing"
)

func TestBridgeDomainNameRejectsGlobMetacharacters_10089(t *testing.T) {
	for _, tc := range []struct {
		name, token string
	}{
		{"ge*", "*"},
		{"ge?", "?"},
		{"ge[0-9]", "["},
		{"ge]0", "]"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path, err := ParseSetCommand(`set bridge-domains "` + tc.name + `" vlan-id-list 10`)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			tr := &ConfigTree{}
			if err := tr.SetPath(path); err != nil {
				t.Fatalf("setpath: %v", err)
			}
			err = SchemaValidate(tr, nil)
			if err == nil {
				t.Fatal("#10089: bridge-domain glob must be rejected at strict validation")
			}
			for _, want := range []string{"#10089", "glob metacharacter", `"` + tc.token + `"`} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("#10089: error %q must mention %q", err, want)
				}
			}
		})
	}

	plain, err := ParseSetCommand(`set bridge-domains bd0 vlan-id-list 10`)
	if err != nil {
		t.Fatalf("plain parse: %v", err)
	}
	plainTree := &ConfigTree{}
	if err := plainTree.SetPath(plain); err != nil {
		t.Fatalf("plain setpath: %v", err)
	}
	if err := SchemaValidate(plainTree, nil); err != nil {
		t.Fatalf("#10089: valid bridge-domain name must remain accepted: %v", err)
	}
}

func TestBridgeDomainNameWhitespaceStays9494_10089(t *testing.T) {
	path, err := ParseSetCommand(`set bridge-domains "ge 0" vlan-id-list 10`)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	tr := &ConfigTree{}
	if err := tr.SetPath(path); err != nil {
		t.Fatalf("setpath: %v", err)
	}
	err = SchemaValidate(tr, nil)
	if err == nil || !strings.Contains(err.Error(), "whitespace") {
		t.Fatalf("#9494: whitespace bridge-domain name must remain rejected as whitespace, got %v", err)
	}
	if strings.Contains(err.Error(), "#10089") {
		t.Fatalf("#10089: whitespace bridge-domain name must stay in #9494's scope, got %v", err)
	}
}
