package configstore

import (
	"strings"
	"testing"
)

func TestCheckTextRejectsUncreatableBridgeDomainName16792(t *testing.T) {
	text := "bridge-domains {\n    customer-vlan-100 {\n        vlan-id-list 100;\n    }\n}\n"
	_, err := CheckText(text, -1)
	if err == nil {
		t.Fatal("CheckText accepted bridge-domain whose br- name exceeds IFNAMSIZ")
	}
	for _, part := range []string{"customer-vlan-100", "br-customer-vlan-100", "IFNAMSIZ", "#16792"} {
		if !strings.Contains(err.Error(), part) {
			t.Errorf("error %q missing %q", err, part)
		}
	}
}

func TestCheckTextAcceptsBridgeDomainAtLimit16792(t *testing.T) {
	text := "bridge-domains {\n    abcdefghijkl {\n        vlan-id-list 100;\n    }\n}\n"
	if _, err := CheckText(text, -1); err != nil {
		t.Fatalf("CheckText rejected 12-byte name (br- =15): %v", err)
	}
}
