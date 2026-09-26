package configstore

import (
	"strings"
	"testing"
)

func TestCheckTextRejectsJunosAAAStanzas10831(t *testing.T) {
	cases := []struct {
		leaf    string
		command string
	}{
		{"radius-server", "set system radius-server 192.0.2.10 secret example"},
		{"tacplus-server", "set system tacplus-server 192.0.2.20 secret example"},
		{"authentication-order", "set system authentication-order radius"},
	}
	for _, tc := range cases {
		t.Run(tc.leaf, func(t *testing.T) {
			if _, err := CheckText(tc.command, -1); err == nil ||
				!strings.Contains(err.Error(), "local-only authentication") ||
				!strings.Contains(err.Error(), tc.leaf) {
				t.Fatalf("CheckText accepted unsupported %s or omitted the local-only message: %v", tc.leaf, err)
			}
		})
	}
	if _, err := CheckText("set system host-name fw1", -1); err != nil {
		t.Fatalf("control: valid local system config was rejected: %v", err)
	}
}
