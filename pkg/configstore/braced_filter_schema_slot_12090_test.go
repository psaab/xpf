package configstore

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestBracedFilterSchemaSlotsReject12090(t *testing.T) {
	cases := []struct {
		name string
		text string
	}{
		{
			name: "interface-unit-identity",
			text: "interfaces { ge-0/0/0 { unit { 0 filter input f; } } }",
		},
		{
			name: "sampling-instance-identity",
			text: "forwarding-options { sampling { instance { s filter input f; } } }",
		},
		{
			name: "relay-group-identity",
			text: "forwarding-options { dhcp-relay { server-group sg { 10.0.0.1; } group { lan filter input f; lan { active-server-group sg; interface ge-0/0/0.0; } } } }",
		},
		{
			name: "flat-unit-control",
			text: "interfaces { ge-0/0/0 { unit 0 filter input f; } }",
		},
		{
			name: "fully-braced-unit-control",
			text: "interfaces { ge-0/0/0 { unit { 0 { filter input f; } } } }",
		},
		{
			name: "flat-instance-control",
			text: "forwarding-options { sampling { instance s filter input f; } }",
		},
		{
			name: "fully-braced-instance-control",
			text: "forwarding-options { sampling { instance { s { filter input f; } } } }",
		},
		{
			name: "relay-filter-child-control",
			text: "forwarding-options { dhcp-relay { server-group sg { 10.0.0.1; } group lan { active-server-group sg; interface ge-0/0/0.0; filter { input f; } } } }",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := CheckText(tc.text, -1); err == nil || !strings.Contains(err.Error(), "#12090") {
				t.Fatalf("CheckText error = %v; want #12090 rejection", err)
			}

			tree, parseErrors := config.NewParser(tc.text).Parse()
			if len(parseErrors) != 0 {
				t.Fatalf("parse test config: %v", parseErrors)
			}
			compiled, err := config.CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("lenient compile: %v", err)
			}
			warned := false
			for _, warning := range compiled.Warnings {
				if strings.Contains(warning, "#12090") {
					warned = true
					break
				}
			}
			if !warned {
				t.Fatalf("lenient compile warnings = %q; want #12090", compiled.Warnings)
			}

			store := newTestStoreAt(t, filepath.Join(t.TempDir(), "xpf.conf"))
			if err := store.EnterConfigure(); err != nil {
				t.Fatalf("EnterConfigure: %v", err)
			}
			defer store.ExitConfigure()
			if err := store.LoadOverride(tc.text); err != nil {
				t.Fatalf("LoadOverride: %v", err)
			}
			if _, err := store.Commit(); err == nil || !strings.Contains(err.Error(), "#12090") {
				t.Fatalf("Store Commit error = %v; want #12090 rejection", err)
			}
		})
	}
}
