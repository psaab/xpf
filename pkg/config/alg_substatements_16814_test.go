package config

import (
	"fmt"
	"strings"
	"testing"
)

func TestALGKnownSubstatements16814(t *testing.T) {
	// Independent inventory from Juniper's class CLI references and SIP
	// hierarchy (linked in docs/log/16814.md), not generated from the schema.
	rows := map[string][]string{
		"dns":  {"doctoring sanity-check", "maximum-message-length 512", "oversize-message-drop", "traceoptions flag all"},
		"ftp":  {"allow-mismatch-ip-address", "ftps-extension", "line-break-extension", "traceoptions flag all"},
		"sip":  {"application-screen unknown-message permit-routed", "bulk-call-mode", "c-timeout 180", "distribution-ip 192.0.2.1", "dscp-rewrite code-point 101010", "enable-call-distribution", "hide-via-headers", "inactive-media-timeout 90", "maximum-call-duration 600", "retain-hold-resource", "t1-interval 500", "t4-interval 5000", "traceoptions flag all"},
		"tftp": {"traceoptions flag all"},
		"pptp": {"traceoptions flag all"},
	}
	for proto, bodies := range rows {
		for _, body := range bodies {
			for _, shape := range []string{"set", "braced", "packed"} {
				t.Run(proto+"/"+body+"/"+shape, func(t *testing.T) {
					var tree *ConfigTree
					switch shape {
					case "set":
						tree = parseSetCommands(t, "set security alg "+proto+" "+body)
					case "braced":
						tree = parseHierText(t, fmt.Sprintf("security { alg { %s { %s; } } }", proto, body))
					case "packed":
						tree = parseHierText(t, fmt.Sprintf("security { alg %s %s; }", proto, body))
					}
					if err := SchemaValidate(tree); err != nil {
						t.Fatal(err)
					}
					cfg := compileTreeStrictKit(t, tree)
					want := proto + " " + strings.Fields(body)[0]
					if got := cfg.Security.ALG.InertSubstatements; len(got) != 1 || got[0] != want {
						t.Fatalf("inert labels = %v; want %q", got, want)
					}
				})
			}
		}
	}
}

func TestALGDisableNoInertAdvisory16814(t *testing.T) {
	for _, proto := range ALGModeledProtos() {
		t.Run(proto, func(t *testing.T) {
			tree := parseSetCommands(t, "set security alg "+proto+" disable")
			if err := SchemaValidate(tree); err != nil {
				t.Fatal(err)
			}
			cfg := compileTreeStrictKit(t, tree)
			if !cfg.Security.ALG.ALGDisabled(proto) {
				t.Fatal("disable lost")
			}
			if len(cfg.Security.ALG.InertSubstatements) != 0 || strings.Contains(strings.Join(cfg.Warnings, "\n"), "#16814") {
				t.Fatalf("false inert advisory: %v", cfg.Warnings)
			}
		})
	}
}

func TestALGLegacyDisableScan16814(t *testing.T) {
	for _, proto := range ALGModeledProtos() {
		t.Run(proto, func(t *testing.T) {
			tree := parseHierText(t, fmt.Sprintf("security { alg %s bogus disable; }", proto))
			if err := SchemaValidate(tree); err == nil {
				t.Fatal("unknown statement must still reject at strict admission")
			}
			cfg := compileTreeLenientKit(t, tree)
			if !cfg.Security.ALG.ALGDisabled(proto) {
				t.Fatal("legacy tolerant disable scan regressed")
			}
		})
	}
}
