package configstore

import (
	"fmt"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestALGSubstatementsCommit16814(t *testing.T) {
	rows := []struct{ proto, body, braced, head string }{
		{"dns", "doctoring none", "doctoring none;", "doctoring"},
		{"dns", "maximum-message-length 8192", "maximum-message-length 8192;", "maximum-message-length"},
		{"ftp", "ftps-extension", "ftps-extension;", "ftps-extension"},
		{"sip", "inactive-media-timeout 90", "inactive-media-timeout 90;", "inactive-media-timeout"},
		{"sip", "application-screen protect deny destination-ip 10.1.1.3", "application-screen { protect { deny { destination-ip 10.1.1.3; } } }", "application-screen"},
		{"pptp", "traceoptions flag all", "traceoptions { flag all; }", "traceoptions"},
		{"tftp", "traceoptions flag all", "traceoptions { flag all; }", "traceoptions"},
	}
	for _, row := range rows {
		for _, shape := range []string{"set", "braced", "packed", "double-packed", "mixed"} {
			t.Run(row.proto+"/"+row.head+"/"+shape, func(t *testing.T) {
				store := newTestStore(t)
				if err := store.EnterConfigure(); err != nil {
					t.Fatal(err)
				}
				if shape == "set" {
					path, err := config.ParseSetCommand("set security alg " + row.proto + " " + row.body)
					if err != nil {
						t.Fatal(err)
					}
					if err := store.Set(path); err != nil {
						t.Fatal(err)
					}
				} else {
					var text string
					switch shape {
					case "braced":
						text = fmt.Sprintf("security { alg { %s { %s } } }", row.proto, row.braced)
					case "packed":
						text = fmt.Sprintf("security { alg { %s %s; } }", row.proto, row.body)
					case "double-packed":
						text = fmt.Sprintf("security { alg %s %s; }", row.proto, row.body)
					case "mixed":
						text = fmt.Sprintf("security { alg %s { %s } }", row.proto, row.braced)
					}
					if err := store.LoadOverride(text); err != nil {
						t.Fatal(err)
					}
				}
				cfg, err := store.Commit()
				if err != nil {
					t.Fatalf("Commit: %v", err)
				}
				warnings := strings.Join(cfg.Warnings, "\n")
				if !strings.Contains(warnings, "security alg "+row.proto+" "+row.head+" accepted but inert") || !strings.Contains(warnings, "no effect (#16814)") {
					t.Fatalf("missing statement-specific advisory: %s", warnings)
				}
				for _, proto := range config.ALGModeledProtos() {
					if cfg.Security.ALG.ALGDisabled(proto) {
						t.Errorf("inert statement disabled %s", proto)
					}
				}
				if len(cfg.Security.ALG.UnsupportedProtos) != 0 {
					t.Fatalf("inert statement misreported as protocol: %+v", cfg.Security.ALG)
				}
			})
		}
	}
}

func TestALGSubstatementTypos16814(t *testing.T) {
	for _, proto := range config.ALGModeledProtos() {
		for _, tmpl := range []string{
			"set security alg %s desable",
			"security { alg { %s { desable; } } }",
			"security { alg { %s desable; } }",
			"security { alg %s desable; }",
			"security { alg %s { desable; } }",
			"security { alg { %s { traceoptions { flag all; } desable; } } }",
		} {
			text := fmt.Sprintf(tmpl, proto)
			t.Run(text, func(t *testing.T) {
				if _, err := CheckText(text, -1); err == nil || !strings.Contains(err.Error(), "desable") {
					t.Fatalf("expected named typo rejection, got %v", err)
				}
			})
		}
	}
}

func TestALGInertBodyDoesNotDisable16814(t *testing.T) {
	for _, text := range []string{
		"security { alg { ftp traceoptions flag disable; } }",
		"security { alg ftp traceoptions flag disable; }",
		"security { alg { ftp traceoptions { disable; } } }",
		"security { alg ftp traceoptions { disable; } }",
	} {
		t.Run(text, func(t *testing.T) {
			cfg, err := CheckText(text, -1)
			if err != nil {
				t.Fatal(err)
			}
			if cfg.Security.ALG.FTPDisable {
				t.Fatal("opaque body changed FTPDisable")
			}
			if !strings.Contains(strings.Join(cfg.Warnings, "\n"), "ftp traceoptions accepted but inert") {
				t.Fatalf("missing warning: %v", cfg.Warnings)
			}
		})
	}
}

func TestALGSubstatementAdvisoryUnion16814(t *testing.T) {
	for _, text := range []string{
		"security { alg { dns { doctoring none; maximum-message-length 8192; disable; } } }",
		"security { alg dns { doctoring none; maximum-message-length 8192; disable; } }",
	} {
		t.Run(text, func(t *testing.T) {
			cfg, err := CheckText(text, -1)
			if err != nil {
				t.Fatal(err)
			}
			if !cfg.Security.ALG.DNSDisable {
				t.Fatal("lost class-level disable")
			}
			if got := strings.Join(cfg.Security.ALG.InertSubstatements, ", "); got != "dns doctoring, dns maximum-message-length" {
				t.Fatalf("inert statements = %q", got)
			}
		})
	}
}
