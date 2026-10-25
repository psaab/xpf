package configstore

import (
	"strings"
	"testing"
)

func TestALGOpaqueBodies16814(t *testing.T) {
	for _, text := range []string{
		"security { alg h323 { ftp desable; } }",
		"security { alg { h323 { ftp desable; } } }",
		"security { alg h323 ftp desable; }",
	} {
		t.Run(text, func(t *testing.T) {
			cfg, err := CheckText(text, -1)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(strings.Join(cfg.Warnings, "\n"), "h323 accepted but inert") {
				t.Fatalf("missing old advisory: %v", cfg.Warnings)
			}
			if cfg.Security.ALG.FTPDisable || len(cfg.Security.ALG.InertSubstatements) != 0 {
				t.Fatalf("opaque body leaked into modeled ALG: %+v", cfg.Security.ALG)
			}
		})
	}
	for _, text := range []string{
		"security { alg ftp traceoptions { dns desable; } }",
		"security { alg { ftp traceoptions { dns desable; } } }",
	} {
		t.Run(text, func(t *testing.T) {
			cfg, err := CheckText(text, -1)
			if err != nil {
				t.Fatal(err)
			}
			if got := strings.Join(cfg.Security.ALG.InertSubstatements, ","); got != "ftp traceoptions" {
				t.Fatalf("opaque body confused statement identity: %q", got)
			}
		})
	}
}
