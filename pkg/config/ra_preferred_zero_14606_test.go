package config

import "testing"

// #14606: an explicit `preferred-lifetime 0` leaf (deprecated) must set
// PreferredLifeSet so pkg/ra honors 0 instead of the 7-day default; an
// absent leaf must leave the flag false (legacy default behavior).

func raCompile14606(t *testing.T, prefixBody string) *RAPrefix {
	t.Helper()
	src := `
protocols {
    router-advertisement {
        interface ge-0/0/0.0 {
            prefix 2001:db8::/64 {
` + prefixBody + `
            }
        }
    }
}
`
	cfg, err := CompileConfig(hierTree(t, src))
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	for _, ra := range cfg.Protocols.RouterAdvertisement {
		if ra != nil && ra.Interface == "ge-0/0/0.0" {
			for _, p := range ra.Prefixes {
				if p != nil && p.Prefix == "2001:db8::/64" {
					return p
				}
			}
		}
	}
	t.Fatal("no RA prefix compiled")
	return nil
}

func TestCompileRAPreferredLifeSet14606(t *testing.T) {
	explicitZero := raCompile14606(t, "                preferred-lifetime 0;\n                valid-lifetime 7200;")
	if !explicitZero.PreferredLifeSet || explicitZero.PreferredLife != 0 {
		t.Errorf("explicit 0: set=%v pref=%d, want true/0", explicitZero.PreferredLifeSet, explicitZero.PreferredLife)
	}
	absent := raCompile14606(t, "                valid-lifetime 7200;")
	if absent.PreferredLifeSet {
		t.Errorf("absent leaf: PreferredLifeSet=true, want false (7-day default must apply)")
	}
	normal := raCompile14606(t, "                preferred-lifetime 3600;")
	if !normal.PreferredLifeSet || normal.PreferredLife != 3600 {
		t.Errorf("explicit 3600: set=%v pref=%d, want true/3600", normal.PreferredLifeSet, normal.PreferredLife)
	}
}
