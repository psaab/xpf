package configstore

import (
	"strings"
	"testing"
)

// #16571, operator channel. CheckText is the gate every commit and
// `xpfd check-config` runs (SchemaValidate, then strict compile). A
// screen numeric leaf authored without its number must reject there in
// every spelling — hierarchical packed, braced, and flat — while the
// bare check (no `threshold` keyword) still arms the #3230 default and
// the valued packed spelling still lands.

func TestCheckTextScreenValuelessRejects16571(t *testing.T) {
	for _, tc := range []struct {
		name string
		text string
		want string
	}{
		{"packed syn-flood source",
			"security { screen { ids-option s1 { tcp syn-flood attack-threshold 300 source-threshold; } } }",
			"tcp syn-flood source-threshold"},
		{"packed icmp flood threshold",
			"security { screen { ids-option s1 { icmp flood threshold; } } }",
			"icmp flood threshold"},
		{"packed tcp port-scan threshold",
			"security { screen { ids-option s1 { tcp port-scan threshold; } } }",
			"tcp port-scan threshold"},
		{"braced syn-flood source",
			"security { screen { ids-option s1 { tcp { syn-flood { attack-threshold 300; source-threshold; } } } } }",
			"source-threshold"},
		{"braced icmp flood threshold",
			"security { screen { ids-option s1 { icmp { flood { threshold; } } } } }",
			"threshold"},
		{"braced tcp port-scan threshold",
			"security { screen { ids-option s1 { tcp { port-scan { threshold; } } } } }",
			"threshold"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CheckText(tc.text, -1)
			if err == nil {
				t.Fatalf("CheckText accepted valueless %q", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) ||
				!strings.Contains(err.Error(), "declares a value and none was given") {
				t.Fatalf("CheckText error does not name the valueless leaf %q: %v", tc.want, err)
			}
		})
	}
}

func TestCheckTextScreenBareAndValuedControls16571(t *testing.T) {
	cfg, err := CheckText("security { screen { ids-option s1 { icmp flood; tcp port-scan; } } }", -1)
	if err != nil {
		t.Fatalf("bare flood/port-scan (no threshold keyword) must commit: %v", err)
	}
	p := cfg.Security.Screen["s1"]
	if p == nil || p.ICMP.FloodThreshold <= 0 || p.TCP.PortScanThreshold <= 0 {
		t.Fatalf("bare checks did not arm Junos defaults: %+v", p)
	}
	cfg2, err := CheckText("security { screen { ids-option s1 { icmp flood threshold 77; tcp syn-flood attack-threshold 300 source-threshold 25; } } }", -1)
	if err != nil {
		t.Fatalf("valued packed spelling must commit: %v", err)
	}
	p2 := cfg2.Security.Screen["s1"]
	if p2.ICMP.FloodThreshold != 77 || p2.TCP.SynFlood.SourceThreshold != 25 {
		t.Fatalf("valued packed values lost: %+v", p2)
	}
	// Non-numeric control keeps its #3317 rejection.
	if _, err := CheckText("security { screen { ids-option s1 { tcp syn-flood source-threshold abc; } } }", -1); err == nil {
		t.Fatal("CheckText accepted non-numeric source-threshold")
	}
}
