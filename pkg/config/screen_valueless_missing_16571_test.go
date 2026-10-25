package config

import (
	"strings"
	"testing"
)

// #16571: a screen numeric leaf authored without its number
// (`source-threshold;`, `flood threshold;`) committed strict-clean in
// the packed spellings because the four families are closedWorldOpaque
// and the #8597 schema-walk gate never reaches the packed tail, while
// the braced spelling was rejected. compileScreen now records each
// such leaf on ScreenProfile.MissingValue and
// validateScreenMissingValueStrict refuses it, so the verdict no
// longer depends on spelling. Bare `flood;` / `port-scan;` /
// `ip-sweep;` (no `threshold` keyword) author no numeric leaf and
// still arm the #3230 Junos default.
//
// FAIL-ON-REVERT: drop the MissingValue recording in compileScreen or
// the gate in runUniformGatesScreen and every reject row below goes
// green on the valueless config.

var screenValuelessReject16571 = []struct {
	name string
	text string // hierarchical text
	want string // leaf path the strict error must name
}{
	{"syn-flood source packed after valued sibling",
		"security { screen { ids-option s1 { tcp syn-flood attack-threshold 300 source-threshold; } } }\n",
		"tcp syn-flood source-threshold"},
	{"syn-flood destination packed",
		"security { screen { ids-option s1 { tcp syn-flood attack-threshold 300 destination-threshold; } } }\n",
		"tcp syn-flood destination-threshold"},
	{"syn-flood alarm packed",
		"security { screen { ids-option s1 { tcp syn-flood alarm-threshold; } } }\n",
		"tcp syn-flood alarm-threshold"},
	{"syn-flood attack packed alone",
		"security { screen { ids-option s1 { tcp syn-flood attack-threshold; } } }\n",
		"tcp syn-flood attack-threshold"},
	{"syn-flood timeout packed",
		"security { screen { ids-option s1 { tcp syn-flood timeout; } } }\n",
		"tcp syn-flood timeout"},
	{"syn-flood source packed alone",
		"security { screen { ids-option s1 { tcp syn-flood source-threshold; } } }\n",
		"tcp syn-flood source-threshold"},
	{"icmp flood threshold packed",
		"security { screen { ids-option s1 { icmp flood threshold; } } }\n",
		"icmp flood threshold"},
	{"udp flood threshold packed",
		"security { screen { ids-option s1 { udp flood threshold; } } }\n",
		"udp flood threshold"},
	{"tcp port-scan threshold packed",
		"security { screen { ids-option s1 { tcp port-scan threshold; } } }\n",
		"tcp port-scan threshold"},
	{"ip ip-sweep threshold packed",
		"security { screen { ids-option s1 { ip ip-sweep threshold; } } }\n",
		"ip ip-sweep threshold"},
	{"icmp ip-sweep threshold packed",
		"security { screen { ids-option s1 { icmp ip-sweep threshold; } } }\n",
		"icmp ip-sweep threshold"},
	{"limit-session source packed",
		"security { screen { ids-option s1 { limit-session source-ip-based; } } }\n",
		"limit-session source-ip-based"},
	{"limit-session destination packed",
		"security { screen { ids-option s1 { limit-session destination-ip-based; } } }\n",
		"limit-session destination-ip-based"},
	// Braced controls: these already rejected via #8597/SchemaValidate
	// on the operator path; at CompileConfig level they must now reject
	// with the same missing-value message.
	{"syn-flood source braced",
		"security { screen { ids-option s1 { tcp { syn-flood { attack-threshold 300; source-threshold; } } } } }\n",
		"tcp syn-flood source-threshold"},
	{"icmp flood threshold braced",
		"security { screen { ids-option s1 { icmp { flood { threshold; } } } } }\n",
		"icmp flood threshold"},
	{"tcp port-scan threshold braced",
		"security { screen { ids-option s1 { tcp { port-scan { threshold; } } } } }\n",
		"tcp port-scan threshold"},
}

func TestScreenValuelessRejectsStrict16571(t *testing.T) {
	for _, tc := range screenValuelessReject16571 {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CompileConfig(parseHierText(t, tc.text))
			if err == nil {
				t.Fatalf("strict CompileConfig accepted valueless %q", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) ||
				!strings.Contains(err.Error(), "declares a value and none was given") ||
				!strings.Contains(err.Error(), "s1") {
				t.Fatalf("error %q does not name profile s1 and valueless leaf %q", err, tc.want)
			}
		})
	}
}

// The flat multi-leaf spelling packs both leaves onto one `set` line;
// it must reject exactly like the hierarchical packed spelling.
func TestScreenValuelessFlatPackedRejects16571(t *testing.T) {
	_, err := CompileConfig(buildTree(t, []string{
		"set security screen ids-option s1 tcp syn-flood attack-threshold 300 source-threshold",
	}))
	if err == nil {
		t.Fatal("strict CompileConfig accepted flat packed valueless source-threshold")
	}
	if !strings.Contains(err.Error(), "tcp syn-flood source-threshold") {
		t.Fatalf("error does not name the valueless leaf: %v", err)
	}
	// Flat single-leaf controls already rejected and must keep rejecting.
	for _, line := range []string{
		"set security screen ids-option s1 tcp syn-flood source-threshold",
		"set security screen ids-option s1 icmp flood threshold",
	} {
		if _, err := CompileConfig(buildTree(t, []string{line})); err == nil {
			t.Fatalf("strict CompileConfig accepted flat valueless %q", line)
		}
	}
}

// On the tolerant path every reject row boots, warns naming the leaf,
// and keeps today's compiled value: Junos default for flood/scan/sweep,
// 0/disabled for syn-flood subfields and limit-session caps.
func TestScreenValuelessLenientWarns16571(t *testing.T) {
	for _, tc := range screenValuelessReject16571 {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := CompileConfigLenient(parseHierText(t, tc.text))
			if err != nil {
				t.Fatalf("lenient compile must boot: %v", err)
			}
			found := false
			for _, w := range cfg.Warnings {
				if strings.Contains(w, tc.want) && strings.Contains(w, "downgraded to warning") {
					found = true
				}
			}
			if !found {
				t.Fatalf("lenient warnings %v do not name valueless leaf %q", cfg.Warnings, tc.want)
			}
		})
	}
	// Compiled-value spot checks on the tolerant path. One `tcp` block
	// per profile: a second `tcp` family block is a #5180 duplicate.
	cfg := compileHierLenient(t,
		"security { screen { ids-option s1 { icmp flood threshold; tcp { port-scan threshold; syn-flood attack-threshold 300 source-threshold; } } } }\n")
	p := cfg.Security.Screen["s1"]
	if p.ICMP.FloodThreshold != defaultICMPFloodThreshold {
		t.Fatalf("lenient icmp flood = %d, want Junos default %d", p.ICMP.FloodThreshold, defaultICMPFloodThreshold)
	}
	if p.TCP.PortScanThreshold != defaultPortScanThreshold {
		t.Fatalf("lenient port-scan = %d, want Junos default %d", p.TCP.PortScanThreshold, defaultPortScanThreshold)
	}
	if p.TCP.SynFlood == nil || p.TCP.SynFlood.AttackThreshold != 300 || p.TCP.SynFlood.SourceThreshold != 0 {
		t.Fatalf("lenient syn-flood = %+v, want attack=300 source disabled", p.TCP.SynFlood)
	}
}

// Bare checks with no `threshold` keyword author no numeric leaf: they
// still arm the #3230 Junos default on BOTH paths, with no missing-value
// record. Valued packed spellings keep landing their values.
func TestScreenBareChecksStillArmDefault16571(t *testing.T) {
	for _, tc := range []struct {
		name string
		text string
	}{
		{"icmp flood bare", "security { screen { ids-option s1 { icmp flood; } } }\n"},
		{"udp flood bare", "security { screen { ids-option s1 { udp flood; } } }\n"},
		{"tcp port-scan bare", "security { screen { ids-option s1 { tcp port-scan; } } }\n"},
		{"ip ip-sweep bare", "security { screen { ids-option s1 { ip ip-sweep; } } }\n"},
		{"icmp ip-sweep bare", "security { screen { ids-option s1 { icmp ip-sweep; } } }\n"},
		{"syn-flood subfield only", "security { screen { ids-option s1 { tcp syn-flood source-threshold 25; } } }\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := compileHierStrict(t, tc.text)
			p := cfg.Security.Screen["s1"]
			if len(p.MissingValue) != 0 {
				t.Fatalf("bare/valued spelling recorded MissingValue %v", p.MissingValue)
			}
		})
	}
	armed := compileHierStrict(t,
		"security { screen { ids-option s1 { icmp flood; ip ip-sweep; tcp { port-scan; syn-flood source-threshold 25; } } } }\n")
	ap := armed.Security.Screen["s1"]
	if ap.ICMP.FloodThreshold != defaultICMPFloodThreshold ||
		ap.TCP.PortScanThreshold != defaultPortScanThreshold ||
		ap.IP.IPSweepThreshold != defaultIPSweepThreshold {
		t.Fatalf("bare checks did not arm Junos defaults: %+v", ap)
	}
	if ap.TCP.SynFlood.SourceThreshold != 25 || ap.TCP.SynFlood.AttackThreshold != defaultSynFloodAttackThreshold {
		t.Fatalf("valued packed syn-flood lost: %+v", ap.TCP.SynFlood)
	}
	valued := compileHierStrict(t,
		"security { screen { ids-option s1 { icmp flood threshold 77; tcp port-scan threshold 4000; } } }\n")
	vp := valued.Security.Screen["s1"]
	if vp.ICMP.FloodThreshold != 77 || vp.TCP.PortScanThreshold != 4000 {
		t.Fatalf("valued packed thresholds lost: icmp=%d portscan=%d", vp.ICMP.FloodThreshold, vp.TCP.PortScanThreshold)
	}
}
