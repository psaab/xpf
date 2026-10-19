package config

import (
	"strings"
	"testing"
)

// #15046 (A05-04) — vrrp-group was open-world at the compiler level.
// The Junos `track { interface <if> { priority-cost <n>; } }` container
// and `no-preempt` passed strict commit with zero warnings and were
// silently dropped (interface tracking absent — the master keeps the
// VIP when the tracked uplink fails), and any other unknown child
// (`zzbogus`) did the same. These tests pin: the Junos track row
// compiles to TrackInterface/TrackPriorityDelta, `no-preempt` compiles
// explicitly (Preempt=false, PreemptSet=true), and unknown children
// are strict-rejected / lenient-warned. RED on origin/master: the
// Junos row compiled Track=""/0 and zzbogus committed clean.

// ge-0/0/1 is declared as an interface: since #15048 an undeclared
// track target fails strict commit, so the fixture must declare it.
const junosTrackHier15046 = `interfaces {
    ge-0/0/1 {
        unit 0 {
            family inet {
                address 10.0.1.1/24;
            }
        }
    }
    reth1 {
        unit 0 {
            family inet {
                address 10.0.61.1/24 {
                    vrrp-group 1 {
                        virtual-address 10.0.61.3;
                        priority 200;
                        track {
                            interface ge-0/0/1 {
                                priority-cost 150;
                            }
                        }
                    }
                }
            }
        }
    }
}`

func vrrpGroupText15046(body string) string {
	return `interfaces {
    reth1 {
        unit 0 {
            family inet {
                address 10.0.61.1/24 {
                    vrrp-group 1 {
                        virtual-address 10.0.61.3;
                        priority 200;
` + body + `
                    }
                }
            }
        }
    }
}`
}

func TestVRRPJunosTrackHier15046(t *testing.T) {
	cfg, err := CompileConfig(parseHier(t, junosTrackHier15046))
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	vg := trackTestVRRPGroup(t, cfg)
	if vg.TrackInterface != "ge-0/0/1" || vg.TrackPriorityDelta != 150 {
		t.Fatalf("Track=%q/%d want ge-0/0/1/150", vg.TrackInterface, vg.TrackPriorityDelta)
	}
}

func TestVRRPJunosTrackFlatSet15046(t *testing.T) {
	tree := replaySetLines(t, []string{
		"set interfaces reth1 unit 0 family inet address 10.0.61.1/24 vrrp-group 1 virtual-address 10.0.61.3",
		"set interfaces reth1 unit 0 family inet address 10.0.61.1/24 vrrp-group 1 priority 200",
		"set interfaces reth1 unit 0 family inet address 10.0.61.1/24 vrrp-group 1 track interface reth1 priority-cost 150",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	vg := trackTestVRRPGroup(t, cfg)
	if vg.TrackInterface != "reth1" || vg.TrackPriorityDelta != 150 {
		t.Fatalf("Track=%q/%d want reth1/150", vg.TrackInterface, vg.TrackPriorityDelta)
	}
}

func TestVRRPJunosTrackInet6_15046(t *testing.T) {
	text := `interfaces {
    reth1 {
        unit 0 {
            family inet6 {
                address 2001:db8::1/64 {
                    vrrp-group 1 {
                        virtual-address 2001:db8::3/64;
                        priority 200;
                        track {
                            interface reth1 {
                                priority-cost 150;
                            }
                        }
                    }
                }
            }
        }
    }
}`
	cfg, err := CompileConfig(parseHier(t, text))
	if err != nil {
		t.Fatalf("CompileConfig inet6: %v", err)
	}
	vg := trackTestVRRPGroup(t, cfg)
	if vg.TrackInterface != "reth1" || vg.TrackPriorityDelta != 150 {
		t.Fatalf("inet6 Track=%q/%d want reth1/150", vg.TrackInterface, vg.TrackPriorityDelta)
	}
}

// Keys-packed hierarchical one-liner spelling.
func TestVRRPJunosTrackKeysPacked15046(t *testing.T) {
	text := vrrpGroupText15046(`                        track interface reth1 priority-cost 150;`)
	// Replace the braced body form: vrrpGroupText already wraps in braces,
	// so the line above is a single statement inside the group — valid.
	cfg, err := CompileConfig(parseHier(t, text))
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	vg := trackTestVRRPGroup(t, cfg)
	if vg.TrackInterface != "reth1" || vg.TrackPriorityDelta != 150 {
		t.Fatalf("Track=%q/%d want reth1/150", vg.TrackInterface, vg.TrackPriorityDelta)
	}
}

func TestVRRPNoPreempt15046(t *testing.T) {
	t.Run("hierarchical", func(t *testing.T) {
		cfg, err := CompileConfig(parseHier(t, vrrpGroupText15046(`                        no-preempt;`)))
		if err != nil {
			t.Fatalf("CompileConfig: %v", err)
		}
		vg := trackTestVRRPGroup(t, cfg)
		if vg.Preempt {
			t.Fatal("no-preempt must compile Preempt=false")
		}
		if !vg.PreemptSet {
			t.Fatal("no-preempt must compile PreemptSet=true (explicit, round-trips)")
		}
	})
	t.Run("flat-set", func(t *testing.T) {
		tree := replaySetLines(t, []string{
			"set interfaces reth1 unit 0 family inet address 10.0.61.1/24 vrrp-group 1 virtual-address 10.0.61.3",
			"set interfaces reth1 unit 0 family inet address 10.0.61.1/24 vrrp-group 1 no-preempt",
		})
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("CompileConfig: %v", err)
		}
		vg := trackTestVRRPGroup(t, cfg)
		if vg.Preempt || !vg.PreemptSet {
			t.Fatalf("Preempt=%v PreemptSet=%v want false/true", vg.Preempt, vg.PreemptSet)
		}
	})
	t.Run("preempt-still-works", func(t *testing.T) {
		cfg, err := CompileConfig(parseHier(t, vrrpGroupText15046(`                        preempt;`)))
		if err != nil {
			t.Fatalf("CompileConfig: %v", err)
		}
		vg := trackTestVRRPGroup(t, cfg)
		if !vg.Preempt || !vg.PreemptSet {
			t.Fatalf("Preempt=%v PreemptSet=%v want true/true", vg.Preempt, vg.PreemptSet)
		}
	})
	t.Run("last-statement-wins", func(t *testing.T) {
		cfg, err := CompileConfig(parseHier(t, vrrpGroupText15046("                        preempt;\n                        no-preempt;")))
		if err != nil {
			t.Fatalf("CompileConfig: %v", err)
		}
		vg := trackTestVRRPGroup(t, cfg)
		if vg.Preempt || !vg.PreemptSet {
			t.Fatalf("preempt then no-preempt: Preempt=%v PreemptSet=%v want false/true", vg.Preempt, vg.PreemptSet)
		}
	})
	t.Run("unset-is-default-not-explicit", func(t *testing.T) {
		cfg, err := CompileConfig(parseHier(t, vrrpGroupText15046(``)))
		if err != nil {
			t.Fatalf("CompileConfig: %v", err)
		}
		vg := trackTestVRRPGroup(t, cfg)
		// #15047 (merged since this issue was filed): preemption
		// defaults ON per Junos/RFC 5798, so no statement compiles
		// Preempt=true; PreemptSet stays false (not authored).
		if !vg.Preempt || vg.PreemptSet {
			t.Fatalf("no preempt statement: Preempt=%v PreemptSet=%v want true/false (#15047 default)", vg.Preempt, vg.PreemptSet)
		}
	})
}

func TestVRRPUnknownChild15046(t *testing.T) {
	cells := map[string]string{
		"braced":      vrrpGroupText15046(`                        zzbogus 1;`),
		"track-inner": vrrpGroupText15046("                        track {\n                            zzbogus ge-0/0/1;\n                        }"),
		"keys-packed": `interfaces { reth1 { unit 0 { family inet { address 10.0.61.1/24 { vrrp-group 1 virtual-address 10.0.61.3 zzbogus 1; } } } } }`,
	}
	for name, text := range cells {
		t.Run(name, func(t *testing.T) {
			_, err := CompileConfig(parseHier(t, text))
			if err == nil {
				t.Fatal("strict must reject zzbogus")
			}
			if !strings.Contains(err.Error(), "zzbogus") {
				t.Fatalf("err must name zzbogus: %v", err)
			}
			cfg, err := CompileConfigLenient(parseHier(t, text))
			if err != nil {
				t.Fatalf("lenient must boot (#1960): %v", err)
			}
			if !hasWarningContaining(cfg.Warnings, "zzbogus") {
				t.Fatalf("lenient must warn zzbogus: %v", cfg.Warnings)
			}
		})
	}
	t.Run("flat-set", func(t *testing.T) {
		tree := replaySetLines(t, []string{
			"set interfaces reth1 unit 0 family inet address 10.0.61.1/24 vrrp-group 1 virtual-address 10.0.61.3",
			"set interfaces reth1 unit 0 family inet address 10.0.61.1/24 vrrp-group 1 zzbogus 1",
		})
		if _, err := CompileConfig(tree); err == nil {
			t.Fatal("strict flat-set must reject zzbogus")
		}
		cfg, err := CompileConfigLenient(tree)
		if err != nil {
			t.Fatalf("lenient flat-set: %v", err)
		}
		if !hasWarningContaining(cfg.Warnings, "zzbogus") {
			t.Fatalf("lenient flat-set must warn zzbogus: %v", cfg.Warnings)
		}
	})
}

// The Junos spelling shares the #1814 single-track slot: a group with
// both spellings (or two Junos tracks) is a duplicate.
func TestVRRPJunosTrackDuplicate15046(t *testing.T) {
	text := vrrpGroupText15046(`                        track-interface reth1;
                        track {
                            interface reth1 {
                                priority-cost 150;
                            }
                        }`)
	if _, err := CompileConfig(parseHier(t, text)); err == nil {
		t.Fatal("strict must reject track-interface + track duplicate")
	}
	cfg, err := CompileConfigLenient(parseHier(t, text))
	if err != nil {
		t.Fatalf("lenient: %v", err)
	}
	if !hasWarningContaining(cfg.Warnings, "track-interface statements") {
		t.Fatalf("lenient must warn duplicate: %v", cfg.Warnings)
	}
	vg := trackTestVRRPGroup(t, cfg)
	if vg.TrackInterface == "" {
		t.Fatal("lenient must keep one tracked interface")
	}
}

// Out-of-range Junos priority-cost follows the #1814 range gate.
func TestVRRPJunosTrackCostRange15046(t *testing.T) {
	text := vrrpGroupText15046(`                        track {
                            interface reth1 {
                                priority-cost 999;
                            }
                        }`)
	if _, err := CompileConfig(parseHier(t, text)); err == nil {
		t.Fatal("strict must reject priority-cost 999 under track interface")
	}
	cfg, err := CompileConfigLenient(parseHier(t, text))
	if err != nil {
		t.Fatalf("lenient: %v", err)
	}
	if !hasWarningContaining(cfg.Warnings, "out of range") {
		t.Fatalf("lenient must warn out of range: %v", cfg.Warnings)
	}
}

// Control: every previously-compiling vrrp-group child still compiles
// with zero unknown-child warnings, in both families' spellings.
func TestVRRPKnownChildrenControl15046(t *testing.T) {
	text := vrrpGroupText15046(`                        accept-data;
                        advertise-interval 5;
                        preempt {
                            hold-time 30;
                        }
                        track-interface reth1 {
                            priority-cost 20;
                        }`)
	cfg, err := CompileConfig(parseHier(t, text))
	if err != nil {
		t.Fatalf("CompileConfig control: %v", err)
	}
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "#15046") {
			t.Fatalf("control must not warn #15046: %v", cfg.Warnings)
		}
	}
	vg := trackTestVRRPGroup(t, cfg)
	if !vg.AcceptData || vg.AdvertiseInterval != 5 || !vg.Preempt || vg.PreemptHoldTime != 30 ||
		vg.TrackInterface != "reth1" || vg.TrackPriorityDelta != 20 {
		t.Fatalf("control compiled wrong: %+v", vg)
	}
}

// SchemaValidate (the configstore strict commit gate's first half)
// must accept the new declared spellings.
func TestVRRPJunosSpellingsSchemaValidate15046(t *testing.T) {
	// Use CIDR VIPs here: SchemaValidate enforces the xpf CIDR
	// contract on virtual-address (the compile-only cells above use
	// the bare form the compiler tolerates).
	junosCIDR := strings.Replace(junosTrackHier15046, "virtual-address 10.0.61.3;", "virtual-address 10.0.61.3/24;", 1)
	noPreemptCIDR := strings.Replace(vrrpGroupText15046(`                        no-preempt;`), "virtual-address 10.0.61.3;", "virtual-address 10.0.61.3/24;", 1)
	for name, text := range map[string]string{
		"junos-track": junosCIDR,
		"no-preempt":  noPreemptCIDR,
	} {
		t.Run(name, func(t *testing.T) {
			if err := SchemaValidate(parseHier(t, text), nil); err != nil {
				t.Fatalf("SchemaValidate must accept %s: %v", name, err)
			}
		})
	}
}

// The Junos braced form must survive a FormatSet round-trip.
func TestVRRPJunosTrackFormatSetRoundTrip15046(t *testing.T) {
	hierTree := parseHier(t, junosTrackHier15046)
	setText := hierTree.FormatSet()
	var lines []string
	for _, line := range strings.Split(setText, "\n") {
		if strings.TrimSpace(line) != "" {
			lines = append(lines, line)
		}
	}
	flatTree := replaySetLines(t, lines)
	cfg, err := CompileConfig(flatTree)
	if err != nil {
		t.Fatalf("CompileConfig(replayed): %v\nset text:\n%s", err, setText)
	}
	vg := trackTestVRRPGroup(t, cfg)
	if vg.TrackInterface != "ge-0/0/1" || vg.TrackPriorityDelta != 150 {
		t.Fatalf("round-trip Track=%q/%d want ge-0/0/1/150\nset text:\n%s", vg.TrackInterface, vg.TrackPriorityDelta, setText)
	}
}
