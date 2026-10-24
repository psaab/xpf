package config

import (
	"strings"
	"testing"
)

// #16424 (R3-F05-02): compileClassOfService read only the FIRST
// classifiers / rewrite-rules / forwarding-classes container under one
// class-of-service root (FindChild), and parseCoSInterfaceUnitBody did the
// same for the per-interface classifiers / rewrite-rules containers. A
// second container — the hierarchical / `load override` shape — was
// silently dropped while `show | display set` still listed it, so voice/EF
// classification or rewrite fell to defaults. #15006 fixed the same-named
// instance overwrite across roots/containers via find-or-create, but the
// container itself was never visited a second time.
//
// Flat-set semantics are the union, so two containers under one root must
// compile exactly as one merged container. Every cell below asserts that
// equality or the distinct-names / conflict controls around it.

const cosFCDefs16424 = `
    forwarding-classes {
        queue 0 best-effort;
        queue 1 voice;
    }
`

func TestTwoDSCPClassifierContainersEqualMerged16424(t *testing.T) {
	dup := mustCompile8436(t, `
class-of-service {
`+cosFCDefs16424+`
    classifiers {
        dscp C1 {
            forwarding-class voice {
                loss-priority low { code-points ef; }
            }
        }
    }
    classifiers {
        dscp C2 {
            forwarding-class best-effort {
                loss-priority low { code-points be; }
            }
        }
    }
}
`)
	merged := mustCompile8436(t, `
class-of-service {
`+cosFCDefs16424+`
    classifiers {
        dscp C1 {
            forwarding-class voice {
                loss-priority low { code-points ef; }
            }
        }
        dscp C2 {
            forwarding-class best-effort {
                loss-priority low { code-points be; }
            }
        }
    }
}
`)
	for label, cfg := range map[string]*Config{"duplicate": dup, "merged": merged} {
		if len(cfg.ClassOfService.DSCPClassifiers) != 2 {
			t.Fatalf("%s: got %d DSCP classifiers, want 2 (C1+C2) — second classifiers container dropped (#16424)",
				label, len(cfg.ClassOfService.DSCPClassifiers))
		}
		if c := cfg.ClassOfService.DSCPClassifiers["C1"]; c == nil || len(c.Entries) != 1 || c.Entries[0].ForwardingClass != "voice" {
			t.Fatalf("%s: C1 = %+v, want one voice entry", label, c)
		}
		if c := cfg.ClassOfService.DSCPClassifiers["C2"]; c == nil || len(c.Entries) != 1 || c.Entries[0].ForwardingClass != "best-effort" {
			t.Fatalf("%s: C2 = %+v, want one best-effort entry", label, c)
		}
	}
}

func TestTwoClassifierContainersSameNameMerge16424(t *testing.T) {
	cfg := mustCompile8436(t, `
class-of-service {
`+cosFCDefs16424+`
    classifiers {
        dscp C1 {
            forwarding-class voice {
                loss-priority low { code-points ef; }
            }
        }
    }
    classifiers {
        dscp C1 {
            forwarding-class best-effort {
                loss-priority low { code-points be; }
            }
        }
    }
}
`)
	c := cfg.ClassOfService.DSCPClassifiers["C1"]
	if c == nil {
		t.Fatal("DSCP classifier C1 did not compile")
	}
	if len(c.Entries) != 2 {
		t.Fatalf("C1 has %d entries, want 2 — same-named instance in second container must merge (#16424/#15006)", len(c.Entries))
	}
	if c.Entries[0].ForwardingClass != "voice" || c.Entries[1].ForwardingClass != "best-effort" {
		t.Fatalf("entries = %v/%v, want voice/best-effort in author order", c.Entries[0], c.Entries[1])
	}
}

func TestTwoClassifierContainersCoverAllKinds16424(t *testing.T) {
	cfg := mustCompile8436(t, `
class-of-service {
`+cosFCDefs16424+`
    classifiers {
        ieee-802.1 P1 {
            forwarding-class voice {
                loss-priority low { code-points 5; }
            }
        }
        inet-precedence N1 {
            forwarding-class voice {
                loss-priority low { code-points 5; }
            }
        }
    }
    classifiers {
        ieee-802.1 P2 {
            forwarding-class best-effort {
                loss-priority low { code-points 0; }
            }
        }
        inet-precedence N2 {
            forwarding-class best-effort {
                loss-priority low { code-points 0; }
            }
        }
    }
}
`)
	if len(cfg.ClassOfService.IEEE8021Classifiers) != 2 {
		t.Fatalf("IEEE classifiers = %d, want 2 (P1+P2) — second container dropped", len(cfg.ClassOfService.IEEE8021Classifiers))
	}
	if len(cfg.ClassOfService.INetPrecedenceClassifierDefs) != 2 {
		t.Fatalf("inet-precedence defs = %d, want 2 (N1+N2)", len(cfg.ClassOfService.INetPrecedenceClassifierDefs))
	}
	for _, want := range []string{"N1", "N2"} {
		found := 0
		for _, n := range cfg.ClassOfService.INetPrecedenceClassifiers {
			if n == want {
				found++
			}
		}
		if found != 1 {
			t.Fatalf("INetPrecedenceClassifiers contains %s %d times, want 1", want, found)
		}
	}
}

func TestTwoRewriteContainersEqualMerged16424(t *testing.T) {
	dup := mustCompile8436(t, `
class-of-service {
`+cosFCDefs16424+`
    rewrite-rules {
        dscp R1 {
            forwarding-class voice { loss-priority low code-point ef; }
        }
    }
    rewrite-rules {
        dscp R2 {
            forwarding-class best-effort { loss-priority low code-point be; }
        }
        ieee-802.1 W2 {
            forwarding-class best-effort { loss-priority low code-point 0; }
        }
        inet-precedence I2 {
            forwarding-class best-effort { loss-priority low code-point 0; }
        }
        exp E2 {
            forwarding-class best-effort { loss-priority low code-point 0; }
        }
    }
}
`)
	merged := mustCompile8436(t, `
class-of-service {
`+cosFCDefs16424+`
    rewrite-rules {
        dscp R1 {
            forwarding-class voice { loss-priority low code-point ef; }
        }
        dscp R2 {
            forwarding-class best-effort { loss-priority low code-point be; }
        }
        ieee-802.1 W2 {
            forwarding-class best-effort { loss-priority low code-point 0; }
        }
        inet-precedence I2 {
            forwarding-class best-effort { loss-priority low code-point 0; }
        }
        exp E2 {
            forwarding-class best-effort { loss-priority low code-point 0; }
        }
    }
}
`)
	for label, cfg := range map[string]*Config{"duplicate": dup, "merged": merged} {
		if len(cfg.ClassOfService.DSCPRewriteRules) != 2 {
			t.Fatalf("%s: DSCP rewrites = %d, want 2 (R1+R2)", label, len(cfg.ClassOfService.DSCPRewriteRules))
		}
		if len(cfg.ClassOfService.IEEE8021RewriteRules) != 1 {
			t.Fatalf("%s: IEEE rewrites = %d, want 1 (W2 from second container)", label, len(cfg.ClassOfService.IEEE8021RewriteRules))
		}
		if len(cfg.ClassOfService.INetPrecedenceRewriteRuleDefs) != 1 {
			t.Fatalf("%s: inet-precedence rewrite defs = %d, want 1 (I2)", label, len(cfg.ClassOfService.INetPrecedenceRewriteRuleDefs))
		}
		if len(cfg.ClassOfService.EXPRewriteRuleDefs) != 1 {
			t.Fatalf("%s: exp rewrite defs = %d, want 1 (E2)", label, len(cfg.ClassOfService.EXPRewriteRuleDefs))
		}
	}
}

func TestTwoRewriteContainersSameNameMerge16424(t *testing.T) {
	cfg := mustCompile8436(t, `
class-of-service {
`+cosFCDefs16424+`
    rewrite-rules {
        dscp R1 {
            forwarding-class voice { loss-priority low code-point ef; }
        }
    }
    rewrite-rules {
        dscp R1 {
            forwarding-class best-effort { loss-priority low code-point be; }
        }
    }
}
`)
	r := cfg.ClassOfService.DSCPRewriteRules["R1"]
	if r == nil {
		t.Fatal("DSCP rewrite R1 did not compile")
	}
	if len(r.Entries) != 2 {
		t.Fatalf("R1 has %d entries, want 2 — same-named instance in second container must merge", len(r.Entries))
	}
}

func TestTwoForwardingClassesContainersEqualMerged16424(t *testing.T) {
	dup := mustCompile8436(t, `
class-of-service {
    forwarding-classes {
        queue 0 best-effort;
    }
    forwarding-classes {
        queue 1 voice;
    }
}
`)
	merged := mustCompile8436(t, `
class-of-service {
    forwarding-classes {
        queue 0 best-effort;
        queue 1 voice;
    }
}
`)
	for label, cfg := range map[string]*Config{"duplicate": dup, "merged": merged} {
		if len(cfg.ClassOfService.ForwardingClasses) != 2 {
			t.Fatalf("%s: forwarding classes = %d, want 2 — second forwarding-classes container dropped (#16424)",
				label, len(cfg.ClassOfService.ForwardingClasses))
		}
		if fc := cfg.ClassOfService.ForwardingClasses["voice"]; fc == nil || fc.Queue != 1 {
			t.Fatalf("%s: voice = %+v, want queue 1", label, fc)
		}
		if fc := cfg.ClassOfService.ForwardingClasses["best-effort"]; fc == nil || fc.Queue != 0 {
			t.Fatalf("%s: best-effort = %+v, want queue 0", label, fc)
		}
	}
}

func TestForwardingClassesConflictAcrossContainersRejects16424(t *testing.T) {
	// Same queue claimed by two FCs in DIFFERENT containers must reject
	// exactly as it does within one container / across roots — iterating
	// containers must not bypass the bijection gate.
	_, err := compile8436Err(t, `
class-of-service {
    forwarding-classes {
        queue 0 best-effort;
    }
    forwarding-classes {
        queue 0 voice;
    }
}
`)
	if err == nil || !strings.Contains(err.Error(), "conflicts with") {
		t.Fatalf("queue conflict across containers: err = %v, want bijection conflict", err)
	}
	// Same FC on two queues across containers.
	_, err = compile8436Err(t, `
class-of-service {
    forwarding-classes {
        queue 0 voice;
    }
    forwarding-classes {
        queue 1 voice;
    }
}
`)
	if err == nil || !strings.Contains(err.Error(), "conflicts with") {
		t.Fatalf("FC conflict across containers: err = %v, want bijection conflict", err)
	}
}

func TestPerInterfaceTwoClassifierContainers16424(t *testing.T) {
	cfg := mustCompile8436(t, `
class-of-service {
`+cosFCDefs16424+`
    classifiers {
        dscp C1 {
            forwarding-class voice {
                loss-priority low { code-points ef; }
            }
        }
        dscp C2 {
            forwarding-class best-effort {
                loss-priority low { code-points be; }
            }
        }
        ieee-802.1 P2 {
            forwarding-class best-effort {
                loss-priority low { code-points 0; }
            }
        }
    }
    rewrite-rules {
        dscp R1 {
            forwarding-class voice { loss-priority low code-point ef; }
        }
        dscp R2 {
            forwarding-class best-effort { loss-priority low code-point be; }
        }
    }
    interfaces {
        ge-0/0/0 {
            unit 0 {
                classifiers {
                    dscp C1;
                }
                classifiers {
                    ieee-802.1 P2;
                }
                rewrite-rules {
                    dscp R1;
                }
                rewrite-rules {
                    dscp R2;
                }
            }
        }
    }
}
`)
	iface := cfg.ClassOfService.Interfaces["ge-0/0/0"]
	if iface == nil {
		t.Fatal("ge-0/0/0 did not compile")
	}
	unit := iface.Units[0]
	if unit == nil {
		t.Fatal("unit 0 did not compile")
	}
	if unit.DSCPClassifier != "C1" {
		t.Errorf("DSCPClassifier = %q, want C1", unit.DSCPClassifier)
	}
	if unit.IEEE8021Classifier != "P2" {
		t.Errorf("IEEE8021Classifier = %q, want P2 — second per-interface classifiers container dropped (#16424)", unit.IEEE8021Classifier)
	}
	// DSCP and ieee rewrite bindings share one field family but DSCP is
	// the only DSCP slot: second container's dscp R2 wins in author order,
	// exactly as a merged container with two dscp lines would (last wins
	// for a scalar binding).
	if unit.DSCPRewriteRule != "R2" {
		t.Errorf("DSCPRewriteRule = %q, want R2 — second per-interface rewrite-rules container dropped (#16424)", unit.DSCPRewriteRule)
	}
}

func TestPerInterfaceLevelTwoClassifierContainers16424(t *testing.T) {
	cfg := mustCompile8436(t, `
class-of-service {
`+cosFCDefs16424+`
    classifiers {
        dscp C1 {
            forwarding-class voice {
                loss-priority low { code-points ef; }
            }
        }
        ieee-802.1 P2 {
            forwarding-class best-effort {
                loss-priority low { code-points 0; }
            }
        }
    }
    interfaces {
        ge-0/0/0 {
            classifiers {
                dscp C1;
            }
            classifiers {
                ieee-802.1 P2;
            }
            unit 0 {
                scheduler-map SM-A;
            }
        }
    }
    scheduler-maps {
        SM-A {
            forwarding-class best-effort scheduler SCHED-A;
        }
    }
    schedulers {
        SCHED-A {
            transmit-rate 100m;
        }
    }
}
`)
	iface := cfg.ClassOfService.Interfaces["ge-0/0/0"]
	if iface == nil || iface.Level == nil {
		t.Fatalf("ge-0/0/0 level binding did not compile: %+v", iface)
	}
	if iface.Level.DSCPClassifier != "C1" {
		t.Errorf("level DSCPClassifier = %q, want C1", iface.Level.DSCPClassifier)
	}
	if iface.Level.IEEE8021Classifier != "P2" {
		t.Errorf("level IEEE8021Classifier = %q, want P2 — second interface-level classifiers container dropped", iface.Level.IEEE8021Classifier)
	}
}

func compile8436Err(t *testing.T, text string) (*Config, error) {
	t.Helper()
	tree, perrs := NewParser(text).Parse()
	if len(perrs) != 0 {
		t.Fatalf("parse: %v", perrs)
	}
	return CompileConfig(tree)
}
