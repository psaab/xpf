package config

import "testing"

// #15006 (A09-03): duplicate hierarchical CoS classifier / rewrite-rule
// blocks overwrote each other (last wins) in compileClassOfService.
//
// The six affected loops each built a fresh object per instance and assigned
// it to the typed map, discarding any same-named earlier block. A second
// top-level `class-of-service` root, or a second `classifiers` /
// `rewrite-rules` container under one root (the raw hierarchical /
// `load override` shapes), therefore lost the first block's code points
// with no diagnostic, while the flat-set spelling merged. Schedulers,
// scheduler-maps, traffic-control-profiles, and interfaces under the same
// compiler already use find-or-create (#8436); these six did not.
//
// Every merge cell below is paired with a different-names control: find-or-
// create is keyed on the authored name, so two blocks naming different
// objects must stay two entries. A merge keyed on anything broader would
// pass the merge cells while silently collapsing distinct objects.

func TestDuplicateCoSDSCPClassifierBlocksMerge15006(t *testing.T) {
	dup := mustCompile8436(t, `
class-of-service {
    classifiers {
        dscp C1 {
            forwarding-class voice {
                loss-priority low {
                    code-points ef;
                }
            }
        }
    }
}
class-of-service {
    classifiers {
        dscp C1 {
            forwarding-class best-effort {
                loss-priority low {
                    code-points be;
                }
            }
        }
    }
}
`)
	merged := mustCompile8436(t, `
class-of-service {
    classifiers {
        dscp C1 {
            forwarding-class voice {
                loss-priority low {
                    code-points ef;
                }
            }
            forwarding-class best-effort {
                loss-priority low {
                    code-points be;
                }
            }
        }
    }
}
`)
	for label, cfg := range map[string]*Config{"duplicate": dup, "merged": merged} {
		c := cfg.ClassOfService.DSCPClassifiers["C1"]
		if c == nil {
			t.Fatalf("%s: DSCP classifier C1 did not compile", label)
		}
		if len(c.Entries) != 2 {
			t.Fatalf("%s: DSCP classifier C1 has %d entries, want 2 (duplicate must equal merged) — "+
				"the first hierarchical block was overwritten (#15006)", label, len(c.Entries))
		}
		if c.Entries[0].ForwardingClass != "voice" || c.Entries[1].ForwardingClass != "best-effort" {
			t.Fatalf("%s: entries = %v/%v, want voice/best-effort", label, c.Entries[0], c.Entries[1])
		}
	}
}

func TestDistinctCoSDSCPClassifierBlocksStayDistinct15006(t *testing.T) {
	cfg := mustCompile8436(t, `
class-of-service {
    classifiers {
        dscp C1 {
            forwarding-class voice {
                loss-priority low {
                    code-points ef;
                }
            }
        }
        dscp C2 {
            forwarding-class best-effort {
                loss-priority low {
                    code-points be;
                }
            }
        }
    }
}
`)
	if len(cfg.ClassOfService.DSCPClassifiers) != 2 {
		t.Fatalf("two different DSCP classifiers produced %d entries, want 2", len(cfg.ClassOfService.DSCPClassifiers))
	}
	if len(cfg.ClassOfService.DSCPClassifiers["C1"].Entries) != 1 ||
		cfg.ClassOfService.DSCPClassifiers["C1"].Entries[0].ForwardingClass != "voice" {
		t.Errorf("C1 entries = %v, want [voice]", cfg.ClassOfService.DSCPClassifiers["C1"].Entries)
	}
	if len(cfg.ClassOfService.DSCPClassifiers["C2"].Entries) != 1 ||
		cfg.ClassOfService.DSCPClassifiers["C2"].Entries[0].ForwardingClass != "best-effort" {
		t.Errorf("C2 entries = %v, want [best-effort]", cfg.ClassOfService.DSCPClassifiers["C2"].Entries)
	}
}

func TestDuplicateCoSIEEEClassifierBlocksMerge15006(t *testing.T) {
	cfg := mustCompile8436(t, `
class-of-service {
    classifiers {
        ieee-802.1 P1 {
            forwarding-class voice {
                loss-priority low {
                    code-points 5;
                }
            }
        }
        ieee-802.1 P1 {
            forwarding-class best-effort {
                loss-priority low {
                    code-points 0;
                }
            }
        }
    }
}
`)
	c := cfg.ClassOfService.IEEE8021Classifiers["P1"]
	if c == nil {
		t.Fatal("IEEE classifier P1 did not compile")
	}
	if len(c.Entries) != 2 {
		t.Fatalf("IEEE classifier P1 has %d entries, want 2 — first block overwritten (#15006)", len(c.Entries))
	}
}

func TestDistinctCoSIEEEClassifierBlocksStayDistinct15006(t *testing.T) {
	cfg := mustCompile8436(t, `
class-of-service {
    classifiers {
        ieee-802.1 P1 {
            forwarding-class voice {
                loss-priority low {
                    code-points 5;
                }
            }
        }
        ieee-802.1 P2 {
            forwarding-class best-effort {
                loss-priority low {
                    code-points 0;
                }
            }
        }
    }
}
`)
	if len(cfg.ClassOfService.IEEE8021Classifiers) != 2 {
		t.Fatalf("two different IEEE classifiers produced %d entries, want 2", len(cfg.ClassOfService.IEEE8021Classifiers))
	}
}

func TestDuplicateCoSINetClassifierBlocksMerge15006(t *testing.T) {
	cfg := mustCompile8436(t, `
class-of-service {
    classifiers {
        inet-precedence N1 {
            forwarding-class voice {
                loss-priority low {
                    code-points 5;
                }
            }
        }
        inet-precedence N1 {
            forwarding-class best-effort {
                loss-priority low {
                    code-points 0;
                }
            }
        }
    }
}
`)
	c := cfg.ClassOfService.INetPrecedenceClassifierDefs["N1"]
	if c == nil {
		t.Fatal("inet-precedence classifier N1 did not compile")
	}
	if len(c.Entries) != 2 {
		t.Fatalf("inet-precedence classifier N1 has %d entries, want 2 — first block overwritten (#15006)", len(c.Entries))
	}
	found := 0
	for _, n := range cfg.ClassOfService.INetPrecedenceClassifiers {
		if n == "N1" {
			found++
		}
	}
	if found != 1 {
		t.Fatalf("INetPrecedenceClassifiers contains N1 %d times, want 1 — duplicate names break definedness scans", found)
	}
}

func TestDistinctCoSINetClassifierBlocksStayDistinct15006(t *testing.T) {
	cfg := mustCompile8436(t, `
class-of-service {
    classifiers {
        inet-precedence N1 {
            forwarding-class voice {
                loss-priority low {
                    code-points 5;
                }
            }
        }
        inet-precedence N2 {
            forwarding-class best-effort {
                loss-priority low {
                    code-points 0;
                }
            }
        }
    }
}
`)
	if len(cfg.ClassOfService.INetPrecedenceClassifierDefs) != 2 {
		t.Fatalf("two different inet-precedence classifiers produced %d defs, want 2", len(cfg.ClassOfService.INetPrecedenceClassifierDefs))
	}
}

func TestDuplicateCoSDSCPRewriteBlocksMerge15006(t *testing.T) {
	cfg := mustCompile8436(t, `
class-of-service {
    rewrite-rules {
        dscp R1 {
            forwarding-class voice {
                loss-priority low code-point ef;
            }
        }
        dscp R1 {
            forwarding-class best-effort {
                loss-priority low code-point be;
            }
        }
    }
}
`)
	r := cfg.ClassOfService.DSCPRewriteRules["R1"]
	if r == nil {
		t.Fatal("DSCP rewrite R1 did not compile")
	}
	if len(r.Entries) != 2 {
		t.Fatalf("DSCP rewrite R1 has %d entries, want 2 — first block overwritten (#15006)", len(r.Entries))
	}
}

func TestDistinctCoSDSCPRewriteBlocksStayDistinct15006(t *testing.T) {
	cfg := mustCompile8436(t, `
class-of-service {
    rewrite-rules {
        dscp R1 {
            forwarding-class voice {
                loss-priority low code-point ef;
            }
        }
        dscp R2 {
            forwarding-class best-effort {
                loss-priority low code-point be;
            }
        }
    }
}
`)
	if len(cfg.ClassOfService.DSCPRewriteRules) != 2 {
		t.Fatalf("two different DSCP rewrites produced %d entries, want 2", len(cfg.ClassOfService.DSCPRewriteRules))
	}
}

func TestDuplicateCoSIEEERewriteBlocksMerge15006(t *testing.T) {
	cfg := mustCompile8436(t, `
class-of-service {
    rewrite-rules {
        ieee-802.1 R1 {
            forwarding-class voice {
                loss-priority low code-point 5;
            }
        }
        ieee-802.1 R1 {
            forwarding-class best-effort {
                loss-priority low code-point 0;
            }
        }
    }
}
`)
	r := cfg.ClassOfService.IEEE8021RewriteRules["R1"]
	if r == nil {
		t.Fatal("IEEE rewrite R1 did not compile")
	}
	if len(r.Entries) != 2 {
		t.Fatalf("IEEE rewrite R1 has %d entries, want 2 — first block overwritten (#15006)", len(r.Entries))
	}
}

func TestDistinctCoSIEEERewriteBlocksStayDistinct15006(t *testing.T) {
	cfg := mustCompile8436(t, `
class-of-service {
    rewrite-rules {
        ieee-802.1 R1 {
            forwarding-class voice {
                loss-priority low code-point 5;
            }
        }
        ieee-802.1 R2 {
            forwarding-class best-effort {
                loss-priority low code-point 0;
            }
        }
    }
}
`)
	if len(cfg.ClassOfService.IEEE8021RewriteRules) != 2 {
		t.Fatalf("two different IEEE rewrites produced %d entries, want 2", len(cfg.ClassOfService.IEEE8021RewriteRules))
	}
}

func TestDuplicateCoSINetRewriteBlocksMerge15006(t *testing.T) {
	cfg := mustCompile8436(t, `
class-of-service {
    rewrite-rules {
        inet-precedence R1 {
            forwarding-class voice {
                loss-priority low code-point 5;
            }
        }
        inet-precedence R1 {
            forwarding-class best-effort {
                loss-priority low code-point 0;
            }
        }
    }
}
`)
	r := cfg.ClassOfService.INetPrecedenceRewriteRuleDefs["R1"]
	if r == nil {
		t.Fatal("inet-precedence rewrite R1 did not compile")
	}
	if len(r.Entries) != 2 {
		t.Fatalf("inet-precedence rewrite R1 has %d entries, want 2 — first block overwritten (#15006)", len(r.Entries))
	}
	found := 0
	for _, n := range cfg.ClassOfService.INetPrecedenceRewriteRules {
		if n == "R1" {
			found++
		}
	}
	if found != 1 {
		t.Fatalf("INetPrecedenceRewriteRules contains R1 %d times, want 1", found)
	}
}

func TestDistinctCoSINetRewriteBlocksStayDistinct15006(t *testing.T) {
	cfg := mustCompile8436(t, `
class-of-service {
    rewrite-rules {
        inet-precedence R1 {
            forwarding-class voice {
                loss-priority low code-point 5;
            }
        }
        inet-precedence R2 {
            forwarding-class best-effort {
                loss-priority low code-point 0;
            }
        }
    }
}
`)
	if len(cfg.ClassOfService.INetPrecedenceRewriteRuleDefs) != 2 {
		t.Fatalf("two different inet-precedence rewrites produced %d defs, want 2", len(cfg.ClassOfService.INetPrecedenceRewriteRuleDefs))
	}
}

func TestDuplicateCoSEXPRewriteBlocksMerge15006(t *testing.T) {
	cfg := mustCompile8436(t, `
class-of-service {
    rewrite-rules {
        exp R1 {
            forwarding-class voice {
                loss-priority low code-point 5;
            }
        }
        exp R1 {
            forwarding-class best-effort {
                loss-priority low code-point 0;
            }
        }
    }
}
`)
	r := cfg.ClassOfService.EXPRewriteRuleDefs["R1"]
	if r == nil {
		t.Fatal("exp rewrite R1 did not compile")
	}
	if len(r.Entries) != 2 {
		t.Fatalf("exp rewrite R1 has %d entries, want 2 — first block overwritten (#15006)", len(r.Entries))
	}
	found := 0
	for _, n := range cfg.ClassOfService.EXPRewriteRules {
		if n == "R1" {
			found++
		}
	}
	if found != 1 {
		t.Fatalf("EXPRewriteRules contains R1 %d times, want 1", found)
	}
}

func TestDistinctCoSEXPRewriteBlocksStayDistinct15006(t *testing.T) {
	cfg := mustCompile8436(t, `
class-of-service {
    rewrite-rules {
        exp R1 {
            forwarding-class voice {
                loss-priority low code-point 5;
            }
        }
        exp R2 {
            forwarding-class best-effort {
                loss-priority low code-point 0;
            }
        }
    }
}
`)
	if len(cfg.ClassOfService.EXPRewriteRuleDefs) != 2 {
		t.Fatalf("two different exp rewrites produced %d defs, want 2", len(cfg.ClassOfService.EXPRewriteRuleDefs))
	}
}

// The second-block-empty edge: find-or-create must not let a later block
// that contributes no entries erase an earlier one that did (the current
// code's `len > 0` guard already hinted at this hazard for the fresh-object
// shape; the control pins it after the fix).
func TestCoSEmptySecondClassifierBlockPreservesFirst15006(t *testing.T) {
	cfg := mustCompile8436(t, `
class-of-service {
    classifiers {
        dscp C1 {
            forwarding-class voice {
                loss-priority low {
                    code-points ef;
                }
            }
        }
        dscp C1 {
        }
    }
}
`)
	c := cfg.ClassOfService.DSCPClassifiers["C1"]
	if c == nil || len(c.Entries) != 1 {
		t.Fatalf("empty second block erased the first: %+v", c)
	}
}
