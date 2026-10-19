package config

import (
	"strings"
	"testing"
)

// #15192 (D07-01): a repeated hierarchical `term T` stanza inside one
// firewall filter strict-commits with zero warnings as two separate
// same-named terms. Flat-set and `load merge` produce one merged term
// instead. The installed filter therefore differs from what was authored,
// and the duplicate (filter,family,term) series fails every Prometheus
// scrape with HTTP 500.
//
// Measured RED at base: both texts below compile strict with no error and
// no warning, and each filter carries TWO terms named T. The merged/flat
// oracle carries ONE.
//
// FAIL-ON-REVERT: removing the validateFirewallFilterDuplicateTermsAST
// call in compiler_prewalk.go (or neutering the validator) makes the
// strict cells compile clean again and the lenient warning vanish.

const dupTermText15192 = `
firewall {
    family inet {
        filter F {
            term T {
                from {
                    protocol tcp;
                }
                then accept;
            }
            term T {
                from {
                    destination-port 80;
                }
                then discard;
            }
        }
    }
}
`

const mergedTermText15192 = `
firewall {
    family inet {
        filter F {
            term T {
                from {
                    protocol tcp;
                    destination-port 80;
                }
                then discard;
            }
        }
    }
}
`

const distinctTermText15192 = `
firewall {
    family inet {
        filter F {
            term T1 {
                from {
                    protocol tcp;
                }
                then accept;
            }
            term T2 {
                from {
                    destination-port 80;
                }
                then discard;
            }
        }
    }
}
`

func parseHier15192(t *testing.T, text string) *ConfigTree {
	t.Helper()
	tree, perrs := NewParser(text).Parse()
	if len(perrs) != 0 {
		t.Fatalf("parse: %v", perrs)
	}
	return tree
}

func TestDuplicateFilterTermRejectedStrict15192(t *testing.T) {
	_, err := CompileConfig(parseHier15192(t, dupTermText15192))
	if err == nil {
		t.Fatal("strict CompileConfig accepted a repeated term T stanza inside one filter; " +
			"it must reject naming the duplicate term (#15192)")
	}
	if !strings.Contains(err.Error(), "duplicate") || !strings.Contains(err.Error(), `"T"`) {
		t.Fatalf("strict error must name the duplicate term T, got: %v", err)
	}
	if !strings.Contains(err.Error(), "filter") {
		t.Fatalf("strict error must name the filter context, got: %v", err)
	}
}

func TestDuplicateFilterTermRejectedInet6AndAny15192(t *testing.T) {
	for _, fam := range []string{"inet6", "any"} {
		text := strings.Replace(dupTermText15192, "family inet {", "family "+fam+" {", 1)
		_, err := CompileConfig(parseHier15192(t, text))
		if err == nil {
			t.Fatalf("family %s: strict CompileConfig accepted a repeated term T stanza (#15192)", fam)
		}
		if !strings.Contains(err.Error(), `"T"`) {
			t.Fatalf("family %s: strict error must name the duplicate term T, got: %v", fam, err)
		}
	}
}

func TestDuplicateFilterTermLenientWarnsAndPreserves15192(t *testing.T) {
	cfg, err := CompileConfigLenient(parseHier15192(t, dupTermText15192))
	if err != nil {
		t.Fatalf("lenient compile must still boot (#1960), got error: %v", err)
	}
	if cfg == nil {
		t.Fatal("lenient compile returned nil config")
	}
	found := false
	for _, w := range cfg.Warnings {
		lw := strings.ToLower(w)
		if strings.Contains(lw, "duplicate") && strings.Contains(w, `"T"`) {
			found = true
		}
	}
	if !found {
		t.Fatalf("lenient path must warn naming the duplicate term T (#15192), warnings=%v", cfg.Warnings)
	}
	// Historical behaviour preserved on the tolerant path: both authored
	// terms survive (the metrics aggregator now folds them into one series).
	f := cfg.Firewall.FiltersInet["F"]
	if f == nil {
		t.Fatal("lenient: filter F missing")
	}
	if len(f.Terms) != 2 || f.Terms[0].Name != "T" || f.Terms[1].Name != "T" {
		t.Fatalf("lenient: want two surviving T terms (historical), got %+v", f.Terms)
	}
}

func TestMergedAndDistinctFilterTermsCompile15192(t *testing.T) {
	// Oracle: the hand-merged spelling is ONE term and must compile clean.
	cfg, err := CompileConfig(parseHier15192(t, mergedTermText15192))
	if err != nil {
		t.Fatalf("merged single-term filter must compile strict: %v", err)
	}
	f := cfg.Firewall.FiltersInet["F"]
	if f == nil || len(f.Terms) != 1 || f.Terms[0].Name != "T" {
		t.Fatalf("merged oracle: want one term T, got %+v", f)
	}
	for _, w := range cfg.Warnings {
		if strings.Contains(strings.ToLower(w), "duplicate") && strings.Contains(w, `"T"`) {
			t.Fatalf("merged oracle must not warn about duplicate term T, warnings=%v", cfg.Warnings)
		}
	}
	// Control: two DIFFERENT term names in one filter must compile clean —
	// an over-broad gate that rejects any second term fails here.
	cfg2, err := CompileConfig(parseHier15192(t, distinctTermText15192))
	if err != nil {
		t.Fatalf("distinct term names must compile strict: %v", err)
	}
	f2 := cfg2.Firewall.FiltersInet["F"]
	if f2 == nil || len(f2.Terms) != 2 {
		t.Fatalf("distinct control: want two terms, got %+v", f2)
	}
	// Control: the same term name in two DIFFERENT filters is legitimate.
	twoFilters := `
firewall {
    family inet {
        filter F1 {
            term T { then accept; }
        }
        filter F2 {
            term T { then discard; }
        }
    }
}
`
	if _, err := CompileConfig(parseHier15192(t, twoFilters)); err != nil {
		t.Fatalf("same term name in different filters must compile strict: %v", err)
	}
}

func TestDuplicateFilterTermImplicitInet15192(t *testing.T) {
	// Implicit-inet spelling: `firewall { filter F { ... } }` with no family.
	text := `
firewall {
    filter F {
        term T {
            from { protocol tcp; }
            then accept;
        }
        term T {
            from { destination-port 80; }
            then discard;
        }
    }
}
`
	_, err := CompileConfig(parseHier15192(t, text))
	if err == nil {
		t.Fatal("implicit-inet: strict CompileConfig accepted a repeated term T stanza (#15192)")
	}
	if !strings.Contains(err.Error(), `"T"`) {
		t.Fatalf("implicit-inet: strict error must name the duplicate term T, got: %v", err)
	}
}
