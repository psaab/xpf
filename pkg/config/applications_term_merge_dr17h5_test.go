package config_test

// #14434 (DR17-H5): a group `applications application <name> term <term>`
// packed leaf beside an inline term leaf was dropped whole by the
// apply-groups leaf merge. `term` is an opaque schema leaf (args:1,
// children:nil), so namedLeafPeer9859 returned identity=false, leafListPeer
// matched the inline term by keyword alone, no union/promotion path applied
// (term is not multi, children==nil), and the leaf branch fell through to the
// inline-wins `continue`. Two cells were lost:
//   - different name (group t2 beside inline t1): the whole group term
//     vanished — compiled implicit set was [myapp-t1] only, so a deny on
//     myapp never matched the group term's protocol/port.
//   - same name (group t1 ... alg ssh beside inline t1 ... destination-port
//     22): the group term was dropped whole, losing its non-conflicting alg
//     tail and widening the term.
//
// FAIL-ON-REVERT: removing the applications-term admission in mergeNodes
// drops the group terms again; every group+inline cell below goes RED. The
// adopt-beside collision control pins that group-container vs inline-leaf
// same-name twins still reach the collision gate (fail-closed), not a
// silent merge.

import (
	"sort"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func appTermSet14434(t *testing.T, cfg *config.Config) []string {
	t.Helper()
	set := cfg.Applications.ApplicationSets["myapp"]
	if set == nil {
		t.Fatalf("no implicit application-set myapp; sets=%v apps=%v", cfg.Applications.ApplicationSets, cfg.Applications.Applications)
	}
	got := append([]string(nil), set.Applications...)
	sort.Strings(got)
	return got
}

func assertAppTerms14434(t *testing.T, cfg *config.Config, want ...string) {
	t.Helper()
	got := appTermSet14434(t, cfg)
	sortedWant := append([]string(nil), want...)
	sort.Strings(sortedWant)
	if strings.Join(got, ",") != strings.Join(sortedWant, ",") {
		t.Fatalf("implicit set applications = %v, want %v", got, sortedWant)
	}
}

func TestGroupApplicationTermLeafLeaf14434(t *testing.T) {
	t.Run("different name group term beside inline term both compile", func(t *testing.T) {
		cfg := compileHier(t, `
groups {
  G {
    applications {
      application myapp {
        term t2 protocol udp destination-port 53;
      }
    }
  }
}
applications {
  application myapp {
    term t1 protocol tcp destination-port 22;
    apply-groups G;
  }
}
`)
		assertAppTerms14434(t, cfg, "myapp-t1", "myapp-t2")
		t1 := cfg.Applications.Applications["myapp-t1"]
		if t1 == nil || t1.Protocol != "tcp" || t1.DestinationPort != "22" {
			t.Fatalf("myapp-t1 = %+v", t1)
		}
		t2 := cfg.Applications.Applications["myapp-t2"]
		if t2 == nil || t2.Protocol != "udp" || t2.DestinationPort != "53" {
			t.Fatalf("myapp-t2 = %+v, want udp/53 from group term", t2)
		}
	})

	t.Run("different name flat-set", func(t *testing.T) {
		cfg := compileFlat(t,
			"set groups G applications application myapp term t2 protocol udp destination-port 53",
			"set applications application myapp term t1 protocol tcp destination-port 22",
			"set applications application myapp apply-groups G",
		)
		assertAppTerms14434(t, cfg, "myapp-t1", "myapp-t2")
	})

	t.Run("same name merges bodies inline wins alg preserved", func(t *testing.T) {
		cfg := compileHier(t, `
groups {
  G {
    applications {
      application myapp {
        term t1 protocol tcp alg ssh;
      }
    }
  }
}
applications {
  application myapp {
    term t1 protocol tcp destination-port 22;
    apply-groups G;
  }
}
`)
		assertAppTerms14434(t, cfg, "myapp-t1")
		got := cfg.Applications.Applications["myapp-t1"]
		if got == nil {
			t.Fatal("myapp-t1 missing")
		}
		if got.Protocol != "tcp" || got.DestinationPort != "22" {
			t.Fatalf("myapp-t1 = %+v, want inline tcp/22", got)
		}
		if got.ALG != "ssh" {
			t.Fatalf("myapp-t1 ALG = %q, want group alg ssh preserved", got.ALG)
		}
	})

	t.Run("same name inline wins on conflicting leaf", func(t *testing.T) {
		cfg := compileHier(t, `
groups {
  G {
    applications {
      application myapp {
        term t1 protocol tcp destination-port 53 alg ssh;
      }
    }
  }
}
applications {
  application myapp {
    term t1 protocol tcp destination-port 22;
    apply-groups G;
  }
}
`)
		assertAppTerms14434(t, cfg, "myapp-t1")
		got := cfg.Applications.Applications["myapp-t1"]
		if got == nil || got.DestinationPort != "22" || got.ALG != "ssh" {
			t.Fatalf("myapp-t1 = %+v, want inline port 22 wins, group alg preserved", got)
		}
	})
	t.Run("same name flat-set merges", func(t *testing.T) {
		cfg := compileFlat(t,
			"set groups G applications application myapp term t1 protocol tcp alg ssh",
			"set applications application myapp term t1 protocol tcp destination-port 22",
			"set applications application myapp apply-groups G",
		)
		assertAppTerms14434(t, cfg, "myapp-t1")
		got := cfg.Applications.Applications["myapp-t1"]
		if got == nil || got.DestinationPort != "22" || got.ALG != "ssh" {
			t.Fatalf("myapp-t1 = %+v", got)
		}
	})

	t.Run("flat chained different name adopts beside", func(t *testing.T) {
		cfg := compileFlat(t,
			"set groups G applications application myapp term t2 protocol udp destination-port 53",
			"set applications application myapp term t1 protocol tcp destination-port 22",
			"set applications application myapp apply-groups G",
		)
		// flat chained t2 already adopted beside pre-fix; pin it stays.
		assertAppTerms14434(t, cfg, "myapp-t1", "myapp-t2")
	})

	t.Run("identical same name term not duplicated", func(t *testing.T) {
		cfg := compileHier(t, `
groups {
  G {
    applications {
      application myapp {
        term t1 protocol tcp destination-port 22;
      }
    }
  }
}
applications {
  application myapp {
    term t1 protocol tcp destination-port 22;
    apply-groups G;
  }
}
`)
		assertAppTerms14434(t, cfg, "myapp-t1")
	})

	t.Run("adopt-beside collision gate unchanged", func(t *testing.T) {
		// Group braced (container) term t1 beside inline packed leaf term t1:
		// this shape is adopted beside today and the collision gate must
		// still reject the duplicate generated name.
		tree, perrs := config.NewParser(`
groups {
  G {
    applications {
      application myapp {
        term t1 {
          protocol udp;
          destination-port 53;
        }
      }
    }
  }
}
applications {
  application myapp {
    term t1 protocol tcp destination-port 22;
    apply-groups G;
  }
}
`).Parse()
		if len(perrs) > 0 {
			t.Fatalf("parse: %v", perrs)
		}
		_, err := config.CompileConfig(tree)
		if err == nil {
			t.Fatal("adopt-beside same-name twins must still be rejected by collision gate")
		}
		if !strings.Contains(err.Error(), "myapp-t1") {
			t.Fatalf("collision error should name myapp-t1, got %v", err)
		}
	})

	t.Run("inline only control", func(t *testing.T) {
		cfg := compileHier(t, `
applications {
  application myapp {
    term t1 protocol tcp destination-port 22;
  }
}
`)
		assertAppTerms14434(t, cfg, "myapp-t1")
	})

	t.Run("group only control", func(t *testing.T) {
		cfg := compileHier(t, `
groups {
  G {
    applications {
      application myapp {
        term t2 protocol udp destination-port 53;
      }
    }
  }
}
applications {
  application myapp {
    apply-groups G;
  }
}
`)
		assertAppTerms14434(t, cfg, "myapp-t2")
	})
}
