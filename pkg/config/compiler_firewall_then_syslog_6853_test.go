package config

import "testing"

// #6853: `then log` and `then syslog` name DIFFERENT sinks in Junos — the
// firewall filter log buffer (`show firewall log`) and the system log
// respectively — but both spellings compiled to `term.Log` alone, so the two
// were indistinguishable in the model and could never be routed apart.
//
// What this change does and does NOT do, because the difference is the whole
// point of shipping it separately from #6859:
//
//   - It makes the distinction REPRESENTABLE. `then syslog` now sets Syslog in
//     addition to Log.
//   - It changes NO behaviour. `then syslog` already reached the system log,
//     because filter-log events are categorised CategoryFirewall
//     (pkg/logging/ringbuf.go) and the syslog fan-out is gated only by a
//     per-CLIENT category filter, never per-term. Both spellings emitted, and
//     both still do.
//
// Keeping Log set on the syslog arm is therefore load-bearing rather than
// conservative: Log is what makes the dataplane emit a filter-log event at
// all, so clearing it would stop `then syslog` producing anything — a
// regression dressed as a fix.
//
// #6859 owns the other direction (whether `then log` should STOP reaching
// syslog), which is a real behaviour change with a migration cost.
func TestThenSyslogIsDistinctFromThenLog_6853(t *testing.T) {
	// compileFilterThen has TWO switches and the spellings do not map onto
	// them the way the names suggest. Measured, not assumed:
	//
	//   compact  `then syslog;`      -> Keys=[then syslog] IsLeaf=true  -> LEAF switch
	//   block    `then { syslog; }`  -> Keys=[then]        IsLeaf=false -> hierarchical
	//   flat set `... then syslog`   -> Keys=[then]        IsLeaf=false -> hierarchical
	//
	// So the flat-set spelling does NOT exercise the leaf arm — it lands on the
	// same switch as the block form. An earlier revision of this test had a
	// cell labelled "flat set (leaf form)" and believed it covered the leaf
	// arm; deleting `term.Syslog = true` from that arm left the whole file
	// GREEN. The compact cell below is the one that binds it.
	t.Run("compact leaf `then syslog;` (the LEAF switch)", func(t *testing.T) {
		tree := parseHierText(t, `
firewall {
    family inet {
        filter f {
            term only_log    { then log; }
            term only_syslog { then syslog; }
            term both        { then log; then syslog; }
        }
    }
}
`)
		assertSyslogTerms6853(t, tree)
	})

	t.Run("block `then { syslog; }` (the hierarchical switch)", func(t *testing.T) {
		tree := parseHierText(t, `
firewall {
    family inet {
        filter f {
            term only_log    { then { log; } }
            term only_syslog { then { syslog; } }
            term both        { then { log; syslog; } }
        }
    }
}
`)
		assertSyslogTerms6853(t, tree)
	})

	// Same switch as the block form, but a distinct entry path (ParseSetCommand
	// + SetPath) and the spelling operators actually type, so it stays a cell.
	t.Run("flat set (also the hierarchical switch)", func(t *testing.T) {
		tree := flatTreeFromSets(t,
			"set firewall family inet filter f term only_log then log",
			"set firewall family inet filter f term only_syslog then syslog",
			"set firewall family inet filter f term both then log",
			"set firewall family inet filter f term both then syslog",
		)
		assertSyslogTerms6853(t, tree)
	})
}

func assertSyslogTerms6853(t *testing.T, tree *ConfigTree) {
	t.Helper()
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	filter := cfg.Firewall.FiltersInet["f"]
	if filter == nil {
		t.Fatalf("filter f did not compile; FiltersInet = %+v", cfg.Firewall.FiltersInet)
	}
	byName := map[string]*FirewallFilterTerm{}
	for _, term := range filter.Terms {
		if term != nil {
			byName[term.Name] = term
		}
	}
	for _, c := range []struct {
		term       string
		wantLog    bool
		wantSyslog bool
	}{
		{"only_log", true, false},
		// Log stays TRUE on the syslog arm. It is what makes the term emit a
		// filter-log event at all; a fix that cleared it would silently stop
		// `then syslog` producing anything.
		{"only_syslog", true, true},
		{"both", true, true},
	} {
		term := byName[c.term]
		if term == nil {
			t.Errorf("term %q missing; got %v", c.term, keysOf6853(byName))
			continue
		}
		if term.Log != c.wantLog {
			t.Errorf("term %q: Log = %v, want %v", c.term, term.Log, c.wantLog)
		}
		if term.Syslog != c.wantSyslog {
			t.Errorf("term %q: Syslog = %v, want %v — `then log` and `then syslog` must be "+
				"distinguishable, or #6859 can never route them apart",
				c.term, term.Syslog, c.wantSyslog)
		}
	}
}

func keysOf6853(m map[string]*FirewallFilterTerm) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
