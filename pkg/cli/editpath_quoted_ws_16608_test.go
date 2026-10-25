package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
)

// #16608: `edit firewall family inet filter "lan in"` stored the cursor as
// [firewall family inet filter lan in] (split), so `set term block then
// discard` landed on a new empty filter `lan`, commit check passed, and the
// applied filter "lan in" was unchanged. Acceptance: the defect arm compiles
// "lan in" terms=[allow block], the lanin control is unchanged, both via the
// real dispatchConfig + CompileCandidate/CommitCheck boundary.

func quotedWSStore16608(t *testing.T, filterName string) *configstore.Store {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	// Seed via hier text so the quoted name is exactly one element.
	quoted := filterName
	if strings.Contains(filterName, " ") {
		quoted = `"` + filterName + `"`
	}
	src := `
firewall {
    family inet {
        filter ` + quoted + ` {
            term allow {
                then accept;
            }
        }
    }
}
interfaces {
    ge-0/0/0 {
        unit 0 {
            family inet filter input ` + quoted + `;
        }
    }
}
`
	if err := store.LoadOverride(src); err != nil {
		t.Fatalf("LoadOverride: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	return store
}

func TestLocalEditQuotedWhitespaceFilter16608(t *testing.T) {
	for _, tc := range []struct {
		name   string
		filter string
	}{
		{"defect whitespace", "lan in"},
		{"control plain", "lanin"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := quotedWSStore16608(t, tc.filter)
			c := cliWithDiscardReadline14716(t, store, "")
			editLine := `edit firewall family inet filter "` + tc.filter + `"`
			if !strings.Contains(tc.filter, " ") {
				editLine = "edit firewall family inet filter " + tc.filter
			}
			var editErr, setErr error
			out := captureStdout(t, func() { editErr = c.dispatchConfig(editLine) })
			if editErr != nil {
				t.Fatalf("dispatchConfig(%q): %v", editLine, editErr)
			}
			got := store.GetEditPath()
			wantCursor := []string{"firewall", "family", "inet", "filter", tc.filter}
			if strings.Join(got, "\x00") != strings.Join(wantCursor, "\x00") {
				t.Fatalf("stored cursor = %q, want %q as lexed tokens (#16608)\nbanner: %s", got, wantCursor, out)
			}
			if strings.Contains(tc.filter, " ") && !strings.Contains(out, `filter "lan in"`) {
				t.Fatalf("edit banner did not quote the whitespace filter as one token: %q (#16608)", out)
			}
			captureStdout(t, func() { setErr = c.dispatchConfig("set term block then discard") })
			if setErr != nil {
				t.Fatalf("set term block: %v", setErr)
			}
			if _, err := store.CommitCheck(); err != nil {
				t.Fatalf("CommitCheck: %v", err)
			}
			cfg, err := store.CompileCandidate()
			if err != nil {
				t.Fatalf("CompileCandidate: %v", err)
			}
			if cfg == nil || cfg.Firewall.FiltersInet[tc.filter] == nil {
				t.Fatalf("compiled filter %q missing: %+v (#16608)", tc.filter, cfg)
			}
			var terms []string
			for _, term := range cfg.Firewall.FiltersInet[tc.filter].Terms {
				if term != nil {
					terms = append(terms, term.Name)
				}
			}
			if strings.Join(terms, ",") != "allow,block" {
				t.Fatalf("filter %q terms = %v, want [allow block] (#16608)", tc.filter, terms)
			}
			// The split spelling must not exist as a stray filter (defect arm).
			if tc.filter == "lan in" {
				if _, ok := cfg.Firewall.FiltersInet["lan"]; ok {
					t.Fatalf("stray split filter %q created (#16608): %+v", "lan", cfg.Firewall.FiltersInet)
				}
				cand := store.ShowCandidateSet()
				if strings.Contains(cand, "filter lan ") || strings.Contains(cand, "filter lan\n") {
					t.Fatalf("candidate carries split filter lan:\n%s", cand)
				}
			}
		})
	}
}

// Scoped compare at the whitespace cursor must show the added term under
// the quoted header, not under a split `filter lan` header.
func TestLocalScopedCompareQuotedWhitespace16608(t *testing.T) {
	store := quotedWSStore16608(t, "lan in")
	c := cliWithDiscardReadline14716(t, store, "")
	var err error
	captureStdout(t, func() { err = c.dispatchConfig(`edit firewall family inet filter "lan in"`) })
	if err != nil {
		t.Fatalf("edit: %v", err)
	}
	captureStdout(t, func() { err = c.dispatchConfig("set term block then discard") })
	if err != nil {
		t.Fatalf("set: %v", err)
	}
	out := captureStdout(t, func() { err = c.dispatchConfig("show | compare") })
	if err != nil {
		t.Fatalf("show | compare: %v", err)
	}
	if !strings.Contains(out, "term block") {
		t.Fatalf("scoped compare missing added term:\n%s", out)
	}
	if strings.Contains(out, "[edit firewall family inet filter lan]") || strings.Contains(out, "[edit firewall family inet filter lan in]") {
		t.Fatalf("scoped compare header split the whitespace filter:\n%s", out)
	}
	if !strings.Contains(out, `[edit firewall family inet filter "lan in"]`) && !strings.Contains(out, "[edit firewall family inet filter") {
		t.Fatalf("scoped compare missing filter header:\n%s", out)
	}
}
