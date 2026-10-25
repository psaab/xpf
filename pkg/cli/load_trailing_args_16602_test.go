package cli

import (
	"io"
	"strings"
	"testing"
)

// #16602: both CLIs' `load merge|set|override <source>` ignored every token
// after the source, including the Junos `relative` modifier. A snippet meant
// for the `[edit ...]` cursor was applied at the root and reported as
// `load <mode> complete`, committing clean whenever it was also valid at the
// root. The fix refuses any token after the source, before reading content.
//
// FAIL-ON-REVERT: delete the `len(args) > 2` guard in handleLoad and every
// cell below goes green on the defect — terminal cells consume the scripted
// paste and mutate the candidate at the root; the file cell loads the file.

func TestConsoleLoadTrailingArgRefused16602(t *testing.T) {
	modes := []string{"merge", "set", "override"}
	extras := []string{"relative", "bogus"}

	for _, mode := range modes {
		for _, extra := range extras {
			t.Run(mode+"_terminal_"+extra, func(t *testing.T) {
				r := &scriptedReader{
					lines: []string{
						"set routing-options static route 0.0.0.0/0 next-hop 192.0.2.1",
						"system {",
						"    host-name fw-trailing;",
						"}",
					},
					endErr: io.EOF,
				}
				c := newLoadCLI(t, r)
				before := c.store.ShowCandidate()
				err := c.handleLoad([]string{mode, "terminal", extra})
				if err == nil {
					t.Fatalf("load %s terminal %s reported success; the trailing token must be refused (#16602)", mode, extra)
				}
				if !strings.Contains(err.Error(), `unexpected argument "`+extra+`"`) {
					t.Fatalf("error = %q, want it to name the unexpected argument %q", err, extra)
				}
				if r.i != 0 {
					t.Fatalf("terminal was read (%d lines) before the trailing argument was refused; nothing may be consumed", r.i)
				}
				if got := c.store.ShowCandidate(); got != before {
					t.Fatalf("candidate mutated by a refused load:\nbefore:\n%s\nafter:\n%s", before, got)
				}
			})
		}
	}

	t.Run("merge_file_relative", func(t *testing.T) {
		r := &scriptedReader{endErr: io.EOF}
		c := newLoadCLI(t, r)
		path := writeConf9892(t, "system {\n    host-name fw-trailing;\n}\n")
		before := c.store.ShowCandidate()
		err := c.handleLoad([]string{"merge", path, "relative"})
		if err == nil || !strings.Contains(err.Error(), `unexpected argument "relative"`) {
			t.Fatalf("load merge <file> relative error = %v, want unexpected-argument refusal (#16602)", err)
		}
		if got := c.store.ShowCandidate(); got != before {
			t.Fatalf("candidate mutated by a refused file load:\nbefore:\n%s\nafter:\n%s", before, got)
		}
	})

	t.Run("multiple_trailing_tokens_name_first", func(t *testing.T) {
		r := &scriptedReader{endErr: io.EOF}
		c := newLoadCLI(t, r)
		err := c.handleLoad([]string{"merge", "terminal", "bogus", "trailing", "tokens"})
		if err == nil || !strings.Contains(err.Error(), `unexpected argument "bogus"`) {
			t.Fatalf("error = %v, want refusal naming the first extra token", err)
		}
	})

	// Narrowness: the exact two-argument forms still load.
	t.Run("plain_merge_terminal_still_loads", func(t *testing.T) {
		r := &scriptedReader{
			lines:  []string{"system {", "    host-name fw-plain;", "}"},
			endErr: io.EOF,
		}
		c := newLoadCLI(t, r)
		if err := c.handleLoad([]string{"merge", "terminal"}); err != nil {
			t.Fatalf("plain load merge terminal refused: %v", err)
		}
		if got := c.store.ShowCandidate(); !strings.Contains(got, "fw-plain") {
			t.Fatalf("plain load did not reach candidate:\n%s", got)
		}
	})
}
