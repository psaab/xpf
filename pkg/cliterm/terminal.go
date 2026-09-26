// Package cliterm holds the terminal-input primitives shared by the local
// console CLI (pkg/cli) and the remote CLI client (cmd/cli).
//
// It exists because those two surfaces had SEPARATE copies of the
// `load ... terminal` read loop and the copies diverged: #4883-D fixed the
// abort semantics on the remote CLI and the console kept the original
// break-on-any-error loop for two more years, silently applying
// Ctrl-C-truncated configurations (#6548). A divergence between the two is
// ALWAYS a bug — both drive the same readline instance and owe the operator
// the same answer — so the loop lives here once rather than being duplicated
// and held in step by a test.
//
// The package is deliberately tiny and dependency-light (readline plus the
// standard library) so the remote CLI binary can import it without pulling in
// the whole interactive console.
package cliterm

import (
	"fmt"
	"io"
	"strings"

	"github.com/chzyer/readline"
)

// DisableReadlineHistoryAutoSave prevents readline from persisting submitted
// CLI lines, which may contain credentials.
func DisableReadlineHistoryAutoSave(cfg *readline.Config) *readline.Config {
	cfg.DisableAutoSaveHistory = true
	return cfg
}

// ReadConfig collects a pasted configuration from readLine until the input is
// COMMITTED by Ctrl-D (io.EOF). A readline.ErrInterrupt (Ctrl-C) or any other
// read error is an ABORT: the partial input is discarded and a non-nil error
// is returned, so the caller does NOT apply a truncated subset of the config
// as if it were complete.
//
// The distinction is the whole point. Both CLIs originally took the same
// `break` for EOF, ErrInterrupt, and every read error, then joined whatever
// lines had been collected, Loaded them, and printed "load ... complete". An
// operator who aborts a paste is told it succeeded, and a truncated
// `security policies` stanza is a WIDENED one — the deny terms that would have
// followed never arrive. Only EOF commits.
//
// It returns the empty string on abort rather than the partial content: a
// caller cannot accidentally use a discarded paste, and the empty-input check
// callers already perform is not the thing standing between a Ctrl-C and a
// truncated commit.
func ReadConfig(readLine func() (string, error)) (string, error) {
	var lines []string
	for {
		line, err := readLine()
		if err != nil {
			if err == io.EOF {
				return strings.Join(lines, "\n"), nil
			}
			if err == readline.ErrInterrupt {
				return "", fmt.Errorf("load terminal: aborted (partial input discarded)")
			}
			return "", fmt.Errorf("load terminal: read error: %v", err)
		}
		lines = append(lines, line)
	}
}
