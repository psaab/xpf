package cliterm

import "testing"

// #7172: SplitPipe is the ONE place a Junos command line is split from its
// output-pipe suffix. It was two byte-identical copies (pkg/cli, cmd/cli) until
// this change.
//
// The corpus below is deliberately shared rather than surface-specific: the
// property being protected is that BOTH CLI surfaces answer "where does the
// command end" identically, because #7172's login-class deny regexes match the
// command and Junos counts the pipe as part of it. A gate and a dispatcher that
// split differently disagree about what the operator ran, and that disagreement
// is the bypass.

func TestSplitPipeCorpus7172(t *testing.T) {
	cases := []struct {
		name                   string
		line                   string
		cmd, pipeType, pipeArg string
		ok                     bool
	}{
		{name: "no pipe", line: "show interfaces",
			cmd: "show interfaces", ok: false},
		{name: "match with arg", line: "show interfaces | match ge-",
			cmd: "show interfaces", pipeType: "match", pipeArg: "ge-", ok: true},
		{name: "count has no arg", line: "show route | count",
			cmd: "show route", pipeType: "count", ok: true},
		{name: "no-more", line: "show configuration | no-more",
			cmd: "show configuration", pipeType: "no-more", ok: true},

		// An unrecognized filter word must return the line UNTOUCHED, not a
		// truncated command. A caller about to authorize the result would
		// otherwise evaluate `show configuration` for a line that actually runs
		// `show configuration | save /tmp/x`.
		{name: "unknown filter returns the whole line",
			line: "show configuration | save /tmp/x",
			cmd:  "show configuration | save /tmp/x", ok: false},
		{name: "display set is not a filter we implement",
			line: "show configuration | display set",
			cmd:  "show configuration | display set", ok: false},

		// Splitting on the LAST " | " means a line whose filter ARGUMENT
		// contains a pipe resolves its trailing token as the filter word.
		// That word is not a filter we implement, so the whole line comes back
		// untouched with ok=false — the command is never truncated.
		//
		// I predicted a truncated command here and was wrong; the fail-safe
		// default arm returns `line`, not the parsed prefix. Recording the real
		// behaviour, because it is the property the gate depends on and the
		// version I guessed would have been the unsafe one.
		{name: "trailing token is not a filter, whole line returned",
			line: "show log | match a | b",
			cmd:  "show log | match a | b", ok: false},

		// #15722: a QUOTED argument pipe is data, not a delimiter: the
		// split lands on the pipe before `match` and the quotes are
		// stripped, so the filter receives the literal `a | b`.
		{name: "pipe inside a quoted arg splits and unquotes",
			line: `show log | match "a | b"`,
			cmd:  "show log", pipeType: "match", pipeArg: "a | b", ok: true},

		// A bare "|" without surrounding spaces is not a pipe separator.
		{name: "no spaces around bar", line: "show interfaces|match ge-",
			cmd: "show interfaces|match ge-", ok: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cmd, pt, pa, ok := SplitPipe(tc.line)
			if cmd != tc.cmd || pt != tc.pipeType || pa != tc.pipeArg || ok != tc.ok {
				t.Errorf("SplitPipe(%q)\n got  (%q, %q, %q, %v)\n want (%q, %q, %q, %v)",
					tc.line, cmd, pt, pa, ok, tc.cmd, tc.pipeType, tc.pipeArg, tc.ok)
			}
		})
	}
}

// The security-relevant property, stated on its own so a failure explains
// itself: when SplitPipe declines to split, the command it returns must be the
// WHOLE line. Returning a prefix would hand an authorization gate a command
// that is not the one about to run.
func TestSplitPipeNeverTruncatesWhenItDeclines7172(t *testing.T) {
	for _, line := range []string{
		"show configuration | save /tmp/x",
		"show configuration | display set",
		"request system reboot | nonsense",
		"show interfaces|match ge-",
		"show interfaces",
	} {
		cmd, _, _, ok := SplitPipe(line)
		if ok {
			continue // split accepted; the suffix is a filter we implement
		}
		if cmd != line {
			t.Errorf("SplitPipe(%q) declined to split but returned a TRUNCATED command %q. "+
				"An authorization gate would then evaluate a command the operator is not "+
				"running — the suffix it dropped is exactly where `| save /tmp/x` lives.",
				line, cmd)
		}
	}
}
