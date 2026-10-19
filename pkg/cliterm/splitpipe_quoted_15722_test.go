package cliterm

import (
	"bytes"
	"strings"
	"testing"
)

// #15722 V47-03: quoted pipe arguments must be unquoted, and a quoted
// " | " must not be mistaken for a pipe delimiter.

func TestSplitPipeQuotedArg15722(t *testing.T) {
	cases := []struct {
		name                   string
		line                   string
		cmd, pipeType, pipeArg string
		ok                     bool
	}{
		{name: "double quoted with spaces", line: `show interfaces | match "Physical interface"`,
			cmd: "show interfaces", pipeType: "match", pipeArg: "Physical interface", ok: true},
		{name: "double quoted pipe", line: `show log | match "a | b"`,
			cmd: "show log", pipeType: "match", pipeArg: "a | b", ok: true},
		{name: "single quoted pipe", line: `show log | match 'a | b'`,
			cmd: "show log", pipeType: "match", pipeArg: "a | b", ok: true},
		{name: "single quoted spaces", line: `show interfaces | except 'Physical interface'`,
			cmd: "show interfaces", pipeType: "except", pipeArg: "Physical interface", ok: true},
		{name: "find quoted", line: `show configuration | find "routing-options"`,
			cmd: "show configuration", pipeType: "find", pipeArg: "routing-options", ok: true},
		{name: "quoted empty", line: `show log | match ""`,
			cmd: "show log", pipeType: "match", pipeArg: "", ok: true},
		{name: "escaped double quote", line: `show log | match "a \"b\" c"`,
			cmd: "show log", pipeType: "match", pipeArg: `a "b" c`, ok: true},
		{name: "escaped backslash before close", line: `show log | match "a\\"`,
			cmd: "show log", pipeType: "match", pipeArg: `a\`, ok: true},
		// Unquoted neighbours unchanged.
		{name: "unquoted plain", line: "show interfaces | match ge-",
			cmd: "show interfaces", pipeType: "match", pipeArg: "ge-", ok: true},
		{name: "unquoted with spaces stays whole", line: "show log | match Physical interface",
			cmd: "show log", pipeType: "match", pipeArg: "Physical interface", ok: true},
		{name: "unquoted internal quote kept", line: `show log | match a"b`,
			cmd: "show log", pipeType: "match", pipeArg: `a"b`, ok: true},
		{name: "unquoted trailing quote kept", line: `show log | match a"`,
			cmd: "show log", pipeType: "match", pipeArg: `a"`, ok: true},
		{name: "mismatched quotes kept", line: `show log | match "a'`,
			cmd: "show log", pipeType: "match", pipeArg: `"a'`, ok: true},
		{name: "unterminated double quoted falls to unquoted form", line: `show log | match "a | b`,
			cmd: "show log", pipeType: "match", pipeArg: `"a | b`, ok: true},
		{name: "unterminated no-pipe-in-arg", line: `show log | match "abc`,
			cmd: "show log", pipeType: "match", pipeArg: `"abc`, ok: true},
		// Quote-aware delimiter search.
		{name: "quoted pipe in quoted cmd segment", line: `show log | match "a | b" | count`,
			cmd: `show log | match "a | b"`, pipeType: "count", pipeArg: "", ok: true},
		{name: "unquoted arg pipe still declines", line: "show log | match a | b",
			cmd: "show log | match a | b", ok: false},
		{name: "quoted pipe before unknown still declines whole", line: `show log | match "a | b" | frobnicate x`,
			cmd: `show log | match "a | b" | frobnicate x`, ok: false},
		{name: "unknown filter whole", line: "show configuration | save /tmp/x",
			cmd: "show configuration | save /tmp/x", ok: false},
		{name: "quoted region hides later pipe in cmd arg", line: `show "a | match x" | count`,
			cmd: `show "a | match x"`, pipeType: "count", pipeArg: "", ok: true},
		{name: "last quoted arg", line: `show log | last "5"`,
			cmd: "show log", pipeType: "last", pipeArg: "5", ok: true},
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

func TestSplitPipeQuotedFiltersEndToEnd15722(t *testing.T) {
	input := "Physical interface: ge-0/0/0\nLogical interface xe-0/0/1\na | b segment\nother\n"
	for _, tc := range []struct {
		name, line, want string
	}{
		{"match quoted spaces", `show interfaces | match "Physical interface"`, "Physical interface: ge-0/0/0\n"},
		{"match quoted pipe", `show log | match "a | b"`, "a | b segment\n"},
		{"match single quoted pipe", `show log | match 'a | b'`, "a | b segment\n"},
		{"except quoted spaces", `show interfaces | except "Physical interface"`, "Logical interface xe-0/0/1\na | b segment\nother\n"},
		{"find quoted", `show log | find "a | b"`, "a | b segment\nother\n"},
		{"unquoted match", `show log | match other`, "other\n"},
		{"unquoted except", `show log | except other`, "Physical interface: ge-0/0/0\nLogical interface xe-0/0/1\na | b segment\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, pt, pa, ok := SplitPipe(tc.line)
			if !ok {
				t.Fatalf("SplitPipe(%q) ok=false", tc.line)
			}
			var out bytes.Buffer
			FilterStream(strings.NewReader(input), &out, pt, pa)
			if out.String() != tc.want {
				t.Errorf("FilterStream via SplitPipe(%q) = %q, want %q", tc.line, out.String(), tc.want)
			}
		})
	}
}
