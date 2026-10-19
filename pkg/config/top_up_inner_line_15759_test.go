package config

import "testing"

// #15759: ParseTopUpPrefix15082 must return the raw inner tail
// (innerLine) sliced from the original line after the consumed
// top/up [n] prefix, so quoted strings with spaces, bracket lists,
// and pipe modifiers survive to the dispatcher instead of being
// destroyed by a strings.Join(inner, " ") round-trip.

func TestParseTopUpPrefixPreservesQuotesPipesAndBrackets(t *testing.T) {
	editPath := []string{"interfaces", "ge-0/0/0"}
	_, inner, innerLine, ok := ParseTopUpPrefix15082(editPath, `top annotate system "lab router"`)
	if !ok || len(inner) == 0 || innerLine != `annotate system "lab router"` {
		t.Fatalf("expected innerLine to preserve quoted annotate comment, got ok=%v inner=%v innerLine=%q", ok, inner, innerLine)
	}
	_, inner, innerLine, ok = ParseTopUpPrefix15082(editPath, `top show | compare`)
	if !ok || len(inner) == 0 || innerLine != `show | compare` {
		t.Fatalf("expected innerLine to preserve '| compare' pipe, got ok=%v inner=%v innerLine=%q", ok, inner, innerLine)
	}
	_, inner, innerLine, ok = ParseTopUpPrefix15082(editPath, `up set ge-0/0/1 description "wan  uplink"`)
	if !ok || innerLine != `set ge-0/0/1 description "wan  uplink"` {
		t.Fatalf("expected innerLine to preserve doubled spaces inside quotes, got ok=%v inner=%v innerLine=%q", ok, inner, innerLine)
	}
	// Bracket list: raw brackets survive slicing; the token view
	// still strips them (lexer sugar) for gate/arity consumers.
	_, inner, innerLine, ok = ParseTopUpPrefix15082(editPath, `top set interfaces ge-0/0/0 unit 0 family inet address [ 10.0.0.1/24 10.0.0.2/24 ]`)
	if !ok || innerLine != `set interfaces ge-0/0/0 unit 0 family inet address [ 10.0.0.1/24 10.0.0.2/24 ]` {
		t.Fatalf("expected innerLine to preserve bracket list, got ok=%v inner=%v innerLine=%q", ok, inner, innerLine)
	}
	// Display pipe with a quoted pipe inside a value.
	_, _, innerLine, ok = ParseTopUpPrefix15082(editPath, `top show | display set`)
	if !ok || innerLine != `show | display set` {
		t.Fatalf("expected innerLine to preserve display pipe, got ok=%v innerLine=%q", ok, innerLine)
	}
	// up with an explicit count: the count token is part of the
	// consumed prefix, not the inner line.
	target, _, innerLine, ok := ParseTopUpPrefix15082(editPath, `up 1 set description "a b"`)
	if !ok || innerLine != `set description "a b"` {
		t.Fatalf("up 1: got ok=%v innerLine=%q, want set description quoted", ok, innerLine)
	}
	if len(target) != 1 || target[0] != "interfaces" {
		t.Fatalf("up 1 target = %v, want [interfaces]", target)
	}
	// Bare navigation yields no inner line.
	_, inner, innerLine, ok = ParseTopUpPrefix15082(editPath, `top`)
	if !ok || len(inner) != 0 || innerLine != "" {
		t.Fatalf("bare top: got ok=%v inner=%v innerLine=%q, want bare", ok, inner, innerLine)
	}
	// Malformed prefixes stay not-ok.
	if _, _, _, ok := ParseTopUpPrefix15082(editPath, `up 99 set description "a b"`); ok {
		t.Fatalf("up 99 prefixed: ok=true, want fail-closed")
	}
	// A quoted "up" must not be mistaken for a count token: the raw
	// tail keeps the quote so annotate can re-parse it.
	_, _, innerLine, ok = ParseTopUpPrefix15082(editPath, `top annotate system "a | b"`)
	if !ok || innerLine != `annotate system "a | b"` {
		t.Fatalf("quoted pipe: got ok=%v innerLine=%q", ok, innerLine)
	}
}
