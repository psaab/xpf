package main

import (
	"testing"
)

// #15760: the remote CLI annotate arm split at the first '"' via
// cliterm.AnnotateCommentFromLine + ParseConfigPath on the truncated
// text, so a quoted path element was mistaken for the comment
// boundary. The wire input must be built from the canonical #14717
// split (config.ParseAnnotateRemainder): quoted path elements stay
// path elements (re-quoted for the wire by JoinConfigPathTokens) and
// only the trailing quoted token is the comment.

func TestDispatchConfigAnnotateQuotedPath15760(t *testing.T) {
	fake := &annotateRecorder13554{}
	c := configModeCtl(fake)
	var dispatchErr error
	captureStdout(t, func() {
		dispatchErr = c.dispatchConfig(`annotate groups "my group" system "production comment"`)
	})
	if dispatchErr != nil {
		t.Fatalf("dispatchConfig(annotate quoted path) = %v, want nil", dispatchErr)
	}
	want := `annotate groups "my group" system "production comment"`
	if len(fake.setInputs) != 1 || fake.setInputs[0] != want {
		t.Fatalf("Set inputs = %v, want [%q] (quoted path element preserved, canonical comment)", fake.setInputs, want)
	}
}

// The acceptance spelling from the issue also parses via the remote
// arm when the path element contains a space and the comment follows.
func TestDispatchConfigAnnotateBracketPath15760(t *testing.T) {
	fake := &annotateRecorder13554{}
	c := configModeCtl(fake)
	var dispatchErr error
	captureStdout(t, func() {
		// Bracketed list path element, as lexed by the config lexer.
		dispatchErr = c.dispatchConfig(`annotate system "host name" "edge fw"`)
	})
	if dispatchErr != nil {
		t.Fatalf("dispatchConfig = %v", dispatchErr)
	}
	want := `annotate system "host name" "edge fw"`
	if len(fake.setInputs) != 1 || fake.setInputs[0] != want {
		t.Fatalf("Set inputs = %v, want [%q]", fake.setInputs, want)
	}
}
