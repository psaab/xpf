package main

import (
	"strings"
	"testing"
)

// #16608 remote surface: `edit ... filter "lan in"` must store one lexed
// token, the banner must quote it, and the next `set` wire input must carry
// the quoted cursor so the daemon lexes `filter "lan in" term block ...`
// as the applied filter — not a split `filter lan`.

func TestRemoteEditQuotedWhitespaceFilter16608(t *testing.T) {
	fake := &navRecorder15237{}
	c := configModeCtl(fake)
	var err error
	out := captureStdout(t, func() { err = c.dispatchConfig(`edit firewall family inet filter "lan in"`) })
	if err != nil {
		t.Fatalf("edit: %v", err)
	}
	want := []string{"firewall", "family", "inet", "filter", "lan in"}
	if strings.Join(c.editPath, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("stored editPath = %q, want %q (#16608)", c.editPath, want)
	}
	if !strings.Contains(out, `[edit firewall family inet filter "lan in"]`) {
		t.Fatalf("banner did not quote whitespace filter: %q (#16608)", out)
	}
	captureStdout(t, func() { err = c.dispatchConfig("set term block then discard") })
	if err != nil {
		t.Fatalf("set: %v", err)
	}
	if len(fake.setInputs) != 1 {
		t.Fatalf("Set inputs = %v, want 1", fake.setInputs)
	}
	if fake.setInputs[0] != `"lan in" term block then discard` && !strings.Contains(fake.setInputs[0], `"lan in"`) {
		t.Fatalf("Set input = %q, want quoted \"lan in\" cursor (#16608)", fake.setInputs[0])
	}
	// Exact wire: quoted cursor + raw remainder.
	if fake.setInputs[0] != `firewall family inet filter "lan in" term block then discard` {
		t.Fatalf("Set input = %q, want %q (#16608)", fake.setInputs[0], `firewall family inet filter "lan in" term block then discard`)
	}

	// Control: plain name unchanged, unquoted.
	fake2 := &navRecorder15237{}
	c2 := configModeCtl(fake2)
	captureStdout(t, func() { err = c2.dispatchConfig("edit firewall family inet filter lanin") })
	if err != nil {
		t.Fatalf("edit control: %v", err)
	}
	if got := strings.Join(c2.editPath, " "); got != "firewall family inet filter lanin" {
		t.Fatalf("control editPath = %q", got)
	}
	captureStdout(t, func() { err = c2.dispatchConfig("set term block then discard") })
	if err != nil {
		t.Fatalf("set control: %v", err)
	}
	if len(fake2.setInputs) != 1 || fake2.setInputs[0] != "firewall family inet filter lanin term block then discard" {
		t.Fatalf("control Set inputs = %v (#16608)", fake2.setInputs)
	}

	// up from the whitespace cursor pops the whole filter identity.
	captureStdout(t, func() { err = c.dispatchConfig("up") })
	if err != nil {
		t.Fatalf("up: %v", err)
	}
	if got := strings.Join(c.editPath, " "); got != "firewall family inet" {
		t.Fatalf("editPath after up = %q, want \"firewall family inet\" (#16608)", got)
	}
}
