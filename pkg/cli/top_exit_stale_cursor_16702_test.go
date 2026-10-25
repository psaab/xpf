package cli

import (
	"strings"
	"testing"
)

// #16702: `top exit` / `up N exit` on the local surface restored the
// pre-exit edit cursor and the config (#) prompt after the inner exit
// had released configuration mode (exitConfigureTop cleared
// configOwned and restored the operational prompt). The console was
// left in operational mode still showing #. FAIL-ON-REVERT: restoring
// the unconditional restore in dispatchTopUp15082 turns the defect
// cells RED (cursor resurrected, prompt back to #).

func TestLocalTopExitDoesNotRestoreStaleCursor16702(t *testing.T) {
	for _, line := range []string{"top exit", "top quit"} {
		store := topUpStore15082(t)
		c := cliTopUp15082(t, store)
		c.configOwned = true
		store.SetEditPath([]string{"routing-instances", "RI1"})
		c.rl.SetPrompt(c.configPrompt())
		var err error
		out := captureStdout(t, func() { err = c.dispatchConfig(line) })
		if err != nil {
			t.Fatalf("%q: %v (#16702)", line, err)
		}
		if !strings.Contains(out, "Exiting configuration mode") {
			t.Fatalf("%q: missing exit banner: %q (#16702)", line, out)
		}
		if store.InConfigMode() {
			t.Fatalf("%q: still in configuration mode after top-level exit (#16702)", line)
		}
		if c.configOwned {
			t.Fatalf("%q: configOwned still set after release (#16702)", line)
		}
		if got := store.GetEditPath(); len(got) != 0 {
			t.Fatalf("%q: edit path = %v, want empty after release — stale cursor restored (#16702)", line, got)
		}
	}
}

// Control: a top-prefixed mutation that stays in configuration mode
// still restores the cursor (the #15082 contract is unchanged).
func TestLocalTopSetStillRestoresCursor16702(t *testing.T) {
	store := topUpStore15082(t)
	c := cliTopUp15082(t, store)
	c.configOwned = true
	store.SetEditPath([]string{"security", "policies"})
	var err error
	captureStdout(t, func() { err = c.dispatchConfig("top set system host-name edge16702") })
	if err != nil {
		t.Fatalf("top set: %v (#16702 control)", err)
	}
	if !store.InConfigMode() || !c.configOwned {
		t.Fatalf("top set left configuration mode: InConfigMode=%v configOwned=%v (#16702 control)", store.InConfigMode(), c.configOwned)
	}
	if got := store.GetEditPath(); strings.Join(got, " ") != "security policies" {
		t.Fatalf("edit path = %v, want cursor restored after top set (#16702 control)", got)
	}
	if out := store.ShowCandidateSet(); !strings.Contains(out, "edge16702") {
		t.Fatalf("top set did not stage host-name at the root (#16702 control):\n%s", out)
	}
}
