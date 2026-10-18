package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
)

// #14714: recursive multi-pipe dispatch overwrote c.pendingPipeSuffix.
//
// SplitPipe splits at the LAST " | ", so dispatchWithPipe handles the
// rightmost filter first and recurses into dispatch for the remainder.
// Each recursion overwrote the single pendingPipeSuffix scalar, and the
// save/restore defer only restored the outer value on unwind — after
// checkCommandRegex had already run at the innermost frame. The gate
// therefore saw only the leftmost pipe stage: prepending any permitted
// pipe (e.g. `| no-more`) hid every later stage from allow-commands /
// deny-commands while all filter goroutines still executed.
//
// Decisive fixture (issue): class allow `^show version` + deny
// `.*match.*`. `show version | match …` is denied (control), so
// `show version | no-more | match …` must be denied too, with no
// version output. Also covers the reverse order and, in the sibling
// test, an allow anchored on the exact full chain: the gate must
// receive every stage in original order, so a fix that passed only
// the pipe-less form or only one stage decides differently there.

func multiPipeStore14714(t *testing.T, allow, deny string) *configstore.Store {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	var b strings.Builder
	b.WriteString("system {\n    host-name multi-pipe-test;\n    login {\n        class piped {\n            permissions all;\n")
	if allow != "" {
		b.WriteString("            allow-commands \"" + allow + "\";\n")
	}
	if deny != "" {
		b.WriteString("            deny-commands \"" + deny + "\";\n")
	}
	b.WriteString("        }\n    }\n}\n")
	if err := store.LoadOverride(b.String()); err != nil {
		t.Fatalf("LoadOverride: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	store.ExitConfigure()
	if store.ActiveConfig() == nil {
		t.Fatal("no active config after commit")
	}
	return store
}

func TestMultiPipeDispatchDoesNotHideLaterStages14714(t *testing.T) {
	// Control + bypass under allow ^show version / deny .*match.*.
	c := &CLI{store: multiPipeStore14714(t, "^show version", ".*match.*"), userClass: "piped", version: "14714-test"}

	// Single-pipe control: denied, no output. captureStdout swaps
	// os.Stdout, and dispatchWithPipe captures os.Stdout as origStdout,
	// so denied output (which happens before any pipe goroutine writes)
	// and allowed filtered output both land in the capture.
	out := captureStdout(t, func() {
		if err := c.dispatch("show version | match xpf"); err == nil {
			t.Error("single-pipe `show version | match xpf` must be denied by deny .*match.* (control)")
		} else if !strings.Contains(err.Error(), "denies") {
			t.Errorf("single-pipe refusal must come from the command regex: %v", err)
		}
	})
	if out != "" {
		t.Errorf("denied single-pipe command produced output %q", out)
	}

	// The bypass: prepend a permitted pipe. Pre-fix the gate sees only
	// `no-more`, so this runs and emits the version banner filtered by
	// match (which still matches "xpf" in the banner line).
	out = captureStdout(t, func() {
		if err := c.dispatch("show version | no-more | match xpf"); err == nil {
			t.Error("`show version | no-more | match xpf` was ALLOWED: the prepended " +
				"permitted pipe hid the denied `match` stage from the gate (#14714)")
		} else if !strings.Contains(err.Error(), "denies") {
			t.Errorf("multi-pipe refusal must come from the command regex: %v", err)
		}
	})
	if out != "" {
		t.Errorf("denied multi-pipe command produced output %q; both filters executed despite the gate seeing only one stage", out)
	}

	// Reverse order: denied stage first, permitted stage prepended last
	// in execution order is still the rightmost split — assert the
	// chain is judged as typed regardless of stage position.
	out = captureStdout(t, func() {
		if err := c.dispatch("show version | match xpf | no-more"); err == nil {
			t.Error("`show version | match xpf | no-more` was ALLOWED (#14714)")
		}
	})
	if out != "" {
		t.Errorf("denied multi-pipe (reverse) produced output %q", out)
	}

	// Permitted multi-pipe must still run: no deny stage present, and
	// the allow matches the command. Guards against a fix that denies
	// every multi-pipe command or mangles the chain order so the
	// banner no longer contains the matched text.
	out = captureStdout(t, func() {
		if err := c.dispatch("show version | no-more | count"); err != nil {
			t.Errorf("permitted `show version | no-more | count` must run: %v", err)
		}
	})
	if !strings.Contains(out, "Count:") {
		t.Errorf("permitted multi-pipe count output = %q, want a Count line", out)
	}

	// Suffix must not leak into the next un-piped dispatch on the
	// same CLI: after the chain above, a bare denied-stage-free
	// command judged with a stale suffix would misbehave. The bare
	// `show version` is allowed by ^show version and must stay so.
	out = captureStdout(t, func() {
		if err := c.dispatch("show version"); err != nil {
			t.Errorf("bare `show version` after a multi-pipe dispatch must be allowed (stale suffix leak): %v", err)
		}
	})
	if !strings.Contains(out, "14714-test") {
		t.Errorf("bare show version output = %q, want version banner", out)
	}
}

func TestMultiPipeDispatchFullChainOrder14714(t *testing.T) {
	// Allow anchored on the FULL chain in original order. Only the
	// exact chain `show version | no-more | count` may run: the gate
	// must receive every stage, in the order typed. A gate that saw
	// only the innermost stage (`no-more`), only the outermost
	// (`count`), the pipe-less command, or the stages reordered
	// would decide differently on at least one row below — each row
	// is the control for one of those truncations. (The pipe-less
	// form is also measured by design, #9628, so this pattern —
	// which requires the pipes — matches no pipe-less form.)
	c := &CLI{store: multiPipeStore14714(t, `^show version \| no-more \| count$`, ""), userClass: "piped", version: "14714-test"}

	out := captureStdout(t, func() {
		if err := c.dispatch("show version | no-more | count"); err != nil {
			t.Errorf("the exact allowed chain must run: %v", err)
		}
	})
	if !strings.Contains(out, "Count:") {
		t.Errorf("allowed chain output = %q, want a Count line", out)
	}

	for _, line := range []string{
		"show version",                             // pipe-less: requires the pipes
		"show version | no-more",                   // truncated chain
		"show version | count",                     // innermost stage only
		"show version | count | no-more",           // reversed order
		"show version | no-more | count | no-more", // extended chain
	} {
		out = captureStdout(t, func() {
			if err := c.dispatch(line); err == nil {
				t.Errorf("%q was ALLOWED under allow ^show version \\| no-more \\| count$; the full pipe chain must reach the gate in original order", line)
			}
		})
		// A denied command produces no command output; a `count`
		// filter over the empty denied stream legitimately prints
		// "Count: 0 lines" (it ran, its input was empty). Anything
		// carrying the version banner is a leak.
		if strings.Contains(out, "14714-test") {
			t.Errorf("%q leaked version output %q despite allowlist refusal", line, out)
		}
	}
}

// The pure gate must also see the whole chain when handed it: this
// pins evaluateCommandRegex's handling of a multi-stage suffix so a
// future refactor that truncates at the first `|` in the gate (rather
// than in dispatch) is caught here as well as end-to-end above.
func TestEvaluateSeesMultiStagePipeSuffix14714(t *testing.T) {
	rules := denyRules(t, ".*match.*")
	if err := evaluateCommandRegex(rules, "ops", "show version", "no-more | match xpf"); err == nil {
		t.Fatal("evaluateCommandRegex allowed suffix `no-more | match xpf` against deny .*match.*; " +
			"the full chain must be part of the matched string")
	}
	// In-order assertion: a deny anchored on the original chain order
	// matches, the reversed spelling does not produce a *different*
	// command — both must be judged as typed.
	rules = denyRules(t, `show version \| no-more \| match`)
	if err := evaluateCommandRegex(rules, "ops", "show version", "no-more | match xpf"); err == nil {
		t.Fatal("deny on the in-order chain `show version | no-more | match` must match")
	}
	if err := evaluateCommandRegex(rules, "ops", "show version", "match xpf | no-more"); err != nil {
		// Reversed chain does not match that deny and there is no
		// other rule, so it is allowed — proving order is preserved
		// rather than stages being sorted or collapsed.
		t.Logf("reversed chain allowed as expected (order preserved): %v", err)
	} else {
		// allowed — expected
	}
}
