package config

import (
	"os"
	"strings"
	"testing"
)

// #8339: a dangling value-taking leaf on an application's DIRECT body committed
// on the STRICT path and then matched every port.
//
// nodeVal returns "" for the 1-key childless node applicationDirectLeaves
// synthesises, resolveAppPort passes that through, and portInSpec("") returns
// true for EVERY port (pkg/appid/runtime.go). So `protocol tcp
// destination-port` — an ordinary typo, one token short — turned a
// single-port application into an all-TCP permit, with the config rendering
// exactly as the operator typed it and no diagnostic anywhere.
//
// The guard already existed for inline `term` bodies (#6564). It had no direct
// twin, which is why this survived: the grep for the term symbols returns
// plenty of hits and the direct one returned none.

func appTree8339(t *testing.T, lines ...string) *ConfigTree {
	t.Helper()
	return buildTreeFromSet(t, lines)
}

func TestDanglingDirectLeafIsRefused8339(t *testing.T) {
	for _, tc := range []struct {
		name string
		set  string
		kw   string
	}{
		{"destination-port", "set applications application a protocol tcp destination-port", "destination-port"},
		{"source-port", "set applications application a protocol tcp source-port", "source-port"},
		{"protocol", "set applications application a protocol", "protocol"},
		{"icmp-type", "set applications application a protocol icmp icmp-type", "icmp-type"},
		{"alg", "set applications application a protocol tcp alg", "alg"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CompileConfig(appTree8339(t, tc.set))
			if err == nil {
				t.Fatalf("strict commit ACCEPTED a dangling %q; the constraint is dropped "+
					"and the application widens", tc.kw)
			}
			if !strings.Contains(err.Error(), tc.kw) {
				t.Errorf("error does not name the offending statement %q: %v", tc.kw, err)
			}
			if !strings.Contains(err.Error(), "missing its value") {
				t.Errorf("error does not say the statement is missing its value, so the "+
					"operator is sent looking for a typo in the KEYWORD: %v", err)
			}
		})
	}
}

// TestCompleteDirectBodyStillCommits8339 is the over-correction control, and it
// is the half that decides whether this change is safe to ship.
//
// A guard that refuses working configs on upgrade is worse than the fail-open
// it replaces: the fail-open widens one application, the over-correction bricks
// a commit. Each case below is a body that MUST still compile.
func TestCompleteDirectBodyStillCommits8339(t *testing.T) {
	for _, tc := range []struct{ name, set string }{
		{"port with a value", "set applications application a protocol tcp destination-port 22"},
		{"protocol only", "set applications application a protocol tcp"},
		// description is deliberately NOT in the arity contract: a dangling one
		// drops a cosmetic field and widens nothing, so refusing it would add
		// commit failures with no security benefit.
		{"bare description", "set applications application a protocol tcp description"},
		{"description with text", "set applications application a protocol tcp description hello"},
		// `term` is a container, not a value-taking leaf.
		{"term body", "set applications application a term t1 protocol tcp destination-port 22"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := CompileConfig(appTree8339(t, tc.set)); err != nil {
				t.Errorf("strict commit REFUSED a valid body (%s): %v", tc.set, err)
			}
		})
	}
}

// TestTermPathGuardStillFires8339 is the required regression: the two paths now
// share one arity contract, and a shared implementation must not weaken the
// case that already worked.
func TestTermPathGuardStillFires8339(t *testing.T) {
	_, err := CompileConfig(appTree8339(t,
		"set applications application a term t1 protocol tcp destination-port"))
	if err == nil {
		t.Fatal("the TERM-path dangling-leaf guard stopped firing; sharing the arity " +
			"contract with the direct body has weakened the case #6564 already fixed")
	}
	if !strings.Contains(err.Error(), "destination-port") {
		t.Errorf("term-path error does not name the statement: %v", err)
	}
}

// TestDanglingDirectLeafOnATermBearingBodyIsRefused8339 covers the branch that
// DISCARDS the parent app struct.
//
// compiler_applications.go carries UnknownDirectLeaves onto each generated term
// for exactly this reason (#6524), and a field added without that carry escapes
// the strict gate entirely while every other test here still passes.
func TestDanglingDirectLeafOnATermBearingBodyIsRefused8339(t *testing.T) {
	_, err := CompileConfig(appTree8339(t,
		"set applications application a destination-port",
		"set applications application a term t1 protocol tcp destination-port 22"))
	if err == nil {
		t.Fatal("a dangling direct leaf on a TERM-BEARING application was accepted; the " +
			"parent app struct is discarded on that branch, so the verdict must be " +
			"carried onto the generated terms or it escapes the gate")
	}
}

// TestValueTakingLeavesCoverEveryDirectConsumingArm8339 is the direct-body twin
// of the #6564 coverage gate: a future value-taking leaf added to the direct
// switch without joining the arity contract silently re-opens the fail-open,
// and every behavioural test above would still pass because they can only
// exercise keywords someone remembered to list.
func TestValueTakingLeavesCoverEveryDirectConsumingArm8339(t *testing.T) {
	src, err := os.ReadFile("compiler_applications.go")
	if err != nil {
		t.Fatalf("read compiler_applications.go: %v", err)
	}
	body := string(src)
	start := strings.Index(body, "directLeaves, unknownDirect, unknownDirectTokens := applicationDirectLeaves")
	if start < 0 {
		t.Fatal("the direct-body loop was not found; this gate is bound to it by the " +
			"applicationDirectLeaves call and must be re-pointed if that moves")
	}
	rest := body[start:]
	end := strings.Index(rest, "\n\t\tapp.DuplicateDirectLeaves")
	if end < 0 {
		t.Fatal("could not find the end of the direct-body loop")
	}
	fn := rest[:end]

	checked := 0
	for _, line := range strings.Split(fn, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "case \"") {
			continue
		}
		// One arm may list several keywords: `case "inactivity-timeout", "timeout":`
		for _, part := range strings.Split(strings.TrimSuffix(trimmed[len("case "):], ":"), ",") {
			kw := strings.Trim(strings.TrimSpace(part), "\"")
			if kw == "" {
				continue
			}
			// Does this arm read a value? Every direct arm that does reads it
			// through nodeVal(prop).
			armStart := strings.Index(fn, trimmed)
			armRest := fn[armStart+len(trimmed):]
			armEnd := strings.Index(armRest, "\n\t\t\tcase ")
			if armEnd < 0 {
				armEnd = len(armRest)
			}
			if !strings.Contains(armRest[:armEnd], "nodeVal(prop)") {
				continue
			}
			// description is the documented exclusion: it consumes a value but
			// a dangling one widens nothing.
			if kw == "description" {
				continue
			}
			checked++
			if !valueTakingApplicationLeaves[kw] {
				t.Errorf("the direct-body switch arm %q reads nodeVal(prop) but %q is NOT in "+
					"valueTakingApplicationLeaves — a dangling %q will be compiled with an "+
					"empty value instead of refused, and an empty port spec matches "+
					"EVERY port", kw, kw, kw)
			}
		}
	}
	if checked == 0 {
		t.Fatal("the scan matched no value-consuming arms; the parse has stopped working " +
			"and this gate is vacuous")
	}
}
