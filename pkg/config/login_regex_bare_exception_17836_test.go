package config

import "testing"

// #17836: the REST pre-buffer bare judge (pkg/api authorizeRESTCommandBare)
// sees only the argument-free charge ("ping") before the body is read.
// A bare tier-denied verdict is FINAL only when no argument-bearing
// extension of that charge could carry the deny-with-exceptions
// geometry (isCoreException): an allow exception written for a longer
// command that does not cover the bare charge at the vetoing deny's
// extent. BareVerdictFinal reports exactly that, so the pre-buffer
// pass defers precisely the verdicts pass 2 could overturn — and
// still denies pre-buffer when no exception geometry is possible.
func TestBareVerdictFinal17836(t *testing.T) {
	compile := func(allow string, allowSet bool, deny string, denySet bool) CompiledLoginRegexes {
		t.Helper()
		r, err := CompileLoginRegexes(LoginRegexPlainFamily, allow, allowSet, deny, denySet)
		if err != nil {
			t.Fatalf("compile allow=%q deny=%q: %v", allow, deny, err)
		}
		return r
	}
	cases := []struct {
		name  string
		rules CompiledLoginRegexes
		bare  string
		final bool
	}{
		// The failing cell: deny ^ping$ + allow ^ping 10.98.1.1$ over
		// bare "ping". The allow does not match the bare charge at
		// all, so an argued form could carry the exception (and
		// EvaluateForms confirms it does). Not final: defer.
		{"argument-scoped exception candidate", compile(`^ping 10\.98\.1\.1$`, true, `^ping$`, true), "ping", false},
		// Deny-only class: no allow leaf, no exception can exist.
		// Final: the #13249 pre-buffer deny stands.
		{"deny only", compile("", false, `^ping$`, true), "ping", true},
		// Wildcard allow covers the bare charge at exactly the
		// deny's extent (^ping.* vs ^ping$): isCoreException's last
		// clause excludes it post-buffer too, so the bare veto is
		// final.
		{"wildcard allow covers bare at deny extent", compile(`^ping.*`, true, `^ping$`, true), "ping", true},
		// Allow matches the bare charge and loses the tie (^ping
		// vs ^ping$ on "ping"): post-buffer EvaluateForms denies
		// the argued form as well (allow extent never exceeds the
		// deny's on the truncated core), so final.
		{"allow matches bare but does not out-measure deny", compile(`^ping`, true, `^ping$`, true), "ping", true},
		// Allow matches the bare charge and BEATS the deny there
		// (^ping 10 vs ^ping$ cannot arise on bare; use a bare the
		// allow out-measures): the bare verdict is allowed, so the
		// question is vacuous — report final (nothing to defer;
		// the caller only asks on denied verdicts, and must not
		// treat "not final" as a reason to deny an allowed bare).
		{"bare itself allowed", compile(`^ping`, true, `^ping 10$`, true), "ping", true},
		// No deny match on the bare charge: nothing vetoed, final.
		{"no deny on bare", compile(`^ping 10\.98\.1\.1$`, true, `^traceroute$`, true), "ping", false},
		// Allow-only class (allowlist miss on bare, DecidedBy=Allow):
		// an argued form matching the allow is exactly the #17836
		// allow leg, so not final.
		{"allow-only allowlist miss", compile(`^ping 10\.98\.`, true, "", false), "ping", false},
		// Neither leaf: allowed, final.
		{"no regexes", compile("", false, "", false), "ping", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.rules.BareVerdictFinal(tc.bare); got != tc.final {
				t.Fatalf("BareVerdictFinal(%q) = %v, want %v", tc.bare, got, tc.final)
			}
		})
	}
}

// Console-parity pin for the same shapes: the post-buffer judge
// (EvaluateForms over [full, bare]) must agree with the deferral —
// every not-final bare above has an argued form whose full-form
// verdict differs from the bare verdict, and every final bare's
// argued forms stay denied. This guards BareVerdictFinal against
// drifting from isCoreException.
func TestBareVerdictFinalConsoleParity17836(t *testing.T) {
	rules, err := CompileLoginRegexes(LoginRegexPlainFamily, `^ping 10\.98\.1\.1$`, true, `^ping$`, true)
	if err != nil {
		t.Fatal(err)
	}
	if d := rules.EvaluateForms("ping 10.98.1.1", "ping 10.98.1.1", "ping"); !d.Allowed {
		t.Fatalf("console/post-buffer exception form denied: %+v", d)
	}
	if d := rules.EvaluateForms("ping 10.98.1.2", "ping 10.98.1.2", "ping"); d.Allowed {
		t.Fatalf("non-exception argued form allowed: %+v", d)
	}
	if rules.BareVerdictFinal("ping") {
		t.Fatal("bare ping verdict reported final, but the exception form above overturns it")
	}
}
