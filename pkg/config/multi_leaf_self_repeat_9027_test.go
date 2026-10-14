package config

import (
	"strings"
	"testing"
)

// #9027: a missing semicolon in a multi-value run injected the leaf's own
// keyword as a VALUE, and at `api-auth expires 2099-01-01 api-key` that value is a CREDENTIAL:
//
//	api-key AAA api-key BBB;   ->  keys = ["AAA", "api-key", "BBB"]
//
// The injected credential is a PREDICTABLE, PUBLICLY-KNOWN ENGLISH LITERAL, so
// anyone who can reach the management listener can present
// `X-API-Key: api-key`. The braced spelling of the same intent yields two keys.
//
// THE TWO READERS OF THIS SHAPE GUESSED OPPOSITE WAYS — firewallMatchValues
// skips the repeat (#8883, an EXPERIMENT, which silently drops a
// legitimately-named object per #9029) and multiLeafAuthoredValues accepts it
// (which injects). Both are guesses at an input that is genuinely ambiguous, so
// this refuses instead of choosing one.

func selfRepeatTree9027(t *testing.T, text string) *ConfigTree {
	t.Helper()
	root, perrs := NewParser(text).Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse: %v", perrs)
	}
	return &ConfigTree{Children: root.Children}
}

func TestMultiLeafSelfRepeatIsRefused9027(t *testing.T) {
	const apiAuth = `system { services { web-management { api-auth { %s } } } }`
	for _, tc := range []struct {
		name       string
		text       string
		wantRefuse bool
	}{
		// THE DEFECT.
		// CONTROLS — every legitimate spelling of the same intent must survive.
		// Without these, "refuse everything" would satisfy the row above.

		// NOTE (#12553): the original api-key rows are gone — the parser
		// now normalizes `api-key A api-key B` into two singleton leaves
		// (#10825), so the run never reaches this gate as one leaf; a
		// credential literally named api-key must be quoted (#9029 row).
		// A DIFFERENT multi leaf, to show the gate is keyed on the shape and
		// not on `api-key`.
		{"firewall match run repeats its keyword",
			`firewall { family inet { filter F { term t1 {
				from { protocol tcp protocol udp; } then { discard; } } } } }`, true},
		{"firewall match, bracketed list",
			`firewall { family inet { filter F { term t1 {
				from { protocol [ tcp udp ]; } then { discard; } } } } }`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tr := selfRepeatTree9027(t, tc.text)
			_, err := CompileConfig(tr)
			if (err != nil) != tc.wantRefuse {
				t.Fatalf("refused=%v, want %v (err=%v)", err != nil, tc.wantRefuse, err)
			}
			if !tc.wantRefuse {
				return
			}
			// The message must offer BOTH readings. A refusal that says only
			// "ambiguous" leaves the operator to guess which fix is meant.
			for _, want := range []string{"missing a semicolon", "named"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("the refusal does not offer both readings (missing %q): %v", want, err)
				}
			}
			// #1960: the tolerant path must WARN, never refuse.
			lc, lerr := CompileConfigLenient(tr)
			if lerr != nil {
				t.Fatalf("the LENIENT path rejected — a persisted config would fail to "+
					"load (#1960): %v", lerr)
			}
			var warned bool
			for _, w := range lc.Warnings {
				if strings.Contains(w, "repeats its own keyword") {
					warned = true
				}
			}
			if !warned {
				t.Error("the lenient path accepted the ambiguous run with NO warning")
			}
		})
	}
	_ = apiAuth
}

// TestApiKeyLiteralIsNotMintedAsACredential9027 is the security assertion,
// stated as the thing an attacker would use rather than as a count.
// #12553 update: the parser now normalizes the packed run into two
// singleton leaves (#10825), so the literal is never minted on ANY path —
// the residual this test used to log is closed; assert it stays closed.
func TestApiKeyLiteralIsNotMintedAsACredential9027(t *testing.T) {
	tr := selfRepeatTree9027(t,
		`system { services { web-management { api-auth { expires 2099-01-01; api-key AAA api-key BBB; } } } }`)
	for _, compile := range []struct {
		name string
		fn   func(*ConfigTree) (*Config, error)
	}{
		{"strict", CompileConfig},
		{"lenient", CompileConfigLenient},
	} {
		cfg, err := compile.fn(tr)
		if err != nil {
			t.Fatalf("%s: %v", compile.name, err)
		}
		if a := cfg.System.Services.WebManagement.APIAuth; a != nil {
			for _, k := range a.APIKeys {
				if k.Reveal() == "api-key" {
					t.Fatalf("%s: the literal keyword was minted as a credential", compile.name)
				}
			}
		}
	}
}
