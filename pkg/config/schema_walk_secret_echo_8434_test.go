package config

import (
	"strings"
	"testing"
)

// #8434: a typed-leaf validation error must never render the VALUE of a leaf
// the secret registry claims.
//
// The leak was in `typedLeafInvalidErrorf`, which quoted the offending token,
// AND in the validator's own message (schema_validators.go's
// "invalid value %q (expected one of: ...)"), so the canary appeared TWICE in
// one error. Redacting only the wrapper leaves the leak.
//
// This is keyed on the REGISTRY, not on a list of leaves: `secretLeafKeywords`
// already claimed `encrypted-password` while this path rendered it anyway.

const secretCanary8434 = "PLAINTEXTCANARY123"

// The canary must not appear in a commit error for a leaf the registry claims.
// RED before #8434 with TWO occurrences.
func TestSecretLeafValueNeverEchoedInCommitError8434(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  string
	}{
		{
			name: "login user encrypted-password",
			cfg: `system {
    login {
        user alice {
            authentication {
                encrypted-password "` + secretCanary8434 + `";
            }
        }
    }
}`,
		},
		{
			name: "root-authentication encrypted-password",
			cfg: `system {
    root-authentication {
        encrypted-password "` + secretCanary8434 + `";
    }
}`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree := parseHier(t, tc.cfg)
			// SchemaValidate, NOT CompileConfig. The typed-leaf validators —
			// including ValidateCryptHash, which is what rejects this value —
			// run here; CompileConfig is a layer BELOW and returns nil for
			// this input. An earlier draft of this cell used CompileConfig,
			// got no error, and SKIPPED every subtest while the parent
			// reported PASS. That is the same layer confusion this finding's
			// source review made throughout, reproduced inside the test for
			// it.
			err := SchemaValidate(tree, nil)
			if err == nil {
				t.Fatal("fixture must produce a validation error, or this cell " +
					"proves nothing — a value the validator ACCEPTS never reaches " +
					"the error renderer under test")
			}
			if n := strings.Count(err.Error(), secretCanary8434); n != 0 {
				t.Errorf("the commit error echoed the credential %d time(s); a leaf in "+
					"secretLeafKeywords must never have its value rendered (#8434).\n"+
					"got: %v", n, err)
			}
		})
	}
}

// #16066 fold (Codex on #16090): the ADDITIONAL-token arm. When the first
// encrypted-password value is a VALID hash, validateTypedLeaf accepts it
// and then formats any extra token via typedLeafErrorf("unknown modifier
// %q") — which (pre-fold) quoted a plaintext pasted as that extra token
// straight into the schema error that tolerant ingress logs. The token
// must never appear; the "unknown modifier" defect class must survive.
// RED pre-fold with the canary quoted in the error.
func TestSecretLeafExtraTokenNeverEchoed16066(t *testing.T) {
	const validHash = "$6$saltsalt$qFmFH.bQmmtXzyBY0s9v7Oicd2z4XSIecDzlB5KiA2/jctKu9YterLp8wwnSq.qc.eoxqOmSuNp2xS0ktL3nh/"
	for _, tc := range []struct {
		name string
		cfg  string
	}{
		{
			name: "login user encrypted-password extra token",
			cfg: `system {
    login {
        user alice {
            authentication {
                encrypted-password "` + validHash + `" "` + secretCanary8434 + `";
            }
        }
    }
}`,
		},
		{
			name: "root-authentication encrypted-password extra token",
			cfg: `system {
    root-authentication {
        encrypted-password "` + validHash + `" "` + secretCanary8434 + `";
    }
}`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree := parseHier(t, tc.cfg)
			err := SchemaValidate(tree, nil)
			if err == nil {
				t.Fatal("fixture must produce a validation error (extra token), " +
					"or this cell proves nothing")
			}
			if strings.Contains(err.Error(), secretCanary8434) {
				t.Errorf("the commit error echoed the additional credential token "+
					"of a secret leaf (#16066): %v", err)
			}
			if !strings.Contains(err.Error(), "unknown modifier") {
				t.Errorf("the error lost its defect-class diagnostic: %v", err)
			}
		})
	}
	// Positive control: typedLeafErrorf on a NON-secret leaf still quotes
	// its token, so the redaction stays registry-scoped (not blanket).
	ctrl := typedLeafErrorf([]string{"system", "host-name"}, "unknown modifier %q", "bogusmod")
	if !strings.Contains(ctrl.Error(), `"bogusmod"`) {
		t.Errorf("non-secret leaf must keep its quoted modifier diagnostic; got: %v", ctrl)
	}
}

// POSITIVE CONTROL on the instrument: a NON-secret leaf must still quote its
// value. Without this, a change that redacted every validation error would pass
// the cell above while destroying every ordinary diagnostic.
//
// Asserted DIRECTLY on typedLeafInvalidErrorf rather than through a config
// fixture. The first draft used `system host-name "bad name with spaces"`,
// which compiles cleanly — so the cell SKIPPED, and a skipped control has no
// power at all. Driving the function directly cannot skip and cannot drift onto
// a different error path: `interfaces ... unit foo` also fails validation, but
// through a different message builder, so it would have exercised nothing here.
func TestNonSecretLeafStillQuotesItsValue8434(t *testing.T) {
	err := typedLeafInvalidErrorf(
		[]string{"system", "host-name"}, "bad name", errTyped8434{})
	got := err.Error()
	if strings.Contains(got, "<redacted>") {
		t.Errorf("a non-secret leaf must keep its value in the error — redaction is "+
			"scoped to the secret registry, not applied to every typed leaf (#8434).\n"+
			"got: %v", got)
	}
	if !strings.Contains(got, "bad name") {
		t.Errorf("a non-secret leaf's value must still be quoted so the operator can "+
			"see what was rejected; got: %v", got)
	}
	if !strings.Contains(got, "the reason") {
		t.Errorf("the validator's own message must survive for a non-secret leaf; "+
			"got: %v", got)
	}
}

// errTyped8434 stands in for a validator's own error so the control can assert
// the reason survives, without depending on which validator a real fixture hits.
type errTyped8434 struct{}

func (errTyped8434) Error() string { return "the reason" }

// The registry is the enumeration, and this cell says so: every keyword the
// registry claims must be redacted by the SAME code path.
//
// It binds the AGREEMENT between the registry and the error renderer rather
// than naming leaves. A cell pinning `encrypted-password` leaves the next typed
// secret leaf to reintroduce the leak — which is exactly how this one arrived
// while `pre-shared-key` was already correct.
func TestEverySecretKeywordIsRedactedByTheSamePath8434(t *testing.T) {
	if !IsSecretLeafKeyword("encrypted-password") {
		t.Fatal("premise: the registry must claim encrypted-password, or this cell " +
			"and #8434 are about different things")
	}
	if IsSecretLeafKeyword("host-name") {
		t.Fatal("negative control: host-name must NOT be claimed, or the registry " +
			"predicate cannot discriminate and the cell above passes vacuously")
	}
	for _, kw := range []string{"encrypted-password", "pre-shared-key", "password"} {
		if !IsSecretLeafKeyword(kw) {
			t.Errorf("registry no longer claims %q — if it was deliberately removed, "+
				"this cell and the redaction it guards need re-scoping together", kw)
			continue
		}
		err := typedLeafInvalidErrorf([]string{"system", kw}, secretCanary8434, nil)
		if strings.Contains(err.Error(), secretCanary8434) {
			t.Errorf("typedLeafInvalidErrorf echoed the value for registry keyword %q "+
				"(#8434): %v", kw, err)
		}
	}
}
