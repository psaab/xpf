package config

import (
	"strings"
	"testing"
)

// TestQuotedPaddedSigningKeyIsDistinctTransition17888 pins #17888: a
// quoted PSK whose boundary spaces are genuine key bytes (the lexer
// copies them into the string token, and the runtime installs
// []byte(Reveal()) untrimmed) is a DIFFERENT signing key from the
// unpadded spelling. The #16858 transition interlock must compare the
// exact runtime bytes, so switching from active {A} to a candidate
// signing `" A "` is a one-shot key change the active config does not
// accept and must be refused — with staging required first.
func TestQuotedPaddedSigningKeyIsDistinctTransition17888(t *testing.T) {
	paddedA := " " + keyA16858 + " "

	// Fixture sanity: the quoted spelling must survive as distinct
	// bytes in the compiled candidate, otherwise the assertions below
	// cannot observe the defect.
	quoted, err := CompileConfig(clusterTree16858(t, `"`+paddedA+`"`, ""))
	if err != nil {
		t.Fatalf("quoted padded candidate fixture: %v", err)
	}
	if got := quoted.Chassis.Cluster.ControlLinkAuthKey.Reveal(); got != paddedA {
		t.Fatalf("quoted padded key compiled to %q, want byte-exact %q — "+
			"fixture does not preserve the boundary whitespace as PSK bytes", got, paddedA)
	}

	// Directed case: active signs A, candidate signs quoted " A ".
	// Byte-exact, these differ, so the transition gate must refuse
	// unless the padded form was staged as the additional key.
	activeA := currentConfig16858(t, keyA16858, "")

	if _, err := CompileConfigWithCurrentClusterPrimary(clusterTree16858(t, `"`+paddedA+`"`, ""), activeA); err == nil {
		t.Fatal("quoted padded signing key \" A \" committed over active {A}: " +
			"byte-different PSK treated as the same transition (#17888)")
	} else if !strings.Contains(err.Error(), "additional-authentication-key") {
		t.Fatalf("rejection must point at the overlap procedure: %v", err)
	}

	// Inverse: active signs the quoted padded key, candidate signs
	// the unpadded spelling — equally a byte change.
	activePadded := currentConfig16858(t, `"`+paddedA+`"`, "")
	if _, err := CompileConfigWithCurrentClusterPrimary(clusterTree16858(t, keyA16858, ""), activePadded); err == nil {
		t.Fatal("unpadded signing key committed over active {\" A \"}: " +
			"byte-different PSK treated as the same transition (#17888)")
	}

	// Staged control: once the padded form is staged as the active
	// additional key, signing with it byte-exact is a legitimate
	// step-3/4 rotation and must be accepted.
	activeStaged := currentConfig16858(t, keyA16858, `"`+paddedA+`"`)
	if _, err := CompileConfigWithCurrentClusterPrimary(clusterTree16858(t, `"`+paddedA+`"`, keyA16858), activeStaged); err != nil {
		t.Fatalf("staged quoted padded key rotation rejected: %v", err)
	}

	// Byte-identical control: the same quoted padded key on both
	// sides is a routine same-key commit.
	if _, err := CompileConfigWithCurrentClusterPrimary(clusterTree16858(t, `"`+paddedA+`"`, ""), activePadded); err != nil {
		t.Fatalf("byte-identical quoted padded key rejected: %v", err)
	}
	// A quote-preserved, byte-distinct additional key is a real
	// two-key overlap, even though trimming makes it resemble A.
	if _, err := CompileConfigWithCurrentClusterPrimary(
		clusterTree16858(t, keyA16858, `"`+paddedA+`"`), activeA); err != nil {
		t.Fatalf("byte-distinct padded additional key rejected as degenerate overlap: %v", err)
	}
}
