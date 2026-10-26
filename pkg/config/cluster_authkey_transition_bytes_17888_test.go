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

func strictSessionClusterTree17888(t *testing.T, primary, additional string) *ConfigTree {
	t.Helper()
	lines := []string{
		"set chassis cluster cluster-id 1",
		"set chassis cluster strict-session-auth",
	}
	if primary != "" {
		lines = append(lines, "set chassis cluster authentication-key "+primary)
	}
	if additional != "" {
		lines = append(lines, "set chassis cluster additional-authentication-key "+additional)
	}
	return buildTree(t, lines)
}

// TestPersistedWhitespaceOnlyPrimaryStagedMigration17888 pins the repair
// path for a tolerantly persisted whitespace-only PSK (#17888 fold): the
// runtime installs `authentication-key "   "` raw, so it is a real active
// key, but the strict strength gate treats it as unset. The operator must
// be able to retire it through the #6630 overlap — stage a strong
// replacement beside the byte-identical old primary, swap, finalize —
// while a freshly authored whitespace-only key stays refused. Retaining
// strict-session-auth ensures its earlier ordered gate also admits this
// same narrowly bounded repair path.
func TestPersistedWhitespaceOnlyPrimaryStagedMigration17888(t *testing.T) {
	const ws = "   "
	quotedWS := `"` + ws + `"`

	currentWS, err := CompileConfigLenient(strictSessionClusterTree17888(t, quotedWS, ""))
	if err != nil {
		t.Fatalf("tolerant strict-session fixture: %v", err)
	}
	if got := currentWS.Chassis.Cluster.ControlLinkAuthKey.Reveal(); got != ws {
		t.Fatalf("persisted whitespace fixture compiled to %q, want byte-exact %q", got, ws)
	}

	// Staging (step 1/2): keep signing with the persisted whitespace
	// primary while staging a strong replacement. Must commit.
	if _, err := CompileConfigWithCurrentClusterPrimary(
		strictSessionClusterTree17888(t, quotedWS, keyB16858), currentWS); err != nil {
		t.Fatalf("staging a replacement beside the persisted whitespace-only primary rejected: %v", err)
	}
	// Direct swap without staging: the active set {"   "} does not
	// accept the strong key, so the transition interlock refuses.
	if _, err := CompileConfigWithCurrentClusterPrimary(
		strictSessionClusterTree17888(t, keyB16858, ""), currentWS); err == nil {
		t.Fatal("direct swap from the persisted whitespace-only primary committed without staging (#17888)")
	}
	// Step 3/4: sign the staged strong key, keep the whitespace key
	// accept-only until the peer catches up.
	currentStaged, err := CompileConfigLenient(strictSessionClusterTree17888(t, quotedWS, keyB16858))
	if err != nil {
		t.Fatalf("tolerant staged-key fixture: %v", err)
	}
	if _, err := CompileConfigWithCurrentClusterPrimary(
		strictSessionClusterTree17888(t, keyB16858, quotedWS), currentStaged); err != nil {
		t.Fatalf("swap to the staged key rejected: %v", err)
	}
	// Step 5 finalize: drop the whitespace additional key.
	currentSwapped, err := CompileConfigLenient(strictSessionClusterTree17888(t, keyB16858, quotedWS))
	if err != nil {
		t.Fatalf("tolerant swapped-key fixture: %v", err)
	}
	if _, err := CompileConfigWithCurrentClusterPrimary(
		strictSessionClusterTree17888(t, keyB16858, ""), currentSwapped); err != nil {
		t.Fatalf("finalize after the whitespace-key rotation rejected: %v", err)
	}
	// A different whitespace spelling is not the persisted key.
	currentOtherWS, err := CompileConfigLenient(strictSessionClusterTree17888(t, `"  "`, ""))
	if err != nil {
		t.Fatalf("tolerant alternate-whitespace fixture: %v", err)
	}
	if _, err := CompileConfigWithCurrentClusterPrimary(
		strictSessionClusterTree17888(t, quotedWS, keyB16858), currentOtherWS); err == nil {
		t.Fatal("staging beside a different whitespace spelling committed; the exception must require the byte-identical persisted primary")
	}
	// Freshly authored whitespace-only keys stay refused even with a
	// strong additional key staged beside them.
	if _, err := CompileConfig(strictSessionClusterTree17888(t, quotedWS, keyB16858)); err == nil {
		t.Fatal("freshly authored whitespace-only primary with a strong additional key committed")
	}
	// A weak additional key does not open the migration path.
	if _, err := CompileConfigWithCurrentClusterPrimary(
		strictSessionClusterTree17888(t, quotedWS, "tiny"), currentWS); err == nil {
		t.Fatal("staging a weak additional key beside the persisted whitespace-only primary committed")
	}
}
