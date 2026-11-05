package configstore

import (
	"fmt"
	"strings"

	"github.com/psaab/xpf/pkg/config"
)

// compileAuthSafeCandidate validates authored cleartext against the schema,
// then compiles and persists only a private tree whose api-auth secrets have
// been replaced with salted verifiers.
//
// bootstrapImport is true only for the daemon's bootstrap import; it feeds
// the #18744 placeholder decision (placeholderJudgedLocked).
func (s *Store) compileAuthSafeCandidate(candidate *config.ConfigTree, bootstrapImport bool) (*config.ConfigTree, *config.Config, error) {
	if err := schemaValidateExpandedTreeForNode(candidate, s.nodeID, false); err != nil {
		return nil, nil, err
	}
	hashed := candidate.Clone()
	_, invalidPaths, err := config.HashAPIAuthSecretsWithInvalidPaths(hashed)
	if err != nil {
		return nil, nil, fmt.Errorf("hashing api-auth secrets failed")
	}
	compiled, findings, err := s.compileTreeAsDrops18771(hashed, bootstrapImport, true)
	if err != nil {
		return nil, nil, err
	}
	// #18771 enforcement: a strict DROP verdict on the LOCAL view
	// refuses the commit — the packed tail would be silently dropped.
	// Bootstrap import never refuses (warn-only): an unattended
	// first-boot/reimage import must still yield an active config
	// (#18744 posture); the first operator commit afterward refuses.
	// Peer-view findings never reach here (discarded in the judged
	// compile); SKIPPED-CAP / SKIPPED-PROVENANCE / INDETERMINATE /
	// PARTIAL / CLEAN never refuse (config.PackedTailGateDrops18771
	// is the only input).
	if config.PackedTailGateEnforce18771() && !bootstrapImport {
		if drops := config.PackedTailGateDrops18771(findings); len(drops) > 0 {
			return nil, nil, packedTailGateRefusal18771(drops)
		}
	}
	for _, path := range invalidPaths {
		compiled.Warnings = append(compiled.Warnings, fmt.Sprintf(
			"%s is shorter than the API-auth credential minimum and was stored "+
				"as a non-authenticating verifier; rotate it before relying on "+
				"API authentication (#11820)", path))
	}
	return hashed, compiled, nil
}

// packedTailGateRefusal18771 renders the enforcement refusal. Site,
// pair and position only — never raw tail text or secret material.
func packedTailGateRefusal18771(drops []config.PackedTailGateDrop18771) error {
	parts := make([]string, 0, len(drops))
	for _, d := range drops {
		parts = append(parts, fmt.Sprintf("site %d %s/%s at %d:%d (%s)", d.Site, d.Container, d.Head, d.Line, d.Column, d.NodeLabel))
	}
	return fmt.Errorf("packed-tail statement(s) would be silently dropped: %s; "+
		"brace the statement (outer { inner { leaf value; } }) or admit the pair via the #8690 path (#18771)",
		strings.Join(parts, "; "))
}
