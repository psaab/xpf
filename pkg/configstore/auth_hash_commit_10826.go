package configstore

import (
	"fmt"

	"github.com/psaab/xpf/pkg/config"
)

// compileAuthSafeCandidate validates authored cleartext against the schema,
// then compiles and persists only a private tree whose api-auth secrets have
// been replaced with salted verifiers.
func (s *Store) compileAuthSafeCandidate(candidate *config.ConfigTree) (*config.ConfigTree, *config.Config, error) {
	if err := s.schemaValidateExpandedTree(candidate); err != nil {
		return nil, nil, err
	}
	hashed := candidate.Clone()
	_, invalidPaths, err := config.HashAPIAuthSecretsWithInvalidPaths(hashed)
	if err != nil {
		return nil, nil, fmt.Errorf("hashing api-auth secrets failed")
	}
	compiled, err := s.compileTree(hashed)
	if err != nil {
		return nil, nil, err
	}
	for _, path := range invalidPaths {
		compiled.Warnings = append(compiled.Warnings, fmt.Sprintf(
			"%s is shorter than the API-auth credential minimum and was stored "+
				"as a non-authenticating verifier; rotate it before relying on "+
				"API authentication (#11820)", path))
	}
	return hashed, compiled, nil
}
