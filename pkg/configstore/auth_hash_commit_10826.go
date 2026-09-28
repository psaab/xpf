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
	if _, err := config.HashAPIAuthSecrets(hashed); err != nil {
		return nil, nil, fmt.Errorf("hashing api-auth secrets failed")
	}
	compiled, err := s.compileTree(hashed)
	if err != nil {
		return nil, nil, err
	}
	return hashed, compiled, nil
}
