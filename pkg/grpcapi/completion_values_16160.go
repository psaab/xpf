package grpcapi

import (
	"github.com/psaab/xpf/pkg/config"
)

// CompletionValuesForTest16160 exposes the gRPC valueProvider seam to
// the cross-package parity tests (#16160): it returns exactly what
// (*Server).valueProvider returns for the same store snapshot. It is
// a thin accessor over the unexported provider, not a second path.
func CompletionValuesForTest16160(s *Server, hint config.ValueHint, path []string) []config.SchemaCompletion {
	if s == nil {
		return nil
	}
	return s.valueProvider(hint, path)
}
