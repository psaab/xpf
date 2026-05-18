package grpcapi

import "github.com/psaab/xpf/pkg/dataplane"

func (s *Server) applyResult() *dataplane.ApplyResult {
	if s == nil {
		return nil
	}
	return dataplane.LastApplyResultOf(s.dp)
}
