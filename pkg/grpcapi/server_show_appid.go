package grpcapi

import (
	"strings"

	"github.com/psaab/xpf/pkg/appid"
	"github.com/psaab/xpf/pkg/config"
)

// showApplicationIdentificationStatus delegates to the shared
// renderer in `pkg/appid` so the local CLI and the gRPC
// text-show surface stay byte-identical (Copilot review #5 on
// PR #1196 — the two surfaces previously duplicated the string
// content line-by-line and could silently drift).
//
// #653: this is the operator-facing answer to "what does
// `services application-identification` actually do on xpf".
func (s *Server) showApplicationIdentificationStatus(cfg *config.Config, buf *strings.Builder) {
	appid.RenderStatus(buf, cfg)
}
