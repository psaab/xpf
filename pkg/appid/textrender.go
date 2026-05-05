package appid

import (
	"fmt"
	"strings"

	"github.com/psaab/xpf/pkg/config"
)

// RenderStatus writes the `show services application-identification
// status` operator-facing output to buf. Single source of truth so the
// local CLI (`pkg/cli`) and the gRPC text-show surface (`pkg/grpcapi`)
// can't drift apart on the AppID contract description (Copilot review
// #5 on PR #1196 — the two surfaces previously duplicated the string
// content line-by-line).
//
// #653: this is the operator-facing answer to "what does
// `services application-identification` actually do on xpf". The
// active config knob is parsed and accepted at commit time;
// this command is the one place where the gap between the knob and
// a Junos vSRX AppID engine is made explicit. xpf AppID today is
// **port + protocol matching only** — no L7 DPI / signature engine.
func RenderStatus(buf *strings.Builder, cfg *config.Config) {
	enabled := cfg != nil && cfg.Services.ApplicationIdentification

	yesNo := func(b bool) string {
		if b {
			return "yes"
		}
		return "no"
	}

	buf.WriteString("Application identification (AppID) status:\n")
	fmt.Fprintf(buf, "  Configured:                  %s\n", yesNo(enabled))
	buf.WriteString("  Engine implementation:        port + protocol matching only\n")
	buf.WriteString("  L7 DPI / signature engine:    not implemented\n")
	buf.WriteString("  Signature package:            not supported\n")
	buf.WriteString("  Application System Cache:     not supported\n")
	buf.WriteString("  Custom L7 signatures:         not supported\n")
	buf.WriteString("  Auto-update / download:       not supported\n")
	buf.WriteString("\n")
	buf.WriteString("How sessions get their app name today:\n")
	buf.WriteString("  1. At session-create time the dataplane looks up\n")
	buf.WriteString("     (protocol, dst_port[, src_port_range]) in the\n")
	buf.WriteString("     compiled `applications` catalog and stamps the\n")
	buf.WriteString("     matching app_id on the session.\n")
	buf.WriteString("  2. `show security flow session` resolves the app_id\n")
	buf.WriteString("     back to a name via the same catalog.\n")
	buf.WriteString("  3. When `services application-identification` is\n")
	buf.WriteString("     ENABLED and no port match exists, the session\n")
	buf.WriteString("     name is `UNKNOWN` (honest — no L7 inspection).\n")
	buf.WriteString("  4. When DISABLED, sessions fall back to a built-in\n")
	buf.WriteString("     port→name heuristic (junos-http=80, junos-ssh=22,\n")
	buf.WriteString("     etc.) for common ports.\n")
	buf.WriteString("\n")
	if enabled {
		buf.WriteString("Operator note:\n")
		buf.WriteString("  `services application-identification` is enabled, but\n")
		buf.WriteString("  this only changes step 3 (UNKNOWN vs port-heuristic).\n")
		buf.WriteString("  It does NOT enable L7 DPI. Dynamic-application policies\n")
		buf.WriteString("  (`security policies ... match dynamic-application`),\n")
		buf.WriteString("  AppTrack, AppFW, AppQoS are NOT implemented.\n")
		buf.WriteString("\n")
	}
	buf.WriteString("Catalog statistics:\n")
	if cfg == nil {
		buf.WriteString("  (no active configuration)\n")
		return
	}
	fmt.Fprintf(buf, "  Predefined applications:     %d\n", len(config.PredefinedApplications))
	fmt.Fprintf(buf, "  User-defined applications:   %d\n", len(cfg.Applications.Applications))
	fmt.Fprintf(buf, "  Application sets:            %d\n", len(cfg.Applications.ApplicationSets))
	buf.WriteString("\n")
	buf.WriteString("See:\n")
	buf.WriteString("  show configuration applications\n")
	buf.WriteString("  show security flow session\n")
	buf.WriteString("  docs/services-application-identification.md\n")
}
