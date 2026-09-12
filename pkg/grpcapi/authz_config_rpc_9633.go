package grpcapi

import (
	"fmt"

	"github.com/psaab/xpf/pkg/config"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// #9633: which regexes govern the config-mode RPCs on gRPC.
//
// The on-box CLI applies the operational `*-commands` regexes to operational
// lines and the `*-configuration` regexes to config-mode lines (dispatchConfig
// calls only checkConfigRegex). The gRPC gate applied the OPERATIONAL regexes
// to every method and denied a method with no canonical command, so any
// operational pattern locked a class out of configuration over gRPC. The
// documented `permissions all; deny-commands "request system zeroize"` class
// could configure at the console and not through the remote `cli`.
//
// Exempting the config-mode methods from the operational gate alone would have
// let `Load` and `Rollback` write paths the class's configuration regexes
// forbid, with no check at all. So this file first gives the configuration gate
// an answer for them:
//   - `Load set` and `Load merge` are adjudicated per written path. Hierarchical
//     content is parsed and rendered as set lines, so every leaf it writes is
//     checked.
//   - `Load override` and `Rollback n>0` replace the whole candidate. The paths
//     they delete cannot be adjudicated one by one, so a class with configuration
//     regexes is refused them. `Rollback 0` returns the candidate to the committed
//     configuration and stays available.

// configModeMethods9633 are the RPCs governed by the configuration regexes and
// not by the operational ones. It is a subset of methodsWithoutCanonicalCommand;
// TestConfigModeMethodsAreDeliberatelyUnmapped9633 binds the two.
var configModeMethods9633 = map[string]bool{
	"EnterConfigure":  true,
	"ExitConfigure":   true,
	"Set":             true,
	"Delete":          true,
	"Load":            true,
	"Commit":          true,
	"CommitCheck":     true,
	"CommitConfirmed": true,
	"ConfirmCommit":   true,
	"Rollback":        true,
	"Complete":        true,
}

func isConfigModeMethod9633(fullMethod string) bool {
	service, method, ok := splitFullMethod(fullMethod)
	return ok && service == serviceName && configModeMethods9633[method]
}

// authorizeRPCLoadAndRollback adjudicates the two config RPCs whose writes are
// not a single request line.
func (s *Server) authorizeRPCLoadAndRollback(cfg *config.Config, class, fullMethod string, req any) error {
	if class == "" {
		return nil
	}
	service, method, ok := splitFullMethod(fullMethod)
	if !ok || service != serviceName || (method != "Load" && method != "Rollback") {
		return nil
	}
	_, restricted, err := config.ConfigurationLoginRegexesFor(cfg, class)
	if err != nil {
		return fmt.Errorf("permission denied: login class %q has an invalid configuration regex: %w", class, err)
	}
	if !restricted {
		return nil
	}
	switch method {
	case "Load":
		r, okReq := req.(*pb.LoadRequest)
		if !okReq {
			return nil
		}
		// #9892: delegate to the shared evaluator. The logic below used to
		// live here; it now lives in pkg/config beside AuthorizeConfigMutation
		// so REST and the CLI adjudicate the SAME content the same way. Two
		// copies of "render hierarchical content as set lines" drift, and the
		// drift is invisible because each copy looks right on its own.
		return config.AuthorizeConfigLoad(cfg, class, r.GetMode(), r.GetContent())
	case "Rollback":
		r, okReq := req.(*pb.RollbackRequest)
		if !okReq {
			return nil
		}
		// #9892: shared with REST and the CLI.
		return config.AuthorizeConfigRollback(cfg, class, int(r.GetN()))
	}
	return nil
}

// unenforceableAllowOnGRPC9633 reports whether the class's allow-commands
// pattern permits no command this listener can produce.
func unenforceableAllowOnGRPC9633(rules config.CompiledLoginRegexes) bool {
	for _, name := range config.UnenforceableAllowSurfaces(rules) {
		if name == grpcSurfaceName {
			return true
		}
	}
	return false
}
