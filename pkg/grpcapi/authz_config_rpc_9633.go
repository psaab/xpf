package grpcapi

import (
	"fmt"
	"strings"

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

// loadFlatVerbs9633 are the first words that make a Load body set-format,
// matching the mutation verbs config.AuthorizeConfigMutation gates.
var loadFlatVerbs9633 = map[string]bool{
	"set": true, "delete": true, "deactivate": true, "activate": true,
	"copy": true, "rename": true, "insert": true, "annotate": true,
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
		if r.GetMode() == "override" {
			return fmt.Errorf("permission denied: login class %q restricts configuration paths, and "+
				"load override replaces the whole candidate, so the paths it deletes cannot be "+
				"adjudicated one by one; use load merge or load set (#9633)", class)
		}
		for _, line := range loadMutationLines9633(r.GetContent()) {
			if err := config.AuthorizeConfigMutation(cfg, class, nil, line); err != nil {
				return err
			}
		}
	case "Rollback":
		r, okReq := req.(*pb.RollbackRequest)
		if !okReq || r.GetN() == 0 {
			return nil
		}
		return fmt.Errorf("permission denied: login class %q restricts configuration paths, and "+
			"rollback %d replaces the candidate with an older configuration whose paths cannot "+
			"be adjudicated one by one; rollback 0 remains available (#9633)", class, r.GetN())
	}
	return nil
}

// loadMutationLines9633 returns the set-form mutation lines a Load body writes.
// Set-format content is taken line by line. Hierarchical content is parsed with
// the store's parser and rendered as set lines, so its every leaf path is
// checked. Content that does not parse yields its parsed part; the store's own
// Load refuses what it cannot parse.
func loadMutationLines9633(content string) []string {
	var lines []string
	flat := false
	for _, raw := range strings.Split(content, "\n") {
		line := strings.TrimSpace(raw)
		if f := strings.Fields(line); len(f) > 0 && loadFlatVerbs9633[f[0]] {
			flat = true
			lines = append(lines, line)
		}
	}
	if flat {
		return lines
	}
	tree, _ := config.NewParser(content).Parse()
	if tree == nil {
		return nil
	}
	for _, line := range strings.Split(tree.FormatSet(), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			lines = append(lines, line)
		}
	}
	return lines
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
