package grpcapi

import (
	"fmt"
	"strings"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"

	"github.com/psaab/xpf/pkg/config"
)

// #9154: THE CONFIGURATION REGEXES WERE NOT ENFORCED HERE AT ALL.
//
// `allow-configuration` / `deny-configuration` were evaluated by the on-box CLI
// and by nothing else, so a class restricted from configuring a subtree was
// restricted only at the console. The shipped `cli` binary speaks this listener,
// which makes the DOCUMENTED way to administer the box the way around the
// restriction.
//
// Measured, with the control that makes it a finding rather than an inference:
//
//	deny-configuration-only : authorizeRPCCommand(Set) -> nil       ALLOWED
//	deny-commands-only      : authorizeRPCCommand(Set) -> denied    the gate IS live
//
// The second row proves the machinery works and simply was never asked this
// question. #7172's own acceptance says both dispatch surfaces must use it and
// "neither may be gated alone".
//
// THE EDIT PATH IS EMPTY HERE ON PURPOSE. The remote CLI prepends its own
// `edit` cursor before sending (cmd/cli/shared.go), so the Input this server
// receives is the RESOLVED path -- and the resolved path is what the server
// acts on, so it is what must be gated. Passing a cursor the server does not
// track would gate a different string from the one being applied.
//
// LOAD IS A REMAINING GAP, inherited from the CLI gate and stated there: `load`
// applies arbitrary content whose paths are not known until parsed, so
// enforcing a path regex against it is a different mechanism. Recorded rather
// than quietly implied.
func (s *Server) authorizeRPCConfigMutation(cfg *config.Config, class, fullMethod string, req any) error {
	if class == "" {
		return nil
	}
	line, ok := configMutationLineFor(fullMethod, req)
	if !ok {
		// #9633: Load and Rollback write more than one line.
		return s.authorizeRPCLoadAndRollback(cfg, class, fullMethod, req)
	}
	if err := config.AuthorizeConfigMutation(cfg, class, nil, line); err != nil {
		return fmt.Errorf("%w", err)
	}
	return nil
}

// configMutationLineFor returns the config-mode line an RPC will apply, or
// ok=false when this RPC does not mutate configuration by path.
//
// Keyed on the REQUEST rather than on a method table, because the string that
// has to be gated is the one the handler will act on: Server.Set carries every
// mutating verb (set / delete / deactivate / activate / copy / rename / insert)
// in its Input, routed by prefix inside the handler.
func configMutationLineFor(fullMethod string, req any) (string, bool) {
	service, method, okM := splitFullMethod(fullMethod)
	if !okM || service != serviceName {
		return "", false
	}
	switch method {
	case "Set":
		// #9938 F-019: the verb is supplied HERE, exactly as `Delete` below
		// supplies its own, and the asymmetry between them was the defect.
		//
		// The production remote CLI sends `SetRequest{Input: strings.Join(
		// fullPath, " ")}` (cmd/cli/shared.go) — a BARE PATH with the verb
		// already stripped. Returned verbatim, that reached
		// AuthorizeConfigMutation as `security policies p1`, whose first token
		// is not a mutation verb, so the gate answered "not gated" and the
		// mutation was ALLOWED. Not a surface-wide gap and that is what makes
		// it a defect rather than a story: REST builds `route.verb+" "+input`,
		// the Delete RPC prepends its verb, and the CLI's deactivate / activate
		// / copy / rename arms keep theirs. `Set` over gRPC was the one hole —
		// and since #9633 exempted config-mode methods from the operational
		// command gate, it had no second net beneath it.
		//
		// A `set` line that ALREADY carries its verb (a `load set` replay, an
		// operator pasting `set …`) must not become `set set …`, so the prefix
		// is added only when it is absent.
		if r, okReq := req.(*pb.SetRequest); okReq {
			if line := strings.TrimSpace(r.GetInput()); line != "" {
				if !strings.HasPrefix(line, "set ") {
					line = "set " + line
				}
				return line, true
			}
		}
	case "Delete":
		// The Delete RPC's Input is the PATH, not a verb-led line, so the verb
		// is supplied here — AuthorizeConfigMutation gates on `<verb> <path>`.
		if r, okReq := req.(*pb.DeleteRequest); okReq {
			if line := strings.TrimSpace(r.GetInput()); line != "" {
				return "delete " + line, true
			}
		}
	}
	return "", false
}
