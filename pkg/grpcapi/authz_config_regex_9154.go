package grpcapi

import (
	"fmt"
	"strings"

	"github.com/psaab/xpf/pkg/cliterm"
	"github.com/psaab/xpf/pkg/config"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
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
	// #14981: Commit / CommitConfirmed carry no line, but they promote a
	// candidate whose group-inherited paths were never adjudicated as
	// literal lines. Adjudicate the expanded candidate for the committing
	// class before the handler runs. CommitCheck only compiles and writes
	// nothing, so it stays ungated here.
	if _, method, okM := splitFullMethod(fullMethod); okM && (method == "Commit" || method == "CommitConfirmed") {
		if s.store == nil {
			return nil
		}
		return config.AuthorizeExpandedCandidate(cfg, class, s.store.CandidateTree(), s.store.ActiveTree())
	}
	line, ok := configMutationLineFor(fullMethod, req)
	if !ok {
		// #9633: Load and Rollback write more than one line.
		return s.authorizeRPCLoadAndRollback(cfg, class, fullMethod, req)
	}
	if err := config.AuthorizeConfigMutation(cfg, class, nil, line); err != nil {
		return fmt.Errorf("%w", err)
	}
	// #14981: a Set/Delete whose path creates or triggers groups is judged
	// above only on its literal spelling. When the candidate already
	// carries the complementary half (a group body awaiting an
	// apply-groups, or an apply-groups awaiting a body), adjudicate the
	// expanded candidate as it will stand after this mutation. Without a
	// store (direct gate tests) there is no candidate to expand; the
	// commit-time gate above remains the backstop.
	if s.store != nil && config.LineTouchesGroups14981(line) {
		if tree := candidateAfterMutation14981(s.store.CandidateTree(), line); tree != nil {
			if err := config.AuthorizeExpandedTree(cfg, class, tree); err != nil {
				return err
			}
		}
	}
	return nil
}

// candidateAfterMutation14981 returns the candidate tree as it will stand
// after applying line, for expanded adjudication. A line that cannot be
// replayed (the handler will refuse it) yields nil: there is no effective
// mutation to adjudicate beyond the literal check already done.
func candidateAfterMutation14981(tree *config.ConfigTree, line string) *config.ConfigTree {
	if tree == nil {
		return nil
	}
	verb, path, quoted, grouped, closed, err := config.ParseSetVerbGroupedClosed(line)
	if err != nil {
		return nil
	}
	switch verb {
	case "delete":
		_ = tree.DeletePathGrouped(path, grouped)
	case "deactivate":
		_ = tree.DeactivatePathGrouped(path, grouped)
	case "activate":
		_ = tree.ActivatePathGrouped(path, grouped)
	case "copy", "rename", "insert", "annotate":
		// Two-endpoint / positional verbs are not replayed here; the
		// commit-time expanded gate adjudicates their effective result.
		return nil
	default:
		_ = tree.SetPathQuotedGrouped(path, quoted, grouped, closed)
	}
	return tree
}

// configMutationLineFor returns the config-mode line an RPC will apply, or
// ok=false when this RPC does not mutate configuration by path.
//
// Keyed on the REQUEST rather than on a method table, because the string that
// has to be gated is the one the handler will act on: Server.Set carries every
// mutating verb (set / delete / deactivate / activate / copy / rename / insert /
// annotate) in its Input, routed by prefix inside the handler.
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
			input := r.GetInput()
			// Server.Set routes these inputs by their leading verb instead of
			// sending them through SetFromInput. Keep the exact handler-routed
			// line so the configuration gate adjudicates the real path(s):
			if fields := strings.Fields(input); len(fields) > 0 && fields[0] == "annotate" {
				// The handler passes this input through AnnotateCommentFromLine,
				// then uses strings.Fields(pathText) and the decoded comment. Rebuild
				// the gate line from those same values so quotes inside a comment
				// cannot become extra path tokens in the authorization lexer.
				line := strings.TrimSpace(strings.TrimPrefix(input, fields[0]))
				pathText, comment, ok := cliterm.AnnotateCommentFromLine(line)
				if ok {
					path := strings.Fields(pathText)
					quotedPath := make([]string, len(path))
					for i, token := range path {
						quotedPath[i] = `"` + cliterm.EscapeAnnotateComment(token) + `"`
					}
					return "annotate " + strings.Join(quotedPath, " ") +
						` "` + cliterm.EscapeAnnotateComment(comment) + `"`, true
				}
				return input, true
			}
			// copy/rename have two endpoints, while insert and
			// activate/deactivate have one. Prepending "set "
			// here turns, for example, "copy <src> to <dst>" into one unrelated
			// path and lets an anchored deny bypass the gate (#10304, #9938 F-029).
			// #14147: route on the lexed verb the handler now also uses,
			// so a tab after the verb is gated on its real endpoints too
			// instead of falling through to the "set " prepend below.
			if verb, isMutation := config.ConfigMutationVerb(input); isMutation &&
				(verb == "copy" || verb == "rename" || verb == "insert" ||
					verb == "deactivate" || verb == "activate") {
				return input, true
			}
			if line := strings.TrimSpace(input); line != "" {
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
