package grpcapi

import (
	"context"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/psaab/xpf/pkg/cmdtree"
	"github.com/psaab/xpf/pkg/config"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Complete RPC and its completion-pair helpers (#16138: moved out of
// server_cluster.go, which now holds only cluster/match-policies
// handlers). The completion walk itself lives in pkg/cmdtree
// (CompleteFromTreeWithDesc / CompleteFromTree over the merged walker).

// pipeFilterNames lists available pipe filters for completion.
var pipeFilterNames = []string{"count", "display", "except", "find", "grep", "last", "match", "no-more"}

func (s *Server) Complete(ctx context.Context, req *pb.CompleteRequest) (*pb.CompleteResponse, error) {
	// req.Pos is the caller-supplied cursor offset into req.Line. It is an
	// int32 on the wire, so a crafted negative value would make the
	// upper-bound guard below pass (int(-1) < len(text)) and slice
	// text[:-1], panicking the handler goroutine. Reject negatives outright;
	// Pos > len is already safe because the slice is then skipped.
	if req.Pos < 0 {
		return nil, status.Error(codes.InvalidArgument, "invalid position")
	}
	text := req.Line
	if int(req.Pos) < len(text) {
		// req.Pos is a BYTE offset into req.Line. Refuse a cut that would
		// land inside a multibyte UTF-8 rune rather than slice a code point
		// in half and emit corrupted completion text. A byte offset is a
		// valid boundary when the byte at that index is a rune start (an
		// ASCII byte or a leading multibyte byte), not a 10xxxxxx
		// continuation byte (#4970).
		if !utf8.RuneStart(text[req.Pos]) {
			return nil, status.Error(codes.InvalidArgument, "position splits a UTF-8 rune")
		}
		text = text[:req.Pos]
	}

	// Pipe filter completion: "show ... | <tab>"
	if candidates := s.completePipeFilter(text); candidates != nil {
		sort.Strings(candidates)
		return &pb.CompleteResponse{Candidates: candidates}, nil
	}

	words := strings.Fields(text)
	trailingSpace := len(text) > 0 && text[len(text)-1] == ' '

	var partial string
	if !trailingSpace && len(words) > 0 {
		partial = words[len(words)-1]
		words = words[:len(words)-1]
	}

	// #15237 A53-06: a config-mode caller at an edit cursor completes
	// relative to that cursor. Old clients send no edit_path and keep
	// the root-relative behaviour.
	editPath := config.NormalizeEditPathTokens(req.GetEditPath())

	// #14144: bind live-config-derived candidates to the admitted principal.
	auth := s.completionAuthFor(ctx)
	var pairs []completionPair
	if req.ConfigMode {
		pairs = s.completeConfigPairsAuth(words, partial, &auth, editPath)
	} else {
		pairs = s.completeOperationalPairsAuth(words, partial, &auth)
	}

	sort.Slice(pairs, func(i, j int) bool { return pairs[i].name < pairs[j].name })
	resp := &pb.CompleteResponse{
		Candidates:   make([]string, len(pairs)),
		Descriptions: make([]string, len(pairs)),
	}
	for i, p := range pairs {
		resp.Candidates[i] = p.name
		resp.Descriptions[i] = p.desc
	}
	return resp, nil
}

// completePipeFilter returns pipe filter candidates if the text contains "|".
// Returns nil if no pipe is present (caller should proceed with normal completion).
func (s *Server) completePipeFilter(text string) []string {
	idx := strings.LastIndex(text, "|")
	if idx < 0 {
		return nil
	}
	after := strings.TrimSpace(text[idx+1:])
	trailingSpace := len(text) > 0 && text[len(text)-1] == ' '

	// Right after "|" or "| " — all filters
	if after == "" || (trailingSpace && after == "") {
		return pipeFilterNames
	}

	// User has typed a complete filter + space — no more completions (freeform arg)
	if trailingSpace {
		return []string{}
	}

	// Partial filter name
	var candidates []string
	for _, f := range pipeFilterNames {
		if strings.HasPrefix(f, after) {
			candidates = append(candidates, f)
		}
	}
	return candidates
}

func filterCompletionPairs(tree map[string]*cmdtree.Node, prefix string) []completionPair {
	pairs := make([]completionPair, 0, len(tree))
	for name, node := range tree {
		if prefix == "" || strings.HasPrefix(name, prefix) {
			pairs = append(pairs, completionPair{name: name, desc: node.Desc})
		}
	}
	return pairs
}

func resolveShowConfigurationWords(words []string) ([]string, bool) {
	if len(words) < 2 {
		return nil, false
	}
	show, ok := cmdtree.ResolveUniquePrefix(cmdtree.KeysFromTree(cmdtree.OperationalTree), words[0])
	if !ok || show != "show" {
		return nil, false
	}
	showNode := cmdtree.OperationalTree[show]
	if showNode == nil || showNode.Children == nil {
		return nil, false
	}
	conf, ok := cmdtree.ResolveUniquePrefix(cmdtree.KeysFromTree(showNode.Children), words[1])
	if !ok || conf != "configuration" {
		return nil, false
	}
	return words[2:], true
}

func (s *Server) completionValueProvider() config.ValueProvider {
	if s == nil || s.store == nil {
		return nil
	}
	return s.valueProvider
}

func (s *Server) completeOperationalPairs(words []string, partial string) []completionPair {
	auth := legacyCompletionAuth()
	return s.completeOperationalPairsAuth(words, partial, &auth)
}

func (s *Server) completeOperationalPairsAuth(words []string, partial string, auth *completionAuth) []completionPair {
	// "show configuration <path>" — delegate sub-path to config schema
	if subPath, ok := resolveShowConfigurationWords(words); ok {
		if resolvedPath, resolved := config.ResolveConsumedSetPathTokens(subPath); resolved {
			subPath = resolvedPath
		}
		if !auth.showConfigPathAllowed(subPath) {
			return nil
		}
		schemaCompletions := config.CompleteSetPathWithValues(subPath, auth.wrapProvider(s))
		if schemaCompletions != nil {
			var pairs []completionPair
			for _, sc := range schemaCompletions {
				if partial == "" || strings.HasPrefix(sc.Name, partial) {
					pairs = append(pairs, completionPair{name: sc.Name, desc: sc.Desc})
				}
			}
			if len(pairs) > 0 {
				return pairs
			}
		}
	}
	cfg := auth.treeConfig(s, words)
	candidates := cmdtree.CompleteFromTreeWithDesc(cmdtree.OperationalTree, words, partial, cfg)
	pairs := make([]completionPair, len(candidates))
	for i, c := range candidates {
		pairs[i] = completionPair{name: c.Name, desc: c.Desc}
	}
	return pairs
}

func (s *Server) completeConfigPairs(words []string, partial string) []completionPair {
	auth := legacyCompletionAuth()
	return s.completeConfigPairsAuth(words, partial, &auth, nil)
}

func (s *Server) completeConfigPairsAuth(words []string, partial string, auth *completionAuth, editPath []string) []completionPair {
	if len(words) == 0 {
		return filterCompletionPairs(cmdtree.ConfigTopLevel, partial)
	}

	resolvedTop, ok := cmdtree.ResolveUniquePrefix(cmdtree.KeysFromTree(cmdtree.ConfigTopLevel), words[0])
	if !ok {
		if len(words) == 1 {
			return filterCompletionPairs(cmdtree.ConfigTopLevel, words[0])
		}
		return nil
	}

	switch resolvedTop {
	case "set", "delete", "activate", "deactivate", "show", "edit":
		// #2051: activate/deactivate complete with schema parity to delete
		// (paths to existing nodes), reusing the shared schema completer.
		pathWords := words[1:]
		if resolvedPath, resolved := config.ResolveConsumedSetPathTokens(pathWords); resolved {
			pathWords = resolvedPath
		}
		// #15237 A53-06: complete relative to the edit cursor. The
		// gate prices the EFFECTIVE (cursor+typed) path; the schema
		// walk starts at the cursor so `set host` under `[edit
		// system]` offers host-name, not the top-level interfaces.
		effective := pathWords
		schemaWords := pathWords
		if len(editPath) > 0 {
			effective = append(append([]string(nil), editPath...), pathWords...)
			schemaWords = effective
		}
		if !auth.configPathAllowed(effective) {
			return nil
		}
		schemaCompletions := config.CompleteSetPathWithValues(schemaWords, auth.wrapProvider(s))
		if schemaCompletions == nil {
			return nil
		}
		var pairs []completionPair
		for _, sc := range schemaCompletions {
			if strings.HasPrefix(sc.Name, partial) {
				pairs = append(pairs, completionPair{name: sc.Name, desc: sc.Desc})
			}
		}
		return pairs
	case "run":
		cfg := auth.treeConfig(s, words[1:])
		names := cmdtree.CompleteFromTree(cmdtree.OperationalTree, words[1:], partial, cfg)
		var pairs []completionPair
		for _, name := range names {
			pairs = append(pairs, completionPair{name: name})
		}
		return pairs
	case "commit", "load":
		if len(words) == 1 {
			node := cmdtree.ConfigTopLevel[resolvedTop]
			if node == nil || node.Children == nil {
				return nil
			}
			var pairs []completionPair
			for name, child := range node.Children {
				if strings.HasPrefix(name, partial) {
					pairs = append(pairs, completionPair{name: name, desc: child.Desc})
				}
			}
			return pairs
		}
		return nil
	default:
		return nil
	}
}

// completionConfig returns the config completion draws from and whether
// the predefined catalogue is suppressed (#15272 B24-04, #5763): in
// config mode a candidate compile cached by generation; otherwise (or
// uncompilable candidate) the active config. Catalogue suppressed until
// the first commit.
func (s *Server) completionConfig() (*config.Config, bool) {
	if s == nil || s.store == nil {
		return nil, false
	}
	if s.store.InConfigMode() {
		if cfg, ok := s.store.CandidateConfigForCompletion(); ok {
			return cfg, !s.store.EverCommitted()
		}
	}
	return s.store.ActiveConfig(), false
}

// valueProvider delegates to the shared config.ProvideValues (#16160).
// Snapshot acquisition (completionConfig) stays here because it is
// per-frontend store/candidate logic; the nil-receiver / nil-store /
// nil-config guards mirror the pre-share behaviour (no config, no live
// values).
func (s *Server) valueProvider(hint config.ValueHint, path []string) []config.SchemaCompletion {
	if s == nil || s.store == nil {
		return nil
	}
	cfg, catalogueSuppressed := s.completionConfig()
	if cfg == nil {
		return nil
	}
	return config.ProvideValues(cfg, hint, path, catalogueSuppressed)
}

// --- Completion RPC ---

// completionPair holds a candidate name and optional description.
type completionPair struct {
	name string
	desc string
}
