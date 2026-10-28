// Package optopic is the metadata registry for the two request-multiplexed
// operational RPCs: ShowText (by topic) and SystemAction (by verb).
//
// #16136: the topic/verb strings, their coarse authz price
// (config.LoginClassPermission), their canonical operational command (for
// deny-commands matching), and their fabric (peer-proxy) admission used to
// live in separate hand-maintained places — pkg/cmdtree's topic->command
// table, pkg/grpcapi's view/elevated topic maps and verb price map,
// pkg/authz's verb->command table, and pkg/grpcapi's fabric topic allowlist.
// A new topic could be dispatched without being priced (it fell to the
// strict PermAll default, so it was a maintenance/admission risk rather than
// a fail-open) and each consumer maintained its own census.
//
// This package is that registry, split from the handlers on purpose:
//
//   - METADATA ONLY. Entries are plain data (strings and a permission).
//     No handler functions — typed *Server handlers stay in pkg/grpcapi.
//     There is deliberately no `func(any, ...)` handler field anywhere in
//     this package.
//   - NO DEPENDENCY on pkg/grpcapi (and none on pkg/authz / pkg/cmdtree
//     dispatch logic beyond the leaf config permission type). pkg/grpcapi,
//     pkg/authz-facing code and the CLIs consume this package; it consumes
//     nothing above pkg/config's permission enum.
//
// Dispatch still lives in pkg/grpcapi (server_show.go's ordered prefix arms
// and switch, server_diag_system_action.go's switch and default-branch
// prefix forms). The registry does not replace that dispatch; it names and
// prices what the dispatch serves. Equivalence between the registry and
// the actual handler dispatch is proven by the census tests in pkg/grpcapi:
// the handler key set comes from an INDEPENDENT source scrape (a
// differently-filtered extraction: AST case/==/HasPrefix literals in the
// handler sources, not this registry), asserted against the registry in
// both directions, separately for exact topics, prefix topics, exact
// verbs, and prefix verbs; per-key price/command attribution is graded
// against a FROZEN pre-registry contract captured from the merge-base
// literal tables — never against this package's own entries. The
// registry must never become its own truth-and-oracle.
//
// Key spelling: a key ending in ':' is a PREFIX rule (the request string is
// a delimiter-packed parameter string, e.g. "route-table:inet.0" is priced
// and command-matched by the "route-table:" entry); any other key is exact.
// Exact and prefix lookups resolve exact-first, then longest-prefix-first.
//
// Permission zero value: PermView is config's zero LoginClassPermission.
// A zero-value Entry therefore prices at view; consumers that must
// distinguish "registered at view" from "absent" use the ok return of the
// Lookup functions, never the permission alone.
package optopic

import (
	"sort"
	"strings"

	"github.com/psaab/xpf/pkg/config"
)

// Kind identifies which multiplexed RPC a registry entry belongs to.
type Kind int

const (
	KindShowText Kind = iota
	KindSystemAction
)

// Entry is one registered topic or verb: pure metadata, no behaviour.
type Entry struct {
	// Key is the exact topic/verb, or a prefix rule when it ends in ':'.
	Key string
	// Permission is the coarse login-class price of the decoded request.
	Permission config.LoginClassPermission
	// Command is the canonical, argument-free operational command that
	// emits this topic/verb ("" only where no operational command emits
	// it — see the named-absence note on entries lacking one).
	Command string
	// FabricAllowed reports whether the cluster-fabric (peer) listener
	// admits this request content. This is a different question from
	// Permission: the fabric has no principal, only "does a node ever ask
	// a peer for this". Default false (fail closed).
	FabricAllowed bool
}

// IsPrefix reports whether the entry keys a prefix rule.
func (e Entry) IsPrefix() bool { return strings.HasSuffix(e.Key, ":") }

type registry struct {
	exact  map[string]Entry
	prefix []Entry // sorted longest-key-first (then lexical)
	all    []Entry // sorted by key
}

// build validates and indexes one kind's entries. It panics on a duplicate
// key or on a prefix rule shadowed by another prefix rule of the same kind:
// both would make a price depend on table ordering or map iteration, which
// is exactly the ambiguity the pre-registry prefix tests forbade. Panicking
// at package init is correct — these are compile-time constants, and a bad
// edit must fail the build/load, not a request.
func build(entries []Entry) registry {
	r := registry{exact: make(map[string]Entry, len(entries))}
	for _, e := range entries {
		if e.Key == "" {
			panic("optopic: empty registry key")
		}
		if _, dup := r.exact[e.Key]; dup {
			panic("optopic: duplicate registry key " + e.Key)
		}
		r.exact[e.Key] = e
		if e.IsPrefix() {
			r.prefix = append(r.prefix, e)
		}
		r.all = append(r.all, e)
	}
	for _, a := range r.prefix {
		for _, b := range r.prefix {
			if a.Key != b.Key && strings.HasPrefix(a.Key, b.Key) {
				panic("optopic: prefix rule " + a.Key + " is shadowed by " + b.Key)
			}
		}
	}
	sort.Slice(r.prefix, func(i, j int) bool {
		if len(r.prefix[i].Key) != len(r.prefix[j].Key) {
			return len(r.prefix[i].Key) > len(r.prefix[j].Key)
		}
		return r.prefix[i].Key < r.prefix[j].Key
	})
	sort.Slice(r.all, func(i, j int) bool { return r.all[i].Key < r.all[j].Key })
	return r
}

func (r registry) lookup(s string) (Entry, bool) {
	if e, ok := r.exact[s]; ok {
		return e, true
	}
	for _, e := range r.prefix {
		if strings.HasPrefix(s, e.Key) {
			return e, true
		}
	}
	return Entry{}, false
}

// --- ShowText ---

var showTextRegistry = build(showTextEntries)

// LookupShowText resolves a ShowText topic to its entry: exact match first,
// then the longest matching prefix rule. ok=false means unregistered —
// callers must price it at the strict default, never at view.
func LookupShowText(topic string) (Entry, bool) { return showTextRegistry.lookup(topic) }

// ShowTextCommand resolves a ShowText topic to its canonical command:
// exact match first, then the longest matching prefix rule — the same
// resolution LookupShowText prices by, so a topic can never be priced by
// one rule and command-matched by another (#17108). ok=false means
// unregistered: callers must treat an unmapped topic as deny for a
// restricted class, never as no-match/allow.
func ShowTextCommand(topic string) (string, bool) {
	e, ok := LookupShowText(topic)
	if !ok {
		return "", false
	}
	return e.Command, true
}

// ShowTextEntries returns every registered ShowText topic/verb-key entry,
// sorted by key. The slice is a copy; mutating it does not affect lookups.
func ShowTextEntries() []Entry { return append([]Entry(nil), showTextRegistry.all...) }

// --- SystemAction ---

var systemActionRegistry = build(systemActionEntries)

var systemActionPrefixPermissions = systemActionPrefixPermissionsList()

// LookupSystemAction resolves a SystemAction action string to its entry:
// exact match first, then the longest matching prefix rule. ok=false means
// unregistered (which includes the cluster-failover grammar forms — those
// are a parsed family, not fixed spellings, and are priced by the caller's
// prefix-verb default, see SystemActionPrefixPermissions).
func LookupSystemAction(action string) (Entry, bool) {
	if e, ok := systemActionRegistry.lookup(action); ok {
		return e, true
	}
	// Prefix-priced families (failover grammar, userspace control forms):
	// no fixed spelling, but a definite price. Longest prefix wins; the
	// attestation arm is NOT here — it prices above the family default
	// and callers match AttestArmPrefix first.
	for _, e := range systemActionPrefixPermissions {
		if strings.HasPrefix(action, e.Key) {
			return e, true
		}
	}
	return Entry{}, false
}

// SystemActionEntries returns every registered SystemAction entry, sorted
// by key. The slice is a copy.
func SystemActionEntries() []Entry {
	return append([]Entry(nil), systemActionRegistry.all...)
}

// Entries returns the entries of one kind, sorted by key.
func Entries(kind Kind) []Entry {
	if kind == KindSystemAction {
		return SystemActionEntries()
	}
	return ShowTextEntries()
}

// Lookup dispatches to the per-kind lookup.
func Lookup(kind Kind, key string) (Entry, bool) {
	if kind == KindSystemAction {
		return LookupSystemAction(key)
	}
	return LookupShowText(key)
}
