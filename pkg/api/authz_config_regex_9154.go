package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/psaab/xpf/pkg/authz"
	"github.com/psaab/xpf/pkg/config"
)

// #9154: THE REST SURFACE PERFORMED CONFIG MUTATIONS WITH NO `*-configuration`
// REGEX CHECK AT ALL.
//
// A class's `allow-configuration` / `deny-configuration` was evaluated by the
// on-box CLI and by nothing else, so an operator who gave someone broad
// `permissions` while withholding specific configuration authority had that
// withholding enforced only at the console. `pkg/api/authz.go` and
// `pkg/api/config.go` had ZERO matches for `Regex`.
//
// Reachability is not theoretical: authorizeInputs resolves the peer UID for a
// local caller, and principalFrom's stated rule is "if the caller is on this
// host, the login model is the only authority". So a local user in a
// PermConfig class, regex-restricted on the CLI and on gRPC, could
// `curl -X POST /api/v1/config/set` with no restriction whatever.
//
// GATED HERE, NOT IN THE HANDLERS. The middleware is where the principal, the
// class and the ONE config snapshot already are, and where the body has already
// been buffered for the #5561 second adjudication — so the line being gated is
// the line the handler will act on, read from the same bytes. Adding the check
// per handler would be a rule enforced by whichever handler remembered it,
// which is the shape that produced this defect.

// restPathField names the JSON field a route's body carries its config PATH in.
// It is declared per route rather than guessed, because the whole defect class
// here is a gate that reads a field the handler does not use: the body decodes,
// the field is empty, and the request sails through looking adjudicated.
type restPathField int

const (
	// pathFromInput — `{"input": "system host-name x"}`; set/delete/deactivate/activate.
	pathFromInput restPathField = iota
	// pathFromPath — `{"path": "system host-name", "comment": "..."}`; annotate.
	pathFromPath
)

// restConfigRoute is the verb a route applies and where its path lives.
type restConfigRoute struct {
	verb  string
	field restPathField
}

// restConfigMutationRoutes maps a config-mutating REST route to the verb its
// handler applies. The verb is supplied here because the request body carries
// only the PATH — `{"input": "system host-name x"}` — while the regexes are
// written against a verb-led config line, the same string the CLI evaluates.
//
// #9890: `deactivate`, `activate` and `annotate` were MISSING. They are
// registered POST routes whose handlers mutate the candidate by path
// (`DeactivateFromInputAs`, `ActivateFromInputAs`, `AnnotateAs`), so a
// regex-restricted principal denied `set system root-authentication` could
// reach the same subtree by choosing a different verb. `deactivate` is the
// sharp one: an inactive node is excluded from compilation, so deactivating a
// denied subtree REMOVES its enforcement rather than editing it, and the next
// legitimate commit by anyone ships that removal.
//
// The omission was not a decision — the comment below explains only why `load`,
// `commit` and `rollback` are absent, and never mentions these three. That is
// why `restConfigRoutesUngated` now exists and why a census asserts against it:
// a hand-maintained list of routes is what failed, so the remedy is not a
// longer hand-maintained list but one whose gaps are reported.
//
// `load` is deliberately ABSENT and is a stated remaining gap, inherited from
// the CLI gate: it applies arbitrary content whose paths are not known until
// parsed, so a path regex cannot be evaluated against it without a different
// mechanism. `commit` and `rollback` act on the candidate as a whole and carry
// no path to match.
var restConfigMutationRoutes = map[string]restConfigRoute{
	"POST /api/v1/config/set":        {verb: "set", field: pathFromInput},
	"POST /api/v1/config/delete":     {verb: "delete", field: pathFromInput},
	"POST /api/v1/config/deactivate": {verb: "deactivate", field: pathFromInput},
	"POST /api/v1/config/activate":   {verb: "activate", field: pathFromInput},
	"POST /api/v1/config/annotate":   {verb: "annotate", field: pathFromPath},
}

// restConfigRoutesUngated names every OTHER registered `POST /api/v1/config/*`
// route and why no regex is evaluated for it (#9890).
//
// This is the declared half of the census in
// authz_config_route_census_9890_test.go: a POST config route must be in ONE of
// these two tables. A new route that mutates the candidate and is added to
// neither fails that test by name, which is the signal this gate did not have
// when `deactivate`, `activate` and `annotate` were added.
//
// A reason here is a claim that the route cannot carry a denied path. Removing
// a route from this map without gating it does not make the gate quieter — it
// makes the census fail.
var restConfigRoutesUngated = map[string]string{
	"POST /api/v1/config/enter":            "opens a candidate session; mutates nothing and carries no path",
	"POST /api/v1/config/exit":             "closes the session; carries no path",
	"POST /api/v1/config/load":             "STATED REMAINING GAP, not an exemption: applies arbitrary content whose paths are unknown until parsed. The gRPC surface closed this in #9633 by evaluating the content line-by-line; REST and the CLI evaluator have not. Tracked separately — do not read this row as 'load is safe'.",
	"POST /api/v1/config/commit":           "acts on the candidate as a whole; every path in it was adjudicated when it was written",
	"POST /api/v1/config/commit-check":     "compiles the candidate and discards the result; writes nothing",
	"POST /api/v1/config/commit-confirmed": "as commit; the confirm window carries no path",
	"POST /api/v1/config/confirm":          "confirms an outstanding commit; carries no path",
	"POST /api/v1/config/rollback":         "replaces the candidate wholesale from a stored revision; carries no path to match, same class as load",
}

// authorizeRESTConfigMutation adjudicates a config-mutating REST request
// against the caller's `*-configuration` regexes.
//
// It reads the ALREADY-BUFFERED body and puts it back, so the handler still
// decodes the same bytes.
func (s *Server) authorizeRESTConfigMutation(r *http.Request, cfg *config.Config, p authz.Principal) error {
	route, gated := restConfigMutationRoutes[r.Method+" "+r.URL.Path]
	if !gated || p.Class == "" {
		return nil
	}
	// A superuser is exempt for the same reason authz.Authorize exempts one:
	// uid 0 owns the config DB and the daemon process, so a regex denial would
	// be theater. p.Class is empty for a superuser anyway.
	if p.Superuser {
		return nil
	}
	if r.Body == nil || r.Body == http.NoBody {
		return nil
	}
	raw, err := io.ReadAll(r.Body)
	r.Body = io.NopCloser(bytes.NewReader(raw))
	if err != nil {
		// The handler will report its own decode failure, which is a better
		// message than a permission denial for a body we could not read.
		return nil
	}
	var req struct {
		Input string `json:"input"`
		Path  string `json:"path"`
	}
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil
	}
	// Read the field this ROUTE declares, never both-and-whichever-is-set.
	// Falling back between them would re-create the defect in a subtler form:
	// a route whose handler reads `path` but whose gate found `input` would be
	// adjudicating a string the store never acts on.
	var input string
	switch route.field {
	case pathFromInput:
		input = strings.TrimSpace(req.Input)
	case pathFromPath:
		input = strings.TrimSpace(req.Path)
	default:
		// FAIL CLOSED. An unrecognised field means this table gained a row
		// whose extraction nobody wrote, and allowing the request would be the
		// exact silence #9890 was: a mutation passing through a gate that
		// examined nothing.
		return fmt.Errorf("config route %s %s declares no path field", r.Method, r.URL.Path)
	}
	if input == "" {
		return nil
	}
	// The edit path is empty: REST has no cursor, so the body carries the
	// resolved path — which is exactly what the store will act on.
	return config.AuthorizeConfigMutation(cfg, p.Class, nil, route.verb+" "+input)
}
