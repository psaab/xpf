package api

import (
	"net/http"
	"strings"

	"github.com/psaab/xpf/pkg/authz"
	"github.com/psaab/xpf/pkg/config"
)

// #14707 (REST twin): the config-show routes rendered the whole
// secret-redacted tree with only the coarse permission bits and the
// bare "show configuration" operational command (restRouteCommand).
// deny-configuration "^security" and path/format-scoped deny-commands
// never fired, exactly as on gRPC. The decision is shared with gRPC in
// pkg/config (AuthorizeConfigShow*); this file decodes each route's
// selectors into that call. It runs inside authorizeRESTRead, after the
// coarse bits and the operational gate, so every config read — including
// SSE re-authorization — reaches it.

// authorizeRESTConfigRead adjudicates the config-render routes against
// the class's *-configuration and path/format-scoped *-commands rules.
func (s *Server) authorizeRESTConfigRead(r *http.Request, cfg *config.Config, p authz.Principal) error {
	class := p.Class
	if class == "" || p.Superuser {
		return nil
	}
	format := r.URL.Query().Get("format")
	route := r.Method + " " + r.URL.Path
	switch route {
	case "GET /api/v1/config/show":
		// #15657 V48-02: ?path= selects the subtree (the gRPC
		// ShowConfigRequest.Path twin); absent = whole-tree render.
		if path := strings.Fields(r.URL.Query().Get("path")); len(path) > 0 {
			// #15995: price every rendered descendant of the target tree.
			target := "candidate"
			if t := strings.TrimSpace(r.URL.Query().Get("target")); t == "" || strings.EqualFold(t, "active") {
				target = "active"
			}
			var trees []*config.ConfigTree
			if s.store != nil {
				trees = s.store.ShowConfigTrees(target)
			}
			return config.AuthorizeConfigShowPathRendered(cfg, class, path,
				config.ConfigShowDisplaySuffix(restShowFormat(format)), trees...)
		}
		return config.AuthorizeConfigShowWhole(cfg, class,
			config.ConfigShowDisplaySuffix(restShowFormat(format)))
	case "GET /api/v1/config":
		// Typed compiled-config render; whole tree, no display format.
		return config.AuthorizeConfigShowWhole(cfg, class, "")
	case "GET /api/v1/config/export":
		if format == "" {
			format = "set" // configExportHandler's default
		}
		return config.AuthorizeConfigShowWhole(cfg, class,
			config.ConfigShowDisplaySuffix(restShowFormat(format)))
	case "GET /api/v1/config/search":
		// Line search over the whole active render.
		return config.AuthorizeConfigShowWhole(cfg, class, "")
	case "GET /api/v1/config/compare":
		// REST compare has no ?path= selector: whole-tree diff.
		return config.AuthorizeConfigShowCompare(cfg, class)
	case "GET /api/v1/config/show-rollback":
		// #15942 H2-04: ?path= scopes the render (the handler honours
		// it), so the gate prices that subtree, not the whole tree.
		// #15995: price the slot's rendered descendants too. An
		// unparseable n renders nothing (the handler 400s); price the
		// active tree (slot 0) as the conservative stand-in.
		n, _ := queryIntStrict(r, "n", 1)
		var trees []*config.ConfigTree
		if s.store != nil {
			if tree := s.store.RollbackTree(n); tree != nil {
				trees = []*config.ConfigTree{tree}
			}
		}
		return config.AuthorizeConfigShowRollbackAtPathRendered(cfg, class,
			strings.Fields(r.URL.Query().Get("path")),
			config.ConfigShowDisplaySuffix(restShowFormat(format)), trees...)
	}
	return nil
}

// restShowFormat maps a REST ?format= spelling to the shared gate's
// display spelling. REST uses "text" for the hierarchical form; the
// handler's own validation rejects unknown spellings, and an unknown
// spelling here yields "" (no suffix) rather than an invented form.
// #15657 V48-02: "inheritance" maps through so a deny-commands rule on
// `display inheritance` fires instead of being bypassed.
func restShowFormat(format string) string {
	switch format {
	case "set", "json", "xml", "inheritance":
		return format
	}
	return ""
}
