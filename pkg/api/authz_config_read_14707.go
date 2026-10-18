package api

import (
	"net/http"

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
		// No path selector exists on this route: whole-tree render.
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
		return config.AuthorizeConfigShowCompare(cfg, class)
	case "GET /api/v1/config/show-rollback":
		return config.AuthorizeConfigShowRollback(cfg, class,
			config.ConfigShowDisplaySuffix(restShowFormat(format)))
	}
	return nil
}

// restShowFormat maps a REST ?format= spelling to the shared gate's
// display spelling. REST uses "text" for the hierarchical form; the
// handler's own validation rejects unknown spellings, and an unknown
// spelling here yields "" (no suffix) rather than an invented form.
func restShowFormat(format string) string {
	switch format {
	case "set", "json", "xml":
		return format
	}
	return ""
}
