package api

import (
	"context"
	"net/http"
	"strings"

	"github.com/psaab/xpf/pkg/authz"
	"github.com/psaab/xpf/pkg/config"
)

// restConfigReadSnapshotsKey carries the deep-copy trees the REST
// config-read gate priced, from authorizeRESTRead to the handler, so
// the handler renders the exact generation that was authorized
// (#15995 fold). Absent on ungated (superuser) calls.
type restConfigReadSnapshotsKey struct{}

type restConfigReadSnapshots struct {
	Primary *config.ConfigTree
	Other   *config.ConfigTree
	NodeID  int
}

func restConfigReadSnapshotsFrom(r *http.Request) (restConfigReadSnapshots, bool) {
	s, ok := r.Context().Value(restConfigReadSnapshotsKey{}).(restConfigReadSnapshots)
	return s, ok
}

func withRESTConfigReadSnapshots(r *http.Request, s restConfigReadSnapshots) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), restConfigReadSnapshotsKey{}, s))
}

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
// the class's *-configuration and path/format-scoped *-commands rules,
// returning the priced snapshots for the handler to render.
func (s *Server) authorizeRESTConfigRead(r *http.Request, cfg *config.Config, p authz.Principal) (restConfigReadSnapshots, error) {
	class := p.Class
	if class == "" || p.Superuser {
		return restConfigReadSnapshots{}, nil
	}
	format := r.URL.Query().Get("format")
	route := r.Method + " " + r.URL.Path
	switch route {
	case "GET /api/v1/config/show":
		// #15657 V48-02: ?path= selects the subtree (the gRPC
		// ShowConfigRequest.Path twin); absent = whole-tree render.
		if path := strings.Fields(r.URL.Query().Get("path")); len(path) > 0 {
			// #15995: price every rendered descendant of the target tree.
			// format=inheritance renders the expanded tree: price it.
			target := "candidate"
			if t := strings.TrimSpace(r.URL.Query().Get("target")); t == "" || strings.EqualFold(t, "active") {
				target = "active"
			}
			var trees []*config.ConfigTree
			nodeID := -1
			if s.store != nil {
				trees = s.store.ShowConfigTrees(target)
				nodeID = s.store.NodeID()
			}
			snaps := restConfigReadSnapshots{NodeID: nodeID}
			if len(trees) > 0 {
				snaps.Primary = trees[0]
			}
			if restShowFormat(format) == "inheritance" {
				return snaps, config.AuthorizeExpandedConfigShowPathRendered(cfg, class, path,
					config.ConfigShowDisplaySuffix(restShowFormat(format)), nodeID, trees...)
			}
			return snaps, config.AuthorizeConfigShowPathRendered(cfg, class, path,
				config.ConfigShowDisplaySuffix(restShowFormat(format)), trees...)
		}
		return restConfigReadSnapshots{}, config.AuthorizeConfigShowWhole(cfg, class,
			config.ConfigShowDisplaySuffix(restShowFormat(format)))
	case "GET /api/v1/config":
		// Typed compiled-config render; whole tree, no display format.
		return restConfigReadSnapshots{}, config.AuthorizeConfigShowWhole(cfg, class, "")
	case "GET /api/v1/config/export":
		if format == "" {
			format = "set" // configExportHandler's default
		}
		return restConfigReadSnapshots{}, config.AuthorizeConfigShowWhole(cfg, class,
			config.ConfigShowDisplaySuffix(restShowFormat(format)))
	case "GET /api/v1/config/search":
		// Line search over the whole active render.
		return restConfigReadSnapshots{}, config.AuthorizeConfigShowWhole(cfg, class, "")
	case "GET /api/v1/config/compare":
		// REST compare has no ?path= selector: whole-tree diff.
		return restConfigReadSnapshots{}, config.AuthorizeConfigShowCompare(cfg, class)
	case "GET /api/v1/config/show-rollback":
		// #15942 H2-04: ?path= scopes the render (the handler honours
		// it), so the gate prices that subtree, not the whole tree.
		// #15995: price the slot's rendered descendants too.
		// queryIntStrict mirrors the handler: absent n defaults to
		// slot 1; an unparseable n yields slot 0 here and the handler
		// 400s before rendering, so that stand-in is never disclosed.
		// format=inheritance prices the expanded slot tree.
		n, _ := queryIntStrict(r, "n", 1)
		var trees []*config.ConfigTree
		nodeID := -1
		if s.store != nil {
			if tree := s.store.RollbackTree(n); tree != nil {
				trees = []*config.ConfigTree{tree}
			}
			nodeID = s.store.NodeID()
		}
		snaps := restConfigReadSnapshots{NodeID: nodeID}
		if len(trees) > 0 {
			snaps.Primary = trees[0]
		}
		if restShowFormat(format) == "inheritance" {
			return snaps, config.AuthorizeExpandedConfigShowRollbackAtPathRendered(cfg, class,
				strings.Fields(r.URL.Query().Get("path")),
				config.ConfigShowDisplaySuffix(restShowFormat(format)), nodeID, trees...)
		}
		return snaps, config.AuthorizeConfigShowRollbackAtPathRendered(cfg, class,
			strings.Fields(r.URL.Query().Get("path")),
			config.ConfigShowDisplaySuffix(restShowFormat(format)), trees...)
	}
	return restConfigReadSnapshots{}, nil
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
