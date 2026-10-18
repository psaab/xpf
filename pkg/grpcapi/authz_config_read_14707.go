package grpcapi

import (
	"fmt"

	"github.com/psaab/xpf/pkg/config"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// #14707: ShowConfig, ShowCompare and ShowRollback bypassed the
// *-configuration subtree restrictions and path/format-scoped
// deny-commands rules.
//
// The handlers discard ctx and render the full secret-redacted tree.
// authorizeRPCCommand flattened them to the bare "show configuration"
// (authz_command_table.go), so deny-commands "^show configuration
// security" and "display set" never fired; authorizeRPCConfigMutation
// adjudicates only Set/Delete/Load/Rollback and returned nil. A class
// with deny-configuration "^security" — which denies `set security …`
// on every surface — still received the security subtree via
// ShowConfig{Path:["security"]}, the whole tree, ShowCompare and
// ShowRollback. Redaction (#4051) masks secret values only; topology,
// zones, policies, address books and class names were disclosed. That
// contradicts the codebase's own invariant: #14144 conceals completion
// candidates for "exactly the subtree those gates conceal from
// ShowConfig/Set".
//
// The decision lives in pkg/config (AuthorizeConfigShow*) so REST
// reaches the same verdict; this file only decodes the request into
// (path, format) and calls it. It runs in authorizeRPCContext after
// the coarse permission bits and the candidate price, beside the
// mutation gate, and only for a non-superuser with a class — the same
// posture as the sibling gates. Fail closed throughout: an undecodable
// request for a restricted class denies rather than rendering blind.

// authorizeRPCConfigRead adjudicates the three config-read RPCs against
// the class's configuration and operational regexes.
func (s *Server) authorizeRPCConfigRead(cfg *config.Config, class, fullMethod string, req any) error {
	if class == "" {
		return nil
	}
	service, method, ok := splitFullMethod(fullMethod)
	if !ok || service != serviceName {
		return nil
	}
	switch method {
	case "ShowConfig":
		r, okReq := req.(*pb.ShowConfigRequest)
		if !okReq || r == nil {
			// Cannot tell which subtree/format would render; for a
			// restricted class that is a denial, mirroring
			// configTargetReadPermission's unreadable-request arm.
			if restricted, err := configReadRestricted(cfg, class); err != nil {
				return err
			} else if restricted {
				return fmt.Errorf("permission denied: login class %q restricts configuration or command paths and this ShowConfig request cannot be adjudicated (#14707)", class)
			}
			return nil
		}
		suffix := config.ConfigShowDisplaySuffix(showFormatName(r.GetFormat()))
		if len(r.GetPath()) == 0 {
			return config.AuthorizeConfigShowWhole(cfg, class, suffix)
		}
		return config.AuthorizeConfigShowPath(cfg, class, r.GetPath(), suffix)
	case "ShowCompare":
		return config.AuthorizeConfigShowCompare(cfg, class)
	case "ShowRollback":
		r, okReq := req.(*pb.ShowRollbackRequest)
		if !okReq || r == nil {
			if restricted, err := configReadRestricted(cfg, class); err != nil {
				return err
			} else if restricted {
				return fmt.Errorf("permission denied: login class %q restricts configuration or command paths and this ShowRollback request cannot be adjudicated (#14707)", class)
			}
			return nil
		}
		return config.AuthorizeConfigShowRollback(cfg, class,
			config.ConfigShowDisplaySuffix(showFormatName(r.GetFormat())))
	}
	return nil
}

func configReadRestricted(cfg *config.Config, class string) (bool, error) {
	if _, ok, err := config.ConfigurationLoginRegexesFor(cfg, class); err != nil {
		return false, fmt.Errorf("permission denied: login class %q has an invalid configuration regex: %w", class, err)
	} else if ok {
		return true, nil
	}
	if _, ok, err := config.OperationalLoginRegexesFor(cfg, class); err != nil {
		return false, fmt.Errorf("permission denied: login class %q has an invalid command regex: %w", class, err)
	} else if ok {
		return true, nil
	}
	return false, nil
}

// showFormatName maps the wire format to the CLI display spelling the
// shared gate consumes. HIERARCHICAL (and any unknown value, which the
// handler renders as hierarchical text) carries no suffix.
func showFormatName(f pb.ConfigFormat) string {
	switch f {
	case pb.ConfigFormat_SET:
		return "set"
	case pb.ConfigFormat_JSON:
		return "json"
	case pb.ConfigFormat_XML:
		return "xml"
	case pb.ConfigFormat_INHERITANCE:
		return "inheritance"
	}
	return ""
}
