package grpcapi

import (
	"context"
	"fmt"

	"github.com/psaab/xpf/pkg/config"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// configReadSnapshotsKey carries the deep-copy trees the config-read
// gate priced, from authorizeRPCContext to the Show* handler, so the
// handler renders the exact generation that was authorized (#15995
// fold). Absent on ungated (superuser) calls, where the handler keeps
// the store renderers.
type configReadSnapshotsKey struct{}

// configReadSnapshots is the snapshot set for one config-read RPC.
// Primary is the ShowConfig target / rollback slot tree; Other is the
// second compare arm. Present records that the gate DID capture a
// snapshot (fold 3): a captured snapshot whose Primary is nil means
// the target/slot was ABSENT at pricing — the handler must render
// that absence (empty / slot error), never re-resolve the live store,
// where a later candidate/slot could carry unpriced content. Absent
// Present (ungated/superuser) keeps the store renderers.
type configReadSnapshots struct {
	Primary *config.ConfigTree
	Other   *config.ConfigTree
	NodeID  int
	Present bool
}

type grpcConfigReadSlotError struct {
	err error
}

func (e grpcConfigReadSlotError) Error() string { return e.err.Error() }

func configReadSnapshotsFrom(ctx context.Context) (configReadSnapshots, bool) {
	s, ok := ctx.Value(configReadSnapshotsKey{}).(configReadSnapshots)
	return s, ok
}

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
// the class's configuration and operational regexes, returning the
// priced tree snapshots for the handler to render.
func (s *Server) authorizeRPCConfigRead(cfg *config.Config, class, fullMethod string, req any) (configReadSnapshots, error) {
	if class == "" {
		return configReadSnapshots{}, nil
	}
	service, method, ok := splitFullMethod(fullMethod)
	if !ok || service != serviceName {
		return configReadSnapshots{}, nil
	}
	switch method {
	case "ShowConfig":
		r, okReq := req.(*pb.ShowConfigRequest)
		if !okReq || r == nil {
			// Cannot tell which subtree/format would render; for a
			// restricted class that is a denial, mirroring
			// configTargetReadPermission's unreadable-request arm.
			if restricted, err := configReadRestricted(cfg, class); err != nil {
				return configReadSnapshots{}, err
			} else if restricted {
				return configReadSnapshots{}, fmt.Errorf("permission denied: login class %q restricts configuration or command paths and this ShowConfig request cannot be adjudicated (#14707)", class)
			}
			return configReadSnapshots{}, nil
		}
		suffix := config.ConfigShowDisplaySuffix(showFormatName(r.GetFormat()))
		if len(r.GetPath()) == 0 {
			// Fold 5: attach the priced generation for the handler
			// (restricted classes are refused by ShowWhole below;
			// admitted ones render this snapshot, not live).
			snaps := configReadSnapshots{Present: true, NodeID: -1}
			priceCfg := cfg
			if s.store != nil {
				target := "candidate"
				if r.GetTarget() == pb.ConfigTarget_ACTIVE {
					target = "active"
				}
				// Fold 6: authorize with the snapshot's OWN cfg.
				scfg, tree, nid, _ := s.store.ShowConfigSnapshot(target)
				if scfg != nil {
					priceCfg = scfg
				}
				snaps.NodeID = nid
				snaps.Primary = tree
			}
			return snaps, config.AuthorizeConfigShowWholeAtTree(priceCfg, class, suffix, snaps.Primary)
		}
		// #15995: price every rendered descendant, not just the
		// requested path — the handler renders the whole subtree.
		// For display inheritance the rendered subtree is the
		// apply-groups-expanded tree, so price that expansion.
		// Fold 3: capture policy+tree atomically (ShowConfigSnapshot)
		// and price with THAT cfg, so a commit between the authz
		// cfg read and the tree read cannot pair old rules with new
		// data. Present marks the capture even when the tree is
		// absent (nil): the handler renders the absence.
		target := "candidate"
		if r.GetTarget() == pb.ConfigTarget_ACTIVE {
			target = "active"
		}
		var trees []*config.ConfigTree
		nodeID := -1
		priceCfg := cfg
		if s.store != nil {
			scfg, tree, nid, _ := s.store.ShowConfigSnapshot(target)
			if scfg != nil {
				priceCfg = scfg
			}
			nodeID = nid
			if tree != nil {
				trees = []*config.ConfigTree{tree}
			}
		}
		snaps := configReadSnapshots{NodeID: nodeID, Present: true}
		if len(trees) > 0 {
			snaps.Primary = trees[0]
		}
		if r.GetFormat() == pb.ConfigFormat_INHERITANCE {
			return snaps, config.AuthorizeExpandedConfigShowPathRendered(priceCfg, class, r.GetPath(), suffix, nodeID, trees...)
		}
		return snaps, config.AuthorizeConfigShowPathRendered(priceCfg, class, r.GetPath(), suffix, trees...)
	case "ShowCompare":
		r, okReq := req.(*pb.ShowCompareRequest)
		if !okReq || r == nil {
			return configReadSnapshots{}, config.AuthorizeConfigShowCompare(cfg, class)
		}
		// #15995: a scoped compare discloses descendants on BOTH arms.
		// Fold 3: atomic policy+arms capture; Present distinguishes a
		// captured absent candidate (Other nil) from no capture.
		var trees []*config.ConfigTree
		snaps := configReadSnapshots{Present: true}
		priceCfg := cfg
		if len(r.GetPath()) == 0 && s.store != nil {
			// Unscoped: substitute contained+expanded pricing over
			// both actual arms; op verdict carried by the helper.
			if r.GetActiveBaseline() || r.GetRollbackN() > 0 {
				scfg, slot, other, nid, _, slotErr := s.store.RollbackCompareSnapshot(int(r.GetRollbackN()), r.GetActiveBaseline())
				if scfg != nil {
					priceCfg = scfg
				}
				snaps.NodeID = nid
				snaps.Primary, snaps.Other = slot, other
				if slotErr != nil {
					if err := config.AuthorizeConfigShowCompareCommand(priceCfg, class, nil); err != nil {
						return snaps, err
					}
					return snaps, grpcConfigReadSlotError{err: slotErr}
				}
				return snaps, config.AuthorizeConfigShowCompareAtTree(priceCfg, class, slot, other)
			}
			scfg, active, candidate, _ := s.store.CompareSnapshot()
			if scfg != nil {
				priceCfg = scfg
			}
			snaps.Primary, snaps.Other = active, candidate
			return snaps, config.AuthorizeConfigShowCompareAtTree(priceCfg, class, active, candidate)
		}
		if s.store != nil {
			if r.GetActiveBaseline() || r.GetRollbackN() > 0 {
				scfg, slot, other, nid, _, slotErr := s.store.RollbackCompareSnapshot(int(r.GetRollbackN()), r.GetActiveBaseline())
				if scfg != nil {
					priceCfg = scfg
				}
				snaps.NodeID = nid
				trees = []*config.ConfigTree{slot, other}
				snaps.Primary, snaps.Other = slot, other
				if slotErr != nil {
					if err := config.AuthorizeConfigShowCompareCommand(priceCfg, class, r.GetPath()); err != nil {
						return snaps, err
					}
					return snaps, grpcConfigReadSlotError{err: slotErr}
				}
			} else {
				scfg, active, candidate, _ := s.store.CompareSnapshot()
				if scfg != nil {
					priceCfg = scfg
				}
				trees = []*config.ConfigTree{active, candidate}
				snaps.Primary, snaps.Other = active, candidate
			}
		}
		return snaps, config.AuthorizeConfigShowCompareAtPathRendered(priceCfg, class, r.GetPath(), trees...)
	case "ShowRollback":
		r, okReq := req.(*pb.ShowRollbackRequest)
		if !okReq || r == nil {
			if restricted, err := configReadRestricted(cfg, class); err != nil {
				return configReadSnapshots{}, err
			} else if restricted {
				return configReadSnapshots{}, fmt.Errorf("permission denied: login class %q restricts configuration or command paths and this ShowRollback request cannot be adjudicated (#14707)", class)
			}
			return configReadSnapshots{}, nil
		}
		// #15995: price the rollback slot's rendered descendants.
		// Display inheritance prices the expanded slot tree.
		// Fold 3: atomic capture; an unresolved slot prices as
		// absent (Primary nil, Present) and the handler surfaces
		// the slot error from the live store without rendering it.
		var trees []*config.ConfigTree
		nodeID := -1
		priceCfg := cfg
		var slotErr error
		if s.store != nil {
			scfg, tree, nid, _, capturedSlotErr := s.store.RollbackSnapshot(int(r.GetN()))
			slotErr = capturedSlotErr
			if scfg != nil {
				priceCfg = scfg
			}
			nodeID = nid
			if tree != nil {
				trees = []*config.ConfigTree{tree}
			}
		}
		snaps := configReadSnapshots{NodeID: nodeID, Present: true}
		if len(trees) > 0 {
			snaps.Primary = trees[0]
		}
		if slotErr != nil {
			if err := config.AuthorizeConfigShowRollbackCommand(priceCfg, class, r.GetPath(),
				config.ConfigShowDisplaySuffix(showFormatName(r.GetFormat()))); err != nil {
				return snaps, err
			}
			return snaps, grpcConfigReadSlotError{err: slotErr}
		}
		if r.GetFormat() == pb.ConfigFormat_INHERITANCE {
			return snaps, config.AuthorizeExpandedConfigShowRollbackAtPathRendered(priceCfg, class, r.GetPath(),
				config.ConfigShowDisplaySuffix(showFormatName(r.GetFormat())), nodeID, trees...)
		}
		return snaps, config.AuthorizeConfigShowRollbackAtPathRendered(priceCfg, class, r.GetPath(),
			config.ConfigShowDisplaySuffix(showFormatName(r.GetFormat())), trees...)
	}
	return configReadSnapshots{}, nil
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
