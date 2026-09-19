package grpcapi

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	dpformat "github.com/psaab/xpf/pkg/dataplane/userspace/format"
	"github.com/psaab/xpf/pkg/fwdstatus"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"google.golang.org/grpc/metadata"
)

func (s *Server) buildLocalForwarding() string {
	var snap fwdstatus.SamplerSnapshot
	if s.fwdSampler != nil {
		snap = s.fwdSampler.Snapshot()
	}
	fs, err := fwdstatus.Build(
		s.forwardingStatusDataplane(),
		fwdstatus.OSProcReader{},
		s.startTime,
		snap,
	)
	if err != nil {
		return fmt.Sprintf("FWDD status:\n  (build failed: %s)\n", err)
	}
	return fwdstatus.Format(fs)
}

type forwardingStatusServerDataPlane struct {
	server *Server
}

func (a forwardingStatusServerDataPlane) IsLoaded() bool {
	return a.server != nil && a.server.dp != nil && a.server.dp.IsLoaded()
}

func (a forwardingStatusServerDataPlane) GetMapStats() []fwdstatus.MapStats {
	if a.server == nil || a.server.dp == nil {
		return nil
	}
	stats := a.server.dp.GetMapStats()
	out := make([]fwdstatus.MapStats, 0, len(stats))
	for _, ms := range stats {
		out = append(out, fwdstatus.MapStats{
			Type:       ms.Type,
			MaxEntries: ms.MaxEntries,
			UsedCount:  ms.UsedCount,
		})
	}
	return out
}

type forwardingStatusServerUserspaceDataPlane struct {
	forwardingStatusServerDataPlane
}

func (a forwardingStatusServerUserspaceDataPlane) Status() (dpuserspace.ProcessStatus, error) {
	return a.server.userspaceDataplaneStatus()
}

// HelperCrashState feeds fwdstatus's #7250 crash block. Resolves the backend
// directly rather than via userspaceDataplaneStatus(), because a crash clears
// the cached ProcessStatus and the crash record is Manager-owned — routing it
// through the status path would blank the block in the one case it is for.
func (a forwardingStatusServerUserspaceDataPlane) HelperCrashState() (dpuserspace.HelperCrashRecord, bool) {
	provider, ok := a.server.dpProbe().(userspaceCrashProvider)
	if !ok {
		return dpuserspace.HelperCrashRecord{}, false
	}
	return provider.HelperCrashState()
}

// HelperCrashHistory feeds fwdstatus's #8397 recovered-episode summary.
// Resolve the backend directly: unlike the current crash record, history is
// deliberately still present after a successful restart has wiped the live
// episode state.
func (a forwardingStatusServerUserspaceDataPlane) HelperCrashHistory() ([]dpuserspace.HelperCrashEpisode, int) {
	provider, ok := a.server.dpProbe().(userspaceCrashHistoryProvider)
	if !ok {
		return nil, 0
	}
	return provider.HelperCrashHistory()
}

func (s *Server) forwardingStatusDataplane() fwdstatus.DataPlaneAccessor {
	if s == nil {
		return nil
	}
	// #2114/#6743 r2-B7: the publication check must ask the CELL, not the
	// field. `s.dp == nil` is permanently false under the daemon's live
	// indirection, so a daemon whose startup arm failed and cleared the
	// cell fell PAST this guard and returned the non-userspace `base`
	// wrapper. fwdstatus.Build then took its BPF-map arm, where
	// GetMapStats() returns nil and the max-occupancy loop over an empty
	// slice leaves maxPct at 0 — and sets BufferKnown=true. The render is
	// "Buffer utilization   0 percent" where the nil-dp control correctly
	// says "unknown (see #878)".
	//
	// This is worse than the sibling r6-F3 renders: a misleading string is
	// read by a human, but BufferKnown=true tells every downstream consumer
	// the zero is TRUSTWORTHY. Returning nil here restores
	// BufferKnown=false, not merely the string.
	//
	// ONE resolution feeds both decisions, as in showBuffers (r7): a
	// setDataplane(nil) landing between a publication check and a separate
	// dpProbe() re-creates the confusion the check exists to prevent.
	backend := dataplane.Unwrap(s.dp)
	if backend == nil {
		return nil
	}
	base := forwardingStatusServerDataPlane{server: s}
	if _, ok := backend.(userspaceStatusProvider); ok {
		return forwardingStatusServerUserspaceDataPlane{forwardingStatusServerDataPlane: base}
	}
	return base
}

func (s *Server) dialAndShowForwarding(ctx context.Context) (string, error) {
	conn, err := s.dialPeer(ctx)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	client := pb.NewBpfrxServiceClient(conn)
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	ctx = metadata.AppendToOutgoingContext(ctx, "xpf-no-peer", "1")
	resp, err := client.ShowText(ctx, &pb.ShowTextRequest{Topic: "chassis-forwarding"})
	if err != nil {
		return "", err
	}
	return resp.Output, nil
}

// --- #1700: residual ShowText branches ---

func (s *Server) showForwardingOptions(cfg *config.Config, buf *strings.Builder) {
	if cfg == nil {
		buf.WriteString("No active configuration\n")
	} else {
		fo := &cfg.ForwardingOptions
		hasContent := false
		if fo.FamilyInet6Mode != "" {
			fmt.Fprintf(buf, "Family inet6 mode: %s\n", fo.FamilyInet6Mode)
			hasContent = true
		}
		if fo.Sampling != nil && len(fo.Sampling.Instances) > 0 {
			buf.WriteString("Sampling:\n")
			for _, name := range sortedInstanceNames(fo.Sampling.Instances) {
				inst := fo.Sampling.Instances[name]
				fmt.Fprintf(buf, "  Instance: %s\n", name)
				if inst.InputRate > 0 {
					fmt.Fprintf(buf, "    Input rate: 1/%d\n", inst.InputRate)
				}
				for _, fam := range []*config.SamplingFamily{inst.FamilyInet, inst.FamilyInet6} {
					if fam == nil {
						continue
					}
					for _, fs := range fam.FlowServers {
						// #6565 row 11 / #7422: annotate a collector the
						// snapshot builder skips, using its own verdict.
						fmt.Fprintf(buf, "    Flow server: %s:%d%s\n", fs.Address,
							fs.Port, flowServerNotInstalledSuffix(fs))
						if fs.Version9Template != "" {
							fmt.Fprintf(buf, "      Version 9 template: %s\n", fs.Version9Template)
						}
						// Per-collector source-address override (#3745).
						if fs.SourceAddress != "" {
							fmt.Fprintf(buf, "      Source address: %s\n", fs.SourceAddress)
						}
					}
					if fam.SourceAddress != "" {
						fmt.Fprintf(buf, "    Source address: %s\n", fam.SourceAddress)
					}
					if fam.InlineJflow {
						buf.WriteString("    Inline jflow: enabled\n")
					}
					if fam.InlineJflowSourceAddress != "" {
						fmt.Fprintf(buf, "    Inline jflow source: %s\n", fam.InlineJflowSourceAddress)
					}
				}
			}
			hasContent = true
		}
		if fo.DHCPRelay != nil {
			buf.WriteString("DHCP relay: (see 'show dhcp-relay' for details)\n")
			hasContent = true
		}
		if fo.PortMirroring != nil && len(fo.PortMirroring.Instances) > 0 {
			buf.WriteString("Port mirroring: (see 'show forwarding-options port-mirroring' for details)\n")
			hasContent = true
		}
		if !hasContent {
			buf.WriteString("No forwarding-options configured\n")
		}
	}
}

func (s *Server) showForwardingOptionsPortMirroring(cfg *config.Config, buf *strings.Builder) {
	if cfg == nil {
		buf.WriteString("No active configuration\n")
		return
	}
	// #7357: single-sourced with the CLI. These two were byte-identical
	// copies with no shared formatter, and the comment that used to sit
	// here said so — "annotating one leaves the other lying". Now there is
	// one render and the parity test compares two callers of it.
	buf.WriteString(dpformat.FormatPortMirroring(cfg, s.mirrorExclusions()))
}

// flowServerNotInstalledSuffix returns the `[NOT INSTALLED: <reason>]` suffix
// for a flow-server (collector) the userspace snapshot builder refuses to
// install, or "" when it installs.
//
// #6565 row 11 / #7422: the verdict is config.FlowServerExcludedReason — the
// SAME predicate buildFlowExportSnapshots consults — so the renderer and the
// builder cannot disagree about which collectors are live. Unlike most #6534
// families this state is reachable through a clean commit: nothing validates
// the flow-server port at commit time, so `flow-server 10.0.0.1` with no
// `port` lands in the active config, is skipped by the builder, and used to
// print as `Collector: 10.0.0.1` — the `:0` suffix suppressed, so it read as a
// healthy collector on the default port.
func flowServerNotInstalledSuffix(fs *config.FlowServer) string {
	reason := config.FlowServerExcludedReason(fs)
	if reason == "" {
		return ""
	}
	return "  [NOT INSTALLED: " + reason + "]"
}

// sortedInstanceNames returns a map's keys in a stable order.
//
// #7357: every `show forwarding-options` renderer iterated its instance map
// with a bare `range`, which Go randomises per run. The listings therefore
// changed order between two calls with identical config -- an operator diffing
// captures sees churn that is not there, and any golden or transcript over
// these surfaces is unstable for a reason unrelated to the config.
//
// Generic over the value type because the same defect appeared in BOTH the
// port-mirroring and sampling families, whose instance types differ. The
// issue named only the two port-mirroring renderers and said its census was a
// FLOOR; measuring the tree found six sites across three files.
func sortedInstanceNames[T any](m map[string]T) []string {
	names := make([]string, 0, len(m))
	for name := range m {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// mirrorExclusions reads the #7357 §2 runtime verdicts off the applied
// snapshot, or nil when the backend keeps none. Capability assertion for the
// same reason as the CLI twin: a nil-returning stub would be
// indistinguishable from "nothing was excluded".
func (s *Server) mirrorExclusions() []dpuserspace.MirrorExclusion {
	// Through dpProbe(), NOT the stored dp field. #2114: under the live
	// indirection the field holds a wrapper, so a type assertion on it
	// answers "capability absent" for a HEALTHY backend that implements the
	// method — which here would render an armed instance as un-annotated,
	// the exact lie this change exists to stop.
	// TestOptionalCapabilityProbesUseDPProbe is the canary; it caught this.
	if m, ok := s.dpProbe().(interface {
		MirrorExclusions() []dpuserspace.MirrorExclusion
	}); ok {
		return m.MirrorExclusions()
	}
	return nil
}
