package natshow

import (
	"fmt"
	"io"
	"strings"

	"github.com/psaab/xpf/pkg/config"
)

// RenderNAT64 renders `show security nat nat64` — NAT64 rule-sets from
// configuration (#16681, shared per #1687).
//
// Both consumers previously hand-rolled this: the local CLI printed
// Prefix / From zones / From routing-instances / Source pool and the
// gRPC ShowText renderer printed only Prefix / Source pool, and neither
// printed the `match source-address[-name]` restriction, so a scoped
// rule-set read as match-any (and, remotely, as unscoped on every axis).
// This single renderer prints the full admission set: zone union,
// routing-instance union, source-address union and source-address-name
// union (compileNAT64 stamps the plural, but a hand-built or pre-union
// config may carry only the singular).
//
// runtime carries the applied snapshot's NAT64 runtime disarm verdicts
// (#16547), keyed by rule-set name; nil reproduces the config-only
// rendering. The config pool verdict keeps precedence, exactly as the
// two duplicated renderers did.
//
// The empty message is the gRPC form ("No NAT64 rule-sets configured\n"
// via the trailing "\n" per rule-set shape); the local CLI's historical
// trailing period is dropped so both consumers emit identical bytes,
// as with the other #1687 extractions.
func RenderNAT64(w io.Writer, cfg *config.Config, runtime RuntimeVerdicts) {
	if cfg == nil || len(cfg.Security.NAT.NAT64) == 0 {
		io.WriteString(w, "No NAT64 rule-sets configured\n")
		return
	}
	for _, rs := range cfg.Security.NAT.NAT64 {
		fmt.Fprintf(w, "NAT64 rule-set: %s\n", rs.Name)
		if rs.Prefix != "" {
			fmt.Fprintf(w, "  Prefix:      %s\n", rs.Prefix)
		}
		// #15932/#16049: one block per authored rule-set; render its
		// zone / routing-instance unions so operators see the full
		// admission set. #16681 adds the source unions beside them.
		// #17139: zones and routing-instances render the effective
		// union (singular ∪ plural, deduped) via the single-sourced
		// config normalisers, so a divergent singular is never hidden.
		zones := config.NAT64EffectiveZones(rs)
		if len(zones) > 0 {
			fmt.Fprintf(w, "  From zones:   %s\n", strings.Join(zones, ", "))
		}
		ris := config.NAT64EffectiveRoutingInstances(cfg, rs)
		// #16604: a lowered explicit-master member ("") renders as the
		// authored `default`, never as a blank list entry. Copy before
		// rewriting so the caller's slice is never mutated.
		if len(ris) > 0 {
			ris = append([]string(nil), ris...)
			for i, ri := range ris {
				if ri == "" || config.IsNATDefaultRoutingInstanceWire(ri) {
					ris[i] = "default"
				}
			}
			fmt.Fprintf(w, "  From routing-instances: %s\n", strings.Join(ris, ", "))
		}
		srcAddrs := rs.SourceAddresses
		if len(srcAddrs) == 0 && rs.SourceAddress != "" {
			srcAddrs = []string{rs.SourceAddress}
		}
		if len(srcAddrs) > 0 {
			fmt.Fprintf(w, "  Source addresses: %s\n", strings.Join(srcAddrs, ", "))
		}
		srcNames := rs.SourceAddressNames
		if len(srcNames) == 0 && rs.SourceAddressName != "" {
			srcNames = []string{rs.SourceAddressName}
		}
		if len(srcNames) > 0 {
			fmt.Fprintf(w, "  Source address-names: %s\n", strings.Join(srcNames, ", "))
		}
		if rs.SourcePool != "" {
			fmt.Fprintf(w, "  Source pool:  %s\n", rs.SourcePool)
		}
		// #16547: the NAT64 twin of the runtime quarantine. Config-only
		// pool verdict first; the applied snapshot's NAT64 verdict fills
		// the runtime-only gap.
		nat64Reason := ""
		if rs.SourcePool != "" {
			if pool, ok := cfg.Security.NAT.SourcePools[rs.SourcePool]; ok {
				nat64Reason = config.SourceNATPoolUnusableReason(pool)
			}
		}
		if nat64Reason == "" && runtime != nil {
			nat64Reason = runtime[rs.Name]
		}
		if nat64Reason != "" {
			fmt.Fprintf(w, "  NOT INSTALLED — %s\n", config.SourceNATDisarmReasonText(nat64Reason))
		}
		io.WriteString(w, "\n")
	}
}
