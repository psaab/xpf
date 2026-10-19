package frr

import (
	"fmt"
	"log/slog"
	"strings"

	"github.com/psaab/xpf/pkg/config"
)

// renderBGPAllowASIn emits the FRR equivalent of Junos `loops`.
//
// Junos `loops N` (loops (Autonomous System) semantics, also used for
// the BGP group/neighbor `loops` leaf xpf accepts) hides a route when
// the local AS is detected N or more times: it allows N-1 occurrences,
// and `loops 1` is Junos's default loop prevention (0 allowed). FRR
// `allowas-in K` instead counts accepted occurrences (route filtered
// when the count exceeds K), and no line means 0 allowed. The
// Junos-equivalent rendering is therefore: loops 1 -> no line,
// loops N>=2 -> `allowas-in N-1` (#15009). Copying N verbatim accepted
// one extra local-AS occurrence on every peer with `loops` set.
//
// Tolerant config loads can retain invalid values even though commit
// validation rejects them; omit those values rather than failing the
// whole frr-reload batch (#11795).
func renderBGPAllowASIn(b *strings.Builder, n *config.BGPNeighbor) {
	if n == nil || n.AllowASIn == 0 {
		return
	}
	if n.AllowASIn < 1 || n.AllowASIn > config.MaxBGPAllowASIn {
		slog.Warn("frr: omitting an out-of-range BGP allowas-in setting (#11795)",
			"neighbor", sanitizeFRRValue(n.Address), "loops", n.AllowASIn,
			"min", 1, "max", config.MaxBGPAllowASIn)
		return
	}
	if n.AllowASIn == 1 {
		// Junos default loop prevention == FRR no allowas-in (0 allowed).
		return
	}
	fmt.Fprintf(b, "  neighbor %s allowas-in %d\n", n.Address, n.AllowASIn-1)
}
