package frr

import (
	"fmt"
	"log/slog"
	"strings"

	"github.com/psaab/xpf/pkg/config"
)

// renderBGPAllowASIn emits only FRR-supported loop counts. Tolerant config
// loads can retain invalid values even though commit validation rejects them;
// omit those values rather than failing the whole frr-reload batch.
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
	fmt.Fprintf(b, "  neighbor %s allowas-in %d\n", n.Address, n.AllowASIn)
}
