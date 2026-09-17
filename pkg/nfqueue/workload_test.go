package nfqueue

import "fmt"

// Phase-0 workload is shared by all measurement cells. Any change requires
// re-baselining every M-cell; it is intentionally smaller than the full r4
// T22 cluster workload because this synthetic harness prices transport only.
const (
	phase0Datagrams = 2000
	// Nine counterbalanced rounds make the baseline useful on a shared build
	// box without pretending that a transport win is a mechanism gate.
	phase0Rounds = 9
)

var phase0Sizes = [...]int{64, 512, 1500}
var phase0BatchSizes = [...]int{1, 3, 8}

func phase0PayloadSize(index int) int {
	return phase0Sizes[index%len(phase0Sizes)]
}

func phase0ShapeName(batch int, affinity bool) string {
	if batch == 1 {
		return "inline"
	}
	if affinity {
		return fmt.Sprintf("batch-%d-affinity", batch)
	}
	return fmt.Sprintf("batch-%d", batch)
}
