package eventengine

import (
	"fmt"
	"testing"
	"unsafe"

	"github.com/psaab/xpf/pkg/config"
)

var remediationCloneSink10877 *config.ConfigTree

// BenchmarkRemediationBatchCloneCost isolates the dominant per-command cost in
// applyOnce: each store mutation clones the complete candidate tree to stamp
// event plant-class provenance. It reports the growth in both candidate size
// and batch length without including compile/apply I/O.
func BenchmarkRemediationBatchCloneCost(b *testing.B) {
	for _, nodes := range []int{1024, 16384, 65536} {
		tree := benchmarkConfigTree10877(nodes)
		for _, commands := range []int{1, 8, 16, 64} {
			b.Run(fmt.Sprintf("nodes=%d/commands=%d", nodes, commands), func(b *testing.B) {
				b.ReportAllocs()
				b.SetBytes(int64(nodes) * int64(unsafe.Sizeof(config.Node{})) * int64(commands))
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					for range commands {
						remediationCloneSink10877 = tree.Clone()
					}
				}
			})
		}
	}
}

func benchmarkConfigTree10877(nodes int) *config.ConfigTree {
	children := make([]*config.Node, nodes)
	for i := range children {
		children[i] = &config.Node{Keys: []string{"entry", fmt.Sprintf("n%06d", i)}}
	}
	return &config.ConfigTree{Children: children}
}
