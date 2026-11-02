//go:build !linux

package fabricsegment

import (
	"context"
	"log/slog"
)

// runTapSampler is Linux-only; elsewhere the watcher is inert. It blocks
// until ctx is done so the Monitor does not read an inert platform as a
// sampler that keeps stopping.
func runTapSampler(ctx context.Context, link Link, _ *Tracker) error {
	slog.Debug("fabric segment: AF_PACKET tap unavailable on this platform (#18719)", "fabric", link.Name)
	<-ctx.Done()
	return nil
}
