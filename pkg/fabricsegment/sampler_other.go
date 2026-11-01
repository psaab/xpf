//go:build !linux

package fabricsegment

import (
	"context"
	"log/slog"
)

// runTapSampler is Linux-only; elsewhere the watcher is inert.
func runTapSampler(_ context.Context, link Link, _ *Tracker) {
	slog.Debug("fabric segment: AF_PACKET tap unavailable on this platform (#18719)", "fabric", link.Name)
}
