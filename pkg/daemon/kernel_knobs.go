package daemon

import "github.com/psaab/xpf/pkg/fsatomic"

// knobs returns the daemon's shared BestEffortKernelKnob registry
// (#17068), lazily created. Every procfs knob with a config lifecycle
// asserts/releases through this one registry so a second owner of the
// same path is refused instead of silently diverging (the
// nf_conntrack_tcp_loose two-writer class).
func (d *Daemon) knobs() *fsatomic.KernelKnobs {
	d.kernelKnobsMu.Lock()
	defer d.kernelKnobsMu.Unlock()
	if d.kernelKnobs == nil {
		d.kernelKnobs = fsatomic.NewKernelKnobs()
	}
	return d.kernelKnobs
}

// knobOwners are the registry owner names for daemon knob lifecycles.
const (
	knobOwnerFib       = "fib-consistent-hash"
	knobOwnerRedirects = "no-redirects"
	knobOwnerPosture   = "host-posture"
	knobOwnerTransit   = "transit-gate"
	knobOwnerCleanup   = "transit-cleanup"
)
