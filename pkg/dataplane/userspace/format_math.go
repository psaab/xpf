package userspace

// saturatingAddU64 avoids silent wraparound in telemetry renderers.
// Hot-path this is not (called at status/scrape cadence), but
// honesty-of-summation matters more here than the cycle cost: an
// overflow under adversarial input is a visible ceiling, not a reset.
func saturatingAddU64(a, b uint64) uint64 {
	sum := a + b
	if sum < a {
		return ^uint64(0)
	}
	return sum
}

// saturatingSubU64 clamps attribution residuals at zero when the source
// counters are not sampled from exactly the same publication window.
func saturatingSubU64(a, b uint64) uint64 {
	if b > a {
		return 0
	}
	return a - b
}
