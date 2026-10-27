package userspace

import "github.com/psaab/xpf/pkg/config"

// StableRethLinkLocalTargetForTest is the exported form of
// stableRethLinkLocalTarget for cross-package placement-parity tests
// (#17049).
type StableRethLinkLocalTargetForTest struct {
	Iface string
	Addr  string
}

// StableRethLinkLocalTargetsForTest exports stableRethLinkLocalTargets so
// the pkg/daemon placement-matrix test can assert the host-inbound mirror
// agrees with the daemon install/NA sets on identical hand-built configs
// (#17049). Production callers use stableRethLinkLocalTargets.
func StableRethLinkLocalTargetsForTest(cfg *config.Config) []StableRethLinkLocalTargetForTest {
	targets := stableRethLinkLocalTargets(cfg)
	out := make([]StableRethLinkLocalTargetForTest, 0, len(targets))
	for _, t := range targets {
		out = append(out, StableRethLinkLocalTargetForTest{Iface: t.iface, Addr: t.addr})
	}
	return out
}
