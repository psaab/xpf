package ipsec

// SetSwanctlForTesting installs a swanctl exec double on m. It exists so a package
// holding a *Manager (the daemon's loaded-generation tracking, #9511) can drive a
// successful or failed reload without a swanctl binary, following the
// pkg/cluster test_seams.go precedent. Production code never calls it.
func (m *Manager) SetSwanctlForTesting(fn func(args ...string) ([]byte, error)) {
	m.swanctl = fn
}
