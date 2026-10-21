package grpcapi

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/frr"
)

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "grpcapi-nat-generation-reset")
	if err != nil {
		fmt.Fprintf(os.Stderr, "persistent NAT reset test seam: %v\n", err)
		os.Exit(1)
	}
	zeroizePersistentNatGenerationStatePath = func() string {
		return filepath.Join(dir, "persistent-nat-lease-generation.json")
	}
	// #16046 fold-2: zeroize fixtures strip a seeded 0644 frr.conf via
	// frr.StripManagedSectionFile; default the resolver to the process
	// egid (pure-preserve tightening) so they need no root/host group.
	_ = frr.SetFRRGroupResolverForTest(func() (int, bool) { return os.Getegid(), true })
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}
