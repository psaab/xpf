package grpcapi

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
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
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}
