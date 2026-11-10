package dataplane

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/internal/testguard"
)

func TestMain(m *testing.M) {
	testguard.ExitIfUnsafe()
	// #19072: rssHashKeyForBoot stores this boot's key under /run/xpf. No
	// test may write there (a root test run on a real box would replace the
	// live key file), so the package runs against a private directory.
	dir, err := os.MkdirTemp("", "xpf-rss-")
	if err != nil {
		panic(err)
	}
	rssBootKeyPath = filepath.Join(dir, "rss-hash-key")
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}
