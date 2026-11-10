package flowexport

import (
	"os"
	"testing"

	"github.com/psaab/xpf/internal/testguard"
)

func TestMain(m *testing.M) {
	testguard.ExitIfUnsafe()
	// #19088: after the tests, no OS thread may be left outside the
	// package's network namespace.
	os.Exit(testguard.Run(m))
}
