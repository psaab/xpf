package routing

import (
	"os"
	"testing"

	"github.com/psaab/xpf/internal/testguard"
)

func TestMain(m *testing.M) {
	testguard.ExitIfUnsafe()
	os.Exit(m.Run())
}
