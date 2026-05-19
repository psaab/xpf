//go:build !dpdk

package dpdk

import (
	"os"
	"strings"
	"testing"
)

func TestDPDKCgoGetSessionUsesHashLookupAndConverters(t *testing.T) {
	src, err := os.ReadFile("dpdk_cgo.go")
	if err != nil {
		t.Fatalf("read dpdk_cgo.go: %v", err)
	}
	text := string(src)

	checks := []string{
		"func (m *Manager) GetSessionV4(key dataplane.SessionKey)",
		"C.rte_hash_lookup(shm.sessions_v4",
		"return convertSessionValue(sv), nil",
		"func (m *Manager) GetSessionV6(key dataplane.SessionKeyV6)",
		"C.rte_hash_lookup(shm.sessions_v6",
		"return convertSessionValueV6(sv), nil",
	}
	for _, want := range checks {
		if !strings.Contains(text, want) {
			t.Fatalf("dpdk_cgo.go missing %q", want)
		}
	}
}
