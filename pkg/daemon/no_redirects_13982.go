package daemon

import (
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
)

// redirectSysctlRoot is the procfs root used for sysctl posture; overridable
// in tests to exercise existing and newly created netdev entries.
var redirectSysctlRoot = "/proc/sys/net"

var noRedirectsActive atomic.Bool

func applyNoRedirectsPosture() {
	if !noRedirectsActive.Load() {
		return
	}
	for _, family := range []struct {
		name  string
		knobs []string
	}{
		{"ipv4", []string{"send_redirects", "accept_redirects"}},
		{"ipv6", []string{"accept_redirects"}},
	} {
		confRoot := filepath.Join(redirectSysctlRoot, family.name, "conf")
		entries, err := os.ReadDir(confRoot)
		if err != nil {
			slog.Warn("failed to enumerate redirect sysctls", "path", confRoot, "err", err)
			continue
		}
		for _, entry := range entries {
			for _, knob := range family.knobs {
				path := filepath.Join(confRoot, entry.Name(), knob)
				current, _ := os.ReadFile(path)
				if strings.TrimSpace(string(current)) == "0" {
					continue
				}
				if err := os.WriteFile(path, []byte("0\n"), 0644); err != nil {
					slog.Warn("failed to disable ICMP redirects", "path", path, "err", err)
				}
			}
		}
	}
}
