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

// redirectFamilies enumerates the sysctl families/knobs the
// no-redirects posture touches, shared by the disable and restore
// walks so the two cannot drift.
var redirectFamilies = []struct {
	name  string
	knobs []string
}{
	{"ipv4", []string{"send_redirects", "accept_redirects"}},
	{"ipv6", []string{"accept_redirects"}},
}

func writeRedirectKnobs(value string) {
	for _, family := range redirectFamilies {
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
				if strings.TrimSpace(string(current)) == value {
					continue
				}
				if err := os.WriteFile(path, []byte(value+"\n"), 0644); err != nil {
					slog.Warn("failed to set ICMP redirects", "path", path, "value", value, "err", err)
				}
			}
		}
	}
}

func applyNoRedirectsPosture() {
	if !noRedirectsActive.Load() {
		return
	}
	writeRedirectKnobs("0")
}

// reconcileNoRedirects records the configured posture and drives the
// kernel knobs: assert 0 while active, and on the active->inactive
// transition restore 1 (the kernel default) exactly once (#15710).
// Deleting `system no-redirects` therefore restores
// send_redirects/accept_redirects instead of leaving the irreversible
// 0 the old code wrote.
func reconcileNoRedirects(active bool) {
	wasActive := noRedirectsActive.Swap(active)
	switch {
	case active:
		writeRedirectKnobs("0")
	case wasActive:
		writeRedirectKnobs("1")
	}
}
