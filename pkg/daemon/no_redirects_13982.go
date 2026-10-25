package daemon

import (
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
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

// redirectKnobPaths enumerates every knob file currently present under
// the sysctl root for the redirect families.
func redirectKnobPaths() []string {
	var out []string
	for _, family := range redirectFamilies {
		confRoot := filepath.Join(redirectSysctlRoot, family.name, "conf")
		entries, err := os.ReadDir(confRoot)
		if err != nil {
			slog.Warn("failed to enumerate redirect sysctls", "path", confRoot, "err", err)
			continue
		}
		for _, entry := range entries {
			for _, knob := range family.knobs {
				out = append(out, filepath.Join(confRoot, entry.Name(), knob))
			}
		}
	}
	return out
}

func writeRedirectKnobs(value string) {
	for _, path := range redirectKnobPaths() {
		current, _ := os.ReadFile(path)
		if strings.TrimSpace(string(current)) == value {
			continue
		}
		if err := os.WriteFile(path, []byte(value+"\n"), 0644); err != nil {
			slog.Warn("failed to set ICMP redirects", "path", path, "value", value, "err", err)
		}
	}
}

// capturedRedirects holds the per-path values observed on the
// inactive->active transition (#16779), restored verbatim on the
// active->inactive transition. Guarded by redirectCaptureMu.
var (
	redirectCaptureMu sync.Mutex
	capturedRedirects map[string]string
)

// captureRedirectKnobs snapshots the current value of every enumerated
// knob. Must be called before writeRedirectKnobs("0") overwrites them.
func captureRedirectKnobs() {
	redirectCaptureMu.Lock()
	defer redirectCaptureMu.Unlock()
	capturedRedirects = make(map[string]string)
	for _, path := range redirectKnobPaths() {
		b, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		capturedRedirects[path] = strings.TrimSpace(string(b))
	}
}

func takeCapturedRedirectKnobs() map[string]string {
	redirectCaptureMu.Lock()
	defer redirectCaptureMu.Unlock()
	m := capturedRedirects
	capturedRedirects = nil
	return m
}

// isIPv4AcceptRedirects reports whether path is an ipv4
// accept_redirects knob (any interface, including dotted names).
func isIPv4AcceptRedirects(path string) bool {
	if filepath.Base(path) != "accept_redirects" {
		return false
	}
	confDir := filepath.Dir(filepath.Dir(path)) // .../ipv4/conf
	return filepath.Base(confDir) == "conf" && filepath.Base(filepath.Dir(confDir)) == "ipv4"
}

func ipv4ForwardingEnabled() bool {
	fwd, err := os.ReadFile(ipv4ForwardSysctlPath)
	return err == nil && strings.TrimSpace(string(fwd)) == "1"
}

// restoreValueForRedirectKnob computes the value to write on restore
// when no captured value exists for path (e.g. an interface created
// while the posture was active). For ipv4 accept_redirects the kernel
// router default is !ip_forward (inet_forward_change sets
// IPV4_DEVCONF_ALL(ACCEPT_REDIRECTS) = !forwarding); every other knob
// keeps the historical default of 1.
func restoreValueForRedirectKnob(path string) string {
	if isIPv4AcceptRedirects(path) && ipv4ForwardingEnabled() {
		return "0"
	}
	return "1"
}

// restoreRedirectKnobs writes back the captured per-path values. For
// ipv4 accept_redirects paths the restored value is additionally
// capped by the forwarding-dependent router default: when ip_forward
// is 1 a forwarding device accepts redirects only when both all and
// the device are 1, and the kernel sets all = !forwarding, so a
// captured 1 must not be restored above 0 while forwarding stays on
// (#16779). Paths with no captured value fall back to
// restoreValueForRedirectKnob.
func restoreRedirectKnobs() {
	captured := takeCapturedRedirectKnobs()
	forwarding := ipv4ForwardingEnabled()
	for _, path := range redirectKnobPaths() {
		value, ok := captured[path]
		if !ok {
			value = restoreValueForRedirectKnob(path)
		} else if forwarding && isIPv4AcceptRedirects(path) && value == "1" {
			value = "0"
		}
		current, _ := os.ReadFile(path)
		if strings.TrimSpace(string(current)) == value {
			continue
		}
		if err := os.WriteFile(path, []byte(value+"\n"), 0644); err != nil {
			slog.Warn("failed to restore ICMP redirects", "path", path, "value", value, "err", err)
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
// transition restore the values captured on activation exactly once
// (#15710, #16779). The previous constant-1 restore was not a restore
// at all: with ip_forward=1 the kernel router default for
// ipv4/conf/all/accept_redirects is 0 (inet_forward_change sets it to
// !forwarding), so writing 1 enabled spoofed on-link redirects for
// the firewall's own traffic and clobbered foreign sysctl.d hardening.
// Deleting `system no-redirects` therefore restores the captured
// per-path values (ipv4 accept_redirects capped at !ip_forward)
// instead of a constant 1.
func reconcileNoRedirects(active bool) {
	wasActive := noRedirectsActive.Swap(active)
	switch {
	case active:
		if !wasActive {
			captureRedirectKnobs()
		}
		writeRedirectKnobs("0")
	case wasActive:
		restoreRedirectKnobs()
	}
}
