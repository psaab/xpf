package daemon

import (
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"
)

// Review of #18625: a warm-up that probes nothing looks exactly like the fix
// working (Group 4 reads 0 either way, and the standby gap #18621 keeps
// Group 2 flat). These are the surfaces that tell the two apart: the last
// pass's counts in `show chassis cluster information`, and edge-triggered
// Warns for the two silent no-op causes (an RG this node is primary for whose
// prefix it holds no address, and a probe socket that cannot be bound).

// neighborWarmNotHeldGrace is how long "primary but holding no address in the
// prefix" must persist before it warns. A VIP lands within milliseconds of the
// RG activating, and a pass can run in between; that is not the condition.
const neighborWarmNotHeldGrace = 5 * time.Second

// neighborWarmHealth is the edge state behind those Warns.
type neighborWarmHealth struct {
	mu sync.Mutex
	// notHeldSince: first pass that saw each "rg<N> <ifname> <prefix>".
	notHeldSince  map[string]time.Time
	notHeldWarned map[string]bool
	// bindFailing: "<network> <ifname>" whose last open() failed.
	bindFailing map[string]bool
	// probeTruncated: the last force-probe pass hit its target cap.
	probeTruncated bool
}

// notePrimaryNotHeld applies one pass's primary-not-holding set. It warns once
// per key after the grace and logs the recovery at Debug. Returns the keys it
// warned for (tests).
func (h *neighborWarmHealth) notePrimaryNotHeld(keys []string, now time.Time) []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.notHeldSince == nil {
		h.notHeldSince = make(map[string]time.Time)
		h.notHeldWarned = make(map[string]bool)
	}
	present := make(map[string]bool, len(keys))
	var warned []string
	for _, k := range keys {
		present[k] = true
		since, ok := h.notHeldSince[k]
		if !ok {
			h.notHeldSince[k] = now
			continue
		}
		if !h.notHeldWarned[k] && now.Sub(since) >= neighborWarmNotHeldGrace {
			h.notHeldWarned[k] = true
			warned = append(warned, k)
			slog.Warn("cluster: neighbor warm-up probes nothing on a prefix of an RG this node is primary for: the kernel holds no address in it",
				"prefix", k, "for", now.Sub(since).Round(time.Second).String())
		}
	}
	for k := range h.notHeldSince {
		if present[k] {
			continue
		}
		if h.notHeldWarned[k] {
			slog.Debug("cluster: neighbor warm-up prefix is held again", "prefix", k)
		}
		delete(h.notHeldSince, k)
		delete(h.notHeldWarned, k)
	}
	return warned
}

// noteBind records one probe-socket open outcome. It warns on the first failure
// for a (network, ifname) and logs the recovery at Debug. Returns true when it
// warned (tests).
func (h *neighborWarmHealth) noteBind(network, ifname string, err error) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.bindFailing == nil {
		h.bindFailing = make(map[string]bool)
	}
	key := network + " " + ifname
	if err == nil {
		if h.bindFailing[key] {
			delete(h.bindFailing, key)
			slog.Debug("cluster: neighbor warm-up socket binds again", "network", network, "iface", ifname)
		}
		return false
	}
	if h.bindFailing[key] {
		slog.Debug("cluster: neighbor warmup socket failed", "network", network, "iface", ifname, "err", err)
		return false
	}
	h.bindFailing[key] = true
	slog.Warn("cluster: neighbor warm-up cannot bind its probe socket; that interface is not warmed",
		"network", network, "iface", ifname, "err", err)
	return true
}

// noteProbeTruncation applies one force-probe pass's truncation state: Warn when
// truncation starts, Debug while it continues, Debug when it stops. Returns true
// when it warned (tests).
func (h *neighborWarmHealth) noteProbeTruncation(truncated bool, total, limit int) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	was := h.probeTruncated
	h.probeTruncated = truncated
	switch {
	case truncated && !was:
		slog.Warn("neighbor probe truncated", "total", total, "cap", limit)
		return true
	case truncated:
		slog.Debug("neighbor probe truncated", "total", total, "cap", limit)
	case was:
		slog.Debug("neighbor probe no longer truncated", "total", total, "cap", limit)
	}
	return false
}

// neighborWarmInformation renders the last warm-up pass for
// `show chassis cluster information` (Manager.SetInformationExtraFunc).
func (d *Daemon) neighborWarmInformation() string {
	return formatNeighborWarmInformation(d.lastNeighborWarmCounts.Load(), time.Now())
}

func formatNeighborWarmInformation(c *neighborWarmCounts, now time.Time) string {
	var b strings.Builder
	if c == nil {
		b.WriteString("Neighbor warm-up: no pass yet\n")
		return b.String()
	}
	fmt.Fprintf(&b, "Neighbor warm-up (last pass %s ago):\n", now.Sub(c.at).Round(time.Second))
	fmt.Fprintf(&b, "  Probed: %d IPv4, %d IPv6\n", c.probedV4, c.probedV6)
	fmt.Fprintf(&b, "  Skipped: %d cluster-owned, %d not held, %d routed, %d not unicast\n",
		c.skippedOwned, c.skippedNotHeld, c.skippedRouted, c.skippedNotUnicast)
	fmt.Fprintf(&b, "  Socket bind failures: %d\n", c.bindFailures)
	fmt.Fprintf(&b, "  Primary prefixes not held: %d\n", c.primaryNotHeld)
	return b.String()
}
