package config

import (
	"fmt"
	"sort"
	"strings"
)

// filterLogSyslogNamedTermCap bounds how many terms the #6859 advisory names
// before it summarises the remainder. A filter set can carry hundreds of `then
// log` terms and an unbounded list would push every other commit warning off
// the operator's screen; the count keeps the total honest.
const filterLogSyslogNamedTermCap = 8

// filterLogSyslogRoutingWarnings reports the terms whose filter-log hits STOPPED
// being forwarded to the configured syslog streams (#6859).
//
// In Junos the two filter-log actions name different sinks: `then log` writes
// the local filter-log buffer and `then syslog` sends to the system log. xpf
// compiled both to the same event and fanned every one of them out to every
// syslog client, so a term written as `then log` specifically to keep hits on
// the box was shipped to whatever remote collector was configured. That is now
// corrected, and correcting it silently stops a stream some deployments may
// have built alerting or retention on.
//
// This is the notice that makes the change non-silent. It is deliberately NOT a
// deprecation notice: `then log` is the correct Junos spelling, it is not going
// away, and saying otherwise would send operators to change configs that are
// already right. It states what changed and the one line that restores the old
// destination.
//
// THE PREDICATE HAS TWO TERMS, and the second is what keeps it quiet on boxes
// where nothing changed:
//
//   - at least one term carries `then log` WITHOUT `then syslog` — those are the
//     terms that lost a destination;
//   - AND the config actually installs syslog clients. `security log mode event`
//     writes local files and installs no clients (daemon_system.go clears them),
//     and stream mode with no streams likewise. On either, a `then log` hit was
//     never leaving the box, so nothing changed and a warning would be noise.
//
// Returns nil when either term fails.
func filterLogSyslogRoutingWarnings(cfg *Config) []string {
	if cfg == nil || !configInstallsSyslogClients(cfg) {
		return nil
	}
	affected := filterLogOnlyTermNames(cfg)
	if len(affected) == 0 {
		return nil
	}

	shown := affected
	suffix := ""
	if len(shown) > filterLogSyslogNamedTermCap {
		shown = shown[:filterLogSyslogNamedTermCap]
		suffix = fmt.Sprintf(" (and %d more)", len(affected)-filterLogSyslogNamedTermCap)
	}
	return []string{fmt.Sprintf(
		"firewall filter %s%s: 'then log' no longer forwards to the configured "+
			"syslog stream(s) — Junos sends only 'then syslog' off-box. The hits are "+
			"still recorded locally and visible in 'show security log'. Add "+
			"'then syslog' to a term to keep sending it to the stream(s).",
		strings.Join(shown, ", "), suffix)}
}

// configInstallsSyslogClients reports whether this config causes the event
// reader to hold at least one syslog client — i.e. whether filter-log events
// have anywhere off-box to go.
//
// It mirrors the two early returns in (*Daemon).applySecurityLogConfig: event
// mode installs LOCAL writers and explicitly clears the syslog clients, and
// stream mode with zero streams clears them too. Only stream mode with at least
// one stream installs clients.
func configInstallsSyslogClients(cfg *Config) bool {
	if cfg == nil {
		return false
	}
	if cfg.Security.Log.Mode == "event" {
		return false
	}
	return len(cfg.Security.Log.Streams) > 0
}

// filterLogOnlyTermNames returns the "<filter> term <term>" identities of every
// term carrying `then log` and NOT `then syslog`, sorted for a stable warning.
//
// Both families are walked: a term is affected regardless of whether it lives
// in an inet or inet6 filter, and an inet6-only config would otherwise warn
// about nothing while losing exactly the same stream.
func filterLogOnlyTermNames(cfg *Config) []string {
	if cfg == nil {
		return nil
	}
	var out []string
	collect := func(filters map[string]*FirewallFilter) {
		for filterName, filter := range filters {
			if filter == nil {
				continue
			}
			if filter.memberFBFSource11321 != "" {
				continue
			}
			for _, term := range filter.Terms {
				if term == nil || !term.Log || term.Syslog {
					continue
				}
				out = append(out, fmt.Sprintf("%s term %s", filterName, term.Name))
			}
		}
	}
	collect(cfg.Firewall.FiltersInet)
	collect(cfg.Firewall.FiltersInet6)
	sort.Strings(out)
	return out
}
