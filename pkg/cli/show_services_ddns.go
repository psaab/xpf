package cli

import (
	"fmt"
	"sort"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/termsafe"
)

// showServicesDynamicDNS renders the Surface A (router/interface-address) DDNS
// status: the provider catalog, runtime counters, and (detail) the per-scope
// last-published state (#2691 P2).
func (c *CLI) showServicesDynamicDNS(detail bool) error {
	cfg := c.store.ActiveConfig()
	fmt.Println("Dynamic DNS (Surface A — router/interface-address publish):")
	if cfg != nil && cfg.System.Services != nil && cfg.System.Services.DynamicDNS != nil {
		cat := cfg.System.Services.DynamicDNS
		if len(cat.Providers) > 0 {
			fmt.Println("  Providers:")
			names := make([]string, 0, len(cat.Providers))
			for n := range cat.Providers {
				names = append(names, n)
			}
			sort.Strings(names)
			for _, n := range names {
				p := cat.Providers[n]
				backend := p.Backend
				if backend == "" {
					backend = "rfc2136"
				}
				fmt.Printf("    %s: backend=%s update-server=%s", n, backend, p.UpdateServer)
				if p.TSIGKeyName != "" {
					fmt.Printf(" tsig-key=%s (secret redacted)", p.TSIGKeyName)
				}
				fmt.Println()
			}
		}
		if cat.ForcedRefreshSeconds > 0 {
			fmt.Printf("  Forced-refresh: %ds\n", cat.ForcedRefreshSeconds)
		}
		if cat.ErrorBackoffMaxSeconds > 0 {
			fmt.Printf("  Error-backoff-max: %ds\n", cat.ErrorBackoffMaxSeconds)
		}
	} else {
		fmt.Println("  No provider catalog configured")
	}

	if c.surfaceADDNSStatsFn == nil {
		fmt.Println("\n  Runtime counters: unavailable")
		return nil
	}
	st := c.surfaceADDNSStatsFn()
	if st == nil {
		fmt.Println("\n  Runtime counters: unavailable (manager not running)")
		return nil
	}
	if st.Degraded {
		fmt.Printf("\n  ALARM: Surface A DDNS DEGRADED (fail-closed) — %s\n", st.DegradedReason)
		fmt.Println("    Publishing and withdrawals are SUSPENDED until the ownership state is resolved.")
	}
	if st.Orphaned > 0 {
		// #6218 item 16: the orphan count was surfaced ONLY as individual
		// per-scope rows in `detail` mode (State == SurfaceAStateOrphaned in
		// the "Configured scopes:" table below) — an operator running a bare
		// `show services dynamic-dns` (no detail) had no signal that any
		// record needed manual cleanup. Mirror the DHCP-DDNS sibling surface
		// (showDHCPDynamicDNS below), which has always printed its own
		// OrphanedBackendChange alarm unconditionally in the summary.
		fmt.Printf("\n  ALARM: %d record(s) orphaned at a previous provider endpoint —\n", st.Orphaned)
		fmt.Println("    a provider identity change left them stale and un-withdrawable through")
		fmt.Println("    the current catalog; manual cleanup required (see 'detail' for which).")
	}
	fmt.Println("\n  Counters:")
	fmt.Printf("    Publishes: ok=%d fail=%d\n", st.UpsertOK, st.UpsertFail)
	fmt.Printf("    Withdraws: ok=%d fail=%d\n", st.DeleteOK, st.DeleteFail)
	fmt.Printf("    Skipped:   unchanged=%d backoff=%d no-backend=%d\n", st.Skipped, st.BackedOff, st.SkippedNoBackend)
	fmt.Printf("    Published records: %d\n", st.Scopes)
	fmt.Printf("    Orphaned records:  %d\n", st.Orphaned)

	if detail && c.surfaceADDNSStatusFn != nil {
		views := c.surfaceADDNSStatusFn()
		fmt.Println("\n  Configured scopes:")
		if len(views) == 0 {
			fmt.Println("    none")
		} else {
			fmt.Printf("    %-32s %-6s %-15s %-39s %-12s %s\n", "FQDN", "Family", "State", "Address", "Provider", "Last error")
			for _, v := range views {
				fam := "inet"
				if v.Family == 6 {
					fam = "inet6"
				}
				// #6468 D1: LastError can embed a DDNS PROVIDER response body.
				// Cloudflare (backend_cloudflare.go:166) and Route 53
				// (backend_route53.go:195,277) embed the provider's own message with
				// %s, so a hostile or compromised provider can land raw ESC bytes on
				// the operator terminal. The other backends do not: dyndns2 and
				// duckdns wrap the response token in %q, generic OMITS the body
				// entirely (it reports only the configured success tokens), and
				// rfc2136 reports a fixed rcode string. Sanitizing at the display site
				// covers the class regardless of which backend produced the string,
				// and survives a backend changing its format verb.
				lastErr := termsafe.SanitizeForDisplay(v.LastError)
				if lastErr == "" {
					lastErr = "-"
				}
				addr := v.Published
				if addr == "" {
					addr = "-"
				}
				fmt.Printf("    %-32s %-6s %-15s %-39s %-12s %s\n",
					v.FQDN, fam, v.State, addr, v.Provider, lastErr)
			}
		}
	}
	return nil
}

// showDHCPDynamicDNS renders the DHCP dynamic-DNS config summary + runtime
// counters (and, in detail mode, the owned records) for the in-process
// interactive CLI (#1387 inc-2). Counters come from the daemon-injected
// hooks; config comes from the active store.
func (c *CLI) showDHCPDynamicDNS(detail bool) error {
	cfg := c.store.ActiveConfig()
	var ddns *config.DHCPDynamicDNSConfig
	if cfg != nil {
		ddns = cfg.System.DHCPServer.DynamicDNS
	}
	if ddns == nil {
		fmt.Println("DHCP dynamic-DNS: not configured")
		return nil
	}
	fmt.Println("DHCP Dynamic DNS:")
	fmt.Printf("  Enabled:         %t\n", ddns.Enabled)
	if ddns.Backend != "" {
		fmt.Printf("  Backend:         %s\n", ddns.Backend)
	}
	if ddns.Domain != "" {
		fmt.Printf("  Domain:          %s\n", ddns.Domain)
	}
	if ddns.UpdateServer != "" {
		fmt.Printf("  Update server:   %s\n", ddns.UpdateServer)
	}
	if ddns.ConflictPolicy != "" {
		fmt.Printf("  Conflict policy: %s\n", ddns.ConflictPolicy)
	}
	if ddns.TSIGKeyName != "" {
		fmt.Printf("  TSIG key:        %s (secret redacted)\n", ddns.TSIGKeyName)
	}

	if c.ddnsStatsFn == nil {
		fmt.Println("\n  Runtime counters: unavailable")
		return nil
	}
	st := c.ddnsStatsFn()
	if st == nil {
		fmt.Println("\n  Runtime counters: unavailable (manager not running)")
		return nil
	}
	if st.Degraded {
		fmt.Printf("\n  ALARM: DDNS DEGRADED (fail-closed) — %s\n", st.DegradedReason)
		fmt.Println("    Publishing and withdrawals are SUSPENDED until the ownership state is resolved.")
	}
	if st.OrphanedBackendChange > 0 {
		// #5814: an update-server/TSIG-key change was detected while the old
		// endpoint was unreachable in-process, so those records could not be
		// withdrawn from the server that published them. Ownership is retained,
		// but DNS may be stale on the old server until an operator resolves it.
		fmt.Printf("\n  ALARM: %d record(s) pending backend-change cleanup — the update-server\n",
			st.OrphanedBackendChange)
		fmt.Println("    changed while the old endpoint was unreachable; the old server may hold a")
		fmt.Println("    stale record. Ownership is retained (never deleted at the wrong endpoint).")
	}
	fmt.Println("\n  Counters:")
	fmt.Printf("    Upserts:    ok=%d fail=%d\n", st.UpsertOK, st.UpsertFail)
	fmt.Printf("    Deletes:    ok=%d fail=%d\n", st.DeleteOK, st.DeleteFail)
	fmt.Printf("    Reconciles: ok=%d fail=%d\n", st.ReconcileOK, st.ReconcileFail)
	fmt.Printf("    Skipped:    no-name=%d no-backend=%d conflict=%d ptr-notauth=%d\n",
		st.SkippedNoName, st.SkippedNoBackend, st.SkippedConflict, st.SkippedPTRNotAuth)
	fmt.Printf("    PTR deferred: %d total (lifetime), %d pending now\n",
		st.PTRDeferred, st.PTRPendingNow)
	fmt.Printf("    Owned records: %d\n", st.OwnedRecords)
	if !st.LastReconcile.IsZero() {
		fmt.Printf("    Last reconcile: %s (%d leases)\n",
			st.LastReconcile.Format(time.RFC3339), st.LastReconcileN)
	}

	if detail && c.ddnsOwnedRecordsFn != nil {
		recs := c.ddnsOwnedRecordsFn()
		fmt.Println("\n  Owned records:")
		if len(recs) == 0 {
			fmt.Println("    none")
		} else {
			fmt.Printf("    %-32s %-6s %-39s %-26s %s\n", "FQDN", "Type", "Address", "PTR", "Pending")
			for _, r := range recs {
				pending := "-"
				if r.PTRPending {
					pending = "PTR"
				}
				// FQDN is built from the device-supplied DHCP client hostname
				// (option 12) — escape terminal control sequences (#6468).
				fmt.Printf("    %-32s %-6s %-39s %-26s %s\n",
					termsafe.SanitizeForDisplay(r.FQDN), r.ForwardType, r.Address, r.PTRName, pending)
			}
		}
	}
	return nil
}
