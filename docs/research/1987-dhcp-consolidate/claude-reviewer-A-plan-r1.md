# Hostile Claude plan reviewer A — r1, #1987

VERDICT: PLAN-REVISE (correct §2.1 to include the DDNS subsystem ~2836
dhcpserver prod LOC; §2.2 dhcpserver importers 4→9 and total 26→31
sites / 19 files; restate §2.3's "server never touches the wire" as
"server speaks DNS-wire/RFC-2136 via DDNS, relay speaks DHCP-wire —
different protocols, no shared code"; add daemon_ddns.go +
daemon_ddns_test.go to the §6/§8 move/doc lists. After revision, land
terminal state as KILL of the common/ consolidation-as-specified with
Option C in-place dhcp.go split re-filed as the cheap modularity
follow-up. The no-common/ conclusion itself is verified correct and
does NOT flip.)

TOP FINDINGS:
1. [MAJOR] §2.1 omits the entire DDNS subsystem. pkg/dhcpserver is 2836
   prod LOC (8 prod files: ddns.go 633, ddns_rfc2136.go 502,
   ddns_leases.go 378, ddns_hostname.go 215, ddns_state.go 176,
   ddns_dns.go 130, dhcpserver.go 732, test_seams.go), not "701 /
   dhcpserver.go 662 + test_seams." DDNS existed at base 5fa964c13.
2. [MAJOR] §2.3's "server never touches the wire / does not do packet
   formatting at all" is FALSE. ddns_rfc2136.go is a live RFC 2136
   DNS-update backend over github.com/miekg/dns. Conclusion (no dedup)
   survives because it's DNS-wire vs the relay's DHCP-wire — different
   protocols — but the stated reasoning is wrong.
3. [MAJOR] §2.2 importer counts wrong. pkg/dhcpserver has 9 importer
   files, not 4 (missed daemon_ddns.go, daemon_ddns_test.go, etc.).
   Total import lines 31, not 26.
4. [MINOR] §2.1 relay LOC stale: 568/539 claimed; 958/705 actual.
5. [MINOR] §6/§8 lists would break the build if executed as written —
   add daemon_ddns.go + daemon_ddns_test.go. Smallest-first ordering
   relay(3)→server(9)→client(19) stays valid.
6. [VERIFIED-CORRECT] The common/ premise holds: zero inter-package
   imports, two Lease types unrelated, no copy-pasted helpers across
   packages, trigger #2076/PR#2112 merged 2026-06-20 on flat structure,
   #2115 OPEN lab+test-only, monolith rule .rs-scoped, Option C
   zero-importer-churn. Verdict direction sound.
