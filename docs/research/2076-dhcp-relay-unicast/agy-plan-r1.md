# AGY Adversarial Plan Review r1 (#2076)

Job: `adversarial-review-mqmrcbuw-43r2js` — succeeded 2026-06-20.

## Verdict

**PLAN-NEEDS-REVISION**

## Findings (verbatim summary)

1. **BLOCKER — L2 fd use-after-close race.** Closing the AF_PACKET fd in the
   cancel watcher (the plan's §7.2/§7.3) races with concurrent `Sendto`; a closed
   int fd can be reused by another goroutine's open → raw frames written to the
   wrong resource (CWE-416/407). The fd is TX-only and never blocks a read, so it
   must NOT be in the watcher. Close it with `defer unix.Close(l2FD)` at the end
   of `runRelay` AFTER `wg.Wait()` returns (all writers joined).

2. **MAJOR — Silent drop on malformed frame defeats the fallback.** `Sendto`
   only errors on syscall failure; a bad checksum/byte-order/MAC frame
   `Sendto`-succeeds and is dropped on the wire, so the fallback never fires.
   Mitigation: UDP checksum=0 (legal IPv4) to drop a whole bug class + strict
   per-byte unit assertions on the constructed headers incl. the mandatory IPv4
   header checksum.

3. **MAJOR — Dynamic ifindex/MAC change.** The fd is opened once; if the
   interface flaps / is recreated (dynamic VLAN/tunnel) the cached index/MAC go
   stale → `Sendto` returns ENODEV/ENXIO → permanent broadcast fallback until
   re-Apply. Mitigation: re-resolve/recreate the L2 socket on interface-related
   Sendto errors.

4. **MAJOR — Raw L2 bypasses kernel IP fragmentation.** A large DHCP reply
   (many options / long classless-static-routes) exceeding the egress MTU is
   auto-fragmented by the UDP path today but the raw path can't fragment.
   Mitigation: if the built IP packet exceeds the interface MTU, fall back to the
   UDP socket (kernel fragments) and log.

5. **MAJOR — ciaddr destination gap.** flag0 + yiaddr==0 currently falls to
   broadcast, but for DHCPINFORM/REBINDING the reply should unicast to **ciaddr**
   (ClientIPAddr) over the normal UDP socket (client already has the IP, answers
   ARP). Avoids needless broadcast storms.

6. **MAJOR — Dual-AST compile coverage.** `overrides` as a structured child must
   be parsed from both inline `Keys` and `Children` shapes; cover
   `dual_ast_differential_test.go`.

7. **MINOR — Wrong schema line cite.** Plan cites schema_routing.go:282-285;
   actual dhcp-relay block is at 373-382 (line drift). Update citation.

## Design notes (AGY agreed)
- Option (b) static-ARP rejection fully justified (table churn / resolver
  interference / stale-entry blackholes).
- DHCPv4-only scope correct; DHCPv6 uses link-local unicast/multicast, no
  raw-L2 / broadcast-flag equivalent.
