# Claude SMR hostile plan review — #6751 plan v13 (round 13, convergence adjudication)

Reviewer: Claude SMR. Posture: hostile — v13 is my own third iteration
of the alias retreat, driven by Codex r12's proof that the cluster codec
truncates `Flags` to one byte (killing the v12 flag-bit carrier). This
pass attacks the receiver-derived signature itself: is it really
computable from what the receiver decodes, is the collateral really
confined to the genuine self-NAT corner, and does the delete-suppression
set actually close the delete corner. Codex r13 was in flight when this
was written.

## Signature computability, verified from the codec side

The cluster codec decodes the full session key and the full
`SessionValue` — the byte-truncation Codex r12 found is specific to the
`Flags` field; the NAT fields (`NATSrcIP`, `NATSrcPort`, `NATDstIP`,
`NATDstPort`, pkg/dataplane/types.go:44-47) ride the payload (they are
how `NATSrcPort` reaches `daemon_ha_userspace_convert.go:357` today).
The receiver's helper-request construction interprets SNAT/DNAT bits
into NAT fields (manager_ha.go:1648), so `decision.rewrite_src` and
`key.src_ip` are both in hand at the decode boundary. The signature
(`forward ∧ sync-derived ∧ rewrite_src.is_some() ∧
key.src_ip == rewrite_src`) is computable exactly where v13 puts the
hook — after decode, before `bulkRecvV4/V6` insertion
(sync_conn_read.go:109 ordering, Codex r12 minor 4). Verified
implementable.

## Collateral precision, attacked

I tried to find a NAT class beyond (fabric alias, genuine self-NAT) that
matches the signature:

- NAT64: canonical src is the v6 client; `rewrite_src` is the v4 pool
  address — never equal. No match.
- Static 1:1: canonical src is the internal host; `rewrite_src` is the
  external static address — equal only in the degenerate self-NAT
  corner (intended collateral).
- DNAT / direct / no-NAT: `rewrite_src` unset — no match.
- Pool-mode `no-translation`: canonical src is the internal host;
  `rewrite_src` is a pool address — equal only if the internal host
  owns a pool address (the §5.7 overlap class — the validator now
  rejects that config, and the residual window is the same self-NAT
  corner, intended).
- The alias itself (target): canonical alias key src == translation
  target — matches by construction.

Precision confirmed: the collateral is exactly the genuine-self-NAT
corner and nothing else, and that corner's forward path is already
ambiguous at the reverse index (#2387, open, §5.1).

## Delete suppression, attacked

The suppression set (4096-entry per-peer LRU of recently-dropped alias
keys) covers every delete that races the drop within the window. The
uncovered case is an alias delete delayed past the LRU window: by then
the alias's session is long closed; the delete targets a key that (on
the new path) holds no signature-matching row (upserts are dropped) —
the only live occupant could be a direct no-NAT session from the WAN
address (signature-clean, since `rewrite_src` is unset). An alias delete
for THAT key is byte-indistinguishable from the direct session's own
delete — indistinguishable today as well (the alias upsert already
clobbers that row at publish, shared_ops.rs:907). So the residual is
strictly weaker than the shipped behavior: today's publish-time clobber
vs the new path's delayed-delete clobber-that-needs-a-past-window-race.
Strictly safer, no new hazard.

## Remaining stale text check

v13.1 audit: §6 now says NO wire change for the alias discipline and
splits the counters (4 helper-wire + 1 Go-side); §7/§9/§11 rewritten to
the signature design; the sticky-gate and flag-bit text is gone; the
§9 "five counters" count is consistent with the §5.8 header
(4 helper + 1 Go). No leftover `SessFlagForwardWireAlias` references
outside the r12-rationale recap.

## Verdict

**PLAN-READY-WITH-NITS.** No BLOCKER or MAJOR survives. The third
iteration is also the simplest: no carrier, no gate, no flag — the
receiver computes alias-ness from content it already has, and the two
foundations (derived-index redundancy, suppression-set delete safety)
survive their fourth and fifth independent walks. If Codex r13
converges, this is terminal.
