# Plan — #5177 NAT64 embedded ICMP-error L4 port/identifier restoration

**Revision:** r1 (draft)
**Base SHA:** `4e0c7f74c` (origin/master at research start)
**Issue:** #5177 — "userspace-dp NAT64: reverse ICMP-error translation leaves
the translated PAT port/ICMP-id in the embedded quote instead of the original
client value."
**Scope:** research-only. Stops at PLAN-READY / PLAN-KILL. No production code
in this branch — plan doc + reviewer verdicts only.

---

## 1. Status

- [x] Defect verified against current origin/master (`4e0c7f74c`).
- [x] Blast radius quantified (call chain, available state, offsets, bounds).
- [x] Design options enumerated (A / A′ / C).
- [ ] Reverse-path reachability trace (delegated; see §3 Q1 — pending, updates
      the value framing, not the design).
- [ ] Codex + AGY + Claude-SMR converge PLAN-READY or PLAN-KILL.

---

## 2. Issue framing (the defect, verified)

`translate_embedded_v4_to_v6` (`userspace-dp/src/nat64.rs:2448-2501`) and its
twin `translate_embedded_v6_to_v4` (`nat64.rs:2363-2443`) translate the quoted
(embedded) original packet of a NAT64 ICMP error. They correctly restore the
embedded **IPv6/IPv4 addresses** from the pre-resolved map
(`EmbeddedV4ToV6.mapped_embedded_src` / `.prefix_bytes`,
`EmbeddedV6ToV4.mapped_embedded_src` / `.mapped_embedded_dst`) but copy the
quoted **L4 bytes verbatim**:

```rust
// translate_embedded_v4_to_v6, nat64.rs:2492
out[40..total].copy_from_slice(l4);
// ...then only an embedded ICMP *type/code* remap (nat64.rs:2494-2499):
if protocol == PROTO_ICMP && l4_len >= 2 {
    if let Some((t, c)) = embedded_icmpv4_type_to_icmpv6(out[40]) { out[40]=t; out[41]=c; }
}
```

There is **no** TCP/UDP source-port rewrite and **no** ICMP echo-Identifier
rewrite. After #4381 introduced stateful PAT (RFC 6146 BIB), the embedded
source port carried in the quote is the **translated pool port** (e.g. 40000),
not the **original client port** (e.g. 12345). Likewise for an ICMP echo flow
the embedded Identifier is the translated pool identifier, not the client's.

RFC 6146 §3.5 / RFC 792: an ICMP error delivered to the inside host must quote
the tuple the inside host **originally emitted** so the host can correlate the
error to its socket. With the pool port in the quote the inside host cannot
match the error to its flow — PMTUD black-holes (TCP path-MTU errors are keyed
on the quoted ports in the Linux/BSD stacks) and NAT64 traceroute breaks.

**Confirmed by the existing test that enshrines the bug.**
`nat64_v4_to_v6_time_exceeded_translates_outer_and_embedded`
(`nat64_tests.rs:1873`) builds an embedded quote with L4
`[0x30,0x39,0x00,0x50,...]` (src port `0x3039`=12345, dst port `0x0050`=80),
translates via `translate_v4_to_v6(&v4_pkt, server_v6, client_v6)` — which
passes **addresses only, no port** — and asserts:

```rust
assert_eq!(&emb[40..48], &inner_l4, "embedded quoted L4 preserved");   // nat64_tests.rs:1928
```

i.e. the test asserts the embedded L4 (including the source port) is preserved
byte-for-byte. In a #4381 deployment that `0x3039` would be the pool port, and
the correct post-fix value is the original client port. **This test must be
updated by the fix** — its "verbatim" expectation is exactly the defect.

---

## 3. Honest scope + value framing

This is a **slow-path correctness** fix on the NAT64 ICMP-error branch. It is
NOT on the throughput fast path (no per-packet cost for TCP/UDP data). Its
value is real but bounded to two operationally-important cases:

- **TCP PMTUD through NAT64.** A "Fragmentation Needed / Packet Too Big" from a
  v4 hop must reach the v6 client's socket. Linux `tcp_v4_err`/`tcp_v6_err`
  look up the socket from the **embedded ports**; a wrong embedded source port
  means the PMTU update is dropped and the flow black-holes at the reduced MTU.
- **NAT64 traceroute / UDP error correlation.** `traceroute`, `ping`, and UDP
  apps correlate Time-Exceeded/Dest-Unreachable to the probe via the embedded
  port / ICMP identifier.

**PLAN-KILL is an acceptable, honest outcome if the win is too small.** Two
kill conditions to weigh against the evidence:

1. If the reverse NAT64 ICMP-error path is **currently unreachable** in
   production (delegated trace Q1 below) AND the forward direction is likewise
   never exercised, the fix is defense-in-depth on latent code — still arguably
   worth doing for correctness-in-depth and to un-enshrine the buggy test, but
   the operational win is deferred until the path is wired. This weakens (not
   necessarily kills) the case.
2. If real inside hosts do NOT parse the embedded L4 port to correlate errors
   (they don't — kernels DO), the fix is cosmetic. Evidence says kernels DO
   parse the embedded ports, so this kill condition does **not** hold.

The plan argues the fix is correct and cheap; the reviewers must decide whether
the operational reachability (Q1) is strong enough to ship now or defer.

### Blast-radius questions (answered)

**Q1 — Does the map struct already carry the original client L4 port / ICMP-id,
or only the address?**
Only the address. `EmbeddedV4ToV6` (`nat64.rs:2144-2149`) carries
`mapped_embedded_src: Ipv6Addr` + `prefix_bytes: [u8;12]`. `EmbeddedV6ToV4`
(`nat64.rs:2132-2137`) carries `mapped_embedded_src`/`mapped_embedded_dst`
(both `Ipv4Addr`). Neither carries any L4 port or identifier. Likewise
`Nat64ReverseInfo` (`nat64.rs:255-259`) carries only `orig_src_v6` /
`orig_dst_v6` — **no ports**. So the port datum must be sourced elsewhere and
plumbed in.

**Q2 — At the caller, is the original client tuple available, or must a new
reverse lookup be plumbed?**
It is **already available on `decision.nat`** at the frame-builder call site;
no new reverse lookup is required. The NAT64 whole-packet translator is reached
via `build_nat64_forwarded_frame` (`afxdp/frame/mod.rs:232`), which receives
`decision: &SessionDecision` and already reads `decision.nat` for the **outer**
port rewrite (`apply_nat64_port_translation`, `frame/mod.rs:286` and `:330`).
The relevant field per direction:

- **Reverse (AF_INET outer, v4→v6):** `decision.nat` is the reverse decision
  (`NatDecision::reverse`, `nat/mod.rs:106-121`), where
  `rewrite_dst_port == original_src_port` = the **original client port/id**.
  The embedded quote is our forward packet, so its **source** port carries the
  pool value and must be restored to `rewrite_dst_port`.
- **Forward (AF_INET6 outer, v6→v4):** `decision.nat` is the forward decision,
  where `rewrite_src_port` = the **translated pool port/id**. The embedded
  quote is the return packet, so its **destination** port carries the original
  client value and must be rewritten to `rewrite_src_port` (so the outside
  server correlates the error to the translated flow it knows).

The ICMP echo identifier rides the **same** `rewrite_*_port` fields — see
`apply_nat_icmp_identifier_rewrite` (`frame/mod.rs:1208`,
`nat.rewrite_src_port.or(nat.rewrite_dst_port)`). So a single `u16` per
direction suffices for TCP-port, UDP-port, and ICMP-id.

> ⚠️ Load-bearing claim under active verification (delegated trace): that a
> *reverse* NAT64 ICMP **error** actually reaches `build_nat64_forwarded_frame`
> with `nat.nat64==true` and `rewrite_dst_port` set — rather than being
> diverted into the **same-family** `icmp_embed` path
> (`try_embedded_icmp_nat_match` → `build_nat_reversed_icmp_error_v4/v6`,
> `poll_descriptor/mod.rs:2454-2506`), which is v4→v4 / v6→v6 only and cannot
> perform a cross-family NAT64 reversal. §7 and Q1 in §11 track this. If the
> reverse path is same-family-diverted, the design shifts (the fix would move
> into the `icmp_embed` builders, or that path must delegate NAT64 to the
> whole-packet translator). The forward v6→v4 direction is unaffected by this
> uncertainty.

**Q3 — Checksum policy: leave the embedded L4 checksum as-is, or update it?**
**Leave as-is** (recommended). Rationale:
- The shipped translator **already** rewrites the embedded IP addresses without
  touching the embedded L4 checksum (`nat64.rs:2429-2432` comment: "the quoted
  L4 checksum is left as-is — it is not validated by a receiver"). The embedded
  L4 checksum is therefore **already stale** w.r.t. the address rewrite in
  production today; adding a port rewrite does not introduce a *new* class of
  staleness.
- Receivers do not validate the embedded transport checksum. Linux
  (`tcp_v4_err`, `__udp4_lib_err`, `ping_err`) and BSD match ICMP errors to
  sockets on the embedded addresses + ports (+ ICMP id), never by recomputing
  the quoted transport checksum. RFC 792/1122/6146 impose no such requirement.
- For TCP the embedded checksum field (TCP header offset 16-17) is typically
  **not even present** in the quote (quotes are commonly 8 bytes of L4), so an
  incremental in-quote fix is impossible for the dominant case anyway.
- The **outer** ICMP checksum DOES cover the rewritten embedded bytes and IS
  recomputed: v6→v4 via `finalize_icmpv4_checksum(out)`
  (`write_icmpv4_error_with_embedded`, `nat64.rs:2325`); v4→v6 via the caller's
  `recompute_l4_checksum_after_nat64_v4_to_v6` over the whole ICMPv6 message.
  Placing the embedded port rewrite **inside** `translate_embedded_*` (Option
  A), i.e. *before* the outer checksum is finalized, keeps the outer checksum
  correct automatically. This is a decisive reason to prefer Option A over a
  post-frame-build step (Option C), which would additionally have to re-fold
  the outer ICMP checksum for the port delta.

**Q4 — The three L4 cases × two directions, with byte offsets and bounds.**
Field layout in the translated embedded output (`out`):

| Direction | Embedded fam | L4 start | TCP/UDP field to rewrite | ICMP-id field |
|-----------|--------------|----------|--------------------------|---------------|
| Reverse v4→v6 | IPv6 | `out[40..]` | **src** port `out[40..42]` (need `l4_len≥2`) | `out[44..46]` (need `l4_len≥6`) |
| Forward v6→v4 | IPv4 | `out[20..]` | **dst** port `out[22..24]` (need `l4_len≥4`) | `out[24..26]` (need `l4_len≥6`) |

- Reverse rewrites **source** port (embedded = forward packet: PAT'd source).
- Forward rewrites **destination** port (embedded = return packet: PAT'd dest).
- ICMP-id lives at L4-offset `+4` in both families (after type/code/checksum),
  and is rewritten only for identifier-bearing echo types (mirror the
  `embedded_icmpv{4,6}_type_to_icmpv{6,4}` echo gate already present, and
  `icmp_identifier_bearing` in the outer helper).
- **Every rewrite is gated on `l4_len ≥ field_end` and uses slice-bounded
  writes** (`out.get_mut(a..b)?` / an explicit `if l4_len >= N` guard), a safe
  no-op on a truncated/hostile quote — never a panic or OOB index. This mirrors
  the existing `if ... l4_len >= 2` guard on the type/code remap.

**Q5 — PLAN-KILL viability.** See §3 opening. The port-parsing-by-receivers
kill condition is refuted by kernel behavior. The residual kill lever is Q1
reachability; argued either way for the reviewers.

---

## 4. What's already shipped (compose, do not re-litigate)

- **#2371 — embedded checksum.** Already handles the embedded/outer checksum
  interplay; this fix does not touch the outer-checksum recompute or re-open
  #2371. The embedded-L4-checksum "leave-as-is" policy (Q3) is consistent with
  #2371's disposition.
- **#4381 — stateful NAT64 PAT (RFC 6146 BIB).** Allocates the unique
  `(pool v4, translated port/id)` and rewrites the **outer** L4 on both
  directions via `apply_nat64_port_translation`. This fix is the **embedded**
  (quoted) analog of that outer rewrite. `rewrite_src_port` / `rewrite_dst_port`
  on `NatDecision` are the exact datums #4381 populated; we reuse them.
- **#4512 / #4565 — HA reverse-BIB sync.** The translated port already rides
  `NatDecision` (synced) and the standby rebuilds `nat64=true` +
  `rewrite_src=snat_v4`. **No new synced state** is introduced by this fix — it
  is a pure translation change reading state that already exists and already
  syncs. (Confirmed: the fix touches no wire field; see §6/§7.)

---

## 5. Concrete design

### Recommended: Option A — thread a per-direction `Option<u16>` into the
embedded translator; apply before the outer-checksum finalize.

Add one `Option<u16>` "embedded L4 rewrite value" parameter, carrying the
port/identifier to stamp into the embedded quote, threaded down the existing
NAT64 whole-packet call chain:

1. **`build_nat64_forwarded_frame`** (`afxdp/frame/mod.rs:232`): in each arm,
   compute the embedded rewrite value from `decision.nat`:
   - AF_INET6 (forward v6→v4): `let emb_l4 = decision.nat.rewrite_src_port;`
   - AF_INET (reverse v4→v6): `let emb_l4 = decision.nat.rewrite_dst_port;`
   Pass `emb_l4` into the frame builder. (These are the same fields already
   read for the outer rewrite, so no new lookup and no new state.)
2. **`build_nat64_v6_to_v4_frame`** (`nat64.rs:3000`) /
   **`build_nat64_v4_to_v6_frame`** (`nat64.rs:3034`): add
   `embedded_l4_rewrite: Option<u16>`; forward it into `write_v6_to_v4_into` /
   `write_v4_to_v6_into`.
3. **`write_v6_to_v4_into`** (`nat64.rs:1583`) /
   **`write_v4_to_v6_into`** (`nat64.rs:1811`): add the param; when the outer
   is an ICMP error it flows into the `EmbeddedV6ToV4`/`EmbeddedV4ToV6`
   construction (or directly into the `translate_embedded_*` call). Non-ICMP
   outer packets ignore it (no embedded translation happens). `None` ⇒
   bit-identical to today.
4. **`EmbeddedV6ToV4` / `EmbeddedV4ToV6`** (`nat64.rs:2132` / `:2144`): add
   `embedded_l4_rewrite: Option<u16>`.
5. **`translate_embedded_v6_to_v4`** (`nat64.rs:2363`) /
   **`translate_embedded_v4_to_v6`** (`nat64.rs:2448`): after the existing
   type/code remap, apply the rewrite at the per-direction offset (§3 Q4 table)
   with `l4_len` bounds gates. For TCP/UDP write the port; for ICMP echo write
   the identifier at `+4`. Leave the embedded L4 checksum untouched (Q3). This
   is **before** `finalize_icmpv4_checksum` / the caller's v6 recompute, so the
   outer ICMP checksum ends correct.

**Why A:** the offset/bounds logic lives in exactly one place
(`translate_embedded_*`) that already knows the embedded layout — no
re-derivation. Outer-checksum correctness is automatic (rewrite precedes
finalize). The value is sourced from the decision already in hand.

**Cost:** four signatures gain one `Option<u16>` param, two structs gain one
field. Test wrappers `translate_v4_to_v6`/`translate_v6_to_v4`
(`nat64.rs:1786`/`:1260`) and the `write_*_into` unit tests gain the param
(pass `None` where the case is address-only; pass the port for the new tests).

### Variant A′ — same as A but bundle `{value: Option<u16>, is_icmp_id: bool}`
into a tiny `EmbeddedL4Rewrite` struct instead of a bare `Option<u16>`. Same
behavior; marginally clearer at the signature boundary. Optional.

### Alternative: Option C — post-frame-build rewrite in
`build_nat64_forwarded_frame`.
After the frame is built, locate the embedded L4 in the **output** frame
(outer eth + outer L3 + outer ICMP(8) + embedded L3) and stamp the port there,
mirroring how the **outer** port is already post-rewritten via
`apply_nat64_port_translation`. **Rejected as primary** because:
- It re-derives the embedded L4 offset that `translate_embedded_*` already
  computes (drift risk, and the offset depends on embedded IHL / v6 ext-header
  stripping already resolved inside the translator).
- It runs **after** the outer ICMP checksum is finalized, so it must
  additionally incrementally re-fold the outer checksum for the port delta —
  more code, more failure surface, exactly the interplay #2371 already got
  right and we'd be re-implementing.
Keep C documented as the lower-signature-churn fallback if reviewers object to
touching `translate_embedded_*` signatures.

---

## 6. API preservation

- No gRPC / wire / HA-sync surface changes. `NatDecision` shape is unchanged
  (we only *read* `rewrite_src_port`/`rewrite_dst_port`, already synced).
- `Nat64ReverseInfo` **need not** grow a port field under Option A (the port is
  read from `decision.nat`, not from the reverse-info struct). If the delegated
  trace shows the reverse path lacks `decision.nat.rewrite_dst_port` at the call
  site, the fallback is to add `orig_src_port: u16` to `Nat64ReverseInfo` — but
  that struct is `#[derive(PartialEq,Eq)]` and compared in session-equality
  (`session/entry.rs:141`); adding a field is safe (still not wire-serialized —
  `ha.rs`/`flow_cache.rs` set it locally), but is only taken if Q1 forces it.
- The public function `translate_v4_to_v6`/`translate_v6_to_v4` are
  `#[cfg(test)]`-only wrappers — signature growth affects tests only, not
  production ABI.

---

## 7. Hidden invariants / gotchas

1. **No panic on a truncated quote.** Every embedded-port/id write is gated on
   `l4_len`. RFC says an error quotes ≥ IP header + 8 L4 bytes (covers both
   TCP/UDP ports and the ICMP id), but a hostile/clamped quote can be shorter —
   the rewrite must be a safe no-op then, never OOB. Mirror the existing
   `l4_len >= 2` type/code gate. Add `l4_len >= 4` (dst port) / `>= 6` (id).
2. **Embedded L4 checksum left stale — deliberately (Q3).** Do not attempt a
   full recompute (payload absent); do not partially update (inconsistent with
   the already-stale address rewrite). Document the RFC/kernel basis in the
   code comment, extending the existing `nat64.rs:2429-2432` note.
3. **Outer ICMP checksum must still cover the rewrite.** Option A guarantees
   this by ordering (rewrite before finalize). Any reviewer pushing Option C
   must confirm the outer re-fold.
4. **Direction picks the field.** Reverse rewrites embedded **source** port;
   forward rewrites embedded **dest** port. Getting this backwards silently
   corrupts the quote. The `NatDecision::reverse` swap
   (`rewrite_dst_port ↔ rewrite_src_port`) is the SSOT — reverse decision's
   `rewrite_dst_port` is the original client value; forward decision's
   `rewrite_src_port` is the pool value.
5. **ICMP-id only for identifier-bearing echo types.** Reuse the echo gate
   already in `embedded_icmpv{4,6}_type_to_icmpv{6,4}`; do not stamp an id onto
   a non-echo embedded ICMP (its bytes 4-5 are not an identifier).
6. **`None` is the identity.** For non-error outer packets, or a NAT64 flow with
   no port allocation, `Option<u16> = None` ⇒ byte-identical to today. Under
   #4381 every TCP/UDP/ICMP-echo NAT64 flow has a port/id allocated, so `Some`
   is the norm for the error path.
7. **Scratch buffer, no aliasing.** The embedded is built in the fixed stack
   `scratch [u8; MAX_EMBEDDED_LEN]` (`nat64.rs:2315`/`:2341`) then copied into
   the frame; the rewrite mutates `out` (the scratch/dest) in place — no
   overlap with the read-only `l4` input slice.
8. **Reverse-path reachability (Q1).** See §3 warning + §11 Q1. The design as
   written assumes the reverse error reaches the whole-packet translator; the
   trace confirms or redirects. The forward direction is unconditionally
   through `build_nat64_forwarded_frame`.

---

## 8. Risk table

| # | Risk | Likelihood | Impact | Mitigation |
|---|------|-----------|--------|------------|
| R1 | Reverse NAT64 ICMP error is same-family-diverted (never hits whole-packet translator) → fix inert for the dominant direction | Medium (under trace) | High to value | Delegated trace Q1; if confirmed, relocate fix into `icmp_embed` builders or delegate nat64 from that path. Forward dir still fixed. |
| R2 | Wrong field per direction (src vs dst) corrupts the quote | Low | High | SSOT via `NatDecision::reverse`; direction-specific unit tests both ways. |
| R3 | OOB/panic on truncated quote | Low | High (DoS) | `l4_len` gates + slice-bounded writes; fuzz-style truncated-quote test. |
| R4 | Outer ICMP checksum invalidated | Low | Medium | Option A orders rewrite before finalize; checksum-oracle asserts in tests. |
| R5 | Embedded L4 checksum staleness rejected by some receiver | Very low | Low | Kernels don't validate; already stale for addresses; documented policy. |
| R6 | Signature churn breaks callers/tests | Low | Low | Compiler-enforced; `None` at address-only call sites. |
| R7 | HA divergence (standby computes different embedded port) | Very low | Medium | No new state; both nodes read the same synced `NatDecision`. |

---

## 9. Test plan

**Gate:** full `cargo test --release` (binary crate — use `cargo test <name>`,
never `--lib`). Rust leg also runs under `make test` (#4006). Build/test env:
`TMPDIR=/dev/shm CARGO_TARGET_DIR=/dev/shm/cargo-5177 cargo test --release`.

**iperf smoke is IRRELEVANT** — this is the ICMP-error slow path, not the
throughput fast path, and the loss cluster is shim-ABI-walled. No cluster smoke
required or meaningful.

New fail-on-revert unit tests (in `nat64_tests.rs`), each building an ICMP error
quoting a PAT'd NAT64 flow (embedded carries the **pool** port/id) and asserting
the translated embedded quote carries the **original client** value:

1. **Reverse v4→v6, TCP.** Embedded src port = pool 40000 → assert `emb[40..42]`
   == original client port 12345. (Update/replace the existing
   `nat64_v4_to_v6_time_exceeded_translates_outer_and_embedded` assertion at
   `nat64_tests.rs:1928`, which currently asserts verbatim — the enshrined bug.)
2. **Reverse v4→v6, UDP.** Same, embedded src port restored.
3. **Reverse v4→v6, ICMP echo id.** Embedded quote is an ICMP echo; assert
   `emb[44..46]` (id) == original client id.
4. **Forward v6→v4, TCP.** Embedded dst port = original client 12345 → assert
   `emb[22..24]` == pool 40000. (v6→v4 embedded is IPv4, L4 at out[20..].)
5. **Forward v6→v4, UDP + ICMP id.** Symmetric.
6. **Truncated quote (both directions).** Quote L4 truncated below the field
   offset (e.g. 2 bytes) → translation succeeds, no panic, port left as-is
   (documented no-op). Guards R3.
7. **Outer checksum oracle (both directions).** After the embedded rewrite,
   assert the **outer** ICMP/ICMPv6 checksum still verifies (pseudo-header sum
   == 0 for v6; one's-complement over the message for v4). Guards R4.
8. **`None`/non-error identity.** A normal (non-ICMP) reverse reply with the new
   param wired is byte-identical to pre-fix. Guards R6.

Each of 1–5 must **fail on revert** (drop the rewrite → embedded field stays the
pool/client value the pre-fix code copied verbatim). Where the delegated trace
confirms an end-to-end reachable path, add one integration-level assertion
through `build_nat64_forwarded_frame` (not just the leaf translator) so the
plumbing (decision.nat → frame builder → translator) is exercised, not only the
byte-level function.

---

## 10. Out of scope

- The embedded **L4 checksum** recompute (deliberately left stale — Q3).
- Any change to #2371 (outer/embedded checksum) or #4381 (outer PAT alloc).
- HA wire-protocol / sync fields (none needed — §4).
- Fragmented ICMP (still fail-closed per #2562).
- The NAT64 fast path (TCP/UDP data-plane throughput) — untouched.
- NPTv6 / same-family SNAT/DNAT embedded ICMP (`icmp_embed` module already
  restores the original tuple incl. ports for same-family — this fix is the
  cross-family NAT64 analog only).

---

## 11. Open questions (each invitable to PLAN-KILL)

1. **Reachability (load-bearing).** Does a *reverse* NAT64 ICMP error reach
   `build_nat64_forwarded_frame` with `nat.nat64==true` +
   `rewrite_dst_port` set, or is it diverted into the same-family `icmp_embed`
   path (`poll_descriptor/mod.rs:2454`)? If diverted, is the fix (a) relocated
   into `icmp_embed`'s builders, (b) a delegation of nat64 from that path to the
   whole-packet translator, or (c) is the reverse path currently *unreachable*
   for cross-family — which materially weakens the value and invites PLAN-KILL /
   PLAN-DEFER-until-wired? **[Delegated trace pending — updates this section.]**
2. **Both directions or reverse-only?** The forward v6→v4 error (v6 client
   emitting an ICMPv6 error toward a v4 server) is rare. Fix both (cheap,
   symmetric) or scope to the dominant reverse direction only?
3. **Checksum policy.** Ratify "leave embedded L4 checksum stale" (Q3) vs an
   incremental in-quote update where the checksum field is present (UDP/ICMP).
   Recommendation: leave-as-is (consistent, kernels don't validate). Any
   dissent?
4. **Design option.** A (thread param, recommended) vs A′ (struct) vs C
   (post-build). Confirm A.
5. **`Nat64ReverseInfo` extension.** Keep sourcing the port from `decision.nat`
   (no struct change), or add `orig_src_port` to `Nat64ReverseInfo` for
   locality? Depends on Q1's answer.
6. **Value threshold.** Given the slow-path scope, is PMTUD-through-NAT64 +
   NAT64-traceroute correlation a strong enough operational win to ship now, or
   PLAN-DEFER behind higher-materiality work? (Honest kill lever.)
7. **HA parity test.** Do we need a standby-side assertion that a promoted
   reverse NAT64 session reconstructs the same embedded port, or is the
   "reads-only-synced-state" argument (§4) sufficient without a new HA test?

---

## Appendix — key line references (origin/master `4e0c7f74c`)

- `translate_embedded_v4_to_v6` — `userspace-dp/src/nat64.rs:2448-2501`
- `translate_embedded_v6_to_v4` — `nat64.rs:2363-2443`
- `EmbeddedV4ToV6` / `EmbeddedV6ToV4` — `nat64.rs:2144` / `:2132`
- `Nat64ReverseInfo` — `nat64.rs:255-259`
- `write_v6_to_v4_into` / `write_v4_to_v6_into` — `nat64.rs:1583` / `:1811`
- embedded map construction — `nat64.rs:1714` (v6→v4) / `:1954` (v4→v6)
- `build_nat64_v6_to_v4_frame` / `build_nat64_v4_to_v6_frame` — `nat64.rs:3000` / `:3034`
- `build_nat64_forwarded_frame` — `afxdp/frame/mod.rs:232`
- `apply_nat64_port_translation` — `afxdp/frame/mod.rs:350`
- `NatDecision` + `reverse()` — `nat/mod.rs:91-121`
- `apply_nat_icmp_identifier_rewrite` — `afxdp/frame/mod.rs:1208`
- same-family embedded-ICMP path — `afxdp/icmp_embed/*`, dispatch at
  `poll_descriptor/mod.rs:2454-2506`
- enshrining test — `nat64_tests.rs:1873` (assert at `:1928`)
