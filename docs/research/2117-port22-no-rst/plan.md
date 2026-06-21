# Research plan — #2117: port-22 policy-reject emits no TCP RST while other ports RST

- **Issue:** #2117
- **Branch:** `research/2117-port22-no-rst`
- **Revision:** r2 (post round-1 hostile review)
- **Outcome:** **PLAN-KILL — NOT A CODE BUG.** The observed behavior is correct.
  The divergence is fully explained by the *test configuration*, not the #2089
  reject path. No production code change is warranted.

---

## 1. Problem statement (from the issue)

During the 2026-06-20 security-matrix smoke (`docs/smoke/security-matrix-2026-06-20.md`,
standalone 3-zone DUT, master `5fa964c13`), with the untrust→trust policy
`allow-dnat-web(http) + allow-icmp(ping) permit, reject-rest reject` and the
untrust zone carrying `tcp-rst`:

- Inbound TCP to ports **23 / 3389 / 9999 / 8080** → blocked at the DUT (0 arrivals
  at trust-host) **AND** a TCP **RST** returned to the source (the correct #2089
  active-reject).
- Inbound TCP to port **22 (SSH)** → still blocked (0 arrivals) but the source sees
  a **silent timeout — no RST.**

Blocking is correct in every case; only the reject *reply* for port 22 is missing.

## 2. Root cause (established by reading source + the loaded config — NOT speculation)

**The DUT config installs an input firewall filter on the untrust ingress
interface that silently `discard`s TCP destination-port 22 BEFORE the security
policy (and therefore before the #2089 reject path) ever runs.**

Evidence chain, all in `test/incus/xpf-test.conf` (the config loaded for the
security matrix on the standalone DUT):

1. **The untrust interface binds an inet input filter** (`ge-0/0/1` = untrust,
   `10.0.2.10`):
   ```
   interfaces { ge-0/0/1 { unit 0 { family inet {
       address 10.0.2.10/24;
       filter { input dscp-filter; }     # lines 24-25
   } } } }
   ```

2. **`dscp-filter` term `block-ssh` discards TCP/22** (lines 404-413):
   ```
   firewall { family inet { filter dscp-filter {
       term mark-ef    { from { dscp ef; } then accept; }
       term block-ssh  { from { protocol tcp; destination-port 22; }
                         then { log; discard; } }     # <-- silent drop
       term default    { then accept; }
   } } }
   ```

3. **`discard` is a silent drop by design** — `FilterAction::Discard` is
   documented in `userspace-dp/src/filter/mod.rs:31-35` as *"Silently drop the
   packet."* It is NOT `reject`. (Junos parity: filter `discard` is silent;
   filter `reject` would send ICMP — different keyword, not used here.)

4. **The input filter runs BEFORE the security policy in the datapath and
   short-circuits on any non-Accept action.** In
   `userspace-dp/src/afxdp/poll_descriptor/mod.rs`, the new-flow path evaluates
   the input filter at lines 659-677:
   ```rust
   let input_filter_eval = evaluate_non_pbr_input_filter(...);   // L659
   if input_filter_eval.action != crate::filter::FilterAction::Accept {  // L665
       if let Some(cached_log) = input_filter_eval.cached_log { emit_input_filter_log_match(...); }
       binding.scratch.scratch_recycle.push(desc.addr);          // L675 recycle frame
       continue;                                                  // L676 — NEVER reaches policy
   }
   ```
   The security-policy `reject-rest reject` evaluation, and the
   `enqueue_policy_reject_reply` call that synthesizes the RST, live far later
   (≈ line 1758, main new-flow deny site; ≈ line 2416, MissingNeighbor deny
   site). A frame discarded at L676 never gets there.

**Therefore:**
- Port 22 SYN → matches `term block-ssh` → `discard` → silent recycle at L676 →
  **no RST, by design** (a `discard` that emitted a RST would be the bug).
- Ports 23 / 3389 / 9999 / 8080 → no filter term matches → `term default
  { then accept; }` → proceed to the security policy → match `reject-rest reject`
  → `enqueue_policy_reject_reply` → TCP RST. Exactly the observed asymmetry.

This is corroborated by the config grep: the **only** inet-filter `discard` for a
TCP destination port is `destination-port 22` (lines 407→411). 8080 appears only
in NAT/application contexts (lines 341/348), not a discard term; 23/3389/9999 are
not in any filter at all.

## 3. Hypotheses from the issue — each resolved against source

| Hypothesis (from #2117 / the research directive) | Verdict |
|---|---|
| Port 22 / `junos-ssh` matched by a different rule / app-id path that skips the reject-reply enqueue | **PARTIALLY — but at the FILTER layer, not app-id.** The untrust→trust security policy is uniform (`junos-http` permit, `junos-ping` permit, `reject-rest reject application any`); SSH would match `reject-rest` identically to 9999. The real divergence is the **input firewall filter** discarding TCP/22 *before* the policy runs. Not an app-id classification issue. |
| Screen / SYN-flood / SYN-cookie / rate-limit interaction on port 22 | **REFUTED.** The screen stanza (`tcp { land; syn-flood; }`) is port-agnostic; a single `nc -w3` SYN does not cross the syn-flood threshold. If syn-cookie HAD fired, the source would receive a **SYN-ACK challenge**, not silence (`ScreenCheckOutcome::SynCookieChallenge` → `enqueue_syn_cookie_reply` → `continue`, mod.rs:214-226). Observed = silence, not a SYN-ACK. Not the cause. |
| Reject reply TX-budget-dropped / suppressed for this case (vs RST-storm / ICMP-error guards) | **REFUTED.** `enqueue_policy_reject_reply` (reject_reply.rs) and `build_reject_rst_frame` (frame/tcp.rs:352) are entirely **port-agnostic**: a bare SYN to :22 and a bare SYN to :9999 are structurally identical (same flags, same headers), so the builder yields a valid RST for both, and the SYN-cookie-shared TX budget gate behaves identically. The RST-storm guard only suppresses an inbound **RST** (`flags & RST`), not a SYN. Port 22 never reaches this code anyway (item 2.4). Not the cause. |
| Capture-window artifact (port 22 DOES RST on a clean repro) | **REFUTED as the cause, but the deterministic repro in §5 still recommended.** The asymmetry is reproducible and deterministic from the config; it is not a missed-capture artifact. The clean repro in §5 exists to let the operator *confirm the kill* (port 22 silent vs 9999 RST, with the filter present; and port 22 RSTs once the filter term is removed). |

## 4. Why this is correct, not a bug

- A firewall-filter `then discard` is **defined** to silently drop. The whole
  point of `discard` (vs the Junos filter keyword `reject`, vs a security-policy
  `then reject`) is silence. Emitting a RST for a `discard`ed packet would be a
  **Junos-parity regression**, not a fix.
- The #2089 active-reject path is **working correctly** — the same smoke proved
  it live on 4 of 5 ports (23/3389/9999/8080 all RST). #2117 is, ironically, the
  first positive *live* confirmation that #2089's RST synthesis works end-to-end
  on a DUT-isolated standalone VM (the #2089 PR #2098 loss-cluster smoke,
  commit `405bd14be`, could only confirm the reject *match/event*, not the
  reply, because AF_XDP zero-copy TX is tcpdump-invisible there and that HA path
  took a session-creating route rather than the instrumented deny sites).
- The block itself is correct in all cases (0 arrivals at the destination for
  every port, including 22).

## 5. Deterministic repro to confirm the kill (operator-runnable, no code change)

On the standalone 3-zone DUT with `test/incus/xpf-test.conf` loaded, from
untrust-host (10.0.2.102), capture on the **source** with a longer window than a
single short-flow:

```bash
# Terminal 1 on untrust-host: capture both the SYN out and any RST back, 10s.
sudo timeout 10 tcpdump -ni eth0 'tcp and host 10.0.1.102 and (tcp[tcpflags] & (tcp-syn|tcp-rst) != 0)' &

# Terminal 2 on untrust-host: port 22 (filter-discarded) vs port 9999 (policy-reject).
nc -w3 10.0.1.102 22     ; echo "ssh rc=$?"     # expect: hang to timeout, NO RST in capture
nc -w3 10.0.1.102 9999   ; echo "9999 rc=$?"    # expect: immediate refusal, RST in capture
```

Expected (confirms the kill):
- `:22` → no RST line in the capture; nc times out (the `discard` is silent).
- `:9999` → `10.0.1.102.9999 > 10.0.2.102.<sp>: Flags [R.]`; nc returns refused.

Definitive confirmation (proves it's the filter, not the port):
```bash
# On the DUT, remove ONLY the block-ssh term, commit, re-run the :22 nc.
cli> configure
cli# delete firewall family inet filter dscp-filter term block-ssh
cli# commit
# Re-run `nc -w3 10.0.1.102 22` from untrust-host:
#   now port 22 ALSO RSTs (it falls through to term default accept -> reject-rest reject).
# Restore: rollback / re-add the term.
```

If `:22` RSTs after removing `block-ssh`, the root cause is conclusively the
filter discard and #2117 is fully explained with zero code change.

## 6. Recommendation

**PLAN-KILL #2117.** No production source change. Actions:

1. **Close #2117 as "not a bug — working as configured"** with the root-cause
   chain (§2) and the confirm-the-kill repro (§5).
2. **Amend the smoke doc follow-up note** (`docs/smoke/security-matrix-2026-06-20.md`,
   the "Port-22 (SSH) reject emits no RST" caveat, lines 97-100) to record the
   resolution: the untrust input filter `dscp-filter` term `block-ssh` silently
   `discard`s TCP/22 before the security policy, so no RST is by-design correct.
   *(This is a doc/test-artifact note, not production code — but it closes the
   loop so a future smoke run does not re-flag the same expected behavior.)*
3. **Optionally**, if a cleaner future smoke matrix is desired, the test config
   could move `block-ssh` to use `then reject` semantics OR drop the term so the
   security-policy reject is what's exercised on :22 — but that is a *test-config
   choice*, explicitly out of scope for a #2089 code fix.

### Adjacent observation (NOT part of #2117, do not scope-creep)

`FilterAction::Reject` at the *firewall-filter* level
(`userspace-dp/src/filter/mod.rs:36-40`) is currently wired to fail closed as a
**silent drop** ("Callers that cannot synthesize the reject packet must fail
closed as a silent drop"). i.e. a *filter* `then reject` does not yet emit
ICMP/RST the way a *security-policy* `then reject` now does (#2089). That is a
**known, documented #2089 scope boundary** (security-policy reject ≠ filter
reject), not #2117 — the #2117 config uses `discard`, which is *correct* to be
silent regardless. If filter-level active reject is ever wanted, that is a
**separate new feature issue**, not a bug, and not this research.

## 7. Blast radius / risk

Zero. PLAN-KILL ships no code. The only artifact is closing the issue + a
one-paragraph note in a test/smoke doc.

## 8. Multiple path options

Only one viable path: **KILL** (the behavior is correct). The "fix the RST"
alternative is rejected because emitting a RST for a `discard`ed packet is a
Junos-parity regression. The "change the test config" alternative is a
test-hygiene choice, not a code fix, and is listed as optional in §6.

## 9. Validation that would be required IF this were (wrongly) treated as a code fix

N/A — no code. The §5 repro is the validation that the *kill* is correct.

## 10. Files examined (read-only)

- `test/incus/xpf-test.conf` (lines 1-66 interfaces+filter binding, 140-164
  untrust→trust policy, 387-433 screen+firewall filter) — the loaded config.
- `userspace-dp/src/afxdp/poll_descriptor/mod.rs` (199-227 screen/syn-cookie,
  659-677 input-filter short-circuit, 1721-1771 main deny+reject site,
  2280-2455 MissingNeighbor deny+reject site).
- `userspace-dp/src/afxdp/poll_descriptor/reject_reply.rs` (whole file —
  `enqueue_policy_reject_reply`).
- `userspace-dp/src/afxdp/frame/tcp.rs` (333-452 `build_reject_rst_frame`,
  `tcp_segment_consumed_len`, `parse_tcp_reply_source`).
- `userspace-dp/src/filter/mod.rs` (29-41 `FilterAction` incl. Discard/Reject
  semantics).
- `docs/smoke/security-matrix-2026-06-20.md` (case 3 + the port-22 caveat).
- #2089 history: PR #2098, commits `735a4575a`, `666a994b3`, `405bd14be`.

## 11. One-line verdict

**PLAN-KILL.** Port 22 is silently dropped by the test config's input firewall
filter `term block-ssh` (`then discard`) *before* the security policy runs;
`discard` is correctly silent; the #2089 reject path is correct and works for
every port that reaches it. No code change.
