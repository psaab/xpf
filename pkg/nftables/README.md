# pkg/nftables

Manages nftables rules via the netlink API (no shell-out to `nft`). It
installs the RST-suppression rule (HA failover correctness) AND, since
#6387 PR-2, the host-inbound / lo0 / fence rulesets via netlink — plus
the counter READERS the observability surface scrapes.

## Entry points

### RST suppression (`rst_suppress.go`)
- `InstallRSTSuppression()` — atomically replaces the table in a single
  netlink batch, so there is no gap between old and new rules. Drop rules
  match conntrack-invalid TCP RSTs at raw priority from protected
  addresses. IPv4 additionally requires `socket wildcard 1` (#14949 as
  corrected by #15727 and #16839). IPv6 socketless reset skbs have no
  `skb->sk`, so the socket expression BREAKs; an ordered `socket
  wildcard 0` return rule spares live address-bound sockets before a
  socketless drop rule (#17868). This preserves live-socket RST delivery
  while suppressing no-socket kernel RSTs; tracked RSTs survive.

### Host-inbound / lo0 / fence installer (#6387)
The `Installer` interface (`netlink_installer.go`) is the concrete
injection seam covering every kernel-touching host-inbound / lo0 / fence
operation. Since #6387 PR-3 it is the PRODUCTION path: `pkg/daemon`
(`daemon_nft_netlink.go`) drives it via the `nftInstaller` package var
instead of the exec-`nft` package vars (`nftApplyPayload` /
`nftDeleteTable`, now retained only as the parity-CI ORACLE), so a node
needs the kernel `nf_tables` MODULE but no `nft` BINARY:

- `InstallHostInbound(HostInboundSpec)` — the real host-inbound table
  (#3070/#3333): ct-state / ESP-AH / ICMP-accept + counters / WireGuard,
  per-zone service accepts + default-deny drops, junos-host DENY
  subchains (#4146), the addressed-but-unzoned catch-all (#4420).
- `InstallColdBootFence(FenceSpec)` — the #5644 cold-boot fail-closed
  fence (scope-independent mandatory admits, per-zone WG accepts, and
  address drops; no service accepts).
- `InstallLo0ColdBootFence(FenceSpec)` — the #6476 lo0 cold-boot fail-closed
  fence, preserving established-flow admits while dropping firewall-local
  addresses.
- `InstallGapFence(GapFenceSpec)` — the #5789 additive coverage-gap fence,
  with per-zone WG accepts limited to uncovered addresses.
- `InstallLo0(Lo0FilterSpec)` — the lo0 loopback input filter (#3445/#3392). It returns the number of operator rules it installed, not counting the #16841 zero-hop rule (#18746). A match-nothing filter therefore reads 0, and the daemon's empty-shell guard refuses it.
- `DeleteTable(name)` — idempotent teardown (fail-closed on a real error).

**Other `Installer` operations:**
- **Early-input barrier:** `InstallEarlyInputBarrier()`, `InstallEarlyInputBarrierWithLifelineAdmit(lifelines)`, `RemoveEarlyInputBarrier()`, and `EarlyInputBarrierPresent()` install the pre-networkd host-input guard (optionally preserving lifeline access), remove it at handoff, and read back its presence before link activation.
- **Transit barrier:** `InstallTransitBarrier()`, `InstallArmedTransitFence(spec)`, and `RemoveTransitBarrier()` manage the unarmed or armed forward-hook fence and its provenance-scoped pinholes.
- **IPsec divert:** `InstallIpsecDivert(spec)`, `RemoveIpsecDivert()`, and `VerifyIpsecQuarantineGuard()` manage the two-family diversion and verify the fail-closed quarantine guard.
- **Overlay readback:** `VerifyHostInboundOverlay(overlay)` checks the exact marker and the overlay's DROP rules for a candidate overlay before publication. The overlay must run before every rule that can admit a packet, so the input chain may open only with DROP-only rules — today the #16841 zero-hop-limit local DROP, which leads every host-input chain. `hostInputRuleIsDropOnly` is an allowlist. A head rule may use only `meta`, `payload`, `cmp`, `bitwise`, `byteorder`, `fib`, a `lookup` that writes no register, `counter`, and exactly one DROP verdict. Overlay rules get the same list plus the marker `objref`. Anything else fails the readback, including ACCEPT, jump/goto, return, a verdict map, `queue`, an xt-compat target, `dup`, `tproxy` and any kind added later. google/nftables v0.3.0 silently skips every expression it has no type for (byteorder, rt, socket, dup, tproxy), so `GetRules` alone cannot see them. The readback therefore also dumps the chain's kernel expression names (`readRuleExprNames`) and requires both views to agree rule for rule. All of those reads must see one ruleset. So the whole readback is bracketed by the nf_tables generation (`NFT_MSG_GETGEN`, `readAtStableNftGeneration`). A readback is exactly ONE pass between two generation reads. If a commit lands between them, from xpf or from outside it, that readback fails closed at once. The bracket itself does not log. It returns a `*GenerationChangedError` carrying the commit count, which matches `errors.Is(err, ErrGenerationChanged)`, and each caller labels and levels it (#18746). The overlay readback Warns "host overlay readback: generation changed during readback; failing closed" with the number of commits observed. There are no retries here. Earlier folds retried behind a backoff and a deadline, but every bound they offered rested on an assumed pass time that a measured slow pass broke. A single pass is the only shape whose cost under `applySem` is provable. The readback runs under `applySem`, and the short `applySem` holder `reconcileIpsecHostInputFence` makes at most two readbacks per hold. 2 × the measured-maximum pass (168 ms on the canonical HA config at loadavg ~40) + 100 ms of headroom = 436 ms stays below pkg/daemon's `transferPreActivateLockWait` (500 ms), so a queued HA transfer keeps make-before-break. `TestOverlayReadbackFitsTransferPreActivateWait18721` enforces this. On the commit path a failed readback marks the apply stale (`noteHostInboundApplyFailed`). The installed fence stays in force, and the operator's commit reports the failure. Nothing re-drives that commit, so the stale status clears on the next successful apply, which is usually the operator's re-commit. The IPsec reconcile re-drives on its own 5 ms supervisor tick. xpf's own nftables writes outside `applySem` are event-driven, not periodic: the transit gate's 1 s tick skips the kernel replace when the forward fence is unchanged, and the others are HA transitions, IPsec divert staging and the boot barrier. So a collision needs one of those events to land inside a single pass, tens of milliseconds, while an overlay is being applied. Each pass reads only the sets the overlay rules reference (`hostOverlayReferencedSets`), not every ifname set in the table. Overlay (marked) rules must match the builder's exact template (`hostOverlayRuleFitsTemplate`): iifname scope, optional sdifname scope, optional counter, the marker objref and DROP, and nothing else. A rule with an extra match, a negated scope or a hidden kind is refused. This narrows the same-handle `NLM_F_REPLACE` race, where a rule replaced in place between `GetRules` and the name dump would let a kind-identical ACCEPT pass as the old DROP. The race shrinks to a commit preempted between generation publish and visibility switch (linux v7.0 `net/netfilter/nf_tables_api.c:11028` and `:11033`). The kernel's interrupted-dump check on the rules dump (`cb->seq = nft_base_seq(net)` in `nf_tables_dump_rules`, `:3860`, checked by `nl_dump_check_consistent`, `:3833`) has the same residual. Reaching it needs a root writer outside xpf. Before #18721 the readback required the overlay to be the first rule, so every overlay install failed it once #16841 put the zero-hop DROP first.
- **Table probes:** `TableEnforcing(name)` distinguishes an active input-hook table from an empty shell; `TableDropsInput(name)` additionally verifies that its input hook contains a DROP verdict. Neither counts the #16841 zero-hop-limit DROP, which heads every xpf input chain and says nothing about host-inbound policy (#18746). That rule is recognised only in its EXACT shape (`isZeroHopLimitLocalDropRule`): the full expression sequence, checked against the kernel's expression names and the anonymous set's exact `{ local, anycast }` contents. A near-miss counts as a real rule, so a misread errs toward "not enforcing", which reads as drift and reinstalls. Both probes read the chain twice (the typed decode and the expression-name dump), so the pair is generation-bracketed like the overlay readback, and a commit landing in between returns `ErrGenerationChanged` rather than a verdict. Each caller decides what that means. The kernel-truth recheck stays Current for that pass, logs Debug, and Warns once after three unreadable passes in a row. The boot handoff re-verify and `xpfd input-barrier ensure` re-read up to `GenerationChangeRereads` (3) more times. The handoff runs under `applySem` and re-reads at once (`RereadOnGenerationChange`). `ensure` runs outside the daemon, so nothing serializes it with an apply, and it pauses about 50 ms before each re-read (`RereadOnGenerationChangeAfter`) so the re-reads do not all land inside one multi-table apply. Each one logs when it had to re-read: an Info in the daemon, a line on `ensure`'s stdout (journal identifier `xpf-input-closed`). Neither runs inside the short `reconcileIpsecHostInputFence` hold that the overlay's no-retry budget protects: the handoff runs inside an apply and `ensure` runs outside the daemon. A probe that stays unreadable still fails closed: the handoff refuses and reinstalls the guard, and `ensure` falls through to its install. Do not use `RereadOnGenerationChange` for the overlay readback.

**Kernel cells.** The real-kernel tests in this package enter a private network namespace and SKIP when they cannot create one, so a plain `go test` reads them as passes. `make test-nftables-kernel-lib` (run by `make test` as `test-nftables-kernel`) runs the whole package under `unshare -rn` with `XPF_REQUIRE_NETNS=1`, overrides inherited `GOFLAGS=-run`/`-skip`, and requires all 216 package tests plus all 36 pinned kernel cells to PASS with no SKIP (#18745).

`NewNetlinkInstaller()` returns the production netlink implementation.
Host-inbound, lo0, and fence table replacement uses one atomic `Flush()`
batch per table. A `Flush()` error does not prove rollback: the kernel may
have committed the batch while its ACK was lost (#12128). `replaceTable`
reads back the table against the complete plan and treats an exact match as
success; otherwise it preserves the `Flush()` error, joining any readback
error. Callers must not assume that an error means the previous table remains
untouched.

google/nftables v0.3.0 drops the expressions it cannot type on readback,
including the `byteorder` in the #16841 zero-hop rule. So since #16841 that
comparison could never match, and every lost-ACK recovery reported failure.
`ruleMatchesPlan` (#18746) fixes this. It judges each decoder-dropped planned
expression (`decoderDroppedExprNames`: byteorder, dup, tproxy, socket, rt)
against the kernel's own expression names (`readRuleExprNames`), position by
position. It compares the rest byte for byte with the typed decode. A
dropped expression the kernel does not hold is still a mismatch. The delete-then-recreate is existence-check-first, so an absent
table on cold boot does NOT abort the batch (#12.2). Table names
`xpf_hostinbound` (prio 10) / `xpf_hostinbound_gap` (prio 11) / `xpf_lo0`
(prio 0) and the named counters are unchanged from the exec-`nft` path, so
the readers below and operator `nft list` output are identical.

**Parity CI (regression gate for the production cutover and a security gate).** The netlink build
must be bit-for-bit equivalent to the exec-`nft` oracle or a
dropped/widened/weakened rule is a host-inbound fail-open on the PRIMARY
host path. Three test layers pin this:
- **T1 kernel ruleset-parity** (`pkg/daemon/daemon_nft_netlink_parity_test.go`,
  package `daemon` because it drives the unexported oracle builders):
  renders the oracle `nft -f -` text and the netlink ruleset into ONE
  private netns (self-isolated via `unshare -rn` re-exec so a forked `nft`
  shares it and the host ruleset is never touched), dumps `nft list table`
  of both, normalizes (strip handles, sort set elements, but NEVER reorder
  rules) and DIFFS. It ALSO compares the PER-RULE `iifname` scope read
  byte-for-byte via netlink (`iifnameScopeByRule`) — NOT a global union —
  because google/nftables v0.3.0 renders anonymous string-set elements
  empty in `nft list`, so a scope move/widen between retained ident-RST
  scope and the broad zone deny is invisible to the text diff and a union
  check (#6405). Mutation-
  sensitivity sub-cases (widened daddr, dropped `saddr !=`, weakened
  verdict, dropped unzoned deny, dropped counter, and an iifname
  exemption-widen that preserves the global union) assert the netlink dump
  or per-rule iifname scope DIVERGES from the oracle. A dedicated
  `lo0_unrepresentable_port_fails_closed` sub-case asserts BOTH sides fail
  CLOSED on a port token nft cannot resolve. **Runs where `nft` exists;
  SKIPs with a logged reason otherwise** (no silent caps).
- **T1b golden expr** (`netlink_golden_test.go`): per-construct
  `[]expr.Any` asserted against goldens DERIVED FROM nft-text semantics
  (netfilter constant values), never captured from the builder (the
  equivalence-tautology trap). Runs everywhere (no kernel).
- **Kernel-load + counter-readback** (`netlink_kernel_test.go`): loads the
  construct-complete matrix into a real netns and asserts the named
  `CounterObj`s read back UNCHANGED through the counter readers below.
  Needs `CAP_NET_ADMIN`; SKIPs otherwise.

### Capability probe (`netlink_capability.go`, #6387 §12.5)
- `ProbeNFTablesAvailable()` — functional probe (NOT `/proc/modules`; the
  module may be built-in). Returns the distinct `ErrNFTablesUnavailable`
  when the kernel nf_tables subsystem is absent, so PR-3 raises the CF
  monitor-failure with an explicit reason.
- `IsNFTablesUnavailable(err)` — classifies that distinct signal.
- PR-3 wiring: on a netlink install failure `pkg/daemon` (`tagNftInstallErr`)
  probes and, when the subsystem is unavailable, tags the returned error
  with `ErrNFTablesUnavailable` (one-time distinct operator log + the CF
  monitor-failure reason via `Manager.SetConfigSyncHealth`). The probe NEVER
  downgrades the H7 fail-closed contract — the real install still runs and its
  error still fails the commit closed.

### Counter readers
`ReadLo0Counters` / `ReadHostInboundDenyCounters` /
`ReadHostInboundAcceptCounters` / `ReadHostInboundJunosHostDenyCounters` —
scrape the named counter objects back via netlink for the Prometheus
surface. The installer's `CounterObj`s are read by these unchanged.

`ReadHostInboundDenyCounters` additionally returns a `HostInboundTableState`
(#5719), because an empty row set alone cannot tell three kernel states apart:

| state | `inet xpf_hostinbound` | named counter objects | is a `0` authoritative? |
|---|---|---|---|
| `HostInboundTableAbsent` | absent | — | YES — no enforcement, no denies |
| `HostInboundTableCounterless` | **present, DROPping** | **none** | **NO** — the #5644 cold-boot fence |
| `HostInboundTableCounted` | present | >=1 | YES — including counters that read 0 |

The `Counterless` state is the #5644 M37 cold-boot fail-closed fence, which
`InstallColdBootFence` renders with catch-all DROPs and deliberately NO named
counters (see the invariant note on `buildHostInboundFenceNetlink`): the kernel
can be actively dropping host-bound traffic with nothing to scrape, so the
caller must mark that zero non-authoritative instead of publishing it
(`pkg/api` sets `host_inbound_kernel_denies_unavailable` and bumps
`xpf_counter_read_errors_total`). The discriminator is "the table carries no
named counter OBJECT", not "no DENY counter": a real generation always declares
the three #4759 ICMP/ND accept counters, so a legitimate junos-host
program-only ruleset (which installs no per-zone catch-all DROP, hence no deny
counter) still reads `Counted`. On a non-nil error the state is the zero value
and carries no meaning — check the error first. `classifyHostInboundDenyObjects`
is the pure object-walk seam that makes the present-table half of this testable
without a kernel; `TestFenceTableReadsCounterless` proves all three states
against the real kernel under `CAP_NET_ADMIN`.

## Callers

`pkg/daemon` (`daemon_nft_netlink.go`: production installer/probe wiring and
converters), `cmd/xpfd` (input/transit barrier operations), `pkg/api`
(counter readers), and `pkg/dataplane/userspace` (RST suppression).

## Dependencies

External: `github.com/google/nftables`. Internal: `pkg/config`,
`pkg/appid`, `pkg/dataplane` (DSCP/protocol/service SSOT re-used by the
netlink builders so the only oracle-vs-netlink difference is the
rendering-to-kernel step). It does NOT import `pkg/dataplane/userspace`
(which imports `pkg/nftables` — a cycle); the daemon converter copies
those types into the self-contained spec structs in `netlink_spec.go`.

## Gotchas

- Issue #450: deleting the RST table without immediate atomic recreate
  gives the kernel a window to send RSTs for connections owned by the peer
  during HA failover. The atomic delete+add via `Flush()` is the fix.
- Anonymous INTERVAL sets set `AutoMerge` so overlapping/adjacent CIDR
  members (e.g. a lo0 `{ 10.0.0.0/8, 10.0.1.0/24 }`) merge in-kernel like
  nft rather than EEXIST-failing the install (a false fail-closed).
- ICMP type/code sets MUST use the 1-byte `icmp_type`/`icmp_code`
  datatype; a 2-byte `inet_service` key is a hard kernel EINVAL (lookup
  register width must equal the set key width).
- IPv6 DSCP spans the low nibble of byte 0 and the high nibble of byte 1
  of the v6 header — a 2-byte payload + `Bitwise{0x0fc0}` (§12.3), NOT the
  IPv4-TOS byte.
- **A prefix reaching the TOP of the key space gets a start element and NO
  end (#8597).** An anonymous interval set encodes each member as a start
  key plus an `IntervalEnd` key at the first address the prefix does NOT
  cover. For `0.0.0.0/0`, `::/0` or `128.0.0.0/1` there is no such
  address, and `prefixNext` used to fall back to the UNSPECIFIED address
  — the BOTTOM of the range. Verified by installing the set in a private
  netns and reading it back (the kernel stores exactly what it is sent):

  ```
  {0.0.0.0/0, 10.0.0.0/8}     00000000, 00000000!end, 0a000000, 0b000000!end
    -> the /0 member is a ZERO-WIDTH interval: a term that must match
       everything matches nothing.  Fail-CLOSED.

  {128.0.0.0/1, 10.0.0.0/8}   00000000!end, 0a000000, 0b000000!end, 80000000
    -> the wrapped end sorts to the bottom as an end marker with no start
       before it; 128.0.0.0 is left open to the top anyway.  Fail-OPEN.
  ```

  Two wrong encodings in opposite directions from one fallback. **The
  kernel ACCEPTS both** — `Flush` succeeds either way — so an install
  check cannot see this and the guard reads the elements BACK.
  `prefixNext` now returns `(addr, ok)` and the builder omits the end
  element when `ok` is false, which is the representation for an interval
  running to the end of the range. Dropping the end for prefixes that DO
  have a valid next address would turn every interval open-ended, a total
  fail-open; `TestOrdinaryPrefixesStillGetTheirEnd_8597` is that control.
  `iifname { a, b }` anonymous set stores byte-correct 16-byte NUL-padded keys,
  but google/nftables v0.3.0 does not emit the `NFTA_SET_USERDATA` nft's
  `list` uses to render string-typed anonymous sets, so `nft list` shows
  `{ "", "" }`. The scope is still enforced correctly (verified) — the T1 parity
  test canonicalizes the iifname-set text and compares the decoded element bytes
  PER RULE (`iifnameScopeByRule`), NOT as a global union: a scope move/widen
  between the retained ident-RST scope and the broad zone deny that preserves
  the union is a fail-open a union check misses (#6405).
- lo0 filter ports and DSCP are RESOLVED numerically at build time via the
  same SSOT the compile path uses (`config.ResolveFilterPortRange`,
  `dataplane.DSCPValues`) — the same resolution nft applies to the raw
  token the oracle emits (`ssh` -> 22). A token that cannot be represented
  numerically FAILS the build CLOSED (`parsePortTokens`/`lo0DSCPs` error ->
  `nlPlan.fail` -> the install aborts, prior ruleset retained), mirroring
  the oracle whose raw token `nft -f -` rejects. NEVER drop the predicate
  and widen a port/DSCP-constrained rule to match-all (the #6405 fail-open).
- lo0 filter ADDRESSES take the same posture (#6512): `filterFamilyAddrs`
  returns an error on a token that is neither a valid address nor a valid
  prefix, so the plan fails and the install aborts with the prior ruleset
  retained. Dropping the token per-token installed a NARROWED positive list
  (a `discard` enforcing a smaller set than authored, the rest falling
  through to the implicit accept) or a WIDENED except list — and an except
  list narrowed to EMPTY takes `lo0AddrScope`'s empty-except arm, which
  drops the predicate entirely and makes the direction match every address.
  "Empty" means "match everything" for an except set, so skipping a bad
  entry is never the fix here. Wrong-family literals and the `any`/empty
  placeholders are still dropped — those match the userspace matcher.
  Pinned by `netlink_lo0_addrs_6512_test.go`.
- lo0 filter PROTOCOL and ICMP-TYPE/CODE complete that posture (#6806).
  They were the last two narrowing dimensions still resolved with a
  per-token DROP, and they reach the builder by DIFFERENT channels — which
  is why one fix could not cover both:
  - **protocol** arrives as a RAW string in `Lo0FilterTerm.Protocols`, so
    the builder detects the bad token itself. `lo0Protocols` now returns an
    error instead of warning-and-skipping, exactly like `lo0DSCPs`.
  - **icmp-type / icmp-code** arrive ALREADY RESOLVED as `[]int`, so an
    unresolvable token leaves no trace in the DTO at all and the builder is
    structurally unable to see it. `Lo0FilterTerm.ICMPTypeUnrepresentable`
    / `ICMPCodeUnrepresentable` are the marker channel (populated in
    `toNftLo0Term` from `config.FirewallFilterTerm.UnknownICMPTypes` /
    `UnknownICMPCodes`), named to match the userspace wire fields so the
    two mirrors of one config term grep as one contract.
  Both directions of the old drop were wrong: ALL tokens unresolvable
  emptied the slice, the `len(...) > 0` guard emitted NO predicate, and the
  term matched every protocol / every ICMP type in its scope; SOME
  unresolvable built the rule from a NARROWED subset, so a `discard` term
  stopped denying what it could not resolve. Strict commit rejects these
  tokens, so the live ingress is the tolerant load / peer-sync /
  mixed-version path (#1960) — the one where the userspace mirror hands the
  raw token to the Rust filter compiler, which rejects the whole snapshot
  and keeps its last-good policy. A kernel term that silently widens while
  userspace refuses the same filter is the mode-dependent fail-open.
  Pinned by `netlink_lo0_proto_icmp_6806_test.go` (builder half) and
  `pkg/daemon/lo0_proto_icmp_failclosed_6806_test.go` (reachability, text
  oracle, and the two-renderer agreement).
- **Why plan-failure is the safe direction on lo0, and why one comment says
  otherwise.** #5512 (tcp-flags) and #6804 (flexible-match-range) chose
  PER-TERM fail-closed instead, reasoning that "nft loads the lo0 table
  atomically and a rejected table leaves NO host filter = fail-OPEN". That
  was true when #5512 was written and is not true now: #6476 added the
  cold-boot fail-closed fence, and #6489/#6492 key it on `lo0Enforced` and
  rebuild it from the CURRENT snapshot. So a failed lo0 install today
  either retains a real prior filter (steady state) or installs the fence
  (cold boot) — never nothing. Read that #5512 comment as a historical
  claim, not a live constraint. The per-term shapes remain correct for
  their own reasons (a tcp-flags drop can be scoped to `meta l4proto 6`; a
  flex-match one cannot, so it would be a lockout).
- Table name `xpf_dp_rst`, family `INet` (covers both IPv4 and IPv6 in
  one table — don't split it without rethinking the atomic batch).
