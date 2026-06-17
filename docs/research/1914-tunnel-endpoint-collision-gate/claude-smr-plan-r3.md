# Claude SMR hostile plan review — #1914 r3 (final)

**Reviewer:** Claude (domain SMR + design). HOSTILE final pass.
**Verdict: PLAN-READY.**

r3 corrects the two r2 precision bugs Codex r2 caught (both of which I had
missed in my r2 PLAN-READY — see the self-correction note in
claude-smr-plan-r2.md). The corrections are accurate and verified:

1. **Defect B is document-only, entirely.** Verified live: the applied-group
   config `set groups g interfaces gr-0/0/0 unit 0 tunnel mode gre` + `set
   apply-groups g` + `set interfaces wg29715 unit 0 tunnel mode wireguard`
   false-rejects today (`gr-0/0/0.0`/`wg29715.0` both fold 44687), and r3's
   design keeps view 1 unchanged so it continues to. §3.5-O1/O4, the Path-1
   summary, and §6.4 now state this correctly; §6.4 pins the residual as
   intentional rather than asserting it must NOT reject.
2. **Emitter returns `{Name, *TunnelConfig}`.** §4.1 corrected; the builder
   needs the TunnelConfig for snapshot field population (`tunnels.go:106-129`).

## Final correctness ledger (all verified against code)

- **Recursion-free:** views 2/3 use `compileInterfaces` (gate-free,
  `compiler_interfaces.go:25`, zero gate refs) + a config-pure pre-`usedIDs`
  emitter — never `CompileConfig*`. No stack overflow.
- **Defect A FIXED:** post-expansion views carry concrete `wg78.0`,
  collision with `wg1408.0` (824) detected → commit rejected. Reproduced
  the false-accept on master; the design closes it.
- **HA symmetry PRESERVED:** union V1∪V2∪V3 is a pure function of the
  candidate bytes, with identical per-node-expansion-error→empty-set
  handling on both nodes. Monotone over view 1 (only adds rejects).
- **Frozen fold UNTOUCHED:** `StableTunnelEndpointID` unchanged; no wire /
  HA-sync / renumber impact.
- **SSOT drift killed:** emitter is the one emission truth; differential
  parity test mandated; canonicalization inherited from `compileInterfaces`.
- **Severity split kept:** strict rejects, lenient warns (boots an
  already-active wildcard-collision config).

## Accepted residual (documented, correct trade)

Defect B's incomplete-non-WG phantom false-reject persists for all cases
(main / applied / un-applied group). It is mutually exclusive with the
Defect-A fix under the pre-expansion-union design (narrowing view 1 provably
re-opens a false-ACCEPT — strictly worse). Remediation is the same "rename
one interface" the existing error already prints; the runtime `usedIDs`
`slog.Error` belt is the backstop. Joint probability is negligible
(1/65535 per pair × half-configured non-WG tunnel).

This is the right design call. PLAN-READY.
