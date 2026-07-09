# Claude SMR plan-review — #4478 r2 (convergence)

**Verdict: PLAN-KILL (security framing invalid). Converges with Codex r1.**

Codex r1 caught a defect I missed in my own r1 pass and in the original triage:
the crux relies on a kernel `Iptun`/`Ip6tnl` decapper that is **never created in
the userspace dataplane**. I independently verified Codex's finding end-to-end
and it is correct.

## Independent verification of the Codex catch

1. `dataplane.EffectiveType("") == TypeUserspace` (`pkg/dataplane/dataplane.go`
   L69-72). The default IS userspace; ebpf is hard-rejected at commit+runtime.
2. `collectAppliedTunnels` sets `AnchorOnly = (EffectiveType == TypeUserspace)`
   (`pkg/daemon/daemon_run.go` L117) and applies it to EVERY tunnel, all modes,
   at L150 (interface-level) and L160 (unit-level). No per-mode branch.
3. `tunnelManager.Apply`: `if tc.AnchorOnly { applyAnchorLocked(...); continue }`
   (`pkg/routing/tunnel.go` L471-474). `applyAnchorLocked` (L514) creates a
   `netlink.Tuntap` anchor and is documented as "the production userspace-dp
   path." The `Iptun`/`Ip6tnl` constructor (`buildKernelTunnelLink`, the
   `case "ipip"` arm) is only reachable via `applyKernelTunnelLocked`
   (`AnchorOnly=false`) — the legacy/ebpf path.
4. `pkg/daemon/tunnel_anchor_test.go` asserts userspace/default ⇒ anchor mode,
   legacy ebpf ⇒ kernel device.

Consequence: for `mode "ipip"` in production there is NO kernel decapper. An
inbound proto-4 frame (outer dst = local tunnel-source) → shim
`is_local_destination` (`userspace-xdp/src/lib.rs` L621) true →
`cpumap_or_pass` → kernel INPUT → no IPPROTO_IPIP handler → **DROP**.
**Fail-CLOSED**, not fail-open.

## This also invalidates my own r2 "degraded residual" finding

My r2 HI-2 argued a degraded-window residual fail-open. That, too, assumed a
kernel Iptun. With no kernel decapper in EITHER the healthy or degraded state,
inbound proto-4 is dropped throughout. The residual does not exist. My r2 pass
was hostile in the right direction (it pushed for the §9 baseline as a gating
precondition, which would have caught this at /engineer time) but it accepted
the kernel-Iptun premise without checking the `AnchorOnly` short-circuit — the
same miss as the original triage. Codex's static catch is strictly better than
my "prove it at runtime later" gate.

## What remains true and reusable

The shim analysis, the GRE-contrast (anchor + native_gre redirect + re-zone
enforcement), the `UserspaceSessionKey` layout, the proto-4-ports-zero finding,
and the snapshot-plumbing findings are all still correct. They describe how one
would IMPLEMENT IPIP inbound decap as a FEATURE — which is the only real gap
here (IPIP inbound is unimplemented ⇒ silently dropped ⇒ fail-closed). That is
feature-completeness, not a vulnerability, and belongs in a separate feature
issue if desired.

## Disposition

- **#4478 as a security issue: KILL.** The M-1 fail-open is not reachable in the
  supported runtime. Close with the §0 evidence chain; label `plan-kill`.
- **No PR, no code.** Correct outcome for a disproven premise — zero rebase debt.
- **Optional follow-up (NOT auto-filed):** if IPIP inbound decap is a wanted
  feature, file a NEW feature issue; the §5 appendix is the starting design.
- **Severity note:** M-1 is not justified; the correct classification is
  "not-a-vuln (fail-closed) + latent unimplemented feature."

Converged with Codex r1 on PLAN-KILL.
