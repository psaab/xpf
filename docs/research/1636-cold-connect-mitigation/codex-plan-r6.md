# Codex plan review — round 6 (#1636)

**Task ID**: task-mpptb9hy-236nc7
**Plan reviewed**: `docs/research/1636-cold-connect-mitigation/plan.md` v6 @ `268fb607243a`

## VERDICT: PLAN-READY

## Findings (verbatim from Codex)

> Findings: none blocking.
>
> 1. Sysctl validation breadth: adequate. Per-dataplane-interface IPv4 + IPv6 plus both defaults resolves my r5 finding. Fail-closed on missing, parse error, or `>250` is the right safety posture.
>
> 2. Per-RG HA architecture: adequate. `WarmItem.rg_id`, enqueue-time owner RG lookup, and pre-fire `HAGroupRuntime::is_forwarding_active(now_secs)` close the multi-RG/global-active hole. Deleted or missing RG resolving to inactive is correct.
>
> 3. OnceLock caching: adequate. Init-time computation plus hot-path `OnceLock` read resolves the cached-once concern. Implementation should ensure init runs before dataplane workers start; the fallback read is fine as a defensive guard.
>
> Minor implementation note: the sysctl pseudocode says "takes max" but returns fixed `800_000_000`; that is fine if max is only for validation/logging, but avoid leaving an unused `max_retrans` or unclear wording in final code.

## Recommendation

proceed to `/engineer 1636` implementation phase.

## Session

Codex session ID: 019e6fcb-5a80-76d3-be1d-444ca065f3b8
