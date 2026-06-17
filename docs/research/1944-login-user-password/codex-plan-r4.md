# Codex Hostile Plan Re-Review — #1944 (r4)

Codex task id: `019ed49c-892f-7c53-8a8a-9388403b3189`

## Verdict: PLAN-NEEDS-WORK

Disposition: Major-1 RESOLVED (marker on pwApply success); Major-3 RESOLVED (non-empty checksum); Minor-1/Minor-2 RESOLVED; Nit-1 PARTLY (one anchor remains).

### Major (NEW) — GC bypassed by the empty-login early-return
applySystemLogin @656-659 returns early when `cfg.System.Login == nil || len(Users) == 0`. If GC is placed after this guard, removing ALL users means GC never runs → markers leak → a recreated out-of-band account is later locked (defect-2 re-appears). Fix: GC must run BEFORE the early-return, or restructure the guard. Found independently by AGY (Finding 1, Critical).

### Major (NEW/consistency) — §6 Path C still says "Accept ... DES ..." contradicting §5.5/§7 DES drop
An implementer following §6 re-adds the 13-char-plaintext footgun. Make DES-drop end-to-end consistent.

### Nit — stale anchor daemon_apply.go:912-918 (apply ordering); actual calls @1021/1027.

Verdict: two blockers (GC/early-return; §5.5-vs-§6 DES) + the nit.
