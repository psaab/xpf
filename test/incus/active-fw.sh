#!/usr/bin/env bash
# Shared active-primary detection for the loss userspace cluster (#13069,
# deep-review D10-14).
#
# Fairness/CoS harnesses used to hardcode loss:xpf-userspace-fw0. Only the
# node holding the active RG forwards traffic (and apply-cos-config.sh must
# run against that primary — config sync replicates the commit to the
# secondary), so a hardcoded target silently applied CoS fixtures and
# sampled dataplane telemetry on the STANDBY whenever fw1 was primary (for
# example after any failover).
#
# Source this file, then call:
#
#     active_fw_detect vm-a vm-b ...
#
# It prints the remote-qualified name of the first candidate whose
# `show chassis cluster data-plane statistics` output reports the local
# data-plane enabled, forwarding, and an rgN (N >= 1) active — the same
# probe cos-be-contention-harness.sh's detect_active_fw uses — and returns
# 0. When no candidate qualifies (incus missing, cluster unreachable, both
# nodes standby) it returns 1 and prints nothing; callers MUST fail closed
# rather than fall back to a hardcoded node.

active_fw_detect() {
    local vm
    local stats

    command -v incus >/dev/null 2>&1 || return 1
    for vm in "$@"; do
        stats="$(incus exec "$vm" -- cli -c 'show chassis cluster data-plane statistics' 2>/dev/null || true)"
        if grep -Eq 'Enabled:[[:space:]]+true' <<<"$stats" &&
            grep -Eq 'Forwarding supported:[[:space:]]+true' <<<"$stats" &&
            grep -Eq 'HA groups:[[:space:]].*rg[1-9][0-9]* active=true' <<<"$stats"; then
            printf '%s\n' "$vm"
            return 0
        fi
    done
    return 1
}
