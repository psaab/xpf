#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=test/incus/wire-config-snapshot-lib.sh
source "${SCRIPT_DIR}/wire-config-snapshot-lib.sh"

pass=0
fail=0
check_equal() {
    local label="$1" input="$2" expected="$3" got
    got="$(printf '%s\n' "$input" | wire_snapshot_payload)"
    if [[ "$got" == "$expected" ]]; then
        printf '  PASS  %s\n' "$label"
        pass=$((pass + 1))
    else
        printf '  FAIL  %s (got %q, want %q)\n' "$label" "$got" "$expected"
        fail=$((fail + 1))
    fi
}

brace_input=$(cat <<'EOF'
cli — connected to xpfd (uptime: 2m19s)
Type '?' for help

groups {
    node0 {
        system {
            host-name xpf-userspace-fw0;
        }
    }
}
EOF
)
brace_expected=$(cat <<'EOF'
groups {
    node0 {
        system {
            host-name xpf-userspace-fw0;
        }
    }
}
EOF
)
check_equal "brace output remains a faithful snapshot" "$brace_input" "$brace_expected"

set_input=$(cat <<'EOF'
cli — connected to xpfd (uptime: 2m19s)
Type '?' for help

set security policies default-policy deny-all
set security policies from-zone lan to-zone wan policy allow-all match application any
EOF
)
set_expected=$(cat <<'EOF'
set security policies default-policy deny-all
set security policies from-zone lan to-zone wan policy allow-all match application any
EOF
)
check_equal "set output remains a faithful snapshot" "$set_input" "$set_expected"

printf '  wire-config-snapshot selftest: %d passed, %d failed\n' "$pass" "$fail"
[[ "$fail" -eq 0 && "$pass" -eq 2 ]]
