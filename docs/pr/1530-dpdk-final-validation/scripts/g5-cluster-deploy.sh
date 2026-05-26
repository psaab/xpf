#!/usr/bin/env bash
#
# G5 pre-flight — build + deploy + readiness gate on the loss
# userspace cluster, then capture status/binary snapshots.
#
# Reproduces the build+deploy pattern from .claude/skills/failover-test/SKILL.md
# and the CoS re-apply step from CLAUDE.md ("deploy wipes CoS").
#
# CALLER must hold cluster access lock via smoke-runner singleton
# ab1c7bcf4d14b36b6 before running this script. Concurrent runs on
# the loss userspace cluster will contend with the singleton.
#
# Writes:
#   artifacts/cluster-deploy.log
#   artifacts/cos-apply-fw0.log
#   artifacts/cos-apply-fw1.log
#   artifacts/cluster-status-fw{0,1}.txt
#   artifacts/node-binary-hashes.txt
#
# Exit 0 only if both nodes reach "Takeover ready: yes" within 60s.

set -uo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)
ART_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/artifacts
mkdir -p "$ART_DIR"

cd "$ROOT_DIR"

ENV_FILE=${ENV_FILE:-test/incus/loss-userspace-cluster.env}
FW0=loss:xpf-userspace-fw0
FW1=loss:xpf-userspace-fw1

# 1. Build Go + Rust binaries.
echo "g5-deploy: building Go daemon + Rust helper"
make build 2>&1 | tee -a "$ART_DIR/cluster-deploy.log"
( cd userspace-dp && cargo build --release ) 2>&1 | tee -a "$ART_DIR/cluster-deploy.log"
cp userspace-dp/target/release/xpf-userspace-dp .

# 2. Rolling deploy via cluster-setup.sh.
echo "g5-deploy: deploying to $FW0 and $FW1"
ENV_FILE="$ENV_FILE" sg incus-admin -c "./test/incus/cluster-setup.sh deploy all" \
    2>&1 | tee -a "$ART_DIR/cluster-deploy.log"

# 3. Re-apply CoS (deploy wipes it).
echo "g5-deploy: re-applying CoS on RG0 primary"
./test/incus/apply-cos-config.sh "$FW0" 2>&1 | tee "$ART_DIR/cos-apply-fw0.log"
./test/incus/apply-cos-config.sh "$FW1" 2>&1 | tee "$ART_DIR/cos-apply-fw1.log" || \
    echo "g5-deploy: NOTE — apply-cos on fw1 may fail if it's the secondary; config sync covers it"

# 4. Readiness gate — both nodes Takeover ready: yes within 60s.
echo "g5-deploy: waiting for both nodes to reach Takeover ready: yes"
READY=0
for i in $(seq 1 12); do
    fw0=$(sg incus-admin -c "incus exec $FW0 -- cli -c 'show chassis cluster status'" 2>&1 | grep -c "Takeover ready: yes")
    fw1=$(sg incus-admin -c "incus exec $FW1 -- cli -c 'show chassis cluster status'" 2>&1 | grep -c "Takeover ready: yes")
    if [[ "$fw0" -ge 3 && "$fw1" -ge 3 ]]; then
        READY=1
        break
    fi
    sleep 5
done

# 5. Snapshot cluster status on both nodes.
sg incus-admin -c "incus exec $FW0 -- cli -c 'show chassis cluster status'" \
    > "$ART_DIR/cluster-status-fw0.txt" 2>&1 || true
sg incus-admin -c "incus exec $FW1 -- cli -c 'show chassis cluster status'" \
    > "$ART_DIR/cluster-status-fw1.txt" 2>&1 || true

# 6. Per-node binary hashes.
: > "$ART_DIR/node-binary-hashes.txt"
for node in xpf-userspace-fw0 xpf-userspace-fw1; do
    sg incus-admin -c "incus exec loss:$node -- sha256sum /usr/local/sbin/xpfd /usr/local/sbin/xpf-userspace-dp" \
        >> "$ART_DIR/node-binary-hashes.txt" 2>&1 || true
done
cat "$ART_DIR/node-binary-hashes.txt"

if [[ "$READY" -ne 1 ]]; then
    echo "g5-deploy: FAIL — cluster not ready after 60s. See cluster-status-fw{0,1}.txt" >&2
    exit 1
fi

echo "g5-deploy: PASS — cluster ready, snapshots captured"
