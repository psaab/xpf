#!/usr/bin/env bash
#
# Same-class 1 Gbps wrapper for the mouse-latency tail measurement.
# Routes mice into the SAME CoS class as the elephants by using
# elephant port 5202 and TCP echo port 6202, both mapped to queue 2
# (`iperf-1g`) by the canonical CoS fixture. The default cross-class
# invocation keeps mice on 6200 best-effort via the bare
# test-mouse-latency-matrix.sh wrapper.
#
# The old port-7 override fixture is no longer used; echo listeners
# should run on 6200..6211 so latency probes can use the same class map
# as iperf 5200..5211.
#
# Prerequisites (see docs/pr/929-same-class-harness/plan.md §3.3):
#   - Echo daemon running on 172.16.80.200:6202 (TCP)
#   - apply-cos-config.sh loads the canonical 520x/620x CoS map
#
# CONCURRENCY: this wrapper and the cross-class matrix MUST NOT run
# simultaneously. test-mouse-latency-matrix.sh enforces a flock-based
# mutex; concurrent invocations fail fast.
#
# Usage:
#   ./test/incus/test-mouse-latency-same-class.sh <out_root>
#

set -euo pipefail

exec env \
    ELEPHANT_PORT=5202 \
    MOUSE_PORT=6202 \
    MOUSE_CLASS=iperf-1g \
    SHAPER_BPS=$((1 * 1000 * 1000 * 1000)) \
    "$(dirname "$0")/test-mouse-latency-matrix.sh" "$@"
