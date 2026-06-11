#!/bin/bash
# #1741 opportunistic live ghost watch: queue 11 cohort died at start time.
# Any nonzero queue_id="11" row while no iperf3 runs = wrap-ghost resurrection.
end=$(( $(date +%s) + 95*60 ))
echo "watch start $(date -Is)" > /tmp/xpf-1741-ghost-watch.log
while [ "$(date +%s)" -lt "$end" ]; do
  out=$(flock -w 55 /tmp/xpf-cluster.lock sg incus-admin -c "incus exec loss:xpf-userspace-fw0 -- curl -s --max-time 3 localhost:8080/metrics" 2>/dev/null | grep '^xpf_userspace_cos_active_flow_count' | grep 'queue_id="11"')
  if [ -n "$out" ]; then
    echo "$(date -Is) HIT:" >> /tmp/xpf-1741-ghost-watch.log
    echo "$out" >> /tmp/xpf-1741-ghost-watch.log
  fi
  sleep 1
done
echo "watch end $(date -Is)" >> /tmp/xpf-1741-ghost-watch.log
