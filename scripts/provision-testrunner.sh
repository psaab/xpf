#!/bin/bash
# scripts/provision-testrunner.sh -- provision an xpf test-runner VM (#19035).
#
# Tests never run on the workstation; they run in these VMs on the lab hosts
# through scripts/vm-test-run.sh. To create a runner (example: udp):
#
#   incus init images:ubuntu/26.04/cloud udp:xpf-testrunner --vm \
#       --storage default --network incusbr-udp \
#       -c limits.cpu=8 -c limits.memory=32GiB -c limits.cpu.priority=1 \
#       -c security.secureboot=false
#   incus config device set udp:xpf-testrunner root size=150GiB
#   incus start udp:xpf-testrunner
#   incus file push scripts/provision-testrunner.sh udp:xpf-testrunner/root/provision.sh
#   incus exec udp:xpf-testrunner -- bash /root/provision.sh
#
# The low limits.cpu.priority keeps the lab firewall VMs ahead of test load,
# so gate measurements on the same host keep priority. Run inside the VM as root.
set -euo pipefail
systemd-detect-virt --vm -q || { echo "provision-testrunner: refusing to run outside a VM" >&2; exit 2; }
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
echo 'Acquire::Retries "5";' > /etc/apt/apt.conf.d/80-retries
apt-get install -y -qq build-essential clang llvm lld libbpf-dev libxdp-dev libelf-dev zlib1g-dev libzstd-dev \
  pkg-config git make python3 python3-venv iproute2 nftables ethtool tcpdump iperf3 bpftool kmod \
  debhelper devscripts shellcheck jq curl ca-certificates protobuf-compiler rsync sudo util-linux \
  "linux-headers-$(uname -r)" >/dev/null
GO_VER=1.24.9
if ! /usr/local/go/bin/go version 2>/dev/null | grep -q "go$GO_VER"; then
  curl -fsSL "https://go.dev/dl/go${GO_VER}.linux-amd64.tar.gz" -o /tmp/go.tgz
  rm -rf /usr/local/go && tar -C /usr/local -xzf /tmp/go.tgz && rm -f /tmp/go.tgz
fi
ln -sf /usr/local/go/bin/go /usr/local/bin/go; ln -sf /usr/local/go/bin/gofmt /usr/local/bin/gofmt
id runner >/dev/null 2>&1 || useradd -m -s /bin/bash runner
echo 'runner ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/runner
su - runner -c 'command -v rustup >/dev/null 2>&1 || (curl -fsSL https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain 1.98.1 >/dev/null)'
su - runner -c '. ~/.cargo/env; rustup toolchain install 1.98.1 --profile minimal -c rustfmt -c clippy >/dev/null; rustup default 1.98.1 >/dev/null; rustc --version; cargo --version'
mkdir -p /work && chown runner:runner /work
install -d -m 1777 /wtgt
echo "xpf-testrunner: provisioned $(date -u +%FT%TZ)" > /etc/xpf-testrunner
go version
