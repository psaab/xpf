CLANG ?= clang
GO ?= go
CARGO ?= $(HOME)/.cargo/bin/cargo
BINARY := xpfd
PREFIX ?= /usr/local

# Version info embedded at build time
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
BUILD_TIME ?= $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')
LDFLAGS := -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.buildTime=$(BUILD_TIME)

# eBPF compilation flags
BPF_CFLAGS := -O2 -g -Wall -Werror -target bpf

.PHONY: all generate build build-ctl build-userspace-dp proto install clean test test-connectivity test-failover test-double-failover test-active-active test-stress-failover test-ha-crash test-chained-crash test-private-rg test-restart-connectivity build-dpdk-worker build-dpdk clean-dpdk

all: generate build build-ctl

# Generate Go bindings from eBPF C programs via bpf2go
generate:
	$(GO) generate ./pkg/dataplane/...

# Build the daemon binary
build:
	CGO_ENABLED=0 $(GO) build -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/xpfd

# Build the remote CLI client
build-ctl:
	CGO_ENABLED=0 $(GO) build -o cli ./cmd/cli

# Build the userspace dataplane helper
build-userspace-dp:
	$(CARGO) build --manifest-path userspace-dp/Cargo.toml --release
	install -m 0755 userspace-dp/target/release/xpf-userspace-dp ./xpf-userspace-dp

# Generate protobuf/gRPC code
proto:
	protoc --proto_path=proto/xpf/v1 \
		--go_out=pkg/grpcapi/xpfv1 --go_opt=paths=source_relative \
		--go-grpc_out=pkg/grpcapi/xpfv1 --go-grpc_opt=paths=source_relative \
		proto/xpf/v1/xpf.proto

install: build build-ctl
	install -m 0755 $(BINARY) $(PREFIX)/sbin/$(BINARY)
	install -m 0755 cli $(PREFIX)/bin/cli

test:
	$(GO) test ./...

clean: clean-dpdk
	rm -f $(BINARY) cli xpf-userspace-dp
	rm -f pkg/dataplane/*_bpfel.go pkg/dataplane/*_bpfeb.go
	rm -f pkg/dataplane/*_bpfel.o pkg/dataplane/*_bpfeb.o
	rm -rf userspace-dp/target

# Legacy standalone test environment management (single Incus VM/container).
.PHONY: test-env-init test-vm standalone-test-vm test-ct test-deploy test-ssh test-destroy test-status test-start test-stop test-restart test-logs test-journal

test-env-init:
	./test/incus/setup.sh init

test-vm:
	./test/incus/setup.sh create-vm

standalone-test-vm: test-vm

test-ct:
	./test/incus/setup.sh create-ct

test-deploy: build build-ctl
	./test/incus/setup.sh deploy

test-ssh:
	./test/incus/setup.sh ssh

test-destroy:
	./test/incus/setup.sh destroy

test-status:
	./test/incus/setup.sh status

test-start:
	./test/incus/setup.sh start

test-stop:
	./test/incus/setup.sh stop

test-restart:
	./test/incus/setup.sh restart

test-logs:
	./test/incus/setup.sh logs

test-journal:
	./test/incus/setup.sh journal

# Connectivity tests (standalone + cluster, VRF-aware)
MODE ?= all
PRIVATE_RG_MODE ?= $(if $(filter all,$(MODE)),full,$(MODE))
test-connectivity:
	BPFRX_CLUSTER_ENV=$(CLUSTER_ENV) ./test/incus/test-connectivity.sh $(MODE)

# Cluster failover test (iperf3 through reboot — requires cluster + iperf3 server)
test-failover:
	BPFRX_CLUSTER_ENV=$(CLUSTER_ENV) ./test/incus/test-failover.sh

# Double failover test (crash fw0 → fw1 takes over → fw0 rejoins → crash fw1 → fw0 takes over)
test-double-failover:
	BPFRX_CLUSTER_ENV=$(CLUSTER_ENV) ./test/incus/test-double-failover.sh

# Active/active per-RG failover test (iperf3 through RG split — requires cluster + iperf3 server)
test-active-active:
	BPFRX_CLUSTER_ENV=$(CLUSTER_ENV) ./test/incus/test-active-active.sh

# Rapid failover stress test (repeated failover cycles — requires cluster + iperf3 server)
test-stress-failover:
	BPFRX_CLUSTER_ENV=$(CLUSTER_ENV) ./test/incus/test-stress-failover.sh

# Hard-crash / hung-node HA test (force-stop + daemon stop + multi-cycle — requires cluster + iperf3 server)
test-ha-crash:
	BPFRX_CLUSTER_ENV=$(CLUSTER_ENV) ./test/incus/test-ha-crash.sh

# Chained hard-reset failover test (fw0 crash → fw1 crash → both rejoin — requires cluster + iperf3 server)
test-chained-crash:
	BPFRX_CLUSTER_ENV=$(CLUSTER_ENV) ./test/incus/test-chained-crash.sh

# Private RG election test (enable/disable private-rg-election, verify VRRP behavior)
test-private-rg:
	BPFRX_CLUSTER_ENV=$(CLUSTER_ENV) ./test/incus/test-private-rg.sh $(PRIVATE_RG_MODE)

# Restart connectivity regression test (verify no transient loss during daemon restart — requires cluster + iperf3 server)
test-restart-connectivity:
	BPFRX_CLUSTER_ENV=$(CLUSTER_ENV) ./test/incus/test-restart-connectivity.sh

# Canonical cluster HA test environment (isolated loss userspace cluster).
# Override CLUSTER_ENV= to use cluster-setup.sh local xpf-fw0/xpf-fw1 defaults.
NODE ?= all
ifeq ($(origin CLUSTER_ENV),undefined)
ifeq ($(origin BPFRX_CLUSTER_ENV),undefined)
CLUSTER_ENV := test/incus/loss-userspace-cluster.env
else
CLUSTER_ENV := $(BPFRX_CLUSTER_ENV)
endif
endif
LOSS_CLUSTER_ENV ?= test/incus/loss-cluster.env
CLUSTER_SETUP = BPFRX_CLUSTER_ENV=$(CLUSTER_ENV) ./test/incus/cluster-setup.sh
LOSS_CLUSTER_SETUP = BPFRX_CLUSTER_ENV=$(LOSS_CLUSTER_ENV) ./test/incus/cluster-setup.sh
.PHONY: cluster-init cluster-create cluster-deploy cluster-destroy cluster-status cluster-ssh cluster-logs cluster-start cluster-stop cluster-restart
.PHONY: userspace-cluster-init userspace-cluster-create userspace-cluster-deploy userspace-cluster-destroy userspace-cluster-status userspace-cluster-ssh userspace-cluster-logs userspace-cluster-start userspace-cluster-stop userspace-cluster-restart

cluster-init:
	$(CLUSTER_SETUP) init

cluster-create:
	$(CLUSTER_SETUP) create

cluster-deploy: build build-ctl
	$(CLUSTER_SETUP) deploy $(NODE)

cluster-destroy:
	$(CLUSTER_SETUP) destroy

cluster-status:
	$(CLUSTER_SETUP) status

cluster-ssh:
	$(CLUSTER_SETUP) ssh $(NODE)

cluster-logs:
	$(CLUSTER_SETUP) logs $(NODE)

cluster-start:
	$(CLUSTER_SETUP) start $(NODE)

cluster-stop:
	$(CLUSTER_SETUP) stop $(NODE)

cluster-restart:
	$(CLUSTER_SETUP) restart $(NODE)

userspace-cluster-init: cluster-init
userspace-cluster-create: cluster-create
userspace-cluster-deploy: cluster-deploy
userspace-cluster-destroy: cluster-destroy
userspace-cluster-status: cluster-status
userspace-cluster-ssh: cluster-ssh
userspace-cluster-logs: cluster-logs
userspace-cluster-start: cluster-start
userspace-cluster-stop: cluster-stop
userspace-cluster-restart: cluster-restart

# Legacy remote "loss" cluster using the older xpf-fw0/xpf-fw1 instance names.
.PHONY: loss-cluster-init loss-cluster-create loss-cluster-deploy loss-cluster-destroy loss-cluster-status loss-cluster-ssh loss-cluster-logs loss-cluster-start loss-cluster-stop loss-cluster-restart

loss-cluster-init:
	$(LOSS_CLUSTER_SETUP) init

loss-cluster-create:
	$(LOSS_CLUSTER_SETUP) create

loss-cluster-deploy: build build-ctl
	$(LOSS_CLUSTER_SETUP) deploy $(NODE)

loss-cluster-destroy:
	$(LOSS_CLUSTER_SETUP) destroy

loss-cluster-status:
	$(LOSS_CLUSTER_SETUP) status

loss-cluster-ssh:
	$(LOSS_CLUSTER_SETUP) ssh $(NODE)

loss-cluster-logs:
	$(LOSS_CLUSTER_SETUP) logs $(NODE)

loss-cluster-start:
	$(LOSS_CLUSTER_SETUP) start $(NODE)

loss-cluster-stop:
	$(LOSS_CLUSTER_SETUP) stop $(NODE)

loss-cluster-restart:
	$(LOSS_CLUSTER_SETUP) restart $(NODE)

# --- DPDK targets (require dpdk-dev, meson, ninja) ---

build-dpdk-worker:
	@echo "==> Building DPDK worker..."
	cd dpdk_worker && meson setup build --buildtype=release 2>/dev/null || true
	cd dpdk_worker && meson compile -C build

build-dpdk: build-dpdk-worker
	@echo "==> Building xpfd with DPDK support..."
	CGO_ENABLED=1 go build -tags dpdk -ldflags "$(LDFLAGS)" -o xpfd ./cmd/xpfd

clean-dpdk:
	rm -rf dpdk_worker/build
