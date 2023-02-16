all: clear build

PKG = github.com/containerd/nydus-snapshotter
PACKAGES ?= $(shell go list ./... | grep -v /tests)
SUDO = $(shell which sudo)
GO_EXECUTABLE_PATH ?= $(shell which go)
CARGO ?= $(shell which cargo)
NYDUS_BUILDER ?= /usr/bin/nydus-image
NYDUS_NYDUSD ?= /usr/bin/nydusd
GOOS ?= linux
GOARCH ?= $(shell go env GOARCH)
KERNEL_VER = $(shell uname -r)

# Used to populate variables in version package.
BUILD_TIMESTAMP=$(shell date '+%Y-%m-%dT%H:%M:%S')
VERSION=$(shell git describe --match 'v[0-9]*' --dirty='.m' --always --tags)
REVISION=$(shell git rev-parse HEAD)$(shell if ! git diff --no-ext-diff --quiet --exit-code; then echo .m; fi)

# Relpace test target images for e2e tests.
ifdef E2E_TEST_TARGET_IMAGES_FILE
ENV_TARGET_IMAGES_FILE = --env-file ${E2E_TEST_TARGET_IMAGES_FILE}
endif

ifdef E2E_DOWNLOADS_MIRROR
BUILD_ARG_E2E_DOWNLOADS_MIRROR = --build-arg DOWNLOADS_MIRROR=${E2E_DOWNLOADS_MIRROR}
endif

ifdef GOPROXY
PROXY := GOPROXY="${GOPROXY}"
endif

ifdef FS_CACHE
FS_DRIVER = fscache
else
FS_DRIVER = fusedev
endif

LDFLAGS = -s -w -X ${PKG}/version.Version=${VERSION} -X ${PKG}/version.Revision=$(REVISION) -X ${PKG}/version.BuildTimestamp=$(BUILD_TIMESTAMP)

OPTIMIZER_SERVER = tools/optimizer-server
OPTIMIZER_SERVER_TOML = ${OPTIMIZER_SERVER}/Cargo.toml
OPTIMIZER_SERVER_BIN = ${OPTIMIZER_SERVER}/target/release/optimizer-server

.PHONY: build
build:
	GOOS=${GOOS} GOARCH=${GOARCH} ${PROXY} go build -ldflags "$(LDFLAGS)" -v -o bin/containerd-nydus-grpc ./cmd/containerd-nydus-grpc
	${CARGO} fmt --manifest-path ${OPTIMIZER_SERVER_TOML} -- --check
	${CARGO} build --release --manifest-path ${OPTIMIZER_SERVER_TOML} && cp ${OPTIMIZER_SERVER_BIN} ./bin

static-release:
	CGO_ENABLED=0 ${PROXY} GOOS=${GOOS} GOARCH=${GOARCH} go build -ldflags "$(LDFLAGS) -extldflags -static" -v -o bin/containerd-nydus-grpc ./cmd/containerd-nydus-grpc

# Majorly for cross build for converter package since it is imported by other projects
converter:
	GOOS=${GOOS} GOARCH=${GOARCH} ${PROXY} go build -ldflags "$(LDFLAGS)" -v -o bin/converter ./cmd/converter

.PHONY: clear
clear:
	${CARGO} clean --manifest-path ${OPTIMIZER_SERVER_TOML}
	rm -f bin/*
	rm -rf _out

.PHONY: install
install:
	sudo install -D -m 755 bin/containerd-nydus-grpc /usr/local/bin/containerd-nydus-grpc
	sudo install -D -m 755 misc/snapshotter/nydusd-config.fusedev.json /etc/nydus/nydusd-config.fusedev.json
	sudo install -D -m 755 misc/snapshotter/nydusd-config.fscache.json /etc/nydus/nydusd-config.fscache.json
	sudo install -D -m 755 misc/snapshotter/config.toml /etc/nydus/config.toml
	sudo ln -f -s /etc/nydus/nydusd-config.${FS_DRIVER}.json /etc/nydus/nydusd-config.json
	sudo install -D -m 644 misc/snapshotter/nydus-snapshotter.${FS_DRIVER}.service /etc/systemd/system/nydus-snapshotter.service

	@sudo mkdir -p /etc/nydus/certs.d
	@if which systemctl; then sudo systemctl enable /etc/systemd/system/nydus-snapshotter.service; sudo systemctl restart nydus-snapshotter; fi

.PHONY: vet
vet:
	go vet $(PACKAGES) ./tests

.PHONY: check
check: vet
	golangci-lint run

.PHONY: test
test:
	go test -race -v -mod=mod -cover ${PACKAGES}

.PHONY: cover
cover:
	go test -v -covermode=atomic -coverprofile=coverage.txt $(PACKAGES)
	go tool cover -func=coverage.txt

smoke:
	$(SUDO) NYDUS_BUILDER=${NYDUS_BUILDER} NYDUS_NYDUSD=${NYDUS_NYDUSD} ${GO_EXECUTABLE_PATH} test -race -v ./tests
	$(SUDO) NYDUS_BUILDER=${NYDUS_BUILDER} NYDUS_NYDUSD=${NYDUS_NYDUSD} ${GO_EXECUTABLE_PATH} test -race -v ./tests

.PHONY: integration
integration:
	CGO_ENABLED=1 ${PROXY} GOOS=${GOOS} GOARCH=${GOARCH} go build -ldflags '-X "${PKG}/version.Version=${VERSION}" -extldflags "-static"' -race -v -o bin/containerd-nydus-grpc ./cmd/containerd-nydus-grpc
	$(SUDO) DOCKER_BUILDKIT=1 docker build ${BUILD_ARG_E2E_DOWNLOADS_MIRROR} -t nydus-snapshotter-e2e:0.1 -f integration/Dockerfile .
	$(SUDO) docker run --name nydus-snapshotter_e2e --rm --privileged -v /root/.docker:/root/.docker -v `go env GOMODCACHE`:/go/pkg/mod \
	-v `go env GOCACHE`:/root/.cache/go-build -v `pwd`:/nydus-snapshotter \
	-v /usr/src/linux-headers-${KERNEL_VER}:/usr/src/linux-headers-${KERNEL_VER} \
	${ENV_TARGET_IMAGES_FILE}  \
	nydus-snapshotter-e2e:0.1
