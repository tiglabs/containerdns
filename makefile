#!/usr/bin/env bash
SRCFILES=main.go $(wildcard utils/*.go) $(wildcard dns-server/*.go) $(wildcard backends/*.go)  $(wildcard  queue/*.go)

#VERSION?=$(shell git describe --tags)
VERSION?=$(shell git rev-parse HEAD)


# Ensure that the dist directory is always created
MAKE_SURE_DIST_EXIST := $(shell mkdir -p dist)

GO_CONTAINER_NAME?=dockerepo/glide
GOPATH=${PWD}/../../../../

.PHONY: all binary
default: all
all: binary kubeapi scanner schedule
binary: dist/containerdns
kubeapi: dist/kubeapi
scanner: dist/dns-scanner
schedule: dist/dns-schedule


docker-image: $(DEPLOY_CONTAINER_MARKER)

.PHONY: clean
clean:
	rm -rf dist vendor $(DEPLOY_CONTAINER_MARKER)




vendor: glide.yaml
	docker run --rm \
        -v ${HOME}/.glide:/root/.glide:rw \
        -v ${PWD}:/go/src/github.com/tigcode/containerdns:rw \
        --entrypoint /bin/sh $(GO_CONTAINER_NAME) -e -c ' \
        cd /go/src/github.com/tigcode/containerdns && \
        glide install -strip-vendor && \
        chown $(shell id -u):$(shell id -u) -R vendor'


dist/containerdns: $(SRCFILES) vendor
	GOPATH=${GOPATH} CGO_ENABLED=1 go build -v -o dist/containerdns \
	-ldflags "-X main.VERSION=$(VERSION) -s -w" main.go


KUBEAPISRC=containerdns-kubeapi/api.go  containerdns-kubeapi/server.go
dist/kubeapi: $(KUBEAPISRC) vendor
	GOPATH=${GOPATH} CGO_ENABLED=1 go build -v -o dist/containerdns-kubeapi \
        -ldflags "-X main.VERSION=$(VERSION) -s -w" containerdns-kubeapi/*.go


SCANNERSRC=dns-scanner/scanner.go $(wildcard dns-scanner/ev2/*.go)
dist/dns-scanner: $(SCANNERSRC) vendor
	GOPATH=${GOPATH} CGO_ENABLED=1 go build -v -o dist/dns-scanner \
        -ldflags "-X main.VERSION=$(VERSION) -s -w" dns-scanner/scanner.go


SCHEDULESRC=dns-schedule/schedule.go $(wildcard dns-scanner/base/*.go) $(wildcard dns-scanner/domain/*.go) $(wildcard dns-scanner/ipaddr/*.go)
dist/dns-schedule: $(SCHEDULESRC) vendor
	GOPATH=${GOPATH} CGO_ENABLED=1 go build -v -o dist/dns-schedule \
        -ldflags "-X main.VERSION=$(VERSION) -s -w" dns-schedule/schedule.go


