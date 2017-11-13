#!/usr/bin/env bash
SRCFILES=main.go $(wildcard utils/*.go) $(wildcard dns-server/*.go) $(wildcard backends/*.go)  $(wildcard  queue/*.go)

VERSION?=$(shell git describe --tags)



# Ensure that the dist directory is always created
MAKE_SURE_DIST_EXIST := $(shell mkdir -p dist)

GO_CONTAINER_NAME?=dockerepo/glide
GOPATH=${PWD}/../../../../

.PHONY: all binary
default: all
all: binary
binary: dist/containerdns

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


