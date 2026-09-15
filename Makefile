SHELL := /bin/bash
VERSION := $(shell cat VERSION)
GO ?= go
LDFLAGS := -s -w -X simplesecretsmanager/internal/version.Version=$(VERSION)

.PHONY: all build test test-ui test-mysql check clean release
all: build
build:
	mkdir -p bin
	$(GO) build -trimpath -ldflags '$(LDFLAGS)' -o bin/ssm-server ./cmd/ssm-server
	$(GO) build -trimpath -ldflags '$(LDFLAGS)' -o bin/ssm-agent ./cmd/ssm-agent

test:
	$(GO) test -race ./...

# Browser projection tests use Node.js built-in test runner; no npm install.
test-ui:
	node --test tests/*.test.cjs

test-mysql:
	@test -n "$$MYSQL_TEST_DSN" || (echo 'MYSQL_TEST_DSN must name a disposable MySQL database'; exit 1)
	$(GO) test -race -count=1 ./internal/storage ./internal/server

check:
	@test -z "$$($(GO) fmt ./...)" || (echo 'Go formatting was corrected; review changes'; exit 1)
	$(GO) vet ./...
	$(GO) test -race ./...

clean:
	rm -rf bin dist

# Linux is the supported deployment platform: secure file publication uses
# Linux openat/O_NOFOLLOW. Both common homelab architectures are self-contained.
release:
	mkdir -p dist
	@for arch in amd64 arm64; do \
	  dest="dist/ssm-$(VERSION)-linux-$$arch"; \
	  mkdir -p "$$dest"; \
	  for app in server agent; do \
	    CGO_ENABLED=0 GOOS=linux GOARCH=$$arch $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o "$$dest/ssm-$$app" ./cmd/ssm-$$app || exit 1; \
	  done; \
	  cp VERSION README.md setup.md "$$dest/"; \
	  cp -r examples "$$dest/"; \
	  tar -C dist -czf "$$dest.tar.gz" "$${dest##*/}" || exit 1; \
	done
	cd dist && sha256sum *.tar.gz > SHA256SUMS
