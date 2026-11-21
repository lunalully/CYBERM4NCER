SHELL := /bin/bash
GO ?= go
BINARY := cyberm4ncer
DIST ?= dist
PREFIX ?= $(HOME)/.local
MODULE := github.com/lunalully/cyberm4ncer
VERSION ?= 0.1.0-dev
COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
BUILD_DATE := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w \
	-X $(MODULE)/internal/version.Version=$(VERSION) \
	-X $(MODULE)/internal/version.Commit=$(COMMIT) \
	-X $(MODULE)/internal/version.BuildDate=$(BUILD_DATE)

.PHONY: all build install test test-race vet fmt fmt-check check clean help

all: build

build:
	@mkdir -p $(DIST)
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(DIST)/$(BINARY) ./cmd/$(BINARY)
	@echo "built $(DIST)/$(BINARY)"

install: build
	install -Dm755 $(DIST)/$(BINARY) $(DESTDIR)$(PREFIX)/bin/$(BINARY)
	@echo "installed $(DESTDIR)$(PREFIX)/bin/$(BINARY)"

test:
	$(GO) test ./...

test-race:
	$(GO) test -race ./internal/core ./internal/scope ./internal/execution ./internal/database

vet:
	$(GO) vet ./...

fmt:
	gofmt -w cmd internal

fmt-check:
	@files="$$(gofmt -l cmd internal)"; \
	if [ -n "$$files" ]; then \
		echo "gofmt required for:"; echo "$$files"; exit 1; \
	fi

check: fmt-check vet test
	@echo "all checks passed"

clean:
	rm -rf $(DIST)

help:
	@echo "make build       build dist/cyberm4ncer"
	@echo "make test        run unit tests"
	@echo "make test-race   run race tests for critical packages"
	@echo "make check       gofmt check, vet and tests"
	@echo "make install     install to \$$PREFIX/bin"
	@echo "make clean       remove dist/"
	@echo ""
	@echo "Variables: VERSION=... PREFIX=... GOOS=... GOARCH=... CGO_ENABLED=0"