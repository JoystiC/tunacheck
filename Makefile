SHELL := /bin/sh
GO ?= go
BIN := bin/tunacheck

.PHONY: all deps build test guidance clean

all: build

deps:
	$(GO) mod tidy

guidance:
	./scripts/fetch_guidance.sh

build: guidance
	mkdir -p bin
	$(GO) build -ldflags "-s -w" -o $(BIN) ./cmd/tunacheck

.PHONY: snapshot release
snapshot:
	goreleaser release --snapshot --clean

release:
	goreleaser release --clean

test:
	$(GO) test ./...

clean:
	rm -rf bin


