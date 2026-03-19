MODULE := $(shell head -1 go.mod | awk '{print $$2}')
BINARY := raven
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT  := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
DATE    := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

LDFLAGS := -s -w \
  -X $(MODULE)/internal/cli.version=$(VERSION) \
  -X $(MODULE)/internal/cli.commit=$(COMMIT) \
  -X $(MODULE)/internal/cli.date=$(DATE)

.PHONY: build run test lint proto clean

build:
	go build -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/raven

run: build
	./$(BINARY) serve --config raven.yaml

test:
	go test -race -count=1 ./...

lint:
	golangci-lint run ./...

proto:
	buf generate

clean:
	rm -f $(BINARY)
	rm -rf dist/
