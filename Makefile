.PHONY: all build clean

GOFLAGS := CGO_ENABLED=1

all: build

build:
	$(GOFLAGS) go build -o bin/council        ./cmd/council/
	$(GOFLAGS) go build -o bin/council-mcp    ./cmd/council-mcp/

clean:
	rm -f bin/council bin/council-mcp
