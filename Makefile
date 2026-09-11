APP        := ip-scanner
DIST       := dist
VERSION    ?= dev
LDFLAGS    := -s -w -X main.version=$(VERSION)

.PHONY: run build test vet fmt clean update-oui \
        build-darwin-amd64 build-darwin-arm64 build-darwin-universal \
        build-linux build-all

run:
	go run .

build:
	go build -o $(APP) .

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -l .

clean:
	rm -rf $(DIST) $(APP)

# Refreshes internal/scanner/data/oui.json from the official IEEE registry.
update-oui:
	python3 scripts/update-oui.py

## ---- macOS release builds (Intel + Apple Silicon) ----

build-darwin-amd64:
	mkdir -p $(DIST)
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o $(DIST)/$(APP)-darwin-amd64 .

build-darwin-arm64:
	mkdir -p $(DIST)
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o $(DIST)/$(APP)-darwin-arm64 .

# Combines both architecture-specific binaries into a single universal
# binary that runs natively on both Intel and Apple Silicon Macs. Requires
# running "make" on (or with a toolchain that provides) the "lipo" utility,
# i.e. on macOS with Xcode command line tools installed.
build-darwin-universal: build-darwin-amd64 build-darwin-arm64
	lipo -create -output $(DIST)/$(APP)-darwin-universal \
		$(DIST)/$(APP)-darwin-amd64 $(DIST)/$(APP)-darwin-arm64
	chmod +x $(DIST)/$(APP)-darwin-universal

build-linux:
	mkdir -p $(DIST)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o $(DIST)/$(APP)-linux-amd64 .

build-all: build-darwin-amd64 build-darwin-arm64 build-linux
