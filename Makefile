# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
BINARY_NAME_LINUX=oidc-agent_linux_amd64
BINARY_NAME_DARWIN=oidc-agent_darwin_amd64
BINARY_NAME_WINDOWS=oidc-agent_windows_amd64.exe

all: test build
build:
		$(GOBUILD) -o bin/$(BINARY_NAME) -v
test:
		$(GOTEST) -v ./...
clean:
		$(GOCLEAN)
		rm -f bin
run:
		$(GOBUILD) -o bin/$(BINARY_NAME) -v ./...
		./bin/$(BINARY_NAME)

# Cross compilation
build-darwin:
		CGO_ENABLED=0 GOOS=darwin  GOARCH=amd64 $(GOBUILD) -o bin/$(BINARY_NAME_DARWIN) -v
build-linux:
		CGO_ENABLED=0 GOOS=linux   GOARCH=amd64 $(GOBUILD) -o bin/$(BINARY_NAME_LINUX) -v
build-windows:
		CGO_ENABLED=0 GOOS=windows GOARCH=amd64 $(GOBUILD) -o bin/$(BINARY_NAME_WINDOWS) -v
