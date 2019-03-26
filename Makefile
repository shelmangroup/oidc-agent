# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
BINARY_NAME_LINUX=oidc-agent_linux_amd64
BINARY_NAME_DARWIN=oidc-agent_darwin_amd64
BINARY_NAME_WINDOWS=$(BINARY_NAME)_windows_amd64.exe

all: test build
build: 
		$(GOBUILD) -o $(BINARY_NAME) -v
test: 
		$(GOTEST) -v ./...
clean: 
		$(GOCLEAN)
		rm -f $(BINARY_NAME)
		rm -f $(BINARY_WINDOWS)
run:
		$(GOBUILD) -o $(BINARY_NAME) -v ./...
		./$(BINARY_NAME)

# Cross compilation
build-darwin:
		CGO_ENABLED=0 GOOS=darwin  GOARCH=amd64 $(GOBUILD) -o $(BINARY_NAME_DARWIN) -v
build-linux:
		CGO_ENABLED=0 GOOS=linux   GOARCH=amd64 $(GOBUILD) -o $(BINARY_NAME_LINUX) -v
build-windows:
		CGO_ENABLED=0 GOOS=windows GOARCH=amd64 $(GOBUILD) -o $(BINARY_NAME_WINDOWS) -v
