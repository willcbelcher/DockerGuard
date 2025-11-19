.PHONY: build install test clean help

# Build the binary
build:
	go build -o dockerguard ./cmd/dockerguard

# Install the binary
install:
	go install ./cmd/dockerguard

# Run tests
test:
	go test ./...

# Run tests with coverage
test-coverage:
	go test -cover ./...

# Clean build artifacts
clean:
	rm -f dockerguard dockerguard.exe
	go clean

# Download dependencies
deps:
	go mod download
	go mod tidy

# Format code
fmt:
	go fmt ./...

# Run linter (requires golangci-lint)
lint:
	golangci-lint run

# Build for multiple platforms
build-all:
	GOOS=linux GOARCH=amd64 go build -o dockerguard-linux-amd64 ./cmd/dockerguard
	GOOS=darwin GOARCH=amd64 go build -o dockerguard-darwin-amd64 ./cmd/dockerguard
	GOOS=darwin GOARCH=arm64 go build -o dockerguard-darwin-arm64 ./cmd/dockerguard
	GOOS=windows GOARCH=amd64 go build -o dockerguard-windows-amd64.exe ./cmd/dockerguard

help:
	@echo "Available targets:"
	@echo "  build       - Build the dockerguard binary"
	@echo "  install     - Install dockerguard to GOPATH/bin"
	@echo "  test        - Run tests"
	@echo "  test-coverage - Run tests with coverage"
	@echo "  clean       - Remove build artifacts"
	@echo "  deps        - Download and tidy dependencies"
	@echo "  fmt         - Format code"
	@echo "  lint        - Run linter (requires golangci-lint)"
	@echo "  build-all   - Build for all platforms"
	@echo "  help        - Show this help message"

