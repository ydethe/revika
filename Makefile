.PHONY: help test test-coverage test-verbose test-short build vet fmt lint clean

help:
	@echo "Revika Phase 1 - Makefile targets:"
	@echo "  make test           - Run all tests"
	@echo "  make test-coverage  - Run tests with coverage report"
	@echo "  make test-verbose   - Run tests with verbose output"
	@echo "  make test-short     - Run tests with short timeout"
	@echo "  make build          - Build all packages"
	@echo "  make vet            - Run go vet"
	@echo "  make fmt            - Format code with gofmt"
	@echo "  make lint           - Run golangci-lint (if installed)"
	@echo "  make clean          - Clean build artifacts"

test:
	go test ./...

test-coverage:
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

test-verbose:
	go test -v ./...

test-short:
	go test -timeout=30s ./...

build:
	go build ./...

vet:
	go vet ./...

fmt:
	gofmt -l -w .

lint:
	@which golangci-lint > /dev/null || (echo "golangci-lint not found. Install with: curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b \$$(go env GOPATH)/bin" && exit 1)
	golangci-lint run

integration-test:
	go test -v -run Integration ./...

package-tests:
	@echo "Testing crypto package..."
	go test -v ./internal/crypto/
	@echo "\nTesting shard package..."
	go test -v ./internal/shard/
	@echo "\nTesting store package..."
	go test -v ./internal/store/
	@echo "\nTesting model package..."
	go test -v ./pkg/model/

benchmark-shard:
	go test -bench=. -benchmem ./internal/shard/

benchmark-store:
	go test -bench=. -benchmem ./internal/store/

benchmark-all:
	go test -bench=. -benchmem ./...

clean:
	rm -f coverage.out coverage.html
	go clean ./...
