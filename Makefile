.PHONY: run test lint deadcode up
run:
	go run ./cmd/privatebin-go
test:
	go test ./...
lint:
	go vet ./...
deadcode:
	go run golang.org/x/tools/cmd/deadcode@latest ./...
up:
	docker compose up -d --build
