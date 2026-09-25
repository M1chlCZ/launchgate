.PHONY: build test vet fmt

build:
	go build -trimpath -o bin/launchgate .

test:
	go test -race ./...

vet:
	go vet ./...

fmt:
	gofmt -w .
