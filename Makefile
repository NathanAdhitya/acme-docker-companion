BINARY := acmed
IMAGE  := acmed:dev

.PHONY: build test race integration e2e docker fmt tidy check

build:
	go build -o bin/$(BINARY) ./cmd/acmed

test:
	go test ./...

race:
	go test -race ./internal/...

# Runs the real lego DNS-01 path against a local Pebble ACME server.
integration:
	ACMED_INTEGRATION=1 go test ./internal/acmex/ -run TestPebble -v -count=1

# Full container end-to-end: Pebble + challtestsrv + acmed + nginx.
e2e:
	bash test/e2e.sh

docker:
	docker build -t $(IMAGE) .

fmt:
	gofmt -w cmd internal

tidy:
	go mod tidy

check: build test
