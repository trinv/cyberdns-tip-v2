SERVICES := feed-ingestor policy-engine blocklist-generator admin-api
VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS  := -s -w -X github.com/vnnic/cyberdns-tip/internal/app.Version=$(VERSION)

.PHONY: all build test test-integration lint fmt vet tidy up down migrate clean

all: lint test build

build:
	@for s in $(SERVICES); do \
		echo "build $$s"; \
		go build -trimpath -ldflags "$(LDFLAGS)" -o bin/$$s ./cmd/$$s || exit 1; \
	done

test:
	go test -race ./...

# Cần một PostgreSQL dùng riêng cho test; test sẽ tự bỏ qua nếu biến chưa đặt.
test-integration:
	TIP_TEST_DATABASE_DSN=$${TIP_TEST_DATABASE_DSN:-postgres://tip:tip@localhost:5432/tip_test?sslmode=disable} \
		go test -race -count=1 ./internal/db/...

lint: fmt vet

fmt:
	@unformatted=$$(gofmt -l ./cmd ./internal ./migrations); \
	if [ -n "$$unformatted" ]; then echo "chưa gofmt:"; echo "$$unformatted"; exit 1; fi

vet:
	go vet ./...

tidy:
	go mod tidy

up:
	docker compose -f deploy/docker-compose/docker-compose.yml up -d

down:
	docker compose -f deploy/docker-compose/docker-compose.yml down

# Chạy migration bằng chính binary service (mọi service đều nhúng cùng bộ migration).
migrate:
	go run ./cmd/feed-ingestor -config configs/feed-ingestor.yaml -migrate

clean:
	rm -rf bin/ out/
