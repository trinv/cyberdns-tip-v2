# syntax=docker/dockerfile:1

# Một Dockerfile dựng cả bốn service; chọn service bằng build arg SERVICE.
FROM golang:1.26-alpine AS build

ARG SERVICE
ARG VERSION=dev

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN test -n "$SERVICE" || (echo "cần build arg SERVICE" && exit 1) \
 && CGO_ENABLED=0 go build \
      -trimpath \
      -ldflags "-s -w -X github.com/vnnic/cyberdns-tip/internal/app.Version=${VERSION}" \
      -o /out/service ./cmd/${SERVICE}

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /out/service /usr/local/bin/service
COPY --from=build /src/configs /etc/cyberdns-tip/configs

USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/service"]
