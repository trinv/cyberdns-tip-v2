# syntax=docker/dockerfile:1

# Một image chứa TẤT CẢ service.
#
# Bản trước dùng build arg SERVICE và build riêng từng service, tức là biên dịch nhiều
# lần trên cùng một mã nguồn. Các binary Go tĩnh cộng lại chỉ vài chục MB, nên gộp chung
# vừa nhanh hơn vừa bỏ được nguy cơ các image lệch phiên bản nhau.
# Chọn service bằng `command` trong compose.

FROM golang:1.26-alpine AS build

ARG VERSION=dev

WORKDIR /src

# Tách bước tải phụ thuộc để Docker cache lại khi chỉ mã nguồn thay đổi.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 go build \
      -trimpath \
      -ldflags "-s -w -X github.com/vnnic/cyberdns-tip/internal/app.Version=${VERSION}" \
      -o /out/ \
      ./cmd/bootstrap \
      ./cmd/feed-ingestor \
      ./cmd/policy-engine \
      ./cmd/blocklist-generator \
      ./cmd/admin-api \
      ./cmd/sync-consumer \
      ./cmd/healthcheck

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /out/ /usr/local/bin/
COPY --from=build /src/configs /etc/cyberdns-tip/configs

# Không đặt ENTRYPOINT: compose chỉ định thẳng binary trong `command`, nên cùng một
# image phục vụ được mọi service.
USER nonroot:nonroot
