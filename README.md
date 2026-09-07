# CyberDNS TIP

Nền tảng Threat Intelligence thu thập nhiều nguồn blocklist/CTI, chuẩn hóa và hợp nhất,
áp policy để quyết định domain nào bị chặn, rồi phát hành blocklist theo category qua
HTTPS cho Blocky và các DNS engine khác.

```
External Feeds → feed-ingestor → OpenCTI / PostgreSQL → policy-engine
                                                             ↓
                                                    blocklist-generator
                                                             ↓
                                  https://tip.cyberdns.vn/blocklist/{category}.txt
```

Blocky **không thuộc phạm vi triển khai** của repo này — nó là bên tiêu thụ các URL trên.

## Tài liệu

| File | Nội dung |
|---|---|
| [claude_rm.md](claude_rm.md) | Đặc tả kiến trúc — **nguồn chân lý** |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Kiến trúc chi tiết |
| [docs/DATA_MODEL.md](docs/DATA_MODEL.md) | Mô hình dữ liệu |
| [docs/API.md](docs/API.md) | Hợp đồng API |
| [docs/IMPLEMENTATION.md](docs/IMPLEMENTATION.md) | Đặc tả hiện thực |
| [docs/OPERATIONS.md](docs/OPERATIONS.md) | Runbook vận hành |
| [CLAUDE.md](CLAUDE.md) | Quy tắc kiến trúc không thương lượng |
| [tests/TEST_PLAN.md](tests/TEST_PLAN.md) | Kế hoạch kiểm thử |

Nguyên lý nền: dữ liệu chia 4 tầng, **chỉ tầng bằng chứng là dữ liệu thật, mọi tầng trên
đều suy dẫn tất định và dựng lại được**.

| Tầng | Bảng | Tính chất |
|---|---|---|
| L0 | `domain_evidence` | Bằng chứng thô. Append-only, chặn bằng trigger ở CSDL. |
| L1 | `domains`, `domain_sources`, `domain_source_categories` | Canonical, hợp nhất giao hoán. |
| L2 | `domain_decisions` theo `(domain, category)` | Hàm thuần của L1 + cấu hình policy. |
| L3 | `snapshot_sets`, `snapshots` | Hàm thuần của L2 + cấu hình tenant. |

## Cấu trúc

```
cmd/            4 service Go
internal/       code dùng chung (config, db, metrics, httpx, app)
migrations/     lược đồ SQL, nhúng vào binary
connectors/     connector Python cho OpenCTI (P4)
configs/        cấu hình mẫu theo service
deploy/         docker-compose
observability/  Prometheus + luật cảnh báo
tests/          fixture, test tích hợp, kết quả benchmark
```

## Yêu cầu

Go 1.26+, PostgreSQL 17+. Docker chỉ cần cho stack phát triển cục bộ.

## Chạy

Bí mật đi qua biến môi trường, không bao giờ nằm trong file cấu hình.

```sh
export TIP_DATABASE_DSN='postgres://tip:tip@localhost:5432/tip?sslmode=disable'

# Chạy migration (mọi service đều nhúng cùng bộ migration)
go run ./cmd/feed-ingestor -config configs/feed-ingestor.yaml -migrate

# Chạy một service
go run ./cmd/feed-ingestor -config configs/feed-ingestor.yaml
```

Cổng vận hành nội bộ của mỗi service: `/healthz`, `/readyz`, `/metrics`
(9101 feed-ingestor, 9102 policy-engine, 9103 blocklist-generator, 9104 admin-api).
Ba endpoint này **không bao giờ được phơi ra `tip.cyberdns.vn`**.

Stack cục bộ đầy đủ:

```sh
docker compose -f deploy/docker-compose/docker-compose.yml up -d
```

## Kiểm thử

```sh
go test ./...                      # unit, không cần PostgreSQL

# Test tích hợp: migration lặp lại được + các ràng buộc chống xung đột.
# Tự bỏ qua khi biến chưa đặt.
TIP_TEST_DATABASE_DSN='postgres://tip:tip@localhost:5432/tip_test?sslmode=disable' \
  go test -count=1 ./internal/db/...
```

## Triển khai production

Chỉ `caddy` mở ra Internet. PostgreSQL, các cổng vận hành, Prometheus và Grafana đều
nằm trong mạng nội bộ của compose — `/metrics` phơi cấu trúc nội bộ nên không bao giờ
được ra ngoài.

```sh
cd deploy/docker-compose
cp .env.example .env          # điền POSTGRES_PASSWORD, ACME_EMAIL, GRAFANA_PASSWORD

docker compose -f docker-compose.prod.yml up -d postgres
docker compose -f docker-compose.prod.yml run --rm feed-ingestor -migrate
docker compose -f docker-compose.prod.yml up -d
```

Điều kiện để Caddy xin được chứng chỉ: bản ghi A/AAAA của `tip.cyberdns.vn` đã trỏ về
máy này, và **cổng 80 mở** — thử thách ACME HTTP đi qua đó, đóng nó thì không cấp được
chứng chỉ.

Hai lưu ý dễ vấp khi chạy trong container:

- Cổng công khai phải bind `0.0.0.0`, không phải `127.0.0.1`. Mặc định trong file cấu
  hình là loopback cho an toàn khi chạy trên máy trần; compose ghi đè qua
  `TIP_PUBLIC_ADDR`.
- Không bật `encode gzip` ở Caddy. `blocklist-generator` đã dựng sẵn bản `.gz` cạnh mỗi
  file lúc build và tự trả về khi client chấp nhận gzip; nén lại ở tầng proxy là nén một
  nội dung đã nén cho từng request.

## Trạng thái

**P0 hoàn tất** — khung repo, lược đồ đầy đủ L0–L3, cấu hình, metrics, CI, compose.

**P1 đang làm.** Đã xong và có test:

| Package | Vai trò |
|---|---|
| `internal/domainname` | Chuẩn hóa tất định, một hàm duy nhất cho mọi nguồn |
| `internal/psl` | Hàng rào public suffix — chặn `com`, `vn`, `com.vn` |
| `internal/policy` | Thang ưu tiên 8 nấc, hàm thuần |
| `internal/render` | Rút gọn cha/con, định dạng đầu ra |
| `internal/snapshot` | Publish nguyên tử ở mức bộ, gzip dựng sẵn, rollback |
| `internal/feed` | Tải có điều kiện, parser streaming, kiểm tra toàn vẹn |
| `internal/blocklistsrv` | Phục vụ HTTP công khai: ETag/304, gzip |

Còn lại của P1: tầng lưu trữ L0/L1 (staging + COPY, upsert giao hoán, grace period),
vòng chạy policy ghi L2, và nối generator để dựng snapshot từ PostgreSQL.
