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
cmd/            6 lệnh Go (5 service + bootstrap chạy một lần)
internal/       code dùng chung (config, db, metrics, httpx, app)
migrations/     lược đồ SQL, nhúng vào binary
connectors/     connector đẩy dữ liệu ngược vào OpenCTI (chưa viết)
configs/        cấu hình mẫu theo service
deploy/         docker-compose
observability/  Prometheus + luật cảnh báo
tests/          fixture, test tích hợp, kết quả benchmark
```

## Yêu cầu

Go 1.26+, PostgreSQL 17+. Docker chỉ cần cho stack phát triển cục bộ.

## Chạy

### Docker (cách thường dùng)

Stack tự chứa hoàn toàn — không cần tên miền, DNS hay chứng thư thật. `compose.yaml`
nằm ở gốc repo nên `docker compose` chạy trần, không cần `-f` hay `--env-file`:

```sh
docker compose up -d
```

Vòng đời sau mỗi lần đẩy code mới:

```sh
docker compose down -v
git pull
docker compose build
docker compose up -d
```

Không có bước thủ công nào ở giữa. Service `bootstrap` chạy migration, tạo tài khoản
quản trị và bật nguồn OpenCTI (nếu đã cấu hình), rồi thoát; mọi service khác chờ nó
chạy **xong** mới khởi động. Đó là lý do `down -v` — vốn xóa sạch cả volume dữ liệu —
vẫn cho ra một stack dùng được ngay.

Mật khẩu quản trị: đặt `TIP_ADMIN_PASSWORD` trong `.env` để nó ổn định qua mỗi lần dựng
lại. Bỏ trống thì bootstrap sinh ngẫu nhiên và in ra nhật ký của chính nó
(`docker compose logs bootstrap`). Không có mật khẩu mặc định.

Muốn có sẵn `.env` với bí mật ngẫu nhiên thì chạy `./deploy/lab.sh up` một lần; sau đó
dùng lệnh `docker compose` trần cũng được. Xem [.env.example](.env.example) và
[deploy/LAB.md](deploy/LAB.md).

### Không dùng Docker

Bí mật đi qua biến môi trường, không bao giờ nằm trong file cấu hình.

```sh
export TIP_DATABASE_DSN='postgres://tip:tip@localhost:5432/tip?sslmode=disable'

# Migration + tài khoản quản trị đầu tiên
go run ./cmd/bootstrap -config configs/bootstrap.yaml

# Chạy một service
go run ./cmd/feed-ingestor -config configs/feed-ingestor.yaml
```

Cổng vận hành nội bộ của mỗi service: `/healthz`, `/readyz`, `/metrics`
(9101 feed-ingestor, 9102 policy-engine, 9103 blocklist-generator, 9104 admin-api,
9105 sync-consumer). Các endpoint này **không bao giờ được phơi ra `tip.cyberdns.vn`**.

## Kiểm thử

```sh
go test ./...                      # unit, không cần PostgreSQL

# Test tích hợp: migration lặp lại được + các ràng buộc chống xung đột.
# Tự bỏ qua khi biến chưa đặt.
TIP_TEST_DATABASE_DSN='postgres://tip:tip@localhost:5432/tip_test?sslmode=disable' \
  go test -count=1 ./internal/db/...
```

## Triển khai production

TLS và reverse proxy do **nginx chạy trên host** (systemd) đảm nhiệm, không phải
container. Chứng thư số nằm ở `/etc/letsencrypt` trên host nên tách hẳn khỏi vòng đời
container: build lại hay xóa sạch stack cũng không đụng tới cert, và không có nguy cơ
xin lại chứng thư rồi chạm trần rate limit của Let's Encrypt (5 lần cấp mỗi tuần cho
một tên miền).

Không container nào mở ra Internet. `blocklist-generator` chỉ ánh xạ cổng lên
`127.0.0.1:8080` của host để nginx proxy tới; PostgreSQL, các cổng vận hành, Prometheus
và Grafana không publish cổng nào.

### Cách nhanh: script tự động

```sh
# Chạy thử trước bằng máy chủ thử nghiệm của Let's Encrypt — không tính vào hạn mức.
sudo ./deploy/install.sh --email admin@vnnic.vn --staging

# Thật:
sudo ./deploy/install.sh --email admin@vnnic.vn
```

Script làm trọn: cài nginx/certbot, kiểm tra DNS, xin chứng thư, cài cấu hình nginx,
chuyển gia hạn sang webroot, sinh `.env`, khởi động stack (bootstrap tự chạy migration),
rồi xác minh.

Chạy lại được nhiều lần — mỗi bước tự kiểm tra trạng thái trước khi làm. Hai thứ script
**không bao giờ** đụng vào: `.env` đã tồn tại (ghi đè là đổi `POSTGRES_PASSWORD`, và
volume dữ liệu cũ sẽ không mở được nữa) và chứng thư còn hơn 30 ngày (Let's Encrypt chỉ
cho 5 lần cấp mỗi tuần).

Các bước thủ công tương đương ở dưới, dùng khi cần kiểm soát từng bước.

### 1. Xin chứng thư (làm một lần)

Điều kiện: bản ghi A/AAAA của `tip.cyberdns.vn` đã trỏ về máy này và cổng 80 mở ra
Internet — thử thách ACME HTTP đi qua đó.

```sh
sudo apt install nginx certbot
sudo mkdir -p /var/www/certbot

# nginx chưa có cấu hình cho tên miền này nên dừng nó ra để certbot tự nghe cổng 80.
sudo systemctl stop nginx
sudo certbot certonly --standalone -d tip.cyberdns.vn
sudo systemctl start nginx
```

### 2. Cài cấu hình nginx

```sh
sudo cp deploy/nginx/tip.cyberdns.vn.conf /etc/nginx/sites-available/
sudo ln -s /etc/nginx/sites-available/tip.cyberdns.vn.conf /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
```

Cấu hình đã chừa sẵn `/.well-known/acme-challenge/` trên cổng 80, nên **các lần gia hạn
sau không cần dừng nginx nữa**. Chuyển timer của certbot sang webroot để tận dụng:

```sh
sudo certbot certonly --webroot -w /var/www/certbot -d tip.cyberdns.vn --force-renewal
sudo systemctl status certbot.timer      # gia hạn tự động, không downtime
```

### 3. Chạy stack

```sh
cd deploy/docker-compose
cp .env.example .env          # điền POSTGRES_PASSWORD, GRAFANA_PASSWORD

docker compose -f docker-compose.prod.yml up -d postgres
docker compose -f docker-compose.prod.yml run --rm feed-ingestor -migrate
docker compose -f docker-compose.prod.yml up -d
```

### Hai chỗ dễ vấp

- **Đừng bật `gzip` ở nginx.** `blocklist-generator` đã dựng sẵn bản `.gz` cạnh mỗi file
  lúc build snapshot và tự trả về khi client chấp nhận gzip. Bật gzip ở tầng proxy là
  nén lại nội dung đã nén cho từng request; ngoài ra module gzip của nginx làm yếu ETag
  (thêm tiền tố `W/`), phá mất cơ chế 304 mà Blocky dựa vào. Cấu hình mẫu đã đặt
  `gzip off`.
- **`proxy_buffering off` là bắt buộc, không phải tùy chọn.** Mặc định nginx đệm phản
  hồi và ghi ra file tạm khi vượt 1 GB; với `all.txt` cỡ vài trăm MB thì mỗi request
  thành một lượt ghi đĩa vô ích.

## OpenCTI

Tầng Threat Intelligence chạy bằng một compose riêng, dựa trên
[OpenCTI-Platform/docker](https://github.com/OpenCTI-Platform/docker):

```sh
sudo ./deploy/install-opencti.sh
```

Giao diện chỉ lắng nghe trên `127.0.0.1:8081` của máy chủ, **không ra Internet** — truy
cập qua `ssh -L 8081:127.0.0.1:8081 user@may-chu`. Cần tối thiểu 16 GB RAM (32 GB để
thoải mái) ngoài phần stack chính đang dùng.

Chiều **OpenCTI -> blocklist** đã thông: service `sync-consumer` nghe Live Stream và ghi
xuống L0/L1, nên thu hồi một indicator trong OpenCTI sẽ gỡ chặn domain tương ứng ở lượt
policy kế tiếp. Chiều ngược lại (`opencti-connector`, đẩy dữ liệu canonical vào OpenCTI
dưới dạng STIX 2.1) chưa viết.

Dữ liệu quay về từ OpenCTI mang `origin='opencti'` và **không** được tính vào phép đếm
nguồn độc lập. Không có quy tắc đó, một domain đi vòng qua OpenCTI rồi quay lại sẽ tự
thưởng cho mình một xác nhận ảo và vượt ngưỡng chặn mà không nguồn nào thật sự xác nhận
thêm.

Chi tiết tài nguyên, truy cập, sao lưu và nâng cấp: [deploy/opencti/README.md](deploy/opencti/README.md).

## Trạng thái

**P0–P3 hoàn tất.** Lược đồ đầy đủ L0–L3, năm service, dashboard quản trị, đóng gói
Docker, CI, metrics và luật cảnh báo.

| Package | Vai trò |
|---|---|
| `internal/domainname` | Chuẩn hóa tất định, một hàm duy nhất cho mọi nguồn |
| `internal/psl` | Hàng rào public suffix — chặn `com`, `vn`, `com.vn` |
| `internal/feed` | Tải có điều kiện, parser streaming, kiểm tra toàn vẹn |
| `internal/store` | L0/L1: staging + COPY, hợp nhất giao hoán, grace period |
| `internal/policy` | Thang ưu tiên 8 nấc, hàm thuần |
| `internal/render` | Rút gọn cha/con, định dạng đầu ra |
| `internal/builder` | Dựng snapshot theo tenant từ một lượt policy đã hoàn tất |
| `internal/snapshot` | Publish nguyên tử ở mức bộ, gzip dựng sẵn, rollback |
| `internal/blocklistsrv` | Phục vụ HTTP công khai: ETag/304, gzip |
| `internal/adminapi` + `web/` | Dashboard quản trị, phiên lưu ở CSDL, RBAC, nhật ký |

**P4 đang làm.** Chiều OpenCTI -> PostgreSQL đã xong:

| Package | Vai trò |
|---|---|
| `internal/opencti` | Phân tích STIX pattern và khung SSE, hàm thuần |
| `internal/syncconsumer` | Điều phối sự kiện: create/update/delete/**merge**, chống phát lại |

Còn lại của P4: `opencti-connector` (chiều ngược lại) và job đối soát định kỳ qua GraphQL
cho trường hợp consumer ngừng lâu hơn cửa sổ lưu của stream.

Sau đó: P5 nạp cấu hình policy từ CSDL và shadow mode; P6 renderer cắm được (hosts,
AdGuard, RPZ); P7 benchmark 10M, HA, sao lưu/PITR, rà soát bảo mật và giấy phép nguồn dữ
liệu trước khi mở dịch vụ ra ngoài VNNIC.
