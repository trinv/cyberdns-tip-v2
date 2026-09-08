# OpenCTI — tầng Threat Intelligence

Dựa trên [OpenCTI-Platform/docker](https://github.com/OpenCTI-Platform/docker), cắt gọn
và siết lại cho vai trò ở đây.

```sh
sudo ./deploy/install.sh --email admin@vnnic.vn   # stack chính, chạy trước
sudo ./deploy/install-opencti.sh
```

Tài liệu này nói về **production**, nơi bí mật nằm ở hai file riêng:
`deploy/docker-compose/.env` cho stack chính và `.env.opencti` cho cụm OpenCTI.

Trong **lab** thì khác: mọi thứ nằm gọn trong một file `.env` ở gốc repo để
`docker compose` chạy trần được — nó chỉ tự nạp đúng một file `.env`. Xem
[../LAB.md](../LAB.md).

## Trạng thái tích hợp

Chiều **OpenCTI → blocklist** đã thông. Chiều ngược lại chưa:

| Thành phần | Vai trò | Trạng thái |
|---|---|---|
| `sync-consumer` | Live Stream → PostgreSQL, ghi các hàng của nguồn `origin='opencti'` | đã có |
| `opencti-connector` | canonical record → STIX 2.1 bundle đẩy vào OpenCTI | chưa viết |

Nghĩa là: thu hồi (`revoked`) một indicator trong OpenCTI sẽ gỡ chặn domain tương ứng ở
lượt policy kế tiếp, kể cả khi nhiều feed vẫn còn liệt kê nó — đó là nấc 5
`opencti_revoked` của thang ưu tiên. Nhưng dữ liệu từ các feed chưa tự động xuất hiện
trong OpenCTI; muốn thấy chúng ở đó thì hiện phải nhập STIX thủ công.

Hai bất biến mà đường này giữ:

- Hàng của nguồn OpenCTI mang `origin='opencti'` và **không** được tính vào phép đếm
  nguồn độc lập. Thiếu quy tắc đó, một domain đi vòng qua OpenCTI rồi quay lại sẽ tự
  thưởng cho mình một xác nhận ảo.
- `revoked` (phủ định tường minh, triệt tiêu mọi nguồn) khác hẳn `valid_until` hết hạn
  (phân rã thụ động, chỉ rút đóng góp của riêng OpenCTI). Nhầm hai thứ này sẽ gỡ chặn
  hàng loạt ngoài ý muốn.

## Yêu cầu tài nguyên

Đây là phần nặng nhất của toàn hệ — nặng hơn tất cả những thứ còn lại cộng lại.

| Thành phần | RAM thực tế |
|---|---|
| Elasticsearch | ~8 GB (heap 4 GB, còn lại là bộ nhớ ngoài heap và page cache) |
| Nền tảng OpenCTI | ~4 GB |
| 3 worker | ~1,5 GB |
| Redis + RabbitMQ + MinIO | ~1,5 GB |
| 6 connector nội bộ | ~1,5 GB |

**Tối thiểu 16 GB RAM** để chạy được, **32 GB** để chạy thoải mái — và stack chính vẫn
chạy song song trên cùng máy. Đĩa: tối thiểu 50 GB trống, chỉ số Elasticsearch phình
theo lượng CTI nhập vào.

Điều chỉnh trong `.env.opencti`: `ELASTIC_MEMORY_SIZE`, `OPENCTI_NODE_HEAP`,
`OPENCTI_WORKER_REPLICAS`. Đừng đặt `ELASTIC_MEMORY_SIZE` quá 31G — trên ngưỡng đó JVM
mất khả năng nén con trỏ, tốn bộ nhớ hơn mà không nhanh hơn.

## Truy cập

Giao diện **không phơi ra Internet**. Nó chỉ lắng nghe trên `127.0.0.1:8081` của máy
chủ, đúng nguyên tắc "OpenCTI UI/API nằm trong management network" của báo cáo phương
án §8.2.

```sh
ssh -L 8081:127.0.0.1:8081 user@may-chu
# rồi mở http://localhost:8081
```

Tài khoản và mật khẩu nằm trong `deploy/docker-compose/.env.opencti`.

Nếu cần mở cho một nhóm người dùng qua trình duyệt mà không dùng tunnel, thêm một
`server` block nginx riêng cho `cti.cyberdns.vn` có `allow`/`deny` theo dải IP quản trị
và chứng thư riêng — **đừng** gắn vào vhost `tip.cyberdns.vn`, vì vhost đó là công khai.

## Vì sao khác compose chính thức

**Bỏ cụm XTM One** (`xtm-one`, `xtm-one-worker`, `pgsql-xtm-one`, `xtm-composer`,
`rsa-key-generator`). Service `opencti` chỉ khai báo phụ thuộc `redis`,
`elasticsearch`, `minio`, `rabbitmq`. XTM One là sản phẩm riêng của Filigran, không cần
cho vai trò kho tri thức CTI ở đây, và nó kéo theo một PostgreSQL thứ hai cùng vài GB
RAM.

**Ghim phiên bản thay vì `:latest`.** Compose chính thức dùng `:latest` cho tiện thử
nghiệm. Với production, một lần `docker pull` vô tình sẽ nâng cấp cả nền tảng lẫn lược
đồ Elasticsearch mà không ai chủ ý — và **OpenCTI không hỗ trợ hạ cấp**, nên đó là thay
đổi một chiều.

**Không publish cổng ra Internet.** Xem mục Truy cập.

**MITRE ATT&CK để tùy chọn.** Lần đồng bộ đầu nặng và kéo dài hàng chục phút. Bật khi cần:

```sh
cd deploy/docker-compose
docker compose -f docker-compose.prod.yml -f docker-compose.opencti.yml \
  --env-file .env --env-file .env.opencti --profile mitre up -d connector-mitre
```

## Hai thứ dễ hỏng

**`vm.max_map_count`.** Elasticsearch cần ≥ 262144, thiếu thì nó **thoát hẳn** với
`max virtual memory areas vm.max_map_count is too low` chứ không chạy ở chế độ suy
giảm. Script cài đặt tự đặt và ghi xuống `/etc/sysctl.d/99-opencti.conf` để tồn tại qua
reboot — đặt bằng `sysctl -w` không thôi thì sau lần khởi động lại máy Elasticsearch
không lên được nữa.

**Xung đột cổng.** `blocklist-generator` đã chiếm `127.0.0.1:8080`, nên OpenCTI dùng
`8081`. Đổi bằng `OPENCTI_HOST_PORT` nếu cần, và nhớ đổi `OPENCTI_BASE_URL` cho khớp —
sai `APP__BASE_URL` thì đăng nhập chuyển hướng hỏng.

## Sao lưu

`deploy/docker-compose/.env.opencti` phải được sao lưu **ngay sau khi sinh ra**. Mất
`OPENCTI_ENCRYPTION_KEY` là mất khả năng giải mã dữ liệu đã lưu; không có cách nào lần
ngược.

Dữ liệu nằm ở bốn volume: `esdata` (Elasticsearch), `s3data` (MinIO, chứa file đính
kèm), `redisdata`, `amqpdata`. Volume cần sao lưu thật sự là `esdata` và `s3data`;
Redis và RabbitMQ chỉ giữ trạng thái tạm.

## Vận hành

```sh
cd deploy/docker-compose
C="-f docker-compose.prod.yml -f docker-compose.opencti.yml --env-file .env --env-file .env.opencti"

docker compose $C ps
docker compose $C logs -f opencti
docker compose $C restart opencti-worker
docker compose $C stop            # dừng, giữ dữ liệu
```

Nâng cấp: đổi `OPENCTI_VERSION` trong `.env.opencti`, đọc release note của OpenCTI về
migration, rồi `docker compose $C up -d`. Sao lưu `esdata` trước — không hạ cấp được.

Chỉ số cần theo dõi (đã có sẵn trong Prometheus và luật cảnh báo):
`cyberdns_opencti_stream_lag_seconds` có dữ liệu ngay khi `sync-consumer` bắt đầu nhận
sự kiện; `cyberdns_opencti_reconcile_drift` đứng yên ở 0 cho tới khi job đối soát GraphQL
được viết. Thêm `cyberdns_opencti_stream_events_total` tách theo loại sự kiện và kết cục
(`applied` / `skipped` / `stale` / `failed`) — `skipped` cao là bình thường, vì luồng CTI
chở nhiều thứ không phải tên miền.
