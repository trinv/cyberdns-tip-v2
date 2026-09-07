# API Specification

Lược đồ URL bám theo `claude_rm.md` §6. Bản trước của tài liệu này dùng tiền tố `/v1/`;
đã bỏ để khớp với đặc tả kiến trúc.

## Public blocklist API

### GET `/blocklist/{category}.txt`

Trả về danh sách domain, một domain mỗi dòng, Blocky nạp trực tiếp được.

```
https://tip.cyberdns.vn/blocklist/malware.txt
https://tip.cyberdns.vn/blocklist/phishing.txt
https://tip.cyberdns.vn/blocklist/ads.txt
https://tip.cyberdns.vn/blocklist/tracking.txt
https://tip.cyberdns.vn/blocklist/adults.txt
https://tip.cyberdns.vn/blocklist/gambling.txt
https://tip.cyberdns.vn/blocklist/all.txt
```

Các URL phẳng này phục vụ **tenant mặc định** (`public`). Tenant riêng dùng token trong
path — Blocky chỉ nhận URL trần nên token không thể đặt ở header:

```
https://tip.cyberdns.vn/blocklist/{token}/malware.txt
```

Header trả về:

- `ETag` — **hash nội dung**, không phải số version. Rollback do đó không làm ETag lùi
  về giá trị cũ một cách khó hiểu.
- `Last-Modified` — luôn là thời điểm publish, kể cả khi rollback.
- `Cache-Control`
- `Content-Type: text/plain; charset=utf-8`
- `Content-Encoding: gzip` khi client chấp nhận. Bắt buộc với `all.txt`: ở mốc 10M domain
  file này cỡ 200–250 MB khi chưa nén.

Request có điều kiện (`If-None-Match`) trả `304 Not Modified`.

### GET `/allowlist/{token}/default.txt`

Danh sách ngoại lệ của tenant, nạp vào cấu hình allowlist của Blocky.

Cần endpoint riêng vì file danh sách phẳng **không có cú pháp ngoại lệ**: khi
`*.example.com` đang bị chặn mà tenant muốn cho phép `shop.example.com`, gỡ rule cha sẽ
mở toang cả `example.com`, còn giữ rule cha thì phớt lờ yêu cầu tenant. Ngoại lệ vì vậy
phải đi qua một file riêng.

### GET `/blocklist/manifest.json`

```json
{
  "version": "2026-09-07T03:00:00Z-abc123",
  "generated_at": "2026-09-07T03:00:00Z",
  "lists": {
    "malware":  {"etag": "sha256:...", "entries": 2100000, "bytes": 44100000},
    "phishing": {"etag": "sha256:...", "entries": 350000,  "bytes": 7350000}
  },
  "attribution": [
    {"source": "hagezi-tif", "license": "GPL-3.0", "url": "https://github.com/hagezi/dns-blocklists"}
  ]
}
```

`attribution` là bắt buộc: hệ tái phát hành list dẫn xuất từ nhiều nguồn có điều khoản
license riêng.

## Cổng vận hành nội bộ

`/healthz`, `/readyz`, `/metrics` chạy trên một cổng riêng và **không bao giờ được phơi
ra `tip.cyberdns.vn`** — `/metrics` để lộ cấu trúc nội bộ và số liệu vận hành.

- `GET /healthz` — liveness. Không kiểm tra phụ thuộc ngoài: nếu kiểm tra, một sự cố
  PostgreSQL sẽ khiến orchestrator giết luôn service vẫn đang phục vụ được bằng snapshot
  sẵn có.
- `GET /readyz` — readiness, có kiểm tra phụ thuộc.
- `GET /metrics` — Prometheus.

## Internal canonical event

```json
{
  "event_type": "indicator.upsert",
  "source_id": "hagezi-tif",
  "domain": "example.com",
  "normalized_domain": "example.com",
  "match_type": "exact",
  "category": ["malware", "phishing"],
  "confidence": 90,
  "first_seen": "2026-09-01T00:00:00Z",
  "last_seen": "2026-09-07T00:00:00Z",
  "valid_until": null,
  "revoked": false,
  "raw_hash": "sha256:..."
}
```

`revoked` và `valid_until` **không đồng nghĩa**: `revoked` là phủ định tường minh và
triệt tiêu mọi nguồn khác; `valid_until` hết hạn chỉ rút đóng góp của chính nguồn đó,
các nguồn còn lại vẫn đứng.

## Error contract

Không bao giờ phát hành snapshot thành công một phần. Publish theo **bộ**: cả bộ vào
`snapshots/{version}/` rồi đổi con trỏ `current` bằng một thao tác nguyên tử. Khi dựng
lỗi thì giữ nguyên version hiện tại và ghi lỗi vào metrics + audit.
