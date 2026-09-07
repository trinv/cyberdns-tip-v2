## Mục tiêu

Xây dựng nền tảng Threat Intelligence-driven DNS Firewall, thu thập các nguồn blocklist/Threat Intelligence bên ngoài, chuẩn hóa và hợp nhất dữ liệu, áp dụng policy để xác định domain cần block, sau đó cung cấp blocklist qua HTTP(S) cho Blocky DNS.

## Kiến trúc tổng thể

```text
External Feeds
    │
    ▼
Feed Ingestor
    │
    ├── Normalize
    ├── Canonicalize
    ├── Deduplicate
    ├── Diff / Version
    └── Source attribution
    │
    ├───────────────┐
    ▼               ▼
  OpenCTI       PostgreSQL
  Intelligence  Enforcement Store
    │               │
    └───────┬───────┘
            ▼
      Policy Engine
            │
            ▼
    Blocklist Generator
            │
            ▼
    https://tip.cyberdns.vn/
            │
     ┌──────┼────────┐
     ▼      ▼        ▼
 malware  ads      adults
  .txt    .txt       .txt
     │      │        │
     └──────┼────────┘
            ▼
          Blocky
```

## Vai trò các thành phần

### 1. Feed Ingestor

Chịu trách nhiệm thu thập dữ liệu từ HaGeZi, URLhaus, Phishing feeds, MISP/TAXII và các nguồn khác.

Phải hỗ trợ:

* HTTP/HTTPS, GitHub/raw feed, JSON, CSV, plain text, TAXII và API tùy nguồn.
* Parse và normalize domain.
* Chuẩn hóa FQDN, lowercase, trailing dot và wildcard.
* Xác định `match_type`: `exact`, `wildcard`, `regex`.
* Deduplicate theo `(normalized_domain, match_type)`.
* Theo dõi `source`, `feed`, `first_seen`, `last_seen`, `source_record_id`, hash/version.
* Phát hiện thay đổi bằng checksum/diff để tránh xử lý lại feed không đổi.

### 2. OpenCTI

OpenCTI chỉ đóng vai trò Threat Intelligence / knowledge layer.

Lưu và quản lý:

* STIX 2.1 indicators/observables.
* Source/provenance.
* Confidence.
* Category.
* Relationships.
* First seen / last seen.
* Lifecycle.
* Threat context và enrichment.

Không sử dụng OpenCTI trên DNS query path và không coi OpenCTI là database trực tiếp cho Blocky.

### 3. PostgreSQL

PostgreSQL là **Operational Enforcement Store**.

Lưu:

* Canonical domain.
* Match type.
* Category.
* Source.
* Confidence/score.
* Active/inactive.
* First/last seen.
* Expiry.
* Allowlist/exclusion.
* Policy result.

Phải bảo đảm một domain chỉ có một record canonical cho mỗi `(domain, match_type)`, nhưng có thể có nhiều nguồn tham chiếu tới cùng domain.

### 4. OpenCTI → PostgreSQL synchronization

Không cho OpenCTI truy cập PostgreSQL trực tiếp bằng SQL.

Sử dụng:

```text
OpenCTI
   ↓
Live Stream / GraphQL API
   ↓
Sync Consumer
   ↓
Policy Engine
   ↓
PostgreSQL
```

Sync phải hỗ trợ incremental create/update/delete/merge và không được làm mất provenance của source.

### 5. Policy Engine

Là thành phần quyết định cuối cùng domain nào được đưa vào DNS blocklist.

Policy có thể dựa trên:

* Source trust score.
* Confidence.
* Số lượng nguồn độc lập cùng xác nhận.
* Category/severity.
* Recency.
* Expiry.
* Allowlist/exclusion.
* False-positive history.

Kết quả:

```text
BLOCK
MONITOR
ALLOW
```

Chỉ `BLOCK` mới được đưa vào output blocklist.

### 6. Blocklist Generator

Đọc dữ liệu enforcement từ PostgreSQL và tạo các snapshot blocklist.

Output bắt buộc:

```text
https://tip.cyberdns.vn/blocklist/malware.txt
https://tip.cyberdns.vn/blocklist/phishing.txt
https://tip.cyberdns.vn/blocklist/ads.txt
https://tip.cyberdns.vn/blocklist/tracking.txt
https://tip.cyberdns.vn/blocklist/adults.txt
https://tip.cyberdns.vn/blocklist/gambling.txt
https://tip.cyberdns.vn/blocklist/all.txt
```

Nên cung cấp thêm:

```text
https://tip.cyberdns.vn/blocklist/manifest.json
```

Generator phải:

* Generate snapshot offline.
* Atomic publish bằng temporary file + `rename`.
* Không để client đọc file đang generate.
* Hỗ trợ ETag và Last-Modified.
* Chỉ regenerate khi dữ liệu thực sự thay đổi.
* Hỗ trợ full rebuild và incremental update.

### 7. Blocky

Blocky chỉ truy cập các URL blocklist HTTP(S).

Không được:

* Query PostgreSQL trong DNS request path.
* Query OpenCTI trong DNS request path.
* Phụ thuộc realtime vào Feed Ingestor/Policy Engine.

Blocky phải tiếp tục hoạt động bằng snapshot gần nhất khi management/intelligence plane gặp sự cố.

## Nguyên tắc hiệu năng và mở rộng

* DNS data plane phải hoàn toàn độc lập với intelligence/management plane.
* Blocky xử lý matching trong memory.
* PostgreSQL không được dùng làm realtime DNS lookup engine.
* Ưu tiên incremental synchronization thay vì full reload.
* Cache/checksum tất cả external feeds.
* Tách bulk blocklist khỏi high-value Threat Intelligence.
* Không đưa hàng chục triệu domain ads/tracking vào OpenCTI nếu không cần thiết.
* Có thể scale độc lập Feed Ingestor, OpenCTI, PostgreSQL, Generator và Blocky.
* Kiến trúc phải sẵn sàng cho quy mô tối thiểu 10M domains.

## Phân loại feed

### Threat Intelligence → OpenCTI + PostgreSQL

Ví dụ:

* Malware
* Phishing
* C2
* Botnet
* Scam
* CERT feeds
* MISP
* URLhaus
* HaGeZi TIF

### Bulk Blocking → PostgreSQL trực tiếp

Ví dụ:

* Ads
* Tracking
* Telemetry
* Annoyance
* Privacy lists

## Yêu cầu chống duplicate

Cùng domain xuất hiện từ nhiều feed phải được hợp nhất:

```text
evil.example.com

HaGeZi
URLhaus
MISP
CERT
```

Phải tạo:

```text
1 canonical domain
+
N source relationships
+
N evidence records
```

Không tạo nhiều bản ghi domain trùng nhau.

Tuy nhiên:

```text
evil.example.com | exact
evil.example.com | wildcard
```

là hai enforcement rule khác nhau.

## HA / Fault Tolerance

Khi OpenCTI, PostgreSQL hoặc Feed Ingestor không hoạt động:

```text
Blocky → vẫn phục vụ DNS
```

Blocklist cuối cùng được publish phải tiếp tục được sử dụng cho đến khi snapshot mới hợp lệ được tạo.

## Mục tiêu triển khai

Triển khai theo các phase:

1. HaGeZi TIF → PostgreSQL → Generator → Blocky.
2. Bổ sung nhiều external feeds.
3. Bổ sung OpenCTI.
4. Bổ sung OpenCTI Live Stream → Policy Engine → PostgreSQL.
5. Bổ sung scoring/correlation/lifecycle.
6. Benchmark 100K → 1M → 5M → 10M domains.
7. HA và horizontal scaling cho production.

Mọi implementation phải ưu tiên:

* High performance.
* Horizontal scalability.
* Incremental processing.
* Fault tolerance.
* Deterministic data processing.
* Observability.
* Không tạo dependency giữa DNS query path và management/intelligence plane.
