# Triển khai trên môi trường lab Docker

Stack lab tự chứa hoàn toàn: PostgreSQL, bốn service, nginx và chứng thư đều nằm trong
container. Không cần tên miền, không cần DNS, không cần Let's Encrypt.

## Yêu cầu

| | |
|---|---|
| Docker Engine | 24+ kèm plugin `docker compose` v2 |
| RAM | 4 GB cho stack chính; thêm 16 GB nếu bật OpenCTI |
| Đĩa trống | 10 GB (CSDL ~2,8 GB với một nguồn HaGeZi TIF) |
| Mạng | Cần ra Internet để tải feed |

Kiểm tra nhanh:

```sh
docker compose version   # phải là v2.x
docker info              # phải chạy được, không cần sudo
```

Nếu `docker info` báo lỗi quyền: `sudo usermod -aG docker $USER` rồi đăng nhập lại.

## Cài đặt

```sh
git clone https://github.com/trinv/cyberdns-tip-v2.git
cd cyberdns-tip-v2
./deploy/lab.sh up
```

`lab.sh up` sinh file `.env` với mật khẩu ngẫu nhiên, build image rồi khởi động. Sau
lần đó thì **không cần script nữa** — `compose.yaml` nằm ở gốc repo và `.env` đã có, nên
`docker compose` chạy trần.

## Vòng đời sau mỗi lần đẩy code

Bốn lệnh, chạy ở gốc repo, không có bước thủ công nào ở giữa:

```sh
docker compose down -v
git pull
docker compose build
docker compose up -d
```

`docker compose up -d` không trả về cho tới khi service **`bootstrap`** chạy xong. Nó
làm ba việc, cả ba đều idempotent:

1. Chạy migration.
2. Tạo tài khoản quản trị đầu tiên **nếu chưa có** — không đụng tới tài khoản đã tồn
   tại, nên mật khẩu bạn đổi trên dashboard không bị ghi đè.
3. Bật nguồn `opencti` nếu OpenCTI đã được cấu hình.

Mọi service khác khai báo `depends_on: bootstrap: service_completed_successfully`, nên
chúng chỉ khởi động sau khi lược đồ đã đúng phiên bản. Đó là lý do `down -v` — vốn xóa
sạch cả volume dữ liệu — vẫn cho ra một stack dùng được ngay.

`--no-cache` chỉ cần khi bạn nghi cache hỏng. Bình thường `docker compose build` là đủ:
lớp `COPY . .` tự mất hiệu lực khi mã nguồn đổi, và bỏ `--no-cache` giúp tiết kiệm phần
lớn thời gian build.

### Mật khẩu quản trị

`lab.sh up` ghi sẵn `TIP_ADMIN_PASSWORD` vào `.env`, nên mật khẩu **ổn định qua mỗi lần
`down -v`**. Xem lại bất cứ lúc nào:

```sh
./deploy/lab.sh urls
```

Nếu bạn tự tạo `.env` và để trống `TIP_ADMIN_PASSWORD`, bootstrap sinh ngẫu nhiên và in
ra nhật ký của chính nó:

```sh
docker compose logs bootstrap
```

Không có mật khẩu mặc định: một tài khoản admin/admin trên hệ điều khiển việc chặn tên
miền quốc gia là chuyện không được phép tồn tại dù chỉ một phút.

## Truy cập

| | |
|---|---|
| Dashboard quản trị | `https://localhost:9443` |
| Blocklist | `https://localhost:8443/blocklist/malware.txt` |
| Manifest | `https://localhost:8443/blocklist/manifest.json` |
| OpenCTI | `https://localhost:10443` (sau khi bật, xem bên dưới) |

Quên mật khẩu thì chạy `./deploy/lab.sh urls`, hoặc đọc `TIP_ADMIN_PASSWORD` trong `.env`.

Chứng thư là bản **tự ký**, nên trình duyệt sẽ cảnh báo — bấm qua. Với `curl` thêm `-k`:

```sh
curl -k https://localhost:8443/blocklist/manifest.json
```

Từ máy khác trong lab, thay `localhost` bằng IP của máy chủ.

## Lần chạy đầu mất bao lâu

Nguồn mặc định là HaGeZi TIF: **42 MB, khoảng 2,15 triệu domain**. Đo trên một máy phát
triển bình thường:

| Giai đoạn | Thời gian |
|---|---|
| Thu thập + nạp CSDL | ~10 phút |
| Chấm điểm | ~6 phút |
| Dựng snapshot | ~1 phút |

Trong suốt thời gian đó, các URL blocklist trả **HTTP 503**. Đó là hành vi **đúng**:
đường dẫn đã thông nhưng chưa có snapshot nào được phát hành. Nếu trả 200 ngay lập tức
mới là chuyện lạ.

Muốn thử nhanh hơn thì tắt HaGeZi TIF trên dashboard và thêm một nguồn nhỏ của riêng
bạn — mọi thứ chạy giống hệt, chỉ khác khối lượng.

Theo dõi tiến trình:

```sh
./deploy/lab.sh status
docker compose logs -f feed-ingestor
```

## Các lệnh

Toàn bộ đều là `docker compose` trần, chạy ở gốc repo:

```sh
docker compose ps                     # trạng thái container
docker compose logs -f                # toàn bộ log
docker compose logs -f feed-ingestor  # một service
docker compose restart feed-ingestor  # chạy thu thập ngay (nó chạy một lượt khi lên)
docker compose down                   # dừng, GIỮ dữ liệu
docker compose down -v                # dừng và XÓA SẠCH volume
```

`lab.sh` chỉ là tiện ích quanh những lệnh đó, cộng phần sinh bí mật:

```sh
./deploy/lab.sh up        # sinh .env nếu chưa có, build và khởi động
./deploy/lab.sh status    # container + số domain + đồng bộ OpenCTI + snapshot
./deploy/lab.sh urls      # in lại URL và mật khẩu
./deploy/lab.sh opencti   # bổ sung bí mật OpenCTI vào .env rồi khởi động cụm đó
./deploy/lab.sh reset     # docker compose down -v, có hỏi xác nhận
```

## Nối vào Blocky

Sau khi có snapshot, dán vào `config.yml` của Blocky:

```yaml
blocking:
  denylists:
    malware:
      - https://<ip-may-chu>:8443/blocklist/malware.txt
    ads:
      - https://<ip-may-chu>:8443/blocklist/ads.txt
  clientGroupsBlock:
    default:
      - malware
```

Chứng thư tự ký nên Blocky sẽ từ chối. Trong lab có hai cách: chép
`deploy/docker-compose` volume `certs` ra rồi thêm vào kho tin cậy của máy chạy Blocky,
hoặc trỏ thẳng vào cổng HTTP nội bộ của container thay vì qua nginx.

## Bật OpenCTI

```sh
./deploy/lab.sh opencti
```

Script tự lo mọi thứ: kiểm tra RAM, kiểm tra `vm.max_map_count`, **bổ sung bí mật
OpenCTI vào cùng file `.env`**, tải image, khởi động, chờ sẵn sàng, xác minh đường đồng
bộ, rồi in ra tài khoản đăng nhập.

Trong đó có dòng `COMPOSE_FILE=compose.yaml:deploy/docker-compose/docker-compose.opencti.yml`.
Nhờ nó, từ lúc đó `docker compose` trần bao gồm luôn cụm OpenCTI — bốn lệnh ở mục *Vòng
đời sau mỗi lần đẩy code* vẫn dùng nguyên như cũ, không cần thêm `-f` nào.

**Đăng nhập:** `https://localhost:10443`, tài khoản `admin@vnnic.vn`. Mật khẩu in ra khi
chạy xong, hoặc lấy lại bất cứ lúc nào bằng `./deploy/lab.sh urls`.

### Trước khi chạy

**RAM.** Cụm này cần khoảng **8–16 GB ngoài** phần stack chính đang dùng. Cấu hình lab
đã hạ Elasticsearch xuống 2 GB heap và chỉ một worker; production cần nhiều hơn hẳn.
Script sẽ cảnh báo và hỏi nếu máy dưới 12 GB.

**`vm.max_map_count`.** Đây là nguyên nhân số một khiến Elasticsearch không khởi động
được, và nó **thoát hẳn** chứ không chạy ở chế độ suy giảm:

```sh
sudo sysctl -w vm.max_map_count=262144

# Giữ qua reboot
echo "vm.max_map_count=262144" | sudo tee /etc/sysctl.d/99-opencti.conf
```

Script kiểm tra trước và dừng lại nếu thiếu, thay vì để bạn chờ Elasticsearch chết đi
chết lại. Trên WSL thì đặt giá trị này **trong WSL**, không phải Windows.

**Thời gian.** Tải image mất vài GB. Lần khởi động đầu OpenCTI phải tạo toàn bộ chỉ mục
Elasticsearch và nạp dữ liệu nền — vài phút là bình thường, script chờ tối đa 15 phút.

### Đường dữ liệu OpenCTI -> blocklist

Sau khi `./deploy/lab.sh opencti` chạy xong, service `bootstrap` đã bật nguồn `opencti`
và `sync-consumer` đã nhận URL cùng token. Từ lúc đó:

| Thành phần | Vai trò | Trạng thái |
|---|---|---|
| `sync-consumer` | OpenCTI Live Stream -> PostgreSQL (L0/L1) | đã có |
| `opencti-connector` | canonical -> STIX 2.1 đẩy vào OpenCTI | chưa viết |

Kiểm tra nó đang chạy:

```sh
docker compose logs -f sync-consumer
```

Dòng cần thấy là `bắt đầu nghe OpenCTI Live Stream`. Nếu thay vào đó là `OpenCTI chưa cấu
hình` hoặc `chưa bật nguồn OpenCTI, sẽ thử lại`, service đang **chờ có chủ đích** chứ
không hỏng — xem phần xử lý sự cố bên dưới.

**Thử một vòng đầu-cuối.** Trong OpenCTI, tạo một Indicator với pattern
`[domain-name:value = 'test-tip.example.com']`, gắn nhãn `malware`. Trong vòng vài giây
domain sẽ xuất hiện ở L1; sau lượt policy và lượt dựng snapshot kế tiếp nó có mặt trong
`malware.txt`. Rút ngắn chờ đợi bằng cách hạ `TIP_POLICY_INTERVAL` và `TIP_BUILD_INTERVAL`
trong `.env` rồi `docker compose up -d`.

Rồi bấm **Revoke** trên chính indicator đó: ở lượt policy kế tiếp domain **rời khỏi**
blocklist với `reason_code = opencti_revoked`, kể cả khi các feed khác vẫn liệt kê nó.
Đó là nấc 5 của thang ưu tiên, và là lý do tồn tại của cả đường dữ liệu này.

**Nhãn quyết định category.** Ánh xạ nhãn sang category nằm ở `configs/sync-consumer.yaml`,
mục `opencti.label_categories`. Nhãn không có trong bảng đó thì indicator rơi về category
mặc định của nguồn — không bị bỏ đi.

**Dữ liệu quay về từ OpenCTI không được tính là xác nhận độc lập.** Nguồn `opencti` có
`origin='opencti'`, và phép đếm nguồn độc lập chỉ đếm `origin='direct'`. Không có quy tắc
đó, một domain đi vòng qua OpenCTI rồi quay lại sẽ tự thưởng cho mình một nguồn ảo và
vượt ngưỡng chặn mà không nguồn nào thật sự xác nhận thêm.

### Tắt OpenCTI, giữ stack chính

```sh
docker compose stop opencti opencti-worker elasticsearch redis minio rabbitmq
```

Cổng 10443 sẽ trả **502** khi OpenCTI tắt — đúng như thiết kế, và blocklist với dashboard
không bị ảnh hưởng.

## Xử lý sự cố

**Cổng đã bị chiếm.** Sửa `LAB_BLOCKLIST_PORT`, `LAB_ADMIN_PORT` hoặc
`LAB_POSTGRES_PORT` trong `.env` ở gốc repo rồi `docker compose up -d`.

**Blocklist trả 503.** Chưa có snapshot. Xem `./deploy/lab.sh status`; nếu lần thu thập
đã xong mà vẫn 503 thì xem `docker compose logs blocklist-generator`.

**Import bị từ chối.** Đây là hành vi cố ý — hệ fail-closed. Vào dashboard, mục **Lịch
sử import** sẽ ghi rõ lý do. Các lý do hay gặp: feed rỗng, phản hồi bị cắt cụt, tỉ lệ
dòng lỗi vượt ngưỡng, hoặc số bản ghi biến động quá lớn so với lần trước. Dữ liệu cũ và
snapshot đang phát hành **không bị ảnh hưởng**.

**`sync-consumer` chưa nối vào Live Stream.** Đây là hành vi có chủ đích, không phải
lỗi. Ba
nguyên nhân, nhật ký nói rõ nguyên nhân nào:

- `OpenCTI chưa cấu hình` — chưa chạy `./deploy/lab.sh opencti`.
- `chưa bật nguồn OpenCTI, sẽ thử lại` — hàng `opencti` trong bảng `sources` đang tắt.
  Bật trên dashboard ở mục Nguồn dữ liệu; service tự bắt được trong vòng 30 giây, không
  cần khởi động lại container.
- Thoát hẳn với thông báo về `origin` — hàng `sources` tên `opencti` có `origin` khác
  `'opencti'`. Đây là lỗi cấu hình nghiêm trọng: nó sẽ khiến dữ liệu quay về từ OpenCTI
  bị tính thành nguồn độc lập và làm lạm phát điểm.

**Đăng nhập thất bại sau khi `down -v`.** Volume bị xóa nên tài khoản cũng mất, nhưng
`bootstrap` tạo lại ngay ở lần `up` kế tiếp với đúng `TIP_ADMIN_PASSWORD` trong `.env`.
Nếu biến đó để trống thì mật khẩu là giá trị mới, đọc bằng `docker compose logs bootstrap`.

**Muốn soi CSDL trực tiếp.**

```sh
docker compose exec postgres psql -U tip -d tip
```

Hoặc từ host, cổng `55433`.

## Khác biệt so với production

| | Lab | Production |
|---|---|---|
| nginx | trong container | trên host bằng systemd |
| Chứng thư | tự ký, sinh tự động | Let's Encrypt qua certbot |
| Phân biệt dịch vụ | theo cổng | theo tên miền |
| PostgreSQL | mở ra loopback host | không publish cổng |
| Chu kỳ chạy | 5–30 phút | hàng giờ |

Lý do nginx nằm ngoài container ở production: chứng thư số tách khỏi vòng đời container,
nên dựng lại stack không đụng tới cert và không có nguy cơ chạm trần cấp phát của
Let's Encrypt (5 lần mỗi tuần cho một tên miền). Trong lab không có chứng thư thật nên
lý do đó biến mất.

Hướng dẫn production: [README.md](../README.md#triển-khai-production).
