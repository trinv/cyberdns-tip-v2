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

Chỉ vậy. Script sẽ:

1. Sinh `deploy/docker-compose/.env.lab` với mật khẩu ngẫu nhiên
2. Build một image chứa cả bốn service
3. Khởi động PostgreSQL và chờ nó sẵn sàng
4. Chạy migration
5. Tạo tài khoản quản trị, in mật khẩu ra màn hình
6. Khởi động toàn bộ dịch vụ kèm nginx và chứng thư tự ký
7. In ra URL và thông tin đăng nhập

Lần đầu mất vài phút để build. Chạy lại `up` bất cứ lúc nào — mỗi bước tự kiểm tra
trạng thái trước khi làm, và **không bao giờ ghi đè** mật khẩu đã sinh.

## Truy cập

| | |
|---|---|
| Dashboard quản trị | `https://localhost:9443` |
| Blocklist | `https://localhost:8443/blocklist/malware.txt` |
| Manifest | `https://localhost:8443/blocklist/manifest.json` |

Quên mật khẩu thì chạy `./deploy/lab.sh urls`.

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

Theo dõi tiến trình:

```sh
./deploy/lab.sh status
./deploy/lab.sh logs feed-ingestor
```

Muốn thử nhanh hơn thì tắt HaGeZi TIF trên dashboard và thêm một nguồn nhỏ của riêng
bạn — mọi thứ chạy giống hệt, chỉ khác khối lượng.

## Các lệnh

```sh
./deploy/lab.sh up        # dựng và khởi động (chạy lại được nhiều lần)
./deploy/lab.sh status    # trạng thái container, số domain, tình trạng snapshot
./deploy/lab.sh urls      # in lại URL và mật khẩu
./deploy/lab.sh logs                    # toàn bộ
./deploy/lab.sh logs feed-ingestor      # một service
./deploy/lab.sh ingest    # chạy thu thập ngay, không chờ hết chu kỳ
./deploy/lab.sh down      # dừng, GIỮ dữ liệu
./deploy/lab.sh reset     # dừng và XÓA SẠCH (hỏi xác nhận)
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

Nặng: cần khoảng **16 GB RAM** ngoài phần stack chính.

```sh
# Elasticsearch cần giá trị này trên HOST, nếu thiếu nó thoát hẳn chứ không chạy suy giảm
sudo sysctl -w vm.max_map_count=262144

sudo ./deploy/install-opencti.sh    # sinh .env.opencti với bí mật ngẫu nhiên
./deploy/lab.sh opencti
```

Giao diện ở `http://localhost:8081`, tài khoản nằm trong
`deploy/docker-compose/.env.opencti`.

**OpenCTI hiện chưa nối vào đường sinh blocklist.** Nó chạy và dùng được giao diện,
nhưng `opencti-connector` và `sync-consumer` thuộc P4 và chưa được viết.

## Xử lý sự cố

**Cổng đã bị chiếm.** Sửa `LAB_BLOCKLIST_PORT`, `LAB_ADMIN_PORT` hoặc
`LAB_POSTGRES_PORT` trong `deploy/docker-compose/.env.lab` rồi chạy lại `up`.

**Blocklist trả 503.** Chưa có snapshot. Xem `./deploy/lab.sh status`; nếu lần thu thập
đã xong mà vẫn 503 thì xem `./deploy/lab.sh logs blocklist-generator`.

**Import bị từ chối.** Đây là hành vi cố ý — hệ fail-closed. Vào dashboard, mục **Lịch
sử import** sẽ ghi rõ lý do. Các lý do hay gặp: feed rỗng, phản hồi bị cắt cụt, tỉ lệ
dòng lỗi vượt ngưỡng, hoặc số bản ghi biến động quá lớn so với lần trước. Dữ liệu cũ và
snapshot đang phát hành **không bị ảnh hưởng**.

**Đăng nhập thất bại sau khi `reset`.** `reset` xóa cả tài khoản. Chạy `up` để tạo lại.

**Muốn soi CSDL trực tiếp.**

```sh
docker compose -f deploy/docker-compose/docker-compose.lab.yml \
  --env-file deploy/docker-compose/.env.lab exec postgres psql -U tip -d tip
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
