#!/usr/bin/env bash
#
# CyberDNS TIP — tiện ích quanh compose.yaml ở gốc repo.
#
# Script này KHÔNG bắt buộc. Stack chạy được bằng docker compose trần:
#
#   docker compose down -v && git pull && docker compose build && docker compose up -d
#
# Việc duy nhất mà docker compose không tự làm được là sinh bí mật ngẫu nhiên, nên
# `lab.sh up` chủ yếu để tạo file .env lần đầu. Sau đó dùng lệnh nào cũng được.
#
#   ./deploy/lab.sh up        sinh .env nếu chưa có, build và khởi động
#   ./deploy/lab.sh status    trạng thái container, dữ liệu, đồng bộ OpenCTI
#   ./deploy/lab.sh logs      xem log (thêm tên service để lọc)
#   ./deploy/lab.sh ingest    chạy thu thập ngay, không chờ hết chu kỳ
#   ./deploy/lab.sh urls      in lại URL và thông tin đăng nhập
#   ./deploy/lab.sh opencti   bật thêm OpenCTI (cần khoảng 16 GB RAM)
#   ./deploy/lab.sh down      dừng, GIỮ dữ liệu
#   ./deploy/lab.sh reset     dừng và XÓA SẠCH dữ liệu
#
# Chạy lại `up` nhiều lần được: mỗi bước tự kiểm tra trạng thái trước khi làm.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE_MAIN="$REPO_ROOT/compose.yaml"
OCTI_FILE="$REPO_ROOT/deploy/docker-compose/docker-compose.opencti.yml"
ENV_FILE="$REPO_ROOT/.env"

RED=$'\033[31m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'
BLUE=$'\033[36m'; BOLD=$'\033[1m'; RESET=$'\033[0m'

step() { printf '\n%s==> %s%s\n' "$BOLD" "$*" "$RESET"; }
info() { printf '    %s\n' "$*"; }
ok()   { printf '    %s✓%s %s\n' "$GREEN" "$RESET" "$*"; }
warn() { printf '    %s!%s %s\n' "$YELLOW" "$RESET" "$*" >&2; }
die()  { printf '\n%sLỗi:%s %s\n' "$RED" "$RESET" "$*" >&2; exit 1; }

# opencti_enabled báo .env đã có bí mật OpenCTI hay chưa.
opencti_enabled() {
    [[ -f "$ENV_FILE" ]] && grep -qE '^OPENCTI_ADMIN_TOKEN=.' "$ENV_FILE"
}

# compose gọi docker compose với đúng bộ file.
#
# Tự thêm lớp phủ OpenCTI khi .env đã có bí mật của nó, để `lab.sh down` dừng được cả
# cụm OpenCTI thay vì bỏ lại một nửa stack đang chạy.
#
# Không truyền --env-file: compose tự nạp .env nằm cạnh compose.yaml. Truyền thêm sẽ
# khiến hành vi của script khác với docker compose trần, mà chính sự khác nhau đó là
# thứ sinh ra những lỗi chỉ xảy ra ở một trong hai đường.
compose() {
    local files=(-f "$COMPOSE_FILE_MAIN")
    opencti_enabled && files+=(-f "$OCTI_FILE")
    docker compose "${files[@]}" "$@"
}

# ------------------------------------------------------------------ tiền kiểm

preflight() {
    command -v docker >/dev/null 2>&1 \
        || die "chưa cài docker. Xem https://docs.docker.com/engine/install/"

    docker compose version >/dev/null 2>&1 \
        || die "chưa có plugin 'docker compose' v2. Bản docker-compose v1 không dùng được."

    docker info >/dev/null 2>&1 \
        || die "không nói chuyện được với Docker daemon. Daemon đã chạy chưa, và người dùng hiện tại có trong nhóm docker không?"

    [[ -f "$COMPOSE_FILE_MAIN" ]] || die "không thấy $COMPOSE_FILE_MAIN"
}

# rand sinh chuỗi ngẫu nhiên an toàn, không phụ thuộc openssl.
rand() {
    local n="${1:-32}"
    if command -v openssl >/dev/null 2>&1; then
        openssl rand -hex "$n" | head -c "$n"
    else
        od -An -tx1 -N"$n" /dev/urandom | tr -d ' \n' | head -c "$n"
    fi
}

# uuid4 sinh một UUID phiên bản 4 mà không cần uuidgen — gói đó không có sẵn ở nhiều
# bản phân phối tối giản.
uuid4() {
    local h
    h=$(od -An -tx1 -N16 /dev/urandom | tr -d ' \n')
    printf '%s-%s-4%s-a%s-%s\n' \
        "${h:0:8}" "${h:8:4}" "${h:13:3}" "${h:17:3}" "${h:20:12}"
}

env_get() {
    local key="$1" fallback="${2:-}" v
    v=$(grep -E "^${key}=" "$ENV_FILE" 2>/dev/null | tail -1 | cut -d= -f2- | tr -d '[:space:]')
    printf '%s' "${v:-$fallback}"
}

# ------------------------------------------------------------------ cấu hình

setup_env() {
    # KHÔNG ghi đè file đã có: POSTGRES_PASSWORD trong đó là mật khẩu của volume dữ
    # liệu hiện tại. Sinh mật khẩu mới sẽ khiến PostgreSQL không mở được dữ liệu cũ.
    if [[ -f "$ENV_FILE" ]]; then
        return
    fi

    step "Sinh .env"

    umask 077
    cat > "$ENV_FILE" <<EOF
# Sinh tự động bởi deploy/lab.sh lúc $(date -Is). Chỉ dùng cho LAB.
#
# docker compose tự nạp file này, nên sau khi có nó thì chạy được lệnh trần:
#   docker compose down -v && git pull && docker compose build && docker compose up -d

POSTGRES_PASSWORD=$(rand 32)

# Tài khoản quản trị đầu tiên. Đặt sẵn ở đây để nó ỔN ĐỊNH qua mỗi lần "down -v" —
# không có nó thì mỗi lần xóa volume lại sinh một mật khẩu mới, và bạn phải đi mò
# trong "docker compose logs bootstrap".
TIP_ADMIN_EMAIL=admin@vnnic.vn
TIP_ADMIN_PASSWORD=$(rand 24)

# Cổng trên máy host. Đổi ở đây nếu bị trùng với dịch vụ khác.
LAB_BLOCKLIST_PORT=8443
LAB_ADMIN_PORT=9443
LAB_OPENCTI_PORT=10443
LAB_POSTGRES_PORT=55433

# Chu kỳ ngắn để thấy kết quả nhanh khi thử nghiệm.
TIP_INGEST_INTERVAL=30m
TIP_POLICY_INTERVAL=10m
TIP_BUILD_INTERVAL=5m
TIP_LOG_LEVEL=info
EOF
    ok "đã ghi $ENV_FILE (quyền 600)"
    warn "Sao lưu file này: mất POSTGRES_PASSWORD là mất quyền đọc volume dữ liệu."
}

# ------------------------------------------------------------------ lệnh

cmd_up() {
    preflight
    setup_env

    step "Build image"
    info "lần đầu mất vài phút; các lần sau dùng cache"
    compose build || die "build thất bại"
    ok "image đã sẵn sàng"

    # "up -d" tự chờ service bootstrap chạy XONG trước khi khởi động phần còn lại —
    # đó là điều kiện service_completed_successfully trong compose.yaml. Nghĩa là
    # migration và tài khoản quản trị đã xong khi lệnh này trả về.
    step "Khởi động"
    compose up -d || die "khởi động thất bại"
    ok "stack đang chạy"

    cmd_urls
    cat <<EOF
    ${YELLOW}Lưu ý:${RESET} lần thu thập đầu tải khoảng 42 MB rồi nạp ~2,15 triệu domain.
    Trên máy lab việc này mất 10–20 phút, và các URL blocklist sẽ trả 503 cho tới khi
    có snapshot đầu tiên — đó là hành vi đúng, không phải lỗi.

    Theo dõi tiến trình:  ./deploy/lab.sh status

EOF
}

cmd_ingest() {
    preflight
    step "Chạy thu thập ngay"
    compose restart feed-ingestor
    ok "đã khởi động lại feed-ingestor; nó chạy một lượt ngay khi lên"
    info "theo dõi: ./deploy/lab.sh logs feed-ingestor"
}

cmd_status() {
    preflight
    [[ -f "$ENV_FILE" ]] || die "chưa có cấu hình. Chạy: ./deploy/lab.sh up"

    step "Container"
    compose ps --format '    {{.Service}}\t{{.Status}}' 2>/dev/null || compose ps

    step "Dữ liệu"
    local sql="SELECT
        (SELECT count(*) FROM domains)                          AS domains,
        (SELECT count(*) FROM domain_decisions
          WHERE action = 'BLOCK')                               AS blocked,
        (SELECT COALESCE(max(status::text), 'chua chay')
           FROM feed_imports)                                   AS last_import"
    if ! compose exec -T postgres psql -U tip -d tip -c "$sql" 2>/dev/null; then
        info "chưa đọc được (PostgreSQL đang khởi động, hoặc migration chưa chạy)"
    fi

    step "Đồng bộ OpenCTI"
    # Bảng rỗng nghĩa là chưa nhận sự kiện nào — hoặc OpenCTI chưa bật, hoặc
    # sync-consumer đang chờ. Cả hai đều bình thường khi chưa chạy 'lab.sh opencti'.
    local octi_sql="SELECT s.name AS nguon, s.enabled AS bat,
        COALESCE(st.last_event_id, '-')                              AS su_kien_cuoi,
        COALESCE(st.events_seen, 0)                                  AS da_nhan,
        (SELECT count(*) FROM domain_sources ds
          WHERE ds.source_id = s.id AND ds.active)                   AS domain,
        (SELECT count(*) FROM domain_sources ds
          WHERE ds.source_id = s.id AND ds.revoked_at IS NOT NULL)   AS da_thu_hoi
       FROM sources s
       LEFT JOIN opencti_stream_state st ON st.source_id = s.id
      WHERE s.origin = 'opencti'"
    if ! compose exec -T postgres psql -U tip -d tip -c "$octi_sql" 2>/dev/null; then
        info "chưa đọc được (CSDL đang khởi động, hoặc migration chưa chạy)"
    fi

    step "Snapshot"
    local bport code
    bport=$(env_get LAB_BLOCKLIST_PORT 8443)
    code=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 5 \
        "https://localhost:${bport}/blocklist/manifest.json" 2>/dev/null || echo 000)

    case "$code" in
        200) ok "đã có snapshot — blocklist đang phục vụ"
             curl -sk --max-time 5 "https://localhost:${bport}/blocklist/manifest.json" \
                 | head -c 400; echo ;;
        503) info "chưa có snapshot. Bình thường cho tới khi lần thu thập đầu xong." ;;
        000) warn "không kết nối được tới nginx. Xem: ./deploy/lab.sh logs nginx" ;;
        *)   warn "manifest trả về HTTP $code" ;;
    esac
    echo
}

cmd_urls() {
    [[ -f "$ENV_FILE" ]] || die "chưa có cấu hình. Chạy: ./deploy/lab.sh up"

    local bport aport email pw
    bport=$(env_get LAB_BLOCKLIST_PORT 8443)
    aport=$(env_get LAB_ADMIN_PORT 9443)
    email=$(env_get TIP_ADMIN_EMAIL admin@vnnic.vn)
    pw=$(env_get TIP_ADMIN_PASSWORD)
    [[ -n "$pw" ]] || pw="(xem: docker compose logs bootstrap)"

    # Chỉ hiện phần OpenCTI khi nó đã được cấu hình.
    local OCTI_BLOCK=""
    if opencti_enabled; then
        local oport oemail opw
        oport=$(env_get LAB_OPENCTI_PORT 10443)
        oemail=$(env_get OPENCTI_ADMIN_EMAIL admin@vnnic.vn)
        opw=$(env_get OPENCTI_ADMIN_PASSWORD)
        OCTI_BLOCK="  ${BLUE}OpenCTI${RESET}
      https://localhost:${oport}
      Tài khoản  ${oemail}
      Mật khẩu   ${opw}

"
    fi

    cat <<EOF

${BOLD}Truy cập${RESET}

  ${BLUE}Dashboard quản trị${RESET}
      https://localhost:${aport}
      Tài khoản  ${email}
      Mật khẩu   ${pw}

  ${BLUE}Blocklist công khai${RESET} — dán vào cấu hình Blocky
      https://localhost:${bport}/blocklist/malware.txt
      https://localhost:${bport}/blocklist/phishing.txt
      https://localhost:${bport}/blocklist/all.txt
      https://localhost:${bport}/blocklist/manifest.json

${OCTI_BLOCK}  Chứng thư là bản TỰ KÝ nên trình duyệt sẽ cảnh báo. Với curl thêm cờ -k:
      curl -k https://localhost:${bport}/blocklist/manifest.json

  Truy cập từ máy khác trong lab: thay localhost bằng IP của máy chủ này.

EOF
}

cmd_logs() {
    preflight
    if [[ $# -gt 0 ]]; then
        compose logs -f --tail 100 "$@"
    else
        compose logs -f --tail 50
    fi
}

# ------------------------------------------------------------------ OpenCTI

# setup_opencti_env bổ sung bí mật OpenCTI vào .env.
#
# Ghi vào CÙNG file .env chứ không tách ra file riêng: docker compose chỉ tự nạp đúng
# một file .env, và mục tiêu của cả thiết kế này là lệnh docker compose trần chạy được
# mà không cần --env-file.
setup_opencti_env() {
    # KHÔNG ghi đè. OPENCTI_ENCRYPTION_KEY gắn với dữ liệu đã nằm trong Elasticsearch và
    # MinIO; sinh khóa mới là mất khả năng giải mã dữ liệu cũ.
    if opencti_enabled; then
        ok "đã có bí mật OpenCTI trong .env, giữ nguyên"
        return
    fi

    local oport token
    oport=$(env_get LAB_OPENCTI_PORT 10443)
    token=$(uuid4)

    umask 077
    cat >> "$ENV_FILE" <<EOF

# ---------------------------------------------------------------- OpenCTI
# Bổ sung bởi deploy/lab.sh lúc $(date -Is).
#
# SAO LƯU: mất OPENCTI_ENCRYPTION_KEY là không giải mã được dữ liệu đã lưu.

# Để docker compose trần nạp luôn lớp phủ OpenCTI. Đường dẫn tính từ gốc repo, nên
# hãy chạy docker compose ở đó.
COMPOSE_FILE=compose.yaml:deploy/docker-compose/docker-compose.opencti.yml

OPENCTI_VERSION=7.260907.0

OPENCTI_ADMIN_EMAIL=admin@vnnic.vn
OPENCTI_ADMIN_PASSWORD=$(rand 24)
OPENCTI_ADMIN_TOKEN=$token
OPENCTI_ENCRYPTION_KEY=$(rand 48)
OPENCTI_HEALTHCHECK_ACCESS_KEY=$(rand 32)
OPENCTI_HOST_PORT=8081
OPENCTI_BASE_URL=https://localhost:${oport}

# sync-consumer đọc hai biến này. Token dùng chung với tài khoản quản trị vì đây là
# cài đặt nội bộ; trước khi mở dịch vụ ra ngoài VNNIC phải tạo service account riêng
# chỉ có quyền đọc stream.
TIP_OPENCTI_URL=http://opencti:8080
TIP_OPENCTI_TOKEN=$token
TIP_OPENCTI_STREAM_ID=

MINIO_ROOT_USER=opencti
MINIO_ROOT_PASSWORD=$(rand 32)

RABBITMQ_DEFAULT_USER=opencti
RABBITMQ_DEFAULT_PASS=$(rand 32)

# Cấu hình gọn cho lab. Production cần nhiều hơn.
ELASTIC_MEMORY_SIZE=2G
OPENCTI_NODE_HEAP=2048
OPENCTI_WORKER_REPLICAS=1

# Mỗi connector một UUID riêng: trùng ID thì hai connector tranh nhau cùng hàng đợi.
CONNECTOR_EXPORT_FILE_STIX_ID=$(uuid4)
CONNECTOR_EXPORT_FILE_CSV_ID=$(uuid4)
CONNECTOR_EXPORT_FILE_TXT_ID=$(uuid4)
CONNECTOR_IMPORT_FILE_STIX_ID=$(uuid4)
CONNECTOR_IMPORT_DOCUMENT_ID=$(uuid4)
CONNECTOR_OPENCTI_ID=$(uuid4)
CONNECTOR_MITRE_ID=$(uuid4)
EOF
    ok "đã bổ sung bí mật OpenCTI vào .env"
}

check_max_map_count() {
    local required=262144 current
    current=$(sysctl -n vm.max_map_count 2>/dev/null || echo 0)

    if [[ "${current:-0}" -ge $required ]]; then
        ok "vm.max_map_count = $current"
        return
    fi

    warn "vm.max_map_count = ${current:-khong doc duoc}, cần >= $required"
    warn "Elasticsearch sẽ THOÁT HẲN nếu thiếu. Chạy lệnh sau rồi thử lại:"
    printf '\n        sudo sysctl -w vm.max_map_count=%s\n\n' "$required"
    warn "Giữ qua reboot:"
    printf '        echo "vm.max_map_count=%s" | sudo tee /etc/sysctl.d/99-opencti.conf\n\n' "$required"

    if [[ -f /proc/version ]] && grep -qiE "microsoft|wsl" /proc/version 2>/dev/null; then
        warn "Đang chạy trên WSL: đặt giá trị này trong WSL, không phải Windows."
    fi
    die "dừng lại để tránh Elasticsearch khởi động rồi chết ngay."
}

cmd_opencti() {
    preflight
    [[ -f "$ENV_FILE" ]] || die "chưa có stack. Chạy: ./deploy/lab.sh up"

    step "Kiểm tra tài nguyên"
    if [[ -r /proc/meminfo ]]; then
        local total_mb
        total_mb=$(( $(awk '/MemTotal/ {print $2}' /proc/meminfo) / 1024 ))
        info "RAM tổng: ${total_mb} MB"
        if [[ $total_mb -lt 12000 ]]; then
            warn "OpenCTI cần khoảng 8-16 GB NGOÀI phần stack chính đang dùng."
            warn "Máy này có ${total_mb} MB — Elasticsearch nhiều khả năng bị OOM killer giết."
            local reply
            read -r -p "    Vẫn tiếp tục? [y/N] " reply </dev/tty || reply=n
            [[ "$reply" =~ ^[Yy]$ ]] || die "dừng lại."
        fi
    else
        warn "không đọc được /proc/meminfo, bỏ qua kiểm tra RAM"
    fi

    check_max_map_count

    step "Cấu hình OpenCTI"
    setup_opencti_env

    step "Tải image"
    info "cụm này vài GB, lần đầu có thể rất lâu"
    compose pull --quiet opencti opencti-worker elasticsearch redis minio rabbitmq \
        || die "docker pull thất bại"

    # up -d dựng lại cả stack chính: bootstrap chạy lại và bật nguồn 'opencti', còn
    # sync-consumer nhận URL và token vừa ghi vào .env. Không có bước này thì container
    # đang chạy vẫn giữ cấu hình rỗng từ trước.
    step "Khởi động OpenCTI"
    compose up -d || die "khởi động thất bại"
    ok "container đã lên"

    step "Chờ OpenCTI sẵn sàng"
    info "lần đầu phải tạo toàn bộ chỉ mục Elasticsearch; vài phút là bình thường"
    local key waited=0
    key=$(env_get OPENCTI_HEALTHCHECK_ACCESS_KEY)
    until curl -fsS --max-time 5 \
        "http://127.0.0.1:$(env_get OPENCTI_HOST_PORT 8081)/health?health_access_key=${key}" >/dev/null 2>&1; do
        sleep 10
        waited=$((waited + 10))
        if [[ $waited -ge 900 ]]; then
            warn "quá 15 phút mà chưa sẵn sàng"
            warn "xem nhật ký: ./deploy/lab.sh logs opencti"
            return
        fi
        [[ $((waited % 60)) -eq 0 ]] && info "còn chờ... ${waited}s"
    done
    ok "OpenCTI sẵn sàng sau ${waited}s"

    verify_sync

    cmd_urls
}

# verify_sync xác minh sync-consumer thật sự đã nối vào Live Stream.
#
# "docker compose up" thành công chỉ nghĩa là container khởi động được. sync-consumer
# vẫn khởi động bình thường khi thiếu token hoặc nguồn còn tắt — và chờ, một cách im
# lặng. Phải đọc nhật ký mới biết thật sự đã nối chưa.
verify_sync() {
    step "Kiểm tra đường đồng bộ"

    local waited=0 logs
    while [[ $waited -lt 60 ]]; do
        logs=$(compose logs --tail 50 sync-consumer 2>/dev/null || true)
        if grep -q 'bắt đầu nghe OpenCTI Live Stream' <<<"$logs"; then
            ok "sync-consumer đã nối vào Live Stream"
            return
        fi
        if grep -qE 'đứng yên|chưa bật nguồn' <<<"$logs"; then
            warn "sync-consumer chưa nối được — lý do nằm trong nhật ký:"
            warn "  ./deploy/lab.sh logs sync-consumer"
            return
        fi
        sleep 5
        waited=$((waited + 5))
    done

    warn "chưa xác nhận được sync-consumer sau ${waited}s"
    warn "  ./deploy/lab.sh logs sync-consumer"
}

# ------------------------------------------------------------------ dừng

cmd_down() {
    preflight
    step "Dừng stack"
    compose down
    ok "đã dừng. Dữ liệu vẫn còn — chạy 'up' để tiếp tục."
}

cmd_reset() {
    preflight
    step "XÓA SẠCH stack"
    warn "Lệnh này xóa TOÀN BỘ volume: CSDL, snapshot, chứng thư, và dữ liệu OpenCTI."
    local reply
    read -r -p "    Chắc chắn? [y/N] " reply </dev/tty || reply=n
    [[ "$reply" =~ ^[Yy]$ ]] || die "dừng lại."

    compose down -v
    ok "đã xóa sạch. Chạy 'up' để dựng lại từ đầu."
    info ".env được giữ nguyên, nên mật khẩu và cổng không đổi."
}

usage() {
    cat <<'EOF'
CyberDNS TIP - tien ich quanh compose.yaml o goc repo.

Script nay KHONG bat buoc. Stack chay duoc bang docker compose tran:

  docker compose down -v && git pull && docker compose build && docker compose up -d

Viec duy nhat docker compose khong tu lam duoc la sinh bi mat ngau nhien, nen
`lab.sh up` chu yeu de tao file .env lan dau.

  ./deploy/lab.sh up        sinh .env neu chua co, build va khoi dong
  ./deploy/lab.sh status    trang thai container, du lieu, dong bo OpenCTI
  ./deploy/lab.sh logs      xem log (them ten service de loc)
  ./deploy/lab.sh ingest    chay thu thap ngay, khong cho het chu ky
  ./deploy/lab.sh urls      in lai URL va thong tin dang nhap
  ./deploy/lab.sh opencti   bat them OpenCTI (can khoang 16 GB RAM)
  ./deploy/lab.sh down      dung, GIU du lieu
  ./deploy/lab.sh reset     dung va XOA SACH du lieu
EOF
}

main() {
    local cmd="${1:-up}"
    [[ $# -gt 0 ]] && shift

    case "$cmd" in
        up)      cmd_up ;;
        urls)    cmd_urls ;;
        status)  cmd_status ;;
        ingest)  cmd_ingest ;;
        logs)    cmd_logs "$@" ;;
        opencti) cmd_opencti ;;
        down)    cmd_down ;;
        reset)   cmd_reset ;;
        -h|--help|help) usage ;;
        *)       die "lệnh không nhận ra: $cmd (xem --help)" ;;
    esac
}

main "$@"
