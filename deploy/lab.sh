#!/usr/bin/env bash
#
# CyberDNS TIP — điều khiển stack lab.
#
#   ./deploy/lab.sh up        dựng và khởi động toàn bộ, in ra URL và mật khẩu
#   ./deploy/lab.sh status    trạng thái container và dữ liệu
#   ./deploy/lab.sh logs      xem log
#   ./deploy/lab.sh ingest    chạy thu thập ngay, không chờ hết chu kỳ
#   ./deploy/lab.sh urls      in lại URL và thông tin đăng nhập
#   ./deploy/lab.sh opencti   bật thêm OpenCTI (cần khoảng 16 GB RAM)
#   ./deploy/lab.sh down      dừng, GIỮ dữ liệu
#   ./deploy/lab.sh reset     dừng và XÓA SẠCH dữ liệu
#
# Chạy lại `up` nhiều lần được: mỗi bước tự kiểm tra trạng thái trước khi làm.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_DIR="$REPO_ROOT/deploy/docker-compose"
LAB_FILE="$COMPOSE_DIR/docker-compose.lab.yml"
OCTI_FILE="$COMPOSE_DIR/docker-compose.opencti.yml"
ENV_FILE="$COMPOSE_DIR/.env.lab"
ADMIN_FILE="$COMPOSE_DIR/.lab-admin"

RED=$'\033[31m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'
BLUE=$'\033[36m'; BOLD=$'\033[1m'; RESET=$'\033[0m'

step() { printf '\n%s==> %s%s\n' "$BOLD" "$*" "$RESET"; }
info() { printf '    %s\n' "$*"; }
ok()   { printf '    %s✓%s %s\n' "$GREEN" "$RESET" "$*"; }
warn() { printf '    %s!%s %s\n' "$YELLOW" "$RESET" "$*" >&2; }
die()  { printf '\n%sLỗi:%s %s\n' "$RED" "$RESET" "$*" >&2; exit 1; }

compose() {
    docker compose -f "$LAB_FILE" --env-file "$ENV_FILE" "$@"
}

compose_all() {
    docker compose -f "$LAB_FILE" -f "$OCTI_FILE" \
        --env-file "$ENV_FILE" --env-file "$COMPOSE_DIR/.env.opencti" "$@"
}

# ------------------------------------------------------------------ tiền kiểm

preflight() {
    command -v docker >/dev/null 2>&1 \
        || die "chưa cài docker. Xem https://docs.docker.com/engine/install/"

    docker compose version >/dev/null 2>&1 \
        || die "chưa có plugin 'docker compose' v2. Bản docker-compose v1 không dùng được."

    docker info >/dev/null 2>&1 \
        || die "không nói chuyện được với Docker daemon. Daemon đã chạy chưa, và người dùng hiện tại có trong nhóm docker không?"

    [[ -f "$LAB_FILE" ]] || die "không thấy $LAB_FILE"
}

# ------------------------------------------------------------------ cấu hình

setup_env() {
    # KHÔNG ghi đè file đã có: POSTGRES_PASSWORD trong đó là mật khẩu của volume dữ
    # liệu hiện tại. Sinh mật khẩu mới sẽ khiến PostgreSQL không mở được dữ liệu cũ.
    if [[ -f "$ENV_FILE" ]]; then
        return
    fi

    step "Sinh cấu hình lab"

    local pw
    if command -v openssl >/dev/null 2>&1; then
        pw=$(openssl rand -hex 16)
    else
        pw=$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' | head -c 32)
    fi

    umask 077
    cat > "$ENV_FILE" <<EOF
# Sinh tự động bởi deploy/lab.sh lúc $(date -Is). Chỉ dùng cho LAB.
POSTGRES_PASSWORD=$pw

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
    ok "đã ghi $(basename "$ENV_FILE")"
}

# uuid4 sinh một UUID phiên bản 4 mà không cần uuidgen — gói đó không có sẵn ở nhiều
# bản phân phối tối giản.
uuid4() {
    local h
    h=$(od -An -tx1 -N16 /dev/urandom | tr -d ' 
')
    printf '%s-%s-4%s-a%s-%s
'         "${h:0:8}" "${h:8:4}" "${h:13:3}" "${h:17:3}" "${h:20:12}"
}

port_of() {
    local key="$1" fallback="$2"
    local v
    v=$(grep -E "^${key}=" "$ENV_FILE" 2>/dev/null | cut -d= -f2 | tr -d '[:space:]')
    printf '%s' "${v:-$fallback}"
}

# ------------------------------------------------------------------ lệnh

cmd_up() {
    preflight
    setup_env

    step "Build image"
    info "lần đầu mất vài phút; các lần sau dùng cache"
    compose build || die "build thất bại"
    ok "image đã sẵn sàng"

    step "Khởi động PostgreSQL"
    compose up -d postgres
    local waited=0
    until compose exec -T postgres pg_isready -U tip -d tip >/dev/null 2>&1; do
        sleep 2
        waited=$((waited + 2))
        [[ $waited -ge 120 ]] && die "PostgreSQL không sẵn sàng sau 120 giây"
    done
    ok "PostgreSQL sẵn sàng"

    step "Chạy migration"
    compose run --rm --no-deps feed-ingestor \
        /usr/local/bin/feed-ingestor -config /etc/cyberdns-tip/configs/feed-ingestor.yaml -migrate \
        || die "migration thất bại"
    ok "lược đồ đã cập nhật"

    step "Tài khoản quản trị"
    if [[ -f "$ADMIN_FILE" ]]; then
        ok "đã có, giữ nguyên"
    else
        local out
        out=$(compose run --rm --no-deps admin-api \
            /usr/local/bin/admin-api -config /etc/cyberdns-tip/configs/admin-api.yaml \
            -create-admin admin@vnnic.vn 2>&1) || die "tạo tài khoản thất bại: $out"

        local pw
        pw=$(printf '%s' "$out" | grep -oE '[A-Za-z0-9_-]{20,}' | tail -1)
        [[ -n "$pw" ]] || die "không đọc được mật khẩu từ đầu ra: $out"

        umask 077
        printf 'admin@vnnic.vn\n%s\n' "$pw" > "$ADMIN_FILE"
        ok "đã tạo admin@vnnic.vn"
    fi

    step "Khởi động toàn bộ dịch vụ"
    compose up -d
    ok "đã lên"

    cmd_urls
    cat <<EOF
    ${YELLOW}Lưu ý:${RESET} lần thu thập đầu tải khoảng 42 MB rồi nạp ~2,15 triệu domain.
    Trên máy lab việc này mất 10–20 phút, và các URL blocklist sẽ trả 503 cho tới khi
    có snapshot đầu tiên — đó là hành vi đúng, không phải lỗi.

    Theo dõi tiến trình:  ./deploy/lab.sh status

EOF
}

cmd_urls() {
    [[ -f "$ENV_FILE" ]] || die "chưa có cấu hình lab. Chạy: ./deploy/lab.sh up"

    local bport aport
    bport=$(port_of LAB_BLOCKLIST_PORT 8443)
    aport=$(port_of LAB_ADMIN_PORT 9443)

    local email="admin@vnnic.vn" pw="(chưa tạo)"
    if [[ -f "$ADMIN_FILE" ]]; then
        email=$(sed -n 1p "$ADMIN_FILE")
        pw=$(sed -n 2p "$ADMIN_FILE")
    fi

    # Chỉ hiện phần OpenCTI khi nó đã được cấu hình.
    local OCTI_BLOCK=""
    if [[ -f "$COMPOSE_DIR/.env.opencti" ]]; then
        local oport oemail opw
        oport=$(port_of LAB_OPENCTI_PORT 10443)
        oemail=$(grep -E '^OPENCTI_ADMIN_EMAIL=' "$COMPOSE_DIR/.env.opencti" | cut -d= -f2)
        opw=$(grep -E '^OPENCTI_ADMIN_PASSWORD=' "$COMPOSE_DIR/.env.opencti" | cut -d= -f2)
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

cmd_status() {
    preflight
    [[ -f "$ENV_FILE" ]] || die "chưa có cấu hình lab. Chạy: ./deploy/lab.sh up"

    step "Container"
    compose ps --format '    {{.Service}}\t{{.Status}}' 2>/dev/null \
        || compose ps

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
    # sync-consumer đang đứng yên. Cả hai đều bình thường khi chưa chạy 'lab.sh opencti'.
    local octi_sql="SELECT s.name AS nguon, s.enabled AS bat,
        COALESCE(st.last_event_id, '-')                       AS su_kien_cuoi,
        COALESCE(st.events_seen, 0)                           AS da_nhan,
        (SELECT count(*) FROM domain_sources ds
          WHERE ds.source_id = s.id AND ds.active)            AS domain,
        (SELECT count(*) FROM domain_sources ds
          WHERE ds.source_id = s.id AND ds.revoked_at IS NOT NULL) AS da_thu_hoi
       FROM sources s
       LEFT JOIN opencti_stream_state st ON st.source_id = s.id
      WHERE s.origin = 'opencti'"
    if ! compose exec -T postgres psql -U tip -d tip -c "$octi_sql" 2>/dev/null; then
        info "chưa đọc được (CSDL đang khởi động, hoặc migration chưa chạy)"
    fi

    step "Snapshot"
    local bport
    bport=$(port_of LAB_BLOCKLIST_PORT 8443)
    local code
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

cmd_ingest() {
    preflight
    step "Chạy thu thập ngay"
    info "khởi động lại feed-ingestor; nó chạy một lượt ngay khi lên"
    compose restart feed-ingestor
    ok "đã kích hoạt. Theo dõi: ./deploy/lab.sh logs feed-ingestor"
}

cmd_logs() {
    preflight
    if [[ $# -gt 0 ]]; then
        compose logs -f --tail 100 "$@"
    else
        compose logs -f --tail 50
    fi
}

# setup_opencti_env sinh cấu hình OpenCTI cho lab.
#
# Không dùng deploy/install-opencti.sh: script đó viết cho production, đòi file .env của
# bản production và dùng docker-compose.prod.yml. Trong lab cả hai đều không tồn tại.
setup_opencti_env() {
    local f="$COMPOSE_DIR/.env.opencti"

    # KHÔNG ghi đè. OPENCTI_ENCRYPTION_KEY gắn với dữ liệu đã nằm trong Elasticsearch và
    # MinIO; sinh khóa mới là mất khả năng giải mã dữ liệu cũ.
    if [[ -f "$f" ]]; then
        ok "đã có .env.opencti, giữ nguyên"
        return
    fi

    command -v openssl >/dev/null 2>&1 || die "cần openssl để sinh bí mật cho OpenCTI"

    local admin_pass minio_pass rabbit_pass
    admin_pass=$(openssl rand -base64 24 | tr -d '
/+=' | head -c 24)
    minio_pass=$(openssl rand -base64 32 | tr -d '
/+=' | head -c 32)
    rabbit_pass=$(openssl rand -base64 32 | tr -d '
/+=' | head -c 32)

    umask 077
    cat > "$f" <<EOF
# Sinh tự động bởi deploy/lab.sh lúc $(date -Is). Chỉ dùng cho LAB.
#
# SAO LƯU FILE NÀY nếu dữ liệu trong lab có giá trị: mất OPENCTI_ENCRYPTION_KEY là
# không giải mã được dữ liệu đã lưu.

OPENCTI_VERSION=7.260907.0

OPENCTI_ADMIN_EMAIL=admin@vnnic.vn
OPENCTI_ADMIN_PASSWORD=$admin_pass
OPENCTI_ADMIN_TOKEN=$(uuid4)
OPENCTI_ENCRYPTION_KEY=$(openssl rand -base64 32)
OPENCTI_HEALTHCHECK_ACCESS_KEY=$(openssl rand -hex 16)
OPENCTI_HOST_PORT=8081
OPENCTI_BASE_URL=https://localhost:${LAB_OPENCTI_PORT:-10443}

MINIO_ROOT_USER=opencti
MINIO_ROOT_PASSWORD=$minio_pass

RABBITMQ_DEFAULT_USER=opencti
RABBITMQ_DEFAULT_PASS=$rabbit_pass

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
    ok "đã sinh .env.opencti với bí mật ngẫu nhiên"
}

# check_max_map_count là nguyên nhân số một khiến Elasticsearch không khởi động được.
# Nó không chạy ở chế độ suy giảm mà thoát hẳn.
check_max_map_count() {
    local required=262144 current
    current=$(sysctl -n vm.max_map_count 2>/dev/null || echo 0)

    if [[ "${current:-0}" -ge $required ]]; then
        ok "vm.max_map_count = $current"
        return
    fi

    warn "vm.max_map_count = ${current:-khong doc duoc}, cần >= $required"
    warn "Elasticsearch sẽ THOÁT HẲN nếu thiếu. Chạy lệnh sau rồi thử lại:"
    printf '
        sudo sysctl -w vm.max_map_count=%s

' "$required"
    warn "Giữ qua reboot:"
    printf '        echo "vm.max_map_count=%s" | sudo tee /etc/sysctl.d/99-opencti.conf

' "$required"

    if [[ -f /proc/version ]] && grep -qiE "microsoft|wsl" /proc/version 2>/dev/null; then
        warn "Đang chạy trên WSL: đặt giá trị này trong WSL, không phải Windows."
    fi
    die "dừng lại để tránh Elasticsearch khởi động rồi chết ngay."
}

cmd_opencti() {
    preflight
    [[ -f "$ENV_FILE" ]] || die "chưa có stack lab. Chạy: ./deploy/lab.sh up"

    step "Kiểm tra tài nguyên"
    if [[ -r /proc/meminfo ]]; then
        local total_mb
        total_mb=$(( $(awk '/MemTotal/ {print $2}' /proc/meminfo) / 1024 ))
        info "RAM tổng: ${total_mb} MB"
        if [[ $total_mb -lt 12000 ]]; then
            warn "OpenCTI cần khoảng 8-16 GB NGOÀI phần stack chính đang dùng."
            warn "Máy này có ${total_mb} MB — Elasticsearch nhiều khả năng bị OOM killer giết."
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
    compose_all pull --quiet opencti opencti-worker elasticsearch redis minio rabbitmq         || die "docker pull thất bại"

    step "Khởi động OpenCTI"
    compose_all up -d || die "khởi động thất bại"
    ok "container đã lên"

    step "Chờ OpenCTI sẵn sàng"
    info "lần đầu phải tạo toàn bộ chỉ mục Elasticsearch; vài phút là bình thường"
    local key waited=0
    key=$(grep -E '^OPENCTI_HEALTHCHECK_ACCESS_KEY=' "$COMPOSE_DIR/.env.opencti" | cut -d= -f2)
    until curl -fsS --max-time 5         "http://127.0.0.1:8081/health?health_access_key=${key}" >/dev/null 2>&1; do
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

    connect_pipeline

    cmd_urls
}

# connect_pipeline bật nguồn 'opencti' rồi dựng lại sync-consumer.
#
# Nguồn 'opencti' được seed ở trạng thái TẮT vì trước P4 chưa có gì đọc nó. Bật ở đây
# chứ không phải trong migration: bật sẵn một nguồn mà không có consumer nào chạy sẽ
# làm dashboard báo nguồn "quá hạn" mãi mãi.
#
# Cả hai thao tác đều idempotent — chạy lại bao nhiêu lần cũng được.
connect_pipeline() {
    step "Nối OpenCTI vào đường sinh blocklist"

    if compose exec -T postgres psql -U tip -d tip -q         -c "UPDATE sources SET enabled = TRUE, updated_at = NOW()
             WHERE name = 'opencti' AND origin = 'opencti'" >/dev/null 2>&1; then
        ok "đã bật nguồn 'opencti'"
    else
        warn "chưa bật được nguồn 'opencti' — bật tay trên dashboard, mục Nguồn dữ liệu"
    fi

    # sync-consumer đọc URL và token lúc khởi động, nên container đang chạy vẫn giữ
    # cấu hình rỗng từ trước khi có OpenCTI. Phải dựng lại.
    if ! compose_all up -d --force-recreate sync-consumer >/dev/null 2>&1; then
        warn "chưa dựng lại được sync-consumer; xem ./deploy/lab.sh logs sync-consumer"
        return
    fi

    # Xác minh thật thay vì tin rằng container lên là xong.
    #
    # "docker compose up" thành công chỉ nghĩa là container khởi động được. Nó vẫn khởi
    # động bình thường khi thiếu token hoặc nguồn còn tắt — và đứng yên. Đó là hành vi
    # cố ý, nhưng im lặng, nên phải đọc nhật ký mới biết thật sự đã nối chưa.
    local waited=0 logs
    while [[ $waited -lt 30 ]]; do
        logs=$(compose_all logs --tail 40 sync-consumer 2>/dev/null || true)
        if grep -q 'bắt đầu nghe OpenCTI Live Stream' <<<"$logs"; then
            ok "sync-consumer đã nối vào Live Stream"
            return
        fi
        if grep -q 'đứng yên' <<<"$logs"; then
            warn "sync-consumer đang đứng yên — lý do nằm trong nhật ký:"
            warn "  ./deploy/lab.sh logs sync-consumer"
            return
        fi
        sleep 3
        waited=$((waited + 3))
    done

    warn "chưa xác nhận được sync-consumer sau ${waited}s"
    warn "  ./deploy/lab.sh logs sync-consumer"
}

cmd_down() {
    preflight
    step "Dừng stack"
    compose down
    ok "đã dừng. Dữ liệu vẫn còn — chạy 'up' để tiếp tục."
}

cmd_reset() {
    preflight
    step "XÓA SẠCH stack lab"
    warn "Thao tác này xóa CSDL, snapshot và tài khoản quản trị."
    read -r -p "    Gõ 'xoa' để xác nhận: " reply </dev/tty || true
    [[ "$reply" == "xoa" ]] || die "đã hủy."

    compose down -v
    rm -f "$ADMIN_FILE"
    ok "đã xóa sạch. File cấu hình $(basename "$ENV_FILE") vẫn giữ."
}

usage() {
    cat <<'EOF'
CyberDNS TIP - dieu khien stack lab.

  ./deploy/lab.sh up        dung va khoi dong toan bo, in ra URL va mat khau
  ./deploy/lab.sh status    trang thai container va du lieu
  ./deploy/lab.sh logs      xem log (them ten service de loc)
  ./deploy/lab.sh ingest    chay thu thap ngay, khong cho het chu ky
  ./deploy/lab.sh urls      in lai URL va thong tin dang nhap
  ./deploy/lab.sh opencti   bat them OpenCTI (can khoang 16 GB RAM)
  ./deploy/lab.sh down      dung, GIU du lieu
  ./deploy/lab.sh reset     dung va XOA SACH du lieu

Chay lai `up` nhieu lan duoc: moi buoc tu kiem tra trang thai truoc khi lam.
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
