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
LAB_POSTGRES_PORT=55433

# Chu kỳ ngắn để thấy kết quả nhanh khi thử nghiệm.
TIP_INGEST_INTERVAL=30m
TIP_POLICY_INTERVAL=10m
TIP_BUILD_INTERVAL=5m
TIP_LOG_LEVEL=info
EOF
    ok "đã ghi $(basename "$ENV_FILE")"
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

  Chứng thư là bản TỰ KÝ nên trình duyệt sẽ cảnh báo. Với curl thêm cờ -k:
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

cmd_opencti() {
    preflight
    [[ -f "$COMPOSE_DIR/.env.opencti" ]] \
        || die "chưa có .env.opencti. Chạy: sudo ./deploy/install-opencti.sh"

    step "Khởi động OpenCTI"
    warn "cụm này cần khoảng 16 GB RAM ngoài phần stack chính đang dùng"
    warn "Elasticsearch cần vm.max_map_count >= 262144 trên HOST:"
    warn "  sudo sysctl -w vm.max_map_count=262144"

    compose_all up -d
    ok "đã lên. Giao diện: http://localhost:8081 (chỉ loopback)"
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
