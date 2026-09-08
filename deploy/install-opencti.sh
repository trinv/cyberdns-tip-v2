#!/usr/bin/env bash
#
# Cài đặt tầng OpenCTI của CyberDNS TIP.
#
#   sudo ./deploy/install-opencti.sh
#
# Chạy sau deploy/install.sh. Script này chạy lại được nhiều lần: mỗi bước tự kiểm tra
# trạng thái trước khi làm, và không bao giờ ghi đè file .env.opencti đã tồn tại.
#
# Cụm này NẶNG. Xem deploy/opencti/README.md để biết yêu cầu tài nguyên thật.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_DIR="$REPO_ROOT/deploy/docker-compose"
MAIN_COMPOSE="$COMPOSE_DIR/docker-compose.prod.yml"
OCTI_COMPOSE="$COMPOSE_DIR/docker-compose.opencti.yml"
ENV_FILE="$COMPOSE_DIR/.env.opencti"

WITH_MITRE=0
ASSUME_YES=0

RED=$'\033[31m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'; BOLD=$'\033[1m'; RESET=$'\033[0m'

step()  { printf '\n%s==> %s%s\n' "$BOLD" "$*" "$RESET"; }
info()  { printf '    %s\n' "$*"; }
ok()    { printf '    %s✓%s %s\n' "$GREEN" "$RESET" "$*"; }
warn()  { printf '    %s!%s %s\n' "$YELLOW" "$RESET" "$*" >&2; }
die()   { printf '\n%sLỗi:%s %s\n' "$RED" "$RESET" "$*" >&2; exit 1; }
have()  { command -v "$1" >/dev/null 2>&1; }

confirm() {
    [[ $ASSUME_YES -eq 1 ]] && return 0
    local reply
    read -r -p "    $1 [y/N] " reply </dev/tty || return 1
    [[ "$reply" =~ ^[Yy]$ ]]
}

usage() {
    cat <<EOF
Cài đặt tầng OpenCTI của CyberDNS TIP.

  --with-mitre   Bật kèm connector MITRE ATT&CK. Lần đồng bộ đầu nặng và kéo dài
                 hàng chục phút; có thể bật sau bằng:
                   docker compose --profile mitre -f ... up -d connector-mitre
  --yes          Không hỏi xác nhận
  --help
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --with-mitre) WITH_MITRE=1; shift ;;
        --yes|-y)     ASSUME_YES=1; shift ;;
        --help|-h)    usage; exit 0 ;;
        *)            die "tham số không nhận ra: $1 (xem --help)" ;;
    esac
done

compose() {
    local args=(-f "$MAIN_COMPOSE" -f "$OCTI_COMPOSE" --env-file "$COMPOSE_DIR/.env" --env-file "$ENV_FILE")
    [[ $WITH_MITRE -eq 1 ]] && args+=(--profile mitre)
    docker compose "${args[@]}" "$@"
}

# ------------------------------------------------------------------ tiền kiểm

preflight() {
    step "Kiểm tra môi trường"

    [[ $EUID -eq 0 ]] || die "cần chạy bằng root: sudo $0"
    have docker || die "chưa cài docker"
    docker compose version >/dev/null 2>&1 || die "chưa có plugin 'docker compose' v2"

    [[ -f "$OCTI_COMPOSE" ]] || die "không thấy $OCTI_COMPOSE"
    [[ -f "$MAIN_COMPOSE" ]] || die "không thấy $MAIN_COMPOSE"

    # Stack chính phải dựng trước: hai bên dùng chung một project và một mạng Docker.
    [[ -f "$COMPOSE_DIR/.env" ]] \
        || die "chưa có $COMPOSE_DIR/.env — hãy chạy deploy/install.sh trước"

    have uuidgen || die "thiếu uuidgen (gói uuid-runtime trên Debian/Ubuntu)"
    have openssl || die "thiếu openssl"
    ok "docker, compose v2, uuidgen, openssl đã sẵn sàng"
}

# ------------------------------------------------------------------ tài nguyên

check_resources() {
    step "Kiểm tra tài nguyên"

    local total_mb
    total_mb=$(( $(awk '/MemTotal/ {print $2}' /proc/meminfo) / 1024 ))
    info "RAM tổng: ${total_mb} MB"

    # Con số này không phải ước lượng dè dặt: Elasticsearch 4G heap dễ chạm 8G RSS,
    # nền tảng OpenCTI thêm 4G, ba worker cùng Redis/RabbitMQ/MinIO thêm vài GB nữa
    # — và stack chính vẫn đang chạy song song trên cùng máy.
    if [[ $total_mb -lt 16000 ]]; then
        warn "OpenCTI cần tối thiểu 16 GB RAM để chạy được, 32 GB để chạy thoải mái."
        warn "Máy này có ${total_mb} MB. Elasticsearch nhiều khả năng bị OOM killer giết."
        confirm "Vẫn tiếp tục?" || die "dừng lại."
    else
        ok "RAM đủ"
    fi

    local free_gb
    free_gb=$(df -BG --output=avail /var/lib/docker 2>/dev/null | tail -n1 | tr -dc '0-9' || echo 0)
    info "dung lượng trống ở /var/lib/docker: ${free_gb} GB"
    if [[ ${free_gb:-0} -lt 50 ]]; then
        warn "Nên có ít nhất 50 GB trống. Chỉ số Elasticsearch phình theo lượng CTI nhập vào."
        confirm "Vẫn tiếp tục?" || die "dừng lại."
    fi
}

# Đây là nguyên nhân số một khiến Elasticsearch không khởi động được. Nó không cảnh
# báo mà thoát hẳn với "max virtual memory areas vm.max_map_count is too low".
set_max_map_count() {
    step "Cấu hình nhân hệ điều hành cho Elasticsearch"

    local required=262144 current
    current=$(sysctl -n vm.max_map_count 2>/dev/null || echo 0)
    info "vm.max_map_count hiện tại = $current (cần >= $required)"

    if [[ $current -ge $required ]]; then
        ok "đã đủ"
    else
        sysctl -w vm.max_map_count=$required >/dev/null
        ok "đã đặt vm.max_map_count=$required cho phiên này"
    fi

    # Đặt bằng sysctl -w sẽ mất sau khi khởi động lại máy, và khi đó Elasticsearch
    # không lên lại được. Ghi xuống file để tồn tại qua reboot.
    local conf=/etc/sysctl.d/99-opencti.conf
    if [[ -f "$conf" ]] && grep -q "vm.max_map_count=$required" "$conf"; then
        ok "đã lưu vĩnh viễn tại $conf"
    else
        printf '# Elasticsearch của OpenCTI cần giá trị này; thiếu nó ES không khởi động.\nvm.max_map_count=%s\n' \
            "$required" > "$conf"
        ok "đã ghi $conf để tồn tại qua reboot"
    fi
}

# ------------------------------------------------------------------ cấu hình

setup_env() {
    step "Cấu hình OpenCTI"

    # KHÔNG ghi đè. OPENCTI_ADMIN_TOKEN và OPENCTI_ENCRYPTION_KEY gắn với dữ liệu đã
    # nằm trong Elasticsearch và MinIO; sinh giá trị mới sẽ làm hỏng quyền truy cập
    # và không giải mã được dữ liệu cũ.
    if [[ -f "$ENV_FILE" ]]; then
        ok "đã có $(basename "$ENV_FILE"), giữ nguyên"
        return
    fi

    local admin_pass minio_pass rabbit_pass
    admin_pass=$(openssl rand -base64 24 | tr -d '\n/+=' | head -c 24)
    minio_pass=$(openssl rand -base64 32 | tr -d '\n/+=' | head -c 32)
    rabbit_pass=$(openssl rand -base64 32 | tr -d '\n/+=' | head -c 32)

    umask 077
    cat > "$ENV_FILE" <<EOF
# Sinh tự động bởi deploy/install-opencti.sh lúc $(date -Is)
#
# SAO LƯU FILE NÀY. Mất OPENCTI_ENCRYPTION_KEY là không giải mã được dữ liệu đã lưu.

OPENCTI_VERSION=7.260907.0

OPENCTI_ADMIN_EMAIL=admin@vnnic.vn
OPENCTI_ADMIN_PASSWORD=$admin_pass
OPENCTI_ADMIN_TOKEN=$(uuidgen)
OPENCTI_ENCRYPTION_KEY=$(openssl rand -base64 32)
OPENCTI_HEALTHCHECK_ACCESS_KEY=$(openssl rand -hex 16)
OPENCTI_HOST_PORT=8081
OPENCTI_BASE_URL=http://localhost:8081

MINIO_ROOT_USER=opencti
MINIO_ROOT_PASSWORD=$minio_pass

RABBITMQ_DEFAULT_USER=opencti
RABBITMQ_DEFAULT_PASS=$rabbit_pass

ELASTIC_MEMORY_SIZE=4G
OPENCTI_NODE_HEAP=4096
OPENCTI_WORKER_REPLICAS=3

# Mỗi connector một UUID riêng: trùng ID thì hai connector tranh nhau cùng hàng đợi.
CONNECTOR_EXPORT_FILE_STIX_ID=$(uuidgen)
CONNECTOR_EXPORT_FILE_CSV_ID=$(uuidgen)
CONNECTOR_EXPORT_FILE_TXT_ID=$(uuidgen)
CONNECTOR_IMPORT_FILE_STIX_ID=$(uuidgen)
CONNECTOR_IMPORT_DOCUMENT_ID=$(uuidgen)
CONNECTOR_OPENCTI_ID=$(uuidgen)
CONNECTOR_MITRE_ID=$(uuidgen)
EOF
    chmod 600 "$ENV_FILE"
    ok "đã sinh $ENV_FILE (quyền 600)"
    warn "SAO LƯU NGAY. Mất OPENCTI_ENCRYPTION_KEY là mất khả năng giải mã dữ liệu."
}

# ------------------------------------------------------------------ khởi động

start_stack() {
    OPENCTI_HOST_PORT=$(grep '^OPENCTI_HOST_PORT=' "$ENV_FILE" | cut -d= -f2)
    OPENCTI_HOST_PORT=${OPENCTI_HOST_PORT:-8081}

    step "Tải image"
    info "cụm này vài GB, lần đầu có thể lâu"
    compose pull --quiet opencti opencti-worker elasticsearch redis minio rabbitmq \
        || die "docker pull thất bại"
    ok "đã có image"

    step "Khởi động OpenCTI"
    compose up -d || die "docker compose up thất bại"
    ok "container đã lên"

    step "Chờ OpenCTI sẵn sàng"
    # Lần khởi động đầu OpenCTI phải tạo toàn bộ chỉ mục Elasticsearch và nạp dữ liệu
    # nền; mất vài phút là bình thường, đừng vội cho là hỏng.
    local waited=0 limit=900
    until curl -fsS --max-time 5 "http://127.0.0.1:${OPENCTI_HOST_PORT}/health?health_access_key=$(grep '^OPENCTI_HEALTHCHECK_ACCESS_KEY=' "$ENV_FILE" | cut -d= -f2)" >/dev/null 2>&1; do
        sleep 10
        waited=$((waited + 10))
        if [[ $waited -ge $limit ]]; then
            warn "quá $((limit / 60)) phút mà chưa sẵn sàng"
            warn "xem nhật ký: docker compose -f $MAIN_COMPOSE -f $OCTI_COMPOSE logs opencti"
            return
        fi
        [[ $((waited % 60)) -eq 0 ]] && info "còn chờ... ${waited}s"
    done
    ok "OpenCTI đã sẵn sàng sau ${waited}s"
}

# --------------------------------------------------- nối đường dữ liệu vào pipeline

# connect_pipeline bật nguồn 'opencti' rồi dựng lại sync-consumer.
#
# Không có bước này thì OpenCTI chạy nhưng đứng một mình: nguồn 'opencti' được seed ở
# trạng thái TẮT (vì trước P4 chưa có gì đọc nó), và sync-consumer đọc URL cùng token
# lúc khởi động nên container đang chạy vẫn giữ cấu hình rỗng từ trước.
#
# Cả hai thao tác đều idempotent — chạy lại script bao nhiêu lần cũng được.
connect_pipeline() {
    step "Nối OpenCTI vào đường sinh blocklist"

    if compose exec -T postgres psql -U tip -d tip -q         -c "UPDATE sources SET enabled = TRUE, updated_at = NOW()
             WHERE name = 'opencti' AND origin = 'opencti'" >/dev/null 2>&1; then
        ok "đã bật nguồn 'opencti'"
    else
        warn "chưa bật được nguồn 'opencti'"
        warn "bật tay trên dashboard quản trị, mục Nguồn dữ liệu"
    fi

    if ! compose up -d --force-recreate sync-consumer >/dev/null 2>&1; then
        warn "chưa dựng lại được sync-consumer"
        return
    fi

    # Xác minh thật thay vì tin rằng container lên là xong.
    #
    # "docker compose up" thành công chỉ nghĩa là container khởi động được. Nó vẫn
    # khởi động bình thường khi thiếu token hoặc nguồn còn tắt — và đứng yên. Đó là
    # hành vi cố ý, nhưng im lặng, nên phải đọc nhật ký mới biết thật sự đã nối chưa.
    local waited=0
    while [[ $waited -lt 30 ]]; do
        local logs
        logs=$(compose logs --tail 40 sync-consumer 2>/dev/null || true)
        if grep -q 'bắt đầu nghe OpenCTI Live Stream' <<<"$logs"; then
            ok "sync-consumer đã nối vào Live Stream"
            return
        fi
        if grep -q 'đứng yên' <<<"$logs"; then
            warn "sync-consumer đang đứng yên — xem lý do trong nhật ký:"
            warn "  docker compose -f $MAIN_COMPOSE -f $OCTI_COMPOSE logs sync-consumer"
            return
        fi
        sleep 3
        waited=$((waited + 3))
    done

    warn "chưa xác nhận được sync-consumer sau ${waited}s"
    warn "  docker compose -f $MAIN_COMPOSE -f $OCTI_COMPOSE logs sync-consumer"
}

summary() {
    local email pass
    OPENCTI_HOST_PORT=${OPENCTI_HOST_PORT:-8081}
    email=$(grep '^OPENCTI_ADMIN_EMAIL=' "$ENV_FILE" | cut -d= -f2)
    pass=$(grep '^OPENCTI_ADMIN_PASSWORD=' "$ENV_FILE" | cut -d= -f2)

    cat <<EOF

$BOLD OpenCTI đã chạy.$RESET

  Giao diện KHÔNG phơi ra Internet — nó chỉ lắng nghe trên 127.0.0.1:${OPENCTI_HOST_PORT} của máy chủ,
  đúng nguyên tắc "OpenCTI UI/API nằm trong management network" của báo cáo phương án.

  Mở từ máy của bạn bằng SSH tunnel:

      ssh -L 8081:127.0.0.1:${OPENCTI_HOST_PORT} <user>@<máy chủ>

  rồi vào http://localhost:8081

      Tài khoản   $email
      Mật khẩu    $pass

  Nhật ký    docker compose -f $MAIN_COMPOSE -f $OCTI_COMPOSE logs -f opencti
  Dừng       docker compose -f $MAIN_COMPOSE -f $OCTI_COMPOSE stop

  SAO LƯU $ENV_FILE ngay. Mất OPENCTI_ENCRYPTION_KEY là mất khả năng giải mã dữ liệu.

  Đường dữ liệu OpenCTI -> blocklist đã nối: sync-consumer nghe Live Stream và ghi
  xuống PostgreSQL. Thu hồi (Revoke) một indicator trong OpenCTI sẽ gỡ chặn domain
  tương ứng ở lượt policy kế tiếp, kể cả khi nhiều feed vẫn liệt kê nó.

  Nhật ký đường này   docker compose -f $MAIN_COMPOSE -f $OCTI_COMPOSE logs -f sync-consumer

  Chiều ngược lại (đẩy dữ liệu từ feed vào OpenCTI) chưa có. Xem README.md.

  Token quản trị ở trên đang được dùng để đọc Live Stream. Trước khi mở dịch vụ ra
  ngoài VNNIC, hãy tạo một service account riêng chỉ có quyền đọc stream — token quản
  trị mở toàn bộ kho tri thức tình báo, kể cả phần chưa công bố.

EOF
}

main() {
    printf '%sCài đặt OpenCTI cho CyberDNS TIP%s\n' "$BOLD" "$RESET"
    preflight
    check_resources
    set_max_map_count
    setup_env
    start_stack
    connect_pipeline
    summary
}

main "$@"
