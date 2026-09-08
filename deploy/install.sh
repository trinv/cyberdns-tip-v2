#!/usr/bin/env bash
#
# Cài đặt CyberDNS TIP lên một máy chủ Linux có systemd.
#
# Script này chạy được nhiều lần. Mỗi bước tự kiểm tra trạng thái hiện tại trước khi
# làm gì, nên chạy lại sau khi sửa một lỗi ở giữa chừng là an toàn.
#
#   sudo ./deploy/install.sh --email admin@vnnic.vn
#
# Chạy thử trước khi làm thật (rất nên, xem --help):
#
#   sudo ./deploy/install.sh --email admin@vnnic.vn --staging

set -euo pipefail

# ------------------------------------------------------------------ mặc định

DOMAIN="tip.cyberdns.vn"
EMAIL=""
STAGING=0
SKIP_CERT=0
SKIP_DNS_CHECK=0
ASSUME_YES=0

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_DIR="$REPO_ROOT/deploy/docker-compose"
COMPOSE_FILE="$COMPOSE_DIR/docker-compose.prod.yml"
NGINX_TEMPLATE="$REPO_ROOT/deploy/nginx/tip.cyberdns.vn.conf"
WEBROOT="/var/www/certbot"

# ------------------------------------------------------------------ tiện ích

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
Cài đặt CyberDNS TIP.

  --email ĐỊA_CHỈ     Email đăng ký Let's Encrypt (bắt buộc, trừ khi --skip-cert)
  --domain TÊN_MIỀN   Mặc định: $DOMAIN
  --staging           Dùng máy chủ thử nghiệm của Let's Encrypt.
                      Chứng thư sinh ra KHÔNG được trình duyệt tin, nhưng không tính
                      vào hạn mức 5 lần cấp mỗi tuần. Hãy chạy thử bằng cờ này trước
                      khi làm thật — chạm trần hạn mức là mất TLS tới tuần sau.
  --skip-cert         Bỏ qua bước chứng thư (đã có sẵn hoặc dùng CA khác)
  --skip-dns-check    Bỏ qua kiểm tra DNS. Chỉ dùng khi bạn chắc chắn, ví dụ máy chủ
                      nằm sau NAT nên IP công khai không khớp IP cục bộ.
  --yes               Không hỏi xác nhận
  --help
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --email)          EMAIL="${2:-}"; shift 2 ;;
        --domain)         DOMAIN="${2:-}"; shift 2 ;;
        --staging)        STAGING=1; shift ;;
        --skip-cert)      SKIP_CERT=1; shift ;;
        --skip-dns-check) SKIP_DNS_CHECK=1; shift ;;
        --yes|-y)         ASSUME_YES=1; shift ;;
        --help|-h)        usage; exit 0 ;;
        *)                die "tham số không nhận ra: $1 (xem --help)" ;;
    esac
done

NGINX_SITE="/etc/nginx/sites-available/${DOMAIN}.conf"
NGINX_LINK="/etc/nginx/sites-enabled/${DOMAIN}.conf"
CERT_DIR="/etc/letsencrypt/live/${DOMAIN}"

# ------------------------------------------------------------------ 1. tiền kiểm

preflight() {
    step "Kiểm tra môi trường"

    [[ $EUID -eq 0 ]] || die "cần chạy bằng root: sudo $0 ..."
    have systemctl || die "không tìm thấy systemd; script này dành cho máy chủ Linux có systemd"
    ok "chạy bằng root trên hệ có systemd"

    have docker || die "chưa cài docker. Xem https://docs.docker.com/engine/install/"
    docker compose version >/dev/null 2>&1 \
        || die "chưa có plugin 'docker compose' (v2). Bản docker-compose v1 không dùng được."
    ok "docker và docker compose v2 đã sẵn sàng"

    [[ -f "$COMPOSE_FILE" ]]    || die "không thấy $COMPOSE_FILE"
    [[ -f "$NGINX_TEMPLATE" ]]  || die "không thấy $NGINX_TEMPLATE"
    ok "tìm thấy repo tại $REPO_ROOT"

    if [[ $SKIP_CERT -eq 0 && -z "$EMAIL" ]]; then
        die "cần --email cho Let's Encrypt (hoặc dùng --skip-cert)"
    fi
}

# ------------------------------------------------------------------ 2. gói hệ thống

install_packages() {
    step "Cài nginx và certbot"

    local missing=()
    have nginx   || missing+=(nginx)
    have certbot || missing+=(certbot)
    have dig     || missing+=(dnsutils)
    have openssl || missing+=(openssl)

    if [[ ${#missing[@]} -eq 0 ]]; then
        ok "đã có đủ: nginx, certbot, dig, openssl"
        return
    fi

    info "cần cài: ${missing[*]}"
    if have apt-get; then
        DEBIAN_FRONTEND=noninteractive apt-get update -qq
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${missing[@]}"
    elif have dnf; then
        # Tên gói dnsutils trên họ RHEL là bind-utils.
        dnf install -y -q "${missing[@]/dnsutils/bind-utils}"
    else
        die "không nhận ra trình quản lý gói; hãy tự cài: ${missing[*]}"
    fi
    ok "đã cài ${missing[*]}"
}

# ------------------------------------------------------------------ 3. kiểm tra DNS

# Đây là hàng rào quan trọng nhất trước bước chứng thư. Let's Encrypt giới hạn số lần
# xác thực THẤT BẠI (5 lần mỗi giờ cho một tên miền), nên chạy certbot khi DNS chưa
# trỏ đúng vừa không được gì vừa tiêu mất hạn mức.
check_dns() {
    step "Kiểm tra DNS của $DOMAIN"

    if [[ $SKIP_DNS_CHECK -eq 1 ]]; then
        warn "bỏ qua theo yêu cầu (--skip-dns-check)"
        return
    fi

    local resolved public
    resolved="$(dig +short A "$DOMAIN" | tail -n1)"
    [[ -n "$resolved" ]] || die "$DOMAIN chưa có bản ghi A. Tạo bản ghi trỏ về máy này trước đã."
    info "$DOMAIN -> $resolved"

    public="$(curl -fsS --max-time 10 https://api.ipify.org 2>/dev/null || true)"
    if [[ -z "$public" ]]; then
        warn "không xác định được IP công khai của máy; bỏ qua phép so sánh"
        return
    fi
    info "IP công khai của máy này -> $public"

    if [[ "$resolved" == "$public" ]]; then
        ok "DNS đã trỏ đúng về máy này"
        return
    fi

    warn "DNS trỏ về $resolved nhưng máy này là $public"
    warn "Nếu tiếp tục, xác thực ACME gần như chắc chắn thất bại và tiêu mất hạn mức."
    confirm "Vẫn tiếp tục?" || die "dừng lại. Sửa DNS rồi chạy lại, hoặc dùng --skip-dns-check nếu máy nằm sau NAT."
}

check_port_80() {
    step "Kiểm tra cổng 80"

    # ss có ở hầu hết bản phân phối hiện đại; không có thì bỏ qua chứ không chặn.
    if ! have ss; then
        warn "không có 'ss', bỏ qua kiểm tra"
        return
    fi

    local holder
    holder="$(ss -lntp 2>/dev/null | awk '$4 ~ /:80$/ {print $NF}' | head -n1 || true)"
    if [[ -z "$holder" ]]; then
        ok "cổng 80 đang rảnh"
    else
        info "cổng 80 đang được giữ bởi: $holder"
        info "certbot sẽ tạm dừng nginx trong lúc xin chứng thư."
    fi
}

# ------------------------------------------------------------------ 4. chứng thư

obtain_certificate() {
    step "Chứng thư số cho $DOMAIN"

    if [[ $SKIP_CERT -eq 1 ]]; then
        warn "bỏ qua theo yêu cầu (--skip-cert)"
        return
    fi

    # Không bao giờ xin lại chứng thư còn hạn. Let's Encrypt chỉ cho 5 lần cấp mỗi
    # tuần cho một tên miền; chạm trần là mất TLS cho tới tuần sau.
    if [[ -f "$CERT_DIR/fullchain.pem" ]]; then
        local days_left
        days_left=$(( ( $(date -d "$(openssl x509 -enddate -noout -in "$CERT_DIR/fullchain.pem" | cut -d= -f2)" +%s) - $(date +%s) ) / 86400 ))
        if [[ $days_left -gt 30 ]]; then
            ok "đã có chứng thư, còn $days_left ngày — không xin lại"
            return
        fi
        info "chứng thư hiện tại còn $days_left ngày, sẽ gia hạn"
    fi

    mkdir -p "$WEBROOT"

    local args=(certonly --non-interactive --agree-tos --email "$EMAIL" -d "$DOMAIN")
    if [[ $STAGING -eq 1 ]]; then
        args+=(--staging)
        warn "dùng máy chủ THỬ NGHIỆM: chứng thư sinh ra sẽ không được trình duyệt tin"
    fi

    # Lần cấp đầu dùng --standalone: lúc này nginx chưa có cấu hình cho tên miền nên
    # chưa phục vụ được đường ACME. Các lần gia hạn sau dùng webroot, không cần dừng
    # nginx — xem setup_renewal.
    if [[ -f "$NGINX_LINK" ]] && systemctl is-active --quiet nginx; then
        info "nginx đã cấu hình sẵn cho tên miền này; dùng webroot, không cần dừng nginx"
        certbot "${args[@]}" --webroot -w "$WEBROOT" || die "certbot thất bại"
    else
        info "tạm dừng nginx để certbot nghe cổng 80"
        local was_active=0
        systemctl is-active --quiet nginx && was_active=1
        [[ $was_active -eq 1 ]] && systemctl stop nginx

        # Bật lại nginx dù certbot thành công hay không: bỏ máy chủ ở trạng thái tắt
        # web là hậu quả tệ hơn việc chưa có chứng thư.
        if ! certbot "${args[@]}" --standalone; then
            [[ $was_active -eq 1 ]] && systemctl start nginx
            die "certbot thất bại. Kiểm tra DNS và cổng 80 rồi chạy lại."
        fi
        [[ $was_active -eq 1 ]] && systemctl start nginx
    fi

    ok "đã có chứng thư tại $CERT_DIR"
}

# ------------------------------------------------------------------ 5. nginx

install_nginx_config() {
    step "Cấu hình nginx"

    local tmp
    tmp="$(mktemp)"
    # Template viết cho tip.cyberdns.vn; thay tên miền nếu người dùng chọn khác.
    sed "s/tip\.cyberdns\.vn/${DOMAIN}/g" "$NGINX_TEMPLATE" > "$tmp"

    if [[ -f "$NGINX_SITE" ]] && cmp -s "$tmp" "$NGINX_SITE"; then
        ok "cấu hình đã đúng, không đổi gì"
        rm -f "$tmp"
    else
        if [[ -f "$NGINX_SITE" ]]; then
            # Khai báo tách khỏi gán: "local x=$(cmd)" nuốt mất mã thoát của cmd, vì
            # giá trị trả về là của chính lệnh local (SC2155).
            local backup
            backup="${NGINX_SITE}.bak.$(date +%Y%m%d%H%M%S)"
            cp "$NGINX_SITE" "$backup"
            info "đã sao lưu cấu hình cũ: $backup"
        fi
        install -m 0644 "$tmp" "$NGINX_SITE"
        rm -f "$tmp"
        ok "đã ghi $NGINX_SITE"
    fi

    mkdir -p "$(dirname "$NGINX_LINK")"
    ln -sfn "$NGINX_SITE" "$NGINX_LINK"

    # Cấu hình mặc định của Debian/Ubuntu chiếm cổng 80 với server_name _; để nguyên
    # cũng không sao vì server_name của ta cụ thể hơn nên khớp trước.
    if ! nginx -t 2>&1 | sed 's/^/    /'; then
        die "nginx -t thất bại; cấu hình chưa được nạp"
    fi

    systemctl enable --now nginx >/dev/null 2>&1 || true
    systemctl reload nginx
    ok "nginx đã nạp cấu hình mới"
}

setup_renewal() {
    step "Gia hạn tự động"

    if [[ $SKIP_CERT -eq 1 ]]; then
        warn "bỏ qua"
        return
    fi

    # Chuyển sang webroot để các lần gia hạn sau không cần dừng nginx. Cấu hình nginx
    # đã chừa sẵn /.well-known/acme-challenge/ trên cổng 80.
    local renewal_conf="/etc/letsencrypt/renewal/${DOMAIN}.conf"
    if [[ -f "$renewal_conf" ]] && grep -q "authenticator = standalone" "$renewal_conf"; then
        info "chuyển cách xác thực từ standalone sang webroot"
        sed -i \
            -e "s|^authenticator = standalone|authenticator = webroot|" \
            -e "/^\[renewalparams\]/a webroot_path = ${WEBROOT},"        \
            "$renewal_conf"
    fi

    if systemctl list-unit-files | grep -q '^certbot.timer'; then
        systemctl enable --now certbot.timer >/dev/null 2>&1 || true
        ok "certbot.timer đang bật — gia hạn tự động, không downtime"
    else
        warn "không thấy certbot.timer; hãy tự đặt cron: certbot renew --quiet"
    fi

    info "kiểm tra thử bằng: sudo certbot renew --dry-run"
}

# ------------------------------------------------------------------ 6. cấu hình stack

setup_env() {
    step "Cấu hình môi trường"

    local env_file="$COMPOSE_DIR/.env"

    # KHÔNG BAO GIỜ ghi đè .env đang có. POSTGRES_PASSWORD trong đó là mật khẩu của
    # volume dữ liệu hiện tại; sinh mật khẩu mới sẽ khiến PostgreSQL không mở được
    # dữ liệu cũ, và đó là kiểu mất dữ liệu không có cách nào lần ngược.
    if [[ -f "$env_file" ]]; then
        ok "đã có .env, giữ nguyên"
        return
    fi

    umask 077
    cat > "$env_file" <<EOF
# Sinh tự động bởi deploy/install.sh lúc $(date -Is)
POSTGRES_PASSWORD=$(openssl rand -base64 32 | tr -d '\n/+=' | head -c 32)
GRAFANA_PASSWORD=$(openssl rand -base64 24 | tr -d '\n/+=' | head -c 24)

# Tài khoản quản trị đầu tiên, do service bootstrap tạo. Đặt sẵn ở đây để mật khẩu
# ỔN ĐỊNH qua mỗi lần dựng lại, thay vì phải mò trong nhật ký.
TIP_ADMIN_EMAIL=admin@vnnic.vn
TIP_ADMIN_PASSWORD=$(openssl rand -base64 24 | tr -d '\n/+=' | head -c 24)
VERSION=$(git -C "$REPO_ROOT" describe --tags --always --dirty 2>/dev/null || echo dev)
TIP_LOG_LEVEL=info
EOF
    chmod 600 "$env_file"
    ok "đã sinh $env_file với mật khẩu ngẫu nhiên (quyền 600)"
    warn "Hãy sao lưu file này. Mất POSTGRES_PASSWORD là mất quyền đọc dữ liệu trong volume."
}

start_stack() {
    step "Khởi động stack"

    cd "$COMPOSE_DIR"

    info "khởi động PostgreSQL"
    docker compose -f "$COMPOSE_FILE" up -d postgres

    info "chờ PostgreSQL sẵn sàng"
    local waited=0
    until docker compose -f "$COMPOSE_FILE" exec -T postgres pg_isready -U tip -d tip >/dev/null 2>&1; do
        sleep 2
        waited=$((waited + 2))
        [[ $waited -ge 120 ]] && die "PostgreSQL không sẵn sàng sau 120 giây"
    done
    ok "PostgreSQL đã sẵn sàng"

    # Không có bước migrate riêng: service "bootstrap" chạy migration và tạo tài khoản
    # quản trị đầu tiên, còn mọi service khác chờ nó chạy XONG mới khởi động
    # (service_completed_successfully). Nghĩa là khi lệnh dưới đây trả về thì lược đồ đã
    # đúng phiên bản và đã có tài khoản để đăng nhập.
    info "khởi động toàn bộ (bootstrap chạy migration trước)"
    docker compose -f "$COMPOSE_FILE" up -d || die "khởi động thất bại"
    ok "stack đang chạy"
}

# ------------------------------------------------------------------ 7. xác minh

verify() {
    step "Xác minh"

    local url="https://${DOMAIN}/blocklist/manifest.json"
    local curl_opts=(-sS -o /dev/null -w '%{http_code}' --max-time 20)
    [[ $STAGING -eq 1 ]] && curl_opts+=(-k)

    sleep 3
    local code
    code="$(curl "${curl_opts[@]}" "$url" 2>/dev/null || echo 000)"

    case "$code" in
        503)
            # Đây là trạng thái ĐÚNG ngay sau khi cài: đường dẫn đã thông từ nginx tới
            # generator, nhưng chưa có nguồn feed nào được nạp nên chưa có snapshot.
            ok "đường dẫn HTTPS đã thông (503 = chưa có snapshot, đúng như mong đợi)"
            ;;
        200)
            ok "đã phục vụ được manifest"
            ;;
        000)
            warn "không kết nối được tới $url"
            warn "kiểm tra: systemctl status nginx; docker compose -f $COMPOSE_FILE ps"
            ;;
        *)
            warn "$url trả về HTTP $code"
            ;;
    esac

    info "trạng thái container:"
    docker compose -f "$COMPOSE_FILE" ps --format '    {{.Service}}\t{{.Status}}' 2>/dev/null || true
}

summary() {
    cat <<EOF

$BOLD Cài đặt xong.$RESET

  Blocklist   https://${DOMAIN}/blocklist/{malware,phishing,ads,tracking,adults,gambling,all}.txt
  Manifest    https://${DOMAIN}/blocklist/manifest.json

  Các URL trên hiện trả về 503 vì chưa có nguồn feed nào được nạp — đó là hành vi
  đúng, không phải lỗi. Snapshot chỉ xuất hiện sau lần import đầu tiên.

  Nhật ký       docker compose -f $COMPOSE_FILE logs -f
  Dừng          docker compose -f $COMPOSE_FILE down
  nginx         systemctl status nginx

  Sao lưu ngay $COMPOSE_DIR/.env — mất POSTGRES_PASSWORD là mất dữ liệu.

  sync-consumer đang chạy nhưng ĐỨNG YÊN vì chưa có OpenCTI — đó là hành vi đúng, không
  phải lỗi. Muốn có tầng Threat Intelligence thì chạy:

      sudo ./deploy/install-opencti.sh

  Script đó dựng OpenCTI, bật nguồn 'opencti' và nối sync-consumer vào Live Stream.
  Cần thêm khoảng 16 GB RAM.

EOF
}

# ------------------------------------------------------------------ chạy

main() {
    printf '%sCài đặt CyberDNS TIP — %s%s\n' "$BOLD" "$DOMAIN" "$RESET"

    preflight
    install_packages
    check_dns
    check_port_80
    obtain_certificate
    install_nginx_config
    setup_renewal
    setup_env
    start_stack
    verify
    summary
}

main "$@"
