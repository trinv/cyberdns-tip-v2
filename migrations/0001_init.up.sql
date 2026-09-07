-- CyberDNS TIP — lược đồ khởi tạo
--
-- Lược đồ này hiện thực mô hình 4 tầng suy dẫn (kế hoạch §2):
--   L0  domain_evidence            bằng chứng thô, chỉ ghi thêm, bất biến
--   L1  domains / domain_sources   canonical + quan hệ nguồn, hợp nhất giao hoán
--   L2  domain_decisions           quyết định theo (domain, category)
--   L3  snapshots / snapshot_sets  ảnh chụp theo (tenant, category, version)
--
-- Mã tham chiếu xung đột (A1..E4) trỏ tới bảng §1 của kế hoạch.

BEGIN;

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ----------------------------------------------------------------- enums

CREATE TYPE source_origin     AS ENUM ('direct', 'opencti');
CREATE TYPE policy_action     AS ENUM ('BLOCK', 'MONITOR', 'ALLOW');
CREATE TYPE policy_run_status AS ENUM ('running', 'completed', 'failed', 'aborted');
CREATE TYPE allowlist_tier    AS ENUM ('protected', 'soft');
CREATE TYPE import_status     AS ENUM ('running', 'completed', 'rejected', 'failed', 'unchanged');
CREATE TYPE snapshot_status   AS ENUM ('building', 'ready', 'published', 'superseded', 'failed');

-- ----------------------------------------------------------------- categories

CREATE TABLE categories (
  id          SMALLSERIAL PRIMARY KEY,
  name        TEXT NOT NULL UNIQUE,   -- slug, cũng là tên file: malware -> malware.txt
  description TEXT,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ----------------------------------------------------------------- sources

-- origin thực thi bất biến "mỗi source_id có đúng một bên ghi" (kế hoạch §4.2, xung đột B4):
--   direct  -> chỉ feed-ingestor được ghi
--   opencti -> chỉ sync-consumer được ghi
-- và là cột mà phép đếm nguồn độc lập lọc theo, để chặn vòng lặp phản hồi (B3).
CREATE TABLE sources (
  id                       BIGSERIAL PRIMARY KEY,
  name                     TEXT NOT NULL UNIQUE,
  url                      TEXT,
  source_type              TEXT NOT NULL,
  origin                   source_origin NOT NULL DEFAULT 'direct',
  trust_score              SMALLINT NOT NULL DEFAULT 50 CHECK (trust_score BETWEEN 0 AND 100),
  enabled                  BOOLEAN NOT NULL DEFAULT TRUE,
  refresh_interval_seconds INTEGER,
  -- A4/A5: domain rời khỏi feed không bị gỡ ngay, phải hết grace period
  grace_period_seconds     INTEGER NOT NULL DEFAULT 604800,
  -- hàng rào §4.6: dừng import nếu số dòng biến động quá ngưỡng so với lần trước
  max_change_ratio         NUMERIC(4,3) NOT NULL DEFAULT 0.500,
  max_response_bytes       BIGINT NOT NULL DEFAULT 1073741824,
  opencti_stix_id          TEXT,
  -- rủi ro license (kế hoạch §7.1): phải khai báo trước khi phát hành ra ngoài
  license                  TEXT,
  attribution              TEXT,
  config                   JSONB NOT NULL DEFAULT '{}',
  created_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at               TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX sources_enabled_idx ON sources (enabled) WHERE enabled;

-- ----------------------------------------------------------------- feed imports (audit)

CREATE TABLE feed_imports (
  id                 BIGSERIAL PRIMARY KEY,
  source_id          BIGINT NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
  started_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  completed_at       TIMESTAMPTZ,
  feed_hash          TEXT,
  http_status        INTEGER,
  http_etag          TEXT,
  http_last_modified TEXT,
  response_bytes     BIGINT,
  total_records      BIGINT NOT NULL DEFAULT 0,
  accepted_records   BIGINT NOT NULL DEFAULT 0,
  rejected_records   BIGINT NOT NULL DEFAULT 0,
  added_records      BIGINT NOT NULL DEFAULT 0,
  updated_records    BIGINT NOT NULL DEFAULT 0,
  removed_records    BIGINT NOT NULL DEFAULT 0,
  status             import_status NOT NULL DEFAULT 'running',
  error_message      TEXT
);

CREATE INDEX feed_imports_source_started_idx ON feed_imports (source_id, started_at DESC);

-- ----------------------------------------------------------------- L1: domains

-- match_type ở đây chỉ nhận 0=exact, 1=wildcard.
-- Regex tách hẳn sang regex_rules: giữ regex trong normalized_domain mâu thuẫn trực tiếp
-- với quy tắc "validate DNS label/hostname semantics" của docs/IMPLEMENTATION.md.
--
-- normalized_domain luôn là kết quả của một hàm canonicalize tất định (xung đột A7):
-- A-label punycode, lowercase, không dấu chấm cuối, đã tách tiền tố "*.".
CREATE TABLE domains (
  id                BIGSERIAL PRIMARY KEY,
  normalized_domain TEXT NOT NULL,
  match_type        SMALLINT NOT NULL DEFAULT 0 CHECK (match_type IN (0, 1)),
  raw_hash          TEXT,
  active            BOOLEAN NOT NULL DEFAULT TRUE,
  first_seen        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_seen         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at        TIMESTAMPTZ,
  created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (normalized_domain, match_type)
);

-- Phục vụ rút gọn cha/con lúc render (xung đột A3): quét tiền tố trên chuỗi đảo chiều.
CREATE INDEX domains_reverse_idx ON domains (reverse(normalized_domain));
CREATE INDEX domains_active_idx  ON domains (active) WHERE active;

CREATE TABLE regex_rules (
  id         BIGSERIAL PRIMARY KEY,
  pattern    TEXT NOT NULL UNIQUE,
  source_id  BIGINT NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
  active     BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ----------------------------------------------------------------- L1: quan hệ nguồn

-- revoked_at và valid_until KHÔNG đồng nghĩa (xung đột B2):
--   revoked_at  = phủ định tường minh -> triệt tiêu mọi nguồn khác (nấc 5 thang ưu tiên)
--   valid_until = phân rã thụ động    -> chỉ rút đóng góp của chính nguồn này
CREATE TABLE domain_sources (
  domain_id        BIGINT NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
  source_id        BIGINT NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
  source_record_id TEXT,
  confidence       SMALLINT CHECK (confidence BETWEEN 0 AND 100),
  first_seen       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_seen        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  valid_until      TIMESTAMPTZ,
  revoked_at       TIMESTAMPTZ,
  active           BOOLEAN NOT NULL DEFAULT TRUE,
  PRIMARY KEY (domain_id, source_id)
);

CREATE INDEX domain_sources_source_idx ON domain_sources (source_id) WHERE active;

-- Category được khẳng định bởi TỪNG NGUỒN, không gán phẳng cho domain. Không tách như vậy
-- thì không tính được "số nguồn độc lập xác nhận category X" — đầu vào bắt buộc của policy
-- (xung đột A1 + B3).
CREATE TABLE domain_source_categories (
  domain_id   BIGINT   NOT NULL,
  source_id   BIGINT   NOT NULL,
  category_id SMALLINT NOT NULL REFERENCES categories(id) ON DELETE CASCADE,
  confidence  SMALLINT CHECK (confidence BETWEEN 0 AND 100),
  PRIMARY KEY (domain_id, source_id, category_id),
  FOREIGN KEY (domain_id, source_id)
    REFERENCES domain_sources (domain_id, source_id) ON DELETE CASCADE
);

CREATE INDEX dsc_category_idx ON domain_source_categories (category_id, domain_id);

-- ----------------------------------------------------------------- L0: evidence (append-only)

CREATE TABLE domain_evidence (
  id             BIGSERIAL PRIMARY KEY,
  domain_id      BIGINT REFERENCES domains(id) ON DELETE CASCADE,
  source_id      BIGINT NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
  feed_import_id BIGINT REFERENCES feed_imports(id) ON DELETE SET NULL,
  raw_line       TEXT NOT NULL,
  raw_hash       TEXT NOT NULL,
  feed_hash      TEXT,
  seen_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX domain_evidence_domain_idx ON domain_evidence (domain_id, seen_at DESC);
CREATE INDEX domain_evidence_import_idx ON domain_evidence (feed_import_id);

-- L0 bất biến. Chặn ở tầng CSDL chứ không chỉ bằng quy ước, vì toàn bộ khả năng dựng lại
-- L1-L3 phụ thuộc vào việc tầng này không bao giờ bị sửa.
CREATE OR REPLACE FUNCTION domain_evidence_append_only() RETURNS TRIGGER AS $fn$
BEGIN
  RAISE EXCEPTION 'domain_evidence la append-only: % bi tu choi', TG_OP;
END;
$fn$ LANGUAGE plpgsql;

CREATE TRIGGER domain_evidence_no_update
  BEFORE UPDATE OR DELETE ON domain_evidence
  FOR EACH ROW EXECUTE FUNCTION domain_evidence_append_only();

-- ----------------------------------------------------------------- allowlist / override toàn cục

-- Hai mức (xung đột D3):
--   protected = chống thảm họa, không tenant nào và không policy nào gỡ được
--   soft      = tenant có thể override bằng denylist riêng
CREATE TABLE global_allowlist (
  id         BIGSERIAL PRIMARY KEY,
  domain     TEXT NOT NULL,
  match_type SMALLINT NOT NULL DEFAULT 0 CHECK (match_type IN (0, 1)),
  tier       allowlist_tier NOT NULL DEFAULT 'soft',
  reason     TEXT,
  expires_at TIMESTAMPTZ,
  created_by TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (domain, match_type)
);

CREATE TABLE global_block_overrides (
  id          BIGSERIAL PRIMARY KEY,
  domain      TEXT NOT NULL,
  match_type  SMALLINT NOT NULL DEFAULT 0 CHECK (match_type IN (0, 1)),
  category_id SMALLINT REFERENCES categories(id) ON DELETE CASCADE,
  reason      TEXT,
  expires_at  TIMESTAMPTZ,
  created_by  TEXT,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (domain, match_type, category_id)
);

-- ----------------------------------------------------------------- L2: policy

CREATE TABLE policy_runs (
  id                BIGSERIAL PRIMARY KEY,
  policy_version    TEXT NOT NULL,
  policy_config     JSONB NOT NULL,
  is_shadow         BOOLEAN NOT NULL DEFAULT FALSE,
  status            policy_run_status NOT NULL DEFAULT 'running',
  started_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  completed_at      TIMESTAMPTZ,
  domains_evaluated BIGINT NOT NULL DEFAULT 0,
  domains_blocked   BIGINT NOT NULL DEFAULT 0,
  error_message     TEXT
);

CREATE INDEX policy_runs_current_idx ON policy_runs (completed_at DESC)
  WHERE status = 'completed' AND NOT is_shadow;

-- Khóa theo (domain, category), KHÔNG theo domain: đầu ra là file theo category và mỗi
-- category có ngưỡng riêng, nên một domain có thể BLOCK ở malware mà không BLOCK ở ads.
CREATE TABLE domain_decisions (
  domain_id                BIGINT   NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
  category_id              SMALLINT NOT NULL REFERENCES categories(id) ON DELETE CASCADE,
  action                   policy_action NOT NULL,
  effective_score          SMALLINT NOT NULL,
  independent_source_count SMALLINT NOT NULL DEFAULT 0,
  reason_code              TEXT NOT NULL,
  matched_rules            JSONB NOT NULL DEFAULT '[]',
  policy_run_id            BIGINT NOT NULL REFERENCES policy_runs(id),
  decided_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (domain_id, category_id)
);

-- Generator quét theo category, chỉ lấy BLOCK.
CREATE INDEX domain_decisions_block_idx ON domain_decisions (category_id, domain_id)
  WHERE action = 'BLOCK';

-- Run thử nghiệm (shadow mode, kế hoạch §4.7) ghi sang bảng riêng để không bao giờ chạm
-- vào quyết định hiện hành.
CREATE TABLE shadow_decisions (
  policy_run_id   BIGINT   NOT NULL REFERENCES policy_runs(id) ON DELETE CASCADE,
  domain_id       BIGINT   NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
  category_id     SMALLINT NOT NULL REFERENCES categories(id) ON DELETE CASCADE,
  action          policy_action NOT NULL,
  effective_score SMALLINT NOT NULL,
  reason_code     TEXT NOT NULL,
  PRIMARY KEY (policy_run_id, domain_id, category_id)
);

-- Chỉ ghi các lần CHUYỂN trạng thái. Lưu trọn mọi run ở mốc 10M domain là quá tốn, nhưng
-- vẫn phải trả lời được "vì sao domain này đổi trạng thái lúc T".
CREATE TABLE decision_changes (
  id            BIGSERIAL PRIMARY KEY,
  domain_id     BIGINT   NOT NULL,
  category_id   SMALLINT NOT NULL,
  old_action    policy_action,
  new_action    policy_action NOT NULL,
  old_score     SMALLINT,
  new_score     SMALLINT,
  reason_code   TEXT NOT NULL,
  policy_run_id BIGINT NOT NULL REFERENCES policy_runs(id),
  changed_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX decision_changes_domain_idx ON decision_changes (domain_id, changed_at DESC);

CREATE TABLE false_positive_events (
  id          BIGSERIAL PRIMARY KEY,
  domain_id   BIGINT REFERENCES domains(id) ON DELETE SET NULL,
  tenant_id   BIGINT,
  reported_by TEXT,
  reported_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  resolved_at TIMESTAMPTZ,
  resolution  TEXT,
  note        TEXT
);

CREATE INDEX fp_domain_idx ON false_positive_events (domain_id);

-- ----------------------------------------------------------------- tenants

CREATE TABLE tenants (
  id            BIGSERIAL PRIMARY KEY,
  name          TEXT NOT NULL,
  slug          TEXT NOT NULL UNIQUE,
  is_default    BOOLEAN NOT NULL DEFAULT FALSE,
  enabled       BOOLEAN NOT NULL DEFAULT TRUE,
  -- 3 biến seed brand-h/s/l mà skill admin-portal-style cần để white-label
  brand         JSONB NOT NULL DEFAULT '{}',
  -- renderer cắm được: domain | hosts | wildcard | adguard | rpz
  output_format TEXT NOT NULL DEFAULT 'domain',
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Tenant mặc định phục vụ các URL phẳng trong claude_rm.md. Chỉ được phép có một.
CREATE UNIQUE INDEX tenants_single_default_idx ON tenants (is_default) WHERE is_default;

CREATE TABLE tenant_tokens (
  id           BIGSERIAL PRIMARY KEY,
  tenant_id    BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  token_hash   TEXT NOT NULL UNIQUE,
  label        TEXT,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_used_at TIMESTAMPTZ,
  -- D5: token cũ còn dùng được tới thời điểm này sau khi quay vòng
  expires_at   TIMESTAMPTZ,
  revoked_at   TIMESTAMPTZ
);

CREATE TABLE tenant_categories (
  tenant_id   BIGINT   NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  category_id SMALLINT NOT NULL REFERENCES categories(id) ON DELETE CASCADE,
  enabled     BOOLEAN NOT NULL DEFAULT TRUE,
  min_score   SMALLINT,   -- NULL = dùng ngưỡng toàn cục
  PRIMARY KEY (tenant_id, category_id)
);

CREATE TABLE tenant_allowlist (
  tenant_id  BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  domain     TEXT NOT NULL,
  match_type SMALLINT NOT NULL DEFAULT 0 CHECK (match_type IN (0, 1)),
  reason     TEXT,
  expires_at TIMESTAMPTZ,
  created_by TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (tenant_id, domain, match_type)
);

CREATE TABLE tenant_denylist (
  tenant_id   BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  domain      TEXT NOT NULL,
  match_type  SMALLINT NOT NULL DEFAULT 0 CHECK (match_type IN (0, 1)),
  category_id SMALLINT REFERENCES categories(id) ON DELETE CASCADE,
  reason      TEXT,
  expires_at  TIMESTAMPTZ,
  created_by  TEXT,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (tenant_id, domain, match_type)
);

ALTER TABLE false_positive_events
  ADD CONSTRAINT fp_tenant_fk FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE SET NULL;

-- ----------------------------------------------------------------- L3: snapshots

-- Publish theo BỘ, không theo từng file (xung đột E2). Cả bộ vào một version, rồi đổi con
-- trỏ current bằng một thao tác nguyên tử duy nhất.
CREATE TABLE snapshot_sets (
  id            BIGSERIAL PRIMARY KEY,
  version       TEXT NOT NULL UNIQUE,
  policy_run_id BIGINT REFERENCES policy_runs(id),
  status        snapshot_status NOT NULL DEFAULT 'building',
  built_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  published_at  TIMESTAMPTZ,
  error_message TEXT
);

CREATE INDEX snapshot_sets_published_idx ON snapshot_sets (published_at DESC)
  WHERE status = 'published';

CREATE TABLE snapshots (
  id          BIGSERIAL PRIMARY KEY,
  set_id      BIGINT NOT NULL REFERENCES snapshot_sets(id) ON DELETE CASCADE,
  tenant_id   BIGINT REFERENCES tenants(id) ON DELETE CASCADE,      -- NULL = base dùng chung
  category_id SMALLINT REFERENCES categories(id) ON DELETE CASCADE, -- NULL = all.txt
  kind        TEXT NOT NULL CHECK (kind IN ('denylist', 'allowlist', 'manifest')),
  -- ETag là hash nội dung, không phải số version (xung đột E3)
  checksum    TEXT NOT NULL,
  entries     BIGINT NOT NULL DEFAULT 0,
  bytes       BIGINT NOT NULL DEFAULT 0,
  file_path   TEXT NOT NULL,
  built_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX snapshots_set_idx      ON snapshots (set_id);
CREATE INDEX snapshots_checksum_idx ON snapshots (checksum);

-- ----------------------------------------------------------------- quản trị

CREATE TABLE admin_roles (
  id          SMALLSERIAL PRIMARY KEY,
  name        TEXT NOT NULL UNIQUE,
  permissions JSONB NOT NULL DEFAULT '[]'
);

CREATE TABLE admin_users (
  id            BIGSERIAL PRIMARY KEY,
  email         TEXT NOT NULL UNIQUE,
  display_name  TEXT,
  password_hash TEXT,
  role_id       SMALLINT REFERENCES admin_roles(id),
  tenant_id     BIGINT REFERENCES tenants(id) ON DELETE CASCADE,  -- NULL = quản trị toàn hệ
  enabled       BOOLEAN NOT NULL DEFAULT TRUE,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_login_at TIMESTAMPTZ
);

CREATE TABLE admin_audit_log (
  id         BIGSERIAL PRIMARY KEY,
  actor      TEXT NOT NULL,
  action     TEXT NOT NULL,
  entity     TEXT NOT NULL,
  entity_id  TEXT,
  before     JSONB,
  after      JSONB,
  ip         INET,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX admin_audit_log_created_idx ON admin_audit_log (created_at DESC);

COMMIT;
