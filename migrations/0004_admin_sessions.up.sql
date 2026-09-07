-- Phiên đăng nhập của dashboard quản trị.
--
-- Lưu phiên trong CSDL chứ không dùng cookie tự ký: bảng này cho phép THU HỒI. Với một
-- bảng điều khiển quyết định việc chặn tên miền ở quy mô quốc gia, khả năng đăng xuất
-- một phiên bị lộ ngay lập tức quan trọng hơn việc tiết kiệm một lượt truy vấn.

BEGIN;

CREATE TABLE admin_sessions (
  -- Chỉ lưu hash của token phiên. CSDL rò rỉ thì cookie đã cấp vẫn không dùng lại được.
  token_hash   TEXT PRIMARY KEY,
  user_id      BIGINT NOT NULL REFERENCES admin_users(id) ON DELETE CASCADE,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at   TIMESTAMPTZ NOT NULL,
  last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  revoked_at   TIMESTAMPTZ,
  user_agent   TEXT,
  ip           INET
);

CREATE INDEX admin_sessions_user_idx    ON admin_sessions (user_id);
CREATE INDEX admin_sessions_expires_idx ON admin_sessions (expires_at);

COMMIT;
