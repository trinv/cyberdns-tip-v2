-- Hàng đợi yêu cầu "chạy ngay" từ dashboard — đồng bộ một nguồn, chấm điểm lại, dựng
-- và phát hành blocklist.
--
-- feed-ingestor, policy-engine và blocklist-generator là ba tiến trình riêng biệt chạy
-- theo chu kỳ độc lập; admin-api không có đường nào gọi thẳng vào chúng, và không nên
-- có: mọi service khác trong hệ này giao tiếp qua PostgreSQL chứ không qua RPC trực
-- tiếp, để một service đứng yên hay đang khởi động lại không làm hỏng service khác.
--
-- Nên đây là một hàng đợi qua CSDL: admin-api ghi một hàng, service tương ứng tự poll
-- bảng của MÌNH (lọc theo kind) và xử lý. Cơ chế này hoạt động bất kể chạy trong một
-- container hay nhiều, kể cả khi service đang khởi động lại giữa lúc có yêu cầu chờ.

BEGIN;

CREATE TYPE trigger_kind AS ENUM ('sync', 'policy', 'build');
CREATE TYPE trigger_status AS ENUM ('pending', 'running', 'done', 'failed');

CREATE TABLE admin_triggers (
  id            BIGSERIAL PRIMARY KEY,
  kind          trigger_kind NOT NULL,
  -- Chỉ có ý nghĩa với kind='sync': đồng bộ một nguồn cụ thể. NULL nghĩa là mọi nguồn
  -- đang bật (kind='sync') hoặc không áp dụng (kind='policy'/'build').
  source_id     BIGINT REFERENCES sources(id) ON DELETE CASCADE,
  status        trigger_status NOT NULL DEFAULT 'pending',
  requested_by  TEXT NOT NULL,
  requested_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  claimed_at    TIMESTAMPTZ,
  completed_at  TIMESTAMPTZ,
  -- Tóm tắt kết quả (số dòng thêm/bớt, version snapshot...), phục vụ dashboard hiển thị
  -- sau khi xong. Không phải bằng chứng lâu dài — L0 (domain_evidence) mới là chỗ đó.
  result        JSONB,
  error_message TEXT
);

-- Phục vụ đúng câu truy vấn mà mỗi service lặp lại mỗi vài giây: "có yêu cầu nào của
-- loại tôi đang chờ không". Partial index vì phần lớn hàng luôn ở trạng thái đã xong.
CREATE INDEX admin_triggers_pending_idx
  ON admin_triggers (kind, id) WHERE status = 'pending';

-- Cho phép operator kích hoạt đồng bộ và phát hành blocklist thủ công.
--
-- "source:*" đã phủ "source:sync" theo đúng ngữ nghĩa wildcard (xem AdminUser.Can), nên
-- không cần thêm gì cho việc đồng bộ nguồn. Nhưng "policy:write" và "snapshot:write" là
-- hai nhóm quyền operator CHƯA có (operator chỉ có snapshot:read) — phải cấp tường minh.
--
-- Dùng "||" nối mảng JSONB thay vì ghi đè cả cột: an toàn nếu ai đó đã tùy chỉnh thêm
-- quyền khác cho vai trò này trước khi chạy migration.
UPDATE admin_roles
   SET permissions = permissions || '["policy:write", "snapshot:write"]'::jsonb
 WHERE name = 'operator'
   AND NOT (permissions ? 'policy:write' AND permissions ? 'snapshot:write');

COMMIT;
