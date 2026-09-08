-- Trạng thái đồng bộ OpenCTI (P4).
--
-- Ba thứ mà đường feed không cần nhưng đường stream thì bắt buộc phải có:
--
--   1. Tra ngược từ STIX ID về hàng đã lưu. Sự kiện delete và merge chỉ mang định danh,
--      không mang giá trị domain, nên không có đường tra này thì không thể xử lý chúng.
--   2. Dấu thời gian "modified" của chính OpenCTI, để bỏ qua sự kiện cũ đến muộn. SSE
--      không bảo đảm thứ tự sau khi kết nối lại, và phát lại một sự kiện cũ sẽ làm
--      trạng thái lùi về quá khứ (xung đột B6).
--   3. Checkpoint id sự kiện cuối cùng, để nối lại đúng chỗ thay vì bỏ trống khoảng
--      thời gian consumer ngừng chạy (B7).

BEGIN;

-- source_modified_at là dấu thời gian của nguồn, KHÔNG phải thời điểm ta ghi.
--
-- Phải tách khỏi last_seen: last_seen hợp nhất giao hoán bằng GREATEST và phản ánh lần
-- cuối ta thấy dữ liệu; còn so sánh thứ tự sự kiện phải dựa trên đồng hồ của OpenCTI.
-- Dùng chung một cột cho hai việc sẽ khiến mỗi lần ghi lại tự đẩy mốc so sánh lên và
-- phép chống lặp lại mất tác dụng hoàn toàn.
ALTER TABLE domain_sources
  ADD COLUMN IF NOT EXISTS source_modified_at TIMESTAMPTZ;

-- Tra ngược STIX ID -> hàng. Partial index vì chỉ hàng của nguồn OpenCTI mới có
-- source_record_id; hàng của feed thường để NULL.
CREATE INDEX IF NOT EXISTS domain_sources_record_idx
  ON domain_sources (source_id, source_record_id)
  WHERE source_record_id IS NOT NULL;

-- Checkpoint cho từng live stream.
--
-- Khóa theo (source_id, stream_id) chứ không chỉ stream_id: một cài đặt có thể nghe
-- nhiều stream từ nhiều instance OpenCTI, và trộn checkpoint của chúng vào một hàng sẽ
-- khiến consumer nhảy tới vị trí của stream khác.
CREATE TABLE IF NOT EXISTS opencti_stream_state (
  source_id     BIGINT NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
  stream_id     TEXT   NOT NULL,
  last_event_id TEXT,
  -- Mốc thời gian sự kiện cuối đã xử lý. Dùng cho tham số recover khi khoảng ngừng
  -- vượt quá thời gian lưu của stream, lúc đó last_event_id không còn giá trị.
  last_event_at TIMESTAMPTZ,
  events_seen   BIGINT NOT NULL DEFAULT 0,
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (source_id, stream_id)
);

COMMIT;
