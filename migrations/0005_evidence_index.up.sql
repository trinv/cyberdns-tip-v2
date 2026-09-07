-- Index phục vụ phép kiểm tra "bằng chứng này đã có chưa" ở mỗi lần import.
--
-- Không có nó, mỗi lần import phải quét toàn bộ domain_evidence để biết dòng thô có
-- thay đổi hay không. Ở mốc vài triệu bằng chứng thì đó là phép quét không chấp nhận
-- được, và nó chạy trong cùng transaction với cả lần import.
BEGIN;
CREATE INDEX IF NOT EXISTS domain_evidence_dedup_idx
  ON domain_evidence (domain_id, source_id, raw_hash);
COMMIT;
