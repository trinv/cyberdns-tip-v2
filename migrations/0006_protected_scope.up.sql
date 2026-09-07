-- Sửa phạm vi bảo vệ của hạ tầng dùng chung: wildcard -> exact.
--
-- LÝ DO — phát hiện khi chạy thật trên feed HaGeZi TIF (2,15 triệu domain).
--
-- Migration 0003 đặt cloudfront.net, googleapis.com, akamai.net, gstatic.com,
-- cloudflare.com và windowsupdate.com ở match_type = 1 (wildcard). Hệ quả là MỌI
-- subdomain của chúng được miễn chặn vĩnh viễn, và trên dữ liệu thật điều đó khiến
-- 739 phân phối CloudFront độc hại đã biết KHÔNG bị chặn.
--
-- Ý định của danh sách protected là "không ai được chặn apex" — chặn cả cloudfront.net
-- sẽ làm hỏng một mảng lớn Internet. Nó KHÔNG phải là "không bao giờ chặn bất cứ thứ
-- gì chạy trên CloudFront": chặn đúng một phân phối độc hại là việc mà một DNS firewall
-- hướng threat intelligence phải làm.
--
-- Phân biệt đúng:
--   * Domain chủ quyền / tổ chức (gov.vn, vnnic.vn) -> wildcard. Không được chặn bất
--     cứ thứ gì bên dưới.
--   * Hạ tầng dùng chung (CDN, cloud, kênh cập nhật) -> exact. Bảo vệ apex, nhưng
--     subdomain cụ thể vẫn chặn được khi có bằng chứng.

BEGIN;

DELETE FROM global_allowlist
 WHERE match_type = 1
   AND domain IN ('googleapis.com', 'gstatic.com', 'cloudflare.com',
                  'cloudfront.net', 'akamai.net', 'windowsupdate.com');

INSERT INTO global_allowlist (domain, match_type, tier, reason) VALUES
  ('googleapis.com',    0, 'protected', 'ha tang dung chung: bao ve apex, subdomain van chan duoc'),
  ('gstatic.com',       0, 'protected', 'ha tang dung chung: bao ve apex, subdomain van chan duoc'),
  ('cloudflare.com',    0, 'protected', 'ha tang dung chung: bao ve apex, subdomain van chan duoc'),
  ('cloudfront.net',    0, 'protected', 'ha tang CDN dung chung: bao ve apex, subdomain van chan duoc'),
  ('akamai.net',        0, 'protected', 'ha tang CDN dung chung: bao ve apex, subdomain van chan duoc'),
  ('windowsupdate.com', 0, 'protected', 'kenh cap nhat he dieu hanh: bao ve apex')
ON CONFLICT (domain, match_type) DO UPDATE
   SET tier = EXCLUDED.tier, reason = EXCLUDED.reason;

-- gov.vn và vnnic.vn giữ nguyên wildcard: đó là domain chủ quyền, không được chặn bất
-- cứ thứ gì bên dưới.

COMMIT;
