-- Các nguồn feed khởi điểm.
--
-- CẢNH BÁO VỀ LICENSE — đọc trước khi bật thêm nguồn nào.
--
-- Hệ này tái phát hành list DẪN XUẤT từ các nguồn bên ngoài qua một endpoint công
-- khai. Điều khoản của từng nguồn ràng buộc việc đó, và chúng không giống nhau:
--
--   * HaGeZi là GPL-3.0. Phát hành lại kèm ghi nhận nguồn và nêu license là phù hợp,
--     và hệ đã tự động đưa attribution vào manifest.json cùng header mỗi file. Câu
--     hỏi bản thân list dẫn xuất có phải mang GPL hay không là câu hỏi pháp lý, cần
--     bộ phận pháp chế trả lời trước khi mở dịch vụ ra ngoài VNNIC.
--
--   * URLhaus của abuse.ch nêu rõ mục đích THƯƠNG MẠI có thể cần đăng ký trả phí.
--     Vì vậy nó được seed ở trạng thái TẮT.
--
-- Quy tắc chung: nguồn nào chưa rà license thì để enabled = FALSE. Bật một nguồn là
-- một quyết định có hệ quả pháp lý, không phải một thao tác kỹ thuật.

BEGIN;

-- HaGeZi Threat Intelligence Feed — nguồn CTI chính theo PLAN.md Phase 1.
INSERT INTO sources (
  name, url, source_type, origin, trust_score, enabled,
  refresh_interval_seconds, grace_period_seconds,
  max_change_ratio, max_response_bytes,
  license, attribution, config
) VALUES (
  'hagezi-tif',
  'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif.txt',
  'plain', 'direct', 85, TRUE,
  21600,   -- 6 giờ
  604800,  -- grace 7 ngày, chống feed flapping
  0.500,
  268435456,  -- 256 MiB
  'GPL-3.0',
  'HaGeZi DNS Blocklists — https://github.com/hagezi/dns-blocklists',
  '{"categories": ["malware", "phishing", "c2"]}'::jsonb
) ON CONFLICT (name) DO NOTHING;

-- HaGeZi Multi PRO — quảng cáo và theo dõi. Khối lượng lớn, giá trị CTI thấp, nên
-- đi thẳng vào PostgreSQL và không qua OpenCTI (claude_rm.md, phần phân loại feed).
INSERT INTO sources (
  name, url, source_type, origin, trust_score, enabled,
  refresh_interval_seconds, grace_period_seconds,
  max_change_ratio, max_response_bytes,
  license, attribution, config
) VALUES (
  'hagezi-multi-pro',
  'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/pro.txt',
  'plain', 'direct', 70, FALSE,   -- TẮT: bật sau khi rà license
  86400, 604800, 0.300, 536870912,
  'GPL-3.0',
  'HaGeZi DNS Blocklists — https://github.com/hagezi/dns-blocklists',
  '{"categories": ["ads", "tracking"]}'::jsonb
) ON CONFLICT (name) DO NOTHING;

-- URLhaus — TẮT. abuse.ch nêu rõ mục đích thương mại có thể cần đăng ký trả phí.
INSERT INTO sources (
  name, url, source_type, origin, trust_score, enabled,
  refresh_interval_seconds, grace_period_seconds,
  max_change_ratio, max_response_bytes,
  license, attribution, config
) VALUES (
  'urlhaus',
  'https://urlhaus.abuse.ch/downloads/hostfile/',
  'hosts', 'direct', 90, FALSE,
  3600, 259200, 0.500, 134217728,
  'abuse.ch — cần rà soát điều khoản sử dụng thương mại',
  'URLhaus by abuse.ch — https://urlhaus.abuse.ch/',
  '{"categories": ["malware"]}'::jsonb
) ON CONFLICT (name) DO NOTHING;

-- Nguồn đại diện cho dữ liệu quay về từ OpenCTI.
--
-- origin = 'opencti' là thứ thực thi bất biến một-bên-ghi: chỉ sync-consumer ghi vào
-- các hàng của nguồn này, và phép đếm nguồn độc lập BỎ QUA chúng để một domain đi
-- vòng qua OpenCTI không tự thưởng cho mình một xác nhận ảo.
--
-- TẮT cho tới khi sync-consumer của P4 được viết.
INSERT INTO sources (
  name, url, source_type, origin, trust_score, enabled,
  grace_period_seconds, license, attribution, config
) VALUES (
  'opencti', NULL, 'stream', 'opencti', 95, FALSE,
  604800, NULL, 'OpenCTI (nội bộ)',
  '{"categories": ["malware", "phishing", "c2", "scam"]}'::jsonb
) ON CONFLICT (name) DO NOTHING;

-- Lớp chống thảm họa: nấc 1 của thang ưu tiên, không tenant nào và không policy nào
-- gỡ được. Đây chỉ là hạt giống tối thiểu — danh sách thật cần bổ sung top domain
-- Việt Nam và hạ tầng CDN/cloud lớn trước khi chạy production.
INSERT INTO global_allowlist (domain, match_type, tier, reason) VALUES
  ('vnnic.vn',        1, 'protected', 'hạ tầng đăng ký tên miền quốc gia'),
  ('gov.vn',          1, 'protected', 'hạ tầng cơ quan nhà nước'),
  ('googleapis.com',  1, 'protected', 'hạ tầng dùng chung, chặn gây sự cố diện rộng'),
  ('gstatic.com',     1, 'protected', 'hạ tầng dùng chung'),
  ('cloudflare.com',  1, 'protected', 'hạ tầng dùng chung'),
  ('cloudfront.net',  1, 'protected', 'hạ tầng CDN dùng chung'),
  ('akamai.net',      1, 'protected', 'hạ tầng CDN dùng chung'),
  ('windowsupdate.com', 1, 'protected', 'kênh cập nhật hệ điều hành')
ON CONFLICT (domain, match_type) DO NOTHING;

COMMIT;
