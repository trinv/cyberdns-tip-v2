-- Dữ liệu khởi tạo tối thiểu: category, tenant mặc định, vai trò quản trị.
-- Idempotent — chạy lại nhiều lần không đổi kết quả.

BEGIN;

-- Tên category chính là tên file xuất ra, khớp với claude_rm.md §6.
INSERT INTO categories (name, description) VALUES
  ('malware',  'Malware, dropper, payload hosting'),
  ('phishing', 'Phishing, credential harvesting'),
  ('c2',       'Command & control, botnet'),
  ('scam',     'Lừa đảo, giả mạo thương hiệu'),
  ('ads',      'Quảng cáo'),
  ('tracking', 'Theo dõi, telemetry'),
  ('adults',   'Nội dung người lớn'),
  ('gambling', 'Cờ bạc, cá cược')
ON CONFLICT (name) DO NOTHING;

-- Tenant mặc định phục vụ các URL phẳng https://tip.cyberdns.vn/blocklist/{category}.txt
INSERT INTO tenants (name, slug, is_default, brand)
VALUES ('Public', 'public', TRUE, '{"h": 220, "s": "100%", "l": "64%"}')
ON CONFLICT (slug) DO NOTHING;

-- Tenant mặc định bật toàn bộ category.
INSERT INTO tenant_categories (tenant_id, category_id, enabled)
SELECT t.id, c.id, TRUE FROM tenants t CROSS JOIN categories c WHERE t.slug = 'public'
ON CONFLICT (tenant_id, category_id) DO NOTHING;

-- Quyền "protected:write" cố tình nằm NGOÀI phạm vi "allowlist:": operator có
-- "allowlist:*", và theo đúng ngữ nghĩa wildcard thì dấu sao phải phủ mọi thứ bên dưới
-- nó. Đặt một quyền cao hơn vào bên trong phạm vi mà vai trò thấp đã nắm là cách tạo ra
-- một lỗ phân quyền không ai nhìn thấy khi đọc bảng này.
INSERT INTO admin_roles (name, permissions) VALUES
  ('owner',    '["*"]'),
  ('operator', '["source:*", "import:*", "allowlist:*", "tenant:*", "snapshot:read", "domain:read"]'),
  ('viewer',   '["source:read", "import:read", "snapshot:read", "domain:read"]')
ON CONFLICT (name) DO NOTHING;

COMMIT;
