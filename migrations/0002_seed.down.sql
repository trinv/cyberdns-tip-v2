BEGIN;

DELETE FROM tenant_categories
 WHERE tenant_id IN (SELECT id FROM tenants WHERE slug = 'public');

DELETE FROM tenants     WHERE slug = 'public';
DELETE FROM admin_roles WHERE name IN ('owner', 'operator', 'viewer');
DELETE FROM categories
 WHERE name IN ('malware', 'phishing', 'c2', 'scam', 'ads', 'tracking', 'adults', 'gambling');

COMMIT;
