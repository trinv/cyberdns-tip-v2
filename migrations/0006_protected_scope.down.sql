BEGIN;

DELETE FROM global_allowlist
 WHERE match_type = 0
   AND domain IN ('googleapis.com', 'gstatic.com', 'cloudflare.com',
                  'cloudfront.net', 'akamai.net', 'windowsupdate.com');

INSERT INTO global_allowlist (domain, match_type, tier, reason) VALUES
  ('googleapis.com',    1, 'protected', 'ha tang dung chung'),
  ('gstatic.com',       1, 'protected', 'ha tang dung chung'),
  ('cloudflare.com',    1, 'protected', 'ha tang dung chung'),
  ('cloudfront.net',    1, 'protected', 'ha tang CDN dung chung'),
  ('akamai.net',        1, 'protected', 'ha tang CDN dung chung'),
  ('windowsupdate.com', 1, 'protected', 'kenh cap nhat he dieu hanh')
ON CONFLICT (domain, match_type) DO NOTHING;

COMMIT;
