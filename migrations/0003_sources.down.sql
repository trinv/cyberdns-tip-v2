BEGIN;

DELETE FROM global_allowlist
 WHERE domain IN ('vnnic.vn', 'gov.vn', 'googleapis.com', 'gstatic.com',
                  'cloudflare.com', 'cloudfront.net', 'akamai.net', 'windowsupdate.com');

DELETE FROM sources
 WHERE name IN ('hagezi-tif', 'hagezi-multi-pro', 'urlhaus', 'opencti');

COMMIT;
