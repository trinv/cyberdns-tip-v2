package store

import (
	"context"
	"fmt"
	"time"

	"github.com/vnnic/cyberdns-tip/internal/domainname"
	"github.com/vnnic/cyberdns-tip/internal/match"
)

// Tenant là một tổ chức nhận blocklist, kèm toàn bộ override của họ.
type Tenant struct {
	ID           int64
	Name         string
	Slug         string
	IsDefault    bool
	OutputFormat string

	// Categories là các category tenant này đăng ký, đã sắp xếp.
	Categories []string

	// Allow là ngoại lệ của tenant. Nó KHÔNG chỉ đơn giản là loại domain khỏi file
	// denylist: khi domain nằm dưới một rule cha wildcard, gỡ rule cha sẽ mở toang cả
	// nhánh. Vì vậy các mục này còn được phát hành thành một file allowlist riêng để
	// Blocky nạp vào cấu hình allowlist của nó (xung đột D2).
	Allow *match.Matcher

	// AllowRules là chính các mục đó, dùng để dựng file allowlist.
	AllowRules []domainname.Rule

	// Deny là các domain tenant tự yêu cầu chặn thêm, khóa theo category.
	// Khóa rỗng nghĩa là áp cho mọi category tenant đăng ký.
	Deny map[string][]domainname.Rule
}

// Tenants trả về mọi tenant đang bật kèm override của họ.
//
// Mục đã hết hạn bị loại ngay lúc nạp, nên tầng dựng không cần biết tới expires_at.
func (s *Store) Tenants(ctx context.Context, now time.Time) ([]Tenant, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT t.id, t.name, t.slug, t.is_default, t.output_format,
		       COALESCE(
		         (SELECT array_agg(c.name ORDER BY c.name)
		            FROM tenant_categories tc
		            JOIN categories c ON c.id = tc.category_id
		           WHERE tc.tenant_id = t.id AND tc.enabled),
		         ARRAY[]::text[]
		       )
		  FROM tenants t
		 WHERE t.enabled
		 ORDER BY t.id`)
	if err != nil {
		return nil, fmt.Errorf("store: đọc tenant: %w", err)
	}
	defer rows.Close()

	var out []Tenant
	for rows.Next() {
		var t Tenant
		if err := rows.Scan(&t.ID, &t.Name, &t.Slug, &t.IsDefault,
			&t.OutputFormat, &t.Categories); err != nil {
			return nil, fmt.Errorf("store: quét tenant: %w", err)
		}
		t.Allow = match.New()
		t.Deny = map[string][]domainname.Rule{}
		out = append(out, t)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	for i := range out {
		if err := s.loadTenantOverrides(ctx, &out[i], now); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (s *Store) loadTenantOverrides(ctx context.Context, t *Tenant, now time.Time) error {
	arows, err := s.pool.Query(ctx, `
		SELECT domain, match_type
		  FROM tenant_allowlist
		 WHERE tenant_id = $1::bigint
		   AND (expires_at IS NULL OR expires_at > $2::timestamptz)
		 ORDER BY domain, match_type`, t.ID, now)
	if err != nil {
		return fmt.Errorf("store: đọc tenant_allowlist: %w", err)
	}
	defer arows.Close()

	for arows.Next() {
		var domain string
		var mt int16
		if err := arows.Scan(&domain, &mt); err != nil {
			return fmt.Errorf("store: quét tenant_allowlist: %w", err)
		}
		rule := domainname.Rule{Domain: domain, MatchType: domainname.MatchType(mt)}
		t.Allow.Add(rule.Domain, rule.MatchType)
		t.AllowRules = append(t.AllowRules, rule)
	}
	if err := arows.Err(); err != nil {
		return err
	}

	drows, err := s.pool.Query(ctx, `
		SELECT d.domain, d.match_type, COALESCE(c.name, '')
		  FROM tenant_denylist d
		  LEFT JOIN categories c ON c.id = d.category_id
		 WHERE d.tenant_id = $1::bigint
		   AND (d.expires_at IS NULL OR d.expires_at > $2::timestamptz)
		 ORDER BY d.domain, d.match_type`, t.ID, now)
	if err != nil {
		return fmt.Errorf("store: đọc tenant_denylist: %w", err)
	}
	defer drows.Close()

	for drows.Next() {
		var domain, category string
		var mt int16
		if err := drows.Scan(&domain, &mt, &category); err != nil {
			return fmt.Errorf("store: quét tenant_denylist: %w", err)
		}
		// category rỗng nghĩa là áp cho mọi category tenant đăng ký.
		t.Deny[category] = append(t.Deny[category],
			domainname.Rule{Domain: domain, MatchType: domainname.MatchType(mt)})
	}
	return drows.Err()
}
