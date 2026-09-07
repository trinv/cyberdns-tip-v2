package store

import (
	"context"
	"fmt"
	"time"
)

// Overview là số liệu tổng quan cho màn hình đầu tiên của dashboard.
type Overview struct {
	DomainsActive  int64            `json:"domains_active"`
	BlockedByCat   map[string]int64 `json:"blocked_by_category"`
	SourcesEnabled int              `json:"sources_enabled"`
	SourcesStale   int              `json:"sources_stale"`
	SourcesFailing int              `json:"sources_failing"`
	Tenants        int              `json:"tenants"`
	LastPolicyRun  *time.Time       `json:"last_policy_run"`
}

// Overview gom số liệu tổng quan. staleAfter là khoảng thời gian sau đó một nguồn bị
// coi là cũ.
func (s *Store) Overview(ctx context.Context, staleAfter time.Duration) (Overview, error) {
	var o Overview
	o.BlockedByCat = map[string]int64{}

	err := s.pool.QueryRow(ctx, `
		SELECT
		  (SELECT count(*) FROM domains WHERE active),
		  (SELECT count(*) FROM sources WHERE enabled),
		  (SELECT count(*) FROM tenants WHERE enabled),
		  (SELECT max(completed_at) FROM policy_runs
		    WHERE status = 'completed' AND NOT is_shadow)`).
		Scan(&o.DomainsActive, &o.SourcesEnabled, &o.Tenants, &o.LastPolicyRun)
	if err != nil {
		return o, fmt.Errorf("store: đọc tổng quan: %w", err)
	}

	rows, err := s.pool.Query(ctx, `
		SELECT c.name, count(*) FILTER (WHERE dd.action = 'BLOCK')
		  FROM categories c
		  LEFT JOIN domain_decisions dd ON dd.category_id = c.id
		 GROUP BY c.name
		 ORDER BY c.name`)
	if err != nil {
		return o, fmt.Errorf("store: đếm theo category: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var name string
		var n int64
		if err := rows.Scan(&name, &n); err != nil {
			return o, err
		}
		o.BlockedByCat[name] = n
	}
	if err := rows.Err(); err != nil {
		return o, err
	}

	// Nguồn "cũ" và nguồn "đang lỗi" là hai chuyện khác nhau: một nguồn có thể vừa
	// import thành công hôm qua rồi hỏng hôm nay, hoặc chưa từng chạy lần nào.
	err = s.pool.QueryRow(ctx, `
		WITH last AS (
			SELECT DISTINCT ON (source_id) source_id, status, completed_at
			  FROM feed_imports
			 ORDER BY source_id, started_at DESC
		)
		SELECT
		  count(*) FILTER (
		    WHERE l.completed_at IS NULL
		       OR l.completed_at < NOW() - make_interval(secs => $1::double precision)),
		  count(*) FILTER (WHERE l.status IN ('failed', 'rejected'))
		  FROM sources s
		  LEFT JOIN last l ON l.source_id = s.id
		 WHERE s.enabled`, staleAfter.Seconds()).
		Scan(&o.SourcesStale, &o.SourcesFailing)
	if err != nil {
		return o, fmt.Errorf("store: đếm nguồn cũ/lỗi: %w", err)
	}
	return o, nil
}

// SourceStatus là một nguồn kèm trạng thái lần import gần nhất.
type SourceStatus struct {
	Source
	LastStatus   string     `json:"last_status"`
	LastRunAt    *time.Time `json:"last_run_at"`
	LastAccepted int        `json:"last_accepted"`
	LastRejected int        `json:"last_rejected"`
	LastError    string     `json:"last_error"`
}

// SourcesWithStatus liệt kê mọi nguồn kèm kết quả lần import gần nhất.
func (s *Store) SourcesWithStatus(ctx context.Context) ([]SourceStatus, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT s.id, s.name, COALESCE(s.url, ''), s.source_type, s.origin::text,
		       s.trust_score, s.enabled, COALESCE(s.refresh_interval_seconds, 0),
		       s.grace_period_seconds, s.max_change_ratio, s.max_response_bytes,
		       COALESCE(s.license, ''), COALESCE(s.attribution, ''),
		       COALESCE(
		         (SELECT array_agg(c.id ORDER BY c.id) FROM categories c
		           WHERE c.name = ANY (
		             SELECT jsonb_array_elements_text(COALESCE(s.config->'categories','[]'::jsonb)))),
		         ARRAY[]::smallint[]),
		       COALESCE(l.status::text, ''), l.started_at,
		       COALESCE(l.accepted_records, 0), COALESCE(l.rejected_records, 0),
		       COALESCE(l.error_message, '')
		  FROM sources s
		  LEFT JOIN LATERAL (
		    SELECT status, started_at, accepted_records, rejected_records, error_message
		      FROM feed_imports WHERE source_id = s.id
		     ORDER BY started_at DESC LIMIT 1
		  ) l ON TRUE
		 ORDER BY s.name`)
	if err != nil {
		return nil, fmt.Errorf("store: đọc nguồn kèm trạng thái: %w", err)
	}
	defer rows.Close()

	var out []SourceStatus
	for rows.Next() {
		var st SourceStatus
		if err := rows.Scan(
			&st.ID, &st.Name, &st.URL, &st.Type, &st.Origin, &st.TrustScore,
			&st.Enabled, &st.RefreshIntervalSec, &st.GracePeriodSec,
			&st.MaxChangeRatio, &st.MaxResponseBytes, &st.License, &st.Attribution,
			&st.CategoryIDs, &st.LastStatus, &st.LastRunAt,
			&st.LastAccepted, &st.LastRejected, &st.LastError,
		); err != nil {
			return nil, fmt.Errorf("store: quét nguồn: %w", err)
		}
		out = append(out, st)
	}
	return out, rows.Err()
}

// SourceByID đọc một nguồn theo id.
func (s *Store) SourceByID(ctx context.Context, id int64) (Source, error) {
	all, err := s.SourcesWithStatus(ctx)
	if err != nil {
		return Source{}, err
	}
	for _, st := range all {
		if st.ID == id {
			return st.Source, nil
		}
	}
	return Source{}, fmt.Errorf("store: không có nguồn id=%d", id)
}

// ImportRecord là một dòng lịch sử import.
type ImportRecord struct {
	ID          int64      `json:"id"`
	SourceName  string     `json:"source"`
	StartedAt   time.Time  `json:"started_at"`
	CompletedAt *time.Time `json:"completed_at"`
	Status      string     `json:"status"`
	FeedHash    string     `json:"feed_hash"`
	Total       int64      `json:"total"`
	Accepted    int64      `json:"accepted"`
	Rejected    int64      `json:"rejected"`
	Added       int64      `json:"added"`
	Removed     int64      `json:"removed"`
	Error       string     `json:"error"`
}

// Imports trả về lịch sử import, mới nhất trước. sourceID = 0 nghĩa là mọi nguồn.
func (s *Store) Imports(ctx context.Context, sourceID int64, limit int) ([]ImportRecord, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}

	rows, err := s.pool.Query(ctx, `
		SELECT i.id, s.name, i.started_at, i.completed_at, i.status::text,
		       COALESCE(i.feed_hash, ''), i.total_records, i.accepted_records,
		       i.rejected_records, i.added_records, i.removed_records,
		       COALESCE(i.error_message, '')
		  FROM feed_imports i
		  JOIN sources s ON s.id = i.source_id
		 WHERE ($1::bigint = 0 OR i.source_id = $1::bigint)
		 ORDER BY i.started_at DESC
		 LIMIT $2::int`, sourceID, limit)
	if err != nil {
		return nil, fmt.Errorf("store: đọc lịch sử import: %w", err)
	}
	defer rows.Close()

	var out []ImportRecord
	for rows.Next() {
		var r ImportRecord
		if err := rows.Scan(&r.ID, &r.SourceName, &r.StartedAt, &r.CompletedAt,
			&r.Status, &r.FeedHash, &r.Total, &r.Accepted, &r.Rejected,
			&r.Added, &r.Removed, &r.Error); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// DomainEvidence là một bằng chứng thô từ tầng L0.
type DomainEvidence struct {
	Source  string    `json:"source"`
	RawLine string    `json:"raw_line"`
	SeenAt  time.Time `json:"seen_at"`
}

// DomainSource là đóng góp của một nguồn cho một domain.
type DomainSource struct {
	Source     string     `json:"source"`
	Origin     string     `json:"origin"`
	TrustScore int        `json:"trust_score"`
	Confidence *int       `json:"confidence"`
	Active     bool       `json:"active"`
	FirstSeen  time.Time  `json:"first_seen"`
	LastSeen   time.Time  `json:"last_seen"`
	ValidUntil *time.Time `json:"valid_until"`
	RevokedAt  *time.Time `json:"revoked_at"`
	Categories []string   `json:"categories"`
}

// DomainDecision là quyết định cho một cặp (domain, category).
type DomainDecision struct {
	Category    string    `json:"category"`
	Action      string    `json:"action"`
	Score       int       `json:"score"`
	Independent int       `json:"independent_sources"`
	ReasonCode  string    `json:"reason_code"`
	DecidedAt   time.Time `json:"decided_at"`
}

// DomainRule là một hàng canonical.
type DomainRule struct {
	ID        int64     `json:"id"`
	MatchType int       `json:"match_type"`
	Active    bool      `json:"active"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

// DomainReport là toàn bộ những gì hệ biết về một domain.
//
// Đây là công cụ xử lý khiếu nại false positive: nó phải trả lời được "vì sao domain
// này bị chặn" bằng bằng chứng THÔ chứ không chỉ bằng kết luận đã suy dẫn.
type DomainReport struct {
	Domain    string           `json:"domain"`
	Found     bool             `json:"found"`
	Rules     []DomainRule     `json:"rules"`
	Decisions []DomainDecision `json:"decisions"`
	Sources   []DomainSource   `json:"sources"`
	Evidence  []DomainEvidence `json:"evidence"`
}

// LookupDomain gom mọi thứ hệ biết về một domain đã chuẩn hóa.
func (s *Store) LookupDomain(ctx context.Context, domain string) (DomainReport, error) {
	rep := DomainReport{Domain: domain}

	rows, err := s.pool.Query(ctx, `
		SELECT id, match_type, active, first_seen, last_seen
		  FROM domains WHERE normalized_domain = $1
		 ORDER BY match_type`, domain)
	if err != nil {
		return rep, fmt.Errorf("store: tra domain: %w", err)
	}
	defer rows.Close()

	var ids []int64
	for rows.Next() {
		var r DomainRule
		if err := rows.Scan(&r.ID, &r.MatchType, &r.Active, &r.FirstSeen, &r.LastSeen); err != nil {
			return rep, err
		}
		rep.Rules = append(rep.Rules, r)
		ids = append(ids, r.ID)
	}
	if err := rows.Err(); err != nil {
		return rep, err
	}
	if len(ids) == 0 {
		return rep, nil
	}
	rep.Found = true

	if err := s.loadDomainDetail(ctx, &rep, ids); err != nil {
		return rep, err
	}
	return rep, nil
}

func (s *Store) loadDomainDetail(ctx context.Context, rep *DomainReport, ids []int64) error {
	drows, err := s.pool.Query(ctx, `
		SELECT c.name, dd.action::text, dd.effective_score,
		       dd.independent_source_count, dd.reason_code, dd.decided_at
		  FROM domain_decisions dd
		  JOIN categories c ON c.id = dd.category_id
		 WHERE dd.domain_id = ANY($1::bigint[])
		 ORDER BY c.name`, ids)
	if err != nil {
		return fmt.Errorf("store: đọc quyết định: %w", err)
	}
	for drows.Next() {
		var d DomainDecision
		if err := drows.Scan(&d.Category, &d.Action, &d.Score,
			&d.Independent, &d.ReasonCode, &d.DecidedAt); err != nil {
			drows.Close()
			return err
		}
		rep.Decisions = append(rep.Decisions, d)
	}
	drows.Close()

	srows, err := s.pool.Query(ctx, `
		SELECT src.name, src.origin::text, src.trust_score, ds.confidence, ds.active,
		       ds.first_seen, ds.last_seen, ds.valid_until, ds.revoked_at,
		       COALESCE(
		         (SELECT array_agg(c.name ORDER BY c.name)
		            FROM domain_source_categories dsc
		            JOIN categories c ON c.id = dsc.category_id
		           WHERE dsc.domain_id = ds.domain_id AND dsc.source_id = ds.source_id),
		         ARRAY[]::text[])
		  FROM domain_sources ds
		  JOIN sources src ON src.id = ds.source_id
		 WHERE ds.domain_id = ANY($1::bigint[])
		 ORDER BY src.name`, ids)
	if err != nil {
		return fmt.Errorf("store: đọc nguồn của domain: %w", err)
	}
	for srows.Next() {
		var d DomainSource
		if err := srows.Scan(&d.Source, &d.Origin, &d.TrustScore, &d.Confidence,
			&d.Active, &d.FirstSeen, &d.LastSeen, &d.ValidUntil, &d.RevokedAt,
			&d.Categories); err != nil {
			srows.Close()
			return err
		}
		rep.Sources = append(rep.Sources, d)
	}
	srows.Close()

	// Bằng chứng thô L0: đây là thứ trả lời "lúc đó nguồn nói gì", kể cả sau khi nguồn
	// đã gỡ domain đi.
	erows, err := s.pool.Query(ctx, `
		SELECT src.name, e.raw_line, e.seen_at
		  FROM domain_evidence e
		  JOIN sources src ON src.id = e.source_id
		 WHERE e.domain_id = ANY($1::bigint[])
		 ORDER BY e.seen_at DESC
		 LIMIT 50`, ids)
	if err != nil {
		return fmt.Errorf("store: đọc bằng chứng: %w", err)
	}
	defer erows.Close()

	for erows.Next() {
		var e DomainEvidence
		if err := erows.Scan(&e.Source, &e.RawLine, &e.SeenAt); err != nil {
			return err
		}
		rep.Evidence = append(rep.Evidence, e)
	}
	return erows.Err()
}
