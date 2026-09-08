// Package store là tầng truy cập PostgreSQL cho L0 và L1.
//
// Hai bất biến của mô hình suy dẫn được thực thi ở đây:
//
//   - L0 (domain_evidence) chỉ ghi thêm. CSDL đã có trigger chặn UPDATE/DELETE; package
//     này không bao giờ thử.
//   - Hàng dùng chung trong bảng domains chỉ được cập nhật bằng thao tác GIAO HOÁN.
//     feed-ingestor và sync-consumer cùng chạm vào hàng này; nếu bên nào cũng ghi đè
//     thì kết quả phụ thuộc thứ tự chạy, và cùng một dữ liệu đầu vào sẽ cho ra hai
//     trạng thái khác nhau (xung đột B4).
//
// Dữ liệu riêng của từng nguồn nằm ở domain_sources, khóa theo source_id, nên mỗi
// source_id có đúng một bên ghi và hai bên không bao giờ đè lên nhau.
package store

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/vnnic/cyberdns-tip/internal/domainname"
)

// Store bọc connection pool.
type Store struct {
	pool *pgxpool.Pool
}

func New(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

// Pool trả về pool bên dưới, dùng cho các truy vấn đặc thù.
func (s *Store) Pool() *pgxpool.Pool { return s.pool }

// Source là một nguồn feed đã cấu hình.
type Source struct {
	ID                 int64
	Name               string
	URL                string
	Type               string
	Origin             string
	TrustScore         int
	Enabled            bool
	RefreshIntervalSec int
	GracePeriodSec     int
	MaxChangeRatio     float64
	MaxResponseBytes   int64
	License            string
	Attribution        string
	CategoryIDs        []int16
}

// EnabledSources trả về các nguồn đang bật, kèm category mà chúng ánh xạ tới.
//
// Ánh xạ category lấy từ cột config->>'categories' của nguồn: một mảng JSON chứa tên
// category, ví dụ ["malware","phishing"].
func (s *Store) EnabledSources(ctx context.Context, origin string) ([]Source, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT s.id, s.name, COALESCE(s.url, ''), s.source_type, s.origin::text,
		       s.trust_score, s.enabled, COALESCE(s.refresh_interval_seconds, 0),
		       s.grace_period_seconds, s.max_change_ratio, s.max_response_bytes,
		       COALESCE(s.license, ''), COALESCE(s.attribution, ''),
		       COALESCE(
		         (SELECT array_agg(c.id ORDER BY c.id)
		            FROM categories c
		           WHERE c.name = ANY (
		             SELECT jsonb_array_elements_text(COALESCE(s.config->'categories', '[]'::jsonb))
		           )),
		         ARRAY[]::smallint[]
		       )
		  FROM sources s
		 WHERE s.enabled AND s.origin = $1::source_origin
		 ORDER BY s.id`, origin)
	if err != nil {
		return nil, fmt.Errorf("store: đọc danh sách nguồn: %w", err)
	}
	defer rows.Close()

	var out []Source
	for rows.Next() {
		var src Source
		if err := rows.Scan(
			&src.ID, &src.Name, &src.URL, &src.Type, &src.Origin,
			&src.TrustScore, &src.Enabled, &src.RefreshIntervalSec,
			&src.GracePeriodSec, &src.MaxChangeRatio, &src.MaxResponseBytes,
			&src.License, &src.Attribution, &src.CategoryIDs,
		); err != nil {
			return nil, fmt.Errorf("store: quét hàng nguồn: %w", err)
		}
		out = append(out, src)
	}
	return out, rows.Err()
}

// LastImport là kết quả lần import thành công gần nhất của một nguồn.
type LastImport struct {
	Found        bool
	FeedHash     string
	ETag         string
	LastModified string
	Accepted     int
}

// LastSuccessfulImport dùng cho request có điều kiện và cho ngưỡng biến động.
func (s *Store) LastSuccessfulImport(ctx context.Context, sourceID int64) (LastImport, error) {
	var li LastImport
	err := s.pool.QueryRow(ctx, `
		SELECT COALESCE(feed_hash, ''), COALESCE(http_etag, ''),
		       COALESCE(http_last_modified, ''), accepted_records
		  FROM feed_imports
		 WHERE source_id = $1 AND status = 'completed'
		 ORDER BY completed_at DESC NULLS LAST
		 LIMIT 1`, sourceID).
		Scan(&li.FeedHash, &li.ETag, &li.LastModified, &li.Accepted)

	if err == pgx.ErrNoRows {
		return LastImport{}, nil
	}
	if err != nil {
		return LastImport{}, fmt.Errorf("store: đọc lần import trước: %w", err)
	}
	li.Found = true
	return li, nil
}

// BeginImport mở một bản ghi audit và trả về id của nó.
func (s *Store) BeginImport(ctx context.Context, sourceID int64) (int64, error) {
	var id int64
	err := s.pool.QueryRow(ctx, `
		INSERT INTO feed_imports (source_id, started_at, status)
		VALUES ($1, NOW(), 'running')
		RETURNING id`, sourceID).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("store: mở bản ghi import: %w", err)
	}
	return id, nil
}

// ImportResult là số liệu kết thúc một lần import.
type ImportResult struct {
	Status       string // completed | rejected | failed | unchanged
	FeedHash     string
	ETag         string
	LastModified string
	HTTPStatus   int
	Bytes        int64
	Total        int
	Accepted     int
	Rejected     int
	Added        int
	Updated      int
	Removed      int
	ErrorMessage string
}

// FinishImport đóng bản ghi audit.
//
// Luôn phải gọi, kể cả khi import hỏng: một bản ghi mắc kẹt ở trạng thái 'running' sẽ
// khiến LastSuccessfulImport bỏ sót và mọi cảnh báo feed stale trở nên vô nghĩa.
func (s *Store) FinishImport(ctx context.Context, importID int64, r ImportResult) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE feed_imports
		   SET completed_at = NOW(), status = $2::import_status,
		       feed_hash = NULLIF($3, ''), http_etag = NULLIF($4, ''),
		       http_last_modified = NULLIF($5, ''), http_status = NULLIF($6, 0),
		       response_bytes = $7,
		       total_records = $8, accepted_records = $9, rejected_records = $10,
		       added_records = $11, updated_records = $12, removed_records = $13,
		       error_message = NULLIF($14, '')
		 WHERE id = $1`,
		importID, r.Status, r.FeedHash, r.ETag, r.LastModified, r.HTTPStatus,
		r.Bytes, r.Total, r.Accepted, r.Rejected, r.Added, r.Updated, r.Removed,
		r.ErrorMessage)
	if err != nil {
		return fmt.Errorf("store: đóng bản ghi import: %w", err)
	}
	return nil
}

// Record là một rule đã chuẩn hóa cùng dòng thô sinh ra nó.
type Record struct {
	Rule    domainname.Rule
	RawLine string
	RawHash string
}

// stagingDDL dựng bảng tạm cho một lần import.
//
// UNLOGGED thay vì TEMP: bảng tạm gắn với phiên kết nối, mà pgxpool có thể trả kết nối
// khác nhau giữa các lệnh. UNLOGGED không ghi WAL nên vẫn nhanh, và bị xóa tường minh
// ở cuối.
const stagingDDL = `
CREATE UNLOGGED TABLE IF NOT EXISTS staging_import_%d (
  normalized_domain TEXT NOT NULL,
  match_type        SMALLINT NOT NULL,
  raw_line          TEXT NOT NULL,
  raw_hash          TEXT NOT NULL
)`

// ApplyResult là số hàng thay đổi khi hợp nhất.
type ApplyResult struct {
	Added   int
	Updated int
	Removed int
}

// Apply nạp toàn bộ record của một lần import vào L0 và L1, trong MỘT transaction.
//
// Hoặc cả lần import có hiệu lực, hoặc không có gì đổi. Đây là điều kiện để quy tắc
// fail-closed của SKILL.md có ý nghĩa: một feed hỏng giữa chừng không được để lại một
// nửa dữ liệu mới lẫn với một nửa dữ liệu cũ.
func (s *Store) Apply(
	ctx context.Context,
	src Source,
	importID int64,
	feedHash string,
	records []Record,
	now time.Time,
) (ApplyResult, error) {
	var res ApplyResult

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return res, fmt.Errorf("store: mở transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()

	staging := fmt.Sprintf("staging_import_%d", importID)

	if _, err := tx.Exec(ctx, fmt.Sprintf(stagingDDL, importID)); err != nil {
		return res, fmt.Errorf("store: tạo bảng staging: %w", err)
	}
	if _, err := tx.Exec(ctx, "TRUNCATE "+staging); err != nil {
		return res, fmt.Errorf("store: dọn bảng staging: %w", err)
	}

	// Khử trùng lặp NGAY TẠI ĐÂY thay vì để SELECT DISTINCT trong SQL lo.
	//
	// Đo trên feed HaGeZi thật (2,15 triệu dòng): để SQL khử trùng lặp khiến truy vấn
	// hợp nhất category chạy hơn 6 phút mà chưa xong, vì nó phải sắp xếp 6,45 triệu
	// hàng (2,15 triệu nhân 3 category). Khử ở Go tốn vài trăm mili giây.
	seen := make(map[domainname.Rule]struct{}, len(records))
	rows := make([][]any, 0, len(records))
	for _, r := range records {
		if _, dup := seen[r.Rule]; dup {
			continue
		}
		seen[r.Rule] = struct{}{}
		rows = append(rows, []any{
			r.Rule.Domain, int16(r.Rule.MatchType), r.RawLine, r.RawHash,
		})
	}
	if _, err := tx.CopyFrom(ctx,
		pgx.Identifier{staging},
		[]string{"normalized_domain", "match_type", "raw_line", "raw_hash"},
		pgx.CopyFromRows(rows),
	); err != nil {
		return res, fmt.Errorf("store: COPY vào staging: %w", err)
	}

	// Index và ANALYZE trước khi hợp nhất.
	//
	// Bảng staging được join ba lần với bảng domains (quan hệ nguồn, category, bằng
	// chứng). Không có index thì mỗi lần là một hash join trên hàng triệu hàng, và
	// planner không có thống kê nên chọn sai kế hoạch.
	if _, err := tx.Exec(ctx, fmt.Sprintf(
		"CREATE INDEX ON %s (normalized_domain, match_type)", staging)); err != nil {
		return res, fmt.Errorf("store: tạo index staging: %w", err)
	}
	if _, err := tx.Exec(ctx, "ANALYZE "+staging); err != nil {
		return res, fmt.Errorf("store: ANALYZE staging: %w", err)
	}

	if err := applyMerge(ctx, tx, staging, src, importID, feedHash, now, &res); err != nil {
		return res, err
	}

	if _, err := tx.Exec(ctx, "DROP TABLE IF EXISTS "+staging); err != nil {
		return res, fmt.Errorf("store: xóa bảng staging: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return res, fmt.Errorf("store: commit: %w", err)
	}
	return res, nil
}

func applyMerge(
	ctx context.Context,
	tx pgx.Tx,
	staging string,
	src Source,
	importID int64,
	feedHash string,
	now time.Time,
	res *ApplyResult,
) error {
	// 1. Hợp nhất vào domains.
	//
	// last_seen dùng GREATEST và active chỉ được bật lên, không bao giờ tắt ở đây:
	// đó là phép hợp nhất GIAO HOÁN mà xung đột B4 đòi hỏi. Nếu ghi đè thẳng, thứ tự
	// chạy giữa feed-ingestor và sync-consumer sẽ quyết định kết quả.
	//
	// raw_hash chỉ đặt khi hàng còn trống, để không xóa mất giá trị của bên kia.
	var added int
	err := tx.QueryRow(ctx, fmt.Sprintf(`
		WITH ins AS (
			INSERT INTO domains (normalized_domain, match_type, raw_hash, first_seen, last_seen, active)
			SELECT normalized_domain, match_type, raw_hash,
			       $1::timestamptz, $1::timestamptz, TRUE
			  FROM %s
			ON CONFLICT (normalized_domain, match_type) DO UPDATE
			   SET last_seen  = GREATEST(domains.last_seen, EXCLUDED.last_seen),
			       first_seen = LEAST(domains.first_seen, EXCLUDED.first_seen),
			       raw_hash   = COALESCE(domains.raw_hash, EXCLUDED.raw_hash),
			       active     = TRUE,
			       updated_at = NOW()
			RETURNING (xmax = 0) AS inserted
		)
		SELECT count(*) FILTER (WHERE inserted) FROM ins`, staging), now).Scan(&added)
	if err != nil {
		return fmt.Errorf("store: hợp nhất domains: %w", err)
	}
	res.Added = added

	// 2. Quan hệ nguồn. Đây là hàng RIÊNG của nguồn này; không bên nào khác ghi vào.
	var updated int
	err = tx.QueryRow(ctx, fmt.Sprintf(`
		WITH ins AS (
			INSERT INTO domain_sources
			       (domain_id, source_id, confidence, first_seen, last_seen, active)
			SELECT d.id, $2::bigint, $3::smallint, $1::timestamptz, $1::timestamptz, TRUE
			  FROM %s s
			  JOIN domains d
			    ON d.normalized_domain = s.normalized_domain
			   AND d.match_type = s.match_type
			ON CONFLICT (domain_id, source_id) DO UPDATE
			   SET last_seen = GREATEST(domain_sources.last_seen, EXCLUDED.last_seen),
			       active    = TRUE,
			       -- Nguồn liệt kê lại domain nghĩa là nó rút lại việc thu hồi trước đó.
			       revoked_at = NULL
			RETURNING (xmax <> 0) AS was_update
		)
		SELECT count(*) FILTER (WHERE was_update) FROM ins`, staging),
		now, src.ID, defaultConfidence(src)).Scan(&updated)
	if err != nil {
		return fmt.Errorf("store: hợp nhất domain_sources: %w", err)
	}
	res.Updated = updated

	// 3. Category do CHÍNH NGUỒN NÀY khẳng định.
	//
	// Không gán phẳng cho domain: có tách theo nguồn thì mới đếm được "bao nhiêu nguồn
	// độc lập xác nhận category X" — đầu vào bắt buộc của policy (xung đột A1, B3).
	if len(src.CategoryIDs) > 0 {
		// Không truyền "now" vào đây: câu lệnh không dùng tới nó, và Postgres từ chối
		// một tham số không xuất hiện ở đâu trong câu lệnh với lỗi "could not
		// determine data type of parameter".
		if _, err := tx.Exec(ctx, fmt.Sprintf(`
			INSERT INTO domain_source_categories (domain_id, source_id, category_id, confidence)
			SELECT d.id, $1::bigint, c.category_id, $2::smallint
			  FROM %s s
			  JOIN domains d
			    ON d.normalized_domain = s.normalized_domain
			   AND d.match_type = s.match_type
			  CROSS JOIN unnest($3::smallint[]) AS c(category_id)
			ON CONFLICT (domain_id, source_id, category_id) DO NOTHING`, staging),
			src.ID, defaultConfidence(src), src.CategoryIDs); err != nil {
			return fmt.Errorf("store: hợp nhất domain_source_categories: %w", err)
		}
	}

	// 4. Bằng chứng L0 — chỉ ghi thêm, không bao giờ sửa.
	//
	// Chỉ ghi khi bản ghi MỚI hoặc dòng thô ĐÃ ĐỔI, không ghi lại mọi dòng ở mọi lần
	// import. Ghi tất cả nghe có vẻ trung thực hơn, nhưng đo trên feed thật thì đó là
	// 2,15 triệu hàng mỗi lần feed đổi; HaGeZi đổi vài lần mỗi ngày, tức là hàng tỉ
	// hàng mỗi năm cho một nguồn. Ghi lại một dòng y hệt lần trước không mang thêm
	// thông tin nào: việc "vẫn còn thấy" đã nằm ở domain_sources.last_seen, còn
	// feed_imports giữ lịch sử từng lần chạy.
	if _, err := tx.Exec(ctx, fmt.Sprintf(`
		INSERT INTO domain_evidence
		       (domain_id, source_id, feed_import_id, raw_line, raw_hash, feed_hash, seen_at)
		SELECT d.id, $2::bigint, $3::bigint, s.raw_line, s.raw_hash, NULLIF($4::text, ''), $1::timestamptz
		  FROM %s s
		  JOIN domains d
		    ON d.normalized_domain = s.normalized_domain
		   AND d.match_type = s.match_type
		 WHERE NOT EXISTS (
		         SELECT 1 FROM domain_evidence e
		          WHERE e.domain_id = d.id
		            AND e.source_id = $2::bigint
		            AND e.raw_hash  = s.raw_hash
		       )`, staging),
		now, src.ID, importID, feedHash); err != nil {
		return fmt.Errorf("store: ghi domain_evidence: %w", err)
	}

	// 5. Vô hiệu hóa những domain nguồn này không còn liệt kê, sau khi hết grace period.
	//
	// KHÔNG xóa cứng, và chỉ đụng tới hàng của CHÍNH nguồn này: domain vẫn có thể đang
	// được nguồn khác khẳng định (xung đột A4, A5). Grace period chống feed flapping —
	// domain biến mất rồi quay lại giữa hai lần refresh không được rời khỏi blocklist.
	var removed int
	err = tx.QueryRow(ctx, `
		WITH deactivated AS (
			UPDATE domain_sources
			   SET active = FALSE
			 WHERE source_id = $1::bigint
			   AND active
			   AND last_seen < $2::timestamptz - make_interval(secs => $3::double precision)
			RETURNING 1
		)
		SELECT count(*) FROM deactivated`,
		src.ID, now, src.GracePeriodSec).Scan(&removed)
	if err != nil {
		return fmt.Errorf("store: vô hiệu hóa bản ghi cũ: %w", err)
	}
	res.Removed = removed

	// 6. Domain không còn nguồn nào đang hoạt động thì tự nó cũng không còn hiệu lực.
	if _, err := tx.Exec(ctx, `
		UPDATE domains d
		   SET active = FALSE, updated_at = NOW()
		 WHERE d.active
		   AND NOT EXISTS (
		         SELECT 1 FROM domain_sources ds
		          WHERE ds.domain_id = d.id AND ds.active
		       )`); err != nil {
		return fmt.Errorf("store: vô hiệu hóa domain mồ côi: %w", err)
	}

	return nil
}

// defaultConfidence quy đổi trust score của nguồn thành confidence mặc định cho các
// bản ghi mà nguồn không tự cung cấp giá trị.
func defaultConfidence(src Source) int16 {
	if src.TrustScore <= 0 {
		return 50
	}
	if src.TrustScore > 100 {
		return 100
	}
	return int16(src.TrustScore)
}

// SetSourceEnabled bật hoặc tắt một nguồn theo tên.
//
// Ràng buộc thêm origin chứ không chỉ tên: bật nhầm một nguồn feed thường thành nguồn
// OpenCTI sẽ khiến dữ liệu quay về từ OpenCTI được tính là xác nhận độc lập và làm lạm
// phát điểm — đúng vòng lặp phản hồi mà cột origin sinh ra để chặn.
func (s *Store) SetSourceEnabled(ctx context.Context, name, origin string, enabled bool) (bool, error) {
	tag, err := s.pool.Exec(ctx, `
		UPDATE sources
		   SET enabled = $3::boolean, updated_at = NOW()
		 WHERE name = $1::text AND origin = $2::source_origin AND enabled <> $3::boolean`,
		name, origin, enabled)
	if err != nil {
		return false, fmt.Errorf("store: đổi trạng thái nguồn %s: %w", name, err)
	}
	return tag.RowsAffected() > 0, nil
}
