package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/vnnic/cyberdns-tip/internal/domainname"
	"github.com/vnnic/cyberdns-tip/internal/match"
	"github.com/vnnic/cyberdns-tip/internal/policy"
)

// Lists là các danh sách tra cứu, đã nạp sẵn vào bộ nhớ.
//
// Nạp một lần cho cả lượt chạy thay vì truy vấn theo từng domain: ở mốc 10M domain
// nhân số category thì tra cứu bằng SQL là hàng chục triệu lượt truy vấn.
type Lists struct {
	ProtectedAllow *match.Matcher
	GlobalAllow    *match.Matcher
	GlobalBlock    *match.Matcher
}

// LoadLists nạp allowlist toàn cục và danh sách chặn thủ công.
//
// Mục đã hết hạn bị bỏ qua ngay lúc nạp, nên policy không cần biết tới expires_at.
func (s *Store) LoadLists(ctx context.Context, now time.Time) (Lists, error) {
	l := Lists{
		ProtectedAllow: match.New(),
		GlobalAllow:    match.New(),
		GlobalBlock:    match.New(),
	}

	rows, err := s.pool.Query(ctx, `
		SELECT domain, match_type, tier::text
		  FROM global_allowlist
		 WHERE expires_at IS NULL OR expires_at > $1::timestamptz`, now)
	if err != nil {
		return l, fmt.Errorf("store: nạp global_allowlist: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var domain, tier string
		var mt int16
		if err := rows.Scan(&domain, &mt, &tier); err != nil {
			return l, fmt.Errorf("store: quét global_allowlist: %w", err)
		}
		// Hai mức khác nhau về quyền: protected không ai override được, soft thì
		// tenant override bằng denylist riêng (xung đột D3).
		if tier == "protected" {
			l.ProtectedAllow.Add(domain, domainname.MatchType(mt))
		} else {
			l.GlobalAllow.Add(domain, domainname.MatchType(mt))
		}
	}
	if err := rows.Err(); err != nil {
		return l, err
	}

	brows, err := s.pool.Query(ctx, `
		SELECT domain, match_type
		  FROM global_block_overrides
		 WHERE expires_at IS NULL OR expires_at > $1::timestamptz`, now)
	if err != nil {
		return l, fmt.Errorf("store: nạp global_block_overrides: %w", err)
	}
	defer brows.Close()

	for brows.Next() {
		var domain string
		var mt int16
		if err := brows.Scan(&domain, &mt); err != nil {
			return l, fmt.Errorf("store: quét global_block_overrides: %w", err)
		}
		l.GlobalBlock.Add(domain, domainname.MatchType(mt))
	}
	return l, brows.Err()
}

// BeginPolicyRun mở một lượt chạy policy.
//
// Generator chỉ dựng snapshot từ một lượt đã HOÀN TẤT, nên không bao giờ đọc phải
// trạng thái nửa cũ nửa mới (xung đột C4).
func (s *Store) BeginPolicyRun(ctx context.Context, cfg policy.Config, shadow bool) (int64, error) {
	raw, err := json.Marshal(cfg)
	if err != nil {
		return 0, fmt.Errorf("store: mã hóa cấu hình policy: %w", err)
	}

	var id int64
	err = s.pool.QueryRow(ctx, `
		INSERT INTO policy_runs (policy_version, policy_config, is_shadow, status)
		VALUES ($1, $2::jsonb, $3, 'running')
		RETURNING id`, cfg.Version, string(raw), shadow).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("store: mở policy run: %w", err)
	}
	return id, nil
}

// FinishPolicyRun đóng một lượt chạy. Chỉ lượt có status 'completed' mới được generator
// dùng để dựng snapshot.
func (s *Store) FinishPolicyRun(ctx context.Context, runID int64, status string, evaluated, blocked int64, errMsg string) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE policy_runs
		   SET status = $2::policy_run_status, completed_at = NOW(),
		       domains_evaluated = $3, domains_blocked = $4,
		       error_message = NULLIF($5, '')
		 WHERE id = $1`, runID, status, evaluated, blocked, errMsg)
	if err != nil {
		return fmt.Errorf("store: đóng policy run: %w", err)
	}
	return nil
}

// RunStats là kết quả một lượt chạy policy.
type RunStats struct {
	Evaluated int64
	Blocked   int64
	Changed   int64
}

// evidenceRow là một hàng thô từ truy vấn gom bằng chứng.
type evidenceRow struct {
	domainID   int64
	domain     string
	matchType  int16
	categoryID int16
	category   string

	sourceName string
	origin     string
	trust      int
	confidence *int16
	lastSeen   time.Time
	validUntil *time.Time
	revokedAt  *time.Time
}

// evidenceQuery gom bằng chứng theo (domain, category).
//
// ORDER BY quyết định tính đúng đắn chứ không phải để cho đẹp: hàm chạy theo kiểu
// streaming và gom nhóm khi ranh giới (domain_id, category_id) đổi, nên dữ liệu phải
// tới đúng thứ tự đó. Streaming là bắt buộc — ở mốc 10M domain thì nạp hết vào bộ nhớ
// là vài GB.
const evidenceQuery = `
SELECT d.id, d.normalized_domain, d.match_type,
       dsc.category_id, c.name,
       s.name, s.origin::text, s.trust_score,
       dsc.confidence, ds.last_seen, ds.valid_until, ds.revoked_at
  FROM domain_source_categories dsc
  JOIN domains d        ON d.id = dsc.domain_id
  JOIN domain_sources ds ON ds.domain_id = dsc.domain_id AND ds.source_id = dsc.source_id
  JOIN sources s        ON s.id = dsc.source_id
  JOIN categories c     ON c.id = dsc.category_id
 WHERE d.active AND ds.active
 ORDER BY dsc.domain_id, dsc.category_id`

// decision là một quyết định chờ ghi.
type decision struct {
	domainID    int64
	categoryID  int16
	action      string
	score       int16
	independent int16
	reason      string
	matched     string
}

// EvaluateAll chạy policy trên toàn bộ L1 và ghi kết quả xuống L2.
//
// Toàn bộ phần ghi nằm trong một transaction: generator đọc song song sẽ thấy hoặc
// trạng thái cũ trọn vẹn, hoặc trạng thái mới trọn vẹn.
func (s *Store) EvaluateAll(
	ctx context.Context,
	runID int64,
	cfg policy.Config,
	lists Lists,
	now time.Time,
) (RunStats, error) {
	var stats RunStats

	rows, err := s.pool.Query(ctx, evidenceQuery)
	if err != nil {
		return stats, fmt.Errorf("store: truy vấn bằng chứng: %w", err)
	}
	defer rows.Close()

	var (
		pending    []decision
		curDomain  int64 = -1
		curCat     int16 = -1
		curName    string
		curCatName string
		evidence   []policy.Evidence
	)

	flush := func() {
		if curDomain < 0 {
			return
		}
		d := evaluateOne(curDomain, curName, curCat, curCatName, evidence, cfg, lists, now)
		stats.Evaluated++
		if d.action == string(policy.Block) {
			stats.Blocked++
		}
		pending = append(pending, d)
		evidence = evidence[:0]
	}

	for rows.Next() {
		var r evidenceRow
		if err := rows.Scan(
			&r.domainID, &r.domain, &r.matchType, &r.categoryID, &r.category,
			&r.sourceName, &r.origin, &r.trust, &r.confidence,
			&r.lastSeen, &r.validUntil, &r.revokedAt,
		); err != nil {
			return stats, fmt.Errorf("store: quét bằng chứng: %w", err)
		}

		if r.domainID != curDomain || r.categoryID != curCat {
			flush()
			curDomain, curCat = r.domainID, r.categoryID
			curName, curCatName = r.domain, r.category
		}
		evidence = append(evidence, toEvidence(r))
	}
	if err := rows.Err(); err != nil {
		return stats, fmt.Errorf("store: đọc bằng chứng: %w", err)
	}
	flush()
	rows.Close()

	changed, err := s.writeDecisions(ctx, runID, pending)
	if err != nil {
		return stats, err
	}
	stats.Changed = changed
	return stats, nil
}

func toEvidence(r evidenceRow) policy.Evidence {
	conf := 50
	if r.confidence != nil {
		conf = int(*r.confidence)
	}
	return policy.Evidence{
		SourceID:   r.sourceName,
		Origin:     policy.Origin(r.origin),
		TrustScore: r.trust,
		Confidence: conf,
		LastSeen:   r.lastSeen,
		ValidUntil: r.validUntil,
		RevokedAt:  r.revokedAt,
	}
}

func evaluateOne(
	domainID int64, domain string,
	categoryID int16, category string,
	evidence []policy.Evidence,
	cfg policy.Config, lists Lists, now time.Time,
) decision {
	in := policy.Input{
		Domain:   domain,
		Category: category,
		Evidence: evidence,
		Now:      now,

		// Các cờ này đã bao gồm khớp theo tổ tiên: rule wildcard ở "example.com" phủ
		// luôn "shop.example.com". Việc giải quyết nằm ở package match.
		InProtectedAllowlist:  lists.ProtectedAllow.Match(domain),
		InGlobalAllowlist:     lists.GlobalAllow.Match(domain),
		InGlobalBlockOverride: lists.GlobalBlock.Match(domain),
		// Danh sách theo tenant áp ở tầng L3 lúc dựng snapshot, không phải ở đây:
		// L2 dùng chung cho mọi tenant nên phần đắt tiền chỉ tính một lần.
	}

	d := policy.Evaluate(in, cfg)

	matched, _ := json.Marshal(d.MatchedRules)
	return decision{
		domainID:    domainID,
		categoryID:  categoryID,
		action:      string(d.Action),
		score:       int16(d.Score),
		independent: int16(d.IndependentSourceCount),
		reason:      string(d.ReasonCode),
		matched:     string(matched),
	}
}

// writeDecisions ghi quyết định mới, đồng thời ghi lại các lần CHUYỂN trạng thái.
func (s *Store) writeDecisions(ctx context.Context, runID int64, decisions []decision) (int64, error) {
	if len(decisions) == 0 {
		return 0, nil
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("store: mở transaction quyết định: %w", err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()

	staging := fmt.Sprintf("staging_decisions_%d", runID)
	if _, err := tx.Exec(ctx, fmt.Sprintf(`
		CREATE UNLOGGED TABLE IF NOT EXISTS %s (
		  domain_id                BIGINT NOT NULL,
		  category_id              SMALLINT NOT NULL,
		  action                   TEXT NOT NULL,
		  effective_score          SMALLINT NOT NULL,
		  independent_source_count SMALLINT NOT NULL,
		  reason_code              TEXT NOT NULL,
		  matched_rules            JSONB NOT NULL
		)`, staging)); err != nil {
		return 0, fmt.Errorf("store: tạo staging quyết định: %w", err)
	}
	if _, err := tx.Exec(ctx, "TRUNCATE "+staging); err != nil {
		return 0, fmt.Errorf("store: dọn staging quyết định: %w", err)
	}

	rows := make([][]any, 0, len(decisions))
	for _, d := range decisions {
		rows = append(rows, []any{
			d.domainID, d.categoryID, d.action, d.score, d.independent, d.reason, d.matched,
		})
	}
	if _, err := tx.CopyFrom(ctx, pgx.Identifier{staging},
		[]string{"domain_id", "category_id", "action", "effective_score",
			"independent_source_count", "reason_code", "matched_rules"},
		pgx.CopyFromRows(rows)); err != nil {
		return 0, fmt.Errorf("store: COPY quyết định: %w", err)
	}

	// Ghi lần chuyển trạng thái TRƯỚC khi upsert: sau khi upsert thì giá trị cũ không
	// còn ở đâu để so sánh. Chỉ ghi khi action thật sự đổi — lưu trọn mọi lượt chạy ở
	// mốc 10M domain là quá tốn, nhưng vẫn phải trả lời được "vì sao domain này đổi
	// trạng thái lúc T".
	var changed int64
	if err := tx.QueryRow(ctx, fmt.Sprintf(`
		WITH ins AS (
			INSERT INTO decision_changes
			       (domain_id, category_id, old_action, new_action,
			        old_score, new_score, reason_code, policy_run_id)
			SELECT n.domain_id, n.category_id, o.action, n.action::policy_action,
			       o.effective_score, n.effective_score, n.reason_code, $1::bigint
			  FROM %s n
			  LEFT JOIN domain_decisions o
			    ON o.domain_id = n.domain_id AND o.category_id = n.category_id
			 WHERE o.action IS DISTINCT FROM n.action::policy_action
			RETURNING 1
		)
		SELECT count(*) FROM ins`, staging), runID).Scan(&changed); err != nil {
		return 0, fmt.Errorf("store: ghi decision_changes: %w", err)
	}

	if _, err := tx.Exec(ctx, fmt.Sprintf(`
		INSERT INTO domain_decisions
		       (domain_id, category_id, action, effective_score,
		        independent_source_count, reason_code, matched_rules, policy_run_id, decided_at)
		SELECT n.domain_id, n.category_id, n.action::policy_action, n.effective_score,
		       n.independent_source_count, n.reason_code, n.matched_rules, $1::bigint, NOW()
		  FROM %s n
		ON CONFLICT (domain_id, category_id) DO UPDATE
		   SET action                   = EXCLUDED.action,
		       effective_score          = EXCLUDED.effective_score,
		       independent_source_count = EXCLUDED.independent_source_count,
		       reason_code              = EXCLUDED.reason_code,
		       matched_rules            = EXCLUDED.matched_rules,
		       policy_run_id            = EXCLUDED.policy_run_id,
		       decided_at               = EXCLUDED.decided_at`, staging), runID); err != nil {
		return 0, fmt.Errorf("store: ghi domain_decisions: %w", err)
	}

	// Quyết định của những domain không còn bằng chứng nào phải biến mất, nếu không
	// generator sẽ tiếp tục xuất chúng mãi mãi.
	if _, err := tx.Exec(ctx, fmt.Sprintf(`
		DELETE FROM domain_decisions dd
		 WHERE NOT EXISTS (
		         SELECT 1 FROM %s n
		          WHERE n.domain_id = dd.domain_id AND n.category_id = dd.category_id
		       )`, staging)); err != nil {
		return 0, fmt.Errorf("store: dọn quyết định mồ côi: %w", err)
	}

	if _, err := tx.Exec(ctx, "DROP TABLE IF EXISTS "+staging); err != nil {
		return 0, fmt.Errorf("store: xóa staging quyết định: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("store: commit quyết định: %w", err)
	}
	return changed, nil
}

// CurrentPolicyRun trả về id lượt chạy hoàn tất gần nhất, dùng cho generator.
func (s *Store) CurrentPolicyRun(ctx context.Context) (int64, error) {
	var id int64
	err := s.pool.QueryRow(ctx, `
		SELECT id FROM policy_runs
		 WHERE status = 'completed' AND NOT is_shadow
		 ORDER BY completed_at DESC
		 LIMIT 1`).Scan(&id)
	if err == pgx.ErrNoRows {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("store: đọc policy run hiện hành: %w", err)
	}
	return id, nil
}

// BlockedRules trả về các rule BLOCK của một category, đã sắp xếp tất định.
//
// Sắp theo (normalized_domain, match_type) để cùng dữ liệu luôn cho cùng thứ tự, và do
// đó cùng checksum — điều kiện để "chỉ dựng lại khi dữ liệu thực sự đổi" hoạt động.
func (s *Store) BlockedRules(ctx context.Context, category string) ([]domainname.Rule, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT d.normalized_domain, d.match_type
		  FROM domain_decisions dd
		  JOIN domains d    ON d.id = dd.domain_id
		  JOIN categories c ON c.id = dd.category_id
		 WHERE dd.action = 'BLOCK' AND d.active AND c.name = $1
		 ORDER BY d.normalized_domain, d.match_type`, category)
	if err != nil {
		return nil, fmt.Errorf("store: đọc rule bị chặn: %w", err)
	}
	defer rows.Close()

	var out []domainname.Rule
	for rows.Next() {
		var domain string
		var mt int16
		if err := rows.Scan(&domain, &mt); err != nil {
			return nil, fmt.Errorf("store: quét rule: %w", err)
		}
		out = append(out, domainname.Rule{Domain: domain, MatchType: domainname.MatchType(mt)})
	}
	return out, rows.Err()
}

// Categories trả về tên mọi category, đã sắp xếp.
// CategoryIDsByName trả về ánh xạ tên category sang id.
//
// sync-consumer cần nó để dịch nhãn OpenCTI sang category: cấu hình viết bằng tên cho
// người đọc, còn CSDL khóa theo id.
func (s *Store) CategoryIDsByName(ctx context.Context) (map[string]int16, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, name FROM categories`)
	if err != nil {
		return nil, fmt.Errorf("store: đọc category: %w", err)
	}
	defer rows.Close()

	out := make(map[string]int16)
	for rows.Next() {
		var id int16
		var name string
		if err := rows.Scan(&id, &name); err != nil {
			return nil, fmt.Errorf("store: quét category: %w", err)
		}
		out[name] = id
	}
	return out, rows.Err()
}

func (s *Store) Categories(ctx context.Context) ([]string, error) {
	rows, err := s.pool.Query(ctx, "SELECT name FROM categories ORDER BY name")
	if err != nil {
		return nil, fmt.Errorf("store: đọc category: %w", err)
	}
	defer rows.Close()

	var out []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// Attribution ghi nhận nguồn và điều khoản license của nó.
type Attribution struct {
	Source  string
	License string
	URL     string
}

// Label là dạng một dòng để đặt vào header của file xuất ra.
func (a Attribution) Label() string {
	if a.License == "" {
		return a.Source
	}
	return a.Source + " (" + a.License + ")"
}

// Attributions trả về ghi nhận nguồn của mọi nguồn đang bật.
//
// Bắt buộc phải có trong manifest và trong header file: hệ tái phát hành list dẫn xuất
// từ nhiều nguồn có điều khoản license riêng.
func (s *Store) Attributions(ctx context.Context) ([]Attribution, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT name, COALESCE(license, ''), COALESCE(url, '')
		  FROM sources
		 WHERE enabled
		 ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("store: đọc ghi nhận nguồn: %w", err)
	}
	defer rows.Close()

	var out []Attribution
	for rows.Next() {
		var a Attribution
		if err := rows.Scan(&a.Source, &a.License, &a.URL); err != nil {
			return nil, fmt.Errorf("store: quét ghi nhận nguồn: %w", err)
		}
		out = append(out, a)
	}
	return out, rows.Err()
}
