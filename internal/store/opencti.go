package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/vnnic/cyberdns-tip/internal/domainname"
)

// Đường ghi tăng dần cho OpenCTI Live Stream.
//
// Cố tình KHÔNG dùng lại Apply: Apply hợp nhất trọn một feed và ở bước cuối vô hiệu hóa
// mọi domain không có mặt trong lần nạp đó. Với stream, mỗi sự kiện chỉ nói về MỘT
// indicator, nên chạy qua Apply sẽ vô hiệu hóa toàn bộ phần còn lại của nguồn OpenCTI ở
// mỗi sự kiện. Hai đường ghi khác nhau về bản chất, và gộp chúng lại là cách chắc chắn
// nhất để xóa sạch dữ liệu OpenCTI ngay sự kiện đầu tiên.
//
// Điểm chung được giữ nguyên: cùng hàm chuẩn hóa domainname, cùng phép hợp nhất giao
// hoán trên bảng domains, cùng quy tắc L0 chỉ ghi thêm.

// OpenCTIRecord là một indicator đã chuẩn hóa, sẵn sàng ghi xuống L1.
//
// Tách khỏi opencti.Record để package store không phụ thuộc ngược vào package opencti:
// store nằm dưới trong đồ thị phụ thuộc, và mọi thứ trong nó phải test được mà không cần
// biết STIX là gì.
type OpenCTIRecord struct {
	// STIXID là định danh dùng để tra ngược khi có sự kiện delete hoặc merge.
	STIXID string
	Rules  []domainname.Rule

	// CategoryIDs rỗng nghĩa là dùng category cấu hình sẵn của nguồn.
	CategoryIDs []int16
	Confidence  int

	Revoked    bool
	ValidUntil *time.Time

	// Modified là đồng hồ của OpenCTI, dùng để bỏ qua sự kiện cũ đến muộn.
	Modified time.Time

	// RawLine là biểu diễn thô lưu xuống L0 để truy vết về sau.
	RawLine string
}

// ErrStale báo sự kiện cũ hơn trạng thái đang lưu nên bị bỏ qua.
//
// Không phải lỗi: SSE phát lại sự kiện sau mỗi lần kết nối lại, và đây là đường đi bình
// thường. Bên gọi vẫn phải ghi checkpoint khi gặp nó.
var ErrStale = errors.New("store: sự kiện cũ hơn trạng thái đang lưu")

// UpsertOpenCTI ghi một indicator xuống L0 và L1 trong một transaction.
func (s *Store) UpsertOpenCTI(ctx context.Context, src Source, rec OpenCTIRecord, now time.Time) error {
	if rec.STIXID == "" {
		return fmt.Errorf("store: bản ghi OpenCTI thiếu STIX ID")
	}
	if len(rec.Rules) == 0 {
		return fmt.Errorf("store: bản ghi OpenCTI %s không có rule nào", rec.STIXID)
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("store: mở transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()

	// Chống sự kiện đến sai thứ tự (xung đột B6).
	//
	// So sánh với dấu thời gian của OpenCTI, không phải với thời điểm ta ghi. Sau khi
	// kết nối lại, stream phát lại các sự kiện đã xử lý; nếu áp dụng chúng lần nữa thì
	// một indicator vừa được thu hồi sẽ sống dậy vì bản sao cũ ghi đè lên bản mới.
	if !rec.Modified.IsZero() {
		stale, err := isStale(ctx, tx, src.ID, rec.STIXID, rec.Modified)
		if err != nil {
			return err
		}
		if stale {
			return ErrStale
		}
	}

	categories := rec.CategoryIDs
	if len(categories) == 0 {
		categories = src.CategoryIDs
	}

	confidence := int16(rec.Confidence)
	if confidence <= 0 {
		confidence = defaultConfidence(src)
	}

	// revoked_at đặt về THỜI ĐIỂM HIỆN TẠI chứ không phải Modified: nó là mốc "phủ định
	// có hiệu lực từ lúc nào", và policy so nó với now. Dùng Modified sẽ vô hại trong
	// hầu hết trường hợp nhưng sai khi OpenCTI và máy này lệch đồng hồ.
	var revokedAt *time.Time
	if rec.Revoked {
		revokedAt = &now
	}

	// Thời gian rỗng phải thành NULL, không phải năm 1.
	//
	// Zero value của time.Time trong Go là 0001-01-01, và Postgres nhận giá trị đó
	// không chút phàn nàn. Ghi nó vào source_modified_at sẽ biến mọi sự kiện sau đó
	// thành "mới hơn" và phép chống phát lại mất tác dụng mà không có triệu chứng nào.
	modified := nullTime(rec.Modified)

	for _, rule := range rec.Rules {
		domainID, err := upsertDomain(ctx, tx, rule, now)
		if err != nil {
			return err
		}

		// Hàng riêng của nguồn OpenCTI. active giữ nguyên TRUE kể cả khi revoked.
		//
		// Đây là điểm dễ sai nhất của cả file: truy vấn bằng chứng của policy lọc
		// "ds.active", nên một hàng bị tắt sẽ KHÔNG bao giờ tới được policy. Tắt hàng
		// lúc thu hồi đồng nghĩa với việc quyền phủ quyết của analyst biến mất im lặng
		// và domain vẫn bị chặn bởi các feed khác — đúng thứ mà nấc 5 của thang ưu tiên
		// sinh ra để ngăn.
		if _, err := tx.Exec(ctx, `
			INSERT INTO domain_sources
			       (domain_id, source_id, source_record_id, confidence,
			        first_seen, last_seen, valid_until, revoked_at, source_modified_at, active)
			VALUES ($1::bigint, $2::bigint, $3::text, $4::smallint,
			        $5::timestamptz, $5::timestamptz, $6::timestamptz, $7::timestamptz,
			        $8::timestamptz, TRUE)
			ON CONFLICT (domain_id, source_id) DO UPDATE
			   SET source_record_id   = EXCLUDED.source_record_id,
			       confidence         = EXCLUDED.confidence,
			       last_seen          = GREATEST(domain_sources.last_seen, EXCLUDED.last_seen),
			       first_seen         = LEAST(domain_sources.first_seen, EXCLUDED.first_seen),
			       valid_until        = EXCLUDED.valid_until,
			       revoked_at         = EXCLUDED.revoked_at,
			       source_modified_at = EXCLUDED.source_modified_at,
			       active             = TRUE`,
			domainID, src.ID, rec.STIXID, confidence,
			now, rec.ValidUntil, revokedAt, modified,
		); err != nil {
			return fmt.Errorf("store: ghi domain_sources cho %s: %w", rule.Domain, err)
		}

		// Category do OpenCTI khẳng định.
		//
		// Xóa rồi ghi lại thay vì chỉ chèn thêm: analyst có thể đổi nhãn của một
		// indicator từ malware sang phishing, và nếu chỉ chèn thêm thì nhãn cũ nằm lại
		// mãi mãi và domain xuất hiện trong cả hai file.
		if _, err := tx.Exec(ctx, `
			DELETE FROM domain_source_categories
			 WHERE domain_id = $1::bigint AND source_id = $2::bigint
			   AND NOT (category_id = ANY ($3::smallint[]))`,
			domainID, src.ID, categories,
		); err != nil {
			return fmt.Errorf("store: dọn category cũ cho %s: %w", rule.Domain, err)
		}

		if len(categories) > 0 {
			if _, err := tx.Exec(ctx, `
				INSERT INTO domain_source_categories (domain_id, source_id, category_id, confidence)
				SELECT $1::bigint, $2::bigint, c, $3::smallint
				  FROM unnest($4::smallint[]) AS c
				ON CONFLICT (domain_id, source_id, category_id) DO UPDATE
				   SET confidence = EXCLUDED.confidence`,
				domainID, src.ID, confidence, categories,
			); err != nil {
				return fmt.Errorf("store: ghi category cho %s: %w", rule.Domain, err)
			}
		}

		rawLine := rec.RawLine
		if rawLine == "" {
			rawLine = rule.Domain
		}
		if err := appendEvidence(ctx, tx, domainID, src.ID, rawLine, now); err != nil {
			return err
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("store: commit: %w", err)
	}
	return nil
}

// DeleteOpenCTI xử lý sự kiện xóa: OpenCTI không còn khẳng định gì về indicator này.
//
// Vô hiệu hóa hàng nguồn, và QUAN TRỌNG là xóa cả revoked_at. Xóa một indicator đã thu
// hồi nghĩa là bản ghi phủ định không còn tồn tại, nên quyền phủ quyết cũng mất theo —
// domain quay lại phụ thuộc vào các feed khác. Giữ lại revoked_at của một hàng đã bị xóa
// sẽ tạo ra một allowlist ẩn mà không giao diện nào hiển thị được.
func (s *Store) DeleteOpenCTI(ctx context.Context, sourceID int64, stixID string) (int64, error) {
	tag, err := s.pool.Exec(ctx, `
		UPDATE domain_sources
		   SET active = FALSE, revoked_at = NULL
		 WHERE source_id = $1::bigint AND source_record_id = $2::text`,
		sourceID, stixID)
	if err != nil {
		return 0, fmt.Errorf("store: xóa bản ghi OpenCTI %s: %w", stixID, err)
	}
	return tag.RowsAffected(), nil
}

// MergeOpenCTI ánh xạ các định danh đã bị gộp sang định danh còn lại (xung đột B5).
//
// Không làm bước này thì hàng của entity bị gộp trở thành mồ côi: OpenCTI không bao giờ
// phát sự kiện nào mang định danh đó nữa, nên không có delete hay update nào chạm tới
// được. Domain bị chặn vĩnh viễn và không ai truy ra vì sao.
//
// Hàng nào đã có sẵn định danh đích thì XÓA hàng cũ thay vì đổi tên, vì đổi tên sẽ vi
// phạm ràng buộc duy nhất khi cả hai entity cùng trỏ tới một domain — trường hợp phổ
// biến nhất của merge, không phải ngoại lệ hiếm.
func (s *Store) MergeOpenCTI(ctx context.Context, sourceID int64, from []string, to string) (int64, error) {
	if to == "" || len(from) == 0 {
		return 0, nil
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("store: mở transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()

	// Bỏ những hàng mà domain tương ứng đã mang định danh đích.
	if _, err := tx.Exec(ctx, `
		DELETE FROM domain_sources old
		 WHERE old.source_id = $1::bigint
		   AND old.source_record_id = ANY ($2::text[])
		   AND EXISTS (
		         SELECT 1 FROM domain_sources keep
		          WHERE keep.source_id = old.source_id
		            AND keep.domain_id = old.domain_id
		            AND keep.source_record_id = $3::text
		       )`, sourceID, from, to); err != nil {
		return 0, fmt.Errorf("store: dọn hàng trùng khi gộp: %w", err)
	}

	tag, err := tx.Exec(ctx, `
		UPDATE domain_sources
		   SET source_record_id = $3::text
		 WHERE source_id = $1::bigint
		   AND source_record_id = ANY ($2::text[])`,
		sourceID, from, to)
	if err != nil {
		return 0, fmt.Errorf("store: ánh xạ lại định danh khi gộp: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("store: commit: %w", err)
	}
	return tag.RowsAffected(), nil
}

// StreamState là checkpoint của một live stream.
type StreamState struct {
	Found       bool
	LastEventID string
	LastEventAt *time.Time
	EventsSeen  int64
}

// StreamState đọc checkpoint để nối lại đúng chỗ đã dừng.
func (s *Store) StreamState(ctx context.Context, sourceID int64, streamID string) (StreamState, error) {
	var st StreamState
	err := s.pool.QueryRow(ctx, `
		SELECT COALESCE(last_event_id, ''), last_event_at, events_seen
		  FROM opencti_stream_state
		 WHERE source_id = $1::bigint AND stream_id = $2::text`,
		sourceID, streamID).Scan(&st.LastEventID, &st.LastEventAt, &st.EventsSeen)
	if errors.Is(err, pgx.ErrNoRows) {
		return st, nil
	}
	if err != nil {
		return st, fmt.Errorf("store: đọc checkpoint stream: %w", err)
	}
	st.Found = true
	return st, nil
}

// SaveStreamState ghi checkpoint.
//
// Ghi SAU khi sự kiện đã xử lý xong, không bao giờ trước. Ghi trước rồi chết giữa chừng
// sẽ bỏ qua vĩnh viễn sự kiện đó; ghi sau thì tệ nhất là xử lý lại, mà đường ghi đã
// idempotent nên xử lý lại vô hại.
func (s *Store) SaveStreamState(
	ctx context.Context, sourceID int64, streamID, eventID string, eventAt time.Time, processed int64,
) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO opencti_stream_state
		       (source_id, stream_id, last_event_id, last_event_at, events_seen, updated_at)
		VALUES ($1::bigint, $2::text, NULLIF($3::text, ''), $4::timestamptz, $5::bigint, NOW())
		ON CONFLICT (source_id, stream_id) DO UPDATE
		   SET last_event_id = COALESCE(EXCLUDED.last_event_id, opencti_stream_state.last_event_id),
		       last_event_at = COALESCE(EXCLUDED.last_event_at, opencti_stream_state.last_event_at),
		       events_seen   = opencti_stream_state.events_seen + EXCLUDED.events_seen,
		       updated_at    = NOW()`,
		sourceID, streamID, eventID, nullTime(eventAt), processed)
	if err != nil {
		return fmt.Errorf("store: ghi checkpoint stream: %w", err)
	}
	return nil
}

// nullTime quy zero value của time.Time về NULL.
func nullTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

// isStale báo bản ghi đang lưu có mới hơn hoặc bằng sự kiện đang xét hay không.
func isStale(ctx context.Context, tx pgx.Tx, sourceID int64, stixID string, modified time.Time) (bool, error) {
	var stored *time.Time
	err := tx.QueryRow(ctx, `
		SELECT max(source_modified_at)
		  FROM domain_sources
		 WHERE source_id = $1::bigint AND source_record_id = $2::text`,
		sourceID, stixID).Scan(&stored)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("store: đọc mốc thời gian đang lưu: %w", err)
	}
	if stored == nil {
		return false, nil
	}
	// Bằng nhau cũng là cũ: cùng một sự kiện được phát lại.
	return !modified.After(*stored), nil
}

// upsertDomain hợp nhất một rule vào bảng domains bằng thao tác giao hoán.
//
// GREATEST/LEAST chứ không phải phép gán: bảng này dùng chung với feed-ingestor, và ghi
// đè thẳng sẽ khiến kết quả phụ thuộc vào việc bên nào chạy sau (xung đột B4).
func upsertDomain(ctx context.Context, tx pgx.Tx, rule domainname.Rule, now time.Time) (int64, error) {
	var id int64
	err := tx.QueryRow(ctx, `
		INSERT INTO domains (normalized_domain, match_type, first_seen, last_seen, active)
		VALUES ($1::text, $2::smallint, $3::timestamptz, $3::timestamptz, TRUE)
		ON CONFLICT (normalized_domain, match_type) DO UPDATE
		   SET last_seen  = GREATEST(domains.last_seen, EXCLUDED.last_seen),
		       first_seen = LEAST(domains.first_seen, EXCLUDED.first_seen),
		       active     = TRUE,
		       updated_at = NOW()
		RETURNING id`,
		rule.Domain, int16(rule.MatchType), now).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("store: hợp nhất domain %s: %w", rule.Domain, err)
	}
	return id, nil
}

// appendEvidence ghi L0, chỉ khi dòng thô này chưa từng thấy.
//
// Cùng lý do như đường feed: stream phát lại sau mỗi lần kết nối, và ghi lại một dòng y
// hệt không mang thêm thông tin nào ngoài việc làm bảng phình vô hạn.
func appendEvidence(ctx context.Context, tx pgx.Tx, domainID, sourceID int64, rawLine string, now time.Time) error {
	sum := sha256.Sum256([]byte(rawLine))
	rawHash := hex.EncodeToString(sum[:])

	if _, err := tx.Exec(ctx, `
		INSERT INTO domain_evidence (domain_id, source_id, raw_line, raw_hash, seen_at)
		SELECT $1::bigint, $2::bigint, $3::text, $4::text, $5::timestamptz
		 WHERE NOT EXISTS (
		         SELECT 1 FROM domain_evidence e
		          WHERE e.domain_id = $1::bigint
		            AND e.source_id = $2::bigint
		            AND e.raw_hash  = $4::text
		       )`,
		domainID, sourceID, rawLine, rawHash, now); err != nil {
		return fmt.Errorf("store: ghi bằng chứng: %w", err)
	}
	return nil
}
