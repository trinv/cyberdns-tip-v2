package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/vnnic/cyberdns-tip/internal/domainname"
	"github.com/vnnic/cyberdns-tip/internal/policy"
	"github.com/vnnic/cyberdns-tip/internal/store"
)

// addOpenCTISource tạo một nguồn origin='opencti'.
//
// Không dùng lại addSource được: cột origin quyết định nguồn có được tính là xác nhận
// độc lập hay không, và đó chính là thứ mấy bài test dưới đây kiểm chứng.
func addOpenCTISource(t *testing.T, pool *pgxpool.Pool, name, cats string) store.Source {
	t.Helper()
	ctx := context.Background()

	var id int64
	if err := pool.QueryRow(ctx, `
		INSERT INTO sources (name, source_type, origin, trust_score, config)
		VALUES ($1, 'stream', 'opencti', 90, $2::jsonb)
		RETURNING id`, name, `{"categories": `+cats+`}`).Scan(&id); err != nil {
		t.Fatalf("tạo nguồn opencti %s: %v", name, err)
	}

	srcs, err := store.New(pool).EnabledSources(ctx, "opencti")
	if err != nil {
		t.Fatalf("EnabledSources: %v", err)
	}
	for _, s := range srcs {
		if s.ID == id {
			return s
		}
	}
	t.Fatalf("không tìm thấy nguồn opencti vừa tạo %s", name)
	return store.Source{}
}

func octiRec(stixID, domain string, modified time.Time) store.OpenCTIRecord {
	return store.OpenCTIRecord{
		STIXID:   stixID,
		Rules:    []domainname.Rule{{Domain: domain, MatchType: domainname.Exact}},
		Modified: modified,
		RawLine:  "[domain-name:value = '" + domain + "']",
	}
}

// sourceRow đọc trạng thái hàng domain_sources của một domain.
func sourceRow(t *testing.T, pool *pgxpool.Pool, sourceID int64, domain string) (active bool, revoked *time.Time, recordID string) {
	t.Helper()
	err := pool.QueryRow(context.Background(), `
		SELECT ds.active, ds.revoked_at, COALESCE(ds.source_record_id, '')
		  FROM domain_sources ds
		  JOIN domains d ON d.id = ds.domain_id
		 WHERE ds.source_id = $1::bigint AND d.normalized_domain = $2`,
		sourceID, domain).Scan(&active, &revoked, &recordID)
	if err != nil {
		t.Fatalf("đọc domain_sources (%d, %s): %v", sourceID, domain, err)
	}
	return active, revoked, recordID
}

func TestUpsertOpenCTIWritesAllLayers(t *testing.T) {
	s, pool := newStore(t)
	ctx := context.Background()

	src := addOpenCTISource(t, pool, "t-octi-basic", `["malware"]`)

	if err := s.UpsertOpenCTI(ctx, src, octiRec("indicator--1", "evil.example.com", baseTime), baseTime); err != nil {
		t.Fatalf("UpsertOpenCTI: %v", err)
	}

	active, revoked, recordID := sourceRow(t, pool, src.ID, "evil.example.com")
	if !active {
		t.Error("hàng nguồn phải active")
	}
	if revoked != nil {
		t.Errorf("revoked_at = %v, muốn nil", revoked)
	}
	if recordID != "indicator--1" {
		t.Errorf("source_record_id = %q", recordID)
	}

	var cats int
	if err := pool.QueryRow(ctx, `
		SELECT count(*) FROM domain_source_categories WHERE source_id = $1`, src.ID).Scan(&cats); err != nil {
		t.Fatalf("đếm category: %v", err)
	}
	if cats != 1 {
		t.Errorf("số category = %d, muốn 1", cats)
	}

	var evidence int
	if err := pool.QueryRow(ctx, `
		SELECT count(*) FROM domain_evidence WHERE source_id = $1`, src.ID).Scan(&evidence); err != nil {
		t.Fatalf("đếm bằng chứng: %v", err)
	}
	if evidence != 1 {
		t.Errorf("số bằng chứng = %d, muốn 1", evidence)
	}
}

// Stream phát lại sự kiện sau mỗi lần kết nối lại. Xử lý lại phải không sinh thêm hàng
// nào — nếu không, một consumer khởi động lại vài lần mỗi ngày sẽ làm phình L0 vô hạn.
func TestUpsertOpenCTIIsIdempotent(t *testing.T) {
	s, pool := newStore(t)
	ctx := context.Background()

	src := addOpenCTISource(t, pool, "t-octi-idem", `["malware"]`)
	r := octiRec("indicator--2", "repeat.example.com", baseTime)

	if err := s.UpsertOpenCTI(ctx, src, r, baseTime); err != nil {
		t.Fatalf("lần 1: %v", err)
	}
	// Lần hai cùng dấu thời gian: coi là phát lại, phải bị bỏ qua.
	if err := s.UpsertOpenCTI(ctx, src, r, baseTime.Add(time.Minute)); !errors.Is(err, store.ErrStale) {
		t.Fatalf("lần 2 = %v, muốn ErrStale", err)
	}

	var evidence, domains int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM domain_evidence`).Scan(&evidence); err != nil {
		t.Fatalf("đếm bằng chứng: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM domains`).Scan(&domains); err != nil {
		t.Fatalf("đếm domain: %v", err)
	}
	if evidence != 1 || domains != 1 {
		t.Errorf("bằng chứng = %d, domain = %d; muốn 1 và 1", evidence, domains)
	}
}

// Sự kiện cũ đến muộn không được làm trạng thái lùi lại.
//
// Đây là xung đột B6: sau khi kết nối lại, stream có thể phát một bản cũ của indicator
// SAU bản mới. Nếu áp dụng theo thứ tự đến, một indicator vừa bị thu hồi sẽ sống dậy.
func TestUpsertOpenCTIRejectsOutOfOrder(t *testing.T) {
	s, pool := newStore(t)
	ctx := context.Background()

	src := addOpenCTISource(t, pool, "t-octi-order", `["malware"]`)

	// Bản mới: đã thu hồi.
	newer := octiRec("indicator--3", "flip.example.com", baseTime.Add(time.Hour))
	newer.Revoked = true
	if err := s.UpsertOpenCTI(ctx, src, newer, baseTime.Add(time.Hour)); err != nil {
		t.Fatalf("ghi bản mới: %v", err)
	}

	// Bản cũ đến sau: chưa thu hồi.
	older := octiRec("indicator--3", "flip.example.com", baseTime)
	if err := s.UpsertOpenCTI(ctx, src, older, baseTime.Add(2*time.Hour)); !errors.Is(err, store.ErrStale) {
		t.Fatalf("bản cũ = %v, muốn ErrStale", err)
	}

	_, revoked, _ := sourceRow(t, pool, src.ID, "flip.example.com")
	if revoked == nil {
		t.Error("revoked_at bị xóa bởi một sự kiện cũ đến muộn")
	}
}

// Thu hồi phải GIỮ hàng active.
//
// Truy vấn bằng chứng của policy lọc "ds.active". Tắt hàng lúc thu hồi sẽ khiến quyền
// phủ quyết của analyst không bao giờ tới được policy, và domain vẫn bị chặn — đúng thứ
// mà nấc 5 của thang ưu tiên sinh ra để ngăn.
func TestRevokedRowStaysActive(t *testing.T) {
	s, pool := newStore(t)
	ctx := context.Background()

	src := addOpenCTISource(t, pool, "t-octi-revoke", `["malware"]`)
	r := octiRec("indicator--4", "revoked.example.com", baseTime)
	r.Revoked = true

	if err := s.UpsertOpenCTI(ctx, src, r, baseTime); err != nil {
		t.Fatalf("UpsertOpenCTI: %v", err)
	}

	active, revoked, _ := sourceRow(t, pool, src.ID, "revoked.example.com")
	if !active {
		t.Error("hàng bị thu hồi phải giữ active để policy còn thấy được nó")
	}
	if revoked == nil {
		t.Error("revoked_at rỗng")
	}
}

// Bài test đầu-cuối của nấc 5: analyst thu hồi một domain mà HAI feed còn liệt kê, và
// domain đó phải rời khỏi blocklist.
func TestOpenCTIRevokeUnblocksDomainAssertedByFeeds(t *testing.T) {
	s, pool := newStore(t)
	ctx := context.Background()

	feedA := addSource(t, pool, "t-feed-a", `["malware"]`, 604800)
	feedB := addSource(t, pool, "t-feed-b", `["malware"]`, 604800)
	octi := addOpenCTISource(t, pool, "t-octi-veto", `["malware"]`)

	target := rec("falsepositive.vn", domainname.Exact)
	apply(t, s, feedA, "v1", baseTime, target)
	apply(t, s, feedB, "v1", baseTime, target)

	runPolicy(t, s, policy.DefaultConfig(), baseTime)
	if action, _, _ := decisionOf(t, pool, "falsepositive.vn", "malware"); action != "BLOCK" {
		t.Fatalf("trước khi thu hồi: action = %s, muốn BLOCK", action)
	}

	r := octiRec("indicator--5", "falsepositive.vn", baseTime.Add(time.Hour))
	r.Revoked = true
	if err := s.UpsertOpenCTI(ctx, octi, r, baseTime.Add(time.Hour)); err != nil {
		t.Fatalf("UpsertOpenCTI: %v", err)
	}

	runPolicy(t, s, policy.DefaultConfig(), baseTime.Add(2*time.Hour))
	action, _, reason := decisionOf(t, pool, "falsepositive.vn", "malware")
	if action != "ALLOW" {
		t.Errorf("sau khi thu hồi: action = %s, muốn ALLOW", action)
	}
	if reason != string(policy.ReasonOpenCTIRevoked) {
		t.Errorf("reason_code = %q, muốn %q", reason, policy.ReasonOpenCTIRevoked)
	}
}

// valid_until hết hạn KHÁC với thu hồi: nó chỉ rút đóng góp của riêng OpenCTI, các feed
// khác vẫn đứng nguyên (xung đột B2). Nhầm hai thứ này sẽ gỡ chặn hàng loạt.
func TestExpiredValidUntilDoesNotUnblock(t *testing.T) {
	s, pool := newStore(t)
	ctx := context.Background()

	feed := addSource(t, pool, "t-feed-valid", `["malware"]`, 604800)
	octi := addOpenCTISource(t, pool, "t-octi-valid", `["malware"]`)

	target := rec("stillbad.example.com", domainname.Exact)
	apply(t, s, feed, "v1", baseTime, target)

	expired := baseTime.Add(-time.Hour)
	r := octiRec("indicator--6", "stillbad.example.com", baseTime)
	r.ValidUntil = &expired
	if err := s.UpsertOpenCTI(ctx, octi, r, baseTime); err != nil {
		t.Fatalf("UpsertOpenCTI: %v", err)
	}

	runPolicy(t, s, policy.DefaultConfig(), baseTime)
	if action, _, _ := decisionOf(t, pool, "stillbad.example.com", "malware"); action != "BLOCK" {
		t.Errorf("action = %s, muốn BLOCK: valid_until hết hạn không phải phủ định", action)
	}
}

// Xóa indicator gỡ luôn quyền phủ quyết: bản ghi phủ định không còn tồn tại thì domain
// quay lại phụ thuộc vào các feed. Giữ lại revoked_at sẽ tạo một allowlist ẩn.
func TestDeleteOpenCTIClearsVeto(t *testing.T) {
	s, pool := newStore(t)
	ctx := context.Background()

	feed := addSource(t, pool, "t-feed-del", `["malware"]`, 604800)
	octi := addOpenCTISource(t, pool, "t-octi-del", `["malware"]`)

	target := rec("comeback.example.com", domainname.Exact)
	apply(t, s, feed, "v1", baseTime, target)

	r := octiRec("indicator--7", "comeback.example.com", baseTime)
	r.Revoked = true
	if err := s.UpsertOpenCTI(ctx, octi, r, baseTime); err != nil {
		t.Fatalf("UpsertOpenCTI: %v", err)
	}
	runPolicy(t, s, policy.DefaultConfig(), baseTime)
	if action, _, _ := decisionOf(t, pool, "comeback.example.com", "malware"); action != "ALLOW" {
		t.Fatalf("sau thu hồi: action = %s, muốn ALLOW", action)
	}

	n, err := s.DeleteOpenCTI(ctx, octi.ID, "indicator--7")
	if err != nil {
		t.Fatalf("DeleteOpenCTI: %v", err)
	}
	if n != 1 {
		t.Errorf("số hàng bị xóa = %d, muốn 1", n)
	}

	active, revoked, _ := sourceRow(t, pool, octi.ID, "comeback.example.com")
	if active {
		t.Error("hàng đã xóa phải hết active")
	}
	if revoked != nil {
		t.Errorf("revoked_at = %v, muốn nil sau khi xóa", revoked)
	}

	runPolicy(t, s, policy.DefaultConfig(), baseTime.Add(time.Hour))
	if action, _, _ := decisionOf(t, pool, "comeback.example.com", "malware"); action != "BLOCK" {
		t.Errorf("sau khi xóa indicator: action = %s, muốn BLOCK trở lại", action)
	}
}

// Gộp entity: định danh cũ phải được ánh xạ sang định danh còn lại, nếu không hàng cũ
// thành mồ côi và không sự kiện nào chạm tới được nữa (xung đột B5).
func TestMergeOpenCTIRemapsIdentifiers(t *testing.T) {
	s, pool := newStore(t)
	ctx := context.Background()

	src := addOpenCTISource(t, pool, "t-octi-merge", `["malware"]`)

	if err := s.UpsertOpenCTI(ctx, src, octiRec("indicator--old", "a.example.com", baseTime), baseTime); err != nil {
		t.Fatalf("ghi bản cũ: %v", err)
	}
	if err := s.UpsertOpenCTI(ctx, src, octiRec("indicator--keep", "b.example.com", baseTime), baseTime); err != nil {
		t.Fatalf("ghi bản giữ lại: %v", err)
	}

	n, err := s.MergeOpenCTI(ctx, src.ID, []string{"indicator--old"}, "indicator--keep")
	if err != nil {
		t.Fatalf("MergeOpenCTI: %v", err)
	}
	if n != 1 {
		t.Errorf("số hàng ánh xạ lại = %d, muốn 1", n)
	}

	if _, _, recordID := sourceRow(t, pool, src.ID, "a.example.com"); recordID != "indicator--keep" {
		t.Errorf("source_record_id = %q, muốn indicator--keep", recordID)
	}

	// Sau khi gộp, một lệnh xóa theo định danh còn lại phải chạm tới CẢ HAI hàng. Đây
	// mới là điều kiện chứng minh không còn hàng mồ côi.
	deleted, err := s.DeleteOpenCTI(ctx, src.ID, "indicator--keep")
	if err != nil {
		t.Fatalf("DeleteOpenCTI: %v", err)
	}
	if deleted != 2 {
		t.Errorf("số hàng bị xóa = %d, muốn 2", deleted)
	}
}

// Trường hợp phổ biến nhất của merge: hai entity cùng trỏ về một domain. Đổi tên thẳng
// sẽ vi phạm khóa chính, nên hàng thừa phải bị xóa thay vì đổi tên.
func TestMergeOpenCTIHandlesSameDomain(t *testing.T) {
	s, pool := newStore(t)
	ctx := context.Background()

	src := addOpenCTISource(t, pool, "t-octi-merge-dup", `["malware"]`)

	if err := s.UpsertOpenCTI(ctx, src, octiRec("indicator--x", "dup.example.com", baseTime), baseTime); err != nil {
		t.Fatalf("ghi lần 1: %v", err)
	}
	// Cùng domain, định danh khác: mô phỏng hai entity trước khi gộp.
	if _, err := pool.Exec(ctx, `
		UPDATE domain_sources SET source_record_id = 'indicator--y' WHERE source_id = $1`, src.ID); err != nil {
		t.Fatalf("đổi định danh: %v", err)
	}
	if err := s.UpsertOpenCTI(ctx, src, octiRec("indicator--x", "dup.example.com", baseTime.Add(time.Hour)), baseTime); err != nil {
		t.Fatalf("ghi lần 2: %v", err)
	}

	if _, err := s.MergeOpenCTI(ctx, src.ID, []string{"indicator--y"}, "indicator--x"); err != nil {
		t.Fatalf("MergeOpenCTI: %v", err)
	}

	var rows int
	if err := pool.QueryRow(ctx, `
		SELECT count(*) FROM domain_sources WHERE source_id = $1`, src.ID).Scan(&rows); err != nil {
		t.Fatalf("đếm hàng: %v", err)
	}
	if rows != 1 {
		t.Errorf("số hàng = %d, muốn 1", rows)
	}
}

func TestStreamStateRoundTrip(t *testing.T) {
	s, pool := newStore(t)
	ctx := context.Background()

	src := addOpenCTISource(t, pool, "t-octi-state", `["malware"]`)

	st, err := s.StreamState(ctx, src.ID, "live-abc")
	if err != nil {
		t.Fatalf("StreamState lần đầu: %v", err)
	}
	if st.Found {
		t.Error("chưa ghi gì mà đã Found")
	}

	if err := s.SaveStreamState(ctx, src.ID, "live-abc", "1757000000000-0", baseTime, 5); err != nil {
		t.Fatalf("SaveStreamState: %v", err)
	}
	if err := s.SaveStreamState(ctx, src.ID, "live-abc", "1757000000000-9", baseTime.Add(time.Minute), 3); err != nil {
		t.Fatalf("SaveStreamState lần 2: %v", err)
	}

	st, err = s.StreamState(ctx, src.ID, "live-abc")
	if err != nil {
		t.Fatalf("StreamState: %v", err)
	}
	if !st.Found {
		t.Fatal("không đọc lại được checkpoint")
	}
	if st.LastEventID != "1757000000000-9" {
		t.Errorf("LastEventID = %q", st.LastEventID)
	}
	if st.EventsSeen != 8 {
		t.Errorf("EventsSeen = %d, muốn 8 (cộng dồn)", st.EventsSeen)
	}
	if st.LastEventAt == nil {
		t.Error("LastEventAt rỗng")
	}
}

// Đổi nhãn của một indicator phải THAY category cũ, không cộng thêm. Chỉ chèn thêm sẽ
// khiến domain nằm trong cả file cũ lẫn file mới mãi mãi.
func TestUpsertOpenCTIReplacesCategories(t *testing.T) {
	s, pool := newStore(t)
	ctx := context.Background()

	src := addOpenCTISource(t, pool, "t-octi-cats", `["malware"]`)

	var phishingID int16
	if err := pool.QueryRow(ctx, `SELECT id FROM categories WHERE name = 'phishing'`).Scan(&phishingID); err != nil {
		t.Fatalf("đọc id category phishing: %v", err)
	}

	r := octiRec("indicator--8", "relabel.example.com", baseTime)
	if err := s.UpsertOpenCTI(ctx, src, r, baseTime); err != nil {
		t.Fatalf("ghi lần 1: %v", err)
	}

	r2 := octiRec("indicator--8", "relabel.example.com", baseTime.Add(time.Hour))
	r2.CategoryIDs = []int16{phishingID}
	if err := s.UpsertOpenCTI(ctx, src, r2, baseTime.Add(time.Hour)); err != nil {
		t.Fatalf("ghi lần 2: %v", err)
	}

	rows, err := pool.Query(ctx, `
		SELECT c.name FROM domain_source_categories dsc
		  JOIN categories c ON c.id = dsc.category_id
		 WHERE dsc.source_id = $1`, src.ID)
	if err != nil {
		t.Fatalf("đọc category: %v", err)
	}
	defer rows.Close()

	var names []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatalf("quét: %v", err)
		}
		names = append(names, n)
	}
	if len(names) != 1 || names[0] != "phishing" {
		t.Errorf("category = %v, muốn [phishing]", names)
	}
}
