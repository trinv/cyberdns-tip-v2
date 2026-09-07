package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/vnnic/cyberdns-tip/internal/domainname"
	"github.com/vnnic/cyberdns-tip/internal/store"
	"github.com/vnnic/cyberdns-tip/internal/testdb"
)

// Schema riêng cho package này; xem internal/testdb.
const schema = "test_store"

var baseTime = time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)

func newStore(t *testing.T) (*store.Store, *pgxpool.Pool) {
	t.Helper()
	pool := testdb.SetupMigrated(t, schema)
	return store.New(pool), pool
}

// addSource tạo một nguồn kèm ánh xạ category.
func addSource(t *testing.T, pool *pgxpool.Pool, name string, cats string, graceSec int) store.Source {
	t.Helper()
	ctx := context.Background()

	var id int64
	err := pool.QueryRow(ctx, `
		INSERT INTO sources (name, url, source_type, origin, trust_score,
		                     grace_period_seconds, config)
		VALUES ($1, 'https://example.test/list.txt', 'plain', 'direct', 90, $2, $3::jsonb)
		RETURNING id`, name, graceSec, `{"categories": `+cats+`}`).Scan(&id)
	if err != nil {
		t.Fatalf("tạo nguồn %s: %v", name, err)
	}

	srcs, err := store.New(pool).EnabledSources(ctx, "direct")
	if err != nil {
		t.Fatalf("EnabledSources: %v", err)
	}
	for _, s := range srcs {
		if s.ID == id {
			return s
		}
	}
	t.Fatalf("không tìm thấy nguồn vừa tạo %s", name)
	return store.Source{}
}

func rec(domain string, mt domainname.MatchType) store.Record {
	return store.Record{
		Rule:    domainname.Rule{Domain: domain, MatchType: mt},
		RawLine: domain,
		RawHash: "sha256:" + domain,
	}
}

func apply(t *testing.T, s *store.Store, src store.Source, hash string, at time.Time, recs ...store.Record) store.ApplyResult {
	t.Helper()
	ctx := context.Background()

	importID, err := s.BeginImport(ctx, src.ID)
	if err != nil {
		t.Fatalf("BeginImport: %v", err)
	}
	res, err := s.Apply(ctx, src, importID, hash, recs, at)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if err := s.FinishImport(ctx, importID, store.ImportResult{
		Status: "completed", FeedHash: hash, Accepted: len(recs),
		Added: res.Added, Updated: res.Updated, Removed: res.Removed,
	}); err != nil {
		t.Fatalf("FinishImport: %v", err)
	}
	return res
}

func count(t *testing.T, pool *pgxpool.Pool, sql string, args ...any) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(), sql, args...).Scan(&n); err != nil {
		t.Fatalf("đếm (%s): %v", sql, err)
	}
	return n
}

func TestApplyCreatesAllLayers(t *testing.T) {
	s, pool := newStore(t)
	src := addSource(t, pool, "t-hagezi", `["malware","phishing"]`, 604800)

	res := apply(t, s, src, "sha256:v1", baseTime,
		rec("evil.example.com", domainname.Exact),
		rec("bad.example.net", domainname.Wildcard),
	)

	if res.Added != 2 {
		t.Errorf("Added = %d, muốn 2", res.Added)
	}

	if n := count(t, pool, "SELECT count(*) FROM domains WHERE active"); n != 2 {
		t.Errorf("domains = %d, muốn 2", n)
	}
	if n := count(t, pool, "SELECT count(*) FROM domain_sources WHERE active"); n != 2 {
		t.Errorf("domain_sources = %d, muốn 2", n)
	}
	// 2 domain x 2 category.
	if n := count(t, pool, "SELECT count(*) FROM domain_source_categories"); n != 4 {
		t.Errorf("domain_source_categories = %d, muốn 4", n)
	}
	if n := count(t, pool, "SELECT count(*) FROM domain_evidence"); n != 2 {
		t.Errorf("domain_evidence = %d, muốn 2", n)
	}
}

// Nạp lại cùng một feed không được nhân bản gì ở L1. L0 thì có — mỗi lần nhìn thấy là
// một bằng chứng riêng, và đó chính là thứ cho phép trả lời "lúc đó nguồn nói gì".
func TestApplyIsIdempotentAtL1(t *testing.T) {
	s, pool := newStore(t)
	src := addSource(t, pool, "t-hagezi", `["malware"]`, 604800)

	recs := []store.Record{rec("evil.example.com", domainname.Exact)}

	apply(t, s, src, "sha256:v1", baseTime, recs...)
	second := apply(t, s, src, "sha256:v1", baseTime.Add(time.Hour), recs...)

	if second.Added != 0 {
		t.Errorf("lần hai Added = %d, muốn 0", second.Added)
	}
	if n := count(t, pool, "SELECT count(*) FROM domains"); n != 1 {
		t.Errorf("domains = %d, muốn 1", n)
	}
	if n := count(t, pool, "SELECT count(*) FROM domain_sources"); n != 1 {
		t.Errorf("domain_sources = %d, muốn 1", n)
	}
	if n := count(t, pool, "SELECT count(*) FROM domain_evidence"); n != 2 {
		t.Errorf("domain_evidence = %d, muốn 2 (L0 tích lũy)", n)
	}
}

// Xung đột B4. Hai bên cùng chạm hàng domains phải cho ra kết quả không phụ thuộc thứ
// tự chạy: last_seen lấy GREATEST, first_seen lấy LEAST.
func TestDomainMergeIsCommutative(t *testing.T) {
	s, pool := newStore(t)
	srcA := addSource(t, pool, "feed-a", `["malware"]`, 604800)
	srcB := addSource(t, pool, "feed-b", `["phishing"]`, 604800)

	early := baseTime.Add(-48 * time.Hour)
	late := baseTime

	// Nguồn B ghi trước với mốc thời gian MUỘN, rồi nguồn A ghi sau với mốc SỚM.
	// Nếu là ghi đè thì last_seen sẽ bị kéo lùi về mốc sớm.
	apply(t, s, srcB, "sha256:b", late, rec("evil.example.com", domainname.Exact))
	apply(t, s, srcA, "sha256:a", early, rec("evil.example.com", domainname.Exact))

	var firstSeen, lastSeen time.Time
	err := pool.QueryRow(context.Background(),
		"SELECT first_seen, last_seen FROM domains WHERE normalized_domain = 'evil.example.com'").
		Scan(&firstSeen, &lastSeen)
	if err != nil {
		t.Fatalf("đọc domain: %v", err)
	}

	if !lastSeen.Equal(late) {
		t.Errorf("last_seen = %v, muốn %v (GREATEST, không bị kéo lùi)", lastSeen, late)
	}
	if !firstSeen.Equal(early) {
		t.Errorf("first_seen = %v, muốn %v (LEAST)", firstSeen, early)
	}

	// Một domain, hai nguồn — đúng yêu cầu chống trùng lặp của claude_rm.md.
	if n := count(t, pool, "SELECT count(*) FROM domains"); n != 1 {
		t.Errorf("domains = %d, muốn 1 bản ghi canonical", n)
	}
	if n := count(t, pool, "SELECT count(*) FROM domain_sources"); n != 2 {
		t.Errorf("domain_sources = %d, muốn 2 quan hệ nguồn", n)
	}
	if n := count(t, pool, "SELECT count(*) FROM domain_evidence"); n != 2 {
		t.Errorf("domain_evidence = %d, muốn 2 bằng chứng", n)
	}
}

// Xung đột A4. Domain biến mất rồi quay lại trong grace period không được rời blocklist.
func TestGracePeriodProtectsAgainstFlapping(t *testing.T) {
	s, pool := newStore(t)
	src := addSource(t, pool, "flappy", `["ads"]`, 7*24*3600) // grace 7 ngày

	apply(t, s, src, "v1", baseTime,
		rec("stable.example.com", domainname.Exact),
		rec("flappy.example.com", domainname.Exact),
	)

	// Lần import sau flappy biến mất, nhưng mới có 1 ngày trôi qua.
	apply(t, s, src, "v2", baseTime.Add(24*time.Hour),
		rec("stable.example.com", domainname.Exact))

	if n := count(t, pool,
		"SELECT count(*) FROM domain_sources ds JOIN domains d ON d.id = ds.domain_id "+
			"WHERE d.normalized_domain = 'flappy.example.com' AND ds.active"); n != 1 {
		t.Errorf("flappy bị gỡ trong grace period (active rows = %d, muốn 1)", n)
	}

	// Sau 10 ngày thì mới hết hiệu lực.
	apply(t, s, src, "v3", baseTime.Add(10*24*time.Hour),
		rec("stable.example.com", domainname.Exact))

	if n := count(t, pool,
		"SELECT count(*) FROM domain_sources ds JOIN domains d ON d.id = ds.domain_id "+
			"WHERE d.normalized_domain = 'flappy.example.com' AND ds.active"); n != 0 {
		t.Errorf("flappy vẫn active sau khi hết grace period (active rows = %d, muốn 0)", n)
	}
	if n := count(t, pool,
		"SELECT count(*) FROM domains WHERE normalized_domain = 'flappy.example.com' AND active"); n != 0 {
		t.Errorf("domain không còn nguồn nào vẫn active")
	}
	// Không xóa cứng: bằng chứng và bản ghi vẫn còn để truy vết.
	if n := count(t, pool,
		"SELECT count(*) FROM domains WHERE normalized_domain = 'flappy.example.com'"); n != 1 {
		t.Errorf("domain bị xóa cứng, muốn giữ lại để truy vết")
	}
}

// Xung đột A5. Vòng đời theo TỪNG NGUỒN, không theo domain.
func TestRemovalFromOneSourceDoesNotAffectOthers(t *testing.T) {
	s, pool := newStore(t)
	srcA := addSource(t, pool, "feed-a", `["malware"]`, 0) // grace 0 để hết hiệu lực ngay
	srcB := addSource(t, pool, "feed-b", `["malware"]`, 0)

	shared := rec("evil.example.com", domainname.Exact)
	apply(t, s, srcA, "a1", baseTime, shared)
	apply(t, s, srcB, "b1", baseTime, shared)

	// Nguồn A gỡ domain; nguồn B vẫn liệt kê.
	apply(t, s, srcA, "a2", baseTime.Add(time.Hour), rec("other.example.com", domainname.Exact))

	if n := count(t, pool, `
		SELECT count(*) FROM domain_sources ds
		  JOIN domains d ON d.id = ds.domain_id
		 WHERE d.normalized_domain = 'evil.example.com' AND ds.source_id = $1 AND ds.active`,
		srcA.ID); n != 0 {
		t.Errorf("bản ghi của nguồn A vẫn active sau khi A gỡ domain")
	}
	if n := count(t, pool, `
		SELECT count(*) FROM domain_sources ds
		  JOIN domains d ON d.id = ds.domain_id
		 WHERE d.normalized_domain = 'evil.example.com' AND ds.source_id = $1 AND ds.active`,
		srcB.ID); n != 1 {
		t.Errorf("bản ghi của nguồn B bị ảnh hưởng oan")
	}

	// Domain vẫn còn hiệu lực vì B còn khẳng định.
	if n := count(t, pool,
		"SELECT count(*) FROM domains WHERE normalized_domain = 'evil.example.com' AND active"); n != 1 {
		t.Errorf("domain bị vô hiệu hóa dù nguồn B vẫn đang liệt kê")
	}
}

// claude_rm.md coi exact và wildcard là hai enforcement rule KHÁC NHAU.
func TestExactAndWildcardAreDistinctRows(t *testing.T) {
	s, pool := newStore(t)
	src := addSource(t, pool, "feed", `["malware"]`, 604800)

	apply(t, s, src, "v1", baseTime,
		rec("example.com", domainname.Exact),
		rec("example.com", domainname.Wildcard),
	)

	if n := count(t, pool,
		"SELECT count(*) FROM domains WHERE normalized_domain = 'example.com'"); n != 2 {
		t.Errorf("domains cho example.com = %d, muốn 2 (exact + wildcard)", n)
	}
}

func TestLastSuccessfulImport(t *testing.T) {
	s, pool := newStore(t)
	src := addSource(t, pool, "feed", `["malware"]`, 604800)
	ctx := context.Background()

	li, err := s.LastSuccessfulImport(ctx, src.ID)
	if err != nil {
		t.Fatalf("LastSuccessfulImport: %v", err)
	}
	if li.Found {
		t.Error("báo có lần import trước khi chưa có lần nào")
	}

	apply(t, s, src, "sha256:abc", baseTime,
		rec("a.example.com", domainname.Exact),
		rec("b.example.com", domainname.Exact),
	)

	li, err = s.LastSuccessfulImport(ctx, src.ID)
	if err != nil {
		t.Fatalf("LastSuccessfulImport: %v", err)
	}
	if !li.Found || li.FeedHash != "sha256:abc" || li.Accepted != 2 {
		t.Errorf("LastSuccessfulImport = %+v, muốn hash sha256:abc và 2 bản ghi", li)
	}
}

// Import hỏng không được để lại một nửa dữ liệu mới lẫn với một nửa dữ liệu cũ.
func TestFailedApplyLeavesNothingBehind(t *testing.T) {
	s, pool := newStore(t)
	src := addSource(t, pool, "feed", `["malware"]`, 604800)
	ctx := context.Background()

	apply(t, s, src, "v1", baseTime, rec("good.example.com", domainname.Exact))
	before := count(t, pool, "SELECT count(*) FROM domains")

	// match_type = 9 vi phạm CHECK của bảng domains, nên transaction phải rollback.
	importID, err := s.BeginImport(ctx, src.ID)
	if err != nil {
		t.Fatalf("BeginImport: %v", err)
	}
	_, err = s.Apply(ctx, src, importID, "v2", []store.Record{
		rec("valid.example.com", domainname.Exact),
		{Rule: domainname.Rule{Domain: "broken.example.com", MatchType: 9}, RawLine: "x", RawHash: "y"},
	}, baseTime.Add(time.Hour))
	if err == nil {
		t.Fatal("Apply chấp nhận match_type không hợp lệ, muốn lỗi")
	}

	if after := count(t, pool, "SELECT count(*) FROM domains"); after != before {
		t.Errorf("số domain đổi từ %d thành %d sau khi Apply hỏng", before, after)
	}
	if n := count(t, pool,
		"SELECT count(*) FROM domains WHERE normalized_domain = 'valid.example.com'"); n != 0 {
		t.Error("bản ghi của lần import hỏng vẫn lọt vào CSDL")
	}
}
