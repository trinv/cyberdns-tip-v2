package builder_test

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/vnnic/cyberdns-tip/internal/blocklistsrv"
	"github.com/vnnic/cyberdns-tip/internal/builder"
	"github.com/vnnic/cyberdns-tip/internal/domainname"
	"github.com/vnnic/cyberdns-tip/internal/feed"
	"github.com/vnnic/cyberdns-tip/internal/metrics"
	"github.com/vnnic/cyberdns-tip/internal/policy"
	"github.com/vnnic/cyberdns-tip/internal/render"
	"github.com/vnnic/cyberdns-tip/internal/snapshot"
	"github.com/vnnic/cyberdns-tip/internal/store"
	"github.com/vnnic/cyberdns-tip/internal/testdb"
)

const schema = "test_builder"

var baseTime = time.Date(2026, 9, 7, 3, 0, 0, 0, time.UTC)

// rig là toàn bộ đường ống lắp sẵn, từ CSDL tới HTTP.
type rig struct {
	db    *store.Store
	pool  *pgxpool.Pool
	snaps *snapshot.Store
	build *builder.Builder
	http  http.Handler
}

func newRig(t *testing.T) *rig {
	t.Helper()

	pool := testdb.SetupMigrated(t, schema)
	db := store.New(pool)

	snaps, err := snapshot.NewStore(t.TempDir(), 3)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	m := metrics.New("test", "v0")
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	return &rig{
		db:    db,
		pool:  pool,
		snaps: snaps,
		build: &builder.Builder{
			DB: db, Store: snaps, Metrics: m, Log: log, Format: render.FormatDomain,
		},
		http: blocklistsrv.New(blocklistsrv.Options{
			Store: snaps, Metrics: m, Log: log,
		}).Handler(),
	}
}

// ingest chạy trọn đường ống thu thập: tải HTTP -> parse -> kiểm tra -> ghi L0/L1.
func (r *rig) ingest(t *testing.T, src store.Source, url string, at time.Time) feed.Stats {
	t.Helper()
	ctx := context.Background()

	fs := feed.Source{
		ID: fmt.Sprint(src.ID), Name: src.Name, URL: url,
		Timeout: 10 * time.Second, MaxAttempts: 1,
	}

	resp, err := feed.NewFetcher().Fetch(ctx, fs, feed.Conditional{})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}

	var records []store.Record
	stats, err := feed.Parse(resp.Body, func(rule domainname.Rule, raw string) error {
		records = append(records, store.Record{Rule: rule, RawLine: raw, RawHash: "sha256:" + raw})
		return nil
	})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	hash := resp.Hash()
	if err := resp.Body.Close(); err != nil {
		t.Fatalf("đóng body: %v", err)
	}

	prev, err := r.db.LastSuccessfulImport(ctx, src.ID)
	if err != nil {
		t.Fatalf("LastSuccessfulImport: %v", err)
	}
	if err := feed.Validate(fs, stats, prev.Accepted); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	importID, err := r.db.BeginImport(ctx, src.ID)
	if err != nil {
		t.Fatalf("BeginImport: %v", err)
	}
	res, err := r.db.Apply(ctx, src, importID, hash, records, at)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if err := r.db.FinishImport(ctx, importID, store.ImportResult{
		Status: "completed", FeedHash: hash, Total: stats.Lines,
		Accepted: stats.Accepted, Rejected: stats.Rejected,
		Added: res.Added, Updated: res.Updated, Removed: res.Removed,
	}); err != nil {
		t.Fatalf("FinishImport: %v", err)
	}
	return stats
}

func (r *rig) runPolicy(t *testing.T, at time.Time) store.RunStats {
	t.Helper()
	ctx := context.Background()

	runID, err := r.db.BeginPolicyRun(ctx, policy.DefaultConfig(), false)
	if err != nil {
		t.Fatalf("BeginPolicyRun: %v", err)
	}
	lists, err := r.db.LoadLists(ctx, at)
	if err != nil {
		t.Fatalf("LoadLists: %v", err)
	}
	stats, err := r.db.EvaluateAll(ctx, runID, policy.DefaultConfig(), lists, at)
	if err != nil {
		t.Fatalf("EvaluateAll: %v", err)
	}
	if err := r.db.FinishPolicyRun(ctx, runID, "completed", stats.Evaluated, stats.Blocked, ""); err != nil {
		t.Fatalf("FinishPolicyRun: %v", err)
	}
	return stats
}

func (r *rig) get(t *testing.T, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	r.http.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec
}

func addSource(t *testing.T, r *rig, name, cats, license string) store.Source {
	t.Helper()
	ctx := context.Background()

	var id int64
	err := r.pool.QueryRow(ctx, `
		INSERT INTO sources (name, url, source_type, origin, trust_score, license, config)
		VALUES ($1, 'https://example.test/l.txt', 'plain', 'direct', 90, $2, $3::jsonb)
		RETURNING id`, name, license, `{"categories": `+cats+`}`).Scan(&id)
	if err != nil {
		t.Fatalf("tạo nguồn: %v", err)
	}

	srcs, err := r.db.EnabledSources(ctx, "direct")
	if err != nil {
		t.Fatalf("EnabledSources: %v", err)
	}
	for _, s := range srcs {
		if s.ID == id {
			return s
		}
	}
	t.Fatal("không tìm thấy nguồn vừa tạo")
	return store.Source{}
}

func feedServer(t *testing.T, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// Đây là tiêu chí nghiệm thu P1 trong PLAN.md, chạy xuyên suốt từ feed HTTP tới URL
// blocklist: domain bị chặn thì có trong file, domain allowlist thì không.
func TestEndToEndFeedToPublishedURL(t *testing.T) {
	r := newRig(t)
	src := addSource(t, r, "hagezi-tif", `["malware"]`, "GPL-3.0")

	srv := feedServer(t, strings.Join([]string{
		"# HaGeZi Threat Intelligence Feed",
		"evil.example.com",
		"0.0.0.0 malware.example.net",
		"*.phish.example.org",
		"allowed.example.com",
		"192.168.1.1", // bị loại: là IP
	}, "\n"))

	stats := r.ingest(t, src, srv.URL, baseTime)
	if stats.Accepted != 4 {
		t.Fatalf("Accepted = %d, muốn 4", stats.Accepted)
	}
	if stats.Rejected != 1 {
		t.Errorf("Rejected = %d, muốn 1 (dòng IP)", stats.Rejected)
	}

	// Một domain được đưa vào allowlist trước khi chạy policy.
	if _, err := r.pool.Exec(context.Background(), `
		INSERT INTO global_allowlist (domain, match_type, tier, reason)
		VALUES ('allowed.example.com', 0, 'soft', 'khách hàng báo false positive')`); err != nil {
		t.Fatalf("thêm allowlist: %v", err)
	}

	if got := r.runPolicy(t, baseTime); got.Blocked != 3 {
		t.Errorf("Blocked = %d, muốn 3 (4 domain trừ 1 allowlist)", got.Blocked)
	}

	res, err := r.build.Build(context.Background(), baseTime)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if res.Skipped {
		t.Fatal("Build bỏ qua ở lần dựng đầu tiên")
	}

	// Phục vụ qua HTTP — đây là thứ Blocky sẽ tải về.
	rec := r.get(t, "/blocklist/malware.txt")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET malware.txt = %d, muốn 200", rec.Code)
	}
	body := rec.Body.String()

	for _, want := range []string{"evil.example.com", "malware.example.net", "phish.example.org"} {
		if !strings.Contains(body, want) {
			t.Errorf("thiếu %q trong file xuất ra:\n%s", want, body)
		}
	}
	if strings.Contains(body, "allowed.example.com") {
		t.Errorf("domain trong allowlist vẫn lọt vào file:\n%s", body)
	}
	// Ghi nhận license bắt buộc phải có: hệ tái phát hành list dẫn xuất.
	if !strings.Contains(body, "GPL-3.0") {
		t.Errorf("thiếu ghi nhận license trong header:\n%s", body)
	}

	// all.txt phải chứa mọi thứ.
	all := r.get(t, "/blocklist/all.txt")
	if all.Code != http.StatusOK {
		t.Fatalf("GET all.txt = %d", all.Code)
	}
	if !strings.Contains(all.Body.String(), "evil.example.com") {
		t.Error("all.txt thiếu domain bị chặn")
	}

	// Manifest phải khớp với file thật.
	mf := r.get(t, "/blocklist/manifest.json")
	if mf.Code != http.StatusOK {
		t.Fatalf("GET manifest.json = %d", mf.Code)
	}
	if !strings.Contains(mf.Body.String(), "malware.txt") {
		t.Error("manifest thiếu malware.txt")
	}
}

// "Chỉ regenerate khi dữ liệu thực sự thay đổi" — yêu cầu §6 của claude_rm.md.
func TestRebuildIsSkippedWhenNothingChanged(t *testing.T) {
	r := newRig(t)
	src := addSource(t, r, "feed", `["malware"]`, "")
	srv := feedServer(t, "evil.example.com\n")

	r.ingest(t, src, srv.URL, baseTime)
	r.runPolicy(t, baseTime)

	first, err := r.build.Build(context.Background(), baseTime)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if first.Skipped {
		t.Fatal("lần dựng đầu bị bỏ qua")
	}

	// Chạy lại policy rồi dựng lại: dữ liệu y nguyên nên không được publish bộ mới.
	r.runPolicy(t, baseTime.Add(time.Hour))
	second, err := r.build.Build(context.Background(), baseTime.Add(time.Hour))
	if err != nil {
		t.Fatalf("Build lần hai: %v", err)
	}
	if !second.Skipped {
		t.Errorf("Build lần hai phát hành bộ mới %q dù dữ liệu không đổi", second.Version)
	}

	current, err := r.snaps.Current()
	if err != nil {
		t.Fatalf("Current: %v", err)
	}
	if current != first.Version {
		t.Errorf("con trỏ current = %q, muốn giữ nguyên %q", current, first.Version)
	}

	// Thêm domain mới thì phải dựng lại.
	srv2 := feedServer(t, "evil.example.com\nnew.example.com\n")
	r.ingest(t, src, srv2.URL, baseTime.Add(2*time.Hour))
	r.runPolicy(t, baseTime.Add(2*time.Hour))

	third, err := r.build.Build(context.Background(), baseTime.Add(2*time.Hour))
	if err != nil {
		t.Fatalf("Build lần ba: %v", err)
	}
	if third.Skipped {
		t.Error("Build bỏ qua dù đã thêm một domain")
	}
	if third.Version == first.Version {
		t.Error("version không đổi dù nội dung đã đổi")
	}
}

// Rollback là thao tác đổi con trỏ và có hiệu lực ngay với request kế tiếp.
func TestRollbackServesPreviousVersion(t *testing.T) {
	r := newRig(t)
	src := addSource(t, r, "feed", `["malware"]`, "")

	r.ingest(t, src, feedServer(t, "old.example.com\n").URL, baseTime)
	r.runPolicy(t, baseTime)
	first, err := r.build.Build(context.Background(), baseTime)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	r.ingest(t, src, feedServer(t, "old.example.com\nnew.example.com\n").URL, baseTime.Add(time.Hour))
	r.runPolicy(t, baseTime.Add(time.Hour))
	if _, err := r.build.Build(context.Background(), baseTime.Add(time.Hour)); err != nil {
		t.Fatalf("Build lần hai: %v", err)
	}

	if !strings.Contains(r.get(t, "/blocklist/malware.txt").Body.String(), "new.example.com") {
		t.Fatal("bộ mới chưa có hiệu lực")
	}

	if err := r.snaps.Rollback(first.Version); err != nil {
		t.Fatalf("Rollback: %v", err)
	}

	body := r.get(t, "/blocklist/malware.txt").Body.String()
	if strings.Contains(body, "new.example.com") {
		t.Errorf("sau rollback vẫn phục vụ nội dung mới:\n%s", body)
	}
	if !strings.Contains(body, "old.example.com") {
		t.Errorf("sau rollback thiếu nội dung cũ:\n%s", body)
	}
}

// Đây là bài kiểm tra quan trọng nhất của toàn hệ, lấy từ SKILL.md: feed hỏng phải làm
// hỏng cả lần import và giữ nguyên snapshot cũ, không bao giờ được gỡ chặn hàng loạt.
func TestBrokenFeedDoesNotChangePublishedFiles(t *testing.T) {
	r := newRig(t)
	src := addSource(t, r, "feed", `["malware"]`, "")

	r.ingest(t, src, feedServer(t, "a.example.com\nb.example.com\nc.example.com\n").URL, baseTime)
	r.runPolicy(t, baseTime)
	if _, err := r.build.Build(context.Background(), baseTime); err != nil {
		t.Fatalf("Build: %v", err)
	}

	before := r.get(t, "/blocklist/malware.txt").Body.String()
	beforeETag := r.get(t, "/blocklist/malware.txt").Header().Get("ETag")

	// Feed trả về trang lỗi HTML kèm mã 200 — tình huống thật và nguy hiểm nhất, vì
	// nó trông như một feed vừa gỡ sạch mọi domain.
	bad := feedServer(t, "<html><body>503 Service Unavailable</body></html>\n")

	ctx := context.Background()
	fs := feed.Source{ID: "x", Name: src.Name, URL: bad.URL, Timeout: 5 * time.Second, MaxAttempts: 1}
	resp, err := feed.NewFetcher().Fetch(ctx, fs, feed.Conditional{})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	stats, _ := feed.Parse(resp.Body, func(domainname.Rule, string) error { return nil })
	_ = resp.Body.Close()

	prev, err := r.db.LastSuccessfulImport(ctx, src.ID)
	if err != nil {
		t.Fatalf("LastSuccessfulImport: %v", err)
	}
	// Kiểm tra toàn vẹn phải TỪ CHỐI lần import này.
	if err := feed.Validate(fs, stats, prev.Accepted); err == nil {
		t.Fatal("Validate chấp nhận feed hỏng, muốn từ chối")
	}

	// Vì bị từ chối, không có gì được ghi và snapshot cũ vẫn nguyên.
	after := r.get(t, "/blocklist/malware.txt")
	if after.Body.String() != before {
		t.Errorf("nội dung publish đã đổi sau một lần import bị từ chối")
	}
	if after.Header().Get("ETag") != beforeETag {
		t.Errorf("ETag đổi sau một lần import bị từ chối")
	}
	if !strings.Contains(after.Body.String(), "a.example.com") {
		t.Error("domain cũ biến mất sau một lần import bị từ chối")
	}
}

func TestBuildRequiresCompletedPolicyRun(t *testing.T) {
	r := newRig(t)
	_, err := r.build.Build(context.Background(), baseTime)
	if err == nil {
		t.Fatal("Build thành công khi chưa có lượt policy nào, muốn lỗi")
	}
	if err != builder.ErrNoPolicyRun {
		t.Errorf("lỗi = %v, muốn ErrNoPolicyRun", err)
	}
}
