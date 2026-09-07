package builder_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/vnnic/cyberdns-tip/internal/blocklistsrv"
	"github.com/vnnic/cyberdns-tip/internal/metrics"
	"github.com/vnnic/cyberdns-tip/internal/store"
)

// addTenant tạo một tenant kèm token, và trả về token thô.
func addTenant(t *testing.T, r *rig, slug string, categories ...string) string {
	t.Helper()
	ctx := context.Background()

	var id int64
	if err := r.pool.QueryRow(ctx, `
		INSERT INTO tenants (name, slug) VALUES ($1, $1) RETURNING id`, slug).Scan(&id); err != nil {
		t.Fatalf("tạo tenant %s: %v", slug, err)
	}

	for _, c := range categories {
		if _, err := r.pool.Exec(ctx, `
			INSERT INTO tenant_categories (tenant_id, category_id, enabled)
			SELECT $1, id, TRUE FROM categories WHERE name = $2`, id, c); err != nil {
			t.Fatalf("gán category %s: %v", c, err)
		}
	}

	raw, hash, err := store.NewToken()
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}
	if _, err := r.pool.Exec(ctx, `
		INSERT INTO tenant_tokens (tenant_id, token_hash, label)
		VALUES ($1, $2, 'test')`, id, hash); err != nil {
		t.Fatalf("tạo token: %v", err)
	}
	return raw
}

// withTenants gắn bộ tra token thật vào server.
func (r *rig) withTenants(t *testing.T) {
	t.Helper()
	r.http = blocklistsrv.New(blocklistsrv.Options{
		Store:   r.snaps,
		Metrics: metrics.New("test", "v0"),
		// TTL cực nhỏ để test thấy ngay hiệu lực của việc thu hồi token. Truyền 0 sẽ
		// rơi vào mặc định 5 phút chứ không phải "tắt đệm".
		Tenants: store.NewTokenResolver(r.db, time.Nanosecond, time.Nanosecond),
	}).Handler()
}

func TestTenantGetsOwnBlocklist(t *testing.T) {
	r := newRig(t)
	r.withTenants(t)
	src := addSource(t, r, "t-feed", `["malware"]`, "")

	acme := addTenant(t, r, "acme", "malware")

	r.ingest(t, src, feedServer(t, "evil.example.com\nbad.example.net\n").URL, baseTime)
	r.runPolicy(t, baseTime)
	if _, err := r.build.Build(context.Background(), baseTime); err != nil {
		t.Fatalf("Build: %v", err)
	}

	rec := r.get(t, "/blocklist/"+acme+"/malware.txt")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET tenant malware.txt = %d, muốn 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "evil.example.com") {
		t.Errorf("file của tenant thiếu domain:\n%s", rec.Body.String())
	}

	// Tenant mặc định vẫn phục vụ ở URL phẳng như claude_rm.md quy định.
	if got := r.get(t, "/blocklist/malware.txt"); got.Code != http.StatusOK {
		t.Errorf("URL phẳng của tenant mặc định = %d, muốn 200", got.Code)
	}
}

// Đây là điểm mấu chốt của đa tenant: allowlist của một tenant chỉ ảnh hưởng file của
// chính họ.
func TestTenantAllowlistIsIsolated(t *testing.T) {
	r := newRig(t)
	r.withTenants(t)
	src := addSource(t, r, "t-feed", `["malware"]`, "")

	acme := addTenant(t, r, "acme", "malware")
	other := addTenant(t, r, "other", "malware")

	ctx := context.Background()
	if _, err := r.pool.Exec(ctx, `
		INSERT INTO tenant_allowlist (tenant_id, domain, match_type, reason)
		SELECT id, 'evil.example.com', 0, 'khách hàng báo false positive'
		  FROM tenants WHERE slug = 'acme'`); err != nil {
		t.Fatalf("thêm allowlist tenant: %v", err)
	}

	r.ingest(t, src, feedServer(t, "evil.example.com\nbad.example.net\n").URL, baseTime)
	r.runPolicy(t, baseTime)
	if _, err := r.build.Build(ctx, baseTime); err != nil {
		t.Fatalf("Build: %v", err)
	}

	acmeBody := r.get(t, "/blocklist/"+acme+"/malware.txt").Body.String()
	if strings.Contains(acmeBody, "evil.example.com") {
		t.Errorf("domain trong allowlist của acme vẫn nằm trong file của acme:\n%s", acmeBody)
	}
	if !strings.Contains(acmeBody, "bad.example.net") {
		t.Errorf("allowlist gỡ nhầm domain khác:\n%s", acmeBody)
	}

	otherBody := r.get(t, "/blocklist/"+other+"/malware.txt").Body.String()
	if !strings.Contains(otherBody, "evil.example.com") {
		t.Errorf("allowlist của acme ảnh hưởng sang tenant khác:\n%s", otherBody)
	}

	// Tenant mặc định cũng không bị ảnh hưởng.
	if !strings.Contains(r.get(t, "/blocklist/malware.txt").Body.String(), "evil.example.com") {
		t.Error("allowlist của acme ảnh hưởng tới tenant mặc định")
	}
}

// Xung đột D2: file danh sách phẳng không có cú pháp ngoại lệ, nên ngoại lệ phải đi
// qua một file allowlist riêng để Blocky nạp vào cấu hình allowlist của nó.
func TestTenantAllowlistIsPublishedAsFile(t *testing.T) {
	r := newRig(t)
	r.withTenants(t)
	src := addSource(t, r, "t-feed", `["malware"]`, "")

	acme := addTenant(t, r, "acme", "malware")

	ctx := context.Background()
	if _, err := r.pool.Exec(ctx, `
		INSERT INTO tenant_allowlist (tenant_id, domain, match_type, reason)
		SELECT id, 'shop.example.com', 0, 'ngoại lệ dưới rule cha'
		  FROM tenants WHERE slug = 'acme'`); err != nil {
		t.Fatalf("thêm allowlist: %v", err)
	}

	r.ingest(t, src, feedServer(t, "*.example.com\n").URL, baseTime)
	r.runPolicy(t, baseTime)
	if _, err := r.build.Build(ctx, baseTime); err != nil {
		t.Fatalf("Build: %v", err)
	}

	allow := r.get(t, "/allowlist/"+acme+"/allowlist.txt")
	if allow.Code != http.StatusOK {
		t.Fatalf("GET allowlist = %d, muốn 200", allow.Code)
	}
	if !strings.Contains(allow.Body.String(), "shop.example.com") {
		t.Errorf("file allowlist thiếu mục ngoại lệ:\n%s", allow.Body.String())
	}

	// Rule cha vẫn nằm trong denylist: gỡ nó sẽ mở toang cả nhánh example.com.
	deny := r.get(t, "/blocklist/"+acme+"/malware.txt").Body.String()
	if !strings.Contains(deny, "example.com") {
		t.Errorf("rule cha bị gỡ khỏi denylist:\n%s", deny)
	}
}

func TestTenantDenylistAddsDomains(t *testing.T) {
	r := newRig(t)
	r.withTenants(t)
	src := addSource(t, r, "t-feed", `["malware"]`, "")

	acme := addTenant(t, r, "acme", "malware")

	ctx := context.Background()
	if _, err := r.pool.Exec(ctx, `
		INSERT INTO tenant_denylist (tenant_id, domain, match_type, reason)
		SELECT id, 'internal-block.example.org', 0, 'chính sách nội bộ'
		  FROM tenants WHERE slug = 'acme'`); err != nil {
		t.Fatalf("thêm denylist: %v", err)
	}

	r.ingest(t, src, feedServer(t, "evil.example.com\n").URL, baseTime)
	r.runPolicy(t, baseTime)
	if _, err := r.build.Build(ctx, baseTime); err != nil {
		t.Fatalf("Build: %v", err)
	}

	body := r.get(t, "/blocklist/"+acme+"/malware.txt").Body.String()
	if !strings.Contains(body, "internal-block.example.org") {
		t.Errorf("denylist riêng của tenant không vào file:\n%s", body)
	}
	if strings.Contains(r.get(t, "/blocklist/malware.txt").Body.String(), "internal-block.example.org") {
		t.Error("denylist của tenant lọt sang tenant mặc định")
	}
}

// Tenant chỉ nhận các category họ đăng ký.
func TestTenantOnlyGetsSubscribedCategories(t *testing.T) {
	r := newRig(t)
	r.withTenants(t)
	src := addSource(t, r, "t-feed", `["malware","ads"]`, "")

	acme := addTenant(t, r, "acme", "malware") // không đăng ký ads

	r.ingest(t, src, feedServer(t, "evil.example.com\n").URL, baseTime)
	r.runPolicy(t, baseTime)
	if _, err := r.build.Build(context.Background(), baseTime); err != nil {
		t.Fatalf("Build: %v", err)
	}

	if got := r.get(t, "/blocklist/"+acme+"/malware.txt"); got.Code != http.StatusOK {
		t.Errorf("category đã đăng ký = %d, muốn 200", got.Code)
	}
	if got := r.get(t, "/blocklist/"+acme+"/ads.txt"); got.Code != http.StatusNotFound {
		t.Errorf("category chưa đăng ký = %d, muốn 404", got.Code)
	}
}

func TestTokenHandling(t *testing.T) {
	r := newRig(t)
	r.withTenants(t)
	src := addSource(t, r, "t-feed", `["malware"]`, "")
	acme := addTenant(t, r, "acme", "malware")

	r.ingest(t, src, feedServer(t, "evil.example.com\n").URL, baseTime)
	r.runPolicy(t, baseTime)
	if _, err := r.build.Build(context.Background(), baseTime); err != nil {
		t.Fatalf("Build: %v", err)
	}

	if got := r.get(t, "/blocklist/"+acme+"/malware.txt"); got.Code != http.StatusOK {
		t.Fatalf("token hợp lệ = %d, muốn 200", got.Code)
	}

	// Token sai trả 404 chứ không phải 403: phân biệt hai trường hợp sẽ giúp người dò
	// tìm biết token nào tồn tại.
	bad := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if got := r.get(t, "/blocklist/"+bad+"/malware.txt"); got.Code != http.StatusNotFound {
		t.Errorf("token sai = %d, muốn 404", got.Code)
	}

	// Thu hồi token thì URL cũ ngừng hoạt động.
	if _, err := r.pool.Exec(context.Background(),
		"UPDATE tenant_tokens SET revoked_at = NOW()"); err != nil {
		t.Fatalf("thu hồi token: %v", err)
	}
	// TTL đệm cực nhỏ trong test nên có hiệu lực ngay. Trong production, thu hồi
	// token mất tối đa một TTL để có hiệu lực trừ khi admin API gọi Invalidate.
	if got := r.get(t, "/blocklist/"+acme+"/malware.txt"); got.Code != http.StatusNotFound {
		t.Errorf("token đã thu hồi = %d, muốn 404", got.Code)
	}
}

// Phần lớn tenant không có override nào, nên file của họ trùng nội dung với bản dùng
// chung. Ghi ra N bản sao của một file 200 MB là lãng phí thuần túy.
func TestIdenticalTenantFilesShareOneFileOnDisk(t *testing.T) {
	r := newRig(t)
	r.withTenants(t)
	src := addSource(t, r, "t-feed", `["malware"]`, "")

	a := addTenant(t, r, "alpha", "malware")
	b := addTenant(t, r, "beta", "malware")

	r.ingest(t, src, feedServer(t, "evil.example.com\nbad.example.net\n").URL, baseTime)
	r.runPolicy(t, baseTime)
	if _, err := r.build.Build(context.Background(), baseTime); err != nil {
		t.Fatalf("Build: %v", err)
	}

	m, err := r.snaps.Manifest()
	if err != nil {
		t.Fatalf("Manifest: %v", err)
	}

	alpha := m.Tenants["alpha"].Lists["malware.txt"]
	if alpha.SameAs == "" {
		t.Errorf("tenant không có override vẫn được ghi ra file riêng (%+v)", alpha)
	}

	// Nhưng nội dung phục vụ vẫn phải đúng và đầy đủ cho cả hai tenant.
	for _, token := range []string{a, b} {
		body := r.get(t, "/blocklist/"+token+"/malware.txt").Body.String()
		if !strings.Contains(body, "evil.example.com") {
			t.Errorf("tenant dùng chung file nhưng nội dung sai:\n%s", body)
		}
	}
}

// Đường dẫn tenant không được trở thành đường thoát ra ngoài thư mục bộ snapshot.
func TestTenantPathTraversalIsRejected(t *testing.T) {
	r := newRig(t)
	r.withTenants(t)
	src := addSource(t, r, "t-feed", `["malware"]`, "")
	acme := addTenant(t, r, "acme", "malware")

	r.ingest(t, src, feedServer(t, "evil.example.com\n").URL, baseTime)
	r.runPolicy(t, baseTime)
	if _, err := r.build.Build(context.Background(), baseTime); err != nil {
		t.Fatalf("Build: %v", err)
	}

	for _, path := range []string{
		"/blocklist/" + acme + "/..%2fmanifest.json",
		"/blocklist/" + acme + "/current",
		"/blocklist/khong-phai-token/malware.txt",
		"/allowlist/" + acme + "/../../current",
	} {
		t.Run(path, func(t *testing.T) {
			rec := httptest.NewRecorder()
			r.http.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
			if rec.Code == http.StatusOK {
				t.Errorf("mã = 200, muốn bị từ chối:\n%s", rec.Body.String())
			}
		})
	}
}
