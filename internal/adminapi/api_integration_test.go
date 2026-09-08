package adminapi_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/vnnic/cyberdns-tip/internal/adminapi"
	"github.com/vnnic/cyberdns-tip/internal/store"
	"github.com/vnnic/cyberdns-tip/internal/testdb"
)

const schema = "test_adminapi"

type client struct {
	t       *testing.T
	h       http.Handler
	pool    *pgxpool.Pool
	db      *store.Store
	cookies []*http.Cookie
}

func newClient(t *testing.T) *client {
	t.Helper()
	pool := testdb.SetupMigrated(t, schema)
	db := store.New(pool)

	api := &adminapi.API{
		DB:  db,
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	return &client{t: t, h: api.Handler(), pool: pool, db: db}
}

func (c *client) do(method, path string, body any) *httptest.ResponseRecorder {
	c.t.Helper()

	var r io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			c.t.Fatalf("mã hóa thân yêu cầu: %v", err)
		}
		r = bytes.NewReader(raw)
	}

	req := httptest.NewRequest(method, path, r)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for _, ck := range c.cookies {
		req.AddCookie(ck)
	}

	rec := httptest.NewRecorder()
	c.h.ServeHTTP(rec, req)

	if ck := rec.Result().Cookies(); len(ck) > 0 {
		c.cookies = ck
	}
	return rec
}

// login tạo tài khoản với vai trò cho trước rồi đăng nhập.
func (c *client) login(role string) {
	c.t.Helper()
	const pw = "mat-khau-test-rat-dai-12345"

	if err := c.db.CreateAdmin(context.Background(),
		role+"@vnnic.vn", "Test "+role, role, pw); err != nil {
		c.t.Fatalf("tạo tài khoản: %v", err)
	}

	rec := c.do(http.MethodPost, "/api/auth/login", map[string]string{
		"email": role + "@vnnic.vn", "password": pw,
	})
	if rec.Code != http.StatusOK {
		c.t.Fatalf("đăng nhập = %d: %s", rec.Code, rec.Body.String())
	}
}

func decodeBody[T any](t *testing.T, rec *httptest.ResponseRecorder) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatalf("giải mã phản hồi: %v\n%s", err, rec.Body.String())
	}
	return v
}

// Mọi endpoint đều phải yêu cầu đăng nhập. Đây là bài kiểm tra chống việc thêm route
// mới mà quên bọc xác thực.
func TestEveryEndpointRequiresAuth(t *testing.T) {
	c := newClient(t)

	endpoints := []struct{ method, path string }{
		{http.MethodGet, "/api/auth/me"},
		{http.MethodGet, "/api/overview"},
		{http.MethodGet, "/api/sources"},
		{http.MethodPost, "/api/sources"},
		{http.MethodPatch, "/api/sources/1"},
		{http.MethodDelete, "/api/sources/1"},
		{http.MethodGet, "/api/imports"},
		{http.MethodGet, "/api/domains/lookup?domain=example.com"},
		{http.MethodGet, "/api/allowlist"},
		{http.MethodPost, "/api/allowlist"},
		{http.MethodDelete, "/api/allowlist/1"},
		{http.MethodPost, "/api/sources/1/sync"},
		{http.MethodPost, "/api/sync"},
		{http.MethodPost, "/api/policy/run"},
		{http.MethodPost, "/api/blocklist/build"},
		{http.MethodGet, "/api/triggers/1"},
	}

	for _, e := range endpoints {
		t.Run(e.method+" "+e.path, func(t *testing.T) {
			rec := c.do(e.method, e.path, nil)
			if rec.Code != http.StatusUnauthorized {
				t.Errorf("mã = %d, muốn 401", rec.Code)
			}
		})
	}
}

func TestLoginAndLogout(t *testing.T) {
	c := newClient(t)
	c.login("owner")

	if rec := c.do(http.MethodGet, "/api/auth/me", nil); rec.Code != http.StatusOK {
		t.Fatalf("/api/auth/me sau đăng nhập = %d", rec.Code)
	}

	if rec := c.do(http.MethodPost, "/api/auth/logout", nil); rec.Code != http.StatusNoContent {
		t.Fatalf("logout = %d", rec.Code)
	}

	// Phiên đã thu hồi phải hết tác dụng ngay: đó là lý do phiên lưu trong CSDL chứ
	// không dùng cookie tự ký.
	if rec := c.do(http.MethodGet, "/api/auth/me", nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("sau logout = %d, muốn 401", rec.Code)
	}
}

func TestLoginRejectsBadCredentials(t *testing.T) {
	c := newClient(t)
	if err := c.db.CreateAdmin(context.Background(),
		"a@vnnic.vn", "A", "owner", "mat-khau-dung-12345"); err != nil {
		t.Fatalf("tạo tài khoản: %v", err)
	}

	tests := []struct{ name, email, pw string }{
		{"sai mật khẩu", "a@vnnic.vn", "mat-khau-sai"},
		{"email không tồn tại", "khong-co@vnnic.vn", "mat-khau-dung-12345"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := c.do(http.MethodPost, "/api/auth/login",
				map[string]string{"email": tt.email, "password": tt.pw})
			if rec.Code != http.StatusUnauthorized {
				t.Errorf("mã = %d, muốn 401", rec.Code)
			}
			// Thông báo lỗi phải giống hệt nhau: phân biệt hai trường hợp cho phép dò
			// xem địa chỉ nào có tài khoản.
			if !strings.Contains(rec.Body.String(), "email hoặc mật khẩu không đúng") {
				t.Errorf("thông báo lỗi tiết lộ thông tin: %s", rec.Body.String())
			}
		})
	}
}

// Quyền phải kiểm ở tầng handler. Giao diện chỉ ẩn nút; nó không phải hàng rào.
func TestRoleRestrictsWrites(t *testing.T) {
	c := newClient(t)
	c.login("viewer") // chỉ có quyền đọc

	if rec := c.do(http.MethodGet, "/api/sources", nil); rec.Code != http.StatusOK {
		t.Errorf("viewer đọc nguồn = %d, muốn 200", rec.Code)
	}

	rec := c.do(http.MethodPost, "/api/sources", map[string]any{
		"name": "x", "url": "https://example.test/l.txt",
	})
	if rec.Code != http.StatusForbidden {
		t.Errorf("viewer tạo nguồn = %d, muốn 403", rec.Code)
	}

	// viewer không có quyền allowlist:read theo seed vai trò.
	if rec := c.do(http.MethodGet, "/api/allowlist", nil); rec.Code != http.StatusForbidden {
		t.Errorf("viewer đọc allowlist = %d, muốn 403", rec.Code)
	}
}

func TestSourceCRUD(t *testing.T) {
	c := newClient(t)
	c.login("owner")

	created := c.do(http.MethodPost, "/api/sources", map[string]any{
		"name": "test-feed", "url": "https://example.test/list.txt",
		"trust_score": 80, "license": "GPL-3.0", "enabled": true,
		"categories": []string{"malware"},
	})
	if created.Code != http.StatusCreated {
		t.Fatalf("tạo nguồn = %d: %s", created.Code, created.Body.String())
	}
	id := decodeBody[map[string]any](t, created)["id"].(float64)

	list := decodeBody[map[string][]map[string]any](t,
		c.do(http.MethodGet, "/api/sources", nil))
	var found bool
	for _, s := range list["sources"] {
		if s["Name"] == "test-feed" || s["name"] == "test-feed" {
			found = true
		}
	}
	if !found {
		t.Errorf("nguồn vừa tạo không có trong danh sách")
	}

	patch := c.do(http.MethodPatch, "/api/sources/"+itoa(id), map[string]any{
		"trust_score": 95,
	})
	if patch.Code != http.StatusNoContent {
		t.Fatalf("cập nhật = %d: %s", patch.Code, patch.Body.String())
	}

	// Xóa mặc định chỉ TẮT: xóa thật kéo theo mọi bằng chứng L0 qua CASCADE, tức là
	// mất khả năng truy vết.
	del := c.do(http.MethodDelete, "/api/sources/"+itoa(id), nil)
	if del.Code != http.StatusNoContent {
		t.Fatalf("xóa = %d", del.Code)
	}

	var enabled bool
	var n int
	if err := c.pool.QueryRow(context.Background(),
		"SELECT enabled FROM sources WHERE id = $1", int64(id)).Scan(&enabled); err != nil {
		t.Fatalf("đọc nguồn: %v", err)
	}
	if enabled {
		t.Error("nguồn vẫn bật sau khi xóa")
	}
	if err := c.pool.QueryRow(context.Background(),
		"SELECT count(*) FROM sources WHERE id = $1", int64(id)).Scan(&n); err != nil {
		t.Fatalf("đếm: %v", err)
	}
	if n != 1 {
		t.Error("nguồn bị xóa cứng dù không yêu cầu purge")
	}
}

// Bật một nguồn chưa khai báo license là quyết định có hệ quả pháp lý: hệ tái phát
// hành list dẫn xuất qua endpoint công khai.
func TestCannotEnableSourceWithoutLicense(t *testing.T) {
	c := newClient(t)
	c.login("owner")

	rec := c.do(http.MethodPost, "/api/sources", map[string]any{
		"name": "no-license", "url": "https://example.test/l.txt", "enabled": true,
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("mã = %d, muốn 400: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "license") {
		t.Errorf("thông báo lỗi không nói về license: %s", rec.Body.String())
	}

	// Tắt thì cho phép: nguồn nằm đó chờ rà soát.
	ok := c.do(http.MethodPost, "/api/sources", map[string]any{
		"name": "no-license", "url": "https://example.test/l.txt", "enabled": false,
	})
	if ok.Code != http.StatusCreated {
		t.Errorf("tạo nguồn tắt = %d, muốn 201: %s", ok.Code, ok.Body.String())
	}
}

// Mức protected là lớp chống thảm họa: không tenant nào và không policy nào gỡ được.
// Đặt hoặc gỡ một mục ở đó phải là quyền riêng.
func TestProtectedAllowlistNeedsExtraPermission(t *testing.T) {
	c := newClient(t)
	c.login("operator") // có allowlist:* nhưng không có protected:write

	soft := c.do(http.MethodPost, "/api/allowlist", map[string]any{
		"domain": "example.com", "match_type": 0, "tier": "soft", "reason": "test",
	})
	if soft.Code != http.StatusCreated {
		t.Fatalf("thêm mục soft = %d: %s", soft.Code, soft.Body.String())
	}

	prot := c.do(http.MethodPost, "/api/allowlist", map[string]any{
		"domain": "vnnic.vn", "match_type": 1, "tier": "protected", "reason": "test",
	})
	if prot.Code != http.StatusForbidden {
		t.Errorf("thêm mục protected = %d, muốn 403: %s", prot.Code, prot.Body.String())
	}
}

// Tra cứu phải chuẩn hóa đầu vào bằng CHÍNH hàm mà đường ingest dùng, nếu không người
// dùng gõ chữ hoa hay tên miền IDN sẽ không tìm thấy gì.
func TestLookupNormalizesInput(t *testing.T) {
	c := newClient(t)
	c.login("owner")

	for _, q := range []string{"EXAMPLE.COM", "example.com.", "  example.com  "} {
		t.Run(q, func(t *testing.T) {
			rec := c.do(http.MethodGet, "/api/domains/lookup?domain="+urlEscape(q), nil)
			if rec.Code != http.StatusOK {
				t.Fatalf("mã = %d: %s", rec.Code, rec.Body.String())
			}
			rep := decodeBody[map[string]any](t, rec)
			if rep["domain"] != "example.com" {
				t.Errorf("domain = %v, muốn example.com đã chuẩn hóa", rep["domain"])
			}
		})
	}

	if rec := c.do(http.MethodGet, "/api/domains/lookup?domain=192.168.1.1", nil); rec.Code != http.StatusBadRequest {
		t.Errorf("tra cứu địa chỉ IP = %d, muốn 400", rec.Code)
	}
}

// Mọi thao tác ghi đều phải để lại dấu vết. Một thay đổi chính sách chặn không truy
// được người thực hiện là một thay đổi không giải trình được.
func TestWritesAreAudited(t *testing.T) {
	c := newClient(t)
	c.login("owner")

	c.do(http.MethodPost, "/api/sources", map[string]any{
		"name": "audited", "url": "https://example.test/l.txt", "license": "GPL-3.0",
	})
	c.do(http.MethodPost, "/api/allowlist", map[string]any{
		"domain": "example.com", "match_type": 0, "tier": "soft",
	})

	rows, err := c.pool.Query(context.Background(),
		"SELECT actor, action, entity FROM admin_audit_log ORDER BY id")
	if err != nil {
		t.Fatalf("đọc nhật ký: %v", err)
	}
	defer rows.Close()

	var actions []string
	for rows.Next() {
		var actor, action, entity string
		if err := rows.Scan(&actor, &action, &entity); err != nil {
			t.Fatalf("quét: %v", err)
		}
		if actor != "owner@vnnic.vn" {
			t.Errorf("actor = %q, muốn email người thực hiện", actor)
		}
		actions = append(actions, action)
	}

	want := []string{"source.create", "allowlist.add"}
	if len(actions) != len(want) {
		t.Fatalf("nhật ký có %v, muốn %v", actions, want)
	}
	for i := range want {
		if actions[i] != want[i] {
			t.Errorf("nhật ký[%d] = %q, muốn %q", i, actions[i], want[i])
		}
	}
}

// Gõ nhầm tên trường mà im lặng bỏ qua sẽ khiến người dùng tưởng đã lưu được thay đổi.
func TestUnknownFieldIsRejected(t *testing.T) {
	c := newClient(t)
	c.login("owner")

	rec := c.do(http.MethodPost, "/api/allowlist", map[string]any{
		"domain": "example.com", "match_type": 0, "resaon": "gõ nhầm",
	})
	if rec.Code != http.StatusBadRequest {
		t.Errorf("mã = %d, muốn 400 khi có trường lạ: %s", rec.Code, rec.Body.String())
	}
}

// Phản hồi lỗi không được lộ cấu trúc bảng hay thông điệp lỗi của PostgreSQL.
func TestErrorsDoNotLeakInternals(t *testing.T) {
	c := newClient(t)
	c.login("owner")

	rec := c.do(http.MethodDelete, "/api/allowlist/999999", nil)
	body := rec.Body.String()
	for _, leak := range []string{"SQLSTATE", "pgx", "SELECT", "relation"} {
		if strings.Contains(body, leak) {
			t.Errorf("phản hồi lộ chi tiết nội bộ (%q): %s", leak, body)
		}
	}
}

// ------------------------------------------------------------ yêu cầu chạy ngay

// newSourceID tạo một nguồn 'direct' tối thiểu và trả về id, dùng làm dữ liệu nền cho
// các test yêu cầu đồng bộ — không đi qua API để không lẫn với thứ đang được test.
func newSourceID(t *testing.T, c *client, name string) int64 {
	t.Helper()
	var id int64
	err := c.pool.QueryRow(context.Background(), `
		INSERT INTO sources (name, url, source_type, origin, trust_score, enabled, license)
		VALUES ($1, 'https://example.test/list.txt', 'plain', 'direct', 80, TRUE, 'GPL-3.0')
		RETURNING id`, name).Scan(&id)
	if err != nil {
		t.Fatalf("tạo nguồn nền %s: %v", name, err)
	}
	return id
}

func TestSyncSourceEnqueuesTrigger(t *testing.T) {
	c := newClient(t)
	c.login("owner")
	id := newSourceID(t, c, "t-sync-src")

	rec := c.do(http.MethodPost, "/api/sources/"+itoa(float64(id))+"/sync", nil)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("mã = %d: %s", rec.Code, rec.Body.String())
	}
	tid := int64(decodeBody[map[string]any](t, rec)["trigger_id"].(float64))
	if tid == 0 {
		t.Fatal("trigger_id = 0")
	}

	status := c.do(http.MethodGet, "/api/triggers/"+itoa(float64(tid)), nil)
	if status.Code != http.StatusOK {
		t.Fatalf("đọc trạng thái = %d: %s", status.Code, status.Body.String())
	}
	got := decodeBody[map[string]any](t, status)
	if got["kind"] != "sync" {
		t.Errorf("kind = %v, muốn sync", got["kind"])
	}
	if got["status"] != "pending" {
		t.Errorf("status = %v, muốn pending (chưa có service nào tiêu thụ)", got["status"])
	}
	if got["source_name"] != "t-sync-src" {
		t.Errorf("source_name = %v, muốn t-sync-src", got["source_name"])
	}
}

func TestSyncSourceNotFound(t *testing.T) {
	c := newClient(t)
	c.login("owner")

	rec := c.do(http.MethodPost, "/api/sources/999999/sync", nil)
	if rec.Code != http.StatusNotFound {
		t.Errorf("mã = %d, muốn 404", rec.Code)
	}
}

// Nguồn 'opencti' đồng bộ qua sync-consumer nghe Live Stream, không qua feed-ingestor —
// gửi yêu cầu vào đây phải bị từ chối rõ ràng, không phải im lặng không làm gì.
func TestSyncSourceRejectsOpenCTIOrigin(t *testing.T) {
	c := newClient(t)
	c.login("owner")

	var octiID int64
	if err := c.pool.QueryRow(context.Background(),
		"SELECT id FROM sources WHERE origin = 'opencti' LIMIT 1").Scan(&octiID); err != nil {
		t.Fatalf("đọc nguồn opencti (seed 0003): %v", err)
	}

	rec := c.do(http.MethodPost, "/api/sources/"+itoa(float64(octiID))+"/sync", nil)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("mã = %d, muốn 400: %s", rec.Code, rec.Body.String())
	}
}

func TestSyncAllEnqueuesTrigger(t *testing.T) {
	c := newClient(t)
	c.login("owner")

	rec := c.do(http.MethodPost, "/api/sync", nil)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("mã = %d: %s", rec.Code, rec.Body.String())
	}
}

// Bấm hai lần liền trước khi có service nào tiêu thụ yêu cầu đầu tiên phải trả về CÙNG
// một trigger_id — xem store.EnqueueTrigger.
func TestDuplicateSyncRequestReusesTrigger(t *testing.T) {
	c := newClient(t)
	c.login("owner")
	id := newSourceID(t, c, "t-sync-dup")

	path := "/api/sources/" + itoa(float64(id)) + "/sync"
	first := decodeBody[map[string]any](t, c.do(http.MethodPost, path, nil))
	second := decodeBody[map[string]any](t, c.do(http.MethodPost, path, nil))

	if first["trigger_id"] != second["trigger_id"] {
		t.Errorf("trigger_id khác nhau giữa hai lần bấm liền: %v vs %v",
			first["trigger_id"], second["trigger_id"])
	}
}

func TestRunPolicyRequiresPermission(t *testing.T) {
	c := newClient(t)
	c.login("viewer")

	if rec := c.do(http.MethodPost, "/api/policy/run", nil); rec.Code != http.StatusForbidden {
		t.Errorf("viewer chạy policy = %d, muốn 403", rec.Code)
	}
}

// operator được migration 0008 cấp policy:write dù seed ban đầu (0002) không có.
func TestRunPolicyAllowsOperator(t *testing.T) {
	c := newClient(t)
	c.login("operator")

	rec := c.do(http.MethodPost, "/api/policy/run", nil)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("operator chạy policy = %d: %s", rec.Code, rec.Body.String())
	}
}

func TestBuildBlocklistRequiresPermission(t *testing.T) {
	c := newClient(t)
	c.login("viewer")

	if rec := c.do(http.MethodPost, "/api/blocklist/build", nil); rec.Code != http.StatusForbidden {
		t.Errorf("viewer dựng blocklist = %d, muốn 403", rec.Code)
	}
}

func TestBuildBlocklistAllowsOperator(t *testing.T) {
	c := newClient(t)
	c.login("operator")

	rec := c.do(http.MethodPost, "/api/blocklist/build", nil)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("operator dựng blocklist = %d: %s", rec.Code, rec.Body.String())
	}
}

func TestTriggerStatusNotFound(t *testing.T) {
	c := newClient(t)
	c.login("owner")

	rec := c.do(http.MethodGet, "/api/triggers/999999", nil)
	if rec.Code != http.StatusNotFound {
		t.Errorf("mã = %d, muốn 404", rec.Code)
	}
}

// Trạng thái yêu cầu không đòi quyền tạo ra loại yêu cầu đó — "đồng bộ xong chưa"
// không phải thông tin nhạy cảm, và một tài khoản chỉ-đọc cần xem được để theo dõi khi
// người khác bấm nút.
//
// Dùng CHUNG một client (cùng schema CSDL) cho cả hai lần đăng nhập: newClient tự dựng
// lại CSDL trắng ở mỗi lần gọi, nên dựng hai client riêng sẽ khiến client thứ hai xóa
// mất dữ liệu client thứ nhất vừa tạo.
func TestTriggerStatusOnlyNeedsAuth(t *testing.T) {
	c := newClient(t)
	c.login("owner")
	id := newSourceID(t, c, "t-sync-viewer")
	tid := int64(decodeBody[map[string]any](t,
		c.do(http.MethodPost, "/api/sources/"+itoa(float64(id))+"/sync", nil))["trigger_id"].(float64))

	c.login("viewer") // đăng nhập lại: cookie phiên chuyển sang tài khoản viewer
	rec := c.do(http.MethodGet, "/api/triggers/"+itoa(float64(tid)), nil)
	if rec.Code != http.StatusOK {
		t.Errorf("viewer đọc trạng thái yêu cầu = %d, muốn 200: %s", rec.Code, rec.Body.String())
	}
}

func itoa(f float64) string { return strings.TrimSuffix(strings.TrimRight(fmtF(f), "0"), ".") }
func fmtF(f float64) string { return strings.TrimSpace(jsonNumber(f)) }
func jsonNumber(f float64) string {
	b, _ := json.Marshal(f)
	return string(b)
}

func urlEscape(s string) string {
	return strings.NewReplacer(" ", "%20").Replace(s)
}
